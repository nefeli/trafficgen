#include "pktgen.h"

static uint16_t
gen_pkt_size(struct pktgen_config *config)
{
    return config->size_min +
           rand_fast(&config->seed) %
               (RTE_MAX(config->size_max - config->size_min, 1));
}

static void
stats(double *start_time, struct rate_stats *r_stats)
{
    double now = get_time_msec();
    double elapsed = (now - *start_time) / 1000;
    double tx_bps = (8 * r_stats->tx_bytes) / elapsed;
    double tx_pps = r_stats->tx_pkts / elapsed;
    double rx_bps = (8 * r_stats->rx_bytes) / elapsed;
    double rx_pps = r_stats->rx_pkts / elapsed;
    double txwire, rxwire;

    r_stats->n++;
    /* update tx bps mean/var */
    double delta = tx_bps / 1000000 - r_stats->avg_txbps;
    r_stats->avg_txbps += delta / r_stats->n;
    r_stats->var_txbps += delta * (tx_bps / 1000000 - r_stats->avg_txbps);

    /* update tx pps mean/var */
    delta = tx_pps / 1000000 - r_stats->avg_txpps;
    r_stats->avg_txpps += delta / r_stats->n;
    r_stats->var_txpps += delta * (tx_pps / 1000000 - r_stats->avg_txpps);

    /* update tx wire rate mean/var */
    txwire = ((tx_bps / 1000000) + ((tx_pps / 1000000) * ETH_OVERHEAD * 8));
    delta = txwire - r_stats->avg_txwire;
    r_stats->avg_txwire += delta / r_stats->n;
    r_stats->var_txwire += delta * (txwire - r_stats->avg_txwire);

    /* update rx bps mean/var */
    delta = rx_bps / 1000000 - r_stats->avg_rxbps;
    r_stats->avg_rxbps += delta / r_stats->n;
    r_stats->var_rxbps += delta * (rx_bps / 1000000 - r_stats->avg_rxbps);

    /* update rx pps mean/var */
    delta = rx_pps / 1000000 - r_stats->avg_rxpps;
    r_stats->avg_rxpps += delta / r_stats->n;
    r_stats->var_rxpps += delta * (rx_pps / 1000000 - r_stats->avg_rxpps);

    /* update rx wire rate mean/var */
    rxwire = ((rx_bps / 1000000) + ((rx_pps / 1000000) * ETH_OVERHEAD * 8));
    delta = rxwire - r_stats->avg_rxwire;
    r_stats->avg_rxwire += delta / r_stats->n;
    r_stats->var_rxwire += delta * (rxwire - r_stats->avg_rxwire);

    if (elapsed >= .1f) {
#ifndef NDEBUG
        syslog(LOG_INFO,
               "[lcore=%u] rx/tx stats: mpps=%.3f/%.3f wire_mbps=%.1f/%.1f\n",
               rte_lcore_id(), rx_pps / 1000000, tx_pps / 1000000, rxwire,
               txwire);
#endif
        r_stats->rx_pkts = 0;
        r_stats->rx_bytes = 0;
        r_stats->tx_bytes = 0;
        r_stats->tx_pkts = 0;
        *start_time = now;
    }
}

static void
latency_calc(double *samples, uint32_t sample_count, struct rate_stats *r_stats)
{
    qsort(samples, sample_count, sizeof(samples[0]), double_compare);
    uint32_t i, j = 0;
    double labels[8] = {0.0f, 0.25f, 0.5f, 0.75f, 0.9f, 0.95f, 0.99f, 1.0f};
    double vals[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    double delta, mean = 0, var = 0;
    for (j = 0; j < 8; j++) {
        i = RTE_MIN(sample_count - 1, (uint32_t)(labels[j] * sample_count));
        vals[j] = samples[i] * 1000000.0f;
    }

    for (i = 0; i < sample_count; i++) {
        delta = samples[i] * 1000000.0f - mean;
        mean += delta / (i + 1);
        var += delta * (samples[i] * 1000000.0f - mean);
    }

    var /= sample_count - 1;

    r_stats->rtt_n = sample_count;
    r_stats->rtt_avg = mean;
    r_stats->rtt_std = sqrt(var);
    r_stats->rtt_0 = vals[0];
    r_stats->rtt_25 = vals[1];
    r_stats->rtt_50 = vals[2];
    r_stats->rtt_75 = vals[3];
    r_stats->rtt_90 = vals[4];
    r_stats->rtt_95 = vals[5];
    r_stats->rtt_99 = vals[6];
    r_stats->rtt_100 = vals[7];
}

static void
generate_packet_init(struct pkt *buf, struct pktgen_config *config)
{
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;

    struct ether_addr addr;
    rte_eth_macaddr_get(config->port, &addr);

    eth_hdr = &buf->eth_hdr;
    if (is_zero_ether_addr(&config->dst_mac)) {
        ether_addr_copy(&ether_dst, &eth_hdr->d_addr);
    } else {
        ether_addr_copy(&config->dst_mac, &eth_hdr->d_addr);
    }

    if (is_zero_ether_addr(&config->src_mac)) {
        ether_addr_copy(&addr, &eth_hdr->s_addr);
    } else {
        ether_addr_copy(&config->src_mac, &eth_hdr->s_addr);
    }

    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    ip_hdr = &buf->ip_hdr;
    memset(ip_hdr, 0, sizeof(*ip_hdr));
    ip_hdr->type_of_service = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = config->proto;
    ip_hdr->packet_id = 0;
    ip_hdr->version_ihl = (1 << 6) + 5;
    ip_hdr->hdr_checksum = 0;
}

static void
generate_packet(struct pkt *buf, struct pktgen_config *config,
                double *flow_times, uint16_t *flow_ctrs, double now)
{
    struct ipv4_hdr *ip_hdr;
    struct udp_hdr *udp_hdr;
    struct tcp_hdr *tcp_hdr;
    uint16_t pkt_size = buf->size;
    uint64_t flow;
    uint32_t num_flows = config->num_flows;

    ip_hdr = &buf->ip_hdr;
    ip_hdr->total_length =
        rte_cpu_to_be_16(pkt_size - sizeof(struct ether_hdr));
    ip_hdr->hdr_checksum = 0;

    flow = num_flows > 0 ? 1 + rand_fast(&config->seed) % num_flows : 0;
    if (config->flags & FLAG_LIMIT_FLOW_LIFE &&
        now - flow_times[flow] >=
            randf(&config->seed, config->life_min, config->life_max)) {
        flow_times[flow] = now;
        flow_ctrs[flow]++;
    }
    if (flow_ctrs[flow] == 0) {
        flow_ctrs[flow]++;
    }

    ip_hdr->src_addr =
        rte_cpu_to_be_32(flow_ctrs[flow] * flow * config->ip_min);
    ip_hdr->dst_addr =
        rte_cpu_to_be_32(flow_ctrs[flow] * (flow ^ GEN_KEY) * config->ip_min);

    ip_hdr->total_length =
        rte_cpu_to_be_16(pkt_size - sizeof(struct ether_hdr));
    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

    uint16_t sport = rte_cpu_to_be_16(ip_hdr->dst_addr % 0x1111);
    uint16_t dport = rte_cpu_to_be_16(
        (ip_hdr->src_addr % RTE_MAX(config->port_max - config->port_min, 1)) +
        config->port_min);
    size_t l4s = 0;

    if (config->proto == 17) {
        udp_hdr = &buf->udp_hdr;
        udp_hdr->src_port = sport;
        udp_hdr->dst_port = dport;
        udp_hdr->dgram_cksum = 0;
        udp_hdr->dgram_len = rte_cpu_to_be_16(
            pkt_size - sizeof(struct ether_hdr) - sizeof(*ip_hdr));
        l4s = sizeof(struct udp_hdr);
    } else {
        tcp_hdr = &buf->tcp_hdr;
        tcp_hdr->src_port = sport;
        tcp_hdr->dst_port = dport;
        tcp_hdr->data_off = ((sizeof(struct tcp_hdr) / sizeof(uint32_t)) << 4);
        tcp_hdr->tcp_flags = (1 << 4);
        l4s = sizeof(struct tcp_hdr);
    }

    // FIXME: data's offset is bad because of the use of union
    if (pkt_size > sizeof(struct ether_hdr) - sizeof(*ip_hdr) - l4s) {
        memset(buf->data, 0,
               pkt_size - sizeof(struct ether_hdr) - sizeof(*ip_hdr) - l4s);
        if (config->flags & FLAG_RANDOMIZE_PAYLOAD) {
            unsigned r = 0;
            while (r < pkt_size - sizeof(struct ether_hdr) - sizeof(*ip_hdr) -
                           l4s) {
                buf->data[r] = (uint8_t)rand_fast(&config->seed);
                r++;
            }
        }
    }
}

#define NUM_SAMPLES (100000)
static void
worker_loop(struct pktgen_config *config)
{
    struct pkt tx_template;
    struct rte_mempool *tx_pool = config->tx_pool;
    uint32_t nb_tx, nb_rx, i, num_samples = NUM_SAMPLES;
    struct rte_mbuf *bufs[BURST_SIZE];
    double now, start_time,
        *samples = (double *)malloc(num_samples * sizeof(double));
    int64_t burst;
    uint8_t run_id = 0;

    struct rate_stats r_stats = {0};
    double *flow_times = NULL;
    uint16_t *flow_ctrs = NULL;

    for (;;) {
        while (config->flags & FLAG_WAIT) {
            usleep(1000);
        }

        // Transitioning from start to stop.
        flow_ctrs =
            realloc(flow_ctrs, sizeof(uint16_t) * (config->num_flows + 1));
        flow_times =
            realloc(flow_times, sizeof(double) * (config->num_flows + 1));
        if (flow_ctrs == NULL || flow_times == NULL) {
            rte_panic("couldn't allocate flow counters");
        }
        memset(flow_times, 0, sizeof(double) * config->num_flows);
        memset(flow_ctrs, 0, sizeof(uint16_t) * config->num_flows);
        memset(&r_stats, 0, sizeof(r_stats));
        memset(samples, 0, sizeof(double) * num_samples);
        uint64_t total_rx = 0;
        uint32_t sample_count = 0;
        double elapsed = 0;

        int reset_pending = 1;

        run_id++;
        config->start_time = get_time_msec();
        generate_packet_init(&tx_template, config);

        /* Flush the RX queue */
        while ((nb_rx = rte_eth_rx_burst(config->port, 0, bufs, BURST_SIZE)) >
               0) {
            rte_mempool_put_bulk(bufs[0]->pool, (void **)bufs, nb_rx);
            rte_delay_us(10);
        }

        while (!(config->flags & FLAG_WAIT)) {
            now = get_time_msec();
            elapsed = now - config->start_time;
            if (unlikely(elapsed > config->duration)) {
                break;
            } else if (unlikely(elapsed > config->warmup && reset_pending)) {
                start_time = now;
                total_rx = 0;
                sample_count = 0;
                reset_pending = 0;
                memset(&r_stats, 0, sizeof(r_stats));
            } else if (unlikely(now - start_time > 0.5f)) {
                stats(&start_time, &r_stats);
            }

            nb_rx = rte_eth_rx_burst(config->port, 0, bufs, BURST_SIZE);

            for (i = 0; i < nb_rx; i++) {
                r_stats.rx_bytes += bufs[i]->pkt_len;

                if (config->flags & FLAG_MEASURE_LATENCY) {
                    uint64_t idx = 0;
                    if ((idx = total_rx) < num_samples ||
                        (idx = rand_fast(&config->seed) % total_rx) <
                            num_samples) {
                        uint8_t *p = rte_pktmbuf_mtod_offset(
                            bufs[i], uint8_t *, sizeof(struct ether_hdr) +
                                                    sizeof(struct ipv4_hdr) +
                                                    sizeof(struct udp_hdr));
                        double *ts = (double *)(p + 1);
                        if (*p == run_id && *ts > 0) {
                            samples[idx] = (now - *ts) / 1000;
                            sample_count =
                                RTE_MIN(num_samples, sample_count + 1);
                            total_rx++;
                        } else {
                            syslog(LOG_ERR,
                                   "[port=%d] received packet from run %d "
                                   "instead of %d",
                                   config->port, *p, run_id);
                        }
                    }
                }
                r_stats.rx_pkts++;
            }

            if (likely(nb_rx > 0)) {
                rte_mempool_put_bulk(bufs[0]->pool, (void **)bufs, nb_rx);
            }

            uint64_t exp_bytes =
                ((now - start_time) / 1000) * config->tx_rate * 1000000 / 8;
            int64_t avg_pkt = (r_stats.tx_bytes + 1) / (r_stats.tx_pkts + 1);
            burst = (exp_bytes - r_stats.tx_bytes);
            burst /= avg_pkt;
            burst = RTE_MIN(burst, (unsigned)BURST_SIZE);
            burst = RTE_MAX((unsigned)0, burst);

            uint32_t lens[burst];
            if (unlikely(mbuf_alloc_bulk(tx_pool, bufs, MAX_PKT_SIZE, burst) !=
                         0)) {
                continue;
            }

            uint16_t pkt_size = gen_pkt_size(config);
            tx_template.size = pkt_size;
            generate_packet(&tx_template, config, flow_times, flow_ctrs, now);
            for (i = 0; i < burst; i++) {
                lens[i] = pkt_size;

                struct rte_mbuf *buf = bufs[i];
                buf->pkt_len = pkt_size;
                buf->data_len = pkt_size;
                buf->nb_segs = 1;

                rte_memcpy((uint8_t *)buf->buf_addr + buf->data_off,
                           (uint8_t *)&tx_template.eth_hdr, pkt_size);

                if (config->flags & FLAG_MEASURE_LATENCY) {
                    uint8_t *p = rte_pktmbuf_mtod_offset(
                        bufs[i], uint8_t *, sizeof(struct ether_hdr) +
                                                sizeof(struct ipv4_hdr) +
                                                sizeof(struct udp_hdr));
                    p[0] = run_id;
                    *(double *)(p + 1) = now;
                }
            }

            nb_tx = rte_eth_tx_burst(config->port, 0, bufs, burst);

            if (likely(nb_tx < burst)) {
                rte_mempool_put_bulk(bufs[nb_tx]->pool, (void **)&bufs[nb_tx],
                                     burst - nb_tx);
            }

            for (i = 0; i < nb_tx; i++) {
                r_stats.tx_bytes += lens[i];
            }

            r_stats.tx_pkts += nb_tx;
        }
        stats(&start_time, &r_stats);

        // Transitions from run to stop
        if (r_stats.n > 0 && sample_count > 0) {
            r_stats.var_txpps /= (r_stats.n - 1);
            r_stats.var_rxpps /= (r_stats.n - 1);
            r_stats.var_txbps /= (r_stats.n - 1);
            r_stats.var_rxbps /= (r_stats.n - 1);
            r_stats.var_txwire /= (r_stats.n - 1);
            r_stats.var_rxwire /= (r_stats.n - 1);

            latency_calc(samples, sample_count, &r_stats);
        }
        config->stats = r_stats;
        if (config->flags & FLAG_WAIT) {
            sem_post(&config->stop_sempahore);
        } else {
            config->flags |= FLAG_WAIT;
        }
    }

    rte_delay_us(100);

    free(samples);
}

static int
launch_worker(void *config)
{
    worker_loop((struct pktgen_config *)config);
    return 0;
}
