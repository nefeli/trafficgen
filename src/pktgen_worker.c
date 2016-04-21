#include "pktgen.h"

static inline void
init_mbuf(struct rte_mbuf *buf, struct pktgen_config *config)
{
    buf->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
    buf->l2_len = sizeof(struct ether_hdr);
    buf->l3_len = sizeof(struct ipv4_hdr);
    buf->l4_len = sizeof(struct udp_hdr);

    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
    struct udp_hdr *udp_hdr;
    struct tcp_hdr *tcp_hdr;
    uint16_t pkt_size = 60;

    buf->pkt_len = pkt_size;
    buf->data_len = pkt_size;

    eth_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);
    memset((void *)eth_hdr, 0, MAX_PKT_SIZE);
    if (is_zero_ether_addr(&config->dst_mac)) {
        ether_addr_copy(&ether_dst, &eth_hdr->d_addr);
    } else {
        ether_addr_copy(&config->dst_mac, &eth_hdr->d_addr);
    }

    if (is_zero_ether_addr(&config->src_mac)) {
        ether_addr_copy(&config->port_mac, &eth_hdr->s_addr);
    } else {
        ether_addr_copy(&config->src_mac, &eth_hdr->s_addr);
    }
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
    ip_hdr->type_of_service = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = config->proto;
    ip_hdr->packet_id = 0;
    ip_hdr->version_ihl = (1 << 6) + 5;
    ip_hdr->total_length =
        rte_cpu_to_be_16(pkt_size - sizeof(struct ether_hdr));
    ip_hdr->src_addr = 0xAABB;
    ip_hdr->dst_addr = 0xCCDD;
    ip_hdr->hdr_checksum = 0;

    if (config->proto == IPPROTO_UDP) {
        udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
        udp_hdr->src_port = 0xAABB;
        udp_hdr->dst_port = 0xCCDD;
        udp_hdr->dgram_cksum = 0;
        udp_hdr->dgram_len = rte_cpu_to_be_16(
            pkt_size - sizeof(struct ether_hdr) - sizeof(*ip_hdr));
    } else {
        tcp_hdr = (struct tcp_hdr *)(ip_hdr + 1);
        tcp_hdr->data_off = ((sizeof(struct tcp_hdr) / sizeof(uint32_t)) << 4);
        tcp_hdr->src_port = 0xAABB;
        tcp_hdr->dst_port = 0xCCDD;
        tcp_hdr->tcp_flags = (1 << 4);
    }
}

static inline void
init_mempool(struct pktgen_config *config)
{
    unsigned i, size = rte_mempool_count(config->tx_pool);
    struct rte_mbuf *bufs[size];
    if (rte_mempool_sc_get_bulk(config->tx_pool, (void **)bufs, size) != 0)
        rte_panic("couldn't allocate all mbufs from tx pool");

    for (i = 0; i < size; i++) init_mbuf(bufs[i], config);

    rte_mempool_sp_put_bulk(config->tx_pool, (void **)bufs, size);
}

static inline void
update_stats(struct pktgen_config *config UNUSED, struct rate_stats *s,
             double elapsed_sec)
{
    double tx_bps = (8 * s->tx_bytes) / elapsed_sec;
    double tx_pps = s->tx_pkts / elapsed_sec;
    double rx_bps = (8 * s->rx_bytes) / elapsed_sec;
    double rx_pps = s->rx_pkts / elapsed_sec;
    double txwire, rxwire;

    s->n++;
    /* update tx bps mean/var */
    double delta = tx_bps - s->avg_txbps;
    s->avg_txbps += delta / s->n;
    s->var_txbps += delta * (tx_bps - s->avg_txbps);

    /* update tx pps mean/var */
    delta = tx_pps - s->avg_txpps;
    s->avg_txpps += delta / s->n;
    s->var_txpps += delta * (tx_pps - s->avg_txpps);

    /* update tx wire rate mean/var */
    txwire = tx_bps + tx_pps * ETH_OVERHEAD * 8;
    delta = txwire - s->avg_txwire;
    s->avg_txwire += delta / s->n;
    s->var_txwire += delta * (txwire - s->avg_txwire);

    /* update rx bps mean/var */
    delta = rx_bps - s->avg_rxbps;
    s->avg_rxbps += delta / s->n;
    s->var_rxbps += delta * (rx_bps - s->avg_rxbps);

    /* update rx pps mean/var */
    delta = rx_pps - s->avg_rxpps;
    s->avg_rxpps += delta / s->n;
    s->var_rxpps += delta * (rx_pps - s->avg_rxpps);

    /* update rx wire rate mean/var */
    rxwire = rx_bps + rx_pps * ETH_OVERHEAD * 8;
    delta = rxwire - s->avg_rxwire;
    s->avg_rxwire += delta / s->n;
    s->var_rxwire += delta * (rxwire - s->avg_rxwire);

    s->rx_pkts = 0;
    s->rx_bytes = 0;
    s->tx_bytes = 0;
    s->tx_pkts = 0;

#if GEN_DEBUG
    syslog(LOG_INFO,
           "[lcore=%d] rx/tx stats: mpps=%.3f/%.3f wire_mbps=%.1f/%.1f\n",
           config->lcore_id, rx_pps / 1000000, tx_pps / 1000000,
           rxwire / 1000000, txwire / 1000000);
#endif
}

static inline void
latency_calc(struct rate_stats *r_stats)
{
    uint32_t nb_samples = r_stats->nb_samples % NUM_SAMPLES;
    double *samples = r_stats->samples;
    qsort(samples, nb_samples, sizeof(samples[0]), double_compare);
    uint32_t i, j = 0;
    double labels[8] = {0.0f, 0.25f, 0.5f, 0.75f, 0.9f, 0.95f, 0.99f, 1.0f};
    double vals[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    double delta, mean = 0, var = 0;
    for (j = 0; j < 8; j++) {
        i = RTE_MIN(nb_samples - 1, (uint32_t)(labels[j] * nb_samples));
        vals[j] = samples[i] * 1000000.0f;
    }

    for (i = 0; i < nb_samples; i++) {
        delta = samples[i] * 1000000.0f - mean;
        mean += delta / (i + 1);
        var += delta * (samples[i] * 1000000.0f - mean);
    }

    var /= nb_samples - 1;

    r_stats->rtt_n = nb_samples;
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

static inline uint16_t
generate_packet(struct rte_mbuf *buf, struct rate_stats *r_stats,
                struct pktgen_config *config, double now)
{
    return 60;
    uint32_t rnd = rand_fast(&config->seed);
    uint16_t pkt_size = config->size_min +
                        rnd % (RTE_MAX(config->size_max - config->size_min, 1));
    buf->pkt_len = pkt_size;
    buf->data_len = pkt_size;

    uint64_t flow = 1 + rnd % config->num_flows;
    if (unlikely(config->flags & FLAG_LIMIT_FLOW_LIFE &&
                 now - r_stats->flow_times[flow] >=
                     to_double(rnd, config->life_min, config->life_max))) {
        r_stats->flow_times[flow] = now;
        r_stats->flow_ctrs[flow]++;
    }
    flow *= 1 + r_stats->flow_ctrs[flow];

    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
    struct udp_hdr *udp_hdr;
    struct tcp_hdr *tcp_hdr;
    uint8_t *ptr, *end;

    eth_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);
    ;
    ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
    ip_hdr->total_length =
        rte_cpu_to_be_16(pkt_size - sizeof(struct ether_hdr));
    // no need for rte_cpu_to_be_32 since this is random anyways
    ip_hdr->src_addr = flow * config->ip_min;
    ip_hdr->dst_addr = (flow ^ GEN_KEY) * config->ip_min;

    uint16_t sport = ip_hdr->dst_addr % 0x1111;
    uint16_t dport =
        (ip_hdr->src_addr % RTE_MAX(config->port_max - config->port_min, 1)) +
        config->port_min;

    if (config->proto == IPPROTO_UDP) {
        udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
        udp_hdr->src_port = sport;
        udp_hdr->dst_port = dport;
        // udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(ip_hdr, buf->ol_flags);
        udp_hdr->dgram_len = rte_cpu_to_be_16(
            pkt_size - sizeof(struct ether_hdr) - sizeof(*ip_hdr));
        ptr = (uint8_t *)(udp_hdr + 1);
    } else {
        tcp_hdr = (struct tcp_hdr *)(ip_hdr + 1);
        tcp_hdr->src_port = sport;
        tcp_hdr->dst_port = dport;
        ptr = (uint8_t *)(tcp_hdr + 1);
    }

    end = (uint8_t *)eth_hdr + pkt_size;
    if (config->flags & FLAG_RANDOMIZE_PAYLOAD) {
        for (; ptr < end - pkt_size % sizeof(uint32_t); ptr += sizeof(uint32_t))
            *(uint32_t *)ptr = rand_fast(&config->seed);
        // FIXME: last 1-3 bytes may be uninitialized
    }

    return pkt_size;
}

static inline uint16_t
do_rx(struct pktgen_config *config, struct rate_stats *r_stats, double now)
{
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t i, nb_rx;
    uint64_t idx;

    nb_rx = rte_eth_rx_burst(config->port_id, 0, bufs, BURST_SIZE);

    for (i = 0; i < nb_rx; i++) {
        r_stats->rx_bytes += bufs[i]->pkt_len;
        if (config->flags & FLAG_MEASURE_LATENCY) {
            idx = 0;
            if ((idx = r_stats->nb_samples) < NUM_SAMPLES ||
                (idx = rand_fast(&config->seed) % r_stats->nb_samples) <
                    NUM_SAMPLES) {
                uint8_t *p = rte_pktmbuf_mtod_offset(
                    bufs[i], uint8_t *, sizeof(struct ether_hdr) +
                                            sizeof(struct ipv4_hdr) +
                                            sizeof(struct udp_hdr));
                double *ts = (double *)(p + 1);
                if (*p == config->run_id && *ts > 0) {
                    r_stats->samples[idx] = (now - *ts) / 1000;
                    r_stats->nb_samples++;
                } else {
                    syslog(
                        LOG_ERR,
                        "[port=%d] received packet from run %d instead of %d",
                        config->port_id, *p, config->run_id);
                }
            }
        }
    }

    r_stats->rx_pkts += nb_rx;
    rte_mempool_sp_put_bulk(config->rx_pool, (void **)bufs, nb_rx);

    return nb_rx;
}

static inline uint16_t
do_tx(struct pktgen_config *config, struct rate_stats *r_stats,
      double elapsed_current, double now UNUSED)
{
    struct rte_mbuf *bufs[BURST_SIZE];
    uint32_t pktlen_sum[BURST_SIZE + 1];
    uint64_t exp_bytes = elapsed_current * config->tx_rate * 1000 / 8;
    uint16_t nb_tx, i;
    int burst = (exp_bytes - r_stats->tx_bytes) /
                ((r_stats->tx_bytes + 1) / (r_stats->tx_pkts + 1));
    burst = RTE_MIN(burst, BURST_SIZE);

    if (unlikely(burst == 0 ||
                 rte_mempool_sc_get_bulk(config->tx_pool, (void **)bufs,
                                         burst) != 0))
        return 0;

    pktlen_sum[0] = 0;
    for (i = 0; i < burst; i++) {
        struct rte_mbuf *buf = bufs[i];
        buf->refcnt = 1;

        uint16_t pkt_size = generate_packet(buf, r_stats, config, now);
        pktlen_sum[i + 1] = pkt_size + pktlen_sum[i];

        if (config->flags & FLAG_MEASURE_LATENCY) {
            uint8_t *p = rte_pktmbuf_mtod_offset(bufs[i], uint8_t *,
                                                 sizeof(struct ether_hdr) +
                                                     sizeof(struct ipv4_hdr) +
                                                     sizeof(struct udp_hdr));
            p[0] = config->run_id;
            *(double *)(p + 1) = now;
        }
    }
    nb_tx = rte_eth_tx_burst(config->port_id, 0, bufs, burst);

    if (unlikely(nb_tx < burst)) {
        rte_mempool_sp_put_bulk(bufs[nb_tx]->pool, (void **)&bufs[nb_tx],
                                burst - nb_tx);
    }

    r_stats->tx_bytes += nb_tx * 60;  // pktlen_sum[nb_tx];
    r_stats->tx_pkts += nb_tx;

    return nb_tx;
}

static inline void
reset_stats(struct pktgen_config *config, struct rate_stats *r_stats)
{
    memset(r_stats, 0, offsetof(struct rate_stats, flow_ctrs));
    r_stats->samples =
        rte_realloc(r_stats->samples, sizeof(double) * NUM_SAMPLES, 0);
    r_stats->flow_ctrs = rte_realloc(
        r_stats->flow_ctrs, sizeof(uint16_t) * (config->num_flows + 1), 0);
    r_stats->flow_times = rte_realloc(
        r_stats->flow_times, sizeof(double) * (config->num_flows + 1), 0);
    memset(r_stats->flow_times, 0, sizeof(double) * (config->num_flows + 1));
    memset(r_stats->flow_ctrs, 0, sizeof(uint16_t) * (config->num_flows + 1));
    memset(r_stats->samples, 0, sizeof(double) * NUM_SAMPLES);

    if (r_stats->flow_ctrs == NULL || r_stats->flow_times == NULL) {
        rte_panic("couldn't allocate flow counters");
    }
}

static void
worker_loop(struct pktgen_config *config)
{
    uint32_t i;
    struct rte_mbuf *bufs[BURST_SIZE];
    double now, start_time, elapsed_total, elapsed_current;
    struct rate_stats *r_stats =
        rte_malloc("rate_stats", sizeof(struct rate_stats), 0);
    int reset_pending;

    config->run_id = 0;

    for (;;) {
        while (config->flags & FLAG_WAIT) {
            usleep(1000);
        }

        // Transitioning from start to stop.
        init_mempool(config);
        reset_stats(config, r_stats);

        reset_pending = 1;
        config->run_id++;
        config->start_time = get_time_msec();
        start_time = config->start_time;
        now = config->start_time;

        /* Drain the RX queue */
        while (do_rx(config, r_stats, now) > 0) {
            rte_delay_us(100);
        }

        for (;;) {
            now = get_time_msec();
            elapsed_total = now - config->start_time;
            elapsed_current = now - start_time;

            if (unlikely((config->flags & FLAG_WAIT) ||
                         elapsed_total > config->duration)) {
                break;
            } else if (unlikely(reset_pending &&
                                elapsed_total > config->warmup)) {
                start_time = now;
                reset_pending = 0;
                reset_stats(config, r_stats);
            } else if (unlikely(elapsed_current > 500)) {
                update_stats(config, r_stats, elapsed_current / 1000);
                start_time = now;
                elapsed_current = 0;
            }
            uint8_t nb_tx = 1, nb_rx = 1;

            while (nb_rx-- && do_rx(config, r_stats, now) > 0)
                ;
            while (nb_tx-- && do_tx(config, r_stats, elapsed_current, now) > 0)
                ;
        }

        // Transitions from run to stop
        if (r_stats->n > 0 && r_stats->nb_samples > 0) {
            r_stats->var_txpps /= (r_stats->n - 1);
            r_stats->var_rxpps /= (r_stats->n - 1);
            r_stats->var_txbps /= (r_stats->n - 1);
            r_stats->var_rxbps /= (r_stats->n - 1);
            r_stats->var_txwire /= (r_stats->n - 1);
            r_stats->var_rxwire /= (r_stats->n - 1);

            latency_calc(r_stats);
        }

        config->stats = *r_stats;

        if (config->flags & FLAG_WAIT) {
            sem_post(&config->stop_sempahore);
        } else {
            config->flags |= FLAG_WAIT;
        }
    }

    rte_delay_us(100);

    for (i = 0; i < BURST_SIZE; i++) {
        if (bufs[i])
            rte_pktmbuf_free(bufs[i]);
    }

    rte_free(r_stats->samples);
    rte_free(r_stats->flow_ctrs);
    rte_free(r_stats->flow_times);
    rte_free(r_stats);
}

static int
launch_worker(void *config)
{
    worker_loop((struct pktgen_config *)config);
    return 0;
}
