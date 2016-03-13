static uint16_t gen_pkt_size(struct pktgen_config *config) {
    return (uint16_t) ranval(&config->seed) % (RTE_MAX(config->size_max - config->size_min, 1)) +
        config->size_min;
}

static void stats(double *start_time, struct rate_stats *r_stats, struct pktgen_config *config) {
    double now = get_time_msec();
    double elapsed = (now - *start_time) / 1000;
    double tx_bps = (8 * r_stats->tx_bytes)/elapsed;
    double tx_pps = r_stats->tx_pkts/elapsed;
    double rx_bps = (8 * r_stats->rx_bytes)/elapsed;
    double rx_pps = r_stats->rx_pkts/elapsed;

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
    double wire = ((tx_bps / 1000000) + ((tx_pps / 1000000) * 20 * 8));
    delta = wire - r_stats->avg_txwire;
    r_stats->avg_txwire += delta / r_stats->n;
    r_stats->var_txwire += delta * (wire - r_stats->avg_txwire);

    /* update rx bps mean/var */
    delta = rx_bps / 1000000 - r_stats->avg_rxbps;
    r_stats->avg_rxbps += delta / r_stats->n;
    r_stats->var_rxbps += delta * (rx_bps / 1000000 - r_stats->avg_rxbps);

    /* update rx pps mean/var */
    delta = rx_pps / 1000000 - r_stats->avg_rxpps;
    r_stats->avg_rxpps += delta / r_stats->n;
    r_stats->var_rxpps += delta * (rx_pps / 1000000 - r_stats->avg_rxpps);

    /* update rx wire rate mean/var */
    wire = ((rx_bps / 1000000) + ((rx_pps / 1000000) * 20 * 8));
    delta = wire - r_stats->avg_rxwire;
    r_stats->avg_rxwire += delta / r_stats->n;
    r_stats->var_rxwire += delta * (wire - r_stats->avg_rxwire);

    if (elapsed >= 1.0f) {
	/*printf("tx_pps %.0f rx_pps %.0f\n", tx_pps, rx_pps);*/
        (void)sprintf(config->o_sec, "Core %u: tx_pps: %.0f tx_gbps: %.2f rx_pps: %.0f rx_gbps: %.2f\n",
                rte_lcore_id(), tx_pps, tx_bps/1000000000.0f,
                rx_pps, rx_bps / 1000000000.0f);
        r_stats->rx_pkts = 0;
        r_stats->rx_bytes = 0;
        r_stats->tx_bytes = 0;
        r_stats->tx_pkts = 0;
        *start_time = now;
    }
}

static void latency_calc(double *samples, uint32_t sample_count, struct pktgen_config *config) {
    (void)strncpy(config->o_delay, "%s", 2);
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
    sprintf(config->o_delay,
            "\"rtt_samples\": %u,"
            "\"rtt_mean\": %.2f,"
            "\"rtt_std\": %.2f,"
            "\"rtt_0\": %.2f,"
            "\"rtt_25\": %.2f,"
            "\"rtt_50\": %.2f,"
            "\"rtt_75\": %.2f,"
            "\"rtt_90\": %.2f,"
            "\"rtt_95\": %.2f,"
            "\"rtt_99\": %.2f,"
            "\"rtt_100\": %.2f,",
            sample_count, mean, sqrt(var),
            vals[0], vals[1], vals[2], vals[3],
            vals[4], vals[5], vals[6], vals[7]);
}

static void generate_packet(struct rte_mbuf *buf, struct pktgen_config *config, double *flow_times, uint16_t *flow_ctrs, double now) {
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
    struct udp_hdr *udp_hdr;
    struct tcp_hdr *tcp_hdr;
    uint16_t pkt_size;
    uint64_t flow;
    uint32_t num_flows = config->num_flows;

    struct ether_addr addr;
    rte_eth_macaddr_get(config->port, &addr);

    pkt_size = gen_pkt_size(config);
    buf->pkt_len = pkt_size - 4;
    buf->data_len = pkt_size - 4;
    buf->nb_segs = 1;
    buf->l2_len = sizeof(struct ether_hdr);
    buf->l3_len = sizeof(struct ipv4_hdr);

    eth_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);
    ether_addr_copy(&ether_dst, &eth_hdr->d_addr);
    ether_addr_copy(&addr, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
    memset(ip_hdr, 0, sizeof(*ip_hdr));
    ip_hdr->type_of_service = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = config->proto;
    ip_hdr->packet_id = 0;
    ip_hdr->version_ihl = (1 << 6) + 5;
    ip_hdr->total_length = rte_cpu_to_be_16(pkt_size - 4 - sizeof(*eth_hdr));
    ip_hdr->hdr_checksum = 0;

    flow = num_flows > 0 ? 1 + ranval(&config->seed) % num_flows : 0;
    if (config->flags & FLAG_LIMIT_FLOW_LIFE &&
        now - flow_times[flow] >= randf(&config->seed, config->life_min, config->life_max)) {
        flow_times[flow] = now;
        flow_ctrs[flow]++;
    }
    if (flow_ctrs[flow] == 0) {
        flow_ctrs[flow]++;
    }

    ip_hdr->src_addr = rte_cpu_to_be_32((~config->prefix & (flow_ctrs[flow] * flow * config->ip_min)) | config->prefix);
    ip_hdr->dst_addr = rte_cpu_to_be_32((~config->prefix & (flow_ctrs[flow] * (flow ^ GEN_KEY) * config->ip_min)) | config->prefix);

    ip_hdr->total_length = rte_cpu_to_be_16(pkt_size - 4 - sizeof(*eth_hdr));
    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

    uint16_t sport = rte_cpu_to_be_16(ip_hdr->dst_addr % 0x1111);
    uint16_t dport = rte_cpu_to_be_16((ip_hdr->src_addr % RTE_MAX(config->port_max - config->port_min, 1)) + config->port_min);
    uint8_t *p;
    size_t l4s = 0;

    if (config->proto == 17) {
        udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
        udp_hdr->src_port = sport;
        udp_hdr->dst_port = dport;
        udp_hdr->dgram_cksum = 0;
        udp_hdr->dgram_len = rte_cpu_to_be_16(pkt_size - 4 - sizeof(*eth_hdr) -
                sizeof(*ip_hdr));
        p = rte_pktmbuf_mtod_offset(buf, uint8_t *,
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
                sizeof(struct udp_hdr));
        l4s = sizeof(struct udp_hdr);
    } else {
        tcp_hdr = (struct tcp_hdr *)(ip_hdr + 1);
        tcp_hdr->src_port = sport;
        tcp_hdr->dst_port = dport;
        tcp_hdr->data_off = ((sizeof(struct tcp_hdr) / sizeof(uint32_t)) << 4);
        tcp_hdr->tcp_flags = (1 << 4);
        p = rte_pktmbuf_mtod_offset(buf, uint8_t *,
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
                sizeof(struct tcp_hdr));
        l4s = sizeof(struct tcp_hdr);
    }

    memset(p, 0, pkt_size - 4 - sizeof(*eth_hdr) - sizeof(*ip_hdr) - l4s - 1);
    if (config->flags & FLAG_RANDOMIZE_PAYLOAD) {
        unsigned r = 0;
        while (r < pkt_size - 4 - sizeof(*eth_hdr) - sizeof(*ip_hdr) - l4s - 1) {
            p[r] = (uint8_t)ranval(&config->seed);
            r++;
        }
    }
}

static void generate_traffic(struct rte_mbuf **tx_bufs, struct pktgen_config *config, double *flow_times, uint16_t *flow_ctrs, double now) {
    uint32_t tx_head = 0;

    for (tx_head = 0; tx_head < NUM_PKTS; tx_head++) {
        tx_bufs[tx_head] = rte_pktmbuf_alloc(config->tx_pool);
        generate_packet(tx_bufs[tx_head], config, flow_times, flow_ctrs, now);
    }
}

#define NUM_SAMPLES (10000)
static void worker_loop(struct pktgen_config *config) {
    struct rte_mbuf *tx_bufs[NUM_PKTS];
    uint32_t nb_tx, nb_rx, tx_head, i, sample_count = 0,
             num_samples = NUM_SAMPLES;
    struct rte_mbuf *rx_bufs[NUM_PKTS];
    double now, start_time = get_time_msec(),
           *samples = (double*)malloc(2*num_samples * sizeof(double));
    int64_t burst;
    uint64_t total_rx = 0;

    struct rate_stats r_stats = {
        .n = 0,
        .avg_rxpps = 0,  .var_rxpps = 0,
        .avg_rxbps = 0,  .var_rxbps = 0,
        .avg_txpps = 0,  .var_txpps = 0,
        .avg_txbps = 0,  .var_txbps = 0,
        .avg_txwire = 0, .var_txwire = 0,
        .avg_rxwire = 0, .var_rxwire = 0,
        .tx_bytes = 0,   .tx_pkts = 0,
        .rx_bytes = 0,   .rx_pkts = 0
    };

    while (config->flags & FLAG_WAIT) {
        rte_delay_us(1);
    }

    double flow_times[config->num_flows + 1];
    uint16_t flow_ctrs[config->num_flows + 1];
    memset(flow_times, 0, sizeof(double) * config->num_flows);
    memset(flow_ctrs, 0, sizeof(uint16_t) * config->num_flows);

    generate_traffic(tx_bufs, config, flow_times, flow_ctrs, 0);

    memset(samples, 0, sizeof(samples[0]) * 2 * num_samples);

    printf("\nCore %u running.\n", rte_lcore_id());

    /* Flush the RX queue */
    printf("Core %u: Flusing port %u RX queue\n", rte_lcore_id(), config->port);
    while (rte_eth_rx_queue_count(config->port, 0) > 0) {
        nb_rx = rte_eth_rx_burst(config->port, 0, rx_bufs, config->rx_ring_size);
        for (i = 0; i < nb_rx; i++) {
            rte_pktmbuf_free(rx_bufs[i]);
        }
        rte_delay_us(10);
    }

    for (;;) {
        while (config->flags & FLAG_WAIT) {
            rte_delay_us(1);
        }

        config->start_time = get_time_msec();
        tx_head = 0;
        while (!(config->flags & FLAG_WAIT) && unlikely((now = get_time_msec()) - config->start_time < config->duration)) {
            if (now - config->start_time > config->warmup) {
                stats(&start_time, &r_stats, config);
            }

            uint64_t exp_bytes = ((now - start_time) / 1000) * config->tx_rate * 1000000 / 8;
            int64_t avg_pkt = (r_stats.tx_bytes + 1) / (r_stats.tx_pkts + 1);
            burst = (exp_bytes - r_stats.tx_bytes);
            burst /= avg_pkt;
            burst = RTE_MIN(burst, (unsigned)BURST_SIZE);
            burst = RTE_MAX((unsigned)0, burst);

            nb_rx = rte_eth_rx_burst(config->port, 0, rx_bufs, config->rx_ring_size);

            for (i = 0; i < nb_rx; i++) {
/*#if 0*/
                struct ether_addr addr;
                rte_eth_macaddr_get(config->port, &addr);
                struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(rx_bufs[i], struct ether_hdr *);

                if (!is_same_ether_addr(&addr, &eth_hdr->d_addr)) {
                    rte_pktmbuf_free(rx_bufs[i]);
                    continue;
                }
/*#endif*/

                r_stats.rx_bytes += rx_bufs[i]->pkt_len;
                if (config->flags & FLAG_MEASURE_LATENCY) {
                    uint64_t idx = 0;
                    if ((idx = total_rx) < num_samples || (idx = ranval(&config->seed) % total_rx) < num_samples)  {
                        double *p = rte_pktmbuf_mtod_offset(rx_bufs[i], double *,
                                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
                                sizeof(struct udp_hdr));
                        if (*p > 0) {
                            samples[idx] = (now - *p) / 1000;
                            sample_count = RTE_MIN(num_samples, sample_count + 1);
                        }
                    }
                    total_rx++;
                }
                rte_pktmbuf_free(rx_bufs[i]);
		r_stats.rx_pkts ++;
            }

            /*r_stats.rx_pkts += nb_rx;*/

            if (unlikely(tx_head + burst >= NUM_PKTS)) {
                tx_head = 0;
            }

            now = get_time_msec();
            uint32_t lens[burst];
            for (i = 0; i < burst; i++) {
                if (config->flags & FLAG_GENERATE_ONLINE) {
                    generate_packet(tx_bufs[tx_head + i], config, flow_times, flow_ctrs, now);
                }

                if (config->flags & FLAG_MEASURE_LATENCY) {
                    double *p = rte_pktmbuf_mtod_offset(tx_bufs[tx_head + i], double *,
                            sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
                            sizeof(struct udp_hdr));
                    *p = now;
                }

                lens[i] = tx_bufs[tx_head + i]->pkt_len;
                if (config->flags & FLAG_GENERATE_ONLINE) {
                    rte_prefetch0(rte_pktmbuf_mtod(tx_bufs[(tx_head + i + 1) % NUM_PKTS], void*));
                }
            }

            nb_tx = rte_eth_tx_burst(config->port, 0, tx_bufs + tx_head, burst);

            for (i = 0; i < nb_tx; i++) {
                r_stats.tx_bytes += lens[i];
                tx_bufs[tx_head + i] = rte_pktmbuf_alloc(config->tx_pool);
            }
            r_stats.tx_pkts += nb_tx;

            tx_head += nb_tx;
            tx_head %= NUM_PKTS;
        }

        if (r_stats.n > 0 && sample_count > 0) {
            r_stats.var_txpps /= (r_stats.n - 1); r_stats.var_rxpps /= (r_stats.n - 1);
            r_stats.var_txbps /= (r_stats.n - 1); r_stats.var_rxbps /= (r_stats.n - 1);
            r_stats.var_txwire /= (r_stats.n - 1); r_stats.var_rxwire /= (r_stats.n - 1);

            latency_calc(samples, sample_count, config);
            (void)sprintf(config->o_xput,
                    "\"tx_mpps_mean\": %9.6f,"
                    "\"tx_mpps_std\": %9.6f,"
                    "\"tx_mbps_mean\": %9.6f,"
                    "\"tx_mbps_std\": %9.6f,"
                    "\"tx_wire_mean\": %9.6f,"
                    "\"tx_wire_std\": %9.6f,\n    "
                    "\"rx_mpps_mean\": %9.6f,"
                    "\"rx_mpps_std\": %9.6f,"
                    "\"rx_mbps_mean\": %9.6f,"
                    "\"rx_mbps_std\": %9.6f,"
                    "\"rx_wire_mean\": %9.6f,"
                    "\"rx_wire_std\": %9.6f",
                    r_stats.avg_txpps, sqrt(r_stats.var_txpps),
                    r_stats.avg_txbps, sqrt(r_stats.var_txbps),
                    r_stats.avg_txwire, sqrt(r_stats.var_txwire),
                    r_stats.avg_rxpps, sqrt(r_stats.var_rxpps),
                    r_stats.avg_rxbps, sqrt(r_stats.var_rxbps),
                    r_stats.avg_rxwire, sqrt(r_stats.var_rxwire));
        }

        config->flags |= FLAG_WAIT; 
    }

    rte_delay_us(100);

    for (i = 0; i < NUM_PKTS; i++) {
        rte_pktmbuf_free(tx_bufs[i]);
        rte_pktmbuf_free(rx_bufs[i]);
    }

    free(samples);
}

static int launch_worker(void *config) {
    worker_loop((struct pktgen_config*)config);
    return 0;
}
