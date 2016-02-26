static uint16_t gen_pkt_size(struct pktgen_config *config) {
    return (uint16_t) ranval(&config->seed) % (RTE_MAX(config->size_max - config->size_min, 1)) +
        config->size_min;
}

static void stats(double *start_time, struct rate_stats *r_stats) {
    double now = get_time_sec();
    double elapsed = now - *start_time;
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
        printf("Core %u: tx_pps: %.0f tx_gbps: %.2f rx_pps: %.0f rx_gbps: %.2f\n",
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

static void generate_traffic(struct rte_mbuf **tx_bufs, struct pktgen_config *config) {
    struct rte_mbuf *buf;
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
    struct udp_hdr *udp_hdr;
    uint16_t pkt_size;
    uint64_t flow, key;
    uint32_t tx_head = 0;

    key = ranval(&config->seed) % config->num_flows;
    for (tx_head = 0; tx_head < NUM_PKTS; tx_head++) {
        tx_bufs[tx_head] = rte_pktmbuf_alloc(config->tx_pool);
        buf = tx_bufs[tx_head];
        pkt_size = gen_pkt_size(config);
        buf->pkt_len = pkt_size - 4;
        buf->data_len = pkt_size - 4;
        buf->nb_segs = 1;
        buf->l2_len = sizeof(struct ether_hdr);
        buf->l3_len = sizeof(struct ipv4_hdr);

        eth_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);
        ether_addr_copy(&ether_dst, &eth_hdr->d_addr);
        ether_addr_copy(&ether_src, &eth_hdr->s_addr);
        eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

        ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
        memset(ip_hdr, 0, sizeof(*ip_hdr));
        ip_hdr->type_of_service = 0;
        ip_hdr->fragment_offset = 0;
        ip_hdr->time_to_live = 64;
        ip_hdr->next_proto_id = 17;
        ip_hdr->packet_id = 0;
        ip_hdr->version_ihl = (1 << 5) + 5;
        ip_hdr->hdr_checksum = 0;

        flow = ranval(&config->seed) % config->num_flows;
        ip_hdr->src_addr = rte_cpu_to_be_32(flow * config->ip_min / config->num_flows);
        ip_hdr->dst_addr = rte_cpu_to_be_32((flow ^ key) * config->ip_min / config->num_flows);
        ip_hdr->total_length = rte_cpu_to_be_16(pkt_size - 4 - sizeof(*eth_hdr));
        ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

        udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
        udp_hdr->src_port = rte_cpu_to_be_16(ip_hdr->src_addr % config->udp_min);
        udp_hdr->dst_port = rte_cpu_to_be_16(ip_hdr->dst_addr % config->udp_min);
        udp_hdr->dgram_cksum = 0;
        udp_hdr->dgram_len = rte_cpu_to_be_16(pkt_size - 4 - sizeof(*eth_hdr) -
                sizeof(*ip_hdr));
        uint8_t *p = rte_pktmbuf_mtod_offset(buf, uint8_t *,
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
                sizeof(struct udp_hdr));
        memset(p, 0, pkt_size - 4 - sizeof(*eth_hdr) - sizeof(*ip_hdr) - sizeof(*udp_hdr) - 1); 
        if (config->flags & FLAG_RANDOMIZE_PAYLOAD) {
            unsigned r = 0;
            while (r < pkt_size - 4 - sizeof(*eth_hdr) - sizeof(*ip_hdr) - sizeof(*udp_hdr) - 1) {
                p[r] = (uint8_t)ranval(&config->seed);
                r++;
            }
        }
    }
}

static void worker_loop(struct pktgen_config *config) {
    struct rte_mbuf *tx_bufs[NUM_PKTS];
    uint32_t nb_tx, nb_rx, tx_head, i,
             tx_rate = config->tx_rate, sample_count = 0,
             num_samples = (tx_rate * 1000000 * config->duration) / (84 * 8);
    struct rte_mbuf *rx_bufs[config->rx_ring_size] UNUSED;
    double now, start_time = get_time_sec(),
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

    struct pktgen_config cfg;
    cfg.port = config->port;
    cfg.role = config->role;
    cfg.tx_rate = config->tx_rate;
    cfg.warmup = config->warmup;
    cfg.duration = config->duration;
    cfg.num_flows = config->num_flows;
    cfg.ip_min = config->ip_min;
    cfg.udp_min = config->udp_min;
    cfg.size_min = config->size_min;
    cfg.size_max = config->size_max;
    cfg.seed = config->seed;
    cfg.rx_pool = config->rx_pool;
    cfg.tx_pool = config->tx_pool;
    cfg.rx_ring_size = config->rx_ring_size;
    cfg.tx_ring_size = config->tx_ring_size;
    cfg.flags = config->flags;

    generate_traffic(tx_bufs,config);

    memset(samples, 0, sizeof(samples[0]) * 2 * num_samples);

    printf("\nCore %u running.\n", rte_lcore_id());

    /* Flush the RX queue */
    printf("Core %u: Flusing port %u RX queue\n", rte_lcore_id(), cfg.port);
    while (rte_eth_rx_queue_count(cfg.port, 0) > 0) {
        nb_rx = rte_eth_rx_burst(cfg.port, 0, rx_bufs, cfg.rx_ring_size);
        for (i = 0; i < nb_rx; i++) {
            rte_pktmbuf_free(rx_bufs[i]);
        }
        rte_delay_us(10);
    }

    cfg.start_time = get_time_sec();
    tx_head = 0;
    while (unlikely((now = get_time_sec()) - cfg.start_time < cfg.duration)) {
        if (now - cfg.start_time > cfg.warmup) {
            stats(&start_time, &r_stats);
        }

        uint64_t exp_bytes = (now - start_time) * tx_rate * 1000000 / 8;
        int64_t avg_pkt = (r_stats.tx_bytes + 1) / (r_stats.tx_pkts + 1);
        burst = (exp_bytes - r_stats.tx_bytes);
        burst /= avg_pkt;
        burst = RTE_MIN(burst, (unsigned)BURST_SIZE);
        burst = RTE_MAX((unsigned)0, burst);

        nb_rx = rte_eth_rx_burst(cfg.port, 0, rx_bufs, cfg.rx_ring_size);

        for (i = 0; i < nb_rx; i++) {
            r_stats.rx_bytes += rx_bufs[i]->pkt_len;
            if (cfg.flags & FLAG_MEASURE_LATENCY) {
                if (!(total_rx % 100)) {
                    double *p = rte_pktmbuf_mtod_offset(rx_bufs[i], double *,
                            sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
                            sizeof(struct udp_hdr));
                    if (*p > 0) {
                        samples[sample_count++] = now - *p;
                    }
                }
                total_rx++;
            }
            rte_pktmbuf_free(rx_bufs[i]);
        }

        r_stats.rx_pkts += nb_rx;

        if (unlikely(tx_head + burst > NUM_PKTS)) {
            tx_head = 0;
        }

        if (cfg.flags & FLAG_MEASURE_LATENCY) {
            now = get_time_sec();
            for (i = 0; i < burst; i++) {
                double *p = rte_pktmbuf_mtod_offset(tx_bufs[tx_head + i], double *,
                        sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +
                        sizeof(struct udp_hdr));
                *p = now;
            }
        }

        nb_tx = rte_eth_tx_burst(cfg.port, 0, tx_bufs + tx_head, burst);

        for (i = 0; i < nb_tx; i++) {
            r_stats.tx_bytes += tx_bufs[tx_head + i]->pkt_len;
        }
        r_stats.tx_pkts += nb_tx;

        tx_head += nb_tx;
        tx_head %= NUM_PKTS;
    }

    rte_delay_us(100);
    for (i = 0; i < NUM_PKTS; i++) {
        rte_pktmbuf_free(tx_bufs[i]);
    }

    for (i = 0; i < cfg.rx_ring_size; i++) {
        rte_pktmbuf_free(rx_bufs[i]);
    }

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

    free(samples);
}

static int launch_worker(void *config) {
    worker_loop((struct pktgen_config*)config);
    return 0;
}
