#include "pktgen.h"
#include "pktgen_worker.c"

static inline int port_init(uint8_t port, struct pktgen_config *config UNUSED) {
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    int retval;
    uint16_t q;
    char name[7];

    rte_eth_dev_stop(port); 

    snprintf(name, sizeof(name), "RX%02u:%02u", port, (unsigned)0);
    struct rte_mempool *rx_mp = rte_pktmbuf_pool_create(name, GEN_DEFAULT_RX_RING_SIZE,
            0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
    if (rx_mp == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create RX mbuf pool: %s\n", rte_strerror(rte_errno));
    }

    snprintf(name, sizeof(name), "TX%02u:%02u", port, (unsigned)0);
    struct rte_mempool *tx_mp = rte_pktmbuf_pool_create(name, NUM_PKTS,
            0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
    if (tx_mp == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create TX mbuf pool: %s\n", rte_strerror(rte_errno));
    }

    if (port >= rte_eth_dev_count()) {
        return -1;
    }

    if (rte_eth_dev_configure(port, 1, 1, &port_conf) != 0) {
        rte_exit(EXIT_FAILURE, "Error with port configuration: %s\n", rte_strerror(rte_errno));
    }

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, GEN_DEFAULT_RX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL, rx_mp);
        if (retval != 0) {
            return retval;
        }
    }

    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, GEN_DEFAULT_TX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL);
        if (retval != 0) {
            return retval;
        }
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0) {
        return retval;
    }

    /* Display the port MAC address. */
    struct ether_addr addr;
    rte_eth_macaddr_get(port, &addr);
    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
            " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            (unsigned)port,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(port);

    return 0;
}

static int lcore_init(void *arg) {
    struct pktgen_config *config = (struct pktgen_config*)arg;
    unsigned port = config->port;
    char name[7];

    printf("Init core %d\n", rte_lcore_id());

    config->seed.a = 1;
    config->seed.b = 2;
    config->seed.c = 3;
    config->seed.d = 4;
    raninit(&config->seed, (u8) get_time_sec());

    snprintf(name, sizeof(name), "RX%02u:%02u", port, (unsigned)0);
    config->rx_pool = rte_mempool_lookup(name);

    if (config->rx_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create RX mbuf pool: %s\n", rte_strerror(rte_errno));
    }

    snprintf(name, sizeof(name), "%s%02u:%02u", "TX", port, (unsigned)0);
    config->tx_pool = rte_mempool_lookup(name);

    if (config->tx_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create TX mbuf pool: %s\n", rte_strerror(rte_errno));
    }

    return 0;
}

static void usage(void) {
    printf("tgen> [-r] [-l] -m M -t T -w W -n N -s MIN[-MAX]\n"
            "Traffic Gen Options and Flags\n"
            "\t-m M          Transmit at M mpbs\n"
            "\t-t T          Generate traffic for T seconds\n"
            "\t-w W          Warmup for W seconds before generating traffic\n"
            "\t-n N          Generate a uniform distribution of N flows\n"
            "\t-s MIN[-MAX]  Genearte packets with sizes in [MIN,MAX] (or only of size MIN if MAX isn't specified)\n"
            "\t-r            Randomize packet payloads\n"
            "\t-l            Measure latency\n");
}

static int pktgen_parse_args(int argc, char *argv[], struct pktgen_config *cfg) {
    int c, n = 0;
    char *p, *q;
    optind = 1;
    while ((c = getopt (argc, argv, "rlm:t:w:n:s:")) != -1) {
        switch (c) {
            case 'r':
                cfg->flags |= FLAG_RANDOMIZE_PAYLOAD;
                break;
            case 'l':
                cfg->flags |= FLAG_MEASURE_LATENCY;
                break;
            case 'm':
                cfg->tx_rate = atoi(optarg);
                n++;
                break;
            case 't':
                cfg->duration = atoi(optarg);
                n++;
                break;
            case 'w':
                cfg->warmup = atoi(optarg);
                n++;
                break;
            case 'n':
                cfg->num_flows = atoi(optarg);
                n++;
                break;
            case 's':
                p = optarg;
                q = strtok(p, "-");
                if (q == NULL) {
                    return -1;
                }
                cfg->size_min = atoi(q);

                q = strtok(NULL, "-");
                if (q == NULL) {
                    cfg->size_max = cfg->size_min;
                } else {
                    cfg->size_max = atoi(q);
                }
                n++;
                break;
            default:
                return -1;
        }
    }
    if (n < 5) {
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    uint8_t nb_ports, port, nb_cores, core; 
    struct rte_mempool *mp UNUSED;
    struct pktgen_config cmd;
    char *icmd;

    /* Initialize EAL */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        usage();
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    nb_ports = rte_eth_dev_count();
    nb_cores = rte_lcore_count();
    uint8_t port_map[nb_cores];

    core = 0;
    for (port = 0; port < nb_ports; port++) {
        if (port_init(port, NULL) != 0) {
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n", port);
        }
        port_map[core++] = port;
    }

    /* Parse pktgen command line */
    ret = read_history(HISTORY_FILE);
    signal(SIGINT, sig_handler);
    while ((icmd = readline("tgen> ")) != NULL) {
        add_history(icmd);
        cmd.size_min = 0;
        cmd.size_max = 0;
        cmd.num_flows = 0;
        cmd.warmup = 0;
        cmd.duration = 0;
        cmd.tx_rate = 0;
        cmd.flags = 0;
        cmd.rx_ring_size = GEN_DEFAULT_RX_RING_SIZE;
        cmd.tx_ring_size = GEN_DEFAULT_TX_RING_SIZE;

        char *p, *q;
        char *cmd_argv[20], tcmd[1024];
        int cmd_argc = 1;

        if (sprintf(tcmd, "tgen %s", icmd) < 0) {
            continue;
        }
        p = tcmd;

        cmd_argv[cmd_argc++] = (q = strtok(p, " "));
        if (q == NULL) {
            usage();
            continue;
        }

        while ((q = strtok(NULL, " ")) != NULL) {
            cmd_argv[cmd_argc++] = q;
        }

        ret = pktgen_parse_args(cmd_argc, cmd_argv, &cmd);
        if (ret < 0) {
            usage();
            continue;
        }

        /* Launch generator */
        int i;
        core = 0;
        port = 0;
        struct pktgen_config config[nb_cores];
        RTE_LCORE_FOREACH_SLAVE(i) {
            if (port == nb_ports) {
                break;
            }
            config[i].tx_rate = cmd.tx_rate;
            config[i].warmup = cmd.warmup;
            config[i].duration = cmd.duration;
            config[i].num_flows = cmd.num_flows;
            config[i].ip_min = 0xFFFFFF00;
            config[i].udp_min = 0xFF00;
            config[i].size_min = cmd.size_min;
            config[i].size_max = cmd.size_max;
            config[i].port = port_map[core];
            config[i].rx_ring_size = cmd.rx_ring_size;
            config[i].tx_ring_size = cmd.tx_ring_size;
            config[i].flags = cmd.flags;

            rte_eal_remote_launch(lcore_init, (void*)&config[i], i);
            rte_eal_wait_lcore(i);
            rte_eal_remote_launch(launch_worker, (void*)&config[i], i);
            core++;
        }

        rte_eal_mp_wait_lcore();

        RTE_LCORE_FOREACH_SLAVE(i) {
            printf("Core %u: Results\n{%s\n    %s}\n", i, config[i].o_delay, config[i].o_xput);
        }
    }
    ret = write_history(HISTORY_FILE);
    printf("\n");
    return 0;
}
