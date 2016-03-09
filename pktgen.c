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
    printf("tgen> [-rlo] -m M -t T -w W -n N -s MIN[-MAX]\n"
            "Traffic Gen Options and Flags\n"
            "\t-m M          Transmit at M mpbs\n"
            "\t-t T          Generate traffic for T seconds\n"
            "\t-w W          Warmup for W seconds before collecting stats\n"
            "\t-n N          Generate a uniform distribution of N flows\n"
            "\t-k MIN-MAX    Generate flows with lifetimes (seconds) uniformly distributed in [MIN,MAX]\n"
            "\t-s MIN[-MAX]  Genearte packets with sizes in [MIN,MAX] (or only of size MIN if MAX isn't specified)\n"
            "\t-r            Randomize packet payloads\n"
            "\t-p            Print stats\n"
            "\t-q            Stop\n"
            "\t-l            Measure latency\n"
            "\t-o            Generate packets online\n");
}

static int pktgen_parse_args(int argc, char *argv[], struct pktgen_config *cfg) {
    int c, n = 0;
    char *p, *q;
    optind = 1;
    cfg->flags &= !FLAG_PRINT;
    cfg->flags &= !FLAG_WAIT;
    while ((c = getopt (argc, argv, "pqrlom:t:w:n:s:k:")) != -1) {
        switch (c) {
            case 'p':
                cfg->flags |= FLAG_PRINT;
                break;
            case 'q':
                cfg->flags |= FLAG_WAIT;
                break;
            case 'r':
                cfg->flags |= FLAG_RANDOMIZE_PAYLOAD;
                break;
            case 'l':
                cfg->flags |= FLAG_MEASURE_LATENCY;
                break;
            case 'o':
                cfg->flags |= FLAG_GENERATE_ONLINE;
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
            case 'k':
                cfg->flags |= FLAG_LIMIT_FLOW_LIFE;
                p = optarg;
                q = strtok(p, "-");
                if (q == NULL) {
                    return -1;
                }
                cfg->life_min = atof(q);

                q = strtok(NULL, "-");
                if (q == NULL) {
                    cfg->life_max = cfg->life_min;
                } else {
                    cfg->life_max = atof(q);
                }
                n++;
                break;

            default:
                return -1;
        }
    }
    if (n < 5 && !(cfg->flags & (FLAG_WAIT | FLAG_PRINT))) {
        return -1;
    }
    return 0;
}

/* start demo stuff */
static int create_and_bind_socket(char *port) {
	int yes = 1;
	int status, fd_server = -1;
	struct addrinfo hints, *res, *p;

	memset(&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ((status = getaddrinfo(NULL, port, &hints, &res)) != 0) {
		return -1;
	}

	for (p = res; p != NULL; p = p->ai_next) {
		if ((fd_server = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
			continue;
		}
		setsockopt(fd_server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
        if (bind(fd_server, p->ai_addr, p->ai_addrlen) < 0) {
            close(fd_server);
            continue;
        }
		break;
	}

	freeaddrinfo(res);

    return fd_server;
}

static int connect_socket(char *ip, char *port) {
	int sock, status;
	struct addrinfo hints, *res, *p;

	memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(ip, port, &hints, &res)) != 0) {
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
            continue;
        }

        if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock);
            continue;
        }
		break;
    }

    if (p == NULL) {
        return -2;
    }

    freeaddrinfo(res); 

    return sock;
}

static int read_n_bytes(int sock, int n, char *buf) {
	int bytes_read = 0;
	while (bytes_read < n) {
		int res = recv(sock, buf + bytes_read, n - bytes_read, 0);
		if (bytes_read < 1) {
			break;
		}
		bytes_read += res;
	}
	return bytes_read;
}

static int request_handler(int fd_client, char *request) {
	int32_t req_len;
	char len_buf[4];

	// read 4 bytes to get the length of the job
	if (read_n_bytes(fd_client, 4, len_buf) < 0) {
		printf("Failed to read length of status.\n");
	}
	
	// convert to host
    // p
    int32_t *x = (int32_t*)&len_buf;
	req_len = ntohl(*x);

	// read req_len bytes from the socket
	if (read_n_bytes(fd_client, req_len, request) < 0) {
		printf("Failed to read status.\n");
	}

	// return len of Job
	return req_len;
}

static int send_status(int status) {
    char ip[32], port[32];
    strcpy(ip, SCHEDULER_IP);
    strcpy(port, SCHEDULER_PORT);
    int sock = connect_socket(ip, port);
	unsigned len;
	int32_t packed_len;
	void *buf;

	if (sock < 0) {
		printf("Failed to connect to the scheduler to send status.\n");
		close(sock);
		return -1;
	}

	// set status
	Status s = STATUS__INIT;
	s.has_type = 1;
	s.type = status;

	// get length of serialized data
	len = status__get_packed_size(&s);
	buf = malloc(len+4);
	packed_len = htonl((int32_t) len);

	// set the first 4 bytes to be the length of data
	// then pack the status into the buf
	memcpy(buf, &packed_len, 4);
	status__pack(&s, (void*)((uint8_t*)(buf)+4));
	
	// send the buf to the socket
	if (send(sock, buf, len+4, 0) < 0) {
		printf("Failed to send status to the scheduler.\n");
		close(sock);
		return -1;
	}
	// finish off
	close(sock);
	return 0;
}

static int response_handler(int fd UNUSED, char *request, int request_bytes, struct pktgen_config *cmd) {
	Job *j = job__unpack(NULL, request_bytes, (void*)request);

	if (j == NULL) {
		printf("Failed to unpack job.\n");
		return -1;
	}

    cmd->flags &= !FLAG_PRINT;
    cmd->flags &= !FLAG_WAIT;

    cmd->tx_rate = j->tx_rate;
    cmd->warmup = j->warmup;
    cmd->duration = j->duration;
    cmd->num_flows = j->num_flows;
    cmd->size_min = j->size_min;
    cmd->size_max = j->size_max;
    cmd->life_min = j->life_min;
    cmd->life_max = j->life_max;

    if (j->randomize)
        cmd->flags |= FLAG_RANDOMIZE_PAYLOAD;

    if (j->latency)
        cmd->flags |= FLAG_MEASURE_LATENCY;

    if (j->online)
        cmd->flags |= FLAG_GENERATE_ONLINE;

    if (j->stop)
        cmd->flags |= FLAG_WAIT;

    if (j->print)
        cmd->flags |= FLAG_PRINT;

    if (cmd->life_min >= 0)
        cmd->flags |= FLAG_LIMIT_FLOW_LIFE;

    printf("Starting traffic: {\n"
           "\ttx_rate: %u\n"
           "\twarmup: %u\n"
           "\tduration: %u\n"
           "\tnum_flows: %u\n"
           "\tsize_min: %u\n"
           "\tsize_max: %u\n"
           "\tlife_min: %f\n"
           "\tlife_max: %f\n"
           "\tlimit flow life: %d\n"
           "\trandomize: %d\n"
           "\tlatency: %d\n"
           "\tonline: %d\n"
           "\tstop: %d\n"
           "\tprint: %d\n}\n",
           cmd->tx_rate, cmd->warmup, cmd->duration,
           cmd->num_flows, cmd->size_min, cmd->size_max,
           cmd->life_min, cmd->life_max,
           cmd->flags & FLAG_LIMIT_FLOW_LIFE,
           cmd->flags & FLAG_RANDOMIZE_PAYLOAD,
           cmd->flags & FLAG_MEASURE_LATENCY,
           cmd->flags & FLAG_GENERATE_ONLINE,
           cmd->flags & FLAG_WAIT,
           cmd->flags & FLAG_PRINT);

	// unpack job
	job__free_unpacked(j, NULL);
	
	// send success status regardless for now
	return send_status(STATUS__TYPE__SUCCESS);
}
/* end demo stuff */

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

    argc -= ret;
    argv += ret;

    if (argc < 2) {
        rte_exit(EXIT_FAILURE, "Args: LISTEN_PORT PREFIX\n");
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

    int fd_server = create_and_bind_socket(argv[1]);
    if (fd_server < 0) {
		rte_exit(EXIT_FAILURE, "Failed to create/bind to socket.\n");
	}

    if (listen(fd_server, BACKLOG) == -1) {
        rte_exit(EXIT_FAILURE, "Failed to listen to socket.\n");
    }

    uint32_t prefix = rte_cpu_to_be_32((uint32_t)inet_addr(argv[2]));

    int i;
    struct pktgen_config config[nb_cores];

    core = 0;
    port = 0;
    RTE_LCORE_FOREACH_SLAVE(i) {
        if (port == nb_ports) {
            break;
        }
        memset(&config[i], 0, sizeof(struct pktgen_config));
        config[i].flags = FLAG_WAIT;

        rte_eal_remote_launch(lcore_init, (void*)&config[i], i);
        rte_eal_wait_lcore(i);
        rte_eal_remote_launch(launch_worker, (void*)&config[i], i);
        core++;
        port++;
    }

    /* Parse pktgen command line */
    ret = read_history(HISTORY_FILE);
    signal(SIGINT, sig_handler);

    cmd.size_min = 0;
    cmd.size_max = 0;
    cmd.life_min = 0;
    cmd.life_max = 2;
    cmd.num_flows = 0;
    cmd.warmup = 0;
    cmd.duration = 0;
    cmd.tx_rate = 0;
    cmd.flags = 0;
    cmd.prefix = prefix;
    cmd.rx_ring_size = GEN_DEFAULT_RX_RING_SIZE;
    cmd.tx_ring_size = GEN_DEFAULT_TX_RING_SIZE;

    int request_bytes;
	char request[8192];
	struct sockaddr_storage addr_client;

    for (;;) {
    	socklen_t sin_size = sizeof addr_client;
        int fd_client = accept(fd_server, (struct sockaddr *)&addr_client, &sin_size);
        if (fd_client >= 0) {
            if ((request_bytes = request_handler(fd_client, request)) > 0) {
            	if (response_handler(fd_client, request, request_bytes, &cmd) == -1) {
            		printf("Failed to respond to request from scheduler.\n");
            	}
			} else {
                printf("Failed to process request from scheduler.\n");
			}
			close(fd_client);
        }

        if (0 && (icmd = readline("tgen> ")) != NULL) {
            add_history(icmd);
            
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
        }

        /* Launch generator */
        core = 0;
        port = 0;
        RTE_LCORE_FOREACH_SLAVE(i) {
            if (port == nb_ports) {
                break;
            }
            config[i].tx_rate = cmd.tx_rate;
            config[i].warmup = cmd.warmup;
            config[i].duration = cmd.duration;
            config[i].num_flows = cmd.num_flows;
            config[i].ip_min = 0xAFCD0123;
            config[i].udp_min = 0x1111;
            config[i].size_min = cmd.size_min;
            config[i].size_max = cmd.size_max;
            config[i].life_min = cmd.life_min;
            config[i].life_max = cmd.life_max;
            config[i].port = port_map[core];
            config[i].rx_ring_size = cmd.rx_ring_size;
            config[i].tx_ring_size = cmd.tx_ring_size;
            config[i].flags = cmd.flags;
            config[i].prefix = cmd.prefix;
#if 0
            printf("config[%u] job: {\n"
                   "\ttx_rate: %u\n"
                   "\twarmup: %u\n"
                   "\tduration: %u\n"
                   "\tnum_flows: %u\n"
                   "\tsize_min: %u\n"
                   "\tsize_max: %u\n"
                   "\tlife_min: %f\n"
                   "\tlife_max: %f\n"
                   "\tflags: %u\n}\n", i,
                   config[i].tx_rate, config[i].warmup, config[i].duration,
                   config[i].num_flows, config[i].size_min, config[i].size_max,
                   config[i].life_min, config[i].life_max, config[i].flags);
#endif

            if (cmd.flags & FLAG_PRINT) {
                printf("%s\n", config[i].o_sec);
                printf("Core %u: Results\n{%s\n    %s}\n", i, config[i].o_delay, config[i].o_xput);
            }
            core++;
            port++;
        }
    }
    ret = write_history(HISTORY_FILE);
    printf("\n");
    return 0;
}
