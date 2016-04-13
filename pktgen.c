#include "pktgen.h"
#include "pktgen_worker.c"

static inline int
port_init(uint8_t port, struct pktgen_config *config UNUSED)
{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    int retval;
    uint16_t q;
    char name[7];

    rte_eth_dev_stop(port); 

    snprintf(name, sizeof(name), "RX%02u:%02u", port, (unsigned)0);
    struct rte_mempool *rx_mp = rte_pktmbuf_pool_create(name, 2 * GEN_DEFAULT_RX_RING_SIZE,
            0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_eth_dev_socket_id(port));
    if (rx_mp == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create RX mbuf pool: %s\n", rte_strerror(rte_errno));
    }

    snprintf(name, sizeof(name), "TX%02u:%02u", port, (unsigned)0);
    struct rte_mempool *tx_mp = rte_pktmbuf_pool_create(name, 2 * GEN_DEFAULT_TX_RING_SIZE,
            0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_eth_dev_socket_id(port));
    if (tx_mp == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create TX mbuf pool: %s\n", rte_strerror(rte_errno));
    }

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(tx_mp);
    tx_mbuf_template[0] = *mbuf;
    rte_pktmbuf_free(mbuf);

    if (port >= rte_eth_dev_count()) {
        return -1;
    }

    if (rte_eth_dev_configure(port, 1, 1, &port_conf) != 0) {
        rte_exit(EXIT_FAILURE, "Error with port configuration: %s\n", rte_strerror(rte_errno));
    }

    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, GEN_DEFAULT_RX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL, rx_mp);
        if (retval != 0) {
            return retval;
        }
    }

    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, GEN_DEFAULT_TX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL);
        if (retval != 0) {
            return retval;
        }
    }

    retval = rte_eth_dev_start(port);
    if (retval < 0) {
        return retval;
    }

    struct ether_addr addr;
    rte_eth_macaddr_get(port, &addr);
    syslog(LOG_INFO, "Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
            " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            (unsigned)port,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);

    rte_eth_promiscuous_enable(port);

    return 0;
}

static int
lcore_init(void *arg)
{
    struct pktgen_config *config = (struct pktgen_config*)arg;
    unsigned port = config->port;
    char name[7];

    syslog(LOG_INFO, "Init core %d", rte_lcore_id());

    config->seed = GEN_DEFAULT_SEED;

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

static int
create_and_bind_socket(char *port)
{
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

static int
connect_socket(char *ip, char *port)
{
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

static int
read_n_bytes(int sock, int n, char *buf)
{
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

static int
request_handler(int fd_client, char *request)
{
	int32_t req_len;
	char len_buf[4];

	if (read_n_bytes(fd_client, 4, len_buf) < 0) {
		syslog(LOG_ERR, "Failed to read length of status.");
	}
	
    int32_t *x = (int32_t*)&len_buf;
	req_len = ntohl(*x);

	if (read_n_bytes(fd_client, req_len, request) < 0) {
		syslog(LOG_ERR, "Failed to read status.");
	}

	return req_len;
}

static int
send_status(int status, char *ip, int ctrl)
{
    char port[32];
    strcpy(port, SCHEDULER_PORT);
    int sock = connect_socket(ip, port);
	unsigned len;
	int32_t packed_len;
	void *buf;

	if (sock < 0) {
		syslog(LOG_ERR, "Failed to connect to the scheduler to send status.");
		close(sock);
		return -1;
	}

	Status s = STATUS__INIT;
	s.has_type = 1;
	s.type = status;
	s.port = ctrl; 

	len = status__get_packed_size(&s);
	buf = malloc(len+4);
	packed_len = htonl((int32_t) len);

	memcpy(buf, &packed_len, 4);
	status__pack(&s, (void*)((uint8_t*)(buf)+4));
	
	if (send(sock, buf, len+4, 0) < 0) {
		syslog(LOG_ERR, "Failed to send status to the scheduler.");
		close(sock);
		return -1;
	}

	close(sock);
	return 0;
}

static int
send_stats(struct pktgen_config *configs, uint16_t n, char *ip, int ctrl)
{
    char port[32];
    strcpy(port, SCHEDULER_PORT);
    int sock = connect_socket(ip, port);
	unsigned len, i;
	int32_t packed_len;
	void *buf;
    struct ether_addr port_addr;

	if (sock < 0) {
		syslog(LOG_ERR, "Failed to connect to the scheduler to send status.\n");
		close(sock);
		return -1;
	}

    Status s = STATUS__INIT;
	s.has_type = 1;
	s.type = 2;
	s.port = ctrl; 

    PortStats *p_stats[n];
    for (i = 0; i < n; i++) {
        p_stats[i] = malloc(sizeof(PortStats));
        port_stats__init(p_stats[i]);
        p_stats[i]->n =                   configs[i].stats.n;
        p_stats[i]->avg_rxmpps =          configs[i].stats.avg_rxpps;
        p_stats[i]->std_rxmpps =          sqrt(configs[i].stats.var_rxpps);
        p_stats[i]->avg_rxbps =           configs[i].stats.avg_rxbps;
        p_stats[i]->std_rxbps =           sqrt(configs[i].stats.var_rxbps);
        p_stats[i]->avg_txmpps =          configs[i].stats.avg_txpps;
        p_stats[i]->std_txmpps =          sqrt(configs[i].stats.var_txpps);
        p_stats[i]->avg_txbps =           configs[i].stats.avg_txbps;
        p_stats[i]->std_txbps =           sqrt(configs[i].stats.var_txbps);
        p_stats[i]->avg_txwire =          configs[i].stats.avg_txwire;
        p_stats[i]->std_txwire =          sqrt(configs[i].stats.var_txwire);
        p_stats[i]->avg_rxwire =          configs[i].stats.avg_rxwire;
        p_stats[i]->std_rxwire =          sqrt(configs[i].stats.var_rxwire);
        p_stats[i]->n_rtt =               configs[i].stats.rtt_n;
        p_stats[i]->rtt_avg =             configs[i].stats.rtt_avg;
        p_stats[i]->rtt_std =             configs[i].stats.rtt_std;
        p_stats[i]->rtt_0 =               configs[i].stats.rtt_0;
        p_stats[i]->rtt_25 =              configs[i].stats.rtt_25;
        p_stats[i]->rtt_50 =              configs[i].stats.rtt_50;
        p_stats[i]->rtt_75 =              configs[i].stats.rtt_75;
        p_stats[i]->rtt_90 =              configs[i].stats.rtt_90;
        p_stats[i]->rtt_95 =              configs[i].stats.rtt_95;
        p_stats[i]->rtt_99 =              configs[i].stats.rtt_99;
        p_stats[i]->rtt_100 =             configs[i].stats.rtt_100;
        p_stats[i]->tx_bytes =            configs[i].stats.tx_bytes;
        p_stats[i]->tx_pkts =             configs[i].stats.tx_pkts;
        p_stats[i]->rx_bytes =            configs[i].stats.rx_bytes;
        p_stats[i]->rx_pkts =             configs[i].stats.rx_pkts;

        if (configs[i].port > n) {
            continue;
        }

        p_stats[i]->port = (char*)malloc(sizeof(char) * 18);
        rte_eth_macaddr_get(configs[i].port, &port_addr);
        ether_format_addr(p_stats[i]->port, 18, &port_addr);
    }
    s.n_stats = n;
	s.stats = p_stats; 

	len = status__get_packed_size(&s);
	buf = malloc(len+4);
	packed_len = htonl((int32_t) len);

	memcpy(buf, &packed_len, 4);
	status__pack(&s, (void*)((uint8_t*)(buf)+4));
	
    for (i = 0; i < n; i++) {
        free(p_stats[i]->port);
        free(p_stats[i]);
    }

	if (send(sock, buf, len+4, 0) < 0) {
		syslog(LOG_ERR, "Failed to send stats to the scheduler.");
		close(sock);
		return -1;
	}

	close(sock);
	return 0;
}

static int
response_handler(int fd UNUSED, char *request, int request_bytes,
                 struct pktgen_config *cmd, char *ip, int ctrl)
{
	Job *j = job__unpack(NULL, request_bytes, (void*)request);

	if (j == NULL) {
		syslog(LOG_ERR, "Failed to unpack job.");
		return -1;
	}

    cmd->flags &= !FLAG_PRINT;
    cmd->flags &= !FLAG_WAIT;
    cmd->port_mac = zero_mac;
    cmd->src_mac = zero_mac;
    cmd->dst_mac = zero_mac;

    cmd->tx_rate = j->tx_rate;
    cmd->warmup = j->warmup;
    cmd->duration = j->duration;
    cmd->num_flows = j->num_flows;
    cmd->size_min = j->size_min;
    cmd->size_max = j->size_max;
    cmd->port_min = j->port_min;
    cmd->port_max = j->port_max;
    cmd->life_min = j->life_min;
    cmd->life_max = j->life_max;

    ether_addr_from_str(j->src_mac, &cmd->src_mac);
    ether_addr_from_str(j->dst_mac, &cmd->dst_mac);
    ether_addr_from_str(j->port, &cmd->port_mac);

    if (j->randomize)
        cmd->flags |= FLAG_RANDOMIZE_PAYLOAD;

    if (j->latency)
        cmd->flags |= FLAG_MEASURE_LATENCY;

    if (j->online)
        cmd->flags |= FLAG_GENERATE_ONLINE;

    if (j->stop)
        cmd->flags |= FLAG_WAIT;

    if (j->print)
        cmd->flags |= (FLAG_PRINT | FLAG_WAIT);

    if (j->tcp)
        cmd->proto = 6;
    else
        cmd->proto = 17;

    if (cmd->life_min >= 0)
        cmd->flags |= FLAG_LIMIT_FLOW_LIFE;

#if GEN_DEBUG
    printf("Starting traffic: {\n"
           "\ttx_rate: %u\n"
           "\twarmup: %u\n"
           "\tduration: %u\n"
           "\tnum_flows: %u\n"
           "\tsize_min: %u\n"
           "\tsize_max: %u\n"
           "\tproto: %u\n"
           "\tport_min: %u\n"
           "\tport_max: %u\n"
           "\tlife_min: %f\n"
           "\tlife_max: %f\n"
           "\tdst_mac: %s\n"
           "\tport: %s\n"
           "\tlimit flow life: %d\n"
           "\trandomize: %d\n"
           "\tlatency: %d\n"
           "\tonline: %d\n"
           "\tstop: %d\n"
           "\tprint: %d\n}\n",
           cmd->tx_rate, cmd->warmup, cmd->duration,
           cmd->num_flows, cmd->size_min, cmd->size_max,
           cmd->proto, cmd->port_min, cmd->port_max,
           cmd->life_min, cmd->life_max,
           j->dst_mac, j->port,
           cmd->flags & FLAG_LIMIT_FLOW_LIFE,
           cmd->flags & FLAG_RANDOMIZE_PAYLOAD,
           cmd->flags & FLAG_MEASURE_LATENCY,
           cmd->flags & FLAG_GENERATE_ONLINE,
           cmd->flags & FLAG_WAIT,
           cmd->flags & FLAG_PRINT);
#endif
	job__free_unpacked(j, NULL);
    if (!(cmd->flags & FLAG_PRINT))
        return send_status(STATUS__TYPE__SUCCESS, ip, ctrl);
    else
        return 0;
}

int
main(int argc, char *argv[])
{

    setup_daemon();

    int i;
    uint8_t nb_ports, port, nb_cores, core; 
    struct pktgen_config cmd;

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization");
    }

    argc -= ret;
    argv += ret;

    if (argc < 1) {
        rte_exit(EXIT_FAILURE, "Args: LISTEN_PORT");
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
        rte_exit(EXIT_FAILURE, "Failed to create/bind to socket.");
	}

    int control_port = atoi(argv[1]);
    if (listen(fd_server, BACKLOG) == -1) {
        rte_exit(EXIT_FAILURE, "Failed to listen to socket.");
    }

    struct pktgen_config config[nb_cores];

    core = 0;
    port = 0;
    RTE_LCORE_FOREACH_SLAVE(i) {
        memset(&config[core], 0, sizeof(struct pktgen_config));
        if (port >= nb_ports) {
            config[core].port = 0xff;
            goto init_done;
        }
        config[core].flags = FLAG_WAIT;
        config[core].port = port_map[core];
        rte_eth_macaddr_get(port_map[core], &config[core].port_mac);
        sem_init(&config[core].stop_sempahore, 0, 0);
        rte_eal_remote_launch(lcore_init, (void*)&config[core], i);
        rte_eal_wait_lcore(i);
        rte_eal_remote_launch(launch_worker, (void*)&config[core], i);
init_done:
        core++;
        port++;
    }

    signal(SIGINT, sig_handler);

    cmd.port_min = 0;
    cmd.port_max = 0;
    cmd.proto = 17;
    cmd.size_min = 0;
    cmd.size_max = 0;
    cmd.life_min = 0;
    cmd.life_max = 2;
    cmd.num_flows = 0;
    cmd.warmup = 0;
    cmd.duration = 0;
    cmd.tx_rate = 0;
    cmd.flags = 0;
    cmd.src_mac = zero_mac;
    cmd.dst_mac = zero_mac;
    cmd.port_mac = zero_mac;
    cmd.rx_ring_size = GEN_DEFAULT_RX_RING_SIZE;
    cmd.tx_ring_size = GEN_DEFAULT_TX_RING_SIZE;

    int request_bytes;
	char request[8192], *client_ip;
	struct sockaddr_storage addr_client;

    for (;;) {
        socklen_t sin_size = sizeof addr_client;
        int fd_client = accept(fd_server, (struct sockaddr *)&addr_client, &sin_size);
        if (fd_client >= 0) {
            struct sockaddr_in *caddr = (struct sockaddr_in*)&addr_client;
            client_ip = inet_ntoa(caddr->sin_addr);
            if ((request_bytes = request_handler(fd_client, request)) > 0) {
            	if (response_handler(fd_client, request, request_bytes, &cmd, client_ip, control_port) == -1) {
            		syslog(LOG_ERR, "Failed to respond to request from scheduler.");
            	}

                /* Launch generator */
                core = 0;
                port = 0;
                RTE_LCORE_FOREACH_SLAVE(i) {
                    unsigned old_flags = 0;
                    if (port == nb_ports) {
                        break;
                    }

                    if (!is_zero_ether_addr(&cmd.port_mac) &&
                        !is_same_ether_addr(&cmd.port_mac, &config[core].port_mac)) {
                        goto launch_done;
                    }
                    config[core].tx_rate = cmd.tx_rate;
                    config[core].warmup = cmd.warmup;
                    config[core].duration = cmd.duration;
                    config[core].num_flows = cmd.num_flows;
                    config[core].ip_min = 0xAFCD0123;
                    config[core].port_min = cmd.port_min;
                    config[core].port_max = cmd.port_max;
                    config[core].proto = cmd.proto;
                    config[core].size_min = cmd.size_min;
                    config[core].size_max = cmd.size_max;
                    config[core].life_min = cmd.life_min;
                    config[core].life_max = cmd.life_max;
                    config[core].port = port_map[core];
                    config[core].rx_ring_size = cmd.rx_ring_size;
                    config[core].tx_ring_size = cmd.tx_ring_size;
                    old_flags = __sync_lock_test_and_set(&config[core].flags, cmd.flags);
                    // Previously we were waiting, but aren't anymore.
                    if (!(old_flags & FLAG_WAIT) &&
                         (cmd.flags & FLAG_WAIT)) {
                        sem_wait(&config[core].stop_sempahore);
                    }
                    ether_addr_copy(&cmd.dst_mac, &config[core].dst_mac);
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
        launch_done:
                    core++;
                    port++;
                }

                if (cmd.flags & FLAG_PRINT && send_stats(config, nb_ports, client_ip, control_port) == -1) {
                    syslog(LOG_ERR, "Failed to send stats to scheduler.");
                }
			} else {
                syslog(LOG_ERR, "Failed to process request from scheduler.");
			}
			close(fd_client);
        }

    }
    return 0;
}
