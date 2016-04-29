#include "pktgen.h"
#include "pktgen_worker.c"

#include <assert.h>

static inline int
port_init(struct pktgen_config *config)
{
    struct rte_eth_conf port_conf = port_conf_default;
    struct rte_eth_fc_conf fc_conf;

    const uint16_t rx_rings = 1, tx_rings = 1;
    int retval;
    uint16_t q;
    char name[8];

    rte_eth_dev_stop(config->port_id);

    config->seed = GEN_DEFAULT_SEED;

    uint8_t socket_id = rte_eth_dev_socket_id(config->port_id);
    assert(socket_id == 0 || socket_id == 1);
    config->socket_id = socket_id;

    snprintf(name, sizeof(name), "RX%02u:%02u", config->port_id, (unsigned)0);
    config->rx_pool =
        rte_pktmbuf_pool_create(name, 2 * GEN_DEFAULT_RX_RING_SIZE, 0, 0,
                                RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
    if (!config->rx_pool) {
        rte_exit(EXIT_FAILURE, "Cannot create RX mbuf pool: %s\n",
                 rte_strerror(rte_errno));
    }

    snprintf(name, sizeof(name), "TX%02u:%02u", config->port_id, (unsigned)0);
    config->tx_pool =
        rte_pktmbuf_pool_create(name, 2 * GEN_DEFAULT_TX_RING_SIZE, 0, 0,
                                RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
    if (!config->tx_pool) {
        rte_exit(EXIT_FAILURE, "Cannot create TX mbuf pool: %s\n",
                 rte_strerror(rte_errno));
    }

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(config->tx_pool);
    tx_mbuf_template = *mbuf;
    rte_pktmbuf_free(mbuf);

    if (config->port_id >= rte_eth_dev_count()) {
        return -1;
    }

    if (rte_eth_dev_configure(config->port_id, 1, 1, &port_conf) != 0) {
        rte_exit(EXIT_FAILURE, "Error with port configuration: %s\n",
                 rte_strerror(rte_errno));
    }

    retval = rte_eth_dev_flow_ctrl_get(config->port_id, &fc_conf);
    if (retval != 0 && retval != -ENOTSUP) {
        rte_exit(EXIT_FAILURE,
                 "rte_eth_dev_flow_ctrl_get: "
                 "err=%d, port=%d, %s",
                 retval, config->port_id, rte_strerror(-retval));
    }
    if (retval == 0) {
        fc_conf.mode = RTE_FC_NONE;

        retval = rte_eth_dev_flow_ctrl_set(config->port_id, &fc_conf);
        if (retval < 0 && retval != -ENOTSUP)
            rte_exit(EXIT_FAILURE,
                     "rte_eth_dev_flow_ctrl_set: "
                     "err=%d, port=%d, %s",
                     retval, config->port_id, rte_strerror(-retval));

        log_info("[port=%d] flow control disabled", config->port_id);
    }

    for (q = 0; q < rx_rings; q++) {
        retval =
            rte_eth_rx_queue_setup(config->port_id, q, GEN_DEFAULT_RX_RING_SIZE,
                                   socket_id, NULL, config->rx_pool);
        if (retval != 0) {
            return retval;
        }
    }

    for (q = 0; q < tx_rings; q++) {
        /* FIXME: UDP CHECKSUM OFFLOAD IS DISABLED (performance degradation)
        struct rte_eth_txconf txconf = {
            .txq_flags = 0;
        };
        */
        retval = rte_eth_tx_queue_setup(
            config->port_id, q, GEN_DEFAULT_TX_RING_SIZE, socket_id, NULL);
        if (retval != 0) {
            return retval;
        }
    }

    retval = rte_eth_dev_start(config->port_id);
    if (retval != 0) {
        return retval;
    }

    struct rte_eth_link link;
    rte_eth_link_get(config->port_id, &link);
    config->port_speed = link.link_speed;

    struct ether_addr *addr = &config->port_mac;
    rte_eth_macaddr_get(config->port_id, &config->port_mac);
    log_info("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
             " %02" PRIx8 " %02" PRIx8 "\n",
             config->port_id, addr->addr_bytes[0], addr->addr_bytes[1],
             addr->addr_bytes[2], addr->addr_bytes[3], addr->addr_bytes[4],
             addr->addr_bytes[5]);

    rte_eth_promiscuous_enable(config->port_id);

    return 0;
}

static int
lcore_init(void *arg)
{
    *(void **)arg =
        rte_zmalloc("pktgen_config", sizeof(struct pktgen_config), 0);
    return arg != NULL;
}

static int
create_and_bind_socket(char *port)
{
    int yes = 1;
    int status, fd_server = -1;
    struct addrinfo hints, *res, *p;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((status = getaddrinfo(NULL, port, &hints, &res)) != 0) {
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        if ((fd_server = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) <
            0) {
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
        log_err("Failed to read length of status.");
    }

    int32_t *x = (int32_t *)&len_buf;
    req_len = ntohl(*x);

    if (read_n_bytes(fd_client, req_len, request) < 0) {
        log_err("Failed to read status.");
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
        log_err("Failed to connect to the scheduler to send status.");
        close(sock);
        return -1;
    }

    Status s = STATUS__INIT;
    s.has_type = 1;
    s.type = status;
    s.port = ctrl;

    len = status__get_packed_size(&s);
    buf = malloc(len + 4);
    packed_len = htonl((int32_t)len);

    memcpy(buf, &packed_len, 4);
    status__pack(&s, (void *)((uint8_t *)(buf) + 4));

    if (send(sock, buf, len + 4, 0) < 0) {
        log_err("Failed to send status to the scheduler.");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

static int
send_stats(struct pktgen_config **config, uint16_t n, char *ip, int ctrl)
{
    char port[32];
    strcpy(port, SCHEDULER_PORT);
    int sock = connect_socket(ip, port);
    unsigned len, i, li;
    int32_t packed_len;
    void *buf;

    if (sock < 0) {
        log_err("Failed to connect to the scheduler to send status.\n");
        close(sock);
        return -1;
    }

    Status s = STATUS__INIT;
    s.has_type = 1;
    s.type = 2;
    s.port = ctrl;

    PortStats *p_stats[n];
    i = 0;
    for (li = 0; li < rte_lcore_count(); li++) {
        p_stats[i] = malloc(sizeof(PortStats));
        port_stats__init(p_stats[i]);
        if (!config[li] || !config[li]->active)
            continue;

        p_stats[i]->n = config[li]->stats.n;
        p_stats[i]->avg_rxmpps = config[li]->stats.avg_rxpps / 1000000;
        p_stats[i]->std_rxmpps = sqrt(config[li]->stats.var_rxpps) / 1000000;
        p_stats[i]->avg_rxbps = config[li]->stats.avg_rxbps / 1000000;
        p_stats[i]->std_rxbps = sqrt(config[li]->stats.var_rxbps) / 1000000;
        p_stats[i]->avg_txmpps = config[li]->stats.avg_txpps / 1000000;
        p_stats[i]->std_txmpps = sqrt(config[li]->stats.var_txpps) / 1000000;
        p_stats[i]->avg_txbps = config[li]->stats.avg_txbps / 1000000;
        p_stats[i]->std_txbps = sqrt(config[li]->stats.var_txbps) / 1000000;
        p_stats[i]->avg_txwire = config[li]->stats.avg_txwire / 1000000;
        p_stats[i]->std_txwire = sqrt(config[li]->stats.var_txwire) / 1000000;
        p_stats[i]->avg_rxwire = config[li]->stats.avg_rxwire / 1000000;
        p_stats[i]->std_rxwire = sqrt(config[li]->stats.var_rxwire) / 1000000;
        p_stats[i]->n_rtt = config[li]->stats.rtt_n;
        p_stats[i]->rtt_avg = config[li]->stats.rtt_avg;
        p_stats[i]->rtt_std = config[li]->stats.rtt_std;
        p_stats[i]->rtt_0 = config[li]->stats.rtt_0;
        p_stats[i]->rtt_25 = config[li]->stats.rtt_25;
        p_stats[i]->rtt_50 = config[li]->stats.rtt_50;
        p_stats[i]->rtt_75 = config[li]->stats.rtt_75;
        p_stats[i]->rtt_90 = config[li]->stats.rtt_90;
        p_stats[i]->rtt_95 = config[li]->stats.rtt_95;
        p_stats[i]->rtt_99 = config[li]->stats.rtt_99;
        p_stats[i]->rtt_100 = config[li]->stats.rtt_100;
        p_stats[i]->tx_bytes = config[li]->stats.tx_bytes;
        p_stats[i]->tx_pkts = config[li]->stats.tx_pkts;
        p_stats[i]->rx_bytes = config[li]->stats.rx_bytes;
        p_stats[i]->rx_pkts = config[li]->stats.rx_pkts;
        p_stats[i]->port = (char *)malloc(sizeof(char) * 18);
        ether_format_addr(p_stats[i]->port, 18, &config[li]->port_mac);

        log_info(
            "[port/lcore/socket=%2d;%s,%2d,%1d] rx/tx: mpps=%06.3f/%06.3f "
            "wire_mbps=%06.1f/%06.1f",
            config[li]->port_id, p_stats[i]->port, config[li]->lcore_id,
            config[li]->socket_id, config[li]->stats.avg_rxpps / 1000000,
            config[li]->stats.avg_txpps / 1000000,
            config[li]->stats.avg_rxwire / 1000000,
            config[li]->stats.avg_txwire / 1000000);
        memset(&config[li]->stats, 0, offsetof(struct rate_stats, flow_ctrs));

        if (++i == n)
            break;
    }

    s.n_stats = n;
    s.stats = p_stats;

    len = status__get_packed_size(&s);
    buf = malloc(len + 4);
    packed_len = htonl((int32_t)len);

    memcpy(buf, &packed_len, 4);
    status__pack(&s, (void *)((uint8_t *)(buf) + 4));

    for (i = 0; i < n; i++) {
        free(p_stats[i]->port);
        free(p_stats[i]);
    }

    if (send(sock, buf, len + 4, 0) < 0) {
        log_err("Failed to send stats to the scheduler.");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

static int
response_handler(int fd UNUSED, char *request, int request_bytes,
                 struct pktgen_config **cmd, char *ip, int ctrl)
{
    Request *r = request__unpack(NULL, request_bytes, (void *)request);

    if (r == NULL) {
        log_err("Failed to unpack request.");
        return -1;
    }

    Job *j;
    int i, ret, n_jobs = r->n_jobs;
    for (i = 0; i < n_jobs; i++) {
        j = r->jobs[i];
        cmd[i]->flags &= !FLAG_PRINT;
        cmd[i]->flags &= !FLAG_WAIT;
        cmd[i]->port_mac = zero_mac;
        cmd[i]->src_mac = zero_mac;
        cmd[i]->dst_mac = zero_mac;

        cmd[i]->tx_rate = j->tx_rate;
        cmd[i]->warmup = j->warmup;
        cmd[i]->duration = j->duration;
        cmd[i]->num_flows = j->num_flows;
        cmd[i]->size_min = j->size_min;
        cmd[i]->size_max = j->size_max;
        cmd[i]->port_min = j->port_min;
        cmd[i]->port_max = j->port_max;
        cmd[i]->life_min = j->life_min;
        cmd[i]->life_max = j->life_max;

        ether_addr_from_str(j->src_mac, &cmd[i]->src_mac);
        ether_addr_from_str(j->dst_mac, &cmd[i]->dst_mac);
        ether_addr_from_str(j->port, &cmd[i]->port_mac);

        if (j->randomize)
            cmd[i]->flags |= FLAG_RANDOMIZE_PAYLOAD;

        if (j->latency)
            cmd[i]->flags |= FLAG_MEASURE_LATENCY;

        if (j->online)
            cmd[i]->flags |= FLAG_GENERATE_ONLINE;

        if (j->stop)
            cmd[i]->flags |= FLAG_WAIT;

        if (j->print)
            cmd[i]->flags |= (FLAG_PRINT | FLAG_WAIT);

        if (j->tcp)
            cmd[i]->proto = IPPROTO_TCP;
        else
            cmd[i]->proto = IPPROTO_UDP;

        if (cmd[i]->life_min >= 0)
            cmd[i]->flags |= FLAG_LIMIT_FLOW_LIFE;

#if GEN_DEBUG
        log_err(
            "request: {"
            "tx_rate: %u"
            ", warmup: %u"
            ", duration: %u"
            ", num_flows: %u"
            ", size_min: %u"
            ", size_max: %u"
            ", proto: %u"
            ", port_min: %u"
            ", port_max: %u"
            ", life_min: %f"
            ", life_max: %f"
            ", dst_mac: %s"
            ", port_id: %s"
            ", limit flow life: %d"
            ", randomize: %d"
            ", latency: %d"
            ", online: %d"
            ", stop: %d"
            ", print: %d}",
            cmd[i]->tx_rate, cmd[i]->warmup, cmd[i]->duration,
            cmd[i]->num_flows, cmd[i]->size_min, cmd[i]->size_max,
            cmd[i]->proto, cmd[i]->port_min, cmd[i]->port_max, cmd[i]->life_min,
            cmd[i]->life_max, j->dst_mac, j->port,
            (cmd[i]->flags & FLAG_LIMIT_FLOW_LIFE) != 0,
            (cmd[i]->flags & FLAG_RANDOMIZE_PAYLOAD) != 0,
            (cmd[i]->flags & FLAG_MEASURE_LATENCY) != 0,
            (cmd[i]->flags & FLAG_GENERATE_ONLINE) != 0,
            (cmd[i]->flags & FLAG_WAIT) != 0,
            (cmd[i]->flags & FLAG_PRINT) != 0);
#endif
    }
    request__free_unpacked(r, NULL);
    ret = send_status(STATUS__TYPE__SUCCESS, ip, ctrl);

    if (ret < 0) {
        return ret;
    }
    return n_jobs;
}

int
main(int argc, char *argv[])
{
#if DAEMON
    setup_daemon();
#endif

    int i, j, li;  // li = lcore_index
    uint8_t nb_ports, port_id, nb_cores;
    struct pktgen_config *cmd[MAX_CMD];
    for (i = 0; i < MAX_CMD; i++) {
        cmd[i] = malloc(sizeof(struct pktgen_config));
    }

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization");
    }

    argc -= ret;
    argv += ret;

    if (argc < 1) {
        rte_exit(EXIT_FAILURE, "Args: LISTEN_PORT [CORE_TO_PORT_MAPPING]\n");
    }

    nb_ports = rte_eth_dev_count();
    nb_cores = rte_lcore_count();

    struct pktgen_config *
        config[nb_cores];  // = malloc(nb_cores * sizeof(struct pktgen_config));
    int port_active[nb_ports];

    for (port_id = 0; port_id < nb_ports; port_id++) port_active[port_id] = 0;
    for (li = 0; li < nb_cores; li++) config[li] = NULL;

    RTE_LCORE_FOREACH_SLAVE(i)
    {
        li = rte_lcore_index(i);
        rte_eal_remote_launch(lcore_init, (void *)&config[li], i);
        rte_eal_wait_lcore(i);
        config[li]->active = 0;
        config[li]->lcore_id = i;
    }

    if (argc > 2) {
        /* Using cmd line core->port mapping */
        for (i = 2; i < argc; i++) {
            if (sscanf(argv[i], "%" SCNu8 ".%" SCNu8, (uint8_t *)&li,
                       &port_id) == EOF) {
                rte_exit(EXIT_FAILURE, "Invalid core-port mapping.");
            }
            if (li >= nb_cores) {
                rte_exit(EXIT_FAILURE, "Core %" PRIu8 " doesn't exist.\n", li);
            }
            if (port_id >= nb_ports) {
                rte_exit(EXIT_FAILURE, "Port %" PRIu8 " doesn't exist.\n",
                         port_id);
            }

            if (port_active[port_id]) {
                rte_exit(EXIT_FAILURE,
                         "Core for port %" PRIu8 " was already set.\n",
                         port_id);
            } else if (config[li]->active) {
                rte_exit(EXIT_FAILURE, "Core %" PRIu8 " was already set.\n",
                         li);
            }

            config[li]->active = 1;
            config[li]->port_id = port_id;
            if (port_init(config[li]) != 0)
                rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu8 "\n",
                         port_id);
            log_info("core: %" PRIu8 " port: %" PRIu8 "\n", li, port_id);
        }
    } else {
        /* Fall back on numa-aware mapping */
        for (port_id = 0; port_id < nb_ports; port_id++) {
            uint8_t socket_id = rte_eth_dev_socket_id(port_id);
            assert(socket_id == 0 || socket_id == 1);

            RTE_LCORE_FOREACH_SLAVE(i)
            {
                li = rte_lcore_index(i);
                if (config[li]->active ||
                    rte_lcore_to_socket_id(i) != socket_id)
                    continue;
                config[li]->active = 1;
                config[li]->port_id = port_id;
                port_active[port_id] = 1;
                if (port_init(config[li]) != 0)
                    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu8 "\n",
                             port_id);
                break;
            }
        }

        /* Assign remaining ports to whatever spare cores there are*/
        for (port_id = 0; port_id < nb_ports; port_id++) {
            if (port_active[port_id])
                continue;

            RTE_LCORE_FOREACH_SLAVE(i)
            {
                li = rte_lcore_index(i);
                if (config[li]->active)
                    continue;
                config[li]->active = 1;
                config[li]->port_id = port_id;
                if (port_init(config[li]) != 0)
                    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu8 "\n",
                             port_id);
                break;
            }
        }
    }

    int fd_server = create_and_bind_socket(argv[1]);
    if (fd_server < 0) {
        rte_exit(EXIT_FAILURE, "Failed to create/bind to socket.");
    }

    int control_port = atoi(argv[1]);
    if (listen(fd_server, BACKLOG) == -1) {
        rte_exit(EXIT_FAILURE, "Failed to listen to socket.");
    }

    RTE_LCORE_FOREACH_SLAVE(i)
    {
        li = rte_lcore_index(i);
        if (!config[li]->active) {
            continue;
        }
        config[li]->flags = FLAG_WAIT;
        sem_init(&config[li]->stop_sempahore, 0, 0);
        rte_eal_remote_launch(launch_worker, (void *)config[li], i);
    }

    signal(SIGINT, sig_handler);

    int request_bytes, n_jobs;
    char request[8192], *client_ip;
    struct sockaddr_storage addr_storage;
    struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr_storage;
    struct sockaddr *addr = (struct sockaddr *)&addr_storage;
    socklen_t sin_size = sizeof addr_storage;

    for (i = 0; i < MAX_CMD; i++) {
        cmd[i]->port_min = 0;
        cmd[i]->port_max = 0;
        cmd[i]->proto = IPPROTO_UDP;
        cmd[i]->size_min = 0;
        cmd[i]->size_max = 0;
        cmd[i]->life_min = 0;
        cmd[i]->life_max = 2;
        cmd[i]->num_flows = 0;
        cmd[i]->warmup = 0;
        cmd[i]->duration = 0;
        cmd[i]->tx_rate = 0;
        cmd[i]->flags = 0;
        cmd[i]->src_mac = zero_mac;
        cmd[i]->dst_mac = zero_mac;
        cmd[i]->port_mac = zero_mac;
        cmd[i]->rx_ring_size = GEN_DEFAULT_RX_RING_SIZE;
        cmd[i]->tx_ring_size = GEN_DEFAULT_TX_RING_SIZE;
    }

    for (;;) {
        int fd_client = accept(fd_server, addr, &sin_size);
        if (fd_client < 0)
            continue;

        if ((request_bytes = request_handler(fd_client, request)) <= 0) {
            log_err("Failed to process request from scheduler.");
            close(fd_client);
            continue;
        }

        client_ip = inet_ntoa(addr_in->sin_addr);
        if ((n_jobs = response_handler(fd_client, request, request_bytes, cmd,
                                       client_ip, control_port)) == -1) {
            log_err("Failed to respond to request from scheduler.");
        }

        for (j = 0; j < n_jobs; j++) {
            // unicast command
            RTE_LCORE_FOREACH_SLAVE(i)
            {
                li = rte_lcore_index(i);
                if (!config[li]->active ||
                    (!is_same_ether_addr(&cmd[j]->port_mac,
                                         &config[li]->port_mac) &&
                     !is_zero_ether_addr(&cmd[j]->port_mac)))
                    continue;

                if (cmd[j]->flags & FLAG_PRINT) {
                    if (send_stats(&config[li], 1, client_ip, control_port) ==
                        -1) {
                        log_err("Failed to send stats to scheduler.");
                    }
                }

                unsigned old_flags = 0;
                config[li]->tx_rate = cmd[j]->tx_rate;
                config[li]->warmup = cmd[j]->warmup;
                config[li]->duration = cmd[j]->duration;
                config[li]->num_flows = cmd[j]->num_flows;
                config[li]->ip_min = 0xAFCD0123;
                config[li]->port_min = cmd[j]->port_min;
                config[li]->port_max = cmd[j]->port_max;
                config[li]->proto = cmd[j]->proto;
                config[li]->size_min = cmd[j]->size_min;
                config[li]->size_max = cmd[j]->size_max;
                config[li]->life_min = cmd[j]->life_min;
                config[li]->life_max = cmd[j]->life_max;
                config[li]->rx_ring_size = cmd[j]->rx_ring_size;
                config[li]->tx_ring_size = cmd[j]->tx_ring_size;
                ether_addr_copy(&cmd[j]->src_mac, &config[li]->src_mac);
                ether_addr_copy(&cmd[j]->dst_mac, &config[li]->dst_mac);
                old_flags =
                    __sync_lock_test_and_set(&config[li]->flags, cmd[j]->flags);
                // Previously we were waiting, but aren't anymore.
                if (!(old_flags & FLAG_WAIT) && (cmd[j]->flags & FLAG_WAIT)) {
                    sem_wait(&config[li]->stop_sempahore);
                }
            }
        }
    }

    free(cmd);
    RTE_LCORE_FOREACH_SLAVE(i)
    {
        li = rte_lcore_index(i);
        rte_free(config[li]);
    }
    return 0;
}
