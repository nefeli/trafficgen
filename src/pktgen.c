#include "pktgen.h"
#include "pktgen_worker.c"

#include <assert.h>

static inline int
port_init(struct port_t *port)
{
    struct rte_eth_conf port_conf = port_conf_default;
    struct rte_eth_fc_conf fc_conf;
    struct rte_eth_dev *dev = &rte_eth_devices[port->id];
    struct rte_eth_dev_info info;

    const uint16_t rx_rings = 1, tx_rings = 1;
    int retval;
    uint16_t q;
    char poolname[32];

    if (!rte_eth_dev_is_valid_port(port->id))
        return -1;
    port->burst = BURST_SIZE;
    port->nb_tx_desc = TX_RING_SIZE;
    port->nb_rx_desc = RX_RING_SIZE;
    port->tx_pool_size = TX_POOL_SIZE;
    port->rx_pool_size = RX_POOL_SIZE;

    rte_eth_dev_info_get(port->id, &info);
    info.default_rxconf.rx_drop_en = 1;
    // FIXME: enabling offload kills xput
    //info.default_txconf.txq_flags = (uint32_t)ETH_TXQ_FLAGS_NOMULTSEGS;

    if (strncmp(info.driver_name, "rte_bond_pmd", 12) == 0) {
        port->tx_pool_size *= 4;
        port->rx_pool_size *= 4;
        port->burst *= 4;
    }

    strncpy(port->name, dev->data->name, 256);
    rte_eth_macaddr_get(port->id, &port->macaddr);
    port->socket_id = rte_eth_dev_socket_id(port->id);

    snprintf(poolname, sizeof(poolname), "MGEN_%s_tx_0", port->name);
    port->tx_pool = rte_mempool_lookup(poolname);
    if (!port->tx_pool)
        port->tx_pool = rte_pktmbuf_pool_create(poolname, port->tx_pool_size, 0, 0,
                RTE_MBUF_DEFAULT_BUF_SIZE, port->socket_id);

    if (!port->tx_pool) {
        rte_exit(EXIT_FAILURE, "Cannot create TX mbuf pool: %s\n",
                 rte_strerror(rte_errno));
    }

    // NOT in use currently
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(port->tx_pool);
    tx_mbuf_template = *mbuf;
    rte_pktmbuf_free(mbuf);


    if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
        return 0;
    }

    rte_eth_dev_stop(port->id);

    snprintf(poolname, sizeof(poolname), "MGEN_%s_rx_0", port->name);
    struct rte_mempool *rx_pool =
        rte_pktmbuf_pool_create(poolname, port->rx_pool_size, 0, 0,
                                RTE_MBUF_DEFAULT_BUF_SIZE, port->socket_id);
    if (!rx_pool) {
        rte_exit(EXIT_FAILURE, "Cannot create RX mbuf pool: %s\n",
                 rte_strerror(rte_errno));
    }

    if (rte_eth_dev_configure(port->id, 1, 1, &port_conf) != 0) {
        rte_exit(EXIT_FAILURE, "Error with port configuration: %s\n",
                 rte_strerror(rte_errno));
    }

    retval = rte_eth_dev_flow_ctrl_get(port->id, &fc_conf);
    if (retval != 0 && retval != -ENOTSUP) {
        rte_exit(EXIT_FAILURE,
                 "rte_eth_dev_flow_ctrl_get: "
                 "err=%d, port=%d, %s",
                 retval, port->id, rte_strerror(-retval));
    } else if (retval == 0) {
        fc_conf.mode = RTE_FC_NONE;

        retval = rte_eth_dev_flow_ctrl_set(port->id, &fc_conf);
        if (retval < 0 && retval != -ENOTSUP)
            rte_exit(EXIT_FAILURE,
                     "rte_eth_dev_flow_ctrl_set: "
                     "err=%d, port=%d, %s",
                     retval, port->id, rte_strerror(-retval));
    }

    for (q = 0; q < rx_rings; q++) {
        retval =
            rte_eth_rx_queue_setup(port->id, q, port->nb_rx_desc,
                                   port->socket_id, &info.default_rxconf, rx_pool);
        if (retval != 0) {
            return retval;
        }
    }

    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port->id, q, port->nb_tx_desc,
                                        port->socket_id, &info.default_txconf);
        if (retval != 0) {
            return retval;
        }
    }

    retval = rte_eth_dev_start(port->id);
    if (retval != 0) {
        return retval;
    }

   syslog(LOG_INFO, "Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                     " %02" PRIx8 " %02" PRIx8 " %02" PRIx8,
           port->id,
           port->macaddr.addr_bytes[0], port->macaddr.addr_bytes[1],
           port->macaddr.addr_bytes[2], port->macaddr.addr_bytes[3],
           port->macaddr.addr_bytes[4], port->macaddr.addr_bytes[5]);

    rte_eth_promiscuous_enable(port->id);

    return 0;
}

static int
create_and_bind_socket(char *port)
{
    int yes = 1;
    int status, fd = -1;
    struct addrinfo hints, *res, *p;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((status = getaddrinfo(NULL, port, &hints, &res)) != 0) {
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) <
                0) {
            continue;
        }
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
        if (bind(fd, p->ai_addr, p->ai_addrlen) < 0) {
            close(fd);
            continue;
        }
        break;
    }

    freeaddrinfo(res);

    return fd;
}

static int
read_n_bytes(int fd, int n, char *buf)
{
    int bytes_read = 0;
    while (bytes_read < n) {
        int res = recv(fd, buf + bytes_read, n - bytes_read, 0);
        if (res <= 0) {
            break;
        }
        bytes_read += res;
    }
    return bytes_read;
}

static int
handle_recv(int fd, char *request)
{
    int32_t req_len;
    char len_buf[4];

    if (read_n_bytes(fd, 4, len_buf) <= 0) {
        syslog(LOG_ERR, "Failed to read request length.");
        return -1;
    }

    int32_t *x = (int32_t *)&len_buf;
    req_len = ntohl(*x);

    if (req_len > 8000) {
        syslog(LOG_ERR, "Invalid request length %d > 8000.", req_len);
        return -1;
    }

    if (read_n_bytes(fd, req_len, request) <= 0) {
        syslog(LOG_ERR, "Failed to read request.");
        return -1;
    }

    return req_len;
}

static int
send_status(int fd, int status, struct pktgen_config **config, uint16_t n)
{
    unsigned len, i, j, li;
    int32_t packed_len;
    void *buf;
    PortStats *p_stats[n];

    Status s = STATUS__INIT;
    s.has_type = 1;
    s.type = status;
    //s.port = ctrl;

    if (config != NULL) {
        i = 0;
        RTE_LCORE_FOREACH_SLAVE(j) {
            li = rte_lcore_index(j);
            if (!config[li]->active)
                continue;
            p_stats[i] = malloc(sizeof(PortStats));
            port_stats__init(p_stats[i]);

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
            strncpy(p_stats[i]->port, config[li]->port_str, 18);
            //ether_format_addr(p_stats[i]->port, 18, &config[li]->port.macaddr);

            syslog(LOG_INFO,
                    "[port/lcore/socket=%2d;%s,%2d,%1d] rx/tx: mpps=%06.3f/%06.3f "
                    "wire_mbps=%06.1f/%06.1f",
                    config[li]->port.id, p_stats[i]->port, config[li]->lcore_id,
                    config[li]->socket_id, config[li]->stats.avg_rxpps / 1000000,
                    config[li]->stats.avg_txpps / 1000000,
                    config[li]->stats.avg_rxwire / 1000000,
                    config[li]->stats.avg_txwire / 1000000);
            config[li]->active = 0;
            memset(&config[li]->stats, 0, offsetof(struct rate_stats, flow_ctrs));

            if (++i == n)
                break;
        }

        n = i; // in case n is larger than the number of active cores
        s.n_stats = n;
        s.stats = p_stats;
    }

    len = status__get_packed_size(&s);
    buf = malloc(len + 4);
    packed_len = htonl((int32_t)len);

    memcpy(buf, &packed_len, 4);
    status__pack(&s, (void *)((uint8_t *)(buf) + 4));

    if (send(fd, buf, len + 4, 0) < 0) {
        syslog(LOG_ERR, "Failed to send status to the scheduler.");
        return -1;
    }

    if (config != NULL) {
        for (i = 0; i < n; i++) {
            free(p_stats[i]->port);
            free(p_stats[i]);
        }
    }

    return 0;
}

static int
handle_request(int fd, struct pktgen_config **cmd)
{
    int request_bytes;
    char request[8192];

    if ((request_bytes = handle_recv(fd, request)) <= 0) {
        syslog(LOG_ERR, "Failed to recv request.");
        return -1;
    }

    Request *r = request__unpack(NULL, request_bytes, (void *)request);

    if (r == NULL) {
        syslog(LOG_ERR, "Failed to unpack request.");
        return -1;
    }

    Job *j;
    int i, n_jobs = r->n_jobs;
    for (i = 0; i < n_jobs; i++) {
        j = r->jobs[i];
        cmd[i]->flags &= !FLAG_PRINT;
        cmd[i]->flags &= !FLAG_WAIT;
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
        strncpy(cmd[i]->port_str, j->port, 256);
        //ether_addr_from_str(j->port, &cmd[i]->port_mac);

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

        syslog(LOG_ERR,
               "request: {"
               "tx_rate: %d"
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
               ", src_mac: %s"
               ", dst_mac: %s"
               ", port: %s"
               ", limit flow life: %d"
               ", randomize: %d"
               ", latency: %d"
               ", online: %d"
               ", stop: %d"
               ", print: %d}",
               cmd[i]->tx_rate, cmd[i]->warmup, cmd[i]->duration,
               cmd[i]->num_flows, cmd[i]->size_min, cmd[i]->size_max,
               cmd[i]->proto, cmd[i]->port_min, cmd[i]->port_max,
               cmd[i]->life_min, cmd[i]->life_max,
               j->src_mac, j->dst_mac, j->port,
               (cmd[i]->flags & FLAG_LIMIT_FLOW_LIFE) != 0,
               (cmd[i]->flags & FLAG_RANDOMIZE_PAYLOAD) != 0,
               (cmd[i]->flags & FLAG_MEASURE_LATENCY) != 0,
               (cmd[i]->flags & FLAG_GENERATE_ONLINE) != 0,
               (cmd[i]->flags & FLAG_WAIT) != 0,
               (cmd[i]->flags & FLAG_PRINT) != 0);
    }
    request__free_unpacked(r, NULL);

    return n_jobs;
}

static int
find_port_id(char *port_str, uint8_t *port_id)
{
    struct ether_addr macaddr, macaddr_this;
    int retval = ether_addr_from_str(port_str, &macaddr);
    int vdev = retval != 0;
    int i;

    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        struct rte_eth_dev *dev = &rte_eth_devices[i];
        if (!dev->attached)
            continue;
        if (vdev) {
            if (strncmp(port_str, dev->data->name, 256) == 0) {
                *port_id = i;
                return 0;
            }
        } else {
            rte_eth_macaddr_get(i, &macaddr_this);
            if (is_same_ether_addr(&macaddr, &macaddr_this)) {
                *port_id = i;
                return 0;
            }
        }
    }

    return -ENODEV;
}

static int
handle_client(int fd,
        struct port_t *ports,
        struct pktgen_config **config,
        struct pktgen_config **cmd) {
    uint8_t port_id, nb_ports = rte_eth_dev_count();
    int n_jobs, retval, i, j, li = 0, socket_id;
    if ((n_jobs = handle_request(fd, cmd)) == -1) {
        syslog(LOG_ERR, "Failed to handle request.");
        return -1;
    }

    for (j = 0; j < n_jobs; j++) {
        retval = find_port_id(cmd[j]->port_str, &port_id);
        // broadcast command (in case port not found)
        if (retval < 0) {
            // only handle stats for now
            if (cmd[j]->flags & FLAG_PRINT) {
                // FIXME: maybe send a copy of config
                if (send_status(fd, STATUS__TYPE__STATS, config, nb_ports) == -1) {
                    syslog(LOG_ERR, "Failed to send stats.");
                    return -1;
                }
            }
            continue;
        }

        // unicast command otherwise
        // find a free lcore on the right socket
        RTE_LCORE_FOREACH_SLAVE(i)
        {
            li = rte_lcore_index(i);
            socket_id = rte_lcore_to_socket_id(i);
            if (!config[li]->active &&
                    socket_id == ports[port_id].socket_id)
                break;
        }

        if (i == RTE_MAX_LCORE) {
            syslog(LOG_ERR, "Not enough cores to run job %d", j);
            continue;
        }

        if (cmd[j]->flags & FLAG_PRINT) {
            if (send_status(fd, STATUS__TYPE__STATS, &config[li], 1) == -1) {
                syslog(LOG_ERR, "Failed to send stats.");
                return -1;
            }
        } else {
            if (send_status(fd, STATUS__TYPE__SUCCESS, NULL, 0))
                return -1;
        }

        config[li]->active = 1;
        config[li]->port = ports[port_id];
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
        ether_addr_copy(&cmd[j]->src_mac, &config[li]->src_mac);
        ether_addr_copy(&cmd[j]->dst_mac, &config[li]->dst_mac);
        //ether_addr_copy(&cmd[j]->port_mac, &config[li]->port_mac);
        strncpy(config[li]->port_str, cmd[j]->port_str, 256);

        unsigned old_flags =
            __sync_lock_test_and_set(&config[li]->flags, cmd[j]->flags);
        // Previously we were waiting, but aren't anymore.
        if (!(old_flags & FLAG_WAIT) && (cmd[j]->flags & FLAG_WAIT)) {
            sem_wait(&config[li]->stop_semaphore);
        }
    }
    return 0;
}

int
main(int argc, char *argv[])
{
#if DAEMON
    setup_daemon();
#endif

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization");
    }

    signal(SIGINT, sig_handler);

    argc -= ret;
    argv += ret;

    if (argc < 1) {
        rte_exit(EXIT_FAILURE, "Args: LISTEN_PORT");
    }

    struct sockaddr_storage addr_storage;
    struct sockaddr *addr = (struct sockaddr *)&addr_storage;
    socklen_t sin_size = sizeof addr_storage;

    int fd_server = create_and_bind_socket(argv[1]);
    int fd_client;
    if (fd_server < 0) {
        rte_exit(EXIT_FAILURE, "Failed to create/bind to socket.");
    }

    if (listen(fd_server, BACKLOG) == -1) {
        rte_exit(EXIT_FAILURE, "Failed to listen to socket.");
    }

    int i, li, socket_id;  // li = lcore_index
    uint8_t port_id;
    struct pktgen_config *cmd[MAX_CMD], *config[rte_lcore_count()];
    uint8_t nb_ports = rte_eth_dev_count();
    struct port_t ports[nb_ports];

    for (port_id = 0; port_id < nb_ports; port_id++) {
        ports[port_id].id = port_id;
        if (port_init(&ports[port_id]) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu8 "\n", port_id);
    }

    for (i = 0; i < MAX_CMD; i++) {
        cmd[i] = malloc(sizeof(struct pktgen_config));
        memset(cmd[i], 0, sizeof(struct pktgen_config));
        cmd[i]->proto = IPPROTO_UDP;
        cmd[i]->life_max = 2;
    }

    RTE_LCORE_FOREACH(i)
    {
        socket_id = rte_lcore_to_socket_id(i);
        assert(socket_id == 0 || socket_id == 1);
        li = rte_lcore_index(i);
        config[li] = rte_zmalloc_socket("pktgen_config",
                sizeof(struct pktgen_config),
                0,
                socket_id);
        config[li]->active = 0;
        config[li]->flags = FLAG_WAIT;
        config[li]->lcore_id = i;
        config[li]->seed = GEN_DEFAULT_SEED;
        config[li]->socket_id = socket_id;
        if (!config[li])
            rte_exit(EXIT_FAILURE, "failed to rte_zmalloc_socket(config[%d])", li);

        sem_init(&config[li]->stop_semaphore, 0, 0);
        if (rte_get_master_lcore() != i)
            rte_eal_remote_launch(worker_loop, (void *)config[li], i);
    }

    for (;;) {
        fd_client = accept(fd_server, addr, &sin_size);
        if (fd_client < 0)
            continue;

        while (handle_client(fd_client, ports, config, cmd) == 0);

        close(fd_client);
    }

    free(cmd);
    RTE_LCORE_FOREACH_SLAVE(i)
    {
        rte_free(config[rte_lcore_index(i)]);
    }

    return 0;
}
