#ifndef PKTGEN_H
#define PKTGEN_H 1

#include "pktgen_util.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <math.h>
#include <signal.h>
#include <readline/readline.h>
#include <readline/history.h>

#include <rte_eal.h>
#include <rte_random.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_mbuf.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>

#define NUM_PKTS (1<<16)
#define BURST_SIZE 32
#define GEN_KEY 0x1234
#define GEN_DEFAULT_RX_RING_SIZE 256
#define GEN_DEFAULT_TX_RING_SIZE 256

#define FLAG_MEASURE_LATENCY 1
#define FLAG_RANDOMIZE_PAYLOAD (1<<1)
#define FLAG_GENERATE_ONLINE (1<<2)
#define FLAG_LIMIT_FLOW_LIFE (1<<3)
#define FLAG_WAIT (1<<4)
#define FLAG_UPDATE (1<<5)
#define FLAG_PRINT (1<<6)

struct pktgen_config {
    uint8_t port;
    uint8_t role;

    uint32_t tx_rate;
    uint32_t warmup;
    uint32_t duration;

    uint32_t num_flows;
    uint32_t ip_src;
    uint32_t ip_min;
    uint16_t udp_min;

    uint16_t size_min;
    uint16_t size_max;

    double life_min;
    double life_max;

    double start_time;

    struct rte_mempool *tx_pool;
    struct rte_mempool *rx_pool;

    unsigned rx_ring_size;
    unsigned tx_ring_size;

    unsigned flags;

    char o_delay[1024];
    char o_xput[1024];
    char o_sec[1024];

    ranctx seed;
};

struct rate_stats {
    uint64_t n;

    double avg_rxpps;
    double var_rxpps;
    double avg_rxbps;
    double var_rxbps;
    double avg_txpps;
    double var_txpps;
    double avg_txbps;
    double var_txbps;
    double avg_txwire;
    double var_txwire;
    double avg_rxwire;
    double var_rxwire;

    uint64_t tx_bytes;
    uint64_t tx_pkts;
    uint64_t rx_bytes;
    uint64_t rx_pkts;
};

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

static struct ether_addr ether_src UNUSED =
{{ 0x68, 0x05, 0xca, 0x00, 0x00, 0xab }};

static struct ether_addr ether_dst UNUSED =
{{ 0x68, 0x05, 0xca, 0x00, 0x00, 0x01 }};
#endif
