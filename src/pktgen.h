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
#include <semaphore.h>

/* start demo stuff */
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "protobufs/job.pb-c.h"
#include "protobufs/status.pb-c.h"

#define PORT "1729"
#define SCHEDULER_IP "127.0.0.1"
#define SCHEDULER_PORT "1800"
#define BUFSIZE 8192
#define BACKLOG 25
/* end demo stuff */

#include <rte_config.h>
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
#include <rte_tcp.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>

#define BURST_SIZE 32
#define MAX_PKT_SIZE 2048
#define MPOOL_SIZE (1 << 16) - 1

#define MAX_CMD 16
#define GEN_DEBUG 1
#define GEN_KEY 0x1234
#define GEN_DEFAULT_SEED 1234
#define GEN_DEFAULT_RX_RING_SIZE 512
#define GEN_DEFAULT_TX_RING_SIZE 256

#define ETH_PREAMBLE 7
#define ETH_START_OF_FRAME 1
#define ETH_FCS 4
#define ETH_GAP 12
#define ETH_OVERHEAD (ETH_PREAMBLE + ETH_START_OF_FRAME + ETH_FCS + ETH_GAP)

#define FLAG_MEASURE_LATENCY 1 << 0
#define FLAG_RANDOMIZE_PAYLOAD 1 << 1
#define FLAG_GENERATE_ONLINE 1 << 2
#define FLAG_LIMIT_FLOW_LIFE 1 << 3
#define FLAG_WAIT 1 << 4
#define FLAG_UPDATE 1 << 5
#define FLAG_PRINT 1 << 6

#define NUM_SAMPLES 100000
#define NUM_ETH_SPEEDS 12

struct rate_stats {
    uint64_t n;
    uint64_t rtt_n;

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

    double rtt_avg;
    double rtt_std;
    double rtt_0;
    double rtt_25;
    double rtt_50;
    double rtt_75;
    double rtt_90;
    double rtt_95;
    double rtt_99;
    double rtt_100;

    uint64_t tx_bytes;
    uint64_t tx_pkts;
    uint64_t rx_bytes;
    uint64_t rx_pkts;

    uint32_t nb_samples;

    uint16_t *flow_ctrs;
    double *flow_times;
    double *samples;
};

struct pktgen_config {
    uint8_t active;

    uint8_t run_id;
    uint8_t lcore_id;
    uint8_t socket_id;
    uint8_t port_id;
    uint32_t port_speed;

    uint8_t role;

    int tx_rate;
    uint32_t warmup;
    uint32_t duration;

    uint32_t num_flows;
    uint32_t ip_src;
    uint32_t ip_min;

    uint8_t proto;
    uint16_t port_min;
    uint16_t port_max;

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

    uint64_t seed;
    struct rate_stats stats;

    struct ether_addr src_mac;
    struct ether_addr dst_mac;
    struct ether_addr port_mac;

    sem_t stop_sempahore;
};

struct pkt {
    uint16_t size;

    struct ether_hdr eth_hdr;
    struct ipv4_hdr ip_hdr;
    union {
        struct udp_hdr udp_hdr;
        struct tcp_hdr tcp_hdr;
    };
    uint8_t dummy[2048];
};

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = ETHER_MAX_LEN}};

static struct ether_addr zero_mac UNUSED = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

static struct ether_addr ether_dst UNUSED = {
    {0x68, 0x05, 0xca, 0x00, 0x00, 0x01}};
#endif
