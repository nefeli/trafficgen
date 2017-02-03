#ifndef PKTGEN_CONFIG_H
#define PKTGEN_CONFIG_H 1

#define DAEMON 0

/* Socket server settings */
#define PORT "1729"
#define SCHEDULER_IP "127.0.0.1"
#define SCHEDULER_PORT "1800"
#define BUFSIZE 8192
#define BACKLOG 25

/* TX/RX and packet generation settings */
#define BURST_SIZE 32
#define MAX_PKT_SIZE 2048
#define MPOOL_SIZE (1 << 16) - 1

#define MAX_CMD 16
#define GEN_KEY 0x1234
#define GEN_DEFAULT_SEED 1234
#define GEN_DEFAULT_RX_RING_SIZE 512
#define GEN_DEFAULT_TX_RING_SIZE 256

/* Latency measurement settings */
#define NUM_SAMPLES 100000

#endif

