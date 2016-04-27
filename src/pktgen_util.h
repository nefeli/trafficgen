#ifndef PKTGEN_UTIL_H
#define PKTGEN_UTIL_H 1

#include "pktgen_config.h"
#include "simd.h"

#include <stdio.h>
#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <sys/types.h>
#include <sys/stat.h>

#define UNUSED __attribute__((__unused__))
#define RTE_MBUF_FROM_BADDR(ba) (((struct rte_mbuf *)(ba)) - 1)

/* Adapted from Zed's Debugging Macros:
 * http://c.learncodethehardway.org/book/ex20.html
 */
#if DAEMON
#include <syslog.h>
#define log_dbg(M, ...) \
    syslog(LOG_DEBUG, "(%s:%d) " M, __FILE__, __LINE__, ##__VA_ARGS__)

#define log_err(M, ...) \
    syslog(LOG_ERR, "(%s:%d) " M, __FILE__, __LINE__, ##__VA_ARGS__)

#define log_warn(M, ...) \
    syslog(LOG_WARN, "(%s:%d) " M, __FILE__, __LINE__, ##__VA_ARGS__)

#define log_info(M, ...) \
    syslog(LOG_INFO, "(%s:%d) " M, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_dbg(M, ...)                                            \
    fprintf(stderr, "[DEBUG] (%s:%d) " M "\n", __FILE__, __LINE__, \
            ##__VA_ARGS__)

#define log_err(M, ...)                                            \
    fprintf(stderr, "[ERROR] (%s:%d) " M "\n", __FILE__, __LINE__, \
            ##__VA_ARGS__)

#define log_warn(M, ...) \
    fprintf(stderr, "[WARN] (%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define log_info(M, ...) \
    fprintf(stderr, "[INFO] (%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#endif

typedef struct rte_mbuf **mbuf_array_t;

struct rte_mbuf tx_mbuf_template;

#if DAEMON
static void
setup_daemon(void)
{
    FILE *f;
    pid_t pid;

    pid = fork();

    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);

    f = fopen("./pktgen.pid", "w+");

    if (f == NULL) {
        exit(EXIT_FAILURE);
    }

    if (fprintf(f, "%d", getpid()) <= 0) {
        fclose(f);
        exit(EXIT_FAILURE);
    }

    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    openlog("pktgen", LOG_PID, LOG_DAEMON);
}
#endif

/* Stolen from BESS
 * https://github.com/NetSys/bess/blob/develop/core/utils/random.h
 */
static inline uint32_t
rand_fast(uint64_t *seed)
{
    uint64_t next_seed;
    next_seed = *seed * 1103515245 + 12345;
    *seed = next_seed;
    return next_seed >> 32;
}

static inline double
to_double(uint32_t rnd, double low, double high)
{
    return low + rnd * (high - low) / (double)(UINT32_MAX);
}

static inline double
randf(uint64_t *x, double low, double high)
{
    return to_double(rand_fast(x), low, high);
}

/* Misc. */
static void
sig_handler(int sig UNUSED)
{
    exit(0);
}

static int
double_compare(const void *a, const void *b)
{
    if (*(const double *)a > *(const double *)b) {
        return 1;
    }
    if (*(const double *)a < *(const double *)b) {
        return -1;
    }
    return 0;
}

static double
get_time_msec(void)
{
    return 1000 * (rte_get_tsc_cycles() / (double)rte_get_tsc_hz());
}

static inline struct rte_mbuf *
current_template(void)
{
    return &tx_mbuf_template;
}

static inline int
ether_addr_from_str(const char *str, struct ether_addr *addr)
{
    int mac[6], ret, i;
    ret = str == NULL ? 0 : sscanf(str, "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1],
                                   &mac[2], &mac[3], &mac[4], &mac[5]);

    if (ret != 6 || addr == NULL) {
        return -1;
    }

    for (i = 0; i < 6; i++) {
        addr->addr_bytes[i] = (uint8_t)mac[i];
    }
    return 0;
}

/* Using AVX for now. Revisit this decision someday */
/* mbuf_alloc_bulk: Bulk alloc packets.
 *    array: Array to allocate into.
 *    len: Length
 *    cnt: Count
 */
static inline int
mbuf_alloc_bulk(struct rte_mempool *mp, mbuf_array_t array, uint16_t len,
                int cnt)
{
    int ret;
    int i;

    __m128i template; /* 256-bit write was worse... */
    __m128i rxdesc_fields;

    struct rte_mbuf tmp;
    /* DPDK 2.1 specific
     * packet_type 0 (32 bits)
     * pkt_len len (32 bits)
     * data_len len (16 bits)
     * vlan_tci 0 (16 bits)
     * rss 0 (32 bits)
     */
    rxdesc_fields = _mm_setr_epi32(0, len, len, 0);

    ret = rte_mempool_get_bulk(mp, (void **)array, cnt);
    if (ret != 0) {
        return ret;
    }

    template = *((__m128i *)&current_template()->buf_len);

    if (cnt & 1) {
        array[cnt] = &tmp;
    }

    /* 4 at a time didn't help */
    for (i = 0; i < cnt; i += 2) {
        /* since the data is
         * likely to be in
         * the store buffer
         * as 64-bit
         * writes,
         * 128-bit
         * read will
         * cause
         * stalls */
        struct rte_mbuf *mbuf0 = array[i];
        struct rte_mbuf *mbuf1 = array[i + 1];

        _mm_store_si128((__m128i *)&mbuf0->buf_len, template);
        _mm_store_si128((__m128i *)&mbuf0->packet_type, rxdesc_fields);

        _mm_store_si128((__m128i *)&mbuf1->buf_len, template);
        _mm_store_si128((__m128i *)&mbuf1->packet_type, rxdesc_fields);
    }

    if (cnt & 1)
        array[cnt] = NULL;
    return 0;
}

#endif
