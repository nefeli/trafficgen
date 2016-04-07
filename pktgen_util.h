#ifndef PKTGEN_UTIL_H
#define PKTGEN_UTIL_H 1

#include "simd.h"

#include <stdio.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <readline/history.h>

#define UNUSED __attribute__((__unused__))
#define HISTORY_FILE "./.pktgen_history"
#define RTE_MBUF_FROM_BADDR(ba)     (((struct rte_mbuf *)(ba)) - 1)

typedef struct rte_mbuf** mbuf_array_t;

struct rte_mbuf tx_mbuf_template[RTE_MAX_LCORE];

/* Stolen from BESS
 * https://github.com/NetSys/bess/blob/develop/core/utils/random.h
 */
static inline uint32_t rand_fast(uint64_t *seed) {
	uint64_t next_seed;
	next_seed = *seed * 1103515245 + 12345;
	*seed = next_seed;
	return next_seed >> 32;
}

static double randf (uint64_t *x, double low, double high) {
    return low + (float)rand_fast(x)/((double)(UINT64_MAX/(high-low)));
}

/* Misc. */
static void sig_handler(int sig UNUSED) {
    printf("\n");
    write_history(HISTORY_FILE);
    exit(0);
}

static int double_compare(const void *a, const void *b) {
    if (*(const double*)a > *(const double*)b) {
        return 1;
    }
    if (*(const double*)a < *(const double*)b) {
        return -1;
    }
    return 0;
}

static double get_time_msec(void) {
    return 1000 * (rte_get_tsc_cycles() / (double) rte_get_tsc_hz());
}

static inline struct rte_mbuf *current_template(void) {
    return &tx_mbuf_template[rte_socket_id()];
}

static inline int
ether_addr_from_str(const char *str, struct ether_addr *addr)
{
    int mac[6], ret, i;
    ret = str == NULL ? 0 : sscanf(str, "%x:%x:%x:%x:%x:%x",
            &mac[0],
            &mac[1],
            &mac[2],
            &mac[3],
            &mac[4],
            &mac[5]);

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
static int mbuf_alloc_bulk(struct rte_mempool *mp, mbuf_array_t array, uint16_t len, int cnt) {
    int ret;
    int i;

    __m128i template;   /* 256-bit write was worse... */
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

    ret = rte_mempool_get_bulk(mp, (void**)array, cnt);
    if (ret != 0) {
        return ret;
    }

    template = *((__m128i*)&current_template()->buf_len);

    if (cnt & 1) {
        array[cnt] = &tmp;
    }

    /* 4 at a time didn't help */
    for (i = 0; i < cnt; i+=2) {
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
        _mm_store_si128((__m128i *)&mbuf0->packet_type,
                rxdesc_fields);

        _mm_store_si128((__m128i *)&mbuf1->buf_len, template);
        _mm_store_si128((__m128i *)&mbuf1->packet_type,
                rxdesc_fields);
    }

    if (cnt & 1)
        array[cnt] = NULL;
    return 0;
}

#if 0
/* for packets to be processed in the fast path, all packets must:
 * 1. share the same mempool
 * 2. single segment
 * 3. reference counter == 1
 * 4. the data buffer is embedded in the mbuf
 *    (Do not use RTE_MBUF_(IN)DIRECT, since there is a difference
 *     between DPDK 1.8 and 2.0) */
static int mbuf_free_bulk(mbuf_array_t array, int cnt) {
    struct rte_mempool *_pool = array[0]->pool;

    /* broadcast */
    // Offset contains two copies of sizeof(struct rte_mbuf)
    __m128i offset = _mm_set1_epi64x(sizeof(struct rte_mbuf));
    // Mask for byte 1-3 (inlusive)
    __m128i info_mask = _mm_set1_epi64x(0x00ffffff00000000UL);
    // consts for comparison
    __m128i info_simple = _mm_set1_epi64x(0x0001000100000000UL);
    __m128i pool = _mm_set1_epi64x((uint64_t) _pool);

    int i;

    for (i = 0; i < (cnt & ~1); i += 2) {
        struct rte_mbuf *mbuf0 = array[i];
        struct rte_mbuf *mbuf1 = array[i + 1];

        __m128i buf_addrs_derived;
        __m128i buf_addrs_actual;
        __m128i info;
        __m128i pools;
        __m128i vcmp1, vcmp2, vcmp3;

        // Pack two mbuf pointers into one _m128i
        __m128i mbuf_ptrs = gather_m128i(mbuf1, mbuf0);

        // Buffer addresses
        buf_addrs_actual = gather_m128i(&mbuf0->buf_addr, &mbuf1->buf_addr);
        // Do buffers begin right after mbufs (checking if buffers
        // are indirect).
        buf_addrs_derived = _mm_add_epi64(mbuf_ptrs, offset);

        /* refcnt and nb_segs must be 1 */
        info = gather_m128i(&mbuf0->buf_len, &mbuf1->buf_len);
        info = _mm_and_si128(info, info_mask);

        pools = gather_m128i(&mbuf0->pool, &mbuf1->pool);

        vcmp1 = _mm_cmpeq_epi64(buf_addrs_derived, buf_addrs_actual);
        vcmp2 = _mm_cmpeq_epi64(info, info_simple);
        vcmp3 = _mm_cmpeq_epi64(pool, pools);

        vcmp1 = _mm_and_si128(vcmp1, vcmp2);
        vcmp1 = _mm_and_si128(vcmp1, vcmp3);

        if (unlikely(_mm_movemask_epi8(vcmp1) != 0xffff))
            goto slow_path;
    }

    // Odd number of packets
    if (i < cnt) {
        struct rte_mbuf *mbuf = array[i];

        if (unlikely(mbuf->pool != _pool ||
                mbuf->next != NULL ||
                rte_mbuf_refcnt_read(mbuf) != 1 ||
                RTE_MBUF_FROM_BADDR(mbuf->buf_addr) != mbuf))
        {
            goto slow_path;
        }
    }

    /* NOTE: it seems that zeroing the refcnt of mbufs is not necessary.
     * (allocators will reset them) */
    rte_mempool_put_bulk(_pool, (void **)array, cnt);
    return 0;

slow_path:
    for (i = 0; i < cnt; i++)
        rte_pktmbuf_free(array[i]);
    return 0;
}
#endif
#endif
