#ifndef PKTGEN_UTIL_H
#define PKTGEN_UTIL_H 1

#include <stdio.h>
#include <rte_cycles.h>
#include <readline/history.h>

#define UNUSED __attribute__((__unused__))
#define HISTORY_FILE "./.pktgen_history"

/* smallprng
 * source: http://burtleburtle.net/bob/rand/smallprng.html
 */
typedef unsigned long long u8;
typedef struct ranctx { u8 a; u8 b; u8 c; u8 d; } ranctx;

#define rot2(x,k) (((x)<<(k))|((x)>>(64-(k))))
static u8 ranval( ranctx *x ) {
    u8 e = x->a - rot2(x->b, 7);
    x->a = x->b ^ rot2(x->c, 13);
    x->b = x->c + rot2(x->d, 37);
    x->c = x->d + e;
    x->d = e + x->a;
    return x->d;
}

static double randf (ranctx *x, double low, double high) {
    return low + (float)ranval(x)/((double)(UINT64_MAX/(high-low)));
}

static void raninit( ranctx *x, u8 seed ) {
    u8 i;
    x->a = 0xf1ea5eed, x->b = x->c = x->d = seed;
    for (i=0; i<20; ++i) {
        (void)ranval(x);
    }
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

static double get_time_sec(void) {
    return rte_get_tsc_cycles() / (double) rte_get_tsc_hz();
}
#endif
