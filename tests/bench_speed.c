/*
 * bench_speed.c — Benchmark for canary_sanitizer throughput.
 *
 * Measures malloc/free/calloc/realloc throughput.
 * Run three ways:
 *   1) No sanitizer (baseline):     ./bench_speed
 *   2) v1 sanitizer:                LD_PRELOAD=../canary_sanitizer.so ./bench_speed
 *   3) v2 sanitizer:                LD_PRELOAD=./canary_sanitizer.so ./bench_speed
 *
 * Use the run_bench.sh script to automate all three and compare.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ITERS      500000
#define LIVE_MAX   4096

static void *live[LIVE_MAX];
static int live_count = 0;

static unsigned int xorshift_state = 0xDEADBEEF;

static unsigned int xorshift(void) {
    xorshift_state ^= xorshift_state << 13;
    xorshift_state ^= xorshift_state >> 17;
    xorshift_state ^= xorshift_state << 5;
    return xorshift_state;
}

static size_t random_size(void) {
    unsigned int r = xorshift() % 100;
    if (r < 40)      return 1 + (xorshift() % 32);       /* tiny: 1-32 */
    else if (r < 70)  return 33 + (xorshift() % 224);     /* small: 33-256 */
    else if (r < 90)  return 257 + (xorshift() % 3840);   /* medium: 257-4096 */
    else               return 4097 + (xorshift() % 61440); /* large: 4K-64K */
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void bench_malloc_free(void) {
    double t0 = now_sec();
    live_count = 0;

    for (int i = 0; i < ITERS; i++) {
        unsigned int action = xorshift() % 100;

        if (action < 60 || live_count == 0) {
            /* malloc */
            if (live_count < LIVE_MAX) {
                size_t sz = random_size();
                void *p = malloc(sz);
                if (p) {
                    memset(p, 0x42, sz < 64 ? sz : 64);
                    live[live_count++] = p;
                }
            }
        } else if (action < 80) {
            /* free */
            int idx = xorshift() % live_count;
            free(live[idx]);
            live[idx] = live[--live_count];
        } else if (action < 90) {
            /* realloc */
            int idx = xorshift() % live_count;
            size_t sz = random_size();
            void *p = realloc(live[idx], sz);
            if (p) {
                live[idx] = p;
            }
        } else {
            /* calloc */
            if (live_count < LIVE_MAX) {
                size_t sz = random_size();
                void *p = calloc(1, sz);
                if (p) {
                    live[live_count++] = p;
                }
            }
        }
    }

    /* Cleanup */
    for (int i = 0; i < live_count; i++)
        free(live[i]);
    live_count = 0;

    double elapsed = now_sec() - t0;
    printf("  malloc/free/realloc/calloc mix: %.3f sec  (%d ops = %.0f ops/sec)\n",
           elapsed, ITERS, ITERS / elapsed);
}

static void bench_pure_malloc_free(void) {
    double t0 = now_sec();
    for (int i = 0; i < ITERS; i++) {
        size_t sz = random_size();
        void *p = malloc(sz);
        if (p) {
            ((char *)p)[0] = 'X';
            free(p);
        }
    }
    double elapsed = now_sec() - t0;
    printf("  pure malloc+free pairs:         %.3f sec  (%d ops = %.0f ops/sec)\n",
           elapsed, ITERS, ITERS / elapsed);
}

static void bench_calloc(void) {
    double t0 = now_sec();
    for (int i = 0; i < ITERS; i++) {
        size_t sz = 1 + (xorshift() % 256);
        void *p = calloc(1, sz);
        if (p) free(p);
    }
    double elapsed = now_sec() - t0;
    printf("  calloc+free pairs:              %.3f sec  (%d ops = %.0f ops/sec)\n",
           elapsed, ITERS, ITERS / elapsed);
}

static void bench_large_alloc(void) {
    int count = ITERS / 10;
    double t0 = now_sec();
    for (int i = 0; i < count; i++) {
        size_t sz = 4096 + (xorshift() % 61440);
        void *p = malloc(sz);
        if (p) {
            memset(p, 0x55, 64);  /* touch first 64 bytes */
            free(p);
        }
    }
    double elapsed = now_sec() - t0;
    printf("  large alloc (4K-64K) pairs:     %.3f sec  (%d ops = %.0f ops/sec)\n",
           elapsed, count, count / elapsed);
}

static void bench_realloc_chain(void) {
    double t0 = now_sec();
    for (int i = 0; i < ITERS / 10; i++) {
        char *p = malloc(16);
        if (!p) continue;
        for (int j = 0; j < 10; j++) {
            size_t sz = 16 + (j * 100);
            p = realloc(p, sz);
            if (!p) break;
            p[0] = 'R';
        }
        if (p) free(p);
    }
    double elapsed = now_sec() - t0;
    int count = ITERS / 10;
    printf("  realloc chains (10 resizes):    %.3f sec  (%d chains = %.0f chains/sec)\n",
           elapsed, count, count / elapsed);
}

int main(void) {
    printf("=== Canary Sanitizer Benchmark (%d iterations) ===\n\n", ITERS);

    bench_malloc_free();
    bench_pure_malloc_free();
    bench_calloc();
    bench_large_alloc();
    bench_realloc_chain();

    printf("\nDone.\n");
    return 0;
}
