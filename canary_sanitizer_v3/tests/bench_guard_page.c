/* bench_guard_page.c — Worst-case benchmark for v3 guard page overhead.
 * Measures throughput of allocations that hit the 64KB guard page threshold. */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(void) {
    int count = 5000;

    printf("=== Guard Page Worst-Case Benchmark (%d iterations) ===\n\n", count);

    /* Test 1: 64KB allocations (exactly at threshold) */
    double t0 = now_sec();
    for (int i = 0; i < count; i++) {
        char *p = malloc(65536);
        if (p) { p[0] = 'X'; free(p); }
    }
    double e1 = now_sec() - t0;
    printf("  malloc(65536) + free:   %.3f sec  (%d ops = %.0f ops/sec)\n",
           e1, count, count / e1);

    /* Test 2: 128KB allocations */
    t0 = now_sec();
    for (int i = 0; i < count; i++) {
        char *p = malloc(131072);
        if (p) { p[0] = 'X'; free(p); }
    }
    double e2 = now_sec() - t0;
    printf("  malloc(128KB) + free:   %.3f sec  (%d ops = %.0f ops/sec)\n",
           e2, count, count / e2);

    /* Test 3: 65535 bytes (just UNDER threshold — regular path) */
    t0 = now_sec();
    for (int i = 0; i < count; i++) {
        char *p = malloc(65535);
        if (p) { p[0] = 'X'; free(p); }
    }
    double e3 = now_sec() - t0;
    printf("  malloc(65535) + free:   %.3f sec  (%d ops = %.0f ops/sec)\n",
           e3, count, count / e3);

    printf("\nDone.\n");
    return 0;
}
