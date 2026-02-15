/* Test: heavy normal usage — stress test with no bugs, exit 0 expected */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    /* Phase 1: many concurrent allocations */
    #define N 1000
    void *ptrs[N];
    for (int i = 0; i < N; i++) {
        size_t sz = (i * 37 + 13) % 4096 + 1;  /* varied sizes 1-4096 */
        ptrs[i] = malloc(sz);
        memset(ptrs[i], i & 0xFF, sz);
    }
    /* Free in random-ish order */
    for (int i = 0; i < N; i++) {
        int j = (i * 997) % N;  /* pseudo-random permutation */
        if (ptrs[j]) {
            free(ptrs[j]);
            ptrs[j] = NULL;
        }
    }
    /* Free any remaining */
    for (int i = 0; i < N; i++) {
        if (ptrs[i]) free(ptrs[i]);
    }

    /* Phase 2: rapid realloc chains */
    for (int i = 0; i < 500; i++) {
        char *p = malloc(8);
        for (int grow = 16; grow <= 1024; grow *= 2) {
            p = realloc(p, grow);
            memset(p, 'R', grow);
        }
        free(p);
    }

    /* Phase 3: calloc + free */
    for (int i = 0; i < 500; i++) {
        void *p = calloc(i + 1, 16);
        free(p);
    }

    /* Phase 4: large allocation */
    char *big = malloc(1024 * 1024);  /* 1MB */
    memset(big, 'B', 1024 * 1024);
    free(big);

    fprintf(stderr, "PASS: heavy normal usage (5000+ allocs) — no false positives\n");
    return 0;
}
