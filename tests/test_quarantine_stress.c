/* Test: heavy quarantine stress — varied sizes, lots of evictions */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    /* 20,000 alloc/free cycles with varied sizes */
    for (int i = 0; i < 20000; i++) {
        size_t sz = (i * 31 + 7) % 2048 + 1;
        char *p = malloc(sz);
        memset(p, i & 0xFF, sz);  /* write full allocation */
        free(p);
    }

    /* Large blocks through quarantine */
    for (int i = 0; i < 100; i++) {
        char *p = malloc(65536);  /* 64KB blocks */
        memset(p, 'L', 65536);
        free(p);
    }

    /* Tiny blocks */
    for (int i = 0; i < 10000; i++) {
        char *p = malloc(1);
        p[0] = 'T';
        free(p);
    }

    fprintf(stderr, "PASS: quarantine stress (30,100 evictions) — no false positives\n");
    return 0;
}
