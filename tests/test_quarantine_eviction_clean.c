/* Test: quarantine eviction of clean blocks — no false positive on eviction */
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    /* Fill quarantine completely (2048 slots) + overflow to trigger evictions */
    for (int i = 0; i < 5000; i++) {
        char *p = malloc(64);
        p[0] = 'x';
        free(p);
        /* Each free pushes to quarantine, evicts oldest.
           Eviction check must pass (no UAF writes happened). */
    }
    fprintf(stderr, "PASS: 5000 clean quarantine evictions — no false positives\n");
    return 0;
}
