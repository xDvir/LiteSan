/* v2 TEST: poison cap limits how much memory is poisoned on free.
 * Run with: CANARY_POISON_CAP=64 LD_PRELOAD=... ./test_poison_cap
 * First 64 bytes should be 0xFE, rest should be original data. */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
int main(void) {
    char *p = malloc(256);
    memset(p, 'X', 256);
    free(p);
    /* With CANARY_POISON_CAP=64, only first 64 bytes poisoned */
    int poisoned_count = 0;
    for (int i = 0; i < 64; i++) {
        if ((unsigned char)p[i] == 0xFE) poisoned_count++;
    }
    if (poisoned_count < 60) {  /* allow some tolerance */
        fprintf(stderr, "FAIL: first 64 bytes should mostly be poisoned, got %d/64\n",
                poisoned_count);
        return 1;
    }
    /* Bytes beyond 64 should NOT all be poisoned */
    int unpoisoned = 0;
    for (int i = 128; i < 256; i++) {
        if ((unsigned char)p[i] != 0xFE) unpoisoned++;
    }
    if (unpoisoned > 0) {
        fprintf(stderr, "PASS: poison cap working (%d poisoned in first 64, "
                "%d unpoisoned in 128-255)\n", poisoned_count, unpoisoned);
    } else {
        fprintf(stderr, "FAIL: all bytes poisoned despite cap\n");
        return 1;
    }
    return 0;
}
