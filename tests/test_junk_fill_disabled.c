/* v2 TEST: CANARY_NO_JUNK disables junk fill
 * Run with: CANARY_NO_JUNK=1 LD_PRELOAD=... ./test_junk_fill_disabled
 * Memory should NOT be 0xAA (likely 0x00 or leftover from libc). */
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    /* Allocate, free, re-allocate to get libc-recycled memory */
    char *dummy = malloc(64);
    memset(dummy, 0, 64);
    free(dummy);

    char *p = malloc(64);
    int all_junk = 1;
    for (int i = 0; i < 64; i++) {
        if ((unsigned char)p[i] != 0xAA) {
            all_junk = 0;
            break;
        }
    }
    if (all_junk) {
        fprintf(stderr, "FAIL: junk fill should be disabled but got 0xAA\n");
        free(p);
        return 1;
    }
    fprintf(stderr, "PASS: junk fill disabled correctly\n");
    free(p);
    return 0;
}
