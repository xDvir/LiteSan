/* v2 TEST: UAF write to MIDDLE of buffer — v1 misses this, v2 catches it
 * This tests the multi-spot UAF check (middle 8 bytes). */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int main(void) {
    char *p = malloc(128);
    free(p);
    /* Write to the middle of the freed buffer (offset ~64, aligned to 8) */
    *(uint64_t *)(p + 64) = 0x4141414141414141ULL;
    /* Force quarantine eviction */
    for (int i = 0; i < 2100; i++) {
        void *tmp = malloc(32);
        free(tmp);
    }
    return 0;
}
