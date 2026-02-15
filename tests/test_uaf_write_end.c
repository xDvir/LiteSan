/* v2 TEST: UAF write to END of buffer — v1 misses this, v2 catches it
 * This tests the multi-spot UAF check (last 8 bytes). */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int main(void) {
    char *p = malloc(128);
    free(p);
    /* Write to the last 8 bytes of the freed buffer */
    *(uint64_t *)(p + 120) = 0x4242424242424242ULL;
    /* Force quarantine eviction */
    for (int i = 0; i < 2100; i++) {
        void *tmp = malloc(32);
        free(tmp);
    }
    return 0;
}
