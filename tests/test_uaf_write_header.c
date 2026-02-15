/* Test: UAF write that corrupts the header (before user data) */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int main(void) {
    char *p = malloc(64);
    free(p);  /* poisoned, in quarantine */

    /* UAF write: corrupt the alloc_header (16 bytes before user ptr) */
    uint64_t *hdr_canary = (uint64_t *)(p - 8);  /* head canary field */
    *hdr_canary = 0x4141414141414141ULL;

    /* Force quarantine eviction */
    for (int i = 0; i < 2100; i++) {
        char *tmp = malloc(32);
        free(tmp);
    }
    /* check_quarantined sees header != FREED_CANARY → UAF WRITE */
    return 0;
}
