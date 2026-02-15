/* Test: new allocations filled with 0xAA junk */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
int main(void) {
    uint64_t *p = (uint64_t *)malloc(64);

    /* Check all 8 uint64_t values are 0xAAAAAAAAAAAAAAAA */
    int pass = 1;
    for (int i = 0; i < 8; i++) {
        if (p[i] != 0xAAAAAAAAAAAAAAAAULL) {
            fprintf(stderr, "FAIL: p[%d] = 0x%llx (expected 0xAAAAAAAAAAAAAAAA)\n",
                    i, (unsigned long long)p[i]);
            pass = 0;
        }
    }
    free(p);
    if (pass) {
        fprintf(stderr, "PASS: all 64 bytes are 0xAA junk fill\n");
        return 0;
    }
    return 1;
}
