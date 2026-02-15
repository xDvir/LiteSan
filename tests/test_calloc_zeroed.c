/* Test: calloc returns zero-initialized memory (not 0xAA junk) */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
int main(void) {
    uint64_t *p = (uint64_t *)calloc(8, sizeof(uint64_t));

    int pass = 1;
    for (int i = 0; i < 8; i++) {
        if (p[i] != 0) {
            fprintf(stderr, "FAIL: p[%d] = 0x%llx (expected 0)\n",
                    i, (unsigned long long)p[i]);
            pass = 0;
        }
    }
    free(p);
    if (pass) {
        fprintf(stderr, "PASS: calloc returned zeroed memory\n");
        return 0;
    }
    return 1;
}
