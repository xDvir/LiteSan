/* Test: realloc(NULL, size) acts as malloc */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
int main(void) {
    uint64_t *p = (uint64_t *)realloc(NULL, 64);
    if (!p) { fprintf(stderr, "FAIL: realloc(NULL,64) returned NULL\n"); return 1; }

    /* Should be junk-filled like malloc */
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
        fprintf(stderr, "PASS: realloc(NULL, 64) = malloc(64) with junk fill\n");
        return 0;
    }
    return 1;
}
