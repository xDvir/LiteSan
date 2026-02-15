/* Test: realloc growth region filled with 0xAA junk */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
int main(void) {
    char *p = malloc(16);
    memset(p, 'Z', 16);       /* write real data to first 16 bytes */
    p = realloc(p, 64);       /* grow to 64 bytes */

    /* First 16 bytes should still be 'Z' (preserved by realloc) */
    int pass = 1;
    for (int i = 0; i < 16; i++) {
        if (p[i] != 'Z') {
            fprintf(stderr, "FAIL: p[%d] = 0x%02x (expected 'Z'=0x5a)\n",
                    i, (unsigned char)p[i]);
            pass = 0;
        }
    }

    /* Bytes 16-63 should be 0xAA (junk fill on grown portion) */
    for (int i = 16; i < 64; i++) {
        if ((unsigned char)p[i] != 0xAA) {
            fprintf(stderr, "FAIL: p[%d] = 0x%02x (expected 0xAA)\n",
                    i, (unsigned char)p[i]);
            pass = 0;
        }
    }

    free(p);
    if (pass) {
        fprintf(stderr, "PASS: realloc preserved old data + junk-filled new portion\n");
        return 0;
    }
    return 1;
}
