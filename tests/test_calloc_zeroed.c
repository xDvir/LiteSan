/* Test: calloc returns zero-filled memory (not 0xAA junk) */
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    char *p = calloc(1, 128);
    for (int i = 0; i < 128; i++) {
        if (p[i] != 0) {
            fprintf(stderr, "FAIL: calloc byte %d is 0x%02x, expected 0x00\n",
                    i, (unsigned char)p[i]);
            free(p);
            return 1;
        }
    }
    fprintf(stderr, "PASS: calloc memory is zeroed\n");
    free(p);
    return 0;
}
