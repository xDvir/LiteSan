/* Test: new allocations filled with 0xAA junk */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
int main(void) {
    char *p = malloc(64);
    /* Check that all bytes are 0xAA */
    for (int i = 0; i < 64; i++) {
        if ((unsigned char)p[i] != 0xAA) {
            fprintf(stderr, "FAIL: byte %d is 0x%02x, expected 0xAA\n",
                    i, (unsigned char)p[i]);
            free(p);
            return 1;
        }
    }
    fprintf(stderr, "PASS: all bytes are 0xAA\n");
    free(p);
    return 0;
}
