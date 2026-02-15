/* Test: realloc growth portion filled with 0xAA junk */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    char *p = malloc(32);
    memset(p, 'X', 32);  /* fill with known data */
    p = realloc(p, 128);
    /* Original 32 bytes should be 'X' */
    for (int i = 0; i < 32; i++) {
        if (p[i] != 'X') {
            fprintf(stderr, "FAIL: original byte %d corrupted\n", i);
            free(p);
            return 1;
        }
    }
    /* New 96 bytes should be 0xAA */
    for (int i = 32; i < 128; i++) {
        if ((unsigned char)p[i] != 0xAA) {
            fprintf(stderr, "FAIL: growth byte %d is 0x%02x, expected 0xAA\n",
                    i, (unsigned char)p[i]);
            free(p);
            return 1;
        }
    }
    fprintf(stderr, "PASS: realloc growth junk fill correct\n");
    free(p);
    return 0;
}
