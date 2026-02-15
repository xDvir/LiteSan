/* Test: realloc shrink — old data preserved, canaries intact */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    char *p = malloc(128);
    memset(p, 'Q', 128);
    p = realloc(p, 32);  /* shrink from 128 to 32 */
    if (!p) { fprintf(stderr, "FAIL: realloc shrink returned NULL\n"); return 1; }

    int pass = 1;
    for (int i = 0; i < 32; i++) {
        if (p[i] != 'Q') {
            fprintf(stderr, "FAIL: p[%d] = 0x%02x (expected 'Q'=0x51)\n",
                    i, (unsigned char)p[i]);
            pass = 0;
        }
    }
    free(p);  /* should pass canary checks (tail was rewritten at new size) */
    if (pass) {
        fprintf(stderr, "PASS: realloc shrink — data preserved, canaries OK\n");
        return 0;
    }
    return 1;
}
