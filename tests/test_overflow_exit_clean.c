/* Test: leaked allocations without corruption — no false positives on exit */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    /* Allocate several buffers, write within bounds, never free */
    char *a = malloc(64);
    memset(a, 'A', 64);

    char *b = malloc(128);
    memset(b, 'B', 128);

    char *c = malloc(256);
    memset(c, 'C', 256);

    /* Atexit registry scan should find these but report no corruption */
    fprintf(stderr, "PASS: leaked allocations — no false positives\n");
    return 0;
}
