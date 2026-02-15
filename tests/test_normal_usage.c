/* Test: normal heap usage — no bugs, should exit 0 (no false positives) */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    /* malloc + use + free */
    char *a = malloc(100);
    memset(a, 'A', 100);
    free(a);

    /* calloc + use + free */
    int *b = calloc(25, sizeof(int));
    for (int i = 0; i < 25; i++) b[i] = i;
    free(b);

    /* realloc chain: grow, grow, shrink, free */
    char *c = malloc(10);
    memset(c, 'C', 10);
    c = realloc(c, 50);
    memset(c + 10, 'D', 40);
    c = realloc(c, 200);
    memset(c + 50, 'E', 150);
    c = realloc(c, 30);
    free(c);

    /* many small allocs + frees */
    for (int i = 0; i < 5000; i++) {
        char *p = malloc(i % 256 + 1);
        p[0] = 'x';
        free(p);
    }

    fprintf(stderr, "PASS: normal usage — no false positives\n");
    return 0;
}
