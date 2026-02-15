/* Test: mixed malloc/calloc/realloc — canaries work across all types */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    /* malloc → realloc → free */
    char *a = malloc(32);
    memset(a, 'A', 32);
    a = realloc(a, 64);
    memset(a + 32, 'B', 32);
    free(a);

    /* calloc → realloc → free */
    char *b = calloc(1, 16);
    memset(b, 'C', 16);
    b = realloc(b, 128);
    memset(b + 16, 'D', 112);
    free(b);

    /* realloc(NULL) → realloc → realloc → free */
    char *c = realloc(NULL, 8);
    memset(c, 'E', 8);
    c = realloc(c, 256);
    memset(c + 8, 'F', 248);
    c = realloc(c, 16);
    free(c);

    /* calloc → free → malloc → free */
    char *d = calloc(10, 10);
    free(d);
    char *e = malloc(100);
    memset(e, 'G', 100);
    free(e);

    fprintf(stderr, "PASS: mixed malloc/calloc/realloc — all canaries intact\n");
    return 0;
}
