/* Test: mix of malloc, calloc, realloc — no false positives */
#include <stdlib.h>
#include <string.h>
int main(void) {
    void *a = malloc(64);
    void *b = calloc(16, 4);
    void *c = realloc(NULL, 128);

    memset(a, 'A', 64);
    memset(b, 'B', 64);
    memset(c, 'C', 128);

    a = realloc(a, 128);
    memset(a, 'A', 128);

    free(b);
    free(c);
    free(a);
    return 0;
}
