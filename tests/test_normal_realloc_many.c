/* Test: many realloc operations — no false positives */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(16);
    memset(p, 'A', 16);
    for (int i = 0; i < 500; i++) {
        size_t new_size = 16 + (i * 7) % 4096;
        p = realloc(p, new_size);
        /* Touch the whole buffer within bounds */
        p[0] = 'X';
        p[new_size - 1] = 'Y';
    }
    free(p);
    return 0;
}
