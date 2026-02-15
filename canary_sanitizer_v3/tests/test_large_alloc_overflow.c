/* Test: overflow on large allocation (>4KB) */
#include <stdlib.h>
int main(void) {
    char *p = malloc(8192);
    p[8192] = 'X';
    free(p);
    return 0;
}
