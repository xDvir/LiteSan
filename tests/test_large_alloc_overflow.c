/* Test: overflow on large allocation (1MB) */
#include <stdlib.h>
#include <string.h>
int main(void) {
    size_t sz = 1024 * 1024;  /* 1MB */
    char *p = malloc(sz);
    memset(p, 'L', sz);
    p[sz] = 'X';     /* 1 byte overflow on 1MB block */
    free(p);
    return 0;
}
