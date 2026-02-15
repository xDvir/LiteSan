/* Test: overflow on zero-size allocation (malloc(0) + write 1 byte) */
#include <stdlib.h>
int main(void) {
    char *p = malloc(0);  /* valid per C standard, returns non-NULL */
    if (!p) return 77;    /* skip if malloc(0) returns NULL */
    p[0] = 'X';           /* any write overflows into tail canary */
    free(p);
    return 0;
}
