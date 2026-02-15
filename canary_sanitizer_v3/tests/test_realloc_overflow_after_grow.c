/* Test: overflow on grown allocation after realloc */
#include <stdlib.h>
int main(void) {
    char *p = malloc(16);
    p = realloc(p, 64);
    p[64] = 'X';  /* overflow on new size */
    free(p);
    return 0;
}
