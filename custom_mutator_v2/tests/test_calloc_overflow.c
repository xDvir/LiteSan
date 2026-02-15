/* Test: overflow on calloc allocation */
#include <stdlib.h>
int main(void) {
    char *p = calloc(1, 32);
    p[32] = 'X';
    free(p);
    return 0;
}
