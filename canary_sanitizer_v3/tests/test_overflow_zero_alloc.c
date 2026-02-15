/* Test: overflow on malloc(0) */
#include <stdlib.h>
int main(void) {
    char *p = malloc(0);
    if (p) {
        p[0] = 'X';
        free(p);
    }
    return 0;
}
