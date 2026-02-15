/* Test: overflow on zero-sized allocation */
#include <stdlib.h>
int main(void) {
    char *p = malloc(0);
    if (p) {
        p[0] = 'X';  /* any write overflows a 0-byte alloc */
        free(p);
    }
    return 0;
}
