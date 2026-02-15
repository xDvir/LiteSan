/* Test: overflow on tiny allocation (1 byte alloc, 1 byte overflow) */
#include <stdlib.h>
int main(void) {
    char *p = malloc(1);
    p[0] = 'A';   /* fine */
    p[1] = 'X';   /* overflow by 1 byte on 1-byte alloc */
    free(p);
    return 0;
}
