/* Test: 1-byte buffer overflow detected on free */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(32);
    p[32] = 'X';  /* off-by-one overflow */
    free(p);
    return 0;
}
