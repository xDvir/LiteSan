/* Test: realloc shrink */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(256);
    memset(p, 'X', 256);
    p = realloc(p, 32);
    /* First 32 bytes should still be 'X' */
    for (int i = 0; i < 32; i++) {
        if (p[i] != 'X') return 1;
    }
    free(p);
    return 0;
}
