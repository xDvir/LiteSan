/* Test: overflow AFTER realloc grow (write past new size) */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(16);
    memset(p, 'A', 16);
    p = realloc(p, 32);        /* grow to 32 */
    memset(p, 'B', 32);
    p[32] = 'X';               /* overflow past new size */
    free(p);                    /* should catch */
    return 0;
}
