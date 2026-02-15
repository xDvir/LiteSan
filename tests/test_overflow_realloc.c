/* Test: overflow detected on realloc (not free) */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(20);
    memset(p, 'D', 20);
    p[20] = 'X';              /* overflow */
    p = realloc(p, 40);       /* check_canaries runs BEFORE resize */
    free(p);
    return 0;
}
