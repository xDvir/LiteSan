/* Test: overflow detected during realloc */
#include <stdlib.h>
int main(void) {
    char *p = malloc(16);
    p[16] = 'X';  /* overflow */
    p = realloc(p, 32);  /* should catch overflow on old buffer */
    free(p);
    return 0;
}
