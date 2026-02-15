/* Test: simple double free */
#include <stdlib.h>
int main(void) {
    char *p = malloc(64);
    free(p);
    free(p);  /* double free */
    return 0;
}
