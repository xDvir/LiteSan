/* Test: immediate double free (no ops in between) */
#include <stdlib.h>
int main(void) {
    void *p = malloc(128);
    free(p);
    free(p);
    return 0;
}
