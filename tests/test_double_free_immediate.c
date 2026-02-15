/* Test: immediate double-free (no other operations between) */
#include <stdlib.h>
int main(void) {
    void *p = malloc(1);
    free(p);
    free(p);
    return 0;
}
