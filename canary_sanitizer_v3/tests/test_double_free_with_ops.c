/* Test: double free with other operations in between */
#include <stdlib.h>
int main(void) {
    void *p = malloc(64);
    void *q = malloc(128);
    free(p);
    free(q);
    free(p);  /* double free — p is still in quarantine */
    return 0;
}
