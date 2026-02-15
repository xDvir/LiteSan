/* Test: double-free with other operations in between */
#include <stdlib.h>
int main(void) {
    char *p = malloc(128);
    free(p);
    /* do other stuff — the block sits in quarantine */
    char *q = malloc(256);
    char *r = malloc(512);
    free(q);
    free(r);
    free(p);  /* double-free, block should still be in quarantine */
    return 0;
}
