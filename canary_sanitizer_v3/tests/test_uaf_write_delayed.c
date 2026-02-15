/* Test: delayed UAF write — write while block is still in quarantine */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(64);
    free(p);
    /* Do some other allocations but not enough to evict p */
    for (int i = 0; i < 100; i++) {
        void *tmp = malloc(16);
        free(tmp);
    }
    /* Now corrupt the freed block */
    memset(p, 'B', 8);
    /* Now evict it */
    for (int i = 0; i < 2100; i++) {
        void *tmp = malloc(32);
        free(tmp);
    }
    return 0;
}
