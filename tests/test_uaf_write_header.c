/* Test: UAF write to header area (before user pointer) */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(64);
    free(p);
    /* Corrupt the freed canary in header (at p - 8, where canary lives) */
    *(long *)(p - 8) = 0x4141414141414141;
    /* Force eviction */
    for (int i = 0; i < 2100; i++) {
        void *tmp = malloc(32);
        free(tmp);
    }
    return 0;
}
