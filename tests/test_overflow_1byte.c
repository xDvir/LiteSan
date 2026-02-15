/* Test: off-by-one heap buffer overflow (1 byte past end) */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(32);
    memset(p, 'A', 32);
    p[32] = 'X';  /* 1 byte overflow — corrupts first byte of tail canary */
    free(p);       /* check_canaries should catch it here */
    return 0;
}
