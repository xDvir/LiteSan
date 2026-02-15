/* Test: calloc'd memory still has canaries (overflow detected on free) */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = calloc(1, 32);
    memset(p, 'E', 32);
    p[32] = 'X';  /* overflow past calloc'd block */
    free(p);       /* should catch tail canary corruption */
    return 0;
}
