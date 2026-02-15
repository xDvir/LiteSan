/* Test: 8-byte heap buffer overflow (overwrites entire tail canary) */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(64);
    memset(p, 'B', 64 + 8);  /* overwrite all 8 bytes of tail canary */
    free(p);
    return 0;
}
