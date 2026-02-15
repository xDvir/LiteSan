/* Test: overflow via memcpy */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(16);
    char src[64];
    memset(src, 'Z', 64);
    memcpy(p, src, 64);  /* copies 64 bytes into 16-byte buffer */
    free(p);
    return 0;
}
