/* Test: overflow via memcpy with wrong size */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[100];
    memset(src, 'M', 100);
    char *dst = malloc(50);
    memcpy(dst, src, 100);  /* copies 100 bytes into 50-byte buffer */
    free(dst);
    return 0;
}
