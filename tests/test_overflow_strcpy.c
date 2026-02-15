/* Test: realistic overflow via strcpy (string longer than buffer) */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = malloc(8);
    strcpy(buf, "AABBCCDDEE");  /* 10 chars + NUL = 11 bytes into 8-byte buffer */
    free(buf);
    return 0;
}
