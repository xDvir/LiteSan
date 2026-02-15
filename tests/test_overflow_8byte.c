/* Test: 8-byte buffer overflow detected on free */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(64);
    memset(p + 64, 'A', 8);  /* 8-byte overflow */
    free(p);
    return 0;
}
