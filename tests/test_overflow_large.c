/* Test: large heap buffer overflow (50 bytes past end) */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(16);
    memset(p, 'C', 16 + 50);  /* massive overrun */
    free(p);
    return 0;
}
