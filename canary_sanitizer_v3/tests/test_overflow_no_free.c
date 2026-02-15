/* Test: overflow detected at exit (block never freed, caught by registry scan) */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(32);
    p[32] = 'X';  /* overflow */
    /* no free — registry scan at exit should catch it */
    return 0;
}
