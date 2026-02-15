/* Test: heap buffer overflow without free — atexit registry scan catches it */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(32);
    memset(p, 'A', 33);  /* 1 byte overflow — corrupts tail canary */
    /* No free(p) — intentional leak. atexit scan should detect the overflow. */
    return 0;
}
