/* Test: realloc(NULL, size) behaves as malloc */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = realloc(NULL, 64);
    memset(p, 'Z', 64);
    free(p);
    return 0;
}
