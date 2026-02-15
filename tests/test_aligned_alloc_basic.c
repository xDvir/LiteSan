/* v2 TEST: aligned_alloc is intercepted */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = aligned_alloc(64, 128);
    if (!p) return 1;
    memset(p, 'A', 128);
    free(p);
    return 0;
}
