/* v2 TEST: aligned_alloc overflow is caught */
#include <stdlib.h>
int main(void) {
    char *p = aligned_alloc(64, 32);
    if (!p) return 1;
    p[32] = 'X';  /* overflow */
    free(p);
    return 0;
}
