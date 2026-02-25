/* v2 TEST: aligned_alloc overflow is caught */
/* alignment <= 16 goes through LiteSan; > 16 passes through to real allocator */
#include <stdlib.h>
int main(void) {
    char *p = aligned_alloc(16, 32);
    if (!p) return 1;
    p[32] = 'X';  /* overflow */
    free(p);
    return 0;
}
