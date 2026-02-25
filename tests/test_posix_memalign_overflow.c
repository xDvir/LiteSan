/* v2 TEST: posix_memalign overflow is caught */
/* alignment <= 16 goes through LiteSan; > 16 passes through to real allocator */
#include <stdlib.h>
int main(void) {
    void *p = NULL;
    posix_memalign(&p, 16, 32);
    if (!p) return 1;
    ((char *)p)[32] = 'X';  /* overflow */
    free(p);
    return 0;
}
