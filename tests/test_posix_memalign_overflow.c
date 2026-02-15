/* v2 TEST: posix_memalign overflow is caught */
#include <stdlib.h>
int main(void) {
    void *p = NULL;
    posix_memalign(&p, 64, 32);
    if (!p) return 1;
    ((char *)p)[32] = 'X';  /* overflow */
    free(p);
    return 0;
}
