/* v2 TEST: memalign overflow is caught (v1 would miss this entirely) */
/* alignment <= 16 goes through LiteSan; > 16 passes through to real allocator */
#include <stdlib.h>
#include <malloc.h>
int main(void) {
    char *p = memalign(16, 32);
    p[32] = 'X';  /* overflow */
    free(p);       /* should detect */
    return 0;
}
