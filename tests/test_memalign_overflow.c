/* v2 TEST: memalign overflow is caught (v1 would miss this entirely) */
#include <stdlib.h>
#include <malloc.h>
int main(void) {
    char *p = memalign(64, 32);
    p[32] = 'X';  /* overflow */
    free(p);       /* should detect */
    return 0;
}
