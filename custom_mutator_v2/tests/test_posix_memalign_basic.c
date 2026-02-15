/* v2 TEST: posix_memalign is intercepted */
#include <stdlib.h>
#include <string.h>
int main(void) {
    void *p = NULL;
    int ret = posix_memalign(&p, 64, 128);
    if (ret != 0 || p == NULL) return 1;
    memset(p, 'P', 128);
    free(p);
    return 0;
}
