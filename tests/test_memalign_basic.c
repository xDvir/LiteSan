/* v2 TEST: memalign is intercepted — basic usage works */
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
int main(void) {
    char *p = memalign(64, 128);
    memset(p, 'M', 128);
    free(p);
    return 0;
}
