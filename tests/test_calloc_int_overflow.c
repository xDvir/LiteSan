/* v2 TEST: calloc integer overflow returns NULL (not a tiny allocation) */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
int main(void) {
    /* SIZE_MAX / 2 + 1 elements of size 2 overflows size_t */
    size_t nmemb = (SIZE_MAX / 2) + 1;
    size_t size = 2;
    void *p = calloc(nmemb, size);
    if (p != NULL) {
        fprintf(stderr, "FAIL: calloc should have returned NULL on overflow\n");
        free(p);
        return 1;
    }
    fprintf(stderr, "PASS: calloc returned NULL on integer overflow\n");
    return 0;
}
