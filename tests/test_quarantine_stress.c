/* Test: quarantine stress — 30K+ frees with varied sizes */
#include <stdlib.h>
#include <string.h>
int main(void) {
    for (int i = 0; i < 30100; i++) {
        size_t sz = 1 + (i * 37) % 4096;
        void *p = malloc(sz);
        memset(p, (char)i, sz);
        free(p);
    }
    return 0;
}
