/* Test: quarantine eviction works cleanly with 2048+ frees */
#include <stdlib.h>
int main(void) {
    for (int i = 0; i < 3000; i++) {
        void *p = malloc(32 + (i % 128));
        free(p);
    }
    return 0;
}
