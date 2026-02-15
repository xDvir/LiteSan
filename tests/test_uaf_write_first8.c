/* Test: UAF write to first 8 bytes — caught on quarantine eviction */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(64);
    free(p);
    /* Write to first 8 bytes after free */
    memset(p, 'A', 8);
    /* Force quarantine eviction by filling it */
    for (int i = 0; i < 2100; i++) {
        void *tmp = malloc(32);
        free(tmp);
    }
    return 0;
}
