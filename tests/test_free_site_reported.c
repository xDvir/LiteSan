/* Test: free-site diagnostic is printed on UAF detection
 * Verifies that the sanitizer reports the free-site in its error output. */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(64);
    if (!p) return 1;
    free(p);

    /* UAF write */
    *(unsigned long long *)p = 0x4141414141414141ULL;

    /* Cycle quarantine */
    for (int i = 0; i < 300; i++) {
        char *q = malloc(64);
        if (q) free(q);
    }
    return 0;
}
