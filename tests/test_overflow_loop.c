/* Test: off-by-one in a loop (classic fence-post error) */
#include <stdlib.h>
int main(void) {
    int n = 100;
    char *p = malloc(n);
    for (int i = 0; i <= n; i++) {  /* bug: <= instead of < */
        p[i] = 'x';
    }
    free(p);
    return 0;
}
