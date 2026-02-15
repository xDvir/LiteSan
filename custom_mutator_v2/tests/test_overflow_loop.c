/* Test: overflow via loop (classic off-by-one) */
#include <stdlib.h>
int main(void) {
    int *p = malloc(10 * sizeof(int));
    for (int i = 0; i <= 10; i++)  /* <= instead of < */
        p[i] = i;
    free(p);
    return 0;
}
