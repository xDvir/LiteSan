/* Test: basic malloc/free usage — no false positives */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(64);
    memset(p, 'X', 64);
    free(p);

    int *arr = malloc(100 * sizeof(int));
    for (int i = 0; i < 100; i++) arr[i] = i;
    free(arr);

    return 0;
}
