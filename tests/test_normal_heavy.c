/* Test: heavy malloc/free churn — no false positives */
#include <stdlib.h>
#include <string.h>
int main(void) {
    void *ptrs[200];
    for (int round = 0; round < 7; round++) {
        for (int i = 0; i < 200; i++) {
            ptrs[i] = malloc(1 + (i * 17) % 512);
            memset(ptrs[i], (char)i, 1 + (i * 17) % 512);
        }
        for (int i = 0; i < 200; i++)
            free(ptrs[i]);
    }
    return 0;
}
