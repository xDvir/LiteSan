/* Test: heap underflow detection — corrupt underflow canary directly
 * v3 header is 24 bytes: [underflow(8)][size(8)][canary(8)][user data...]
 * underflow canary is at p - 24 */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(64);
    /* Write 8 bytes BEFORE the allocation — corrupts underflow canary
     * In v3: header is 24 bytes. underflow canary is at p-24 */
    *(unsigned long long *)(p - 24) = 0x4141414141414141ULL;
    free(p);  /* should detect underflow canary corruption */
    return 0;
}
