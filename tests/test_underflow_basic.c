/* Test: heap underflow detection — corrupt underflow canary directly
 * Header is 32 bytes: [underflow(8)][alloc_site(8)][size(8)][canary(8)][user data...]
 * underflow canary is at p - 32 */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(64);
    /* Write 8 bytes BEFORE the allocation — corrupts underflow canary
     * Header is 32 bytes. underflow canary is at p-32 */
    *(unsigned long long *)(p - 32) = 0x4141414141414141ULL;
    free(p);  /* should detect underflow canary corruption */
    return 0;
}
