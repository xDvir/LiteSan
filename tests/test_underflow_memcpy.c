/* Test: heap underflow via memcpy — corrupt underflow canary
 * Header is 32 bytes: [underflow(8)][alloc_site(8)][size(8)][canary(8)][user data...]
 * underflow canary is at p - 32 */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(128);
    char junk[32];
    memset(junk, 'X', sizeof(junk));
    /* Copy backwards past the start of allocation — corrupts underflow canary */
    memcpy(p - 32, junk, 8);
    free(p);  /* should detect underflow canary corruption */
    return 0;
}
