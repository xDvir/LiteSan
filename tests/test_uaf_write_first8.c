/* Test: UAF write to first 8 bytes — caught by quarantine eviction */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(64);
    memset(p, 'A', 64);
    free(p);  /* poisoned with 0xFE, pushed to quarantine */

    /* UAF write: overwrite first 8 bytes of freed memory */
    memset(p, 'X', 8);

    /* Force quarantine eviction by doing 2048+ more frees */
    for (int i = 0; i < 2100; i++) {
        char *tmp = malloc(32);
        free(tmp);
    }
    /* When p's quarantine slot is evicted, check_quarantined() sees
       first 8 bytes = 'XXXXXXXX' instead of 0xFEFEFEFE → UAF WRITE */
    return 0;
}
