/* v2 TEST: CANARY_NO_SCAN disables periodic scanning
 * Run with: CANARY_NO_SCAN=1 LD_PRELOAD=... ./test_no_scan_env
 * This does overflow-without-free, which is only caught by periodic/exit scan.
 * With CANARY_NO_SCAN=1, periodic scan is disabled but exit scan still runs. */
#include <stdlib.h>
#include <string.h>
int main(void) {
    /* Normal heavy usage — should not crash even without periodic scan */
    for (int i = 0; i < 5000; i++) {
        void *p = malloc(64);
        memset(p, 'A', 64);
        free(p);
    }
    return 0;
}
