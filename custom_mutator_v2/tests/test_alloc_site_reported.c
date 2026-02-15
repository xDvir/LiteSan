/* v2 TEST: allocation site is reported on error.
 * This test verifies the stderr output contains "Allocated at:" */
#include <stdlib.h>
int main(void) {
    char *p = malloc(32);
    p[32] = 'X';  /* overflow */
    free(p);       /* should report "Allocated at: 0x..." */
    return 0;
}
