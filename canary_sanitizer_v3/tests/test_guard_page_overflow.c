/* Test: overflow on huge allocation — caught by tail canary or guard page
 * Writing past the end corrupts the tail canary. On free(), check_canaries()
 * detects the corrupted tail canary and aborts (exit 134). */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(65536);
    if (!p) return 1;
    /* Write past the end — should hit tail canary */
    memset(p, 'A', 65536);
    /* Overflow past allocation — corrupt tail canary */
    p[65536] = 'X';
    free(p);  /* should detect overflow */
    return 0;
}
