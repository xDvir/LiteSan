/* Test: UAF read sees 0xFE poison (passive detection — should NOT abort) */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
int main(void) {
    uint64_t *p = (uint64_t *)malloc(64);
    p[0] = 0x1234567890ABCDEFULL;
    free(p);

    /* Read freed memory — should see poison 0xFEFEFEFEFEFEFEFE */
    uint64_t val = p[0];
    if (val == 0xFEFEFEFEFEFEFEFEULL) {
        fprintf(stderr, "PASS: UAF read sees poison 0x%llx\n",
                (unsigned long long)val);
        return 0;  /* expected exit 0 */
    } else {
        fprintf(stderr, "FAIL: UAF read got 0x%llx (expected 0xFEFEFEFEFEFEFEFE)\n",
                (unsigned long long)val);
        return 1;
    }
}
