/* Test: UAF read sees poison (passive — should NOT crash) */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
int main(void) {
    char *p = malloc(64);
    free(p);
    /* Read freed memory — should see 0xFE poison pattern */
    uint64_t val = *(uint64_t *)p;
    if (val == 0xFEFEFEFEFEFEFEFEULL) {
        fprintf(stderr, "PASS: read poison 0xFEFEFEFEFEFEFEFE as expected\n");
    }
    return 0;
}
