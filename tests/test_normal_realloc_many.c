/* Test: many reallocs on same pointer — canaries must survive each resize */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    char *p = malloc(1);
    p[0] = 'x';

    /* Grow from 1 to 10000 in steps */
    for (int sz = 2; sz <= 10000; sz += sz / 2 + 1) {
        int old_sz = (sz - 1 > 0) ? sz - 1 : 1;
        p = realloc(p, sz);
        if (!p) { fprintf(stderr, "FAIL: realloc returned NULL at sz=%d\n", sz); return 1; }
        /* Write to last byte — must NOT corrupt tail canary */
        p[sz - 1] = 'y';
    }

    /* Shrink back down */
    for (int sz = 5000; sz >= 1; sz /= 2) {
        p = realloc(p, sz);
        if (!p) { fprintf(stderr, "FAIL: realloc shrink returned NULL at sz=%d\n", sz); return 1; }
    }

    free(p);
    fprintf(stderr, "PASS: many reallocs (grow + shrink) — canaries intact\n");
    return 0;
}
