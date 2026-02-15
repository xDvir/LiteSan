/* Test: huge allocations work normally with guard page path — no false positives */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    /* 64KB allocation — should use guard page path */
    char *p = malloc(65536);
    if (!p) { printf("malloc failed\n"); return 1; }
    memset(p, 'A', 65536);  /* fill entirely */
    p[0] = 'X';
    p[65535] = 'Y';
    free(p);
    /* Another large alloc */
    char *q = malloc(100000);
    if (!q) { printf("malloc failed\n"); return 1; }
    q[0] = 'Z';
    q[99999] = 'W';
    free(q);
    printf("guard page basic test passed\n");
    return 0;
}
