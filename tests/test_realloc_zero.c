/* Test: realloc(ptr, 0) acts as free (no crash) */
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    char *p = malloc(64);
    p = realloc(p, 0);  /* should free p, return NULL */
    /* p is now freed — don't touch it */
    fprintf(stderr, "PASS: realloc(ptr, 0) — no crash\n");
    return 0;
}
