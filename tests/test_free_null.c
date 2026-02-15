/* Test: free(NULL) is safe (no crash) */
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    free(NULL);
    free(NULL);
    free(NULL);
    fprintf(stderr, "PASS: free(NULL) x3 — no crash\n");
    return 0;
}
