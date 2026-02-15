/* Test: large buffer overflow */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(16);
    memset(p, 'B', 128);  /* massive overflow */
    free(p);
    return 0;
}
