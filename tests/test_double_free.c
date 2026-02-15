/* Test: classic double-free */
#include <stdlib.h>
int main(void) {
    char *p = malloc(64);
    free(p);
    free(p);  /* second free — head canary is FREED_CANARY → caught */
    return 0;
}
