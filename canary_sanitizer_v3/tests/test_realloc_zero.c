/* Test: realloc(ptr, 0) behaves as free */
#include <stdlib.h>
int main(void) {
    void *p = malloc(64);
    realloc(p, 0);  /* should free p */
    return 0;
}
