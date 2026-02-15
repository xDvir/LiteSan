/* Test: overflow via strcpy */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(8);
    strcpy(p, "this string is way too long for 8 bytes");
    free(p);
    return 0;
}
