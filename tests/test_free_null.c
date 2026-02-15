/* Test: free(NULL) is a no-op */
#include <stdlib.h>
int main(void) {
    free(NULL);
    free(NULL);
    free(NULL);
    return 0;
}
