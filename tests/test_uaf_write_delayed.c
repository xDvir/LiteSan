/* Test: UAF write after many other operations (block still in quarantine) */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *victim = malloc(256);
    memset(victim, 'V', 256);
    free(victim);

    /* Do 500 other alloc/frees (victim stays in quarantine — 2048 slots) */
    for (int i = 0; i < 500; i++) {
        char *p = malloc(64);
        free(p);
    }

    /* UAF write to victim — it's still in quarantine, poisoned with 0xFE */
    victim[0] = 'X';
    victim[1] = 'Y';

    /* Now force eviction of victim's quarantine slot */
    for (int i = 0; i < 2000; i++) {
        char *p = malloc(32);
        free(p);
    }
    /* Eviction of victim checks first 8 bytes → sees 'XY' + 0xFE... → UAF WRITE */
    return 0;
}
