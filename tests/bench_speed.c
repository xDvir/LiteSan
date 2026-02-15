/* Benchmark: heavy allocation/free workload — measures sanitizer overhead */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define ITERS      500000
#define LIVE_MAX   4096

int main(void) {
    void *live[LIVE_MAX];
    int live_count = 0;
    unsigned seed = 12345;

    for (int i = 0; i < ITERS; i++) {
        /* Simple LCG random */
        seed = seed * 1103515245 + 12345;
        int action = seed % 100;

        if (live_count == 0 || (action < 60 && live_count < LIVE_MAX)) {
            /* malloc — varied sizes: tiny(1-32), small(33-256), medium(257-4096), large(4097-65536) */
            seed = seed * 1103515245 + 12345;
            int bucket = seed % 100;
            size_t sz;
            if (bucket < 40)      sz = (seed >> 8) % 32 + 1;        /* tiny */
            else if (bucket < 70) sz = (seed >> 8) % 224 + 33;      /* small */
            else if (bucket < 90) sz = (seed >> 8) % 3840 + 257;    /* medium */
            else                  sz = (seed >> 8) % 61440 + 4097;  /* large */

            void *p = malloc(sz);
            if (p) {
                memset(p, 0x42, sz);  /* write within bounds */
                live[live_count++] = p;
            }
        } else if (action < 80 && live_count > 0) {
            /* free a random live allocation */
            seed = seed * 1103515245 + 12345;
            int idx = seed % live_count;
            free(live[idx]);
            live[idx] = live[--live_count];
        } else if (action < 90 && live_count > 0) {
            /* realloc a random live allocation */
            seed = seed * 1103515245 + 12345;
            size_t new_sz = (seed >> 8) % 4096 + 1;
            seed = seed * 1103515245 + 12345;
            int idx = seed % live_count;
            void *p = realloc(live[idx], new_sz);
            if (p) {
                memset(p, 0x43, new_sz);
                live[idx] = p;
            }
        } else if (live_count > 0) {
            /* calloc replacement */
            seed = seed * 1103515245 + 12345;
            size_t sz = (seed >> 8) % 512 + 1;
            void *p = calloc(1, sz);
            if (p) {
                memset(p, 0x44, sz);
                if (live_count < LIVE_MAX)
                    live[live_count++] = p;
                else
                    free(p);
            }
        }
    }

    /* Free remaining */
    for (int i = 0; i < live_count; i++)
        free(live[i]);

    return 0;
}
