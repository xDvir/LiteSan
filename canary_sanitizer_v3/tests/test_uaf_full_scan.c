/* Test: sampled full-buffer poison check catches UAF that spot-check misses.
 *
 * The thread-local quarantine has 256 slots. The full-buffer scan runs every
 * 64 evictions (when ++tl_evict_count % 64 == 0). We need the target block's
 * eviction from quarantine to coincide with a full-scan trigger.
 *
 * Careful cycle counting:
 *   1. Fill quarantine: 256 dummy frees (no evictions, tl_evict_count=0)
 *   2. Pre-pad: 63 dummy frees → evictions #1-63
 *   3. Free target → eviction #64 (64%64=0 → full scan on OLD block, not target)
 *      Target lands in slot 63. tl_q.idx = 320.
 *   4. UAF write to target byte 20
 *   5. 256 more dummy frees → evictions #65-320
 *      At free #256: slot wraps to 63, evicting TARGET. Eviction #320.
 *      320%64=0 → FULL SCAN on target → finds byte 20 corrupted → abort.
 */
#include <stdlib.h>
#include <string.h>

int main(void) {
    /* Step 1: Fill all 256 quarantine slots */
    for (int i = 0; i < 256; i++) {
        char *p = malloc(64);
        if (p) free(p);
    }

    /* Step 2: Pre-pad eviction counter to 63 */
    for (int i = 0; i < 63; i++) {
        char *p = malloc(64);
        if (p) free(p);
    }

    /* Step 3: Free target — goes into slot 63, eviction #64 triggers full scan
     * on the OLD occupant of slot 63 (clean), not target */
    char *target = malloc(256);
    if (!target) return 1;
    char *saved = target;
    free(target);

    /* Step 4: UAF write to byte 20 — misses the 3-spot check:
     *   first=0, middle=(256/2)&~7=128, last=(256-8)&~7=248 */
    saved[20] = 'X';

    /* Step 5: Cycle 256 frees to wrap back to target's slot (63).
     * The 256th free evicts target at eviction #320 (320%64=0 → full scan).
     * Full scan finds byte 20 is 'X' instead of 0xFE → abort. */
    for (int i = 0; i < 256; i++) {
        char *p = malloc(64);
        if (p) free(p);
    }

    /* Should not reach here */
    return 0;
}
