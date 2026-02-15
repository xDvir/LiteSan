/*
 * canary_sanitizer.so v2 — Lightweight heap sanitizer for persistent mode fuzzing
 *
 * LD_PRELOAD shim: overrides malloc/free/calloc/realloc/memalign/posix_memalign/
 * aligned_alloc with canary-guarded versions. Uses normal libc malloc internally —
 * no mmap per alloc, no syscall explosion, no VMA accumulation.
 *
 * v2 improvements over v1:
 *   - Resolve libc functions once in constructor (not every call)
 *   - Calloc skips junk fill (avoids double-write)
 *   - Thread-local op counter (no atomic on hot path)
 *   - __builtin_expect on cold error paths
 *   - Multi-spot UAF check (first/middle/last 8 bytes)
 *   - Intercept memalign/posix_memalign/aligned_alloc/valloc
 *   - calloc integer overflow protection
 *
 * Detects:
 *   - Heap buffer overflow  (tail canary corrupted, checked on free/realloc)
 *   - Overflow without free (exit/signal/periodic registry scan)
 *   - Double-free           (head canary is poison from first free)
 *   - UAF writes            (quarantine keeps freed blocks, multi-spot re-check on eviction)
 *   - UAF reads (partial)   (freed memory poisoned with 0xFE)
 *   - Uninitialized reads   (new allocs filled with 0xAA junk)
 *
 * On detection: prints bug type + backtrace, then aborts.
 *
 * Build:
 *   gcc -shared -fPIC -O2 -o canary_sanitizer.so canary_sanitizer.c -ldl -rdynamic
 *
 * Usage:
 *   AFL_PRELOAD=./canary_sanitizer.so afl-fuzz ...
 *   LD_PRELOAD=./canary_sanitizer.so ./harness_foxit test.pdf
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <errno.h>

/* ========================================================================= */
/* Canary values                                                             */
/* ========================================================================= */

#define HEAD_CANARY  0xDEADBEEFCAFEBABEULL
#define TAIL_CANARY  0xFEEDFACE8BADF00DULL
#define FREED_CANARY 0xFEFEFEFEFEFEFEFEULL
#define POISON_BYTE  0xFE
#define JUNK_BYTE    0xAA   /* fill new allocs — catches uninitialized reads */

/* Header prepended to every allocation:
 *   [size (8B)][canary (8B)][user data ...][tail_canary (8B)]
 */
typedef struct {
    size_t   size;
    uint64_t canary;
} alloc_header_t;

#define HDR_SIZE  sizeof(alloc_header_t)   /* 16 */
#define TAIL_SIZE sizeof(uint64_t)         /* 8 */

/* ========================================================================= */
/* Quarantine — delayed free for UAF detection                               */
/*                                                                           */
/* Instead of calling real_free() immediately, freed blocks go into a ring   */
/* buffer. The memory stays poisoned (0xFE) until evicted. This means:       */
/*   - UAF reads see 0xFE poison reliably (not recycled by libc)             */
/*   - UAF writes corrupt the poison → detected on eviction                  */
/*                                                                           */
/* Lock-free: atomic index gives each thread a unique slot. Atomic exchange  */
/* on the slot swaps the old/new block without races.                        */
/* ========================================================================= */

#define QUARANTINE_SIZE 2048

static void *quarantine[QUARANTINE_SIZE];
static volatile size_t q_idx = 0;

/* ========================================================================= */
/* Allocation Registry — tracks live allocations for exit/signal/periodic    */
/* scanning. Detects overflows on blocks that are never freed (leaked).      */
/*                                                                           */
/* Fixed-size hash table (open addressing, linear probing). No dynamic       */
/* allocation. Hash = pointer >> 4, O(1) amortized add/remove.              */
/* Lock-free via atomic CAS, same philosophy as quarantine.                  */
/* ========================================================================= */

#define REGISTRY_SIZE  65536          /* must be power of 2 */
#define REGISTRY_MASK  (REGISTRY_SIZE - 1)
#define SCAN_INTERVAL  1024

static void * volatile registry[REGISTRY_SIZE];
static volatile int already_scanned = 0;

/* v2: thread-local counter — no atomic on hot path */
static __thread size_t tl_op_count = 0;

static inline size_t registry_hash(void *ptr) {
    return ((uintptr_t)ptr >> 4) & REGISTRY_MASK;
}

/* ========================================================================= */
/* Real libc functions (resolved via dlsym)                                  */
/* ========================================================================= */

static void *(*real_malloc)(size_t)            = NULL;
static void  (*real_free)(void *)              = NULL;
static void *(*real_realloc)(void *, size_t)   = NULL;
static void *(*real_calloc)(size_t, size_t)    = NULL;

/* Bootstrap buffer: dlsym() internally calls calloc(), so we need a static
 * buffer to service those allocations before real_calloc is resolved. */
static char   bootstrap_buf[16384];
static size_t bootstrap_used = 0;
static int    resolving = 0;

static void resolve_real(void) {
    if (real_malloc) return;
    resolving = 1;
    real_malloc  = dlsym(RTLD_NEXT, "malloc");
    real_free    = dlsym(RTLD_NEXT, "free");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_calloc  = dlsym(RTLD_NEXT, "calloc");
    resolving = 0;
}

static inline int is_bootstrap(void *ptr) {
    return (char *)ptr >= bootstrap_buf &&
           (char *)ptr <  bootstrap_buf + sizeof(bootstrap_buf);
}

/* ========================================================================= */
/* Canary helpers                                                            */
/* ========================================================================= */

static inline void write_tail(void *user, size_t size) {
    *(uint64_t *)((char *)user + size) = TAIL_CANARY;
}

static void print_backtrace(void) {
    void *frames[32];
    int n = backtrace(frames, 32);
    if (__builtin_expect(n > 0, 1)) {
        fprintf(stderr, "Backtrace:\n");
        backtrace_symbols_fd(frames, n, STDERR_FILENO);
    }
}

/* Check canaries on a LIVE allocation (in malloc/free/realloc) */
static void check_canaries(alloc_header_t *hdr, void *user, const char *fn) {
    if (__builtin_expect(hdr->canary == FREED_CANARY, 0)) {
        fprintf(stderr,
            "\n*** CANARY_SANITIZER: DOUBLE-FREE in %s() ptr=%p ***\n", fn, user);
        print_backtrace();
        abort();
    }
    if (__builtin_expect(hdr->canary != HEAD_CANARY, 0)) {
        fprintf(stderr,
            "\n*** CANARY_SANITIZER: HEAD CANARY corrupt in %s() ptr=%p "
            "expected=0x%llx got=0x%llx ***\n",
            fn, user, (unsigned long long)HEAD_CANARY,
            (unsigned long long)hdr->canary);
        print_backtrace();
        abort();
    }
    uint64_t tail = *(uint64_t *)((char *)user + hdr->size);
    if (__builtin_expect(tail != TAIL_CANARY, 0)) {
        fprintf(stderr,
            "\n*** CANARY_SANITIZER: HEAP BUFFER OVERFLOW in %s() ptr=%p "
            "size=%zu expected=0x%llx got=0x%llx ***\n",
            fn, user, hdr->size, (unsigned long long)TAIL_CANARY,
            (unsigned long long)tail);
        print_backtrace();
        abort();
    }
}

/* v2: Check a QUARANTINED block on eviction — multi-spot UAF write detection.
 * Checks first, middle, and last 8 bytes instead of just the first 8. */
static void check_quarantined(alloc_header_t *hdr) {
    void *user = (char *)hdr + HDR_SIZE;

    /* Head canary should still be FREED_CANARY from when we freed it.
     * If it's different, someone wrote to the block after free (UAF write). */
    if (__builtin_expect(hdr->canary != FREED_CANARY, 0)) {
        fprintf(stderr,
            "\n*** CANARY_SANITIZER: USE-AFTER-FREE WRITE detected ***\n"
            "    ptr=%p size=%zu (header corrupted after free, "
            "expected=0x%llx got=0x%llx)\n",
            user, hdr->size,
            (unsigned long long)FREED_CANARY, (unsigned long long)hdr->canary);
        print_backtrace();
        abort();
    }

    /* Spot-check first 8 bytes of user data */
    if (hdr->size >= 8) {
        uint64_t first8 = *(uint64_t *)user;
        if (__builtin_expect(first8 != 0xFEFEFEFEFEFEFEFEULL, 0)) {
            fprintf(stderr,
                "\n*** CANARY_SANITIZER: USE-AFTER-FREE WRITE detected ***\n"
                "    ptr=%p size=%zu (freed data corrupted at offset 0, "
                "expected=0xFEFEFEFEFEFEFEFE got=0x%llx)\n",
                user, hdr->size, (unsigned long long)first8);
            print_backtrace();
            abort();
        }
    }

    /* v2: Spot-check middle 8 bytes */
    if (hdr->size >= 24) {
        size_t mid_off = (hdr->size / 2) & ~(size_t)7;
        uint64_t mid8 = *(uint64_t *)((char *)user + mid_off);
        if (__builtin_expect(mid8 != 0xFEFEFEFEFEFEFEFEULL, 0)) {
            fprintf(stderr,
                "\n*** CANARY_SANITIZER: USE-AFTER-FREE WRITE detected ***\n"
                "    ptr=%p size=%zu (freed data corrupted at offset %zu, "
                "expected=0xFEFEFEFEFEFEFEFE got=0x%llx)\n",
                user, hdr->size, mid_off, (unsigned long long)mid8);
            print_backtrace();
            abort();
        }
    }

    /* v2: Spot-check last 8 bytes */
    if (hdr->size >= 16) {
        size_t end_off = (hdr->size - 8) & ~(size_t)7;
        uint64_t end8 = *(uint64_t *)((char *)user + end_off);
        if (__builtin_expect(end8 != 0xFEFEFEFEFEFEFEFEULL, 0)) {
            fprintf(stderr,
                "\n*** CANARY_SANITIZER: USE-AFTER-FREE WRITE detected ***\n"
                "    ptr=%p size=%zu (freed data corrupted at offset %zu, "
                "expected=0xFEFEFEFEFEFEFEFE got=0x%llx)\n",
                user, hdr->size, end_off, (unsigned long long)end8);
            print_backtrace();
            abort();
        }
    }
}

/* ========================================================================= */
/* Allocation Registry — add / remove / scan                                 */
/* ========================================================================= */

static void registry_add(alloc_header_t *hdr) {
    size_t idx = registry_hash(hdr);
    for (size_t i = 0; i < REGISTRY_SIZE; i++) {
        size_t slot = (idx + i) & REGISTRY_MASK;
        void *expected = NULL;
        if (__atomic_compare_exchange_n(&registry[slot], &expected, (void *)hdr,
                                        0, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            return;
    }
    /* Registry full — silently drop. Overflow will still be caught on free(). */
}

static void registry_remove(alloc_header_t *hdr) {
    size_t idx = registry_hash(hdr);
    for (size_t i = 0; i < REGISTRY_SIZE; i++) {
        size_t slot = (idx + i) & REGISTRY_MASK;
        void *expected = (void *)hdr;
        if (__atomic_compare_exchange_n(&registry[slot], &expected, NULL,
                                        0, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            return;
    }
}

/* Signal-safe write helper: write a string to stderr using write(2) */
static void safe_write(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    (void)!write(STDERR_FILENO, s, len);
}

/* Hex formatter for signal-safe output */
static void safe_write_hex(uint64_t val) {
    char buf[19]; /* "0x" + 16 hex digits + NUL */
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 15; i >= 0; i--) {
        int nibble = (val >> (i * 4)) & 0xF;
        buf[17 - i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
    }
    buf[18] = '\0';
    safe_write(buf);
}

static void scan_registry(int is_signal) {
    int found_corruption = 0;

    for (size_t i = 0; i < REGISTRY_SIZE; i++) {
        void *slot = __atomic_load_n(&registry[i], __ATOMIC_RELAXED);
        if (!slot) continue;

        alloc_header_t *hdr = (alloc_header_t *)slot;
        void *user = (char *)hdr + HDR_SIZE;

        /* Check head canary */
        if (__builtin_expect(hdr->canary != HEAD_CANARY, 0)) {
            if (is_signal) {
                safe_write("\n*** CANARY_SANITIZER: HEAD CANARY corrupt "
                           "(registry scan) ptr=");
                safe_write_hex((uint64_t)(uintptr_t)user);
                safe_write(" ***\n");
            } else {
                fprintf(stderr,
                    "\n*** CANARY_SANITIZER: HEAD CANARY corrupt "
                    "(registry scan) ptr=%p expected=0x%llx got=0x%llx ***\n",
                    user, (unsigned long long)HEAD_CANARY,
                    (unsigned long long)hdr->canary);

                print_backtrace();
            }
            found_corruption = 1;
            continue;
        }

        /* Check tail canary */
        uint64_t tail = *(uint64_t *)((char *)user + hdr->size);
        if (__builtin_expect(tail != TAIL_CANARY, 0)) {
            if (is_signal) {
                safe_write("\n*** CANARY_SANITIZER: HEAP BUFFER OVERFLOW "
                           "(registry scan) ptr=");
                safe_write_hex((uint64_t)(uintptr_t)user);
                safe_write(" size=");
                /* Write size as decimal — simple signal-safe conversion */
                char numbuf[21];
                int pos = 20;
                size_t sz = hdr->size;
                numbuf[pos] = '\0';
                if (sz == 0) { numbuf[--pos] = '0'; }
                else { while (sz) { numbuf[--pos] = '0' + (sz % 10); sz /= 10; } }
                safe_write(&numbuf[pos]);
                safe_write(" ***\n");
            } else {
                fprintf(stderr,
                    "\n*** CANARY_SANITIZER: HEAP BUFFER OVERFLOW "
                    "(registry scan) ptr=%p size=%zu "
                    "expected=0x%llx got=0x%llx ***\n",
                    user, hdr->size, (unsigned long long)TAIL_CANARY,
                    (unsigned long long)tail);

                print_backtrace();
            }
            found_corruption = 1;
        }
    }

    if (found_corruption && !is_signal)
        abort();
}

/* v2: thread-local counter, no atomic on hot path */
static inline void maybe_periodic_scan(void) {
    if (__builtin_expect(++tl_op_count % SCAN_INTERVAL == 0, 0))
        scan_registry(0);
}

/* ========================================================================= */
/* Exit + Signal handlers — scan registry at exit and on crash signals       */
/* ========================================================================= */

static struct sigaction old_sigsegv;
static struct sigaction old_sigbus;
static struct sigaction old_sigabrt;

static void atexit_scan(void) {
    if (__sync_lock_test_and_set(&already_scanned, 1))
        return;
    scan_registry(0);
}

static void crash_signal_handler(int sig, siginfo_t *info, void *ucontext) {
    /* Guard against re-entrancy (abort from scan_registry → signal → here) */
    if (__sync_lock_test_and_set(&already_scanned, 1) == 0)
        scan_registry(1);

    /* Chain to previous handler */
    struct sigaction *old = NULL;
    if (sig == SIGSEGV) old = &old_sigsegv;
    else if (sig == SIGBUS) old = &old_sigbus;
    else if (sig == SIGABRT) old = &old_sigabrt;

    if (old && (old->sa_flags & SA_SIGINFO) && old->sa_sigaction) {
        old->sa_sigaction(sig, info, ucontext);
    } else if (old && old->sa_handler && old->sa_handler != SIG_DFL
               && old->sa_handler != SIG_IGN) {
        old->sa_handler(sig);
    } else {
        /* Restore default and re-raise */
        struct sigaction dfl;
        memset(&dfl, 0, sizeof(dfl));
        dfl.sa_handler = SIG_DFL;
        sigaction(sig, &dfl, NULL);
        raise(sig);
    }
}

/* v2: resolve libc functions ONCE in constructor */
__attribute__((constructor))
static void canary_sanitizer_init(void) {
    resolve_real();
    atexit(atexit_scan);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_signal_handler;
    sa.sa_flags = SA_SIGINFO;

    sigaction(SIGSEGV, &sa, &old_sigsegv);
    sigaction(SIGBUS,  &sa, &old_sigbus);
    sigaction(SIGABRT, &sa, &old_sigabrt);
}

/* ========================================================================= */
/* Internal allocation (v2: shared by malloc and calloc)                     */
/* ========================================================================= */

static inline void *malloc_internal(size_t size, int junk_fill) {
    void *raw = real_malloc(HDR_SIZE + size + TAIL_SIZE);
    if (__builtin_expect(!raw, 0)) return NULL;

    alloc_header_t *hdr = (alloc_header_t *)raw;
    hdr->size   = size;
    hdr->canary = HEAD_CANARY;

    void *user = (char *)raw + HDR_SIZE;
    if (junk_fill)
        memset(user, JUNK_BYTE, size);
    write_tail(user, size);
    registry_add(hdr);
    maybe_periodic_scan();
    return user;
}

/* ========================================================================= */
/* Public API overrides                                                      */
/* ========================================================================= */

void *malloc(size_t size) {
    /* v2: resolve_real() already called in constructor. Fallback for edge case
     * where malloc is called before constructor (should not happen on glibc). */
    if (__builtin_expect(!real_malloc, 0)) resolve_real();
    if (__builtin_expect(!real_malloc, 0)) return NULL;

    return malloc_internal(size, 1);
}

void free(void *ptr) {
    if (!ptr) return;
    if (__builtin_expect(is_bootstrap(ptr), 0)) return;
    if (__builtin_expect(!real_free, 0)) resolve_real();

    alloc_header_t *hdr = (alloc_header_t *)((char *)ptr - HDR_SIZE);
    check_canaries(hdr, ptr, "free");
    registry_remove(hdr);

    /* Poison user data + tail for UAF detection */
    memset(ptr, POISON_BYTE, hdr->size + TAIL_SIZE);

    /* Mark freed (double-free detection + quarantine eviction check) */
    hdr->canary = FREED_CANARY;

    /* Quarantine: push to ring, evict oldest.
     * Lock-free: atomic increment gives unique slot per thread.
     * Atomic exchange on slot prevents read-write races. */
    size_t idx = __sync_fetch_and_add(&q_idx, 1) % QUARANTINE_SIZE;
    void *oldest = __atomic_exchange_n(&quarantine[idx], (void *)hdr,
                                       __ATOMIC_RELAXED);

    if (oldest) {
        /* Re-check the evicted block — catches UAF writes that happened
         * while the block sat in quarantine with poisoned memory. */
        check_quarantined((alloc_header_t *)oldest);
        real_free(oldest);
    }
    maybe_periodic_scan();
}

void *calloc(size_t nmemb, size_t size) {
    /* Bootstrap buffer is ONLY for dlsym's internal calloc calls. */
    if (__builtin_expect(resolving, 0)) {
        size_t total = nmemb * size;
        if (bootstrap_used + total > sizeof(bootstrap_buf)) return NULL;
        void *p = bootstrap_buf + bootstrap_used;
        bootstrap_used += total;
        memset(p, 0, total);
        return p;
    }
    if (__builtin_expect(!real_malloc, 0)) resolve_real();
    if (__builtin_expect(!real_malloc, 0)) return NULL;

    /* v2: integer overflow check */
    size_t total = nmemb * size;
    if (__builtin_expect(nmemb != 0 && total / nmemb != size, 0))
        return NULL;

    /* v2: skip junk fill — calloc will zero it anyway */
    void *ptr = malloc_internal(total, 0);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

void *realloc(void *ptr, size_t size) {
    if (!ptr) return malloc(size);
    if (size == 0) { free(ptr); return NULL; }
    if (__builtin_expect(is_bootstrap(ptr), 0)) {
        void *new_ptr = malloc(size);
        if (new_ptr) {
            size_t avail = (bootstrap_buf + sizeof(bootstrap_buf)) - (char *)ptr;
            memcpy(new_ptr, ptr, size < avail ? size : avail);
        }
        return new_ptr;
    }
    if (__builtin_expect(!real_realloc, 0)) resolve_real();

    alloc_header_t *hdr = (alloc_header_t *)((char *)ptr - HDR_SIZE);
    /* Check canaries BEFORE realloc — detects overflow on the old buffer */
    check_canaries(hdr, ptr, "realloc");

    size_t old_size = hdr->size;
    registry_remove(hdr);

    /* Let libc handle the resize — may grow in-place without copying */
    void *new_raw = real_realloc(hdr, HDR_SIZE + size + TAIL_SIZE);
    if (__builtin_expect(!new_raw, 0)) {
        registry_add(hdr);  /* realloc failed — old block is still live */
        return NULL;
    }

    alloc_header_t *new_hdr = (alloc_header_t *)new_raw;
    new_hdr->size = size;

    void *new_user = (char *)new_raw + HDR_SIZE;

    /* If grown, junk-fill the new portion */
    if (size > old_size) {
        memset((char *)new_user + old_size, JUNK_BYTE, size - old_size);
    }

    write_tail(new_user, size);
    registry_add(new_hdr);
    maybe_periodic_scan();
    return new_user;
}

/* ========================================================================= */
/* v2: Aligned allocation interception                                       */
/*                                                                           */
/* Programs using memalign/posix_memalign/aligned_alloc/valloc bypass the    */
/* sanitizer entirely if not intercepted. We redirect to our malloc — this   */
/* sacrifices alignment guarantees (acceptable during fuzzing) but ensures   */
/* every heap allocation gets canary protection.                             */
/* ========================================================================= */

void *memalign(size_t alignment, size_t size) {
    (void)alignment; /* alignment not honored — canary layout takes priority */
    return malloc(size);
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
    (void)alignment;
    if (!memptr) return EINVAL;
    void *p = malloc(size);
    if (!p) return ENOMEM;
    *memptr = p;
    return 0;
}

void *aligned_alloc(size_t alignment, size_t size) {
    (void)alignment;
    return malloc(size);
}

void *valloc(size_t size) {
    return malloc(size);
}

void *pvalloc(size_t size) {
    return malloc(size);
}
