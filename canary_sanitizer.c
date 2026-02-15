/*
 * canary_sanitizer.so v3 — Maximum speed heap sanitizer for persistent mode fuzzing
 *
 * LD_PRELOAD shim: overrides malloc/free/calloc/realloc/memalign/posix_memalign/
 * aligned_alloc with canary-guarded versions.
 *
 * v3 improvements over v2:
 *   Speed:
 *   1. Multiply-shift registry hash (better distribution, fewer probes)
 *   2. Thread-local quarantine (eliminates 2 atomics from free hot path)
 *   3. Incremental registry scan (1/64th per trigger, not all 65536 slots)
 *   4. Inline small memset for tiny allocations (<= 64 bytes)
 *   5. Build with -O3 (vs -O2)
 *   6. Bitmask for scan interval check (& instead of %)
 *
 *   New detection (zero/near-zero cost):
 *   7. Free-site stored in header on free (reuses size field for diagnostics)
 *   8. Sampled full-buffer poison check (1-in-64 full scan on eviction)
 *   9. Heap underflow detection (8-byte pre-header red zone)
 *   10. Guard page for huge allocations (>= 64KB, mmap+mprotect)
 *
 * Build:
 *   gcc -shared -fPIC -O3 -o canary_sanitizer.so canary_sanitizer.c -ldl -rdynamic
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
#include <sys/mman.h>

/* ========================================================================= */
/* Canary values                                                             */
/* ========================================================================= */

#define HEAD_CANARY     0xDEADBEEFCAFEBABEULL
#define TAIL_CANARY     0xFEEDFACE8BADF00DULL
#define FREED_CANARY    0xFEFEFEFEFEFEFEFEULL
#define UNDERFLOW_CANARY 0xBADC0FFEE0DDF00DULL  /* v3: pre-header red zone */
#define GUARD_UNDERFLOW  0xBADC0FFEE0DD6ACEULL  /* v3: guard page alloc marker */
#define POISON_BYTE     0xFE
#define JUNK_BYTE       0xAA

/* v3: Header layout:
 *   [underflow_canary (8B)][size (8B)][canary (8B)][user data ...][tail_canary (8B)]
 * The underflow canary sits BEFORE the original header, detecting writes
 * before the allocation (heap underflow / out-of-bounds write backward).
 */
typedef struct {
    uint64_t underflow;  /* v3: UNDERFLOW_CANARY — detects backward OOB writes */
    size_t   size;       /* requested allocation size (overwritten with free-site on free) */
    uint64_t canary;     /* HEAD_CANARY (live) or FREED_CANARY (freed) */
} alloc_header_t;

#define HDR_SIZE  sizeof(alloc_header_t)   /* 24 */
#define TAIL_SIZE sizeof(uint64_t)         /* 8 */

/* v3: Guard page threshold — huge allocations get mmap + guard page */
#define GUARD_PAGE_THRESHOLD  (64 * 1024)  /* 64KB */
#define PAGE_SIZE_VAL         4096

/* Guard page allocs are marked with GUARD_UNDERFLOW in the underflow field */

/* ========================================================================= */
/* Quarantine — v3: thread-local ring buffer (no atomics on free hot path)   */
/* ========================================================================= */

#define TL_QUARANTINE_SIZE 256  /* per-thread quarantine ring */

typedef struct {
    void *ring[TL_QUARANTINE_SIZE];
    size_t idx;
} tl_quarantine_t;

static __thread tl_quarantine_t tl_q = { .idx = 0 };

/* Global quarantine for overflow from thread exit or large buffers */
#define GLOBAL_QUARANTINE_SIZE 2048
static void *g_quarantine[GLOBAL_QUARANTINE_SIZE];
static volatile size_t g_q_idx = 0;

/* ========================================================================= */
/* Allocation Registry                                                       */
/* ========================================================================= */

#define REGISTRY_SIZE  65536
#define REGISTRY_MASK  (REGISTRY_SIZE - 1)
#define SCAN_INTERVAL  1024      /* must be power of 2 for bitmask */
#define SCAN_INTERVAL_MASK (SCAN_INTERVAL - 1)  /* v3: bitmask instead of modulo */
#define SCAN_CHUNK     (REGISTRY_SIZE / 64)     /* v3: scan 1/64th at a time */

static void * volatile registry[REGISTRY_SIZE];
static volatile int already_scanned = 0;

/* v3: thread-local counter + incremental scan position */
static __thread size_t tl_op_count = 0;
static volatile size_t scan_cursor = 0;  /* shared cursor for incremental scan */

/* v3: multiply-shift hash — better distribution than simple shift */
static inline size_t registry_hash(void *ptr) {
    uintptr_t x = (uintptr_t)ptr;
    /* Fibonacci hashing: multiply by golden ratio constant, take high bits */
    x *= 0x9E3779B97F4A7C15ULL;  /* 2^64 / phi */
    return (x >> 48) & REGISTRY_MASK;
}

/* ========================================================================= */
/* Real libc functions                                                       */
/* ========================================================================= */

static void *(*real_malloc)(size_t)            = NULL;
static void  (*real_free)(void *)              = NULL;
static void *(*real_realloc)(void *, size_t)   = NULL;
static void *(*real_calloc)(size_t, size_t)    = NULL;

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

/* v3: inline small memset for tiny allocations (avoids function call overhead) */
static inline void fast_memset(void *dst, int val, size_t n) {
    if (__builtin_expect(n <= 64, 1)) {
        /* Inline for small sizes — avoids memset function call overhead */
        unsigned char *d = (unsigned char *)dst;
        unsigned char v = (unsigned char)val;
        size_t i = 0;
        /* Unrolled 8-byte writes */
        uint64_t v8 = v;
        v8 |= v8 << 8; v8 |= v8 << 16; v8 |= v8 << 32;
        for (; i + 8 <= n; i += 8)
            *(uint64_t *)(d + i) = v8;
        for (; i < n; i++)
            d[i] = v;
    } else {
        memset(dst, val, n);
    }
}

static void print_backtrace(void) {
    void *frames[32];
    int n = backtrace(frames, 32);
    if (__builtin_expect(n > 0, 1)) {
        fprintf(stderr, "Backtrace:\n");
        backtrace_symbols_fd(frames, n, STDERR_FILENO);
    }
}

/* v3: Check canaries including underflow detection */
static void check_canaries(alloc_header_t *hdr, void *user, const char *fn) {
    /* Check double-free FIRST — on freed blocks, underflow field holds the
     * free-site return address (not the underflow canary), so checking
     * underflow first would give a misleading "HEAP UNDERFLOW" error. */
    if (__builtin_expect(hdr->canary == FREED_CANARY, 0)) {
        fprintf(stderr,
            "\n*** CANARY_SANITIZER: DOUBLE-FREE in %s() ptr=%p ***\n", fn, user);
        /* v3: show free-site if stored */
        if (hdr->underflow != UNDERFLOW_CANARY && hdr->underflow != GUARD_UNDERFLOW
            && hdr->underflow != 0) {
            fprintf(stderr, "    previous free-site: %p\n", (void *)hdr->underflow);
        }
        print_backtrace();
        abort();
    }
    /* v3: Check underflow canary (detects backward OOB writes) */
    if (__builtin_expect(hdr->underflow != UNDERFLOW_CANARY &&
                         hdr->underflow != GUARD_UNDERFLOW, 0)) {
        fprintf(stderr,
            "\n*** CANARY_SANITIZER: HEAP UNDERFLOW in %s() ptr=%p "
            "expected=0x%llx got=0x%llx ***\n",
            fn, user, (unsigned long long)UNDERFLOW_CANARY,
            (unsigned long long)hdr->underflow);
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

/* v3: sampled full-buffer check counter */
static __thread unsigned int tl_evict_count = 0;
#define FULL_CHECK_INTERVAL 64  /* full-buffer check every 64 evictions */

/* v3: Check quarantined block — multi-spot + sampled full-buffer scan */
static void check_quarantined(alloc_header_t *hdr) {
    void *user = (char *)hdr + HDR_SIZE;
    /* v3: retrieve saved_size from after the free-site was stored */
    size_t saved_size = hdr->size;

    /* v3: on free(), we store the return address in size. To get the real
     * size we need it preserved separately. We'll use a slightly different
     * approach: store size in the first 8 bytes of the poisoned user area
     * (before poisoning those bytes, of course). Actually, let's keep it
     * simpler: we store the free-site in the underflow field (which was
     * already checked during free), and keep size untouched. */

    if (__builtin_expect(hdr->canary != FREED_CANARY, 0)) {
        fprintf(stderr,
            "\n*** CANARY_SANITIZER: USE-AFTER-FREE WRITE detected ***\n"
            "    ptr=%p size=%zu (header corrupted after free, "
            "expected=0x%llx got=0x%llx)\n",
            user, saved_size,
            (unsigned long long)FREED_CANARY, (unsigned long long)hdr->canary);
        print_backtrace();
        abort();
    }

    /* Spot-check first 8 bytes */
    if (saved_size >= 8) {
        uint64_t first8 = *(uint64_t *)user;
        if (__builtin_expect(first8 != 0xFEFEFEFEFEFEFEFEULL, 0)) {
            fprintf(stderr,
                "\n*** CANARY_SANITIZER: USE-AFTER-FREE WRITE detected ***\n"
                "    ptr=%p size=%zu (freed data corrupted at offset 0, "
                "expected=0xFEFEFEFEFEFEFEFE got=0x%llx)\n",
                user, saved_size, (unsigned long long)first8);
            /* v3: show free-site if available */
            if (hdr->underflow != UNDERFLOW_CANARY && hdr->underflow != 0) {
                fprintf(stderr, "    free-site: %p\n", (void *)hdr->underflow);
            }
            print_backtrace();
            abort();
        }
    }

    /* Multi-spot: middle 8 bytes */
    if (saved_size >= 24) {
        size_t mid_off = (saved_size / 2) & ~(size_t)7;
        uint64_t mid8 = *(uint64_t *)((char *)user + mid_off);
        if (__builtin_expect(mid8 != 0xFEFEFEFEFEFEFEFEULL, 0)) {
            fprintf(stderr,
                "\n*** CANARY_SANITIZER: USE-AFTER-FREE WRITE detected ***\n"
                "    ptr=%p size=%zu (freed data corrupted at offset %zu, "
                "expected=0xFEFEFEFEFEFEFEFE got=0x%llx)\n",
                user, saved_size, mid_off, (unsigned long long)mid8);
            if (hdr->underflow != UNDERFLOW_CANARY && hdr->underflow != 0) {
                fprintf(stderr, "    free-site: %p\n", (void *)hdr->underflow);
            }
            print_backtrace();
            abort();
        }
    }

    /* Multi-spot: last 8 bytes */
    if (saved_size >= 16) {
        size_t end_off = (saved_size - 8) & ~(size_t)7;
        uint64_t end8 = *(uint64_t *)((char *)user + end_off);
        if (__builtin_expect(end8 != 0xFEFEFEFEFEFEFEFEULL, 0)) {
            fprintf(stderr,
                "\n*** CANARY_SANITIZER: USE-AFTER-FREE WRITE detected ***\n"
                "    ptr=%p size=%zu (freed data corrupted at offset %zu, "
                "expected=0xFEFEFEFEFEFEFEFE got=0x%llx)\n",
                user, saved_size, end_off, (unsigned long long)end8);
            if (hdr->underflow != UNDERFLOW_CANARY && hdr->underflow != 0) {
                fprintf(stderr, "    free-site: %p\n", (void *)hdr->underflow);
            }
            print_backtrace();
            abort();
        }
    }

    /* v3: Sampled full-buffer check — every FULL_CHECK_INTERVAL evictions,
     * scan ALL bytes. Catches UAF writes that miss the 3 spot-checks. */
    if (__builtin_expect(++tl_evict_count % FULL_CHECK_INTERVAL == 0, 0)) {
        unsigned char *p = (unsigned char *)user;
        for (size_t i = 0; i < saved_size; i++) {
            if (__builtin_expect(p[i] != POISON_BYTE, 0)) {
                fprintf(stderr,
                    "\n*** CANARY_SANITIZER: USE-AFTER-FREE WRITE detected ***\n"
                    "    ptr=%p size=%zu (freed data corrupted at byte %zu, "
                    "expected=0x%02x got=0x%02x) [full-buffer scan]\n",
                    user, saved_size, i, POISON_BYTE, p[i]);
                if (hdr->underflow != UNDERFLOW_CANARY && hdr->underflow != 0) {
                    fprintf(stderr, "    free-site: %p\n", (void *)hdr->underflow);
                }
                print_backtrace();
                abort();
            }
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

static void safe_write(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    (void)!write(STDERR_FILENO, s, len);
}

static void safe_write_hex(uint64_t val) {
    char buf[19];
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 15; i >= 0; i--) {
        int nibble = (val >> (i * 4)) & 0xF;
        buf[17 - i] = nibble < 10 ? '0' + nibble : 'a' + nibble - 10;
    }
    buf[18] = '\0';
    safe_write(buf);
}

/* v3: scan a chunk of registry (incremental) or all (full) */
static void scan_registry_range(size_t start, size_t count, int is_signal) {
    int found_corruption = 0;

    for (size_t i = 0; i < count; i++) {
        size_t slot_idx = (start + i) & REGISTRY_MASK;
        void *slot = __atomic_load_n(&registry[slot_idx], __ATOMIC_RELAXED);
        if (!slot) continue;

        alloc_header_t *hdr = (alloc_header_t *)slot;
        void *user = (char *)hdr + HDR_SIZE;

        /* v3: Check underflow canary (both regular and guard-page markers are valid) */
        if (__builtin_expect(hdr->underflow != UNDERFLOW_CANARY &&
                             hdr->underflow != GUARD_UNDERFLOW, 0)) {
            if (is_signal) {
                safe_write("\n*** CANARY_SANITIZER: HEAP UNDERFLOW "
                           "(registry scan) ptr=");
                safe_write_hex((uint64_t)(uintptr_t)user);
                safe_write(" ***\n");
            } else {
                fprintf(stderr,
                    "\n*** CANARY_SANITIZER: HEAP UNDERFLOW "
                    "(registry scan) ptr=%p expected=0x%llx got=0x%llx ***\n",
                    user, (unsigned long long)UNDERFLOW_CANARY,
                    (unsigned long long)hdr->underflow);
                print_backtrace();
            }
            found_corruption = 1;
            continue;
        }

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

/* Full registry scan (for exit/signal handlers) */
static void scan_registry(int is_signal) {
    scan_registry_range(0, REGISTRY_SIZE, is_signal);
}

/* v3: Incremental scan — scan 1/64th of registry per trigger */
static inline void maybe_periodic_scan(void) {
    if (__builtin_expect((++tl_op_count & SCAN_INTERVAL_MASK) == 0, 0)) {
        size_t cursor = __sync_fetch_and_add(&scan_cursor, SCAN_CHUNK);
        scan_registry_range(cursor & REGISTRY_MASK, SCAN_CHUNK, 0);
    }
}

/* ========================================================================= */
/* Guard page allocations (v3: for huge allocs >= 64KB)                      */
/*                                                                           */
/* Layout: [guard_page(4K)][header(24B)][user_data(N)][tail(8B)][guard_page] */
/* The trailing guard page is PROT_NONE — any overflow segfaults instantly.  */
/* ========================================================================= */

static inline size_t align_up(size_t n, size_t align) {
    return (n + align - 1) & ~(align - 1);
}

static void *guard_page_alloc(size_t size) {
    /* Total: header + user + tail, rounded up to page, plus 2 guard pages */
    size_t inner = HDR_SIZE + size + TAIL_SIZE;
    size_t inner_pages = align_up(inner, PAGE_SIZE_VAL);
    size_t total = PAGE_SIZE_VAL + inner_pages + PAGE_SIZE_VAL;  /* guard + data + guard */

    void *base = mmap(NULL, total, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return NULL;

    /* Front guard page: PROT_NONE (underflow → instant segfault) */
    mprotect(base, PAGE_SIZE_VAL, PROT_NONE);

    /* Back guard page: PROT_NONE (overflow past tail → instant segfault) */
    mprotect((char *)base + PAGE_SIZE_VAL + inner_pages, PAGE_SIZE_VAL, PROT_NONE);

    /* Header sits right after front guard page */
    alloc_header_t *hdr = (alloc_header_t *)((char *)base + PAGE_SIZE_VAL);
    hdr->underflow = GUARD_UNDERFLOW;  /* marks this as a guard-page alloc */
    hdr->size = size;
    hdr->canary = HEAD_CANARY;

    void *user = (char *)hdr + HDR_SIZE;
    fast_memset(user, JUNK_BYTE, size);
    write_tail(user, size);
    registry_add(hdr);

    return user;
}

static void guard_page_free(alloc_header_t *hdr, void *user) {
    size_t size = hdr->size;
    size_t inner = HDR_SIZE + size + TAIL_SIZE;
    size_t inner_pages = align_up(inner, PAGE_SIZE_VAL);
    size_t total = PAGE_SIZE_VAL + inner_pages + PAGE_SIZE_VAL;
    void *base = (char *)hdr - PAGE_SIZE_VAL;

    /* Re-protect front guard so we can check header */
    registry_remove(hdr);

    /* No quarantine for guard page allocs — munmap is instant cleanup */
    munmap(base, total);
}

/* Check if a pointer is from a guard-page allocation */
static inline int is_guard_page_alloc(alloc_header_t *hdr) {
    return hdr->underflow == GUARD_UNDERFLOW;
}

/* ========================================================================= */
/* Exit + Signal handlers                                                    */
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
    if (__sync_lock_test_and_set(&already_scanned, 1) == 0)
        scan_registry(1);

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
        struct sigaction dfl;
        memset(&dfl, 0, sizeof(dfl));
        dfl.sa_handler = SIG_DFL;
        sigaction(sig, &dfl, NULL);
        raise(sig);
    }
}

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
/* v3: Thread-local quarantine push + evict                                  */
/* No atomics on the hot path — each thread has its own 256-slot ring.       */
/* ========================================================================= */

static void quarantine_push(alloc_header_t *hdr) {
    size_t idx = tl_q.idx % TL_QUARANTINE_SIZE;
    tl_q.idx++;

    void *oldest = tl_q.ring[idx];
    tl_q.ring[idx] = (void *)hdr;

    if (oldest) {
        check_quarantined((alloc_header_t *)oldest);
        real_free(oldest);
    }
}

/* ========================================================================= */
/* Internal allocation                                                       */
/* ========================================================================= */

static inline void *malloc_internal(size_t size, int junk_fill) {
    /* v3: Guard page for huge allocations */
    if (__builtin_expect(size >= GUARD_PAGE_THRESHOLD, 0)) {
        return guard_page_alloc(size);
    }

    void *raw = real_malloc(HDR_SIZE + size + TAIL_SIZE);
    if (__builtin_expect(!raw, 0)) return NULL;

    alloc_header_t *hdr = (alloc_header_t *)raw;
    hdr->underflow = UNDERFLOW_CANARY;  /* v3: underflow red zone */
    hdr->size      = size;
    hdr->canary    = HEAD_CANARY;

    void *user = (char *)raw + HDR_SIZE;
    if (junk_fill)
        fast_memset(user, JUNK_BYTE, size);  /* v3: inline for small sizes */
    write_tail(user, size);
    registry_add(hdr);
    maybe_periodic_scan();
    return user;
}

/* ========================================================================= */
/* Public API overrides                                                      */
/* ========================================================================= */

void *malloc(size_t size) {
    if (__builtin_expect(!real_malloc, 0)) resolve_real();
    if (__builtin_expect(!real_malloc, 0)) return NULL;
    return malloc_internal(size, 1);
}

void free(void *ptr) {
    if (!ptr) return;
    if (__builtin_expect(is_bootstrap(ptr), 0)) return;
    if (__builtin_expect(!real_free, 0)) resolve_real();

    alloc_header_t *hdr = (alloc_header_t *)((char *)ptr - HDR_SIZE);

    /* v3: Guard page allocations get special free path */
    if (__builtin_expect(is_guard_page_alloc(hdr), 0)) {
        check_canaries(hdr, ptr, "free");
        guard_page_free(hdr, ptr);
        return;
    }

    check_canaries(hdr, ptr, "free");
    registry_remove(hdr);

    /* v3: Store return address (free-site) in underflow field for diagnostics.
     * The underflow canary was already verified in check_canaries above. */
    hdr->underflow = (uint64_t)(uintptr_t)__builtin_return_address(0);

    /* Poison user data + tail for UAF detection */
    memset(ptr, POISON_BYTE, hdr->size + TAIL_SIZE);

    /* Mark freed */
    hdr->canary = FREED_CANARY;

    /* v3: Push to thread-local quarantine (no atomics!) */
    quarantine_push(hdr);
    maybe_periodic_scan();
}

void *calloc(size_t nmemb, size_t size) {
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

    size_t total = nmemb * size;
    if (__builtin_expect(nmemb != 0 && total / nmemb != size, 0))
        return NULL;

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

    /* v3: Guard page allocs can't be realloc'd in-place, do malloc+copy+free */
    if (__builtin_expect(is_guard_page_alloc(hdr), 0)) {
        check_canaries(hdr, ptr, "realloc");
        size_t old_size = hdr->size;
        void *new_ptr = malloc(size);
        if (new_ptr) {
            memcpy(new_ptr, ptr, old_size < size ? old_size : size);
            guard_page_free(hdr, ptr);
        }
        return new_ptr;
    }

    check_canaries(hdr, ptr, "realloc");

    size_t old_size = hdr->size;
    registry_remove(hdr);

    void *new_raw = real_realloc(hdr, HDR_SIZE + size + TAIL_SIZE);
    if (__builtin_expect(!new_raw, 0)) {
        registry_add(hdr);
        return NULL;
    }

    alloc_header_t *new_hdr = (alloc_header_t *)new_raw;
    new_hdr->underflow = UNDERFLOW_CANARY;
    new_hdr->size = size;

    void *new_user = (char *)new_raw + HDR_SIZE;

    if (size > old_size) {
        fast_memset((char *)new_user + old_size, JUNK_BYTE, size - old_size);
    }

    write_tail(new_user, size);
    registry_add(new_hdr);
    maybe_periodic_scan();
    return new_user;
}

/* ========================================================================= */
/* Aligned allocation interception                                           */
/* ========================================================================= */

void *memalign(size_t alignment, size_t size) {
    (void)alignment;
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
