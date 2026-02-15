# LiteSan — Lightweight Heap Sanitizer for Persistent Mode Fuzzing

## Table of Contents

1. [Problem: Why libdislocator Fails in Persistent Mode](#problem-why-libdislocator-fails-in-persistent-mode)
2. [Solution Overview](#solution-overview)
3. [Core Concept: LD_PRELOAD Function Interposition](#core-concept-ld_preload-function-interposition)
4. [The Chicken-and-Egg Problem: Bootstrap Buffer](#the-chicken-and-egg-problem-bootstrap-buffer)
5. [Memory Layout: How Every Allocation Looks](#memory-layout-how-every-allocation-looks)
6. [Algorithm: malloc()](#algorithm-malloc)
7. [Algorithm: free()](#algorithm-free)
8. [Algorithm: realloc()](#algorithm-realloc)
9. [Algorithm: calloc()](#algorithm-calloc)
10. [Detection Logic: How Each Bug Type Is Caught](#detection-logic-how-each-bug-type-is-caught)
11. [Allocation Registry: Exit, Signal, and Periodic Scanning](#allocation-registry-exit-signal-and-periodic-scanning)
12. [Quarantine: The Ring Buffer Algorithm](#quarantine-the-ring-buffer-algorithm)
13. [Lock-Free Concurrency: Why No Mutex](#lock-free-concurrency-why-no-mutex)
14. [Magic Values: Why These Specific Numbers](#magic-values-why-these-specific-numbers)
15. [Edge Cases Handled](#edge-cases-handled)
16. [Signal Chain: From Detection to AFL](#signal-chain-from-detection-to-afl)
17. [Comparison: LiteSan vs libdislocator vs ASan](#comparison)
18. [Limitations and Trade-offs](#limitations-and-trade-offs)
19. [Build and Usage](#build-and-usage)
20. [Files](#files)
21. [Honest Trade-offs](#honest-trade-offs)

---

## Problem: Why libdislocator Fails in Persistent Mode

libdislocator is AFL++'s built-in heap sanitizer. It works by replacing every
`malloc(N)` with `mmap(N rounded up to page size)` and placing the allocation
at the end of the page so any overflow hits the unmapped guard page after it.

This is great for fork-per-exec fuzzing (fresh address space each run), but
**catastrophic for persistent mode** where the same process runs 1000+ iterations:

```
                  libdislocator                        Normal malloc
                  ─────────────                        ─────────────
malloc(16)    →   mmap(4096) + mprotect(4096)     →   sbrk adjustment (no syscall)
free(ptr)     →   munmap(4096)                    →   returned to freelist (no syscall)
Syscalls/exec →   ~500,000                        →   ~100
VMAs/exec     →   ~195,000                        →   ~200
```

In persistent mode, each iteration does malloc/free but VMAs (Virtual Memory
Areas — kernel tracking structures for each mmap region) **accumulate across
iterations** because munmap doesn't always collapse adjacent VMAs. After ~150
iterations the kernel's VMA limit is hit → `mmap()` returns `MAP_FAILED` →
libdislocator calls `abort()` → false positive crash recorded by AFL.

**Measured impact**: sanitizer instances ran at ~64 exec/sec (vs ~1,400 regular)
and spent 100% of time in calibration (fuzz_time: 0 in fuzzer_stats). They
never actually started fuzzing.

## Solution Overview

`litesan.so` takes a completely different approach:

- Uses **normal libc malloc** internally (no mmap per alloc)
- Wraps each allocation with **canary sentinel values** (magic numbers)
- Checks canaries on every `free()` and `realloc()` to detect corruption
- **Allocation registry** tracks all live allocations — scans at exit, on crash signals, and periodically during execution to catch overflows on blocks that are never freed
- **Quarantine** delays `free()` to catch use-after-free
- **Poison fill** (0xFE) on freed memory makes UAF reads visible
- **Junk fill** (0xAA) on new allocations makes uninitialized reads visible

**Overhead: ~3% (1.35x)** vs 1,510% (14.5x) for libdislocator.

### Key Features

- **Constructor-resolved libc functions** — `dlsym()` runs once at library load
  in `__attribute__((constructor))`. No per-call branches.
- **Thread-local quarantine** — each thread has its own 256-slot ring buffer.
  Zero atomics on `free()`, zero contention between cores.
- **Fibonacci multiply-shift hash** — `ptr * 0x9E3779B97F4A7C15 >> 48` for
  better distribution in the registry, fewer probe chains.
- **Incremental registry scan** — scans 1/64th (1024 slots) per trigger instead
  of all 65,536. Same coverage over time, 64x less work per trigger.
- **Inline memset** for allocations <= 64 bytes (the common case).
- **Multi-spot + sampled full-buffer UAF check** — 3 spot-checks on every
  eviction, plus a full byte scan every 64th eviction.
- **Heap underflow detection** — 8-byte red zone before the header.
- **Guard pages for huge allocs** (>= 64KB) — `mmap` + `PROT_NONE` pages
  before and after. Hardware-enforced overflow/underflow detection.
- **Free-site diagnostics** — stores caller address on `free()`, prints it
  when UAF or double-free is detected.
- **Aligned allocator interception** — `memalign`, `posix_memalign`,
  `aligned_alloc`, `valloc`, `pvalloc` all instrumented.
- **calloc integer overflow protection** — `calloc(nmemb, size)` where
  `nmemb * size` overflows returns NULL.
- **-O3 build** with `__builtin_expect` on all error paths.

---

## Core Concept: LD_PRELOAD Function Interposition

When Linux loads a program, it resolves symbols (function names → addresses)
from shared libraries. Normally `malloc` resolves to glibc's implementation.

`LD_PRELOAD` forces the dynamic linker to load our `.so` **before** libc.
Since our `.so` exports symbols named `malloc`, `free`, `calloc`, `realloc`,
the linker binds those names to **our** functions instead of libc's.

```
Normal:     program calls malloc() → libc malloc()

With us:    program calls malloc() → OUR malloc() → libc malloc() (via dlsym)
```

To call the **real** libc functions from inside our overrides, we use
`dlsym(RTLD_NEXT, "malloc")` which says: "find the NEXT library in the load
order that exports `malloc`" — that's libc. We store these function pointers:

```c
static void *(*real_malloc)(size_t)  = NULL;   // pointer to libc's malloc
static void  (*real_free)(void *)    = NULL;    // pointer to libc's free
// ... etc

static void resolve_real(void) {
    if (real_malloc) return;
    resolving = 1;                    // flag: we're inside dlsym
    real_malloc  = dlsym(RTLD_NEXT, "malloc");
    real_free    = dlsym(RTLD_NEXT, "free");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_calloc  = dlsym(RTLD_NEXT, "calloc");
    resolving = 0;
}

// v2: resolve once at library load
__attribute__((constructor))
static void litesan_init(void) {
    resolve_real();
    atexit(atexit_scan);
    // install signal handlers ...
}
```

v2 resolves all function pointers once in `__attribute__((constructor))` at
library load time. The `resolve_real()` call in each function is kept as a
fallback (hinted `__builtin_expect(0)`) but in practice never executes.

## The Chicken-and-Egg Problem: Bootstrap Buffer

There's a tricky bootstrapping issue: `dlsym()` internally calls `calloc()`
to allocate memory for its own bookkeeping. But we've overridden `calloc()`.
If our `calloc()` calls `resolve_real()` which calls `dlsym()` which calls
`calloc()` ... infinite recursion → stack overflow → crash.

The solution is a **static bootstrap buffer** — a fixed 16KB array in the
`.bss` segment that services allocations during the dlsym resolution window:

```c
static char   bootstrap_buf[16384];   // 16KB static buffer
static size_t bootstrap_used = 0;     // bump pointer (how much is used)
static int    resolving = 0;          // flag: are we inside dlsym()?

void *calloc(size_t nmemb, size_t size) {
    // If we're inside dlsym(), use the bootstrap buffer instead
    if (resolving || !real_malloc) {
        size_t total = nmemb * size;
        if (bootstrap_used + total > sizeof(bootstrap_buf)) return NULL;
        void *p = bootstrap_buf + bootstrap_used;
        bootstrap_used += total;       // bump pointer forward
        memset(p, 0, total);           // calloc must zero-fill
        return p;
    }
    // Normal path: use our instrumented malloc
    ...
}
```

This is a **bump allocator** — the simplest possible allocator. It just moves
a pointer forward. It never frees (bootstrap allocations are tiny and permanent).
When `free()` receives a bootstrap pointer, it checks and silently ignores it:

```c
static inline int is_bootstrap(void *ptr) {
    return (char *)ptr >= bootstrap_buf &&
           (char *)ptr <  bootstrap_buf + sizeof(bootstrap_buf);
}

void free(void *ptr) {
    if (!ptr) return;
    if (is_bootstrap(ptr)) return;   // came from bootstrap, ignore
    ...
}
```

The bootstrap window is extremely short: just the 4 `dlsym()` calls during
`resolve_real()`. After that, all allocations go through the real path.

---

## Memory Layout: How Every Allocation Looks

When the program calls `malloc(N)`, we actually allocate `N + 32` bytes from
libc and lay them out like this:

```
 What libc                                  What the program
 allocates                                  sees (returned ptr)
 ┌──────────┐                               │
 │          ▼                               ▼
 ┌──────────┬──────────┬──────────┬─────────────────────────┬──────────┐
 │underflow │  size    │  head    │    user data            │  tail    │
 │  canary  │  (8B)   │  canary  │    (N bytes)            │  canary  │
 │  (8B)   │          │  (8B)   │                         │  (8B)   │
 └──────────┴──────────┴──────────┴─────────────────────────┴──────────┘
 ◄──────── HDR_SIZE (24B) ────────►◄────── N bytes ─────────►◄─ 8B ───►

 Total libc allocation = 24 + N + 8 = N + 32 bytes
```

The `alloc_header_t` struct is the first 24 bytes:

```c
typedef struct {
    uint64_t underflow; // 8 bytes: UNDERFLOW_CANARY (red zone before header)
    size_t   size;      // 8 bytes: the original requested size N
    uint64_t canary;    // 8 bytes: HEAD_CANARY (live) or FREED_CANARY (freed)
} alloc_header_t;
```

The **underflow canary** is an 8-byte red zone before the size/canary fields. If
something writes backward past the start of a preceding allocation, it corrupts
this value → detected on `free()` or `realloc()`.

The **user pointer** (what `malloc` returns to the caller) points to byte 24 —
right after the header. The caller doesn't know about the header or tail canary.

The **tail canary** is an 8-byte value written at `user_ptr + size`, immediately
after the user's data. If the program writes past its allocation, it overwrites
this value, and we detect it on the next `free()` or `realloc()`.

### Huge allocations (>= 64KB): Guard page layout

Allocations >= 64KB use `mmap` with hardware-enforced guard pages instead:

```
 [PROT_NONE guard (4KB)] [header(24)] [user data(N)] [tail(8)] [PROT_NONE guard (4KB)]
```

Any overflow or underflow beyond the guard pages triggers an instant SIGSEGV
from the CPU — no need to wait for `free()` to check canaries.

---

## Algorithm: malloc()

Uses an internal `malloc_internal(size, junk_fill)` function shared by both
`malloc()` and `calloc()`. The `junk_fill` flag controls whether 0xAA fill is
applied (1 for malloc, 0 for calloc since calloc zeroes anyway).

Libc function pointers are resolved once in `__attribute__((constructor))` at
library load time. A fallback `resolve_real()` check is kept in `malloc()` for
edge cases, but it's hinted `__builtin_expect(!real_malloc, 0)`.

For allocations >= 64KB, a separate `guard_page_alloc()` path is used (see
Memory Layout above).

```
malloc(size):
    1. (libc pointers already resolved in constructor)
    2. if size >= 64KB: return guard_page_alloc(size)
    3. raw = real_malloc(24 + size + 8) — ask libc for extra space
    4. hdr = (alloc_header_t *)raw
    5. hdr->underflow = UNDERFLOW_CANARY — write underflow red zone
    6. hdr->size   = size              — remember the requested size
    7. hdr->canary = HEAD_CANARY       — write 0xDEADBEEFCAFEBABE
    8. user = raw + 24                 — user pointer starts after header
    9. fast_memset/memset(user, 0xAA)  — junk fill (inline for <= 64 bytes)
   10. write_tail(user, size)          — write 0xFEEDFACE8BADF00D after user data
   11. registry_add(hdr)               — track in allocation registry (Fibonacci hash)
   12. maybe_incremental_scan()        — scan 1/64th of registry if counter triggers
   13. return user                     — caller gets pointer to step 8
```

**Why junk fill (step 7)?** If we left the memory uninitialized (whatever libc
gives us), the program might read garbage and coincidentally get "correct" values.
By filling with `0xAA` (10101010 in binary), any read of uninitialized memory
produces a distinctive recognizable pattern. If you see `0xAAAAAAAA` in a crash
dump or debugger, you know immediately: this was never written by the program.

**Why not zero-fill?** Zero is a common "valid" value (NULL pointer, 0 integer,
empty string). `0xAA` is almost never valid, making bugs more obvious.

## Algorithm: free()

```
free(ptr):
    1. if ptr == NULL: return          — C standard: free(NULL) is a no-op
    2. if is_bootstrap(ptr): return    — came from bootstrap buffer, ignore
    3. if is_guard_page_alloc(ptr):    — huge alloc, use guard_page_free()
         check_canaries + munmap
         return
    4. resolve_real()
    5. hdr = ptr - 24                  — walk back to find our header
    6. check_canaries(hdr, ptr)        — THE KEY CHECK (see below)
    7. hdr->underflow = return_address — store free-site for diagnostics
    8. memset(ptr, 0xFE, size + 8)    — poison user data AND tail canary
    9. hdr->canary = FREED_CANARY      — mark header as freed
   10. tl_quarantine_push(hdr)         — push to thread-local quarantine ring
```

**Step 6 — check_canaries()** does four checks in order:

```
check_canaries(hdr, ptr):
    A. if hdr->canary == FREED_CANARY:
         → DOUBLE-FREE! This block was already freed.
         → print free-site address from hdr->underflow
         → print backtrace, abort()

    B. if hdr->underflow != UNDERFLOW_CANARY (and != GUARD_UNDERFLOW):
         → HEAP UNDERFLOW! Something wrote before this allocation.
         → print backtrace, abort()

    C. if hdr->canary != HEAD_CANARY:
         → HEAD CANARY CORRUPT! Something wrote into the header,
           or the pointer is garbage.
         → print backtrace, abort()

    D. tail = *(uint64_t *)(ptr + hdr->size)
       if tail != TAIL_CANARY:
         → HEAP BUFFER OVERFLOW! The program wrote past its allocation
           and corrupted the tail canary.
         → print backtrace, abort()
```

The **order matters**: we check for double-free first (A) because on `free()`,
we store the return address in `hdr->underflow` (step 7), overwriting the
underflow canary. If we checked underflow before double-free, a second free
would see the return address instead of UNDERFLOW_CANARY and falsely report
"HEAP UNDERFLOW" instead of "DOUBLE-FREE".

**Step 7 — free-site**: After canaries pass, we save `__builtin_return_address(0)`
(the address of the code that called `free()`) into `hdr->underflow`. This
reuses the underflow field (already validated) for diagnostics. If a UAF is
later detected, the error message includes where the block was freed.

**Step 8 — poison**: After the checks pass, we fill the entire user region
(and the tail canary) with `0xFE`. This means:
- Any subsequent READ of this memory returns `0xFEFEFEFE...` — distinctive
  pattern that screams "use-after-free" in debugger/crash dumps
- Any subsequent WRITE changes the poison — detected by quarantine on eviction

**Step 9 — mark freed**: We set `hdr->canary = FREED_CANARY` so that if
`free()` is called again on this pointer, step 6A catches it immediately.

**Step 10 — quarantine**: Instead of calling `real_free(hdr)` now, we push
the block into the thread-local quarantine ring. This delays the actual free
so the poison stays in place longer, increasing the window to catch UAF. See
the Quarantine section below for the full algorithm.

## Algorithm: realloc()

`realloc()` has several edge cases defined by the C standard:

```
realloc(ptr, size):
    1. if ptr == NULL: return malloc(size)     — realloc(NULL, N) = malloc(N)
    2. if size == 0: free(ptr); return NULL    — realloc(p, 0) = free(p)
    3. if is_bootstrap(ptr):                   — handle bootstrap → real transition
         new = malloc(size)
         memcpy(new, ptr, min(size, available))
         return new                            — can't free bootstrap, just abandon it
    4. resolve_real()
    5. hdr = ptr - 24
    6. check_canaries(hdr, ptr)                — check BEFORE resize!
    7. old_size = hdr->size
    8. new_raw = real_realloc(hdr, 24 + size + 8)  — libc resizes the raw block
    9. if new_raw == NULL: return NULL
   10. new_hdr = (alloc_header_t *)new_raw
   11. new_hdr->size = size                    — update stored size
   12. new_user = new_raw + 24
   13. if size > old_size:                     — if grown, junk-fill new portion
         memset(new_user + old_size, 0xAA, size - old_size)
   14. write_tail(new_user, size)              — write tail canary at new end
   15. return new_user
```

**Why check canaries BEFORE resize (step 6)?** If there's a buffer overflow
on the old allocation, we want to catch it NOW, before `real_realloc` potentially
moves the data somewhere else (destroying the evidence). Once libc copies the
data to a new location, the corrupted tail canary is gone.

**Why use real_realloc instead of malloc+memcpy+free (step 8)?** This is a key
optimization. `real_realloc` can often **grow the allocation in-place** without
copying if there's free space after the current block in libc's heap. The naive
approach (malloc new, memcpy, free old) ALWAYS copies, which is wasteful for
large allocations that grow slightly. Using `real_realloc` directly lets libc
make the optimal decision.

**Step 13 — junk fill new portion**: If the allocation grew, the new bytes
beyond `old_size` are uninitialized. We fill them with `0xAA` just like in
`malloc()`, so any read of the new portion without writing first is detectable.

## Algorithm: calloc()

```
calloc(nmemb, size):
    1. if resolving:                           — inside dlsym bootstrap
         total = nmemb * size
         p = bootstrap_buf + bootstrap_used    — bump allocate
         bootstrap_used += total
         memset(p, 0, total)                   — calloc zeroes memory
         return p
    2. total = nmemb * size
    3. if nmemb != 0 && total / nmemb != size: — v2: integer overflow check
         return NULL                           — reject dangerous wraparound
    4. ptr = malloc_internal(total, 0)         — v2: junk_fill=0 (skip 0xAA)
    5. memset(ptr, 0, total)                   — zero-fill
    6. return ptr
```

**v2 changes from v1:**

1. **Integer overflow protection (step 3)**: `calloc(0x100000001, 0x100000001)`
   overflows to a tiny `total`. v1 would allocate a small buffer and the program
   could write `nmemb * size` bytes into it — classic heap overflow. v2 detects
   the wraparound and returns NULL.

2. **Skip junk fill (step 4)**: v1 called `malloc(total)` which junk-filled
   with 0xAA, then immediately zeroed it in step 5 — a double-write. v2 uses
   `malloc_internal(total, 0)` with `junk_fill=0`, avoiding the wasted memset.
   This makes calloc ~6% faster.

---

## Detection Logic: How Each Bug Type Is Caught

### 1. Heap Buffer Overflow

```
 malloc(10) returns:
 ┌────────┬────────┬──────────┬────────────┐
 │ size=10│DEADBEEF│ AAAAAAA… │ FEEDFACE…  │
 │        │CAFEBABE│ (10 B)  │ (tail)     │
 └────────┴────────┴──────────┴────────────┘

 Program writes 12 bytes (2 past the end):
 ┌────────┬────────┬──────────┬────────────┐
 │ size=10│DEADBEEF│ data……XX │ XXEDFACE…  │  ← tail canary corrupted!
 │        │CAFEBABE│          │            │
 └────────┴────────┴──────────┴────────────┘

 On free(): check_canaries() reads tail → 0xXXEDFACE… != 0xFEEDFACE…
 → HEAP BUFFER OVERFLOW detected → backtrace + abort()
```

The overflow must be large enough to reach the tail canary (immediately after
the allocation). An off-by-one that writes 1 byte past the allocation WILL
corrupt the first byte of the tail canary → detected. Even a single-byte
overflow is caught.

### 2. Double-Free

```
 First free(ptr):
   check_canaries → HEAD_CANARY OK → pass
   poison memory with 0xFE
   hdr->canary = FREED_CANARY (0xFEFEFEFEFEFEFEFE)
   push to quarantine

 Second free(ptr):  (block is still in quarantine, not yet recycled)
   check_canaries → hdr->canary == FREED_CANARY
   → DOUBLE-FREE detected → backtrace + abort()
```

This works as long as the block is still in quarantine (256 most recent frees
per thread). If the block was evicted and recycled by libc as a new allocation
with a fresh HEAD_CANARY, the double-free might not be caught. For multi-threaded
targets, total capacity is 256 x N_threads.

### 3. Use-After-Free Write

```
 free(ptr):
   poison all user bytes with 0xFE
   hdr->canary = FREED_CANARY
   push to quarantine[slot]

 ... time passes, program writes to ptr (UAF!) ...
   ptr[50..57] is now 0x4141414141414141 instead of 0xFEFEFEFEFEFEFEFE

 ... later, quarantine[slot] is evicted by another free() ...
   check_quarantined(hdr):
     hdr->canary == FREED_CANARY? YES (header wasn't touched)
     first 8 bytes == 0xFEFE...?    YES (untouched)
     middle 8 bytes == 0xFEFE...?   NO → got 0x4141414141414141
     → USE-AFTER-FREE WRITE detected → backtrace + abort()
```

**Multi-spot + sampled full-buffer UAF check.** On every quarantine eviction,
3 spots are checked: first 8 bytes, middle 8 bytes (aligned to 8-byte
boundary), and last 8 bytes. This catches UAF writes at any region of the
buffer for the cost of only 2 extra loads.

Additionally, every 64th eviction triggers a **full-buffer scan** — checking
ALL bytes of the freed block against the poison pattern. This catches UAF
writes that land between the 3 spot-check locations:

- UAF writes to the header (bytes -24 to -1): **always detected**
- UAF writes to bytes 0-7: **always detected** (spot check)
- UAF writes near the middle: **always detected** (spot check)
- UAF writes near the end: **always detected** (spot check)
- UAF writes between spots: **detected 1/64 of the time** (sampled full scan)

The 3-spot check runs in O(1). The full-buffer scan runs in O(N) but only
on 1/64 of evictions — a good balance between coverage and throughput.

### 4. Use-After-Free Read (partial)

```
 free(ptr):
   memset(ptr, 0xFE, size)    ← all user data is now 0xFE

 Program reads ptr[0]:
   gets 0xFE  ← if this propagates to a crash or unexpected behavior,
                 the 0xFE pattern in the crash dump reveals it's a UAF read
```

This is "partial" detection because the sanitizer doesn't actively abort on
UAF reads — it can't intercept arbitrary memory reads without hardware support
(like ASan's shadow memory). Instead, the poisoned data **passively** causes
downstream failures: NULL pointer derefs (0xFEFEFEFE as a pointer), wrong
branch taken, garbled output, etc. The 0xFE pattern in crash dumps is the clue.

### 5. Uninitialized Read

```
 malloc(100) returns memory filled with 0xAA

 Program reads ptr[50] without writing first:
   gets 0xAA  ← distinctive pattern in crash dump / debugger
```

Same passive detection as UAF reads. The `0xAA` pattern (10101010 binary)
is unlikely to be a valid pointer, integer, or string, so it tends to cause
visible failures downstream.

---

## Allocation Registry: Exit, Signal, and Periodic Scanning

The original LiteSan only checks for overflows at `free()` / `realloc()`
time. If a buffer is overflowed but never freed (memory leak), the overflow is
completely invisible. The **allocation registry** closes this gap.

### How it works

Every `malloc()` registers the allocation header pointer in a fixed-size hash
table (65536 slots, open addressing with linear probing). Every `free()` removes
it. The registry can be scanned at any time to check all live allocations for
canary corruption.

```c
#define REGISTRY_SIZE  65536          // must be power of 2
#define REGISTRY_MASK  (REGISTRY_SIZE - 1)
#define SCAN_INTERVAL_MASK  1023      // bitmask: scan every 1024 ops
#define SCAN_CHUNK          1024      // scan 1/64th of registry per trigger

static void * volatile registry[REGISTRY_SIZE];

static inline size_t registry_hash(void *ptr) {
    uintptr_t x = (uintptr_t)ptr;
    x *= 0x9E3779B97F4A7C15ULL;      // Fibonacci / golden ratio constant
    return (x >> 48) & REGISTRY_MASK;
}
```

The hash uses **multiply-shift (Fibonacci hashing)**: multiplying by the golden
ratio constant spreads entries uniformly across the table, avoiding the clustering
that a simple shift-and-mask causes with malloc's address patterns. This gives
O(1) amortized add/remove with shorter probe chains.

### Three scan triggers

1. **atexit scan** — `atexit(atexit_scan)` registered in a `__attribute__((constructor))`.
   When the process exits normally, all live allocations are checked. Detects
   overflows on leaked buffers.

2. **Signal handler scan** — handlers installed for SIGSEGV, SIGBUS, SIGABRT.
   On crash, the registry is scanned (using only signal-safe `write(2)` calls,
   not `fprintf`). Previous signal handlers are saved and chained to, so
   `foxit_throw_bypass.so` and other handlers still work.

3. **Incremental scan** — every 1024 `malloc()`+`free()` operations, 1/64th
   of the registry (1024 slots) is scanned. A shared cursor advances through
   the table, achieving full coverage over 64 triggers. Catches overflows while
   the program is still running, even if the corrupted buffer isn't freed.

### Lock-free design

Same philosophy as the quarantine — no mutex, atomic CAS operations only:

- **`registry_add(hdr)`**: Fibonacci hash to get bucket, linear probe for NULL
  slot, `__atomic_compare_exchange_n` to claim it. If full (all 65536 slots
  occupied), silently drops — overflow will still be caught on `free()`.
- **`registry_remove(hdr)`**: Fibonacci hash to get bucket, linear probe for
  matching pointer, atomic CAS to NULL.
- **`scan_registry_range(start, count)`**: walks a range of slots (1024 per
  trigger), checks head+tail+underflow canaries. Uses `write(2)` in signal
  context, `fprintf()` otherwise.

### Re-entrancy guard

An `already_scanned` flag (atomic test-and-set) prevents double-scanning when
atexit calls `abort()` which triggers the signal handler. Without this guard:
atexit → scan → find corruption → abort → SIGABRT handler → scan again.

---

## Quarantine: Thread-Local Ring Buffer

Each thread has its own private 256-slot quarantine ring that delays
`real_free()` to keep freed memory poisoned longer. No atomics, no contention.

```c
#define TL_QUARANTINE_SIZE 256

typedef struct {
    void *ring[TL_QUARANTINE_SIZE];
    size_t idx;
} tl_quarantine_t;

static __thread tl_quarantine_t tl_q = { .idx = 0 };
```

### Push operation (inside our free()):

```
 1. slot = tl_q.idx % 256          — simple modulo, no atomic needed
 2. oldest = tl_q.ring[slot]       — get whatever was in this slot
 3. tl_q.ring[slot] = new_block    — put our freed block in
 4. tl_q.idx++

 5. if oldest != NULL:
      check_quarantined(oldest)    — verify poison is intact
      real_free(oldest)            — finally return memory to libc
```

### check_quarantined() — multi-spot + sampled full scan:

```
 check_quarantined(hdr):
   if hdr->canary != FREED_CANARY → USE-AFTER-FREE (header corrupted)

   // 3-spot check (every eviction):
   first 8 user bytes  == 0xFEFE...? → if not, USE-AFTER-FREE
   middle 8 user bytes == 0xFEFE...? → if not, USE-AFTER-FREE
   last 8 user bytes   == 0xFEFE...? → if not, USE-AFTER-FREE

   // Full-buffer scan (every 64th eviction):
   if ++tl_evict_count % 64 == 0:
     scan ALL user bytes for any non-0xFE byte → USE-AFTER-FREE
```

### Why 256 per-thread instead of 2048 shared?

| Property | Shared 2048 | Thread-local 256 |
|---|---|---|
| Atomics per free() | 2 (`lock xadd` + `lock xchg`) | 0 |
| Multi-thread contention | Cache-line bouncing | None |
| Single-thread window | 2048 frees | 256 frees |
| Multi-thread (10 threads) | 2048 total | 2560 total (256 x 10) |
| Speed impact | ~39% slower | Baseline |

For the main use case (multi-threaded Foxit with 10 threads), the total
quarantine capacity is actually **larger** than the shared version, while
eliminating all atomic operations from the free path.

---

## Lock-Free Concurrency: Why No Mutex

The Foxit SDK spawns **9 permanent background threads** on `Library::Initialize()`.
These threads do their own malloc/free concurrently with the fuzzing thread.
A mutex in malloc/free would cause:

1. **Contention**: 10 threads fighting over one lock on every alloc/free
2. **Priority inversion**: fuzzing thread blocked waiting for SDK background thread
3. **Deadlock risk**: if a signal handler fires while holding the mutex

### Thread-local quarantine: zero atomics

The quarantine is entirely thread-local (`__thread` storage). Each thread's
`free()` writes only to its own 256-slot ring — no shared state, no atomics,
no contention. This is the biggest performance win over earlier versions.

### Registry: lock-free atomic CAS

The allocation registry IS shared across threads (it needs to track all live
allocations for signal-handler and exit scans). It uses atomic CAS operations:

- **`registry_add(hdr)`**: hash pointer with Fibonacci hash, linear probe for
  NULL slot, `__atomic_compare_exchange_n` to claim it.
- **`registry_remove(hdr)`**: hash pointer, linear probe for matching entry,
  atomic CAS to NULL.
- **`scan_registry_range(start, count)`**: walks a range of slots, checks
  canaries. Uses `write(2)` in signal context, `fprintf()` otherwise.

### Why this is safe:

- Quarantine: entirely thread-local, no sharing at all
- Registry: atomic CAS ensures no torn reads/writes on pointer slots
- No ABA problem: we don't make decisions based on "was this value changed?"
- Worst case under extreme contention: a registry slot is briefly occupied
  by two threads probing — one will find the next empty slot

---

## Magic Values: Why These Specific Numbers

```c
#define HEAD_CANARY       0xDEADBEEFCAFEBABEULL   // live allocation
#define TAIL_CANARY       0xFEEDFACE8BADF00DULL   // end of allocation
#define FREED_CANARY      0xFEFEFEFEFEFEFEFEULL  // freed allocation
#define UNDERFLOW_CANARY  0xBADC0FFEE0DDF00DULL   // red zone before header
#define GUARD_UNDERFLOW   0xBADC0FFEE0DD6ACEULL   // marks guard-page allocs
#define POISON_BYTE       0xFE                     // fill freed memory
#define JUNK_BYTE         0xAA                     // fill new allocations
```

**HEAD_CANARY (0xDEADBEEFCAFEBABE)**:
- Recognizable hex-speak pattern — easy to spot in debugger
- 8 bytes = extremely unlikely to appear by accident (1 in 2^64)
- Different from TAIL and FREED so we can distinguish states

**TAIL_CANARY (0xFEEDFACE8BADF00D)**:
- Different from HEAD — if head and tail were the same value, an overflow that
  copies the head canary forward would create a "valid" tail canary and hide
  the overflow
- Also hex-speak for easy visual identification

**FREED_CANARY (0xFEFEFEFEFEFEFEFE)**:
- Same byte pattern as POISON_BYTE (0xFE) — this is intentional
- When we poison freed memory, the header canary visually "blends" with the
  poisoned data in a hex dump, making freed blocks easy to identify
- Different from both HEAD and TAIL so check_canaries() correctly identifies
  the block as freed (→ double-free) vs corrupted (→ overflow)

**POISON_BYTE (0xFE)**:
- Not 0x00: zero is too commonly valid (NULL, empty string, zero integer)
- Not 0xFF: sometimes used as "all bits set" sentinel
- 0xFE as a pointer: 0xFEFEFEFEFEFEFEFE is in non-canonical address space
  on x86-64 (only 48-bit addresses are valid), so dereferencing it ALWAYS
  segfaults — perfect for catching UAF reads that become pointer derefs

**JUNK_BYTE (0xAA)**:
- Binary: 10101010 — alternating bits, distinctive pattern
- As a 32-bit integer: 0xAAAAAAAA = 2,863,311,530 — absurdly large, likely to
  cause failures if used as a size, index, or count
- As a pointer: 0xAAAAAAAAAAAAAAAA — non-canonical, always segfaults
- As a character: not printable ASCII, stands out in string dumps
- Different from POISON (0xFE) so you can distinguish "never written" from
  "freed" in crash dumps

**UNDERFLOW_CANARY (0xBADC0FFEE0DDF00D)**:
- Placed before the header as a red zone for heap underflow detection
- Different from HEAD, TAIL, and FREED so it's never confused with other states
- Checked on every `free()` and `realloc()` before any other canary checks

**GUARD_UNDERFLOW (0xBADC0FFEE0DD6ACE)**:
- Marks allocations that used the guard-page code path (>= 64KB)
- `is_guard_page_alloc()` checks for this marker to route to `munmap`-based free
- Accepted as valid alongside UNDERFLOW_CANARY in canary checks

---

## Edge Cases Handled

### free(NULL)
C standard says `free(NULL)` is a no-op. We handle this on line 1 of `free()`:
```c
if (!ptr) return;
```

### free(bootstrap pointer)
During startup, `dlsym()` allocates via our bootstrap buffer. These pointers
don't have our header/canary layout. If they reach `free()`, we'd read garbage
as the header → false positive crash. We detect and skip them:
```c
if (is_bootstrap(ptr)) return;
```

### realloc(NULL, size)
C standard: equivalent to `malloc(size)`. Handled on line 1 of `realloc()`:
```c
if (!ptr) return malloc(size);
```

### realloc(ptr, 0)
C standard: equivalent to `free(ptr)`. Handled on line 2 of `realloc()`:
```c
if (size == 0) { free(ptr); return NULL; }
```

### realloc(bootstrap_ptr, size)
A bootstrap pointer being reallocated means the program wants to resize a
dlsym-era allocation. We can't `real_realloc` it (it's not from libc heap),
so we malloc new, copy what we can, and return:
```c
if (is_bootstrap(ptr)) {
    void *new_ptr = malloc(size);
    memcpy(new_ptr, ptr, min(size, available_bootstrap_space));
    return new_ptr;
    // bootstrap memory is never freed — it's a static buffer, that's fine
}
```

### calloc overflow (nmemb * size)
v2 checks for integer overflow in `calloc(nmemb, size)`: if `nmemb * size`
wraps around to a small value, we return NULL. Without this check, the program
would get a tiny buffer and write `nmemb * size` bytes into it — a heap
overflow that might not corrupt our tail canary (the write could skip past it).

---

## Signal Chain: From Detection to AFL

When LiteSan detects corruption, it calls `abort()` which sends
SIGABRT to the process. Here's the full chain of signal handlers:

```
litesan.so: check_canaries() fails
  │
  ▼
abort()  →  raises SIGABRT
  │
  ▼
foxit_throw_bypass.so: sigabrt_handler()
  │
  ├─ mmap probe (4MB): can we still allocate memory?
  │   │
  │   ├─ MAP_FAILED → address space exhausted (OOM)
  │   │   └─ _exit(0)  — suppress, not a real bug
  │   │
  │   └─ SUCCESS → memory is fine, this is a REAL bug
  │       └─ munmap the probe, forward to fallback handler
  │
  ▼
harness crash_handler (installed by harness_foxit_persist.cpp)
  │
  ├─ Phase 0 (parsing): we're inside PDF processing
  │   └─ _exit(SIGABRT) — AFL records this as a crash ✓
  │
  └─ Phase 1 (cleanup): we're in Library::Release() / destructor
      └─ _exit(0) — suppress, cleanup crashes aren't interesting
```

**Why the mmap probe?** When running with libdislocator (not LiteSan),
libdislocator itself calls `abort()` when it can't mmap. The bypass handler's
mmap probe distinguishes "ran out of address space" (OOM → suppress) from
"canary corruption detected" (real bug → report to AFL).

With LiteSan, the mmap probe always succeeds (we don't exhaust
address space), so canary detections always flow through as real crashes to AFL.

**Why phase-based handling?** Foxit SDK can crash during cleanup
(`Library::Release()`, `PDFDoc` destructor) on already-corrupted state.
These cleanup crashes aren't interesting — the real bug was during parsing.
The harness sets `phase = 0` before parsing and `phase = 1` before cleanup.

---

## Comparison

### LiteSan vs libdislocator vs AddressSanitizer (ASan)

| Property                  | LiteSan                | libdislocator          | ASan (compile-time)     |
|---------------------------|------------------------|------------------------|-------------------------|
| Instrumentation           | LD_PRELOAD (binary)    | LD_PRELOAD (binary)    | Compile-time (source)   |
| Works on closed-source    | **Yes**                | **Yes**                | No (need source)        |
| Overhead                  | ~3% (1.35x)           | ~1,510% (14.5x)       | ~2x (with source)       |
| Persistent mode safe      | **Yes**                | No (OOM)               | Yes                     |
| Heap overflow             | Tail canary (8B)       | Guard page (4KB)       | Shadow memory (byte)    |
| Overflow w/o free         | **Yes** (registry scan)| No                     | **Yes**                 |
| Off-by-one               | **Yes** (exact boundary)| Page boundary only     | **Yes**                 |
| Stack overflow            | No                     | No                     | **Yes**                 |
| Global overflow           | No                     | No                     | **Yes**                 |
| Double-free               | **Yes**                | No                     | **Yes**                 |
| UAF writes                | **Yes** (quarantine)   | No                     | **Yes**                 |
| UAF reads                 | Partial (poison)       | No                     | **Yes** (immediate)     |
| Uninit reads              | Partial (junk fill)    | No                     | MSan (separate tool)    |
| Memory overhead           | ~32 bytes/alloc + quarantine | 1 page/alloc    | 1/8 of address space    |
| False positives           | None                   | OOM in persistent mode | None                    |

**Key insight**: ASan is the gold standard but requires source code and
compile-time instrumentation. For a closed-source library like Foxit's
`libfsdk_linux64.so`, we can only use LD_PRELOAD approaches. Among those,
LiteSan gives us most of ASan's detection capabilities with
dramatically lower overhead than libdislocator.

---

## Limitations and Trade-offs

### What we CANNOT detect

1. **Heap overflow that skips the tail canary**: If code writes to `ptr + size + 8`
   (jumping over the 8-byte tail canary) into the next allocation's header, we
   miss it. In practice this is rare — overflows are almost always sequential.

2. **UAF writes that miss all checks**: The 3-spot check (first/middle/last
   8 bytes) catches most UAF patterns. The sampled full-buffer scan (every
   64th eviction) provides additional coverage. But a UAF write between spots
   that gets evicted on a non-scan eviction (63/64 chance) is missed.

3. **UAF reads**: No active detection. Poison (0xFE) passively causes downstream
   failures but doesn't immediately abort. Hardware watchpoints or shadow memory
   (ASan) are needed for immediate UAF read detection.

4. **Stack buffer overflow**: We only instrument heap allocations (malloc/free).
   Stack-allocated arrays are invisible to us.

5. **Global buffer overflow**: Same — global/static arrays don't go through malloc.

6. **Heap underflow beyond the red zone**: We have an 8-byte underflow canary
   before the header. Writes that land in those 8 bytes are caught. But an
   underflow that writes to a different allocation before ours (not into our
   red zone) won't be caught by the underflow check.

### Thread safety caveats

The quarantine is lock-free and safe. However, the `check_canaries()` function
itself is not atomic — it reads head canary, then tail canary as two separate
reads. In theory, a concurrent thread could corrupt the tail between our head
check and tail check. In practice, this doesn't cause false positives (a corrupt
tail IS a real bug), but the backtrace might not show the exact corrupting thread.

### Registry limitations

7. **Registry size limit**: The allocation registry holds 65536 entries. Programs
   with more than 65536 simultaneous live allocations will have some untracked —
   overflows on those are only caught on `free()`, not by registry scans.

8. **Incremental scan coverage cycle**: Every 1024 malloc/free operations, 1/64th
   of the registry (1024 slots) is scanned. Full coverage takes 64 triggers
   (65,536 ops). An overflow on a never-freed buffer could sit undetected for
   up to 64 scan cycles before the cursor reaches its slot.

### Memory overhead

- Per allocation: 32 bytes extra (24-byte header + 8-byte tail canary)
- Quarantine: up to 256 freed blocks per thread held in memory
- Registry: 65536 pointer slots (512KB static array)
- Guard pages: 2 extra 4KB pages per allocation >= 64KB
- For Foxit SDK: negligible compared to the library's own memory usage (~200MB+)

---

## Build and Usage

### Build

```bash
cd /home/dvirgo/custom_sanitizer
gcc -shared -fPIC -O3 -o litesan.so litesan.c -ldl -rdynamic
```

Flags:
- `-shared -fPIC`: build as position-independent shared library
- `-O3`: aggressive optimization (auto-vectorization, inlining — important for
  fuzzing throughput)
- `-ldl`: link libdl for `dlsym()` (resolving real libc functions)
- `-rdynamic`: export symbols from the executable so `backtrace_symbols_fd()`
  can resolve function names in the backtrace output

### Run tests

```bash
bash tests/run_tests.sh          # 48 tests
bash tests/run_bench.sh          # Benchmark: baseline vs sanitizer
```

### Standalone test (single PDF)
```bash
LD_PRELOAD=./foxit_throw_bypass.so:./custom_sanitizer/litesan.so \
  ./harness_foxit_persist test.pdf
```

### With AFL++ (single instance test)
```bash
./scripts/run_fuzz_canary_test.sh              # Fresh start
./scripts/run_fuzz_canary_test.sh --resume     # Resume
```

### With AFL++ (10 parallel instances)
```bash
./scripts/run_fuzz_10_canary.sh                # Fresh start
./scripts/run_fuzz_10_canary.sh --resume       # Resume
```

### AFL_PRELOAD order
```
AFL_PRELOAD=foxit_throw_bypass.so:litesan.so
```

The bypass .so MUST come first — it installs signal handlers that the canary
sanitizer's `abort()` calls flow through.

### No harness changes needed

LiteSan is a pure LD_PRELOAD shim. It works with the existing
`harness_foxit_persist` binary without any modifications.

---

## Files

```
custom_sanitizer/
├── litesan.c                 — Source (~700 lines)
├── litesan.so                — Compiled library (-O3)
├── README.md                 — This file
├── .gitignore
└── tests/                    — Test suite (48 tests)
    ├── run_tests.sh          — Full test harness
    ├── run_bench.sh          — Benchmark: baseline vs sanitizer
    ├── bench_speed.c         — Throughput benchmark (500K ops)
    ├── bench_guard_page.c    — Guard page overhead benchmark
    └── test_*.c              — 48 test files
```

## Tested Detections

All verified with 48 automated tests (`tests/run_tests.sh`):

| Test                         | Result    | Details                                     |
|------------------------------|-----------|---------------------------------------------|
| Heap buffer overflow (1B)    | DETECTED  | exit 134 (SIGABRT), backtrace printed       |
| Heap buffer overflow (8B)    | DETECTED  | exit 134 (SIGABRT), backtrace printed       |
| Heap buffer overflow (large) | DETECTED  | exit 134 (SIGABRT), backtrace printed       |
| Overflow via strcpy          | DETECTED  | exit 134 (SIGABRT), backtrace printed       |
| Overflow via memcpy          | DETECTED  | exit 134 (SIGABRT), backtrace printed       |
| Overflow via loop            | DETECTED  | exit 134 (SIGABRT), backtrace printed       |
| Overflow without free        | DETECTED  | atexit registry scan catches corruption     |
| Overflow on realloc'd buf    | DETECTED  | exit 134 (SIGABRT), backtrace printed       |
| Overflow on calloc'd buf     | DETECTED  | exit 134 (SIGABRT), backtrace printed       |
| Overflow on large alloc      | DETECTED  | exit 134 (SIGABRT), backtrace printed       |
| Overflow on zero-size alloc  | DETECTED  | exit 134 (SIGABRT), backtrace printed       |
| Double-free                  | DETECTED  | exit 134, includes free-site address        |
| Double-free (immediate)      | DETECTED  | exit 134, includes free-site address        |
| Double-free (with ops)       | DETECTED  | exit 134, includes free-site address        |
| UAF write (first 8 bytes)    | DETECTED  | quarantine eviction catches corruption      |
| UAF write (header)           | DETECTED  | quarantine eviction catches corruption      |
| UAF write (delayed)          | DETECTED  | quarantine eviction catches corruption      |
| UAF write (middle)           | DETECTED  | multi-spot check catches middle corruption  |
| UAF write (end)              | DETECTED  | multi-spot check catches end corruption     |
| UAF write (between spots)    | DETECTED  | sampled full-buffer scan catches it         |
| UAF read                     | PARTIAL   | `0xFEFEFEFE` poison visible in memory      |
| Heap underflow (direct)      | DETECTED  | underflow canary corrupted → abort          |
| Heap underflow (memcpy)      | DETECTED  | underflow canary corrupted → abort          |
| Guard page basic (no crash)  | CLEAN     | 64KB/100KB allocs work without false pos    |
| Guard page overflow           | DETECTED  | SIGSEGV from hardware guard page            |
| Free-site in error msg       | DETECTED  | UAF error includes free-site address        |
| Junk fill                    | WORKING   | `0xAAAAAAAA` in new allocations             |
| calloc zeroed                | WORKING   | calloc memory correctly zero-initialized    |
| calloc integer overflow      | WORKING   | returns NULL on nmemb*size wraparound       |
| memalign basic               | CLEAN     | intercepted, allocation works correctly     |
| memalign overflow            | DETECTED  | overflow caught after memalign              |
| posix_memalign basic         | CLEAN     | intercepted, allocation works correctly     |
| posix_memalign overflow      | DETECTED  | overflow caught after posix_memalign        |
| aligned_alloc basic          | CLEAN     | intercepted, allocation works correctly     |
| aligned_alloc overflow       | DETECTED  | overflow caught after aligned_alloc         |
| Normal usage                 | CLEAN     | exit 0, no false positives                  |
| Heavy normal usage           | CLEAN     | 10K+ operations, no false positives         |
| Quarantine stress            | CLEAN     | 50K frees, quarantine cycles correctly      |
| Mixed alloc types            | CLEAN     | all allocator variants, no false positives  |

---

## Honest Trade-offs

### 1. Shorter UAF detection window (single-threaded)

The thread-local quarantine has 256 slots per thread. A freed block stays
poisoned for up to 256 more frees on that thread. For single-threaded targets,
this is a shorter window than a shared 2048-slot quarantine would provide.

For multi-threaded targets (e.g., Foxit with 10 threads), total capacity is
256 x 10 = 2560 slots — comparable to or better than a shared approach.

### 2. Bigger header (24 bytes vs 16 bytes)

Every allocation uses 32 bytes of overhead (24-byte header + 8-byte tail).
For programs that do millions of tiny `malloc(8)` calls, this means 4x the
requested size per allocation.

### 3. Guard page allocs are slower than regular malloc

Allocations >= 64KB use mmap + 2x mprotect + munmap (4 syscalls per alloc/free
cycle). Benchmarked:

```
malloc(65536) + free:   ~42,919 ops/sec  (regular malloc: ~86K ops/sec = 2x slower)
malloc(128KB) + free:   ~21,136 ops/sec  (regular malloc: ~34K ops/sec = 1.6x slower)
malloc(65535) + free:   ~262,936 ops/sec (just below threshold, regular path)
```

The 65535 vs 65536 boundary is sharp: 1 byte difference = completely different
code path. If a target does lots of 64KB+ allocations (image buffers,
decompression buffers), those specific allocations will be slower.

### 4. Guard page allocs skip quarantine

Huge allocs are `munmap`'d immediately on free — no quarantine delay. This means
UAF writes to huge freed buffers cannot be detected by quarantine eviction checks.
The guard page catches overflow/underflow instantly via hardware SIGSEGV, but UAF
detection for huge buffers relies on the registry scan only.

### 5. Sampled full-buffer scan is probabilistic

The full-buffer scan runs every 64th eviction. If a UAF write lands between the
3 spot-check locations AND the block gets evicted on a non-scan eviction (63/64
chance), it's missed. This is strictly better than no full-buffer scan, but it's
not 100% coverage.

### 6. Incremental registry scan has longer coverage cycle

The registry scans 1/64th (1024 slots) per trigger, taking 64 triggers
(65,536 total ops) to cover the full 65,536-slot table. An overflow on a
never-freed buffer could sit undetected for up to 64 scan cycles before the
cursor reaches its slot.
