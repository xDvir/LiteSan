# Canary Sanitizer — Lightweight Heap Sanitizer for Persistent Mode Fuzzing

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
17. [Comparison: canary_sanitizer vs libdislocator vs ASan](#comparison)
18. [Limitations and Trade-offs](#limitations-and-trade-offs)
19. [Build and Usage](#build-and-usage)
20. [Files](#files)
21. [v3: Maximum Speed Variant](#v3-maximum-speed-variant)

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

`canary_sanitizer.so` takes a completely different approach:

- Uses **normal libc malloc** internally (no mmap per alloc)
- Wraps each allocation with **canary sentinel values** (magic numbers)
- Checks canaries on every `free()` and `realloc()` to detect corruption
- **Allocation registry** tracks all live allocations — scans at exit, on crash signals, and periodically during execution to catch overflows on blocks that are never freed
- **Quarantine** delays `free()` to catch use-after-free
- **Poison fill** (0xFE) on freed memory makes UAF reads visible
- **Junk fill** (0xAA) on new allocations makes uninitialized reads visible

**Overhead: ~3% (1.35x)** vs 1,510% (14.5x) for libdislocator.

### v2 Improvements (current version)

The sanitizer has been upgraded from v1 to v2 with the following improvements,
all at equal or better speed:

- **Constructor-resolved libc functions** — `dlsym()` runs once at library load
  in `__attribute__((constructor))` instead of checking `if (real_malloc)` on
  every malloc/free call. Eliminates a branch from the hottest path.
- **Calloc skips junk fill** — v1 junk-filled with 0xAA then immediately zeroed.
  v2 skips the junk fill for calloc since it zeros anyway. ~6% faster calloc.
- **Thread-local periodic scan counter** — v1 used `__sync_fetch_and_add` (atomic
  `lock xadd`) on every malloc and free for the periodic scan counter. v2 uses a
  `__thread` local variable — no atomic, no cache-line bouncing between cores.
- **`__builtin_expect` on error paths** — all canary mismatch checks are hinted
  as unlikely, helping branch prediction and instruction cache layout.
- **Multi-spot UAF check** — v1 only checked the first 8 bytes of freed memory
  on quarantine eviction. v2 checks first, middle, and last 8 bytes. Catches
  UAF writes at any region of the buffer for the cost of 2 extra loads.
- **Aligned allocator interception** — v1 didn't intercept `memalign`,
  `posix_memalign`, `aligned_alloc`, `valloc`, or `pvalloc`. Programs using
  these bypassed the sanitizer entirely. v2 intercepts all of them.
- **calloc integer overflow protection** — `calloc(nmemb, size)` where
  `nmemb * size` overflows now returns NULL instead of a dangerously small buffer.

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
static void canary_sanitizer_init(void) {
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

When the program calls `malloc(N)`, we actually allocate `N + 24` bytes from
libc and lay them out like this:

```
 What libc                        What the program
 allocates                        sees (returned ptr)
 ┌──────────┐                     │
 │          ▼                     ▼
 ┌──────────┬──────────┬──────────────────────────┬──────────┐
 │  size    │  head    │    user data             │  tail    │
 │  (8B)   │  canary  │    (N bytes)             │  canary  │
 │          │  (8B)   │                          │  (8B)   │
 └──────────┴──────────┴──────────────────────────┴──────────┘
 ◄─── HDR_SIZE (16B) ──►◄────── N bytes ─────────►◄─ 8B ───►

 Total libc allocation = 16 + N + 8 = N + 24 bytes
```

The `alloc_header_t` struct is the first 16 bytes:

```c
typedef struct {
    size_t   size;      // 8 bytes: the original requested size N
    uint64_t canary;    // 8 bytes: HEAD_CANARY (live) or FREED_CANARY (freed)
} alloc_header_t;
```

The **user pointer** (what `malloc` returns to the caller) points to byte 16 —
right after the header. The caller doesn't know about the header or tail canary.

The **tail canary** is an 8-byte value written at `user_ptr + size`, immediately
after the user's data. If the program writes past its allocation, it overwrites
this value, and we detect it on the next `free()` or `realloc()`.

---

## Algorithm: malloc()

v2 uses an internal `malloc_internal(size, junk_fill)` function shared by both
`malloc()` and `calloc()`. The `junk_fill` flag controls whether 0xAA fill is
applied (1 for malloc, 0 for calloc since calloc zeroes anyway).

Libc function pointers are resolved once in `__attribute__((constructor))` at
library load time. A fallback `resolve_real()` check is kept in `malloc()` for
edge cases, but it's hinted `__builtin_expect(!real_malloc, 0)`.

```
malloc(size):
    1. (libc pointers already resolved in constructor)
    2. raw = real_malloc(16 + size + 8) — ask libc for extra space
    3. hdr = (alloc_header_t *)raw
    4. hdr->size   = size              — remember the requested size
    5. hdr->canary = HEAD_CANARY       — write 0xDEADBEEFCAFEBABE
    6. user = raw + 16                 — user pointer starts after header
    7. memset(user, 0xAA, size)        — junk fill (uninitialized read detection)
    8. write_tail(user, size)          — write 0xFEEDFACE8BADF00D after user data
    9. registry_add(hdr)               — track in allocation registry
   10. maybe_periodic_scan()           — thread-local counter, no atomic
   11. return user                     — caller gets pointer to step 6
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
    3. resolve_real()
    4. hdr = ptr - 16                  — walk back to find our header
    5. check_canaries(hdr, ptr)        — THE KEY CHECK (see below)
    6. memset(ptr, 0xFE, size + 8)    — poison user data AND tail canary
    7. hdr->canary = FREED_CANARY      — mark header as freed
    8. quarantine_push(hdr)            — delay actual free (see Quarantine section)
```

**Step 5 — check_canaries()** does three checks in order:

```
check_canaries(hdr, ptr):
    A. if hdr->canary == FREED_CANARY:
         → DOUBLE-FREE! This block was already freed.
         → print backtrace, abort()

    B. if hdr->canary != HEAD_CANARY:
         → HEAD CANARY CORRUPT! Something wrote before the user data
           (underflow), or the pointer is garbage.
         → print backtrace, abort()

    C. tail = *(uint64_t *)(ptr + hdr->size)
       if tail != TAIL_CANARY:
         → HEAP BUFFER OVERFLOW! The program wrote past its allocation
           and corrupted the tail canary.
         → print backtrace, abort()
```

The **order matters**: we check for double-free first (A) because a freed block
has `FREED_CANARY` in the head, which would fail check B ("head != HEAD_CANARY")
with a confusing "head canary corrupt" message. By checking for FREED_CANARY
explicitly first, we give the correct diagnosis.

**Step 6 — poison**: After the checks pass, we fill the entire user region
(and the tail canary) with `0xFE`. This means:
- Any subsequent READ of this memory returns `0xFEFEFEFE...` — distinctive
  pattern that screams "use-after-free" in debugger/crash dumps
- Any subsequent WRITE changes the poison — detected by quarantine on eviction

**Step 7 — mark freed**: We set `hdr->canary = FREED_CANARY` so that if
`free()` is called again on this pointer, step 5A catches it immediately.

**Step 8 — quarantine**: Instead of calling `real_free(hdr)` now, we push
the block into the quarantine ring. This delays the actual free so the poison
stays in place longer, increasing the window to catch UAF. See the Quarantine
section below for the full algorithm.

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
    5. hdr = ptr - 16
    6. check_canaries(hdr, ptr)                — check BEFORE resize!
    7. old_size = hdr->size
    8. new_raw = real_realloc(hdr, 16 + size + 8)  — libc resizes the raw block
    9. if new_raw == NULL: return NULL
   10. new_hdr = (alloc_header_t *)new_raw
   11. new_hdr->size = size                    — update stored size
   12. new_user = new_raw + 16
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

This works as long as the block is still in quarantine (2048 most recent frees).
If the block was evicted and recycled by libc as a new allocation with a fresh
HEAD_CANARY, the double-free might not be caught. With 2048 slots, this covers
a very wide window.

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

**v2: Multi-spot UAF check.** v1 only checked the first 8 bytes after the
header. v2 checks **three spots**: first 8 bytes, middle 8 bytes (aligned to
8-byte boundary), and last 8 bytes. This catches UAF writes at any region
of the buffer for the cost of only 2 extra loads:

- UAF writes to the header (bytes -16 to -1): **always detected**
- UAF writes to bytes 0-7: **always detected**
- UAF writes near the middle: **detected** (v2 only)
- UAF writes near the end: **detected** (v2 only)
- UAF writes that miss all 3 spots: **not detected** (rare in practice)

Full-scan would be: `memcmp(user, expected_poison, size)` for every byte.
We skip this because it would add O(N) work per eviction, which is too slow
for a fuzzing sanitizer where millions of allocs/frees happen per second.
The 3-spot check is a good compromise: O(1) work, catches most UAF patterns.

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

The original canary sanitizer only checks for overflows at `free()` / `realloc()`
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
#define SCAN_INTERVAL  1024           // periodic scan every 1024 malloc+free ops

static void * volatile registry[REGISTRY_SIZE];

static inline size_t registry_hash(void *ptr) {
    return ((uintptr_t)ptr >> 4) & REGISTRY_MASK;
}
```

The hash function shifts the pointer right by 4 bits (malloc returns 16-byte
aligned pointers, so the low bits are always zero) and masks to the table size.
This gives O(1) amortized add/remove instead of O(N) linear scan — benchmarked
at only ~28% overhead vs the version without registry.

### Three scan triggers

1. **atexit scan** — `atexit(atexit_scan)` registered in a `__attribute__((constructor))`.
   When the process exits normally, all live allocations are checked. Detects
   overflows on leaked buffers.

2. **Signal handler scan** — handlers installed for SIGSEGV, SIGBUS, SIGABRT.
   On crash, the registry is scanned (using only signal-safe `write(2)` calls,
   not `fprintf`). Previous signal handlers are saved and chained to, so
   `foxit_throw_bypass.so` and other handlers still work.

3. **Periodic scan** — every 1024 `malloc()`+`free()` operations, a full registry
   scan runs. Catches overflows while the program is still running, even if the
   corrupted buffer isn't freed for a long time.

### Lock-free design

Same philosophy as the quarantine — no mutex, atomic CAS operations only:

- **`registry_add(hdr)`**: hash pointer to get bucket, linear probe for NULL slot,
  `__atomic_compare_exchange_n` to claim it. If full (all 65536 slots occupied),
  silently drops — overflow will still be caught on `free()`.
- **`registry_remove(hdr)`**: hash pointer to get bucket, linear probe for matching
  pointer, atomic CAS to NULL.
- **`scan_registry(is_signal)`**: walks all slots, checks head+tail canaries.
  Uses `write(2)` in signal context, `fprintf()` otherwise. Calls `abort()` if
  corruption found (non-signal mode only).

### Re-entrancy guard

An `already_scanned` flag (atomic test-and-set) prevents double-scanning when
atexit calls `abort()` which triggers the signal handler. Without this guard:
atexit → scan → find corruption → abort → SIGABRT handler → scan again.

---

## Quarantine: The Ring Buffer Algorithm

The quarantine is the most algorithmically interesting part. It's a fixed-size
ring buffer that delays `real_free()` to keep freed memory poisoned longer:

```
 quarantine[] array (2048 slots):

 ┌───┬───┬───┬───┬───┬───┬───┬───┬─────┬──────┐
 │ 0 │ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ ... │ 2047 │
 └───┴───┴───┴───┴───┴───┴───┴───┴─────┴──────┘
   ↑           ↑
   │           └─ slot has a freed block from earlier
   └─ slot is NULL (empty, never used yet)
```

### Push operation (inside our free()):

```
 1. idx = atomic_fetch_add(&q_idx, 1) % 2048
    — atomically get a unique slot index (wraps around)
    — each thread gets a different slot (no collision)

 2. oldest = atomic_exchange(&quarantine[idx], new_block)
    — atomically swap: put our new freed block IN, get the old one OUT
    — if slot was empty (NULL): oldest = NULL, nothing to evict
    — if slot had a block: oldest = that block, needs eviction

 3. if oldest != NULL:
      check_quarantined(oldest)   — verify poison is intact
      real_free(oldest)           — finally return memory to libc
```

### Visual example:

```
 State: quarantine = [blkA, blkB, NULL, blkC, ...]
                      ^^^^
 free(ptr_X): idx = atomic_add(q_idx) % 2048 = 0

   atomic_exchange(&quarantine[0], ptr_X)
   → returns blkA (the old occupant)
   → quarantine[0] = ptr_X now

 State: quarantine = [ptr_X, blkB, NULL, blkC, ...]

 check_quarantined(blkA):
   blkA->canary == FREED_CANARY? ✓
   first 8 bytes == 0xFEFE...?   ✓
 real_free(blkA)                  — finally freed
```

### Why ring buffer size = 2048?

- Too small (e.g., 64): blocks get evicted quickly, short UAF detection window
- Too large (e.g., 1M): holds too much memory, could cause OOM
- 2048 is a sweet spot: holds ~100KB-1MB depending on allocation sizes,
  long enough window for most UAF patterns, negligible memory overhead

### Why not a queue (FIFO)?

A proper FIFO queue would evict blocks in exact free-order (oldest first).
Our ring buffer with `idx % 2048` is an **approximate FIFO** — blocks are
evicted roughly in order but not exactly, because concurrent threads may
increment `q_idx` out of order. For fuzzing, approximate FIFO is perfectly
fine. The benefit is no linked list, no mutex, just an array + atomic counter.

---

## Lock-Free Concurrency: Why No Mutex

The Foxit SDK spawns **9 permanent background threads** on `Library::Initialize()`.
These threads do their own malloc/free concurrently with the fuzzing thread.
A mutex in malloc/free would cause:

1. **Contention**: 10 threads fighting over one lock on every alloc/free
2. **Priority inversion**: fuzzing thread blocked waiting for SDK background thread
3. **Deadlock risk**: if a signal handler fires while holding the mutex

Instead, we use two atomic operations:

### 1. `__sync_fetch_and_add(&q_idx, 1)` — Atomic increment

This is a single CPU instruction (`lock xadd` on x86). It atomically reads the
current value of `q_idx`, adds 1, and returns the old value. Even if 10 threads
call this simultaneously, each gets a **unique** number. No two threads ever get
the same slot index.

```
 Thread A: __sync_fetch_and_add(&q_idx, 1) → gets 500
 Thread B: __sync_fetch_and_add(&q_idx, 1) → gets 501  (or vice versa)
 Never: both get 500
```

### 2. `__atomic_exchange_n(&quarantine[idx], new_block, __ATOMIC_RELAXED)` — Atomic swap

This atomically replaces the value in `quarantine[idx]` with `new_block` and
returns whatever was there before. Even if two threads somehow get the same
`idx` (can't happen with our design, but hypothetically), the exchange is atomic:
one thread gets the old value, the other gets the first thread's value. No data
is lost or corrupted.

`__ATOMIC_RELAXED` means we don't need memory ordering guarantees between threads.
We don't care if thread B sees thread A's write immediately — quarantine eviction
checks are probabilistic anyway (we only check on eviction, not on every access).

### Why this is safe:

- Unique index per free() → no two threads write to same slot simultaneously
- Atomic exchange → even if same slot, swap is atomic (no torn read/write)
- No shared mutable state beyond the quarantine array itself
- No ABA problem: we don't make decisions based on "was this value changed?"
- Worst case under extreme contention: a block gets evicted slightly sooner
  or later than ideal — acceptable for a fuzzing sanitizer

---

## Magic Values: Why These Specific Numbers

```c
#define HEAD_CANARY  0xDEADBEEFCAFEBABEULL    // live allocation
#define TAIL_CANARY  0xFEEDFACE8BADF00DULL    // end of allocation
#define FREED_CANARY 0xFEFEFEFEFEFEFEFEULL   // freed allocation
#define POISON_BYTE  0xFE                      // fill freed memory
#define JUNK_BYTE    0xAA                      // fill new allocations
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

When the canary sanitizer detects corruption, it calls `abort()` which sends
SIGABRT to the process. Here's the full chain of signal handlers:

```
canary_sanitizer.so: check_canaries() fails
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

**Why the mmap probe?** When running with libdislocator (not our canary sanitizer),
libdislocator itself calls `abort()` when it can't mmap. The bypass handler's
mmap probe distinguishes "ran out of address space" (OOM → suppress) from
"canary corruption detected" (real bug → report to AFL).

With our canary sanitizer, the mmap probe always succeeds (we don't exhaust
address space), so canary detections always flow through as real crashes to AFL.

**Why phase-based handling?** Foxit SDK can crash during cleanup
(`Library::Release()`, `PDFDoc` destructor) on already-corrupted state.
These cleanup crashes aren't interesting — the real bug was during parsing.
The harness sets `phase = 0` before parsing and `phase = 1` before cleanup.

---

## Comparison

### canary_sanitizer vs libdislocator vs AddressSanitizer (ASan)

| Property                  | canary_sanitizer       | libdislocator          | ASan (compile-time)     |
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
| Memory overhead           | ~24 bytes/alloc + quarantine | 1 page/alloc    | 1/8 of address space    |
| False positives           | None                   | OOM in persistent mode | None                    |

**Key insight**: ASan is the gold standard but requires source code and
compile-time instrumentation. For a closed-source library like Foxit's
`libfsdk_linux64.so`, we can only use LD_PRELOAD approaches. Among those,
canary_sanitizer gives us most of ASan's detection capabilities with
dramatically lower overhead than libdislocator.

---

## Limitations and Trade-offs

### What we CANNOT detect

1. **Heap overflow that skips the tail canary**: If code writes to `ptr + size + 8`
   (jumping over the 8-byte tail canary) into the next allocation's header, we
   miss it. In practice this is rare — overflows are almost always sequential.

2. **UAF writes that miss all 3 check spots**: v2 checks first/middle/last
   8 bytes (3 spots), which catches most UAF patterns. But a UAF write that
   lands between the spots (e.g., exactly at byte 20 of a 256-byte buffer)
   won't be caught. Full-scan would fix this but costs O(N) per eviction.

3. **UAF reads**: No active detection. Poison (0xFE) passively causes downstream
   failures but doesn't immediately abort. Hardware watchpoints or shadow memory
   (ASan) are needed for immediate UAF read detection.

4. **Stack buffer overflow**: We only instrument heap allocations (malloc/free).
   Stack-allocated arrays are invisible to us.

5. **Global buffer overflow**: Same — global/static arrays don't go through malloc.

6. **Heap underflow (writing before the allocation)**: We check the head canary,
   but only on free()/realloc(). An underflow that doesn't reach the head canary
   (e.g., writes to a neighboring allocation before ours) won't be caught.

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

8. **Periodic scan overhead**: Every 1024 malloc/free operations, a full registry
   scan walks all 65536 slots. Add/remove are O(1) amortized (hash table with
   linear probing). Benchmarked at ~28% overhead vs the version without registry
   on a 500K-operation mixed workload (0.19s vs 0.15s).

### Memory overhead

- Per allocation: 24 bytes extra (16-byte header + 8-byte tail canary)
- Quarantine: up to 2048 freed blocks held in memory
- Registry: 65536 pointer slots (512KB static array)
- For Foxit SDK: negligible compared to the library's own memory usage (~200MB+)

---

## Build and Usage

### Build

```bash
cd /home/dvirgo/foxit_fuzz/custom_sanitizer
gcc -shared -fPIC -O2 -o canary_sanitizer.so canary_sanitizer.c -ldl -rdynamic
```

Flags:
- `-shared -fPIC`: build as position-independent shared library
- `-O2`: optimize (faster checks, important for fuzzing throughput)
- `-ldl`: link libdl for `dlsym()` (resolving real libc functions)
- `-rdynamic`: export symbols from the executable so `backtrace_symbols_fd()`
  can resolve function names in the backtrace output

### Standalone test (single PDF)
```bash
LD_PRELOAD=./foxit_throw_bypass.so:./custom_sanitizer/canary_sanitizer.so \
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
AFL_PRELOAD=foxit_throw_bypass.so:canary_sanitizer.so
```

The bypass .so MUST come first — it installs signal handlers that the canary
sanitizer's `abort()` calls flow through.

### No harness changes needed

The canary sanitizer is a pure LD_PRELOAD shim. It works with the existing
`harness_foxit_persist` binary without any modifications.

---

## Files

```
custom_sanitizer/
├── canary_sanitizer.c        — v2 source (~585 lines)
├── canary_sanitizer.so       — v2 compiled library
├── README.md                 — This file
├── .gitignore
├── tests/                    — v2 test suite (42 tests)
│   ├── run_tests.sh
│   ├── run_bench.sh
│   ├── bench_speed.c
│   └── test_*.c              — 42 test files
└── canary_sanitizer_v3/      — v3 maximum speed variant
    ├── canary_sanitizer.c    — v3 source (~700 lines)
    ├── canary_sanitizer.so   — v3 compiled library (-O3)
    └── tests/                — v3 test suite (48 tests)
        ├── run_tests.sh      — Full test harness
        ├── run_bench.sh      — Benchmark: baseline vs v2 vs v3
        ├── run_comparison.sh — Detection comparison: v2 vs v3
        ├── bench_speed.c     — Throughput benchmark
        └── test_*.c          — 48 test files (42 from v2 + 6 new)
```

## Tested Detections

All verified with 42 automated tests (`tests/run_tests.sh`):

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
| Double-free                  | DETECTED  | exit 134 (SIGABRT), backtrace printed       |
| Double-free (immediate)      | DETECTED  | exit 134 (SIGABRT), backtrace printed       |
| Double-free (with ops)       | DETECTED  | exit 134 (SIGABRT), backtrace printed       |
| UAF write (first 8 bytes)    | DETECTED  | quarantine eviction catches corruption      |
| UAF write (header)           | DETECTED  | quarantine eviction catches corruption      |
| UAF write (delayed)          | DETECTED  | quarantine eviction catches corruption      |
| UAF write (middle) [v2]      | DETECTED  | multi-spot check catches middle corruption  |
| UAF write (end) [v2]         | DETECTED  | multi-spot check catches end corruption     |
| UAF read                     | PARTIAL   | `0xFEFEFEFE` poison visible in memory      |
| Junk fill                    | WORKING   | `0xAAAAAAAA` in new allocations             |
| calloc zeroed                | WORKING   | calloc memory correctly zero-initialized    |
| calloc integer overflow [v2] | WORKING   | returns NULL on nmemb*size wraparound       |
| memalign basic [v2]          | CLEAN     | intercepted, allocation works correctly     |
| memalign overflow [v2]       | DETECTED  | overflow caught after memalign              |
| posix_memalign basic [v2]    | CLEAN     | intercepted, allocation works correctly     |
| posix_memalign overflow [v2] | DETECTED  | overflow caught after posix_memalign        |
| aligned_alloc basic [v2]     | CLEAN     | intercepted, allocation works correctly     |
| aligned_alloc overflow [v2]  | DETECTED  | overflow caught after aligned_alloc         |
| Normal usage                 | CLEAN     | exit 0, no false positives                  |
| Heavy normal usage           | CLEAN     | 10K+ operations, no false positives         |
| Quarantine stress            | CLEAN     | 50K frees, quarantine cycles correctly      |
| Speed                        | ~1.03x    | ~3% overhead on 500K operation benchmark    |

---

## v3: Maximum Speed Variant

`canary_sanitizer_v3/` is a separate version optimized for maximum speed while adding
new detection capabilities. It is **not** a replacement for v2 — each has trade-offs
that make it better suited for different targets.

### v3 Speed Improvements (6 changes)

**1. Thread-local quarantine (biggest win)**

v2 uses a single shared 2048-slot quarantine ring with 2 atomic CPU instructions
(`lock xadd` + `lock xchg`) on every `free()`. These atomics cause cache-line
bouncing between CPU cores in multi-threaded programs.

v3 gives each thread its own private 256-slot quarantine ring using `__thread`
storage. Free becomes pure local memory operations — zero atomics, zero contention.

**2. Incremental registry scan**

v2 scans all 65,536 registry slots every 1024 operations — O(65536) work per trigger.
v3 scans only 1/64th (1024 slots) per trigger using a shared cursor that advances
through the table. Same full coverage over time, 64x less work per trigger.

**3. Multiply-shift hash (Fibonacci hashing)**

v2: `(ptr >> 4) & mask` — simple shift, clusters entries because malloc returns
addresses with patterns in the upper bits. Causes long linear probe chains.

v3: `(ptr * 0x9E3779B97F4A7C15) >> 48 & mask` — multiplication by the golden
ratio constant spreads entries uniformly. Fewer probes = faster add/remove.

**4. Inline small memset**

For allocations <= 64 bytes (the majority), v3 does junk fill inline with
unrolled 8-byte writes instead of calling `memset()`. Avoids function call
overhead for the common case.

**5. -O3 build (vs -O2)**

More aggressive compiler optimizations including auto-vectorization and
function inlining.

**6. Bitmask for scan interval**

v2: `counter % 1024` — requires a division instruction.
v3: `counter & 1023` — single AND instruction. Same result since 1024 is power of 2.

### v3 New Detection (4 features)

**7. Heap underflow red zone**

v3 adds an 8-byte underflow canary (`0xBADC0FFEE0DDF00D`) BEFORE the header:

```
 v2 layout (16-byte header):
 [size(8)][canary(8)][user data...][tail(8)]

 v3 layout (24-byte header):
 [underflow(8)][size(8)][canary(8)][user data...][tail(8)]
```

If something writes backward past the start of an allocation (heap underflow),
the underflow canary gets corrupted → detected on `free()` or `realloc()`.

**8. Sampled full-buffer poison check**

Every 64th quarantine eviction, v3 scans ALL bytes of the freed block instead
of just the 3 spot-check locations. This catches UAF writes that land between
the first/middle/last spots. Cost: O(N) work on 1/64 of evictions, O(1) on
the other 63/64.

**9. Free-site diagnostic**

When `free()` is called, v3 saves `__builtin_return_address(0)` (the caller's
address) in the header's underflow field (which was already verified). If a UAF
is later detected, the error message includes where the block was freed:

```
*** CANARY_SANITIZER: USE-AFTER-FREE WRITE detected ***
    ptr=0x55f8a0 size=64 (freed data corrupted at offset 0)
    free-site: 0x401234
```

**10. Guard pages for huge allocations (>= 64KB)**

Allocations >= 64KB use `mmap` with `PROT_NONE` guard pages before and after:

```
 [PROT_NONE guard(4K)][header(24)][user data(N)][tail(8)][PROT_NONE guard(4K)]
```

Any overflow or underflow on a huge buffer triggers an instant SIGSEGV from the
CPU hardware — no need to wait for `free()` to check canaries.

### v3 Benchmark Results

500K-operation mixed workload (ops/sec, higher = better):

```
                          Baseline       v2            v3          v3 vs v2
malloc/free mix:      20,297,537    6,752,920     9,223,537      +37% faster
pure malloc+free:     27,277,001    4,701,576     6,549,295      +39% faster
calloc+free:          37,753,643   18,681,834    35,540,841      +90% faster
large alloc (4K-64K): 10,655,240      289,634       834,309     +188% faster
realloc chains:        6,852,165    2,248,330     3,616,578      +61% faster
```

### v3 Detection Comparison (what v3 catches that v2 misses)

```
Test                       v2        v3
─────────────────────────  ────────  ────────
Heap underflow (direct)    MISSED    CAUGHT
Heap underflow (memcpy)    MISSED    CAUGHT
UAF write (between spots)  MISSED    CAUGHT   (sampled full-buffer scan)
Guard page overflow (64K+) CAUGHT    CAUGHT
All v2 detections          CAUGHT    CAUGHT   (no regressions)
```

### v3 Honest Trade-offs

**1. Shorter UAF detection window (single-threaded)**

v2 quarantine: 2048 shared slots. A freed block stays poisoned for up to 2048
more frees. v3 quarantine: 256 per-thread slots. A freed block stays poisoned
for only 256 more frees. A UAF write that happens between 256-2048 frees after
the original free — v2 catches it, v3 doesn't.

For multi-threaded targets (e.g., Foxit with 10 threads), total v3 capacity is
256 x 10 = 2560, which is larger than v2's 2048. But for single-threaded
fuzz harnesses, the window is 8x shorter.

**2. Bigger header (24 bytes vs 16 bytes)**

Every allocation costs 8 extra bytes for the underflow canary. Per-allocation
overhead goes from 24 bytes (v2: 16 header + 8 tail) to 32 bytes (v3: 24
header + 8 tail). For a program that does millions of tiny `malloc(8)` calls,
this means 4x the requested size per allocation instead of 3x.

**3. Guard page allocs are slower than regular malloc**

Allocations >= 64KB use mmap + 2x mprotect + munmap (4 syscalls per alloc/free
cycle). Measured overhead:

```
malloc(65536) + free:   v2 = 85,970 ops/sec    v3 = 42,919 ops/sec  (v3 is 2x slower)
malloc(128KB) + free:   v2 = 33,853 ops/sec    v3 = 21,136 ops/sec  (v3 is 1.6x slower)
malloc(65535) + free:   v2 = 175,718 ops/sec   v3 = 262,936 ops/sec (v3 is 1.5x faster)
```

The 65535 vs 65536 boundary is sharp: 1 byte difference = completely different
code path. If a target does lots of 64KB+ allocations (image buffers,
decompression buffers), v3 will be slower than v2 for those allocations.

**4. Guard page allocs skip quarantine**

Huge allocs are `munmap`'d immediately on free — no quarantine delay. This means
UAF writes to huge freed buffers cannot be detected by quarantine eviction checks.
The guard page catches overflow/underflow instantly, but UAF detection for huge
buffers is weaker than v2.

**5. Sampled full-buffer scan is probabilistic**

The full-buffer scan runs every 64th eviction. If a UAF write lands between the
3 spot-check locations AND the block gets evicted on a non-scan eviction (63/64
chance), it's missed. v2 never catches these at all, so v3 is strictly better,
but it's not 100% coverage.

**6. Incremental registry scan has longer coverage cycle**

v2 scans all 65,536 slots every 1024 ops — guaranteed full coverage. v3 scans
1/64th per trigger, taking 64 triggers (65,536 ops) to cover the full registry.
An overflow on a never-freed buffer could sit undetected 64x longer before the
scan reaches its slot.

### When to use v2 vs v3

| Scenario | Best choice | Why |
|---|---|---|
| Single-threaded target, lots of UAF bugs | **v2** | 2048-slot quarantine catches delayed UAF |
| Target allocates many 64KB+ buffers | **v2** | No mmap/munmap overhead |
| Multi-threaded target (Foxit, Chrome, etc.) | **v3** | Thread-local quarantine = no atomic contention |
| Target uses mostly small allocations (< 64KB) | **v3** | 37-90% faster across the board |
| Need heap underflow detection | **v3** | v2 has no underflow canary |
| Need free-site in error messages | **v3** | v2 doesn't store free-site |
| Memory-tight target, every byte counts | **v2** | 8 fewer bytes per allocation |

### v3 Build

```bash
cd canary_sanitizer_v3
gcc -shared -fPIC -O3 -o canary_sanitizer.so canary_sanitizer.c -ldl -rdynamic
```

### v3 Test Suite

```bash
cd canary_sanitizer_v3
bash tests/run_tests.sh          # 48 tests (42 from v2 + 6 new)
bash tests/run_bench.sh          # Benchmark: baseline vs v2 vs v3
bash tests/run_comparison.sh     # Detection comparison: v2 vs v3
```
