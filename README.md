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
    if (real_malloc) return;          // already resolved, skip
    resolving = 1;                    // flag: we're inside dlsym
    real_malloc  = dlsym(RTLD_NEXT, "malloc");
    real_free    = dlsym(RTLD_NEXT, "free");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_calloc  = dlsym(RTLD_NEXT, "calloc");
    resolving = 0;
}
```

Every one of our override functions calls `resolve_real()` first. The
`if (real_malloc) return` check means dlsym only runs once (first call).

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

```
malloc(size):
    1. resolve_real()                  — ensure we have libc function pointers
    2. raw = real_malloc(16 + size + 8) — ask libc for extra space
    3. hdr = (alloc_header_t *)raw
    4. hdr->size   = size              — remember the requested size
    5. hdr->canary = HEAD_CANARY       — write 0xDEADBEEFCAFEBABE
    6. user = raw + 16                 — user pointer starts after header
    7. memset(user, 0xAA, size)        — junk fill (uninitialized read detection)
    8. write_tail(user, size)          — write 0xFEEDFACE8BADF00D after user data
    9. return user                     — caller gets pointer to step 6
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
    1. if resolving or !real_malloc:           — inside dlsym bootstrap
         total = nmemb * size
         p = bootstrap_buf + bootstrap_used    — bump allocate
         bootstrap_used += total
         memset(p, 0, total)                   — calloc zeroes memory
         return p
    2. resolve_real()
    3. total = nmemb * size
    4. ptr = malloc(total)                     — goes through OUR malloc (gets canaries)
    5. memset(ptr, 0, total)                   — override junk fill with zeros
    6. return ptr
```

Note step 5: our `malloc()` fills with `0xAA` (junk), but `calloc()` is
defined to return zero-initialized memory. So we override the junk with zeros.
This means `calloc()` memory does NOT get uninitialized-read detection, but
that's correct — the memory IS initialized (to zero).

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
   ptr[0..7] is now 0x4141414141414141 instead of 0xFEFEFEFEFEFEFEFE

 ... later, quarantine[slot] is evicted by another free() ...
   check_quarantined(hdr):
     hdr->canary == FREED_CANARY? YES (header wasn't touched)
     first 8 bytes == 0xFEFEFEFEFEFEFEFE? NO → got 0x4141414141414141
     → USE-AFTER-FREE WRITE detected → backtrace + abort()
```

The quarantine check only inspects 2 things: the header canary and the first
8 bytes of user data. It's a **spot check**, not a full scan. This means:
- UAF writes to bytes 0-7: **always detected**
- UAF writes to the header (bytes -16 to -1): **always detected**
- UAF writes to bytes 8+: **NOT detected** (only first 8 bytes are checked)

Full-scan would be: `memcmp(user, expected_poison, size)` for every byte.
We skip this because it would add O(N) work per eviction, which is too slow
for a fuzzing sanitizer where millions of allocs/frees happen per second.

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
We don't currently check for integer overflow in `nmemb * size`. This matches
the simplicity goal — in practice, Foxit SDK doesn't call calloc with sizes
that overflow, and libc's own malloc would fail on absurd sizes anyway.

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

2. **UAF writes beyond first 8 bytes**: Quarantine only spot-checks bytes 0-7.
   A UAF write to byte 100 of a freed block won't be caught. Full-scan would
   fix this but costs O(N) per eviction.

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
├── canary_sanitizer.c    — Source code (~280 lines)
├── canary_sanitizer.so   — Compiled shared library
└── README.md             — This file

scripts/
├── run_fuzz_canary_test.sh   — 1 instance (testing)
└── run_fuzz_10_canary.sh     — 10 parallel instances (production)
```

## Tested Detections

All verified with test programs + the Foxit harness:

| Test               | Result    | Details                                  |
|--------------------|-----------|------------------------------------------|
| Heap buffer overflow | DETECTED | exit 134 (SIGABRT), backtrace printed   |
| Overflow w/o free  | DETECTED  | atexit registry scan catches corruption  |
| Double-free        | DETECTED  | exit 134 (SIGABRT), backtrace printed    |
| UAF read           | PARTIAL   | `0xFEFEFEFE` poison visible in memory   |
| Junk fill          | WORKING   | `0xAAAAAAAA` in new allocations          |
| Leak (no corrupt)  | CLEAN     | atexit scan finds no corruption          |
| Normal PDF         | CLEAN     | exit 0, no false positives               |
| Speed              | ~1.35x    | 0.112s vs 0.083s bare on single PDF      |
