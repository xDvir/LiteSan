#!/usr/bin/env bash
#
# run_tests.sh — Comprehensive test suite for litesan
#
# Builds all tests, runs them with the sanitizer, checks results.
# Tests are either CRASH (expected abort, exit 134) or CLEAN (expected exit 0).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SANITIZER="$SCRIPT_DIR/../litesan.so"
BUILD_DIR="$SCRIPT_DIR/build"

# Colors
RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[0;33m'
CYN='\033[0;36m'
RST='\033[0m'

pass=0
fail=0
skip=0

mkdir -p "$BUILD_DIR"

# Check sanitizer exists
if [ ! -f "$SANITIZER" ]; then
    echo -e "${RED}ERROR: $SANITIZER not found. Build it first:${RST}"
    echo "  gcc -shared -fPIC -O2 -o litesan.so litesan.c -ldl -rdynamic"
    exit 1
fi

run_test() {
    local src="$1"
    local expect="$2"       # CRASH or CLEAN
    local env_vars="${3:-}"  # optional env vars like "CANARY_NO_JUNK=1"
    local check_msg="${4:-}" # optional: check stderr contains this string

    local name
    name=$(basename "$src" .c)
    local bin="$BUILD_DIR/$name"

    # Build
    if ! gcc -O0 -g -o "$bin" "$src" 2>/dev/null; then
        printf "  ${YEL}SKIP${RST}  %-45s (compile failed)\n" "$name"
        ((skip++)) || true
        return
    fi

    # Run
    local stderr_file
    stderr_file=$(mktemp)
    local exit_code=0
    if [ -n "$env_vars" ]; then
        env $env_vars LD_PRELOAD="$SANITIZER" "$bin" >"$stderr_file" 2>&1 || exit_code=$?
    else
        LD_PRELOAD="$SANITIZER" "$bin" >"$stderr_file" 2>&1 || exit_code=$?
    fi

    local result=""
    local detail=""

    if [ "$expect" = "CRASH" ]; then
        if [ "$exit_code" -eq 134 ]; then
            # Verify it's our sanitizer, not a random crash
            if grep -q "LITESAN" "$stderr_file"; then
                result="PASS"
                # Check for specific message if requested
                if [ -n "$check_msg" ]; then
                    if grep -q "$check_msg" "$stderr_file"; then
                        result="PASS"
                    else
                        result="FAIL"
                        detail="(missing: '$check_msg')"
                    fi
                fi
            else
                result="FAIL"
                detail="(crashed but not by sanitizer)"
            fi
        else
            result="FAIL"
            detail="(expected exit 134, got $exit_code)"
        fi
    elif [ "$expect" = "CLEAN" ]; then
        if [ "$exit_code" -eq 0 ]; then
            result="PASS"
            # Check for specific message if requested
            if [ -n "$check_msg" ]; then
                if grep -q "$check_msg" "$stderr_file"; then
                    result="PASS"
                else
                    result="FAIL"
                    detail="(missing: '$check_msg')"
                fi
            fi
        else
            result="FAIL"
            detail="(expected exit 0, got $exit_code)"
            # Show sanitizer output for debugging
            if grep -q "LITESAN" "$stderr_file"; then
                detail="$detail — FALSE POSITIVE"
            fi
        fi
    fi

    if [ "$result" = "PASS" ]; then
        printf "  ${GRN}PASS${RST}  %-45s [%s]\n" "$name" "$expect"
        ((pass++)) || true
    else
        printf "  ${RED}FAIL${RST}  %-45s [%s] %s\n" "$name" "$expect" "$detail"
        # Show first few lines of stderr for debugging
        head -5 "$stderr_file" | sed 's/^/        /'
        ((fail++)) || true
    fi

    rm -f "$stderr_file"
}

echo ""
echo -e "${CYN}╔══════════════════════════════════════════════════════════════╗${RST}"
echo -e "${CYN}║          LiteSan — Test Suite                      ║${RST}"
echo -e "${CYN}╚══════════════════════════════════════════════════════════════╝${RST}"
echo ""

# ─── Buffer Overflow Tests ────────────────────────────────────────────
echo -e "${CYN}── Buffer Overflow Detection ──${RST}"
run_test "$SCRIPT_DIR/test_overflow_1byte.c"              CRASH "" "HEAP BUFFER OVERFLOW"
run_test "$SCRIPT_DIR/test_overflow_8byte.c"              CRASH "" "HEAP BUFFER OVERFLOW"
run_test "$SCRIPT_DIR/test_overflow_large.c"              CRASH "" "HEAP BUFFER OVERFLOW"
run_test "$SCRIPT_DIR/test_overflow_tiny.c"               CRASH "" "HEAP BUFFER OVERFLOW"
run_test "$SCRIPT_DIR/test_overflow_strcpy.c"             CRASH "" "HEAP BUFFER OVERFLOW"
run_test "$SCRIPT_DIR/test_overflow_memcpy.c"             CRASH "" "HEAP BUFFER OVERFLOW"
run_test "$SCRIPT_DIR/test_overflow_loop.c"               CRASH "" "HEAP BUFFER OVERFLOW"
run_test "$SCRIPT_DIR/test_overflow_no_free.c"            CRASH "" "HEAP BUFFER OVERFLOW"
run_test "$SCRIPT_DIR/test_overflow_realloc.c"            CRASH "" "HEAP BUFFER OVERFLOW"
run_test "$SCRIPT_DIR/test_realloc_overflow_after_grow.c" CRASH "" "HEAP BUFFER OVERFLOW"
run_test "$SCRIPT_DIR/test_large_alloc_overflow.c"        CRASH "" "HEAP BUFFER OVERFLOW"
run_test "$SCRIPT_DIR/test_calloc_overflow.c"             CRASH "" "HEAP BUFFER OVERFLOW"
run_test "$SCRIPT_DIR/test_overflow_zero_alloc.c"         CRASH "" "HEAP BUFFER OVERFLOW"
echo ""

# ─── Double-Free Tests ────────────────────────────────────────────────
echo -e "${CYN}── Double-Free Detection ──${RST}"
run_test "$SCRIPT_DIR/test_double_free.c"                 CRASH "" "DOUBLE-FREE"
run_test "$SCRIPT_DIR/test_double_free_immediate.c"       CRASH "" "DOUBLE-FREE"
run_test "$SCRIPT_DIR/test_double_free_with_ops.c"        CRASH "" "DOUBLE-FREE"
echo ""

# ─── Use-After-Free Tests ────────────────────────────────────────────
echo -e "${CYN}── Use-After-Free Detection ──${RST}"
run_test "$SCRIPT_DIR/test_uaf_write_first8.c"            CRASH "" "USE-AFTER-FREE"
run_test "$SCRIPT_DIR/test_uaf_write_header.c"            CRASH "" "USE-AFTER-FREE"
run_test "$SCRIPT_DIR/test_uaf_write_delayed.c"           CRASH "" "USE-AFTER-FREE"
run_test "$SCRIPT_DIR/test_uaf_read_poison.c"             CLEAN "" "read poison"
echo ""

# ─── v2: Multi-Spot UAF Detection ──────────────────────────────────
echo -e "${CYN}── Multi-Spot UAF Detection ──${RST}"
run_test "$SCRIPT_DIR/test_uaf_write_middle.c"            CRASH "" "USE-AFTER-FREE"
run_test "$SCRIPT_DIR/test_uaf_write_end.c"               CRASH "" "USE-AFTER-FREE"
echo ""

# ─── v2: Aligned Allocator Interception ────────────────────────
echo -e "${CYN}── Aligned Allocator Interception ──${RST}"
run_test "$SCRIPT_DIR/test_memalign_basic.c"              CLEAN
run_test "$SCRIPT_DIR/test_memalign_overflow.c"           CRASH "" "HEAP BUFFER OVERFLOW"
run_test "$SCRIPT_DIR/test_posix_memalign_basic.c"        CLEAN
run_test "$SCRIPT_DIR/test_posix_memalign_overflow.c"     CRASH "" "HEAP BUFFER OVERFLOW"
run_test "$SCRIPT_DIR/test_aligned_alloc_basic.c"         CLEAN
run_test "$SCRIPT_DIR/test_aligned_alloc_overflow.c"      CRASH "" "HEAP BUFFER OVERFLOW"
echo ""

# ─── Junk Fill Tests ─────────────────────────────────────────────────
echo -e "${CYN}── Junk Fill & Calloc ──${RST}"
run_test "$SCRIPT_DIR/test_junk_fill.c"                   CLEAN "" "all bytes are 0xAA"
run_test "$SCRIPT_DIR/test_junk_fill_realloc_grow.c"      CLEAN "" "realloc growth junk fill correct"
run_test "$SCRIPT_DIR/test_calloc_zeroed.c"               CLEAN "" "calloc memory is zeroed"
echo ""

# ─── v2: calloc overflow protection ───────────────────────────────────
echo -e "${CYN}── Calloc Overflow Protection ──${RST}"
run_test "$SCRIPT_DIR/test_calloc_int_overflow.c"         CLEAN "" "calloc returned NULL"
echo ""

# ─── Correctness Tests (no false positives) ──────────────────────────
echo -e "${CYN}── Correctness (no false positives) ──${RST}"
run_test "$SCRIPT_DIR/test_normal_usage.c"                CLEAN
run_test "$SCRIPT_DIR/test_normal_heavy.c"                CLEAN
run_test "$SCRIPT_DIR/test_normal_realloc_many.c"         CLEAN
run_test "$SCRIPT_DIR/test_realloc_null.c"                CLEAN
run_test "$SCRIPT_DIR/test_realloc_zero.c"                CLEAN
run_test "$SCRIPT_DIR/test_realloc_shrink.c"              CLEAN
run_test "$SCRIPT_DIR/test_free_null.c"                   CLEAN
run_test "$SCRIPT_DIR/test_quarantine_eviction_clean.c"   CLEAN
run_test "$SCRIPT_DIR/test_quarantine_stress.c"           CLEAN
run_test "$SCRIPT_DIR/test_mixed_alloc_types.c"           CLEAN
echo ""

# ─── v3: Heap Underflow Detection ────────────────────────────────────
echo -e "${CYN}── Heap Underflow Detection ──${RST}"
run_test "$SCRIPT_DIR/test_underflow_basic.c"             CRASH "" "HEAP UNDERFLOW"
run_test "$SCRIPT_DIR/test_underflow_memcpy.c"            CRASH "" "HEAP UNDERFLOW"
echo ""

# ─── v3: Guard Page Detection ────────────────────────────────────────
echo -e "${CYN}── Guard Page Detection ──${RST}"
run_test "$SCRIPT_DIR/test_guard_page_basic.c"            CLEAN
run_test "$SCRIPT_DIR/test_guard_page_overflow.c"         CRASH
echo ""

# ─── v3: Sampled Full-Buffer Check ───────────────────────────────────
echo -e "${CYN}── Sampled Full-Buffer Check ──${RST}"
run_test "$SCRIPT_DIR/test_uaf_full_scan.c"               CRASH "" "USE-AFTER-FREE"
echo ""

# ─── v3: Free-Site Diagnostics ───────────────────────────────────────
echo -e "${CYN}── Free-Site Diagnostics ──${RST}"
run_test "$SCRIPT_DIR/test_free_site_reported.c"          CRASH "" "free-site"
echo ""

# ─── Summary ─────────────────────────────────────────────────────────
echo -e "${CYN}══════════════════════════════════════════════════════════════${RST}"
total=$((pass + fail + skip))
echo -e "  Total: $total  ${GRN}Pass: $pass${RST}  ${RED}Fail: $fail${RST}  ${YEL}Skip: $skip${RST}"
echo -e "${CYN}══════════════════════════════════════════════════════════════${RST}"
echo ""

if [ "$fail" -gt 0 ]; then
    echo -e "${RED}SOME TESTS FAILED${RST}"
    exit 1
else
    echo -e "${GRN}ALL TESTS PASSED${RST}"
    exit 0
fi
