#!/bin/bash
#
# =============================================================================
# Canary Sanitizer — Comprehensive Test Suite
# =============================================================================
#
# Compiles and runs all test_*.c files against canary_sanitizer.so.
# Each test expects either:
#   EXPECT_CRASH  — sanitizer must abort (exit 134 = SIGABRT)
#   EXPECT_CLEAN  — program must exit 0 (no false positives)
#
# Usage:
#   cd custom_sanitizer/tests && ./run_tests.sh
#   OR from project root:
#   ./custom_sanitizer/tests/run_tests.sh
#
# =============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SANITIZER="$SCRIPT_DIR/../canary_sanitizer.so"
BUILD_DIR="$SCRIPT_DIR/build"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0
TOTAL=0

# =============================================================================
# Test definitions: test_name → expected result
# =============================================================================
# CRASH = expect exit 134 (SIGABRT from sanitizer detection)
# CLEAN = expect exit 0 (no bugs, no false positives)

declare -A TESTS

# --- Overflow tests (all must CRASH) ---
TESTS[test_overflow_1byte]="CRASH"
TESTS[test_overflow_8byte]="CRASH"
TESTS[test_overflow_large]="CRASH"
TESTS[test_overflow_tiny]="CRASH"
TESTS[test_overflow_zero_alloc]="CRASH"
TESTS[test_overflow_realloc]="CRASH"
TESTS[test_overflow_strcpy]="CRASH"
TESTS[test_overflow_memcpy]="CRASH"
TESTS[test_overflow_loop]="CRASH"
TESTS[test_overflow_no_free]="CRASH"
TESTS[test_realloc_overflow_after_grow]="CRASH"
TESTS[test_large_alloc_overflow]="CRASH"
TESTS[test_calloc_overflow]="CRASH"

# --- Double-free tests (all must CRASH) ---
TESTS[test_double_free]="CRASH"
TESTS[test_double_free_immediate]="CRASH"
TESTS[test_double_free_with_ops]="CRASH"

# --- UAF tests ---
TESTS[test_uaf_write_first8]="CRASH"
TESTS[test_uaf_write_header]="CRASH"
TESTS[test_uaf_write_delayed]="CRASH"
TESTS[test_uaf_read_poison]="CLEAN"   # passive detection, no abort expected

# --- Registry / exit-scan tests ---
TESTS[test_overflow_exit_clean]="CLEAN"

# --- Correctness tests (all must be CLEAN — no false positives) ---
TESTS[test_junk_fill]="CLEAN"
TESTS[test_junk_fill_realloc_grow]="CLEAN"
TESTS[test_calloc_zeroed]="CLEAN"
TESTS[test_free_null]="CLEAN"
TESTS[test_realloc_null]="CLEAN"
TESTS[test_realloc_zero]="CLEAN"
TESTS[test_realloc_shrink]="CLEAN"
TESTS[test_normal_usage]="CLEAN"
TESTS[test_normal_heavy]="CLEAN"
TESTS[test_normal_realloc_many]="CLEAN"
TESTS[test_quarantine_eviction_clean]="CLEAN"
TESTS[test_quarantine_stress]="CLEAN"
TESTS[test_mixed_alloc_types]="CLEAN"

# =============================================================================
# Validation
# =============================================================================
if [ ! -f "$SANITIZER" ]; then
    echo -e "${RED}[!] Sanitizer not found: $SANITIZER${NC}"
    echo "    Build it first: cd custom_sanitizer && gcc -shared -fPIC -O2 -o canary_sanitizer.so canary_sanitizer.c -ldl -rdynamic"
    exit 1
fi

mkdir -p "$BUILD_DIR"

# =============================================================================
# Compile all tests
# =============================================================================
echo
echo "================================================================"
echo "  Canary Sanitizer Test Suite"
echo "================================================================"
echo
echo -e "${CYAN}[*] Compiling tests...${NC}"

COMPILE_FAIL=0
for test_name in "${!TESTS[@]}"; do
    src="$SCRIPT_DIR/${test_name}.c"
    bin="$BUILD_DIR/$test_name"
    if [ ! -f "$src" ]; then
        echo -e "  ${YELLOW}[SKIP] $test_name — source not found${NC}"
        ((SKIP++))
        continue
    fi
    if ! gcc -O0 -g -o "$bin" "$src" 2>/dev/null; then
        echo -e "  ${RED}[COMPILE FAIL] $test_name${NC}"
        ((COMPILE_FAIL++))
    fi
done

if [ "$COMPILE_FAIL" -gt 0 ]; then
    echo -e "${RED}[!] $COMPILE_FAIL tests failed to compile${NC}"
fi
echo

# =============================================================================
# Run tests
# =============================================================================
echo -e "${CYAN}[*] Running tests...${NC}"
echo
printf "  %-40s %-10s %-10s %s\n" "TEST" "EXPECT" "GOT" "RESULT"
printf "  %-40s %-10s %-10s %s\n" "────────────────────────────────────────" "──────────" "──────────" "──────"

# Sort test names for consistent output
SORTED_TESTS=($(echo "${!TESTS[@]}" | tr ' ' '\n' | sort))

for test_name in "${SORTED_TESTS[@]}"; do
    bin="$BUILD_DIR/$test_name"
    expect="${TESTS[$test_name]}"
    ((TOTAL++))

    if [ ! -x "$bin" ]; then
        printf "  %-40s %-10s %-10s " "$test_name" "$expect" "N/A"
        echo -e "${YELLOW}SKIP${NC}"
        ((SKIP++))
        continue
    fi

    # Run with sanitizer, capture exit code and stderr
    stderr_file="$BUILD_DIR/${test_name}.stderr"
    LD_PRELOAD="$SANITIZER" "$bin" >/dev/null 2>"$stderr_file"
    exit_code=$?

    if [ "$expect" = "CRASH" ]; then
        # Expect exit 134 (128 + 6 = SIGABRT) or 139 (128 + 11 = SIGSEGV for abort)
        if [ "$exit_code" -eq 134 ] || [ "$exit_code" -eq 139 ]; then
            # Verify it's actually our sanitizer (check stderr for CANARY_SANITIZER)
            if grep -q "CANARY_SANITIZER" "$stderr_file" 2>/dev/null; then
                printf "  %-40s %-10s %-10s " "$test_name" "CRASH" "exit $exit_code"
                echo -e "${GREEN}PASS${NC}"
                ((PASS++))
            else
                printf "  %-40s %-10s %-10s " "$test_name" "CRASH" "exit $exit_code"
                echo -e "${RED}FAIL (crashed but no CANARY_SANITIZER message)${NC}"
                ((FAIL++))
            fi
        elif [ "$exit_code" -eq 0 ]; then
            printf "  %-40s %-10s %-10s " "$test_name" "CRASH" "exit 0"
            echo -e "${RED}FAIL (expected crash, got clean exit)${NC}"
            ((FAIL++))
        else
            printf "  %-40s %-10s %-10s " "$test_name" "CRASH" "exit $exit_code"
            echo -e "${RED}FAIL (unexpected exit code)${NC}"
            ((FAIL++))
        fi
    elif [ "$expect" = "CLEAN" ]; then
        if [ "$exit_code" -eq 0 ]; then
            printf "  %-40s %-10s %-10s " "$test_name" "CLEAN" "exit 0"
            echo -e "${GREEN}PASS${NC}"
            ((PASS++))
        else
            printf "  %-40s %-10s %-10s " "$test_name" "CLEAN" "exit $exit_code"
            echo -e "${RED}FAIL (expected clean exit, got $exit_code)${NC}"
            # Show sanitizer output for debugging
            if [ -s "$stderr_file" ]; then
                echo -e "    ${YELLOW}stderr:${NC}"
                head -5 "$stderr_file" | sed 's/^/    /'
            fi
            ((FAIL++))
        fi
    fi
done

# =============================================================================
# Summary
# =============================================================================
echo
echo "================================================================"
if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}ALL $PASS/$TOTAL TESTS PASSED${NC}  ($SKIP skipped)"
else
    echo -e "  ${RED}$FAIL/$TOTAL TESTS FAILED${NC}  ($PASS passed, $SKIP skipped)"
fi
echo "================================================================"
echo

# Show failed test details
if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}Failed test stderr outputs:${NC}"
    for test_name in "${SORTED_TESTS[@]}"; do
        stderr_file="$BUILD_DIR/${test_name}.stderr"
        expect="${TESTS[$test_name]}"
        bin="$BUILD_DIR/$test_name"
        [ ! -x "$bin" ] && continue

        LD_PRELOAD="$SANITIZER" "$bin" >/dev/null 2>"$stderr_file"
        exit_code=$?

        is_fail=0
        if [ "$expect" = "CRASH" ]; then
            if [ "$exit_code" -ne 134 ] && [ "$exit_code" -ne 139 ]; then
                is_fail=1
            elif ! grep -q "CANARY_SANITIZER" "$stderr_file" 2>/dev/null; then
                is_fail=1
            fi
        elif [ "$expect" = "CLEAN" ] && [ "$exit_code" -ne 0 ]; then
            is_fail=1
        fi

        if [ "$is_fail" -eq 1 ]; then
            echo
            echo -e "  ${RED}=== $test_name (expect=$expect, got=exit $exit_code) ===${NC}"
            if [ -s "$stderr_file" ]; then
                cat "$stderr_file" | sed 's/^/  /'
            else
                echo "  (no stderr output)"
            fi
        fi
    done
    echo
fi

# Cleanup
# rm -rf "$BUILD_DIR"  # uncomment to auto-cleanup

exit $FAIL
