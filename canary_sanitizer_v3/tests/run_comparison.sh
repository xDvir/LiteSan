#!/usr/bin/env bash
#
# run_comparison.sh — Compare v3-specific test results between v2 and v3 sanitizers
#
# Tests v3-specific test cases against BOTH the v2 and v3 sanitizer to show
# which bugs each version catches vs misses.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
SANITIZER_V3="$SCRIPT_DIR/../canary_sanitizer.so"
SANITIZER_V2="/home/dvirgo/custom_sanitizer/canary_sanitizer.so"

# Colors
RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[0;33m'
CYN='\033[0;36m'
RST='\033[0m'

mkdir -p "$BUILD_DIR"

# Check both sanitizers exist
if [ ! -f "$SANITIZER_V2" ]; then
    echo -e "${RED}ERROR: v2 sanitizer not found at $SANITIZER_V2${RST}"
    echo "  Build it first in the v2 directory."
    exit 1
fi

if [ ! -f "$SANITIZER_V3" ]; then
    echo -e "${RED}ERROR: v3 sanitizer not found at $SANITIZER_V3${RST}"
    echo "  Build it first:"
    echo "  gcc -shared -fPIC -O2 -o canary_sanitizer.so canary_sanitizer.c -ldl -rdynamic"
    exit 1
fi

# Test cases: source file and expected outcome (CRASH = sanitizer should catch it)
declare -a TEST_SOURCES=(
    "test_underflow_basic.c"
    "test_underflow_memcpy.c"
    "test_guard_page_overflow.c"
    "test_uaf_full_scan.c"
)

# Run a single test with a given sanitizer, return CAUGHT / MISSED / BUILD_FAIL
run_single() {
    local src="$1"
    local sanitizer="$2"
    local bin="$3"

    local stderr_file
    stderr_file=$(mktemp)
    local exit_code=0

    LD_PRELOAD="$sanitizer" "$bin" >"$stderr_file" 2>&1 || exit_code=$?

    local status="MISSED"
    if [ "$exit_code" -eq 134 ]; then
        if grep -q "CANARY_SANITIZER" "$stderr_file"; then
            status="CAUGHT"
        else
            status="CRASH_OTHER"
        fi
    elif [ "$exit_code" -ne 0 ]; then
        # Non-zero exit but not 134 — could be SIGSEGV from guard page etc.
        status="CAUGHT"
    fi

    rm -f "$stderr_file"
    echo "$status"
}

echo ""
echo -e "${CYN}╔══════════════════════════════════════════════════════════════╗${RST}"
echo -e "${CYN}║       v3 Feature Comparison: v2 Sanitizer vs v3 Sanitizer  ║${RST}"
echo -e "${CYN}╚══════════════════════════════════════════════════════════════╝${RST}"
echo ""

# Table header
printf "  ${CYN}%-35s  %-12s  %-12s${RST}\n" "Test" "v2" "v3"
printf "  %-35s  %-12s  %-12s\n" "-----------------------------------" "------------" "------------"

for src_file in "${TEST_SOURCES[@]}"; do
    src_path="$SCRIPT_DIR/$src_file"
    name=$(basename "$src_file" .c)
    bin="$BUILD_DIR/$name"

    # Build the test
    if ! gcc -O0 -g -o "$bin" "$src_path" 2>/dev/null; then
        printf "  ${YEL}%-35s  %-12s  %-12s${RST}\n" "$name" "BUILD_FAIL" "BUILD_FAIL"
        continue
    fi

    # Run with v2
    result_v2=$(run_single "$src_path" "$SANITIZER_V2" "$bin")

    # Run with v3
    result_v3=$(run_single "$src_path" "$SANITIZER_V3" "$bin")

    # Colorize results
    if [ "$result_v2" = "CAUGHT" ]; then
        v2_display="${GRN}CAUGHT${RST}"
    elif [ "$result_v2" = "MISSED" ]; then
        v2_display="${RED}MISSED${RST}"
    else
        v2_display="${YEL}${result_v2}${RST}"
    fi

    if [ "$result_v3" = "CAUGHT" ]; then
        v3_display="${GRN}CAUGHT${RST}"
    elif [ "$result_v3" = "MISSED" ]; then
        v3_display="${RED}MISSED${RST}"
    else
        v3_display="${YEL}${result_v3}${RST}"
    fi

    printf "  %-35s  $(echo -e "$v2_display")%-6s  $(echo -e "$v3_display")%-6s\n" "$name" "" ""
done

echo ""
echo -e "${CYN}══════════════════════════════════════════════════════════════${RST}"
echo -e "  ${GRN}CAUGHT${RST} = sanitizer detected the bug (process terminated)"
echo -e "  ${RED}MISSED${RST} = bug went undetected (process exited cleanly)"
echo -e "  ${YEL}CRASH_OTHER${RST} = process crashed but not by sanitizer"
echo -e "${CYN}══════════════════════════════════════════════════════════════${RST}"
echo ""
