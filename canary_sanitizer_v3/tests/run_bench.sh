#!/usr/bin/env bash
#
# run_bench.sh — Benchmark: baseline vs canary_sanitizer v2 vs v3
#
# Builds bench_speed.c and runs it three ways to compare overhead.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
SANITIZER_V3="$SCRIPT_DIR/../canary_sanitizer.so"
SANITIZER_V2="/home/dvirgo/custom_sanitizer/canary_sanitizer.so"

# Colors
CYN='\033[0;36m'
GRN='\033[0;32m'
YEL='\033[0;33m'
RED='\033[0;31m'
RST='\033[0m'

mkdir -p "$BUILD_DIR"

echo ""
echo -e "${CYN}╔══════════════════════════════════════════════════════════════╗${RST}"
echo -e "${CYN}║     Canary Sanitizer Benchmark: Baseline vs v2 vs v3       ║${RST}"
echo -e "${CYN}╚══════════════════════════════════════════════════════════════╝${RST}"
echo ""

# Build benchmark
echo -e "${CYN}Building benchmark...${RST}"
gcc -O2 -o "$BUILD_DIR/bench_speed" "$SCRIPT_DIR/bench_speed.c"
echo ""

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

# 1) Baseline (no sanitizer)
echo -e "${GRN}━━━ 1/3: Baseline (no sanitizer) ━━━${RST}"
"$BUILD_DIR/bench_speed"
echo ""

# 2) v2 sanitizer
echo -e "${YEL}━━━ 2/3: Canary Sanitizer v2 ━━━${RST}"
LD_PRELOAD="$SANITIZER_V2" "$BUILD_DIR/bench_speed"
echo ""

# 3) v3 sanitizer
echo -e "${CYN}━━━ 3/3: Canary Sanitizer v3 ━━━${RST}"
LD_PRELOAD="$SANITIZER_V3" "$BUILD_DIR/bench_speed"
echo ""

echo -e "${CYN}══════════════════════════════════════════════════════════════${RST}"
echo -e "${GRN}Benchmark complete.${RST}"
echo -e "Compare the ops/sec numbers above to see overhead ratios."
echo -e "  Overhead = (baseline ops/sec) / (sanitizer ops/sec)"
echo -e "  Lower overhead ratio = better performance."
echo -e "${CYN}══════════════════════════════════════════════════════════════${RST}"
