#!/usr/bin/env bash
#
# run_bench.sh — Benchmark comparison: no sanitizer vs v1 vs v2
#
# Builds the benchmark binary, runs it three ways, and shows a comparison.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
V2_DIR="$SCRIPT_DIR/.."
V1_DIR="$V2_DIR/.."
BUILD_DIR="$SCRIPT_DIR/build"

V1_SO="$V1_DIR/canary_sanitizer.so"
V2_SO="$V2_DIR/canary_sanitizer.so"

CYN='\033[0;36m'
GRN='\033[0;32m'
YEL='\033[0;33m'
RED='\033[0;31m'
RST='\033[0m'

mkdir -p "$BUILD_DIR"

echo ""
echo -e "${CYN}╔══════════════════════════════════════════════════════════════╗${RST}"
echo -e "${CYN}║      Canary Sanitizer Benchmark: Baseline vs v1 vs v2      ║${RST}"
echo -e "${CYN}╚══════════════════════════════════════════════════════════════╝${RST}"
echo ""

# Build benchmark
echo -e "${CYN}Building benchmark...${RST}"
gcc -O2 -o "$BUILD_DIR/bench_speed" "$SCRIPT_DIR/bench_speed.c"
echo ""

# Check sanitizers exist
if [ ! -f "$V1_SO" ]; then
    echo -e "${RED}WARNING: v1 sanitizer not found at $V1_SO${RST}"
    echo -e "${YEL}Building v1...${RST}"
    gcc -shared -fPIC -O2 -o "$V1_SO" "$V1_DIR/canary_sanitizer.c" -ldl -rdynamic
fi

if [ ! -f "$V2_SO" ]; then
    echo -e "${RED}WARNING: v2 sanitizer not found at $V2_SO${RST}"
    echo -e "${YEL}Building v2...${RST}"
    gcc -shared -fPIC -O2 -o "$V2_SO" "$V2_DIR/canary_sanitizer.c" -ldl -rdynamic
fi

# Run baseline (no sanitizer)
echo -e "${GRN}━━━ 1/3: Baseline (no sanitizer) ━━━${RST}"
"$BUILD_DIR/bench_speed"
echo ""

# Run v1
echo -e "${YEL}━━━ 2/3: v1 Sanitizer (original) ━━━${RST}"
LD_PRELOAD="$V1_SO" "$BUILD_DIR/bench_speed"
echo ""

# Run v2
echo -e "${CYN}━━━ 3/3: v2 Sanitizer (all features) ━━━${RST}"
LD_PRELOAD="$V2_SO" "$BUILD_DIR/bench_speed"
echo ""

echo -e "${CYN}══════════════════════════════════════════════════════════════${RST}"
echo -e "${GRN}Benchmark complete.${RST}"
echo -e "Compare the ops/sec numbers above to see overhead ratios."
echo -e "${CYN}══════════════════════════════════════════════════════════════${RST}"
