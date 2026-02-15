#!/usr/bin/env bash
#
# run_bench.sh — Benchmark: baseline (no sanitizer) vs canary_sanitizer
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
BUILD_DIR="$SCRIPT_DIR/build"
SANITIZER="$ROOT_DIR/canary_sanitizer.so"

CYN='\033[0;36m'
GRN='\033[0;32m'
YEL='\033[0;33m'
RED='\033[0;31m'
RST='\033[0m'

mkdir -p "$BUILD_DIR"

echo ""
echo -e "${CYN}╔══════════════════════════════════════════════════════════════╗${RST}"
echo -e "${CYN}║         Canary Sanitizer Benchmark: Baseline vs Sanitizer   ║${RST}"
echo -e "${CYN}╚══════════════════════════════════════════════════════════════╝${RST}"
echo ""

# Build benchmark
echo -e "${CYN}Building benchmark...${RST}"
gcc -O2 -o "$BUILD_DIR/bench_speed" "$SCRIPT_DIR/bench_speed.c"
echo ""

# Check sanitizer exists
if [ ! -f "$SANITIZER" ]; then
    echo -e "${RED}ERROR: $SANITIZER not found. Build it first:${RST}"
    echo "  gcc -shared -fPIC -O2 -o canary_sanitizer.so canary_sanitizer.c -ldl -rdynamic"
    exit 1
fi

# Run baseline (no sanitizer)
echo -e "${GRN}━━━ 1/2: Baseline (no sanitizer) ━━━${RST}"
"$BUILD_DIR/bench_speed"
echo ""

# Run sanitizer
echo -e "${CYN}━━━ 2/2: Canary Sanitizer ━━━${RST}"
LD_PRELOAD="$SANITIZER" "$BUILD_DIR/bench_speed"
echo ""

echo -e "${CYN}══════════════════════════════════════════════════════════════${RST}"
echo -e "${GRN}Benchmark complete.${RST}"
echo -e "Compare the ops/sec numbers above to see overhead ratio."
echo -e "${CYN}══════════════════════════════════════════════════════════════${RST}"
