#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
BUILD="$REPO/build"

echo "================================================"
echo "  lancer-nmap workspace build (Linux / macOS)"
echo "================================================"
echo ""
echo "  Repo   : $REPO"
echo "  Output : $BUILD"
echo ""

echo "[1/2] Building release workspace..."
cargo build --release --workspace

echo "[2/2] Collecting binaries..."
mkdir -p "$BUILD"
for bin in lancer-nmap lancer-nmap-cli lancer-ndiff lancer-ncat lancer-nping; do
    if [ -f "$REPO/target/release/$bin" ]; then
        cp -f "$REPO/target/release/$bin" "$BUILD/"
    fi
done

echo ""
echo "================================================"
echo "  Done!  Binaries copied to: $BUILD/"
echo "================================================"
