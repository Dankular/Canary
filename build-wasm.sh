#!/usr/bin/env bash
set -euo pipefail

CRATE_DIR="crates/canary-wasm"
PKG_DIR="$CRATE_DIR/pkg"

echo "==> Building Canary WASM (standard build)..."
wasm-pack build "$CRATE_DIR" \
    --target web \
    --out-dir pkg \
    --release

echo ""
echo "==> Building Canary WASM (threads/SAB build)..."
echo "    Requires: rustup override set nightly"
echo "    Requires: rustup target add wasm32-unknown-unknown (nightly)"
echo ""

if rustup show active-toolchain 2>/dev/null | grep -q nightly; then
    RUSTFLAGS="-C target-feature=+atomics,+bulk-memory,+mutable-globals" \
    wasm-pack build "$CRATE_DIR" \
        --target web \
        --out-dir pkg-threads \
        --release \
        -- -Z build-std=panic_abort,std
    echo "==> Threads build complete → $CRATE_DIR/pkg-threads/"
else
    echo "    Skipping threads build (nightly not active)"
    echo "    To build: rustup override set nightly && ./build-wasm.sh"
fi

echo ""
echo "==> Standard build complete → $CRATE_DIR/pkg/"
echo "==> Start dev server: node harness/server.mjs"
