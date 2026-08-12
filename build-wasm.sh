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
echo "==> Skipping memory64/wasm64 build: not currently possible."
echo "    See docs/memory64-status.md — the core emulator (canary-memory,"
echo "    canary-cpu, ...) compiles fine for the wasm64-unknown-unknown"
echo "    target, but wasm-bindgen 0.2.111's JS-interop codegen is hardcoded"
echo "    to target_arch = \"wasm32\" and silently no-ops on wasm64, so a"
echo "    wasm64 build of canary-wasm produces a module with no usable JS"
echo "    exports. Revisit once wasm-bindgen supports wasm64 upstream."

echo ""
echo "==> Standard build complete → $CRATE_DIR/pkg/"
echo "==> Start dev server: node harness/server.mjs"
