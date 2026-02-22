#!/bin/bash
set -e
export PATH="$PATH:/root/.cargo/bin"
cd "/mnt/d/Dev Proj/Canary"
wasm-pack build crates/canary-wasm --target web --out-dir crates/canary-wasm/pkg 2>&1
