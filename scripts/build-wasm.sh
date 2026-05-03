#!/usr/bin/env bash
# Build the WASM verifier and emit JS bindings to public/wasm/.
#
# Output:
#   public/wasm/verifier_wasm_bg.wasm   — the WebAssembly binary
#   public/wasm/verifier_wasm.js        — JS glue + types
#   public/wasm/verifier_wasm.d.ts      — TypeScript types
#   public/wasm/package.json            — npm-ready manifest
#
# Requires:
#   - rustup target add wasm32-unknown-unknown    (one-time)
#   - cargo install wasm-bindgen-cli              (one-time)
#
# After this script: any browser, extension, or chat-app integration loads
# `/wasm/verifier_wasm.js` and calls recognize_win() / recognize_bundle().

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "error: wasm-bindgen not found." >&2
  echo "       run: cargo install wasm-bindgen-cli" >&2
  exit 1
fi

echo "▸ Building verifier-wasm for wasm32-unknown-unknown (release)…"
cargo build --target wasm32-unknown-unknown --release -p verifier-wasm

echo "▸ Generating JS bindings → public/wasm/…"
mkdir -p public/wasm
wasm-bindgen \
  --target web \
  --out-dir public/wasm \
  --no-typescript \
  target/wasm32-unknown-unknown/release/verifier_wasm.wasm

# Re-emit with TypeScript types alongside (keeps both available)
wasm-bindgen \
  --target web \
  --out-dir public/wasm \
  target/wasm32-unknown-unknown/release/verifier_wasm.wasm

# wasm-opt is optional but typically halves the wasm size.
#
# The Rust toolchain emits modern WebAssembly features by default
# (bulk-memory ops, sign extension, non-trapping float→int, multi-value
# returns, mutable globals, reference types). wasm-opt's validator
# rejects these unless the matching feature flags are enabled. The set
# below is the standard MVP+1 — supported by every current browser and
# matches what wasm-bindgen targets.
if command -v wasm-opt >/dev/null 2>&1; then
  echo "▸ Optimizing with wasm-opt…"
  wasm-opt -Oz \
    --enable-bulk-memory \
    --enable-sign-ext \
    --enable-nontrapping-float-to-int \
    --enable-mutable-globals \
    --enable-multivalue \
    --enable-reference-types \
    -o public/wasm/verifier_wasm_bg.opt.wasm \
    public/wasm/verifier_wasm_bg.wasm
  mv public/wasm/verifier_wasm_bg.opt.wasm public/wasm/verifier_wasm_bg.wasm
fi

size=$(wc -c < public/wasm/verifier_wasm_bg.wasm)
echo "✔ Done. wasm size: $((size / 1024)) KB"
echo "  Loaded via: import init, { recognize_win } from '/wasm/verifier_wasm.js'"
