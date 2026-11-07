#!/bin/sh
# Builds the WebAssembly module and puts it beside the page. Serve this folder over HTTP to use it.
set -e
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
cargo build -p zkhypervm-wasm --target wasm32-unknown-unknown --release --locked
cp target/wasm32-unknown-unknown/release/zkhypervm_wasm.wasm web/zkhypervm.wasm
ls -l web/zkhypervm.wasm
