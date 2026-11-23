# @rabbitlock/crypto-wasm

RabbitLock's crypto core in Rust, compiled to WebAssembly. It handles the SOPS-format encrypted secrets file, with hybrid post-quantum recipients (X25519 + ML-KEM-768). The `rabbitlock` CLI bundles it at pack time; it is not published on its own.

- Prebuilt artifacts live in `pkg/` so the CLI works without a Rust toolchain.
- Rebuild: install Rust and `wasm-pack`, then `npm run build`.
- Test: `cargo test`.
