# pcci-attestation-cpu-amd

## Repo Binaries

* `create-report`, server side report generation
* `attest-report`, client side report validation

## Requirements

### ubuntu 25.05

#### server
* libtss2-tctildr0t64 [fix: tss-esapi 8.x statically bundles it in the binary]
* libtss2-esys-3.0.2-0t64 [^]

#### build

* libssl-dev
* pkg-config
* libtss2-dev

### build

```bash
cargo build \
  --target x86_64-unknown-linux-gnu \
  --features hyperv
```

## references

https://github.com/virtee/snpguest

## WASM

* https://drager.github.io/wasm-pack/installer/
* https://github.com/wasm-bindgen/wasm-bindgen
* https://emscripten.org
* https://doc.rust-lang.org/beta/rustc/platform-support/wasm32-unknown-unknown.html
