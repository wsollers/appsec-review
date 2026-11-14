---
title: "Rust and WebAssembly build image"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: []
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Rust and WebAssembly build image

`Dockerfile` installs Rust 1.90.0 (`rustc`, `cargo`, the `x86_64-unknown-linux-gnu`,
`wasm32-unknown-unknown` and `wasm32-wasip1` standard libraries, and `rust-src`) from official
release component archives listed in `assets.lock.json`. `rust-src` puts the standard-library
source under `/opt/rust/lib/rustlib/src/rust/library`; the CodeQL Rust extractor loads it as the
sysroot, and without it no `std` call (`std::env::args`, `std::process::Command`, `Option::unwrap`)
resolves, so Rust sources, sinks and dataflow paths are lost. `build.py` downloads each archive and accepts it only at its
locked size and SHA-256; the Dockerfile verifies the hashes again and runs the components'
`install.sh` into `/opt/rust`. It does not use rustup. The catalog sets `build_network = "default"`:
the Dockerfile installs `xz-utils` from APT before unpacking the already acquired Rust archives.

The image builds `FROM` the shared native toolchain, so Rust build scripts, the native linker and
C-to-wasm32 producers (`clang --target=wasm32`, `wasm-ld`) use the same pinned gcc/clang as the
other families that inherit that base.

Both the `rust` and `wasm` build profiles use this image. After a rebuild, refresh its tag binding
in the host-owned pins file; that binding supplies both resolved profile IDs
(see [profile image pins](../README.md#profile-image-pins)).

```sh
python3 containers/build.py build audit-buildenv-rust-wasm
docker image inspect audit-buildenv-rust-wasm:local --format '{{.Id}}'
```
