# Rust and WebAssembly build image

`Dockerfile` installs Rust 1.90.0 (`rustc`, `cargo`, and the `x86_64-unknown-linux-gnu`,
`wasm32-unknown-unknown` and `wasm32-wasip1` standard libraries) from official release component
archives listed in `assets.lock.json`. `build.py` downloads each archive and accepts it only at its
locked size and SHA-256; the Dockerfile verifies the hashes again and runs the components'
`install.sh` into `/opt/rust`. No rustup and no network access happen inside the image build.

The image builds `FROM` the shared native toolchain, so Rust build scripts, the native linker and
C-to-wasm32 producers (`clang --target=wasm32`, `wasm-ld`) use the same pinned gcc/clang as every
other family.

Both the `rust` and `wasm` build profiles use this image; when it is rebuilt, update both
`image_id` pins in `appsec-review.toml` (see `../README.md`).

```sh
python3 containers/build.py build audit-buildenv-rust-wasm
docker image inspect audit-buildenv-rust-wasm:local --format '{{.Id}}'
```
