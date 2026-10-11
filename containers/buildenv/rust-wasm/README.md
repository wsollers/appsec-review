# Local Rust WebAssembly build image

`Dockerfile` adds the `wasm32-unknown-unknown` and `wasm32-wasip1` Rust 1.90.0
standard-library targets to the exact local Rust image used by the current
`rust` build profile. Rustup verifies the downloaded components against its
release manifest. The image is layered on the existing deferred build
environment; it is not a replacement for the catalog's planned reproducible
Rust image.

First verify that `audit-buildenv-rust:local` matches the pinned `rust` profile
image ID in `appsec-review.toml`. Build it with Docker Desktop, then update the `wasm` profile's `image_id` in
`appsec-review.toml` to the resulting `docker image inspect` ID:

```sh
docker build --pull=false --provenance=false --sbom=false --tag audit-buildenv-rust-wasm:local containers/buildenv/rust-wasm
docker image inspect audit-buildenv-rust-wasm:local --format '{{.Id}}'
```

The build disables generated attestations because their changing metadata
changes Docker Desktop's local image ID even when the image contents are cached.

The `rust` profile keeps its original image. The `wasm` profile uses this
variant for Rust recipes; native and Node WebAssembly producers retain their
own configured family images.
