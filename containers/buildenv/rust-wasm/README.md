# Local Rust WebAssembly build image

`Dockerfile` adds the `wasm32-unknown-unknown` and `wasm32-wasip1` Rust 1.90.0
standard-library targets to the exact local Rust image used by the current
`rust` build profile. Rustup verifies the downloaded components against its
release manifest. The image is layered on the existing deferred build
environment; it is not a replacement for the catalog's planned reproducible
Rust image.

First verify that the legacy `audit-buildenv-rust:local` base resolves to
`sha256:c8ce7e10708cc0b43cb15196abb289fff633da852ab2d7ac1144c0310bf0a5ed`.
Build it with Docker Desktop, then update
both the `rust` and `wasm` profiles' `image_id` values in `appsec-review.toml` to
the resulting `docker image inspect` ID:

```sh
docker build --pull=false --provenance=false --sbom=false --tag audit-buildenv-rust-wasm:local containers/buildenv/rust-wasm
docker image inspect audit-buildenv-rust-wasm:local --format '{{.Id}}'
```

The build disables generated attestations because their changing metadata
changes Docker Desktop's local image ID even when the image contents are cached.

Both `rust` and `wasm` profiles use this image. The language-build Wasm job
executes Rust producer recipes with the accepted Rust source-family image, so
updating only the `wasm` profile would leave those recipes on the old image.
Native and Node WebAssembly producers retain their own configured family images.
