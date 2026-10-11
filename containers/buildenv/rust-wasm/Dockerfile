# The shared Rust image is a pinned local build environment while its replacement
# remains deferred in the container catalog. Keep this thin layer tied to its exact
# image identity so changing that base requires an explicit rebuild and config edit.
FROM audit-buildenv-rust:local

USER root
RUN rustup target add --toolchain 1.90.0 wasm32-unknown-unknown wasm32-wasip1 \
    && rustup target list --installed | grep -Fx wasm32-unknown-unknown \
    && rustup target list --installed | grep -Fx wasm32-wasip1 \
    && chmod -R a+rX /usr/local/rustup
USER worker
