# syntax=docker/dockerfile:1
# Rust and WebAssembly build environment on the shared native toolchain. Rust 1.90.0 is
# installed from hash-locked official release components (no rustup, no network at build
# time) together with the wasm32-unknown-unknown and wasm32-wasip1 standard libraries. The
# shared toolchain's clang/wasm-ld also serve C-to-wasm32 producers, and its gcc is the
# linker and build-script C compiler for native Rust targets.
FROM appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1
LABEL org.opencontainers.image.title="audit-buildenv-rust-wasm" \
      org.opencontainers.image.version="rust1.90.0-wasm32-clang18.1"
USER 0:0
COPY downloads/ /tmp/rust-assets/
RUN apt-get update \
 && apt-get install -y --no-install-recommends xz-utils=5.6.1+really5.4.5-1ubuntu0.3 \
 && rm -rf /var/lib/apt/lists/* \
 && printf '%s  %s\n' \
      48c2a42de9e92fcae8c24568f5fe40d5734696a6f80e83cc6d46eef1a78f13c9 /tmp/rust-assets/rustc-1.90.0-x86_64-unknown-linux-gnu.tar.xz \
      9853db03d68578a30972e2755c89c66aec035fec641cf8f3a7117c81eec2578d /tmp/rust-assets/cargo-1.90.0-x86_64-unknown-linux-gnu.tar.xz \
      663f4ab7945b392d5e5294dec1b050a66820a20e86f084ec37eeb0f2f7ff5569 /tmp/rust-assets/rust-std-1.90.0-x86_64-unknown-linux-gnu.tar.xz \
      e6e3964f4a9639688577d5a3609633b983c795ad8de43c9eceb878a84d1aeb78 /tmp/rust-assets/rust-std-1.90.0-wasm32-unknown-unknown.tar.xz \
      d813ddb537b57e79f18b6493e7ec2b0a18a8dd2be0dec0a7d6472d9bd62edbe6 /tmp/rust-assets/rust-std-1.90.0-wasm32-wasip1.tar.xz \
    | sha256sum -c - \
 && mkdir -p /tmp/rust-unpack \
 && for archive in /tmp/rust-assets/*.tar.xz; do \
      tar -xJf "$archive" -C /tmp/rust-unpack; \
    done \
 && for component in /tmp/rust-unpack/*/; do \
      sh "$component/install.sh" --prefix=/opt/rust --disable-ldconfig --without=rust-docs; \
    done \
 && rm -rf /tmp/rust-assets /tmp/rust-unpack \
 && chmod -R a+rX /opt/rust \
 && sh /opt/native-toolchain/check-toolchain.sh \
 && /opt/rust/bin/rustc --version | grep -F 'rustc 1.90.0' \
 && /opt/rust/bin/cargo --version | grep -F 'cargo 1.90.0' \
 && test -d /opt/rust/lib/rustlib/wasm32-unknown-unknown/lib \
 && test -d /opt/rust/lib/rustlib/wasm32-wasip1/lib
ENV PATH=/opt/rust/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /workspace
