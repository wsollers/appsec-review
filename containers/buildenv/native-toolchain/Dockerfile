# syntax=docker/dockerfile:1
# Shared C/C++ toolchain base for every language build environment. Family images build FROM
# this image so node-gyp, phpize, setuptools, cgo, wasm32 clang, and direct native builds all
# compile with one pinned gcc/clang identity. It contains no language runtime and no analysis
# tooling.
FROM appsec-review/base-ubuntu:24.04
LABEL org.opencontainers.image.title="buildenv-native-toolchain" \
      org.opencontainers.image.version="noble-gcc13.3-clang18.1"
USER 0:0
COPY packages.lock check-toolchain.sh /opt/native-toolchain/
RUN apt-get update \
 && apt-get install -y --no-install-recommends $(grep -v '^#' /opt/native-toolchain/packages.lock) \
 && rm -rf /var/lib/apt/lists/* \
 && sh /opt/native-toolchain/check-toolchain.sh \
 && mkdir -p /workspace /scratch /capture /opt/project-deps \
 && chown 10001:10001 /workspace /scratch /capture /opt/project-deps
ENV HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /workspace
