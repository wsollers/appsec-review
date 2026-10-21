# syntax=docker/dockerfile:1
# C/C++ build environment: the shared native toolchain plus native build-system drivers.
# Analysis tools (clang-tidy, CodeQL, Joern, LSPs) live in their own images, never here.
FROM appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1
LABEL org.opencontainers.image.title="audit-buildenv-cpp" \
      org.opencontainers.image.version="noble-gcc13.3-clang18.1-cmake3.28"
USER 0:0
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      autoconf=2.71-3 automake=1:1.16.5-1.3ubuntu1 cmake=3.28.3-1build7 \
      libtool=2.4.7-7build1 ninja-build=1.11.1-2 \
 && rm -rf /var/lib/apt/lists/* \
 && sh /opt/native-toolchain/check-toolchain.sh \
 && cmake --version | grep -F 'cmake version 3.28.3'
# clang is the preferred compiler: CMake, Autotools and make read CC/CXX from the environment. gcc stays
# installed (cc and c++ still resolve to it) for recipes that name it or set CC/CXX themselves.
ENV CC=clang CXX=clang++
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /workspace
