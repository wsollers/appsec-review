# syntax=docker/dockerfile:1
# C/C++ build environment: the shared native toolchain, which already carries the build drivers
# (Autotools, libtool, CMake, Ninja, Meson; T-058), with clang as the family's default compiler.
# Analysis tools (clang-tidy, CodeQL, Joern, LSPs) live in their own images, never here.
FROM appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1
LABEL org.opencontainers.image.title="audit-buildenv-cpp" \
      org.opencontainers.image.version="noble-gcc13.3-clang18.1-cmake3.28"
USER 0:0
RUN sh /opt/native-toolchain/check-toolchain.sh \
 && cmake --version | grep -F 'cmake version 3.28.3'
# clang is the preferred compiler: CMake, Autotools and make read CC/CXX from the environment. gcc stays
# installed (cc and c++ still resolve to it) for recipes that name it or set CC/CXX themselves.
ENV CC=clang CXX=clang++
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /workspace
