# syntax=docker/dockerfile:1
#
# C/C++ build/LSP/MCP environment. This intentionally extends the existing
# audit-native image so the C++ compiler, CSA, SVF, Joern, and native evidence
# behavior stay aligned with the authoritative C++ worker.
FROM audit-native:local

USER root
ARG DEBIAN_FRONTEND=noninteractive
ARG NODE_MAJOR=22
ARG AUTOCONF_VERSION=2.71-3
ARG AUTOMAKE_VERSION=1:1.16.5-1.3ubuntu1
ARG LIBTOOL_VERSION=2.4.7-7build1
ARG MAKE_VERSION=4.3-4.1build2
ARG BEAR_VERSION=3.1.3-1build4
ARG PKG_CONFIG_VERSION=1.8.1-2build1
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends \
      autoconf=${AUTOCONF_VERSION} automake=${AUTOMAKE_VERSION} \
      libtool=${LIBTOOL_VERSION} make=${MAKE_VERSION} bear=${BEAR_VERSION} \
      pkg-config=${PKG_CONFIG_VERSION} \
      nodejs python3-venv python3-pip \
      clangd-21 gdb lldb file strace ltrace binutils elfutils procps \
    && rm -rf /var/lib/apt/lists/* \
    && printf '%s\n' '#!/usr/bin/env bash' 'unset LD_LIBRARY_PATH' 'exec /usr/bin/clangd-21 "$@"' > /usr/local/bin/clangd \
    && chmod +x /usr/local/bin/clangd \
    && npm install -g \
      @modelcontextprotocol/server-filesystem \
      @modelcontextprotocol/server-memory \
    && test "$(command -v clang)" = /opt/llvm/bin/clang \
    && test "$(command -v clang++)" = /opt/llvm/bin/clang++ \
    && /opt/llvm/bin/clang --version | grep -F 'clang version 21.1.0 ' \
    && command -v autoconf automake libtoolize make bear pkg-config >/dev/null \
    && clangd --version | head -1 \
    && node --version

USER worker
WORKDIR /scratch
ENV CC=/opt/llvm/bin/clang \
    CXX=/opt/llvm/bin/clang++
CMD ["/bin/bash"]
