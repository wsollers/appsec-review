# syntax=docker/dockerfile:1
#
# C/C++ build/LSP/MCP environment. This intentionally extends the existing
# audit-native image so the C++ compiler, CSA, SVF, Joern, and native evidence
# behavior stay aligned with the authoritative C++ worker.
#
# Language tooling (docs/language-servers.md): clangd 21.1.0 (same release as the 21.1.0 compiler)
# and tree-sitter come hash-verified from audit-lsp-vendor:local; build that image first.
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
ARG CLANGD_VERSION=21.1.0
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends \
      autoconf=${AUTOCONF_VERSION} automake=${AUTOMAKE_VERSION} \
      libtool=${LIBTOOL_VERSION} make=${MAKE_VERSION} bear=${BEAR_VERSION} \
      pkg-config=${PKG_CONFIG_VERSION} \
      nodejs python3-venv python3-pip \
      gdb lldb file strace ltrace binutils elfutils procps \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g \
      @modelcontextprotocol/server-filesystem@2026.8.31 \
      @modelcontextprotocol/server-memory@2026.8.31 \
    && test "$(command -v clang)" = /opt/llvm/bin/clang \
    && test "$(command -v clang++)" = /opt/llvm/bin/clang++ \
    && /opt/llvm/bin/clang --version | grep -F 'clang version 21.1.0 ' \
    && command -v autoconf automake libtoolize make bear pkg-config >/dev/null \
    && node --version

# --- clangd, pinned wheel from audit-lsp-vendor. The wrapper drops audit-native's LD_LIBRARY_PATH
# (/opt/llvm/lib) so clangd loads only its own bundled runtime.
RUN --mount=type=bind,from=audit-lsp-vendor:local,source=/opt/lsp-vendor,target=/mnt/lsp-vendor \
    python3 -m venv /opt/clangd \
    && /opt/clangd/bin/pip install --no-cache-dir --no-index --find-links /mnt/lsp-vendor/wheels \
         --require-hashes -r /mnt/lsp-vendor/requirements/clangd.txt \
    && ln -s "$(/opt/clangd/bin/python -c 'import clangd, os; print(os.path.join(os.path.dirname(clangd.__file__), "data", "bin", "clangd"))')" /opt/clangd/clangd \
    && printf '%s\n' '#!/usr/bin/env bash' 'unset LD_LIBRARY_PATH' 'exec /opt/clangd/clangd "$@"' > /usr/local/bin/clangd \
    && chmod +x /usr/local/bin/clangd \
    && clangd --version | grep -F "clangd version ${CLANGD_VERSION}"

# --- tree-sitter CLI + py-tree-sitter/grammars, vendored in audit-lsp-vendor (docs/language-servers.md §3).
RUN --mount=type=bind,from=audit-lsp-vendor:local,source=/opt/lsp-vendor,target=/mnt/lsp-vendor \
    install -m 0755 /mnt/lsp-vendor/bin/tree-sitter /usr/local/bin/tree-sitter \
    && python3 -m venv /opt/treesitter \
    && /opt/treesitter/bin/pip install --no-cache-dir --no-index --find-links /mnt/lsp-vendor/wheels \
         --require-hashes -r /mnt/lsp-vendor/requirements/treesitter.txt \
    && /opt/treesitter/bin/python -c "import tree_sitter, tree_sitter_c, tree_sitter_python, tree_sitter_php" \
    && tree-sitter --version | grep -F "tree-sitter 0.26.13"

USER worker
WORKDIR /scratch
ENV CC=/opt/llvm/bin/clang \
    CXX=/opt/llvm/bin/clang++
CMD ["/bin/bash"]
