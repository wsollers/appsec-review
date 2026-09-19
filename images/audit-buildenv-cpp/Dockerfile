# syntax=docker/dockerfile:1
#
# C/C++ build/LSP/MCP environment. This intentionally extends the existing
# audit-native image so the C++ compiler, CSA, SVF, Joern, and native evidence
# behavior stay aligned with the authoritative C++ worker.
FROM audit-native:local

USER root
ARG NODE_MAJOR=22
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends \
      nodejs python3-venv python3-pip \
      clangd-21 gdb lldb file strace ltrace binutils elfutils procps pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && printf '%s\n' '#!/usr/bin/env bash' 'unset LD_LIBRARY_PATH' 'exec /usr/bin/clangd-21 "$@"' > /usr/local/bin/clangd \
    && chmod +x /usr/local/bin/clangd \
    && npm install -g \
      @modelcontextprotocol/server-filesystem \
      @modelcontextprotocol/server-memory \
    && clangd --version | head -1 \
    && node --version

USER worker
WORKDIR /scratch
CMD ["/bin/bash"]
