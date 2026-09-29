# syntax=docker/dockerfile:1
# Rust build/LSP environment. rust-analyzer is the rustup component of the digest-pinned 1.90.0
# toolchain. Pins and install methods: docs/language-servers.md (needs audit-lsp-vendor:local).
FROM rust:1.90.0-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f

ARG NODE_MAJOR=22
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq ripgrep build-essential gnupg python3 python3-pip python3-venv \
      file gdb lldb strace ltrace binutils elfutils procps \
    && curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rust-analyzer rustfmt clippy rust-src \
    && ln -sfn /usr/local/cargo/bin/cargo /usr/local/bin/cargo \
    && ln -sfn /usr/local/cargo/bin/rustc /usr/local/bin/rustc \
    && ln -sfn /usr/local/cargo/bin/rustfmt /usr/local/bin/rustfmt \
    && ln -sfn /usr/local/cargo/bin/clippy-driver /usr/local/bin/clippy-driver \
    && ln -sfn /usr/local/cargo/bin/rust-analyzer /usr/local/bin/rust-analyzer \
    && rustc --version | grep -F "rustc 1.90.0" \
    && rust-analyzer --version \
    && chmod -R a+rX /usr/local/rustup /usr/local/cargo \
    && npm install -g @modelcontextprotocol/server-filesystem@2026.8.31 @modelcontextprotocol/server-memory@2026.8.31

# --- tree-sitter CLI + py-tree-sitter/grammars, vendored in audit-lsp-vendor (docs/language-servers.md §3).
RUN --mount=type=bind,from=audit-lsp-vendor:local,source=/opt/lsp-vendor,target=/mnt/lsp-vendor \
    install -m 0755 /mnt/lsp-vendor/bin/tree-sitter /usr/local/bin/tree-sitter \
    && python3 -m venv /opt/treesitter \
    && /opt/treesitter/bin/pip install --no-cache-dir --no-index --find-links /mnt/lsp-vendor/wheels \
         --require-hashes -r /mnt/lsp-vendor/requirements/treesitter.txt \
    && /opt/treesitter/bin/python -c "import tree_sitter, tree_sitter_c, tree_sitter_python, tree_sitter_php" \
    && tree-sitter --version | grep -F "tree-sitter 0.26.13"

RUN useradd -m -u 10001 -s /bin/bash worker && mkdir -p /workspace /scratch && chown worker:worker /scratch
USER worker
WORKDIR /scratch
ENV PATH="/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
CMD ["/bin/bash"]
