# syntax=docker/dockerfile:1
# Python build/LSP environment. Pins and install methods: docs/language-servers.md (needs audit-lsp-vendor:local).
FROM python:3.12-bookworm@sha256:dbbe4ceb97851e2e5fa83798b239811f871cb743b259ba3563737349f6bcfaa0

ARG NODE_MAJOR=22
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq ripgrep build-essential gnupg python3-venv \
      file gdb lldb strace ltrace binutils elfutils procps \
    && curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# pylsp + basedpyright (+ debugpy, ruff, pytest) from a hash lock: lsp/requirements-lsp.txt.
COPY lsp/requirements-lsp.txt /opt/python-lsp/requirements-lsp.txt
RUN pip install --no-cache-dir --require-hashes -r /opt/python-lsp/requirements-lsp.txt \
    && pylsp --version \
    && basedpyright --version \
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
CMD ["/bin/bash"]
