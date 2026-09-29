# syntax=docker/dockerfile:1
# JS/TS build/LSP environment. Servers are installed with npm ci from lsp/package-lock.json
# (sha512 integrity per package). Pins: docs/language-servers.md (needs audit-lsp-vendor:local).
FROM node:22-bookworm@sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq ripgrep build-essential python3 python3-pip python3-venv \
      file gdb lldb strace ltrace binutils elfutils procps \
    && rm -rf /var/lib/apt/lists/*

COPY lsp/package.json lsp/package-lock.json /opt/node-lsp/
RUN cd /opt/node-lsp \
    && npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
    && for bin in tsc tsserver typescript-language-server eslint \
                  vscode-json-language-server vscode-css-language-server vscode-html-language-server \
                  vscode-eslint-language-server vscode-markdown-language-server; do \
         ln -s /opt/node-lsp/node_modules/.bin/$bin /usr/local/bin/$bin; \
       done \
    && typescript-language-server --version \
    && tsc --version | grep -F "Version 5.9.3" \
    && chmod -R a+rX /opt/node-lsp \
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
