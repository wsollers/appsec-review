# syntax=docker/dockerfile:1
# PHP LSP environment. Pins and install methods: docs/language-servers.md (needs audit-lsp-vendor:local).
FROM composer:2.8.12@sha256:5248900ab8b5f7f880c2d62180e40960cd87f60149ec9a1abfd62ac72a02577c AS composer

FROM php:8.3-cli-bookworm@sha256:4687aec76c4a895b68b91bcd5e48f1ba7a3dea120f6de50bba7e1a93af5372dd

ARG NODE_MAJOR=22
ARG PHPACTOR_VERSION=2026.07.22.0
ENV COMPOSER_HOME=/opt/composer
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq ripgrep unzip zip build-essential gnupg python3 python3-pip python3-venv \
      file gdb lldb strace ltrace binutils elfutils procps \
    && curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer /usr/bin/composer /usr/local/bin/composer
# Phpactor at a release tag; create-project installs from Phpactor's own composer.lock (dist
# checksums where Packagist records them), no dev dependencies, no plugins or scripts.
RUN docker-php-ext-install pcntl \
    && mkdir -p "${COMPOSER_HOME}" \
    && composer create-project --no-dev --no-interaction --prefer-dist --no-plugins --no-scripts \
         "phpactor/phpactor:${PHPACTOR_VERSION}" /opt/phpactor \
    && test -f /opt/phpactor/composer.lock \
    && ln -s /opt/phpactor/bin/phpactor /usr/local/bin/phpactor \
    && chmod -R a+rX /opt/phpactor \
    && phpactor --version \
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
ENV PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
CMD ["/bin/bash"]
