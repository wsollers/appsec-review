# syntax=docker/dockerfile:1
# Java build/LSP environment. Pins and install methods: docs/language-servers.md (needs audit-lsp-vendor:local).
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

ARG DEBIAN_FRONTEND=noninteractive
ARG NODE_MAJOR=22
ARG JDTLS_VERSION=1.61.0-202609031315
ENV LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git unzip zip jq ripgrep build-essential \
      gnupg \
      file gdb lldb strace ltrace binutils elfutils procps \
      python3 python3-pip python3-venv \
      maven gradle \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor -o /usr/share/keyrings/adoptium.gpg \
    && . /etc/os-release \
    && echo "deb [signed-by=/usr/share/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb ${VERSION_CODENAME} main" > /etc/apt/sources.list.d/adoptium.list \
    && curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends temurin-25-jdk nodejs \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/temurin-25-jdk-amd64

# Eclipse JDT LS milestone, vendored by image.json's prebuild download (host side, sha256-checked
# there and again here). Host fetch if building by hand:
#   curl -L -o images/audit-buildenv-java/jdtls.tar.gz \
#     https://download.eclipse.org/jdtls/milestones/1.61.0/jdt-language-server-1.61.0-202609031315.tar.gz
COPY jdtls.tar.gz /tmp/jdtls.tar.gz
RUN echo "338e7e73d61836651ba2453919a0d34fa763eb4e7c03342092309bffb8934c64  /tmp/jdtls.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/jdtls \
    && tar -xzf /tmp/jdtls.tar.gz -C /opt/jdtls \
    && rm /tmp/jdtls.tar.gz \
    && chmod -R a+rX /opt/jdtls \
    && test -x /opt/jdtls/bin/jdtls \
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
ENV PATH="/opt/jdtls/bin:${PATH}"
CMD ["/bin/bash"]
