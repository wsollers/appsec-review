# syntax=docker/dockerfile:1
#
# audit-lsp-vendor — build-only image holding the per-version vendored language-tool dependencies
# shared by the compiler images (docs/language-servers.md §3). Consumers read it with
#   RUN --mount=type=bind,from=audit-lsp-vendor:local,source=/opt/lsp-vendor,target=/mnt/lsp-vendor
# so nothing here becomes a layer of theirs. It is never run against a target and has no B16 record.
#
#   /opt/lsp-vendor/bin/tree-sitter        tree-sitter CLI, cargo install --locked (crates.io checksums)
#   /opt/lsp-vendor/wheels/                py-tree-sitter + 13 grammars (CPython 3.11-3.14) and clangd,
#                                          downloaded with --require-hashes against the committed locks
#   /opt/lsp-vendor/requirements/*.txt     the hash locks consumers install with (--no-index)
#
# Regenerate a lock (network needed, outside the image):
#   uv pip compile requirements-treesitter.in --universal --python-version 3.10 --generate-hashes \
#     --no-header -o requirements-treesitter.txt
#   uv pip compile requirements-clangd.in --universal --generate-hashes --no-header -o requirements-clangd.txt

FROM rust:1.90.0-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f AS cli
ARG TREE_SITTER_CLI_VERSION=0.26.13
RUN cargo install --locked tree-sitter-cli --version "${TREE_SITTER_CLI_VERSION}" --root /opt/ts \
    && /opt/ts/bin/tree-sitter --version | grep -Fx "tree-sitter ${TREE_SITTER_CLI_VERSION}"

FROM python:3.12-bookworm@sha256:dbbe4ceb97851e2e5fa83798b239811f871cb743b259ba3563737349f6bcfaa0
COPY requirements-treesitter.txt /opt/lsp-vendor/requirements/treesitter.txt
COPY requirements-clangd.txt /opt/lsp-vendor/requirements/clangd.txt
RUN set -eu; \
    for py in 3.11 3.12 3.13 3.14; do \
      pip download --no-cache-dir --require-hashes --only-binary=:all: --no-deps \
        --implementation cp --python-version "$py" \
        --platform manylinux_2_28_x86_64 --platform manylinux_2_17_x86_64 --platform manylinux2014_x86_64 \
        -d /opt/lsp-vendor/wheels -r /opt/lsp-vendor/requirements/treesitter.txt; \
    done; \
    pip download --no-cache-dir --require-hashes --only-binary=:all: --no-deps \
      --python-version 3.12 --platform manylinux_2_28_x86_64 \
      -d /opt/lsp-vendor/wheels -r /opt/lsp-vendor/requirements/clangd.txt; \
    cd /opt/lsp-vendor/wheels && sha256sum *.whl | sort -k2 > SHA256SUMS; \
    test "$(ls *.whl | wc -l)" -ge 18
COPY --from=cli /opt/ts/bin/tree-sitter /opt/lsp-vendor/bin/tree-sitter
RUN /opt/lsp-vendor/bin/tree-sitter --version \
    && python3 -m venv /tmp/probe \
    && /tmp/probe/bin/pip install --no-cache-dir --no-index --find-links /opt/lsp-vendor/wheels \
         --require-hashes -r /opt/lsp-vendor/requirements/treesitter.txt \
    && /tmp/probe/bin/python -c "import tree_sitter, tree_sitter_c, tree_sitter_php; print('tree-sitter', tree_sitter.LANGUAGE_VERSION)" \
    && rm -rf /tmp/probe \
    && chmod -R a+rX /opt/lsp-vendor
CMD ["/opt/lsp-vendor/bin/tree-sitter", "--version"]
