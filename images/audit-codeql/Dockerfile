# syntax=docker/dockerfile:1
#
# audit-codeql — CodeQL CLI + bundled query packs for pre-engagement evidence gathering.
#
# Role (ADR-0006): broad security-extended query suites across the languages CodeQL
# supports, run offline from the bundle (query packs included, no `codeql pack download`
# at run time). It is NOT the native memory-safety substrate (ADR-0001); C/C++ is
# extracted with --build-mode none by default because the C++ extractor's clang-cl
# support is documented as preliminary. Traced builds are opt-in (see run-codeql.sh).
#
# LICENSE GATE: the CodeQL CLI is licensed for open-source and academic use; use on
# proprietary code in a commercial engagement requires GitHub Advanced Security.
# run-codeql.sh refuses to run unless CODEQL_LICENSE_BASIS is set (oss | academic | ghas)
# and records the value in the run manifest. This is deliberately not defaultable.
#
# Pins (verified 2026-09-12): codeql-bundle-v2.27.0 (github/codeql-action releases,
# linux64, 553 MB zst; bundle == CLI + codeql/*-queries packs at matching versions).

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
ARG DEBIAN_FRONTEND=noninteractive
ARG CODEQL_BUNDLE=codeql-bundle-v2.27.0

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl zstd git python3 python3-pip python3-venv \
      openjdk-21-jre-headless nodejs libicu74 \
    && rm -rf /var/lib/apt/lists/*

# .NET SDK for C# --build-mode none (CodeQL resolves references with `dotnet`; ADR-0017 consequence 2).
# Copied from the digest-pinned Microsoft SDK image for the same Ubuntu release (noble).
COPY --from=mcr.microsoft.com/dotnet/sdk:9.0.318-noble@sha256:0f97a4002de8050867e7e55e03a0487aea4f4a933158fe1d2cc35f570fc81a0d \
     /usr/share/dotnet /usr/share/dotnet
ENV DOTNET_ROOT=/usr/share/dotnet \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
RUN ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
    && HOME=/tmp dotnet --list-sdks | grep -E '^9\.0\.318 '

# --- tree-sitter CLI + py-tree-sitter/grammars, vendored in audit-lsp-vendor (docs/language-servers.md §3).
RUN --mount=type=bind,from=audit-lsp-vendor:local,source=/opt/lsp-vendor,target=/mnt/lsp-vendor \
    install -m 0755 /mnt/lsp-vendor/bin/tree-sitter /usr/local/bin/tree-sitter \
    && python3 -m venv /opt/treesitter \
    && /opt/treesitter/bin/pip install --no-cache-dir --no-index --find-links /mnt/lsp-vendor/wheels \
         --require-hashes -r /mnt/lsp-vendor/requirements/treesitter.txt \
    && /opt/treesitter/bin/python -c "import tree_sitter, tree_sitter_c, tree_sitter_python, tree_sitter_php" \
    && tree-sitter --version | grep -F "tree-sitter 0.26.13"

# The bundle is downloaded on the host and COPY'd in — an in-build curl of 553 MB has no
# progress and one dropped connection fails the layer (2026-09-12). Host side:
#   curl -L -C - -o images/audit-codeql/codeql-bundle-linux64.tar.zst \
#     https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.0/codeql-bundle-linux64.tar.zst
# Expected: 553280102 bytes, sha256 5e0f04bcb92c0c0973b6f5597e55316269051fa98bda3f725d8af9a85016721a
# (the file is .gitignored; it is a build input like the MSVC headers, not source).
# chmod: the bundle ships precompiled query plans (.codeql/precompiled/*.qlx) readable by root only.
# The lanes run as a non-root uid, so without it every query is recompiled from source, which needs
# several GB of heap and ran out of memory at 2 GB (2026-09-30, smoke_codeql_per_language.sh).
COPY codeql-bundle-linux64.tar.zst /opt/bundle.tar.zst
RUN cd /opt \
    && echo "5e0f04bcb92c0c0973b6f5597e55316269051fa98bda3f725d8af9a85016721a  bundle.tar.zst" | sha256sum -c - \
    && tar --zstd -xf bundle.tar.zst && rm bundle.tar.zst \
    && chmod -R a+rX /opt/codeql \
    && /opt/codeql/codeql version --format=json \
    && /opt/codeql/codeql resolve languages
ENV CODEQL_LICENSE_BASIS=ghas \
    PATH="/opt/codeql:${PATH}" \
    CODEQL_BUNDLE=${CODEQL_BUNDLE}


# --- Repo-owned scripts, kept LAST so editing them rebuilds only this layer.
COPY scripts/ /opt/scripts/
RUN chmod +x /opt/scripts/*

RUN useradd -m -u 10001 -s /bin/bash worker && mkdir -p /workspace /scratch && chown worker:worker /scratch
USER worker
WORKDIR /scratch
CMD ["/bin/bash"]
