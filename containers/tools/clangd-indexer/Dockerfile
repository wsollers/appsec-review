# clangd-indexer is acquired and hash-verified by containers/build.py. This build runs with
# --network=none: no installer, package manager, or download is used.
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS unpack
ARG TOOL_VERSION
ARG CLANGD_SHA512
COPY downloads/clangd_indexing_tools-linux-23.1.0.zip /tmp/clangd.zip
COPY --from=shared safe_extract.py /opt/review/
COPY tool.toml assets.lock.json inventory.json /opt/review/
# Upstream publishes no checksum, so the archive is checked against the reviewer-recorded SHA-512
# build argument. safe_extract.py then re-verifies size, SHA-256, and SHA-512 against
# assets.lock.json, rejects unsafe members, installs only the reviewed closure, and requires the
# result to equal the committed inventory.
RUN set -eu; \
    test "${#CLANGD_SHA512}" -eq 128; \
    echo "${CLANGD_SHA512}  /tmp/clangd.zip" | sha512sum --check --strict -; \
    python -I /opt/review/safe_extract.py /tmp/clangd.zip /opt/clangd \
        --policy /opt/review/tool.toml --lock /opt/review/assets.lock.json \
        --expect-inventory /opt/review/inventory.json; \
    cp /opt/review/inventory.json /opt/clangd/inventory.json; \
    rm -f /tmp/clangd.zip

FROM appsec-review/base-ubuntu:24.04
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-clangd-indexer" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0 WITH LLVM-exception"
COPY --from=unpack /opt/clangd /opt/clangd
ENV PATH="/opt/clangd/clangd_23.1.0/bin:${PATH}" HOME=/tmp
RUN /opt/clangd/clangd_23.1.0/bin/clangd-indexer --version | grep -F "LLVM version ${TOOL_VERSION}"
USER 10001:10001
WORKDIR /scratch
