# Joern is acquired and hash-verified by containers/build.py. This build runs with --network=none:
# no installer, package manager, Maven, SBT, or runtime dependency resolution is used.
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS unpack
ARG TOOL_VERSION
ARG JOERN_SHA512
COPY downloads/joern-cli-linux-x86_64-v4.0.630.zip /tmp/joern.zip
COPY downloads/joern-cli-linux-x86_64-v4.0.630.zip.sha512 /tmp/joern.zip.sha512
COPY safe_extract.py tool.toml assets.lock.json inventory.json /opt/review/
# The upstream SHA-512 sidecar must name the platform archive and agree with the pinned build
# argument before the archive is checked. safe_extract.py then re-verifies size, SHA-256, and
# SHA-512 against assets.lock.json, rejects unsafe members, installs only the reviewed closure, and
# requires the result to equal the committed inventory byte-for-byte.
RUN set -eu; \
    test "${#JOERN_SHA512}" -eq 128; \
    read -r sidecar_hash sidecar_name < /tmp/joern.zip.sha512; \
    test "$sidecar_hash" = "$JOERN_SHA512"; \
    test "${sidecar_name##*/}" = "joern-cli-linux-x86_64.zip"; \
    echo "${JOERN_SHA512}  /tmp/joern.zip" | sha512sum --check --strict -; \
    python -I /opt/review/safe_extract.py /tmp/joern.zip /opt/joern \
        --policy /opt/review/tool.toml --lock /opt/review/assets.lock.json \
        --expect-inventory /opt/review/inventory.json --version-file /opt/joern/VERSION; \
    grep -Fx "joern-cli ${TOOL_VERSION}" /opt/joern/VERSION; \
    grep -Fx "c2cpg ${TOOL_VERSION}" /opt/joern/VERSION; \
    cp /opt/review/inventory.json /opt/joern/inventory.json; \
    rm -f /tmp/joern.zip /tmp/joern.zip.sha512

FROM appsec-review/base-jre:21-noble
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-joern" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=unpack /opt/joern /opt/joern
COPY --chmod=0555 joern-version /opt/joern/bin/joern-version
ENV PATH="/opt/joern/bin:/opt/joern/joern-cli:${PATH}" HOME=/tmp
RUN /opt/joern/bin/joern-version | grep -Fx "c2cpg ${TOOL_VERSION}"
USER 10001:10001
WORKDIR /scratch
