# syntax=docker/dockerfile:1
# The upstream PMD distribution is unpacked without package-manager access and
# copied into the repository's digest-pinned, non-root JRE runtime.
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS unpack
COPY downloads/pmd-dist-7.28.0-bin.zip /tmp/pmd.zip
RUN mkdir -p /opt/unpack \
    && python -m zipfile -e /tmp/pmd.zip /opt/unpack \
    && mv /opt/unpack/pmd-bin-* /opt/pmd \
    && chmod 0755 /opt/pmd/bin/pmd

FROM appsec-review/base-jre:21-noble
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-pmd" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.licenses="BSD-4-Clause"
COPY --from=unpack /opt/pmd /opt/pmd
ENV PATH="/opt/pmd/bin:${PATH}" HOME=/tmp
RUN pmd --version 2>&1 | grep -F "PMD ${TOOL_VERSION}"
USER 10001:10001
WORKDIR /scratch
