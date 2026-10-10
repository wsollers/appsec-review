# syntax=docker/dockerfile:1
# tool-git: read-only Git history queries for source history analysis.
#
# The asset is the Ubuntu 24.04 (noble-updates) git package from an immutable snapshot URL, fetched
# and verified by size and SHA-256 by containers/build.py before this network-free build executes.
# Only the git binary is extracted; it links against glibc, zlib, and PCRE2 already present in the
# shared Ubuntu base. Helper programs, perl scripts, remote helpers, and credential helpers are not
# installed. The job runs git with a sanitized GIT_DIR, --network none, read-only, as uid 10001.

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS unpack
COPY downloads/git.deb /tmp/git.deb
RUN dpkg-deb -x /tmp/git.deb /tmp/git \
    && install -D -m 0755 /tmp/git/usr/bin/git /opt/tool/bin/git

FROM appsec-review/base-ubuntu:24.04
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-git" org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.licenses="GPL-2.0-only"
COPY --from=unpack /opt/tool/bin/git /opt/tool/bin/git
ENV PATH="/opt/tool/bin:${PATH}"
RUN /opt/tool/bin/git --version | grep -F "git version ${TOOL_VERSION}"
USER 10001
WORKDIR /scratch
