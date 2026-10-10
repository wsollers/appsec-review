# syntax=docker/dockerfile:1
# Assets are fetched and verified by containers/build.py before this network-free build executes.
#
# tool-opengrep: OpenGrep engine for the portable SEI CERT rule pack (rules/sei-cert). Rules are not
# in the image; they are mounted read-only per run after pack.lock.json verification.
#
# The upstream release is a self-extracting launcher that unpacks about 250 MB into XDG_CACHE_HOME
# and rewrites that payload on every start. Runtime /tmp is a 128 MB noexec tmpfs and the root
# filesystem is read-only, so the payload is extracted once here, by a scan of a trivial built-in
# fixture, and the extracted opengrep.bin is executed directly. OpenGrep only needs an existing,
# writable XDG_CONFIG_HOME for its log, which the runtime /tmp tmpfs provides.

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS unpack
ARG TOOL_VERSION
COPY --chmod=0755 downloads/opengrep /tmp/opengrep
RUN mkdir -p /tmp/warm /opt/extract \
    && printf 'int f(void) { return 0; }\n' > /tmp/warm/warm.c \
    && printf 'rules:\n  - id: warm\n    languages: [c]\n    severity: INFO\n    message: warm\n    pattern: f()\n' > /tmp/warm/warm.yml \
    && HOME=/tmp/warm XDG_CONFIG_HOME=/tmp/warm XDG_CACHE_HOME=/opt/extract \
       /tmp/opengrep scan --disable-version-check --json --config /tmp/warm/warm.yml /tmp/warm/warm.c > /dev/null \
    && test -x "/opt/extract/opengrep/v${TOOL_VERSION}/opengrep.bin" \
    && mv "/opt/extract/opengrep/v${TOOL_VERSION}" /opt/opengrep \
    && chmod -R a+rX,go-w /opt/opengrep

FROM appsec-review/base-ubuntu:24.04
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-opengrep" org.opencontainers.image.version="${TOOL_VERSION}"
COPY --from=unpack /opt/opengrep /opt/tool/opengrep
ENV XDG_CONFIG_HOME=/tmp \
    XDG_CACHE_HOME=/tmp
RUN HOME=/tmp /opt/tool/opengrep/opengrep.bin --version 2>&1 | grep -F "${TOOL_VERSION}"
USER 10001
WORKDIR /scratch
