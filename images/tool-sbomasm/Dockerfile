# syntax=docker/dockerfile:1
#
# tool-sbomasm: offline semantic assembly, editing and redaction of SPDX/CycloneDX SBOMs.
#
# images/tool_pins.py downloads the release archive on the host and verifies it against the
# vendor-published SHA-256 list. Nothing is downloaded during this build. No ENTRYPOINT or CMD:
# B13 supplies argv[0] and runs the image offline, read-only, as uid 10001.

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS unpack
COPY downloads/sbomasm.tar.gz /tmp/sbomasm.tar.gz
RUN mkdir -p /opt/tool/bin \
    && tar -xzf /tmp/sbomasm.tar.gz -C /opt/tool/bin sbomasm \
    && chmod 0755 /opt/tool/bin/sbomasm

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-sbomasm" \
      org.opencontainers.image.version="${TOOL_VERSION}"
COPY --from=unpack /opt/tool/bin/sbomasm /opt/tool/bin/sbomasm
ENV PATH="/opt/tool/bin:${PATH}"
RUN groupadd -g 10001 worker && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir -p /workspace /scratch && chown 10001:10001 /scratch \
    && /opt/tool/bin/sbomasm version 2>&1 | grep -F "${TOOL_VERSION}"
USER 10001
WORKDIR /scratch
