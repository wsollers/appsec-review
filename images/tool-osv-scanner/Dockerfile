# syntax=docker/dockerfile:1
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-osv-scanner" org.opencontainers.image.version="${TOOL_VERSION}"
COPY downloads/osv-scanner /opt/tool/bin/osv-scanner
RUN chmod 0755 /opt/tool/bin/osv-scanner \
    && groupadd -g 10001 worker && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir -p /workspace /scratch && chown 10001:10001 /scratch \
    && /opt/tool/bin/osv-scanner --version 2>&1 | grep -F "${TOOL_VERSION}"
ENV PATH="/opt/tool/bin:${PATH}"
USER 10001
WORKDIR /scratch
