# syntax=docker/dockerfile:1
# Migrated from the audited pre-simplification definition. Assets are fetched and
# verified by containers/build.py before this network-free build executes.
FROM appsec-review/base-ubuntu:24.04
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-osv-scanner" org.opencontainers.image.version="${TOOL_VERSION}"
COPY --chmod=0755 downloads/osv-scanner /opt/tool/bin/osv-scanner
RUN /opt/tool/bin/osv-scanner --version 2>&1 | grep -F "${TOOL_VERSION}"
ENV PATH="/opt/tool/bin:${PATH}"
USER 10001
WORKDIR /scratch
