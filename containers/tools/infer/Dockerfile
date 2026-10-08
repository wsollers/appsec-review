# syntax=docker/dockerfile:1
# Infer is acquired and hash-verified by containers/build.py. The build itself is offline.
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS unpack
COPY downloads/infer-linux-x86_64-v1.3.0.tar.xz /tmp/infer.tar.xz
RUN python -c "import tarfile; tarfile.open('/tmp/infer.tar.xz', 'r:xz').extractall('/opt', filter='data')" \
    && mv /opt/infer-linux-x86_64-v1.3.0 /opt/infer

FROM appsec-review/base-ubuntu:24.04
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-infer" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.licenses="MIT"
COPY --from=unpack /opt/infer /opt/infer
ENV PATH="/opt/infer/bin:${PATH}"
RUN /opt/infer/bin/infer --version 2>&1 | grep -F "Infer version v${TOOL_VERSION}"
USER 10001:10001
WORKDIR /scratch
