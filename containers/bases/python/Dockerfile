# syntax=docker/dockerfile:1
# Shared non-root runtime boundary; intentionally contains no analysis tools.
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e
LABEL org.opencontainers.image.title="base-python" \
      org.opencontainers.image.version="3.12-bookworm"
RUN groupadd -g 10001 worker \
    && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir -p /workspace /scratch \
    && chown 10001:10001 /scratch
ENV HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /scratch
