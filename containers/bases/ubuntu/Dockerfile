# syntax=docker/dockerfile:1
# Shared non-root runtime boundary; intentionally contains no analysis tools.
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
LABEL org.opencontainers.image.title="base-ubuntu" \
      org.opencontainers.image.version="24.04"
RUN groupadd -g 10001 worker \
    && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir -p /workspace /scratch \
    && chown 10001:10001 /scratch
ENV HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /scratch
