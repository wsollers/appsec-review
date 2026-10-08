# syntax=docker/dockerfile:1
# Shared non-root runtime boundary; intentionally contains no analysis tools.
FROM php:8.4-cli-bookworm@sha256:f1d32fb402fffba0b3dd8ba8c0aca474c9e9f04395fa846eedea77c503257dee
LABEL org.opencontainers.image.title="base-php" \
      org.opencontainers.image.version="8.4-bookworm"
RUN groupadd -g 10001 worker \
    && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir -p /workspace /scratch \
    && chown 10001:10001 /scratch
ENV HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /scratch
