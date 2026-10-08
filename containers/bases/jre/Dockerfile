# syntax=docker/dockerfile:1
# Shared non-root runtime boundary; intentionally contains no analysis tools.
FROM eclipse-temurin:21-jre-noble@sha256:7edbe8532195c8222735caca437e56780e1fc7db08a4b4b4af77fe188cccc15f
LABEL org.opencontainers.image.title="base-jre" \
      org.opencontainers.image.version="21-noble"
RUN groupadd -g 10001 worker \
    && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir -p /workspace /scratch \
    && chown 10001:10001 /scratch
ENV HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /scratch
