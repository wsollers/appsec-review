# syntax=docker/dockerfile:1
# The exact 166-package closure is acquired separately, recorded in assets.lock.json,
# and supplied from the ignored downloads cache. Docker dependency resolution is offline.
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS build
ARG DEBIAN_FRONTEND=noninteractive
COPY downloads/native-cpp-debs.tar /tmp/native-cpp-debs.tar
RUN mkdir /tmp/debs \
    && tar -xf /tmp/native-cpp-debs.tar -C /tmp/debs \
    && cp /tmp/debs/*.deb /var/cache/apt/archives/ \
    && apt-get install -y --no-download /tmp/debs/*.deb \
    && rm -rf /tmp/debs /tmp/native-cpp-debs.tar /var/lib/apt/lists/*

FROM build AS runtime
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-native-cpp" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0 AND NCSA AND GPL-3.0-or-later"
RUN groupadd -g 10001 worker \
    && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir -p /scratch /opt/appsec \
    && chown 10001:10001 /scratch
COPY native.py /opt/appsec/native.py
RUN chmod 0555 /opt/appsec/native.py \
    && clang-18 --version | grep -F 'clang version 18' \
    && cmake --version | grep -F '3.28' \
    && bear --version | grep -F '3.1.3'
ENV HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC CC=clang-18 CXX=clang++-18
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /scratch
