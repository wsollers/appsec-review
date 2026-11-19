# syntax=docker/dockerfile:1
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
ARG DEBIAN_FRONTEND=noninteractive
ARG TOOL_VERSION=6.11.0
LABEL org.opencontainers.image.title="tool-cbmc" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.source="https://github.com/diffblue/cbmc" \
      org.opencontainers.image.licenses="BSD-4-Clause AND MIT"
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Acquisition verifies the release and the complete APT closure before this offline install.
RUN --mount=type=bind,source=downloads,target=/assets \
    mkdir /tmp/debs \
    && tar -xf /assets/cbmc-debs.tar -C /tmp/debs \
    && cp /tmp/debs/*.deb /var/cache/apt/archives/ \
    && apt-get install -y --no-download --no-install-recommends /tmp/debs/*.deb \
    && dpkg --install /assets/cbmc.deb \
    && install -D -m 0444 /assets/LICENSE-CBMC /usr/share/doc/cbmc/LICENSE \
    && tar -xOf /assets/minisat2_2.2.1.orig.tar.gz minisat2-2.2.1/LICENSE \
       > /usr/share/doc/cbmc/LICENSE-MINISAT \
    && rm -rf /tmp/debs /var/lib/apt/lists/* /var/cache/apt/archives/*.deb
RUN cbmc --version | cut -d ' ' -f 1 | grep -Fx "${TOOL_VERSION}" \
    && goto-cc --version \
    && goto-instrument --version | cut -d ' ' -f 1 | grep -Fx "${TOOL_VERSION}" \
    && gcc --version \
    && g++ --version \
    && cmake --version \
    && ninja --version \
    && python3 --version \
    && groupadd -g 10001 worker \
    && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir /scratch \
    && chown 10001:10001 /scratch
ENV HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
USER 10001:10001
WORKDIR /scratch
ENTRYPOINT []
CMD ["cbmc", "--help"]
