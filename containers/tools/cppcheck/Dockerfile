# syntax=docker/dockerfile:1
# Cppcheck is compiled from the hash-pinned upstream source archive in a
# digest-pinned compiler image. The build and runtime have no network access.
FROM gcc:15.2.0-bookworm@sha256:c74b2d34b775e6a1b14b13b1d41dc7233f62a18f7a6a4e139e0cf59eeab2e070 AS build
COPY downloads/cppcheck-2.22.0.tar.gz /tmp/cppcheck.tar.gz
RUN mkdir -p /src/cppcheck /opt/cppcheck/bin /opt/cppcheck/cfg \
    && tar -xzf /tmp/cppcheck.tar.gz --strip-components=1 -C /src/cppcheck \
    && make -C /src/cppcheck -j2 MATCHCOMPILER=yes FILESDIR=/opt/cppcheck \
       CXXFLAGS="-O2 -pipe -static-libstdc++ -static-libgcc" \
    && install -m 0755 /src/cppcheck/cppcheck /opt/cppcheck/bin/cppcheck \
    && cp -R /src/cppcheck/cfg/. /opt/cppcheck/cfg/

FROM appsec-review/base-ubuntu:24.04
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-cppcheck" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"
COPY --from=build /opt/cppcheck /opt/cppcheck
ENV PATH="/opt/cppcheck/bin:${PATH}" HOME=/tmp
RUN cppcheck --version 2>&1 | grep -F "Cppcheck ${TOOL_VERSION}"
USER 10001:10001
WORKDIR /scratch
