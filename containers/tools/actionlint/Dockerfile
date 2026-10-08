# syntax=docker/dockerfile:1
# The release archive is fetched and SHA-256 verified by containers/build.py before
# this network-free image build. Runtime execution is separately forced offline.
FROM appsec-review/base-ubuntu:24.04
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-actionlint" org.opencontainers.image.version="${TOOL_VERSION}"
ADD downloads/actionlint_1.7.12_linux_amd64.tar.gz /opt/actionlint/
RUN test -x /opt/actionlint/actionlint \
    && /opt/actionlint/actionlint -version 2>&1 | grep -F "${TOOL_VERSION}"
USER 10001
WORKDIR /scratch
