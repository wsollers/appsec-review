# syntax=docker/dockerfile:1
# Infer is acquired and hash-verified by containers/build.py. The build itself is offline.
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS unpack
COPY downloads/infer-linux-x86_64-v1.3.0.tar.xz /tmp/infer.tar.xz
RUN python -c "import tarfile; tarfile.open('/tmp/infer.tar.xz', 'r:xz').extractall('/opt', filter='data')" \
    && mv /opt/infer-linux-x86_64-v1.3.0 /opt/infer

# Infer's bundled clang parses each captured translation unit against the system C/C++ headers
# (/usr/include, libstdc++). base-ubuntu has none, so every unit failed with "'stdio.h' file not
# found". tool-native-cpp is the C/C++ replay image: it carries the system headers plus the PHP and
# Python development headers at the build environments' pins, so Infer resolves every captured
# include (including phpize and setuptools extension compiles) exactly as the replays do.
FROM appsec-review/tool-native-cpp:1.0.0
USER 0
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-infer" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.licenses="MIT"
COPY --from=unpack /opt/infer /opt/infer
ENV PATH="/opt/infer/bin:${PATH}"
RUN /opt/infer/bin/infer --version 2>&1 | grep -F "Infer version v${TOOL_VERSION}" \
    && test -f /usr/include/stdio.h \
    && test -d /usr/include/c++/13 \
    && test -f /usr/include/python3.12/Python.h \
    && test -f /usr/include/php/20230831/main/php.h
USER 10001:10001
WORKDIR /scratch
