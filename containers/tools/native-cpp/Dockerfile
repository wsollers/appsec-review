# syntax=docker/dockerfile:1
# The exact package closure is acquired by acquire_assets.sh, recorded in assets.lock.json and
# packages.manifest, and supplied from the ignored downloads cache. Docker dependency resolution is offline.
# The closure carries the PHP 8.3 and Python 3.12 development headers that buildenv-php and
# buildenv-python install, so their captured extension compiles replay against the same include paths.
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
    && /usr/bin/llvm-dwarfdump-18 --version | grep -F '18.1.3' \
    && /usr/bin/llvm-pdbutil-18 --version | grep -F '18.1.3' \
    && /usr/bin/python3 --version | grep -F 'Python 3.12.3' \
    && cmake --version | grep -F '3.28' \
    && bear --version | grep -F '3.1.3' \
    && test -f /usr/include/php/20230831/main/php.h \
    && test -f /usr/include/php/20230831/Zend/zend.h \
    && php-config8.3 --version | grep -Fx '8.3.6' \
    && php-config8.3 --includes | grep -F -- '-I/usr/include/php/20230831 -I/usr/include/php/20230831/main' \
    && test -f /usr/include/python3.12/Python.h \
    && test -f /usr/include/x86_64-linux-gnu/python3.12/pyconfig.h \
    && python3.12-config --includes | grep -F -- '-I/usr/include/python3.12' \
    && printf '#include <Python.h>\nint f(void){return PY_MAJOR_VERSION;}\n' \
       | clang-18 -fsyntax-only -I/usr/include/python3.12 -x c - \
    && printf '#include <php.h>\nint f(void){return PHP_MAJOR_VERSION;}\n' \
       | clang-18 -fsyntax-only $(php-config8.3 --includes) -x c -
ENV HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC CC=clang-18 CXX=clang++-18
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /scratch
