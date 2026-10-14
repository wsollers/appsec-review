# syntax=docker/dockerfile:1
# The compiler and shared LLVM libraries come from the hash-locked native image. The exact
# clang-tidy package closure is fetched and hash-verified by containers/build.py; installation is
# offline and cannot resolve or download additional packages.
FROM appsec-review/tool-native-cpp:1.0.0
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-clang-static-analysis" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0 WITH LLVM-exception"
USER 0
COPY downloads/*.deb /tmp/debs/
COPY clang-static.py /opt/appsec/clang-static.py
RUN dpkg --install /tmp/debs/*.deb \
    && rm -rf /tmp/debs /var/lib/apt/lists/* \
    && chmod 0555 /opt/appsec/clang-static.py \
    && clang-tidy-18 --version | grep -F 'LLVM version 18' \
    && clang-18 --version | grep -F 'clang version 18' \
    && /opt/appsec/clang-static.py version | grep -F "appsec-clang-static ${TOOL_VERSION}"
USER 10001:10001
WORKDIR /scratch
