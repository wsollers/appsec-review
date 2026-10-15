# syntax=docker/dockerfile:1
# Go build environment on the shared native toolchain (cgo compiles with the same gcc).
# GOTOOLCHAIN=local forbids silent toolchain downloads requested by a target go.mod; a
# module that needs a newer Go fails visibly instead of executing an unpinned compiler.
FROM appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1
LABEL org.opencontainers.image.title="audit-buildenv-go" \
      org.opencontainers.image.version="noble-go1.23.1"
USER 0:0
RUN apt-get update \
 && apt-get install -y --no-install-recommends golang-1.23-go=1.23.1-1~24.04.1 \
 && rm -rf /var/lib/apt/lists/* \
 && sh /opt/native-toolchain/check-toolchain.sh \
 && /usr/lib/go-1.23/bin/go version | grep -F 'go1.23.1 linux/amd64'
ENV GOTOOLCHAIN=local \
    PATH=/usr/lib/go-1.23/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /workspace
