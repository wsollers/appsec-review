# syntax=docker/dockerfile:1
# Migrated from the audited pre-simplification definition. Assets are fetched and
# verified by containers/build.py before this network-free build executes.
#
# tool-gosec: Go source SAST (gosec), with the Go toolchain it needs to load packages.
#
# One tool per image (docs/processes/tool-images.md). The tool's release assets are downloaded and
# verified on the host by `images/tool_pins.py pin tool-gosec` (vendor checksums / signatures, recorded
# in pin-record.json) and fetched again, checksummed, by images/image_build.py into downloads/.
# Nothing is downloaded inside this build. Bases are pinned by digest. No ENTRYPOINT or CMD: the
# pinned-container adapter (B13) runs argv[0] as the entrypoint, read-only, --network none, as
# uid 10001 with HOME=/tmp. Update: bump "version" in tool.json and run `tool_pins.py pin`.
#
# Bundled: the Go toolchain. gosec loads packages through `go list`; without it gosec cannot
# type-check. GOPROXY=off and GOFLAGS=-mod=mod keep it offline: modules not vendored or in the
# module cache are a load error, reported, never fetched.

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS unpack
COPY downloads/gosec.tar.gz /tmp/gosec.tar.gz
COPY downloads/go.tar.gz /tmp/go.tar.gz
RUN mkdir -p /opt/tool/bin && tar -xzf /tmp/gosec.tar.gz -C /opt/tool/bin gosec && chmod 0755 /opt/tool/bin/gosec \
    && tar -xzf /tmp/go.tar.gz -C /opt

FROM appsec-review/base-ubuntu:24.04
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-gosec" org.opencontainers.image.version="${TOOL_VERSION}"
COPY --from=unpack /opt/tool/bin/gosec /opt/tool/bin/gosec
COPY --from=unpack /opt/go /opt/go
ENV PATH="/opt/tool/bin:/opt/go/bin:${PATH}" \
    GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=mod GOTELEMETRY=off \
    GOPATH=/tmp/go GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go/pkg/mod
RUN gosec -version 2>&1 | grep -F "${TOOL_VERSION}" && go version
USER 10001
WORKDIR /scratch
