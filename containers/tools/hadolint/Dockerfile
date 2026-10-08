# syntax=docker/dockerfile:1
# Migrated from the audited pre-simplification definition. Assets are fetched and
# verified by containers/build.py before this network-free build executes.
#
# tool-hadolint: Dockerfile lint (hadolint).
#
# One tool per image (docs/processes/tool-images.md). The tool's release assets are downloaded and
# verified on the host by `images/tool_pins.py pin tool-hadolint` (vendor checksums / signatures, recorded
# in pin-record.json) and fetched again, checksummed, by images/image_build.py into downloads/.
# Nothing is downloaded inside this build. Bases are pinned by digest. No ENTRYPOINT or CMD: the
# pinned-container adapter (B13) runs argv[0] as the entrypoint, read-only, --network none, as
# uid 10001 with HOME=/tmp. Update: bump "version" in tool.json and run `tool_pins.py pin`.

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS unpack
COPY downloads/hadolint /tmp/asset
RUN mkdir -p /opt/tool/bin && install -m 0755 /tmp/asset /opt/tool/bin/hadolint && chmod 0755 /opt/tool/bin/hadolint

FROM appsec-review/base-ubuntu:24.04
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-hadolint" org.opencontainers.image.version="${TOOL_VERSION}"
COPY --from=unpack /opt/tool/bin/hadolint /opt/tool/bin/hadolint
ENV PATH="/opt/tool/bin:${PATH}"
RUN /opt/tool/bin/hadolint --version 2>&1 | grep -F "${TOOL_VERSION}"
USER 10001
WORKDIR /scratch
