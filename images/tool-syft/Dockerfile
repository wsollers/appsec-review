# syntax=docker/dockerfile:1
#
# tool-syft: SBOM generation from manifests, lockfiles and vendored code (syft).
#
# One tool per image (docs/processes/tool-images.md). The tool's release assets are downloaded and
# verified on the host by `images/tool_pins.py pin tool-syft` (vendor checksums / signatures, recorded
# in pin-record.json) and fetched again, checksummed, by images/image_build.py into downloads/.
# Nothing is downloaded inside this build. Bases are pinned by digest. No ENTRYPOINT or CMD: the
# pinned-container adapter (B13) runs argv[0] as the entrypoint, read-only, --network none, as
# uid 10001 with HOME=/tmp. Update: bump "version" in tool.json and run `tool_pins.py pin`.

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS unpack
COPY downloads/syft.tar.gz /tmp/asset
RUN mkdir -p /opt/tool/bin && tar -xzf /tmp/asset -C /opt/tool/bin syft && chmod 0755 /opt/tool/bin/syft

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-syft" org.opencontainers.image.version="${TOOL_VERSION}"
COPY --from=unpack /opt/tool/bin/syft /opt/tool/bin/syft
ENV PATH="/opt/tool/bin:${PATH}" \
    SYFT_CHECK_FOR_APP_UPDATE=false
RUN groupadd -g 10001 worker && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir -p /workspace /scratch && chown 10001:10001 /scratch \
    && /opt/tool/bin/syft version 2>&1 | grep -F "${TOOL_VERSION}"
USER 10001
WORKDIR /scratch
