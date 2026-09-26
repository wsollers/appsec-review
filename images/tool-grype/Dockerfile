# syntax=docker/dockerfile:1
#
# tool-grype: vulnerability matching of an SBOM against a mirrored, pinned Grype database (grype; ADR-0010 M1).
#
# One tool per image (docs/processes/tool-images.md). The tool's release assets are downloaded and
# verified on the host by `images/tool_pins.py pin tool-grype` (vendor checksums / signatures, recorded
# in pin-record.json) and fetched again, checksummed, by images/image_build.py into downloads/.
# Nothing is downloaded inside this build. Bases are pinned by digest. No ENTRYPOINT or CMD: the
# pinned-container adapter (B13) runs argv[0] as the entrypoint, read-only, --network none, as
# uid 10001 with HOME=/tmp. Update: bump "version" in tool.json and run `tool_pins.py pin`.

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS unpack
COPY downloads/grype.tar.gz /tmp/asset
RUN mkdir -p /opt/tool/bin && tar -xzf /tmp/asset -C /opt/tool/bin grype && chmod 0755 /opt/tool/bin/grype

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-grype" org.opencontainers.image.version="${TOOL_VERSION}"
COPY --from=unpack /opt/tool/bin/grype /opt/tool/bin/grype
ENV PATH="/opt/tool/bin:${PATH}" \
    GRYPE_CHECK_FOR_APP_UPDATE=false GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_VALIDATE_AGE=false
RUN groupadd -g 10001 worker && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir -p /workspace /scratch && chown 10001:10001 /scratch \
    && /opt/tool/bin/grype version 2>&1 | grep -F "${TOOL_VERSION}"
USER 10001
WORKDIR /scratch
