# syntax=docker/dockerfile:1
#
# tool-phpstan: PHP static analysis (PHPStan).
#
# One tool per image (docs/processes/tool-images.md). The tool's release assets are downloaded and
# verified on the host by `images/tool_pins.py pin tool-phpstan` (vendor checksums / signatures, recorded
# in pin-record.json) and fetched again, checksummed, by images/image_build.py into downloads/.
# Nothing is downloaded inside this build. Bases are pinned by digest. No ENTRYPOINT or CMD: the
# pinned-container adapter (B13) runs argv[0] as the entrypoint, read-only, --network none, as
# uid 10001 with HOME=/tmp. Update: bump "version" in tool.json and run `tool_pins.py pin`.

FROM php:8.4-cli-bookworm@sha256:f1d32fb402fffba0b3dd8ba8c0aca474c9e9f04395fa846eedea77c503257dee
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-phpstan" org.opencontainers.image.version="${TOOL_VERSION}"
COPY --chmod=0755 downloads/phpstan.phar /opt/tool/bin/phpstan
ENV PATH="/opt/tool/bin:${PATH}"
RUN groupadd -g 10001 worker && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir -p /workspace /scratch && chown 10001:10001 /scratch \
    && /opt/tool/bin/phpstan --version 2>&1 | grep -F "${TOOL_VERSION}"
USER 10001
WORKDIR /scratch
