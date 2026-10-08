# syntax=docker/dockerfile:1
# Migrated from the audited pre-simplification definition. Assets are fetched and
# verified by containers/build.py before this network-free build executes.
#
# tool-phpstan: PHP static analysis (PHPStan).
#
# One tool per image (docs/processes/tool-images.md). The tool's release assets are downloaded and
# verified on the host by `images/tool_pins.py pin tool-phpstan` (vendor checksums / signatures, recorded
# in pin-record.json) and fetched again, checksummed, by images/image_build.py into downloads/.
# Nothing is downloaded inside this build. Bases are pinned by digest. No ENTRYPOINT or CMD: the
# pinned-container adapter (B13) runs argv[0] as the entrypoint, read-only, --network none, as
# uid 10001 with HOME=/tmp. Update: bump "version" in tool.json and run `tool_pins.py pin`.

FROM appsec-review/base-php:8.4-bookworm
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-phpstan" org.opencontainers.image.version="${TOOL_VERSION}"
COPY --chmod=0755 downloads/phpstan.phar /opt/tool/bin/phpstan
ENV PATH="/opt/tool/bin:${PATH}"
RUN /opt/tool/bin/phpstan --version 2>&1 | grep -F "${TOOL_VERSION}"
USER 10001
WORKDIR /scratch
