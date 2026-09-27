# syntax=docker/dockerfile:1
#
# tool-microsoft-sbom-tool: Microsoft SPDX SBOM generation, validation, redaction and aggregation.
#
# The release binary is downloaded and verified on the host by images/tool_pins.py against the
# SPDX release manifest Microsoft publishes beside it. Nothing is downloaded during this build.
# No ENTRYPOINT or CMD: B13 supplies argv[0] and runs the image offline, read-only, as uid 10001.

FROM mcr.microsoft.com/dotnet/runtime-deps:8.0-noble@sha256:a83f3565178daccf8974fd854aa8359a0f8aaec5bd2ea06e11159d476369a228
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-microsoft-sbom-tool" \
      org.opencontainers.image.version="${TOOL_VERSION}"
COPY downloads/sbom-tool /opt/tool/bin/sbom-tool
RUN chmod 0755 /opt/tool/bin/sbom-tool \
    && groupadd -g 10001 worker && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir -p /workspace /scratch && chown 10001:10001 /scratch \
    && /opt/tool/bin/sbom-tool --version 2>&1 | grep -F "${TOOL_VERSION}"
ENV PATH="/opt/tool/bin:${PATH}" \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_BUNDLE_EXTRACT_BASE_DIR=/tmp/.net \
    DOTNET_NOLOGO=1
USER 10001
WORKDIR /scratch
