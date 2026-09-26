# syntax=docker/dockerfile:1
#
# tool-spotbugs: JVM bytecode SAST (SpotBugs) with the Find Security Bugs plugin.
#
# One tool per image (docs/processes/tool-images.md). The tool's release assets are downloaded and
# verified on the host by `images/tool_pins.py pin tool-spotbugs` (vendor checksums / signatures, recorded
# in pin-record.json) and fetched again, checksummed, by images/image_build.py into downloads/.
# Nothing is downloaded inside this build. Bases are pinned by digest. No ENTRYPOINT or CMD: the
# pinned-container adapter (B13) runs argv[0] as the entrypoint, read-only, --network none, as
# uid 10001 with HOME=/tmp. Update: bump "version" in tool.json and run `tool_pins.py pin`.
#
# Bundled: the Find Security Bugs plugin (a SpotBugs plugin jar; it has no runtime of its own) and
# the Java runtime from the digest-pinned Temurin base. SpotBugs reads compiled classes, so its job
# depends on a build (02-native-build or the managed-build equivalent), not on source alone.

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS unpack
COPY downloads/spotbugs.tgz /tmp/spotbugs.tgz
RUN mkdir -p /opt && tar -xzf /tmp/spotbugs.tgz -C /opt && mv /opt/spotbugs-* /opt/spotbugs \
    && chmod 0755 /opt/spotbugs/bin/spotbugs

FROM eclipse-temurin:21-jre-noble@sha256:7edbe8532195c8222735caca437e56780e1fc7db08a4b4b4af77fe188cccc15f
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-spotbugs" org.opencontainers.image.version="${TOOL_VERSION}"
COPY --from=unpack /opt/spotbugs /opt/spotbugs
COPY --chmod=0644 downloads/findsecbugs-plugin.jar /opt/spotbugs/plugin/findsecbugs-plugin.jar
ENV PATH="/opt/spotbugs/bin:${PATH}"
RUN groupadd -g 10001 worker && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir -p /workspace /scratch && chown 10001:10001 /scratch \
    && spotbugs -version 2>&1 | grep -F "${TOOL_VERSION}"
USER 10001
WORKDIR /scratch
