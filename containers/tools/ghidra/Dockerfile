# Ghidra is acquired and hash-verified by containers/build.py. This build runs with --network=none:
# no installer, package manager, Gradle, or runtime dependency resolution is used.
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS unpack
ARG TOOL_VERSION
COPY downloads/ghidra_12.1.4_PUBLIC_20260921.zip /tmp/ghidra.zip
COPY --from=shared safe_extract.py /opt/review/
COPY tool.toml assets.lock.json inventory.json /opt/review/
# safe_extract.py verifies size, SHA-256, and SHA-512 against assets.lock.json, rejects unsafe
# members, installs only the reviewed closure, and requires the result to equal the committed
# inventory byte-for-byte.
RUN set -eu; \
    python -I /opt/review/safe_extract.py /tmp/ghidra.zip /opt/unpack \
        --policy /opt/review/tool.toml --lock /opt/review/assets.lock.json \
        --expect-inventory /opt/review/inventory.json; \
    mv "/opt/unpack/ghidra_${TOOL_VERSION}_PUBLIC" /opt/ghidra; \
    grep -Fx "application.version=${TOOL_VERSION}" /opt/ghidra/Ghidra/application.properties; \
    grep -Fx "application.release.name=PUBLIC" /opt/ghidra/Ghidra/application.properties; \
    cp /opt/review/inventory.json /opt/ghidra/inventory.json; \
    rm -f /tmp/ghidra.zip

# Ghidra compiles its Java scripts at run time and its launcher refuses a JRE, so the reviewed
# JDK is copied from this digest-pinned stage. Nothing is downloaded during the build.
FROM eclipse-temurin:21-jdk-noble@sha256:b468c3fc688b14450571494f588bd939378e7fd542ed5a73f8efc13f17872a87 AS jdk

FROM appsec-review/base-jre:21-noble
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-ghidra" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=jdk /opt/java/openjdk /opt/jdk
COPY --from=unpack /opt/ghidra /opt/ghidra
COPY --chmod=0555 ghidra-export ghidra-version /opt/appsec/bin/
# One mode covers the created directory too, so it must keep the search bit.
COPY --chmod=0555 scripts/AppsecExportProgram.java /opt/appsec/ghidra-scripts/
ENV JAVA_HOME=/opt/jdk PATH="/opt/jdk/bin:/opt/appsec/bin:${PATH}" HOME=/tmp
# Compile the export script against the pinned Ghidra classes so an API mismatch fails the image
# build instead of a decompilation run. The class files are discarded; Ghidra recompiles the
# script itself at run time.
RUN set -eu; \
    /opt/appsec/bin/ghidra-version | grep -Fx "ghidra ${TOOL_VERSION}"; \
    classpath=$(find /opt/ghidra/Ghidra -name '*.jar' -path '*/lib/*' | sort | tr '\n' ':'); \
    mkdir /tmp/script-check; \
    javac -proc:none -cp "$classpath" -d /tmp/script-check \
        /opt/appsec/ghidra-scripts/AppsecExportProgram.java; \
    rm -rf /tmp/script-check
USER 10001:10001
WORKDIR /scratch
