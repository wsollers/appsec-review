# syntax=docker/dockerfile:1
FROM fkiecad/cwe_checker:latest AS cwe-checker

FROM debian:bookworm-slim

ARG NODE_MAJOR=22
ARG GHIDRA_VERSION=12.1.3
ARG GHIDRA_BUILD=20260817
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip
ARG RETDEC_VERSION=5.0
ARG RETDEC_URL=https://github.com/avast/retdec/releases/download/v${RETDEC_VERSION}/RetDec-v${RETDEC_VERSION}-Linux-Release.tar.xz
ARG FLOSS_VERSION=3.1.1
ARG FLOSS_URL=https://github.com/mandiant/flare-floss/releases/download/v${FLOSS_VERSION}/floss-v${FLOSS_VERSION}-linux.zip
ARG DIE_VERSION=3.21
ARG DIE_DEB_URL=https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Debian_12_amd64.deb
ARG JADX_VERSION=1.5.6
ARG JADX_URL=https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip
ARG JAVA_DOWNLOAD_URL=https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse
ENV JAVA_HOME="/opt/java"
ENV GHIDRA_HOME="/opt/ghidra"
ENV RETDEC_HOME="/opt/retdec"
ENV DOTNET_ROOT="/opt/dotnet"
ENV PATH="/opt/binary-analysis-venv/bin:/opt/retdec:/opt/ghidra:/opt/java/bin:/opt/dotnet:/usr/local/bin:/usr/bin:/bin"

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates curl git jq ripgrep gnupg passwd \
      build-essential cmake ninja-build pkg-config \
      python3 python3-pip python3-venv \
      file binutils elfutils dwarfdump dwarves pax-utils \
      gdb gdbserver lldb llvm clang valgrind rr \
      strace ltrace procps \
      exiftool unzip zip tar \
      binwalk checksec yara ssdeep tlsh-tools qemu-user-static apktool \
    && curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "$JAVA_DOWNLOAD_URL" -o /tmp/jdk.tar.gz \
    && mkdir -p "$JAVA_HOME" \
    && tar -xzf /tmp/jdk.tar.gz -C "$JAVA_HOME" --strip-components=1 \
    && rm /tmp/jdk.tar.gz \
    && curl -fsSL "$GHIDRA_URL" -o /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && rm /tmp/ghidra.zip \
    && ln -sfn "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" "$GHIDRA_HOME" \
    && curl -fsSL "$RETDEC_URL" -o /tmp/retdec.tar.xz \
    && mkdir -p "$RETDEC_HOME" \
    && tar -xJf /tmp/retdec.tar.xz -C "$RETDEC_HOME" --strip-components=1 \
    && rm /tmp/retdec.tar.xz \
    && ln -sfn "$JAVA_HOME/bin/java" /usr/local/bin/java \
    && ln -sfn "$JAVA_HOME/bin/javac" /usr/local/bin/javac \
    && ln -sfn "$GHIDRA_HOME/ghidraRun" /usr/local/bin/ghidra \
    && ln -sfn "$GHIDRA_HOME/support/analyzeHeadless" /usr/local/bin/ghidra-analyzeHeadless \
    && ln -sfn "$RETDEC_HOME/retdec-fileinfo" /usr/local/bin/retdec-fileinfo \
    && ln -sfn "$RETDEC_HOME/retdec-decompiler" /usr/local/bin/retdec-decompiler \
    && curl -fsSL "$FLOSS_URL" -o /tmp/floss.zip \
    && mkdir -p /opt/floss \
    && unzip -q /tmp/floss.zip -d /opt/floss \
    && rm /tmp/floss.zip \
    && find /opt/floss -type f -name floss -exec ln -sfn {} /usr/local/bin/floss \; \
    && curl -fsSL "$DIE_DEB_URL" -o /tmp/die.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends /tmp/die.deb \
    && rm /tmp/die.deb \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "$JADX_URL" -o /tmp/jadx.zip \
    && mkdir -p /opt/jadx \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && rm /tmp/jadx.zip \
    && ln -sfn /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && ln -sfn /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui \
    && curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && bash /tmp/dotnet-install.sh --channel 10.0 --install-dir "$DOTNET_ROOT" \
    && rm /tmp/dotnet-install.sh \
    && dotnet tool install ilspycmd --tool-path /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

COPY --from=cwe-checker /home/cwe/cwe_checker /usr/local/bin/cwe_checker
COPY --from=cwe-checker /home/cwe/.config/cwe_checker /opt/cwe_checker_config

RUN python3 -m venv /opt/binary-analysis-venv \
    && /opt/binary-analysis-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/binary-analysis-venv/bin/pip install --no-cache-dir \
      angr \
      capstone \
      flare-capa \
      frida-tools \
      lief \
      networkx \
      pefile \
      pyelftools \
    && npm install -g @modelcontextprotocol/server-filesystem @modelcontextprotocol/server-memory \
    && chmod +x /usr/local/bin/cwe_checker \
    && ln -sfn /usr/local/bin/cwe_checker /usr/local/bin/check_cwe \
    && ln -sfn /opt/binary-analysis-venv/bin/frida /usr/local/bin/frida \
    && ln -sfn /opt/binary-analysis-venv/bin/frida-ps /usr/local/bin/frida-ps \
    && ln -sfn /opt/binary-analysis-venv/bin/frida-trace /usr/local/bin/frida-trace \
    && ln -sfn /opt/binary-analysis-venv/bin/frida-discover /usr/local/bin/frida-discover \
    && ln -sfn /opt/binary-analysis-venv/bin/frida-itrace /usr/local/bin/frida-itrace \
    && ln -sfn /opt/binary-analysis-venv/bin/frida-apk /usr/local/bin/frida-apk \
    && /usr/sbin/useradd -m -u 10001 -s /bin/bash worker \
    && mkdir -p /home/worker/.config \
    && cp -R /opt/cwe_checker_config /home/worker/.config/cwe_checker \
    && mkdir -p /workspace /scratch \
    && chown -R worker:worker /home/worker/.config /scratch

# --- Repo-owned scripts, kept LAST so editing them rebuilds only these layers.
COPY scripts/analyze-binary.sh /usr/local/bin/analyze-binary
COPY scripts/binary-summary.py /usr/local/bin/binary-summary
COPY scripts/angr-summary.py /usr/local/bin/angr-summary
RUN chmod +x /usr/local/bin/analyze-binary /usr/local/bin/binary-summary /usr/local/bin/angr-summary

USER worker
WORKDIR /scratch
CMD ["/bin/bash"]
