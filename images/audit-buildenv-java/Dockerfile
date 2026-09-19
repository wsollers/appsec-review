# syntax=docker/dockerfile:1
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG NODE_MAJOR=22
ENV LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git unzip zip jq ripgrep build-essential \
      gnupg \
      file gdb lldb strace ltrace binutils elfutils procps \
      python3 python3-pip python3-venv \
      maven gradle \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor -o /usr/share/keyrings/adoptium.gpg \
    && . /etc/os-release \
    && echo "deb [signed-by=/usr/share/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb ${VERSION_CODENAME} main" > /etc/apt/sources.list.d/adoptium.list \
    && curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends temurin-25-jdk nodejs \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/temurin-25-jdk-amd64

RUN mkdir -p /opt/jdtls \
    && cd /tmp \
    && curl -fsSL -o jdtls.tgz "https://download.eclipse.org/jdtls/snapshots/jdt-language-server-latest.tar.gz" \
    && tar -xzf jdtls.tgz -C /opt/jdtls \
    && rm jdtls.tgz \
    && npm install -g @modelcontextprotocol/server-filesystem @modelcontextprotocol/server-memory

RUN useradd -m -u 10001 -s /bin/bash worker && mkdir -p /workspace /scratch && chown worker:worker /scratch
USER worker
WORKDIR /scratch
ENV PATH="/opt/jdtls/bin:${PATH}"
CMD ["/bin/bash"]
