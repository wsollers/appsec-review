# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/dotnet/sdk:9.0

ARG NODE_MAJOR=22
ARG CSHARP_LS_VERSION=0.20.0
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq ripgrep unzip build-essential gnupg python3 python3-pip python3-venv \
      file gdb lldb strace ltrace binutils elfutils procps \
    && curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/dotnet-tools \
    && dotnet tool install csharp-ls --version ${CSHARP_LS_VERSION} --tool-path /opt/dotnet-tools \
    && dotnet tool install dotnet-dump --tool-path /opt/dotnet-tools \
    && dotnet tool install dotnet-symbol --tool-path /opt/dotnet-tools \
    && dotnet tool install dotnet-trace --tool-path /opt/dotnet-tools \
    && ln -s /opt/dotnet-tools/csharp-ls /usr/local/bin/csharp-ls \
    && ln -s /opt/dotnet-tools/dotnet-dump /usr/local/bin/dotnet-dump \
    && ln -s /opt/dotnet-tools/dotnet-symbol /usr/local/bin/dotnet-symbol \
    && ln -s /opt/dotnet-tools/dotnet-trace /usr/local/bin/dotnet-trace \
    && chmod -R a+rx /opt/dotnet-tools \
    && npm install -g @modelcontextprotocol/server-filesystem @modelcontextprotocol/server-memory

RUN useradd -m -u 10001 -s /bin/bash worker && mkdir -p /workspace /scratch && chown worker:worker /scratch
USER worker
WORKDIR /scratch
ENV PATH="/opt/dotnet-tools:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
CMD ["/bin/bash"]
