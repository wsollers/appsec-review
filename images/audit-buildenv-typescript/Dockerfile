# syntax=docker/dockerfile:1
FROM node:22-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq ripgrep build-essential python3 python3-pip python3-venv \
      file gdb lldb strace ltrace binutils elfutils procps \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g \
      typescript \
      typescript-language-server \
      vscode-langservers-extracted \
      eslint \
      @modelcontextprotocol/server-filesystem \
      @modelcontextprotocol/server-memory

RUN useradd -m -u 10001 -s /bin/bash worker && mkdir -p /workspace /scratch && chown worker:worker /scratch
USER worker
WORKDIR /scratch
CMD ["/bin/bash"]
