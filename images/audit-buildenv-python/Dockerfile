# syntax=docker/dockerfile:1
FROM python:3.12-bookworm

ARG NODE_MAJOR=22
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq ripgrep build-essential gnupg python3-venv \
      file gdb lldb strace ltrace binutils elfutils procps \
    && curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      python-lsp-server[all] \
      basedpyright \
      debugpy \
      ruff \
      pytest \
    && npm install -g @modelcontextprotocol/server-filesystem @modelcontextprotocol/server-memory

RUN useradd -m -u 10001 -s /bin/bash worker && mkdir -p /workspace /scratch && chown worker:worker /scratch
USER worker
WORKDIR /scratch
CMD ["/bin/bash"]
