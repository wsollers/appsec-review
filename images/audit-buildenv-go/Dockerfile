# syntax=docker/dockerfile:1
FROM golang:1.23-bookworm

ARG NODE_MAJOR=22
ARG GOPLS_VERSION=v0.18.1
ARG DELVE_VERSION=v1.25.2
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq ripgrep build-essential gnupg python3 python3-pip python3-venv \
      file gdb lldb strace ltrace binutils elfutils procps \
    && curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN go install golang.org/x/tools/gopls@${GOPLS_VERSION} \
    && go install github.com/go-delve/delve/cmd/dlv@${DELVE_VERSION} \
    && ln -s /usr/local/go/bin/go /usr/local/bin/go \
    && ln -s /go/bin/gopls /usr/local/bin/gopls \
    && ln -s /go/bin/dlv /usr/local/bin/dlv \
    && npm install -g @modelcontextprotocol/server-filesystem @modelcontextprotocol/server-memory

RUN useradd -m -u 10001 -s /bin/bash worker && mkdir -p /workspace /scratch && chown worker:worker /scratch
USER worker
WORKDIR /scratch
ENV PATH="/go/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
CMD ["/bin/bash"]
