# syntax=docker/dockerfile:1
FROM rust:1-bookworm

ARG NODE_MAJOR=22
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq ripgrep build-essential gnupg python3 python3-pip python3-venv \
      file gdb lldb strace ltrace binutils elfutils procps \
    && curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rust-analyzer rustfmt clippy \
    && ln -sfn /usr/local/cargo/bin/cargo /usr/local/bin/cargo \
    && ln -sfn /usr/local/cargo/bin/rustc /usr/local/bin/rustc \
    && ln -sfn /usr/local/cargo/bin/rustfmt /usr/local/bin/rustfmt \
    && ln -sfn /usr/local/cargo/bin/clippy-driver /usr/local/bin/clippy-driver \
    && ln -sfn /usr/local/cargo/bin/rust-analyzer /usr/local/bin/rust-analyzer \
    && npm install -g @modelcontextprotocol/server-filesystem @modelcontextprotocol/server-memory

RUN useradd -m -u 10001 -s /bin/bash worker && mkdir -p /workspace /scratch && chown worker:worker /scratch
USER worker
WORKDIR /scratch
ENV PATH="/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
CMD ["/bin/bash"]
