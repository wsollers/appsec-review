# syntax=docker/dockerfile:1
FROM php:8.3-cli-bookworm

ARG NODE_MAJOR=22
ENV COMPOSER_HOME=/opt/composer
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq ripgrep unzip zip build-essential gnupg python3 python3-pip python3-venv \
      file gdb lldb strace ltrace binutils elfutils procps \
    && curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer
RUN docker-php-ext-install pcntl \
    && mkdir -p "${COMPOSER_HOME}" \
    && composer global config minimum-stability dev \
    && composer global config prefer-stable true \
    && composer global require phpactor/phpactor \
    && ln -s "${COMPOSER_HOME}/vendor/bin/phpactor" /usr/local/bin/phpactor \
    && npm install -g @modelcontextprotocol/server-filesystem @modelcontextprotocol/server-memory

RUN useradd -m -u 10001 -s /bin/bash worker && mkdir -p /workspace /scratch && chown worker:worker /scratch
USER worker
WORKDIR /scratch
ENV PATH="/opt/composer/vendor/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
CMD ["/bin/bash"]
