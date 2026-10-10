# syntax=docker/dockerfile:1
# Offline SQLite FTS5 shard builder. No packages are installed on the host.
FROM appsec-review/base-python:3.12-bookworm
ARG TOOL_VERSION=1.0.0
LABEL org.opencontainers.image.title="tool-sqlite-fts" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.licenses="NOASSERTION"
COPY --chmod=0555 sqlite_fts.py /opt/tool/bin/sqlite-fts
RUN python /opt/tool/bin/sqlite-fts probe
USER 10001:10001
WORKDIR /scratch
