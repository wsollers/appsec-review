# syntax=docker/dockerfile:1
# First-party read-only SQLite inspection utility. The SQLite runtime is supplied by the
# digest-pinned base-python image; no packages or extensions are downloaded here.

FROM appsec-review/base-python:3.12-bookworm
ARG TOOL_VERSION=1.0.0
LABEL org.opencontainers.image.title="tool-sqlite" \
      org.opencontainers.image.version="${TOOL_VERSION}"
USER 0:0
COPY sqlite_tool.py /opt/tool/bin/sqlite-tool
RUN chmod 0555 /opt/tool/bin/sqlite-tool \
    && /opt/tool/bin/sqlite-tool version | grep -F "sqlite-tool ${TOOL_VERSION}"
USER 10001:10001
WORKDIR /scratch
