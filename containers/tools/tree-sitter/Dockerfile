FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f
ARG TOOL_VERSION=1.0.0
LABEL org.opencontainers.image.title="tool-tree-sitter" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.source="https://github.com/xberg-io/tree-sitter-language-pack" \
      org.opencontainers.image.licenses="MIT"
COPY downloads/wheels/ /opt/assets/wheels/
COPY downloads/parsers-linux/ /opt/grammars/
COPY assets.lock.json /opt/assets/assets.lock.json
COPY verify_assets.py /opt/assets/verify_assets.py
RUN python /opt/assets/verify_assets.py
RUN pip install --no-index --no-cache-dir --find-links=/opt/assets/wheels \
      tree-sitter==0.26.0 tree-sitter-language-pack==1.12.5 \
    && rm -rf /opt/assets /root/.cache
COPY parser.py /opt/appsec/parser.py
RUN groupadd -g 10001 worker \
    && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir -p /work \
    && chown 10001:10001 /work \
    && chmod 0555 /opt/appsec/parser.py \
    && python /opt/appsec/parser.py version
ENV HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC PYTHONHASHSEED=0
ENTRYPOINT ["python", "/opt/appsec/parser.py"]
USER 10001:10001
WORKDIR /work
