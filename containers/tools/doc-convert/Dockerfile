# syntax=docker/dockerfile:1
# tool-doc-convert: offline text extraction for design documents the target catalog cannot store
# (PDF via pypdf, DOCX/ODT/RTF/EPUB via the static pandoc binary run with --sandbox).
#
# Assets are fetched and verified against assets.lock.json by containers/build.py before this
# network-free build executes; nothing is downloaded inside the build. Bases are pinned by digest.
# No ENTRYPOINT or CMD: the application runs argv[0] (/opt/tool/bin/doc-convert) read-only,
# --network none, as uid 10001. The converter script is the only command surface.

FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS install
ARG PANDOC_VERSION
COPY requirements.txt /tmp/requirements.txt
COPY downloads/wheels/ /tmp/wheels/
COPY downloads/pandoc.tar.gz /tmp/pandoc.tar.gz
RUN python -m venv /opt/tool \
    && /opt/tool/bin/pip install --no-cache-dir --no-index --find-links /tmp/wheels --no-deps \
       --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
    && mkdir -p /opt/pandoc \
    && tar -xzf /tmp/pandoc.tar.gz -C /opt/pandoc --strip-components=2 "pandoc-${PANDOC_VERSION}/bin/pandoc" \
    && chmod 0755 /opt/pandoc/pandoc

FROM appsec-review/base-python:3.12-bookworm
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG TOOL_VERSION
ARG PYPDF_VERSION
ARG PANDOC_VERSION
LABEL org.opencontainers.image.title="tool-doc-convert" org.opencontainers.image.version="${TOOL_VERSION}"
COPY --from=install /opt/tool /opt/tool
COPY --from=install /opt/pandoc/pandoc /opt/tool/bin/pandoc
COPY doc_convert.py /opt/tool/bin/doc-convert
ENV PATH="/opt/tool/bin:${PATH}" PYTHONDONTWRITEBYTECODE=1
RUN chmod 0755 /opt/tool/bin/doc-convert \
    && /opt/tool/bin/doc-convert --version | grep -Fx "doc-convert ${TOOL_VERSION}" \
    && /opt/tool/bin/doc-convert --version-details | grep -F "pypdf ${PYPDF_VERSION}" \
    && /opt/tool/bin/pandoc --version | head -n 1 | grep -Fx "pandoc ${PANDOC_VERSION}"
USER 10001
WORKDIR /scratch
