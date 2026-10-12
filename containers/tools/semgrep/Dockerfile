# syntax=docker/dockerfile:1
# Migrated from the audited pre-simplification definition. Assets are fetched and
# verified by containers/build.py before this network-free build executes.
#
# tool-semgrep: source SAST (Semgrep CE engine). Rules are not in the image; they are mounted per run.
#
# One tool per image. Every release asset, including each Python wheel, is pinned by URL, byte size,
# and SHA-256 in assets.lock.json; containers/build.py validates the catalog and lock, then fetches
# and verifies each asset into downloads/. Nothing is downloaded inside this build. Bases are pinned
# by digest. No ENTRYPOINT or CMD: the application executor runs the tool.toml executable as the
# entrypoint, read-only, --network none, as uid 10001. Update: follow "Updating a pin" in
# containers/README.md (assets.lock.json, requirements.txt, tool.toml, and the catalog entry), then
# run validate, build, and smoke.
#
# Python packages come from requirements.txt, a lock with every sha256; each pinned wheel must be an
# assets.lock.json artifact. pip installs them with --no-index --require-hashes: no package index is
# reached from inside the build.

FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS install
COPY requirements.txt /tmp/requirements.txt
COPY downloads/wheels/ /tmp/wheels/
RUN python -m venv /opt/tool \
    && /opt/tool/bin/pip install --no-cache-dir --no-index --find-links /tmp/wheels --no-deps \
       --require-hashes --only-binary=:all: -r /tmp/requirements.txt

FROM appsec-review/base-python:3.12-bookworm
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-semgrep" org.opencontainers.image.version="${TOOL_VERSION}"
COPY --from=install /opt/tool /opt/tool
ENV PATH="/opt/tool/bin:${PATH}" PYTHONDONTWRITEBYTECODE=1 \
    SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
RUN /opt/tool/bin/semgrep --version 2>&1 | grep -F "${TOOL_VERSION}"
USER 10001
WORKDIR /scratch
