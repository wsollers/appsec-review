# syntax=docker/dockerfile:1
# Migrated from the audited pre-simplification definition. Assets are fetched and
# verified by containers/build.py before this network-free build executes.
#
# tool-mobsfscan: mobile-source SAST (mobsfscan).
#
# One tool per image (docs/processes/tool-images.md). The tool's release assets are downloaded and
# verified on the host by `images/tool_pins.py pin tool-mobsfscan` (vendor checksums / signatures, recorded
# in pin-record.json) and fetched again, checksummed, by images/image_build.py into downloads/.
# Nothing is downloaded inside this build. Bases are pinned by digest. No ENTRYPOINT or CMD: the
# pinned-container adapter (B13) runs argv[0] as the entrypoint, read-only, --network none, as
# uid 10001 with HOME=/tmp. Update: bump "version" in tool.json and run `tool_pins.py pin`.
#
# Bundled: the semgrep Python package, which mobsfscan imports as a library (its own pinned dependency)
#
# Python packages come from requirements.txt, a lock with every sha256 (`tool_pins.py pin` writes it
# with `uv pip compile --generate-hashes` and downloads the exact wheels, each a checksummed
# download in image.json). pip installs them with --no-index --require-hashes: no package index is
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
LABEL org.opencontainers.image.title="tool-mobsfscan" org.opencontainers.image.version="${TOOL_VERSION}"
COPY --from=install /opt/tool /opt/tool
ENV PATH="/opt/tool/bin:${PATH}" PYTHONDONTWRITEBYTECODE=1 \
    SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
RUN /opt/tool/bin/mobsfscan --version 2>&1 | grep -F "${TOOL_VERSION}"
USER 10001
WORKDIR /scratch
