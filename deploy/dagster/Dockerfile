ARG TARGETARCH

FROM scratch AS copilot-cli-amd64
ADD --checksum=sha256:cabbb04a88a8034ddfa21234cbd52b7676536aec2b292624e6fd6796f891a8ff https://github.com/github/copilot-cli/releases/download/v1.0.102/copilot-linux-x64.tar.gz /copilot-cli.tar.gz

FROM scratch AS copilot-cli-arm64
ADD --checksum=sha256:634ee7cc4fa4b7447ac41e2c3ce54928d8f5214f418954e3af36f372e849c9c9 https://github.com/github/copilot-cli/releases/download/v1.0.102/copilot-linux-arm64.tar.gz /copilot-cli.tar.gz

FROM copilot-cli-${TARGETARCH} AS copilot-cli

FROM docker/buildx-bin:0.37.0@sha256:1387e0aa2b756894e8b6ee10d0f80904cb0badc4356a29e7843b230d0b8fd48f AS buildx

FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS runtime-base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DAGSTER_HOME=/opt/dagster/home \
    APPSEC_REVIEW_CONFIG=/opt/app/appsec-review.toml
WORKDIR /opt/app

RUN apt-get update \
    && apt-get install -y --no-install-recommends docker-cli openssl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=buildx /buildx /usr/libexec/docker/cli-plugins/docker-buildx

COPY deploy/dagster/requirements.txt deploy/dagster/requirements.lock.txt /tmp/dagster/
RUN python -m pip install --no-cache-dir --upgrade "pip==25.0.1" \
    && python -m pip install --no-cache-dir -r /tmp/dagster/requirements.txt -c /tmp/dagster/requirements.lock.txt \
    && python -m pip check

COPY pyproject.toml appsec-review.toml ./
COPY profiles ./profiles
COPY docs/schemas/ ./docs/schemas/
COPY src ./src
COPY containers ./containers
COPY data ./data
COPY pipeline ./pipeline
COPY rules ./rules
COPY tools/cve-bin-tool ./tools/cve-bin-tool
RUN python -m pip install --no-cache-dir --no-build-isolation --no-deps . \
    && mkdir -p /opt/dagster/home /var/dagster/compute-logs /var/dagster/artifacts /opt/app/runs /opt/app/data \
    && chmod 1777 /opt/dagster/home /var/dagster /var/dagster/compute-logs /var/dagster/artifacts \
    && python -c "from appsec_review.application_paths import verify_runtime_assets; verify_runtime_assets()" \
    && python -c "from pathlib import Path; from appsec_review.container_runtime.catalog import load_catalog; load_catalog(Path.cwd())" \
    && python -c "from appsec_review.graph.catalog import load_catalog; load_catalog()" \
    && python -c "from appsec_review.orchestration.dagster.definitions import defs; defs.get_job_def('wave1_review')"

COPY deploy/dagster/dagster.yaml deploy/dagster/workspace.yaml /opt/dagster/home/

# Signed-module enforcement: a root-owned verifier outside the package it verifies, run from the
# interpreter's own sitecustomize in every Python process. These variables alone are inert; the
# final stages add the module envelope and APPSEC_REVIEW_REQUIRE_SIGNED_MODULES=1 after every
# build-time Python step, and the trust anchors are mounted read-only at run time.
COPY --chown=0:0 --chmod=0644 src/appsec_review/signing/bootstrap.py src/appsec_review/signing/core.py \
    src/appsec_review/signing/modules.py src/appsec_review/signing/import_hook.py \
    src/appsec_review/signing/sitecustomize_shim.py /opt/appsec-review/signing-bootstrap/
COPY --chown=0:0 --chmod=0644 src/appsec_review/signing/sitecustomize_shim.py /usr/local/lib/python3.12/sitecustomize.py
ENV APPSEC_REVIEW_SIGNING_BOOTSTRAP_DIR=/opt/appsec-review/signing-bootstrap \
    APPSEC_REVIEW_MODULE_ROOT=/usr/local/lib/python3.12/site-packages/appsec_review \
    APPSEC_REVIEW_TRUSTED_KEYS_DIR=/etc/appsec-review/signing/trusted-keys \
    APPSEC_REVIEW_OPENSSL=/usr/bin/openssl
RUN chmod 0755 /opt/appsec-review /opt/appsec-review/signing-bootstrap \
    && python -c "import os, sys; assert sys.modules['sitecustomize'].__file__ == '/usr/local/lib/python3.12/sitecustomize.py', 'site did not import the signing sitecustomize'" \
    && python -c "import os, appsec_review; assert os.path.dirname(appsec_review.__file__) == os.environ['APPSEC_REVIEW_MODULE_ROOT'], 'APPSEC_REVIEW_MODULE_ROOT is not the installed package'" \
    && /usr/bin/openssl version
RUN status=0; APPSEC_REVIEW_REQUIRE_SIGNED_MODULES=1 python -c pass || status=$?; \
    test "$status" = 78 || { echo "signed-module enforcement does not fail closed (exit $status)" >&2; exit 1; }

FROM runtime-base AS runtime-copilot-base
COPY --from=copilot-cli /copilot-cli.tar.gz /tmp/copilot-cli.tar.gz
RUN case "$(dpkg --print-architecture)" in \
      amd64) bytes=128117626 ;; \
      arm64) bytes=129124281 ;; \
      *) echo "Unsupported Copilot CLI architecture" >&2; exit 1 ;; \
    esac \
    && test "$(stat -c %s /tmp/copilot-cli.tar.gz)" = "$bytes" \
    && mkdir -p /opt/copilot-cli \
    && tar -xzf /tmp/copilot-cli.tar.gz -C /opt/copilot-cli --no-same-owner \
    && chmod 755 /opt/copilot-cli/copilot \
    && ln -s /opt/copilot-cli/copilot /usr/local/bin/copilot \
    && copilot --version | grep -F "GitHub Copilot CLI 1.0.102." \
    && rm /tmp/copilot-cli.tar.gz
COPY deploy/dagster/requirements.copilot.txt /tmp/dagster/
ENV COPILOT_CLI_EXTRACT_DIR=/opt/copilot-runtime
RUN python -m pip install --no-cache-dir -r /tmp/dagster/requirements.copilot.txt \
        -c /tmp/dagster/requirements.lock.txt \
    && python -m copilot download-runtime \
    && chmod -R a+rX /opt/copilot-runtime \
    && python -m pip check
ENV COPILOT_SKIP_CLI_DOWNLOAD=1

FROM runtime-base AS runtime-windows-base
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --prefix /opt/claude --no-audit --no-fund @anthropic-ai/claude-code@2.1.282 \
    && ln -s /opt/claude/node_modules/.bin/claude /usr/local/bin/claude \
    && claude --version

# Final stages: the host signs src/appsec_review into deploy/dagster/signing/python-modules.json
# (lifecycle.py build) before the build; pip installed identical bytes at APPSEC_REVIEW_MODULE_ROOT.
# No Python runs after enforcement is switched on, so the build never needs the trust anchors.
FROM runtime-base AS runtime
COPY --chown=0:0 --chmod=0644 deploy/dagster/signing/python-modules.json /opt/appsec-review/signing/python-modules.json
ENV APPSEC_REVIEW_MODULE_SIGNATURE=/opt/appsec-review/signing/python-modules.json \
    APPSEC_REVIEW_REQUIRE_SIGNED_MODULES=1

FROM runtime-copilot-base AS runtime-copilot
COPY --chown=0:0 --chmod=0644 deploy/dagster/signing/python-modules.json /opt/appsec-review/signing/python-modules.json
ENV APPSEC_REVIEW_MODULE_SIGNATURE=/opt/appsec-review/signing/python-modules.json \
    APPSEC_REVIEW_REQUIRE_SIGNED_MODULES=1

FROM runtime-windows-base AS runtime-windows
COPY --chown=0:0 --chmod=0644 deploy/dagster/signing/python-modules.json /opt/appsec-review/signing/python-modules.json
ENV APPSEC_REVIEW_MODULE_SIGNATURE=/opt/appsec-review/signing/python-modules.json \
    APPSEC_REVIEW_REQUIRE_SIGNED_MODULES=1

# Unenforced: the deployment test image needs neither the module envelope nor trust anchors.
FROM runtime-base AS test
RUN python -m pip install --no-cache-dir "pytest==8.4.2"
COPY tests/__init__.py tests/capture_fakes.py ./tests/
COPY tests/fixtures/reference_feeds.py ./tests/fixtures/
COPY tests/fixtures/inference_review ./tests/fixtures/inference_review
COPY tests/orchestration/dagster ./tests/orchestration/dagster
RUN mkdir -p /opt/app/test/tmp
CMD ["python", "-m", "pytest", "tests/orchestration/dagster"]
