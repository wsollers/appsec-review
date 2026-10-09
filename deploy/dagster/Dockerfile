FROM docker/buildx-bin:0.37.0@sha256:1387e0aa2b756894e8b6ee10d0f80904cb0badc4356a29e7843b230d0b8fd48f AS buildx

FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DAGSTER_HOME=/opt/dagster/home \
    APPSEC_REVIEW_CONFIG=/opt/app/appsec-review.toml
WORKDIR /opt/app

RUN apt-get update \
    && apt-get install -y --no-install-recommends docker-cli \
    && rm -rf /var/lib/apt/lists/*
COPY --from=buildx /buildx /usr/libexec/docker/cli-plugins/docker-buildx

COPY deploy/dagster/requirements.txt deploy/dagster/requirements.lock.txt /tmp/dagster/
RUN python -m pip install --no-cache-dir --upgrade "pip==25.0.1" \
    && python -m pip install --no-cache-dir -r /tmp/dagster/requirements.txt -c /tmp/dagster/requirements.lock.txt \
    && python -m pip check

COPY pyproject.toml appsec-review.toml ./
COPY src ./src
COPY containers ./containers
COPY data ./data
COPY pipeline ./pipeline
COPY rules ./rules
COPY skills ./skills
COPY tools/cve-bin-tool ./tools/cve-bin-tool
RUN python -m pip install --no-cache-dir --no-build-isolation --no-deps . \
    && mkdir -p /opt/dagster/home /var/dagster/compute-logs /var/dagster/artifacts /opt/app/runs /opt/app/data \
    && chmod 1777 /opt/dagster/home /var/dagster

COPY deploy/dagster/dagster.yaml deploy/dagster/workspace.yaml /opt/dagster/home/

FROM runtime AS test
RUN python -m pip install --no-cache-dir "pytest==8.4.2"
COPY tests/orchestration/dagster ./tests/orchestration/dagster
RUN mkdir -p /opt/app/test/tmp
CMD ["python", "-m", "pytest", "tests/orchestration/dagster"]
