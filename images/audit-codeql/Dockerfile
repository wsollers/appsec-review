# syntax=docker/dockerfile:1
#
# audit-codeql — CodeQL CLI + bundled query packs for pre-engagement evidence gathering.
#
# Role (ADR-0006): broad security-extended query suites across the languages CodeQL
# supports, run offline from the bundle (query packs included, no `codeql pack download`
# at run time). It is NOT the native memory-safety substrate (ADR-0001); C/C++ is
# extracted with --build-mode none by default because the C++ extractor's clang-cl
# support is documented as preliminary. Traced builds are opt-in (see run-codeql.sh).
#
# LICENSE GATE: the CodeQL CLI is licensed for open-source and academic use; use on
# proprietary code in a commercial engagement requires GitHub Advanced Security.
# run-codeql.sh refuses to run unless CODEQL_LICENSE_BASIS is set (oss | academic | ghas)
# and records the value in the run manifest. This is deliberately not defaultable.
#
# Pins (verified 2026-09-12): codeql-bundle-v2.27.0 (github/codeql-action releases,
# linux64, 553 MB zst; bundle == CLI + codeql/*-queries packs at matching versions).

FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive
ARG CODEQL_BUNDLE=codeql-bundle-v2.27.0

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl zstd git python3 python3-pip \
      gcc g++ libc6-dev \
      openjdk-21-jre-headless nodejs \
    && rm -rf /var/lib/apt/lists/*

# Bundle is downloaded on the host (resumable; `curl -L -C - -o codeql-bundle-linux64.tar.zst <url>`)
# and copied in. Its sha256 is recorded in run-manifest by run-codeql.sh via CODEQL_BUNDLE_SHA256.
COPY codeql-bundle-linux64.tar.zst /opt/bundle.tar.zst
RUN cd /opt && tar --zstd -xf bundle.tar.zst && rm bundle.tar.zst \
    && chmod -R a+rX /opt/codeql \
    && /opt/codeql/codeql version --format=json \
    && /opt/codeql/codeql resolve languages
ENV CODEQL_LICENSE_BASIS=ghas \
    PATH="/opt/codeql:${PATH}" \
    CODEQL_BUNDLE=${CODEQL_BUNDLE}

COPY run-codeql.sh replay_compile_commands.py smoke-test.sh /opt/scripts/
RUN chmod +x /opt/scripts/*

RUN useradd -m -u 10001 -s /bin/bash worker && mkdir -p /workspace /scratch && chown worker:worker /scratch
USER worker
WORKDIR /scratch
CMD ["/bin/bash"]
