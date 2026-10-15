# syntax=docker/dockerfile:1
# Python package build environment on the shared native toolchain, so setuptools C
# extensions compile with the same gcc as every other family. Build-backend requirements are
# restored per project (pinned by the target) into the derived project image, not here.
FROM appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1
LABEL org.opencontainers.image.title="audit-buildenv-python" \
      org.opencontainers.image.version="noble-python3.12.3-pip24.0"
USER 0:0
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python-is-python3=3.11.4-1 python3-dev=3.12.3-0ubuntu2.1 \
      python3-pip=24.0+dfsg-1ubuntu1.3 python3-venv=3.12.3-0ubuntu2.1 \
 && rm -rf /var/lib/apt/lists/* \
 && sh /opt/native-toolchain/check-toolchain.sh \
 && python -m pip --version | grep -F 'pip 24.0'
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /workspace
