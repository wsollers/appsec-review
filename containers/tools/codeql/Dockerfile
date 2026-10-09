ARG CODEQL_SOURCE_IMAGE
FROM ${CODEQL_SOURCE_IMAGE} AS codeql_source

ARG BUILD_IMAGE
FROM ${BUILD_IMAGE}
ARG RUNTIME_USER=10001:10001
USER 0:0
COPY --from=codeql_source /opt/codeql /opt/codeql
COPY codeql_runner.py /opt/appsec/codeql_runner.py
RUN chmod 0555 /opt/appsec/codeql_runner.py
ENV PATH=/opt/codeql:${PATH}
USER ${RUNTIME_USER}
WORKDIR /scratch
