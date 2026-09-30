# syntax=docker/dockerfile:1
#
# docs-render -- renders the process-model BPMN files (docs/processes/bpmn: pre-submission.bpmn and the
# generated job cards) to SVG and PNG with bpmn-js, so the host needs neither Node packages nor a
# browser. Tools only: render.cjs is mounted read-only at run time, never copied
# (docs/processes/bpmn/render-in-docker.sh).
#
# Tools:
#   node 22            same digest-pinned base as audit-buildenv-typescript
#   chromium           Debian's build, driven headless by puppeteer-core (no browser download)
#   fonts-liberation   metric-compatible Arial, the font bpmn-js lays labels out in
#   bpmn-js, puppeteer-core   npm ci from package-lock.json (sha512 integrity per package)

FROM node:22-bookworm@sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7

RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium \
        fonts-liberation \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json /opt/docs-render/
RUN cd /opt/docs-render \
    && npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
    && chmod -R a+rX /opt/docs-render \
    && node -e "require('/opt/docs-render/node_modules/puppeteer-core'); require.resolve('bpmn-js/dist/bpmn-viewer.development.js', {paths: ['/opt/docs-render']})" \
    && chromium --version

ENV NODE_PATH=/opt/docs-render/node_modules \
    PUPPETEER_PATH=/opt/docs-render/node_modules/puppeteer-core \
    CHROME=/usr/bin/chromium \
    HOME=/tmp

WORKDIR /work
USER 10001
