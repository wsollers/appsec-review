# syntax=docker/dockerfile:1
# Node/TypeScript build and capture environment. It carries only the language toolchain:
# target dependencies are restored into derived project images, and language servers are not
# part of this image. Node, pnpm, and Yarn come from hash-locked official archives.
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
LABEL org.opencontainers.image.title="audit-buildenv-typescript" \
      org.opencontainers.image.version="node22.23.3-pnpm9.15.9-yarn1.22.22"
USER 0:0
# python3 also runs the build-capture tool wrapper; strace is the ptrace capture backend.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash=5.2.21-2ubuntu4 ca-certificates=20260601~24.04.1 \
      coreutils=9.4-3ubuntu6.3 findutils=4.9.0-5build1 grep=3.11-4build1 \
      sed=4.9-2ubuntu0.24.04.1 strace=6.8-0ubuntu2 \
      xz-utils=5.6.1+really5.4.5-1ubuntu0.3 \
 && rm -rf /var/lib/apt/lists/*
# --- BEGIN shared native toolchain (containers/buildenv/native-toolchain/packages) ---
# node-gyp compiles addons with this pinned gcc/g++, make, pkg-config, and python3 closure.
COPY --from=native-toolchain packages /tmp/native-toolchain.packages
RUN apt-get update \
 && grep -Ev '^[[:space:]]*(#|$)' /tmp/native-toolchain.packages \
    | xargs apt-get install -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* /tmp/native-toolchain.packages
# --- END shared native toolchain ---
COPY downloads/ /tmp/node-assets/
RUN printf '%s  %s\n' \
      df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de /tmp/node-assets/node-v22.23.3-linux-x64.tar.xz \
      cf86a7ad764406395d4286a6d09d730711720acc6d93e9dce9ac7ac4dc4a28a7 /tmp/node-assets/pnpm-9.15.9.tgz \
      c17d3797fb9a9115bf375e31bfd30058cac6bc9c3b8807a3d8cb2094794b51ca /tmp/node-assets/yarn-1.22.22.tgz \
    | sha256sum -c - \
 && mkdir -p /opt/node /opt/pnpm /opt/yarn \
 && tar -xJf /tmp/node-assets/node-v22.23.3-linux-x64.tar.xz -C /opt/node --strip-components=1 --no-same-owner \
 && tar -xzf /tmp/node-assets/pnpm-9.15.9.tgz -C /opt/pnpm --strip-components=1 --no-same-owner \
 && tar -xzf /tmp/node-assets/yarn-1.22.22.tgz -C /opt/yarn --strip-components=1 --no-same-owner \
 && rm -f /opt/node/bin/corepack \
 && ln -s /opt/pnpm/bin/pnpm.cjs /usr/local/bin/pnpm \
 && ln -s /opt/yarn/bin/yarn.js /usr/local/bin/yarn \
 && chmod -R a+rX /opt/node /opt/pnpm /opt/yarn \
 && rm -rf /tmp/node-assets \
 && groupadd -g 10001 worker \
 && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
 && mkdir -p /workspace /scratch /capture /opt/project-deps \
 && chown -R 10001:10001 /workspace /scratch /capture /opt/project-deps
# node-gyp compiles against the headers shipped with this exact Node release instead of
# downloading them at build time.
ENV HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
    npm_config_nodedir=/opt/node \
    npm_config_update_notifier=false \
    PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /workspace
