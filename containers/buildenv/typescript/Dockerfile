# syntax=docker/dockerfile:1
# Node/TypeScript build environment on the shared native toolchain, so node-gyp addons compile
# with the same pinned gcc/g++, make, and python3 as every other family (strace and python3 also
# serve the build capture). Only the language toolchain lives here: target dependencies are
# restored into derived project images, and language servers are out of scope. Node, pnpm, and
# Yarn come from hash-locked official archives, so this layer needs no network.
FROM appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1
LABEL org.opencontainers.image.title="audit-buildenv-typescript" \
      org.opencontainers.image.version="node22.23.3-pnpm9.15.9-yarn1.22.22"
USER 0:0
COPY downloads/ /tmp/node-assets/
RUN printf '%s  %s\n' \
      1084aa36196bba4c3a5e69a1ee388a6e4ff729dad09445fbcd434b28fe3c24af /tmp/node-assets/node-v22.23.3-linux-x64.tar.gz \
      cf86a7ad764406395d4286a6d09d730711720acc6d93e9dce9ac7ac4dc4a28a7 /tmp/node-assets/pnpm-9.15.9.tgz \
      c17d3797fb9a9115bf375e31bfd30058cac6bc9c3b8807a3d8cb2094794b51ca /tmp/node-assets/yarn-1.22.22.tgz \
    | sha256sum -c - \
 && mkdir -p /opt/node /opt/pnpm /opt/yarn \
 && tar -xzf /tmp/node-assets/node-v22.23.3-linux-x64.tar.gz -C /opt/node --strip-components=1 --no-same-owner \
 && tar -xzf /tmp/node-assets/pnpm-9.15.9.tgz -C /opt/pnpm --strip-components=1 --no-same-owner \
 && tar -xzf /tmp/node-assets/yarn-1.22.22.tgz -C /opt/yarn --strip-components=1 --no-same-owner \
 && rm -f /opt/node/bin/corepack \
 && ln -s /opt/pnpm/bin/pnpm.cjs /usr/local/bin/pnpm \
 && ln -s /opt/yarn/bin/yarn.js /usr/local/bin/yarn \
 && chmod -R a+rX /opt/node /opt/pnpm /opt/yarn \
 && rm -rf /tmp/node-assets \
 && sh /opt/native-toolchain/check-toolchain.sh \
 && /opt/node/bin/node --version | grep -Fx v22.23.3
# node-gyp compiles against the headers shipped with this exact Node release instead of
# downloading them at build time.
ENV npm_config_nodedir=/opt/node \
    npm_config_update_notifier=false \
    PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /workspace
