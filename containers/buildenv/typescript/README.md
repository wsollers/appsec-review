---
title: "Node/TypeScript build image"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: ["job_project_build"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Node/TypeScript build image

`Dockerfile` defines `audit-buildenv-typescript:local`, the image behind the `node` build profile
in `appsec-review.toml`. It contains only the toolchain:

- Node.js 22.23.3 (npm 10.9.9) from the official `nodejs.org` archive, verified against the
  release `SHASUMS256.txt` value recorded in `assets.lock.json`;
- pnpm 9.15.9 and Yarn 1.22.22 from their npm-registry tarballs, hash-locked the same way
  (corepack is removed, so no package manager is downloaded at build time);
- everything else from the shared native toolchain it is built `FROM`
  (`../native-toolchain/`, catalog id `buildenv-native-toolchain`): gcc/g++, make, pkg-config, and
  python3 for node-gyp addons, plus `strace` and `python3` for the ptrace build capture;
- `npm_config_nodedir=/opt/node`, so node-gyp compiles against the bundled headers instead of
  downloading them.

Target dependencies are never installed here. The project-build job derives a per-recipe image
from this one and performs the script-disabled restore (`npm ci`/`npm install`, `pnpm install`,
`yarn install`) there. Language servers are out of scope.

## Building and pinning

```sh
python3 containers/build.py build audit-buildenv-typescript   # builds its toolchain dependencies first
python3 containers/build.py smoke audit-buildenv-typescript
python3 containers/build.py security audit-buildenv-typescript
docker image inspect audit-buildenv-typescript:local --format '{{.Id}}'
```

The fetch step downloads the locked archives over HTTPS on the host and accepts each one only at its
locked size and SHA-256. This layer's Docker build runs without network; the pinned Ubuntu
packages come from the shared toolchain image.

The resulting image ID is not reproducible across hosts, because apt and layer metadata carry build
timestamps. After a host rebuild, `appsec-review update-image-pins --write` updates the ignored
`deploy/dagster/host-pins.toml` binding for this tag, not `appsec-review.toml`.
The loader freezes it as the resolved `node` profile's `image_id`. The executor refuses a different
local image, and `deploy/dagster/bin/review_run.py` checks the effective host-bound profiles before
submission. See [profile image pins](../README.md#profile-image-pins).
