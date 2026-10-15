# Node/TypeScript build image

`Dockerfile` defines `audit-buildenv-typescript:local`, the image behind the `node` build profile
in `appsec-review.toml`. It contains only the toolchain:

- Node.js 22.23.3 (npm 10.9.9) from the official `nodejs.org` archive, verified against the
  release `SHASUMS256.txt` value recorded in `assets.lock.json`;
- pnpm 9.15.9 and Yarn 1.22.22 from their npm-registry tarballs, hash-locked the same way
  (corepack is removed, so no package manager is downloaded at build time);
- the shared C/C++ toolchain manifest from `../native-toolchain/packages` (gcc/g++, make,
  pkg-config, python3), installed in one marked block for node-gyp addons;
- `strace` and `python3` for the ptrace build capture, and `npm_config_nodedir=/opt/node` so
  node-gyp compiles against the bundled headers instead of downloading them.

Target dependencies are never installed here. The project-build job derives a per-recipe image
from this one and performs the script-disabled restore (`npm ci`/`npm install`, `pnpm install`,
`yarn install`) there. Language servers are out of scope.

## Building and pinning

```sh
python3 containers/build.py build audit-buildenv-typescript
python3 containers/build.py smoke audit-buildenv-typescript
python3 containers/build.py security audit-buildenv-typescript
docker image inspect audit-buildenv-typescript:local --format '{{.Id}}'
```

The fetch step downloads the locked archives over HTTPS on the host and accepts each one only at its
locked size and SHA-256. The Docker build needs network access only for the pinned Ubuntu packages.

The resulting image ID is not reproducible across hosts, because apt and layer metadata carry build
timestamps. After every build, copy the inspected ID into
`[jobs.job_project_build.settings.profiles.node].image_id`. The executor refuses to run any other
image under the `node` profile, and `deploy/dagster/bin/review_run.py` refuses to submit a review
when the local tag resolves to a different ID.
