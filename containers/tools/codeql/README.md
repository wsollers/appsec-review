# CodeQL images

CodeQL is not in `containers/catalog.toml` and is not built by `containers/build-all.sh`. The
licensed CodeQL payload is downloaded from its pinned upstream release (see [`LICENSE.md`](LICENSE.md));
this directory holds the build script and the layers the repository adds on top of it. Run every command from the repository root.

## Licensed source image

Build both CodeQL images on any Linux Docker host (native Linux, or WSL 2 with Docker Engine or
Docker Desktop's WSL integration; never Windows PowerShell) with one command from the repository
root:

```bash
containers/tools/codeql/build-source-image.sh
```

The script downloads the official `github/codeql-action@codeql-bundle-v2.27.0` Linux x64 bundle and
the `github/codeql-coding-standards@v2.62.0` CERT C++ query packs into the ignored
`containers/tools/codeql/downloads/` directory, verifies both against pinned SHA-256 values,
builds the `buildenv-native-toolchain` base through `containers/build-all.sh` when it is missing,
then runs `docker build --network=none` for `Dockerfile.bundle` (`audit-codeql:local`) and
`Dockerfile.custom-source` (`audit-codeql:custom-2.27.0`) and prints the final image id. It needs
only `docker`, `curl` and `sha256sum`; nothing is fetched from a review host. Optional environment:
`APPSEC_DOCKER_BIN` (docker client), `CODEQL_LOCAL_TAG` / `CODEQL_CUSTOM_TAG` (alternative tags,
for example to rebuild without replacing pinned tags) and `CODEQL_KEEP_DOWNLOADS=1` (keep the
verified archives). CodeQL's license terms still apply (see [`LICENSE.md`](LICENSE.md)); never
commit the downloaded payloads.

Byte-identical rebuilds are not a goal: a fresh build has a new image id. The final image must pass
the runner's `inventory` action against `assets.lock.json` before updating its source-image
identity and lock-file hash below.
The resulting image id must equal `source_image.image_id` in `assets.lock.json` and
`jobs.job_codeql_analysis.settings.source_image_id` in `appsec-review.toml`; the runtime refuses a
source tag whose identity changed. Customer review execution does not hash `assets.lock.json`,
the supplied runner or installed packs/extractors. Update the relevant
`review_policy.releases` declarations when platform material changes; missing declarations disable
reuse rather than restore payload fingerprinting.

## Derived analysis images

The CodeQL resolver (`src/appsec_review/codeql/runtime.py`) requests required layering through an
operator-commissioned bounded builder, using run/tenant-private tags and manifests under
`codeql-images/` metadata. Do not tag these by hand or bypass a missing backend with an
uncustomized image. See [builder requirements](../../../docs/operations/performance-assurance.md#scheduling-and-limits).
An operator-approved compatible runtime already installed by immutable image ID can instead use
[explicit preinstalled declarations](../../../docs/operations/codeql-analysis.md#explicit-preinstalled-runtimes).
That path performs no build and claims no cache reuse; it requires exact source/build/user/release
bindings and does not upgrade old manifests or runners.
For an older image wrapper, explicit ordinary-only `runner_source = "application"` can supply the
current fixed application wrapper through a read-only bind, with distinct release/source
provenance and no image mutation. This does not supply missing CodeQL tools or target dependencies.
The manual commands below are separate platform-maintenance examples, not the customer-review
execution path or a substitute for backend commissioning; `<build-image>` is an accepted build
environment image and `<uid>:<gid>` its numeric non-root runtime user.

Both derived-image Dockerfiles make the bundled `/opt/codeql` tree readable and its directories
searchable with `chmod -R a+rX` before switching users. Upstream precompiled `.qlx` files can be
owner-only and owned by a different UID. Without this normalization, CodeQL rejects those plans
with `AccessDeniedException` and recompiles them, which can exhaust the query memory/time budget.
This does not grant write access or change query contents, the pinned source image, or asset hashes.
The operator's declared release participates in derived-image identity; update it when these
supplied instructions change. The customer-review path does not hash the Dockerfile.

The focused live regression test reads every bundled `.qlx` as non-root UIDs 1000 and 10001 across
the source-only and build-environment image paths, with a read-only filesystem and no network:

```text
.venv/bin/python -m pytest -q tests/test_live_codeql_toolchains.py -k precompiled_queries
```

`Dockerfile` copies `/opt/codeql` from the source image into an accepted build image:

```text
docker buildx build --load --pull=false --network none \
  --file containers/tools/codeql/Dockerfile \
  --build-arg CODEQL_SOURCE_IMAGE=audit-codeql:custom-2.27.0 \
  --build-arg BUILD_IMAGE=<build-image> \
  --build-arg RUNTIME_USER=<uid>:<gid> \
  --tag appsec-review-codeql:manual containers/tools/codeql
```

`Dockerfile.source` is used when the accepted build image is the source image itself:

```text
docker buildx build --load --pull=false --network none \
  --file containers/tools/codeql/Dockerfile.source \
  --build-arg CODEQL_SOURCE_IMAGE=audit-codeql:custom-2.27.0 \
  --build-arg RUNTIME_USER=<uid>:<gid> \
  --tag appsec-review-codeql:manual containers/tools/codeql
```
