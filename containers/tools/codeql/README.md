# CodeQL images

CodeQL is not in `containers/catalog.toml` and is not built by `containers/build-all.sh`. The
licensed CodeQL payload is operator-provided (see [`LICENSE.md`](LICENSE.md)); this directory holds
only the layers the repository adds on top of it. Run every command from the repository root.

## Licensed source image

`Dockerfile.custom-source` layers the release-pinned CERT C++ coding-standards query pack onto an
operator-provided licensed image (default `audit-codeql:local`). Download
`coding-standards-codeql-packs.zip` from the `github/codeql-coding-standards@v2.62.0` release into
this directory first; the build verifies its SHA-256 before extracting it. The archive is not
ignored by git; delete it after the build and never commit it.

```text
docker build --network=none --pull=false \
  --file containers/tools/codeql/Dockerfile.custom-source \
  --build-arg CODEQL_SOURCE_IMAGE=audit-codeql:local \
  --tag audit-codeql:custom-2.27.0 containers/tools/codeql
docker image inspect audit-codeql:custom-2.27.0 --format "{{.Id}}"
```

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
