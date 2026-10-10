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
source tag whose identity changed.

## Derived analysis images

The CodeQL job builds the derived images itself (`src/appsec_review/codeql/runtime.py`), tagging
them `appsec-review-codeql:<identity>` and caching their manifest under the job's
`codeql-images/` metadata directory. Do not tag these by hand. For diagnosis, the equivalent commands
are below; `<build-image>` is an accepted build environment image and `<uid>:<gid>` its numeric
non-root runtime user.

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
