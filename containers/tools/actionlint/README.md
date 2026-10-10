# actionlint tool image

`appsec-review/tool-actionlint:1.7.12` is the tool image declared by `tool-actionlint` in
[`containers/catalog.toml`](../../catalog.toml). It builds `FROM` `appsec-review/base-ubuntu:24.04`,
which must exist locally first. Its external artifacts are pinned by exact byte size and SHA-256 in
`assets.lock.json` and are fetched into the ignored `downloads/` directory.

## Build

Run from the repository root. The launcher builds missing dependency images in order, fetches and
verifies the locked assets, runs the build with networking disabled, and writes logs under
`runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build tool-actionlint
containers/build-all.ps1 build tool-actionlint
```

Equivalent direct build once the dependency images exist and `downloads/` holds the verified assets:

```text
docker build --network=none --pull=false \
  --file containers/tools/actionlint/Dockerfile \
  --build-arg TOOL_VERSION=1.7.12 \
  --tag appsec-review/tool-actionlint:1.7.12 containers/tools/actionlint
```

Run the startup smoke test:

```text
containers/build-all.sh smoke tool-actionlint
```
