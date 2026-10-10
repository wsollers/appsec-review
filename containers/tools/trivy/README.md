# trivy tool image

`appsec-review/tool-trivy:0.74.0` is the tool image declared by `tool-trivy` in
[`containers/catalog.toml`](../../catalog.toml). It builds `FROM` `appsec-review/base-ubuntu:24.04`,
which must exist locally first. Its external artifacts are pinned by exact byte size and SHA-256 in
`assets.lock.json` and are fetched into the ignored `downloads/` directory.

## Build

Run from the repository root. The launcher builds missing dependency images in order, fetches and
verifies the locked assets, runs the build with networking disabled, and writes logs under
`runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build tool-trivy
containers/build-all.ps1 build tool-trivy
```

Equivalent direct build once the dependency images exist and `downloads/` holds the verified assets:

```text
docker build --network=none --pull=false \
  --file containers/tools/trivy/Dockerfile \
  --build-arg TOOL_VERSION=0.74.0 \
  --tag appsec-review/tool-trivy:0.74.0 containers/tools/trivy
```

Run the startup smoke test:

```text
containers/build-all.sh smoke tool-trivy
```
