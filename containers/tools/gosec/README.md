---
title: "gosec tool image"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: []
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# gosec tool image

`appsec-review/tool-gosec:2.29.0` is the tool image declared by `tool-gosec` in
[`containers/catalog.toml`](../../catalog.toml). It builds `FROM` `appsec-review/base-ubuntu:24.04`,
which must exist locally first. Its external artifacts are pinned by exact byte size and SHA-256 in
`assets.lock.json` and are fetched into the ignored `downloads/` directory.

## Build

Run from the repository root. The launcher builds dependency images in order, fetches and
verifies the locked assets, runs the build with networking disabled, and writes logs under
`runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build tool-gosec
containers/build-all.ps1 build tool-gosec
```

Equivalent direct build once the dependency images exist and `downloads/` holds the verified assets:

```text
docker build --network=none --pull=false --provenance=false --sbom=false \
  --file containers/tools/gosec/Dockerfile \
  --build-arg TOOL_VERSION=2.29.0 \
  --tag appsec-review/tool-gosec:2.29.0 containers/tools/gosec
```

Run the startup smoke test:

```text
containers/build-all.sh smoke tool-gosec
```
