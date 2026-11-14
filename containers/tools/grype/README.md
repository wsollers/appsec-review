---
title: "grype tool image"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: ["job_third_party_data_sync"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# grype tool image

The independent `job_third_party_data_sync.grype_db_sync` step imports and validates the mirrored
v6 database with this exact tool release and an observed immutable image ID. Its host-side fetch
may reach the network; this image stays `network = "none"` for both database validation and
scanning. Consumers require the validated `grype-snapshot/2` cache and a fresh upstream build.
See [database synchronization](../../../docs/operations/third-party-data-sync.md#grype-database-cache).
This does not enable the currently disabled Grype scanner.

`appsec-review/tool-grype:0.119.0` is the tool image declared by `tool-grype` in
[`containers/catalog.toml`](../../catalog.toml). It builds `FROM` `appsec-review/base-ubuntu:24.04`,
which must exist locally first. Its external artifacts are pinned by exact byte size and SHA-256 in
`assets.lock.json` and are fetched into the ignored `downloads/` directory.

## Build

Run from the repository root. The launcher builds dependency images in order, fetches and
verifies the locked assets, runs the build with networking disabled, and writes logs under
`runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build tool-grype
containers/build-all.ps1 build tool-grype
```

Equivalent direct build once the dependency images exist and `downloads/` holds the verified assets:

```text
docker build --network=none --pull=false --provenance=false --sbom=false \
  --file containers/tools/grype/Dockerfile \
  --build-arg TOOL_VERSION=0.119.0 \
  --tag appsec-review/tool-grype:0.119.0 containers/tools/grype
```

Run the startup smoke test:

```text
containers/build-all.sh smoke tool-grype
```
