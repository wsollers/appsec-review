---
title: "sqlite-fts tool image"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: ["job_evidence_collection", "job_review_data_indexing"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# sqlite-fts tool image

`appsec-review/tool-sqlite-fts:1.0.0` is the tool image declared by `tool-sqlite-fts` in
[`containers/catalog.toml`](../../catalog.toml). It builds `FROM`
`appsec-review/base-python:3.12-bookworm`, which must exist locally first. It packages the
repository-owned `sqlite_fts.py` as `/opt/tool/bin/sqlite-fts` and uses the SQLite FTS5 support of
the base image's Python runtime; the build probes FTS5 availability. It downloads nothing, so it has
no `assets.lock.json`. Its expected image ID comes from the host binding frozen into resolved
configuration, not a machine-specific catalog edit; see
[image pin verification](../../../docs/operations/image-pin-verification.md).

## Use

`job_review_data_indexing` runs it through `src/appsec_review/indexing/fts_worker.py`: a `build` step
reads sanitized `documents.jsonl` from the read-only `/target` mount and writes `search.sqlite` to the
writable `/scratch`, and a separate `verify` step checks the built index. The run uses `tool.toml`
and [`runtime-policy.toml`](../../runtime-policy.toml): no network, non-root execution, read-only root,
dropped capabilities, `no-new-privileges`, and bounded CPU, memory, PIDs, time, and output. Its
`tool.toml` sets `static_adapter = false`, so it has no `job_evidence_collection` adapter.

## Build

Run from the repository root. The launcher builds dependency images in order, runs the
build with networking disabled, and writes logs under `runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build tool-sqlite-fts
containers/build-all.ps1 build tool-sqlite-fts
```

Equivalent direct build once the dependency image exists:

```text
docker build --network=none --pull=false --provenance=false --sbom=false \
  --file containers/tools/sqlite-fts/Dockerfile \
  --build-arg TOOL_VERSION=1.0.0 \
  --tag appsec-review/tool-sqlite-fts:1.0.0 containers/tools/sqlite-fts
```

A rebuilt image can have a new ID; refresh its host binding only after reviewing the rebuild.
Run the startup smoke test:

```text
containers/build-all.sh smoke tool-sqlite-fts
```
