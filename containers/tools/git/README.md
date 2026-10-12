# git tool image

`appsec-review/tool-git:2.43.0` is the tool image declared by `tool-git` in
[`containers/catalog.toml`](../../catalog.toml). It builds `FROM` `appsec-review/base-ubuntu:24.04`,
which must exist locally first. Its single external artifact, the Ubuntu 24.04 `git` package
`1:2.43.0-1ubuntu7.3` from an immutable `snapshot.ubuntu.com` URL, is pinned by exact byte size and
SHA-256 in `assets.lock.json` and is fetched into the ignored `downloads/` directory. Only the `git`
binary is extracted; helper programs, Perl scripts, and remote and credential helpers are not
installed.

## Use

`job_source_history_analysis` runs read-only history queries through
`src/appsec_review/jobs/job_source_history_analysis/git.py`. The target is mounted read-only at
`/target`, an application-written `/gitdir` (minimal `config` and detached `HEAD`) is mounted
read-only as `GIT_DIR`, and output goes to the writable `/scratch`. The target's own Git config,
hooks, and refs are never consulted. The run uses `tool.toml` and
[`runtime-policy.toml`](../../runtime-policy.toml): no network, UID/GID 10001, read-only root,
dropped capabilities, `no-new-privileges`, and bounded CPU, memory, PIDs, time, and output. Its
`tool.toml` sets `static_adapter = false`, so it has no `job_evidence_collection` adapter.

## Build

Run from the repository root. The launcher builds missing dependency images in order, fetches and
verifies the locked assets, runs the build with networking disabled, and writes logs under
`runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build tool-git
containers/build-all.ps1 build tool-git
```

Equivalent direct build once the dependency images exist and `downloads/` holds the verified assets:

```text
docker build --network=none --pull=false \
  --file containers/tools/git/Dockerfile \
  --build-arg TOOL_VERSION=2.43.0 \
  --tag appsec-review/tool-git:2.43.0 containers/tools/git
```

Run the startup smoke test:

```text
containers/build-all.sh smoke tool-git
```
