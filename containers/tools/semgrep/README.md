# semgrep tool image

`appsec-review/tool-semgrep:1.178.0` is the tool image declared by `tool-semgrep` in
[`containers/catalog.toml`](../../catalog.toml). It builds `FROM`
`appsec-review/base-python:3.12-bookworm`, which must exist locally first. Its external artifacts
are pinned by exact byte size and SHA-256 in `assets.lock.json` and are fetched into the ignored
`downloads/` directory.

## Build

Run from the repository root. The launcher builds missing dependency images in order, fetches and
verifies the locked assets, runs the build with networking disabled, and writes logs under
`runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build tool-semgrep
containers/build-all.ps1 build tool-semgrep
```

Equivalent direct build once the dependency images exist and `downloads/` holds the verified assets:

```text
docker build --network=none --pull=false \
  --file containers/tools/semgrep/Dockerfile \
  --build-arg TOOL_VERSION=1.178.0 \
  --tag appsec-review/tool-semgrep:1.178.0 containers/tools/semgrep
```

Run the startup smoke test:

```text
containers/build-all.sh smoke tool-semgrep
```
