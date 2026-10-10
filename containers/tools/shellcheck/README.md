# shellcheck tool image

`appsec-review/tool-shellcheck:0.11.0.1` is the tool image declared by `tool-shellcheck` in
[`containers/catalog.toml`](../../catalog.toml). It builds `FROM`
`appsec-review/base-python:3.12-bookworm`, which must exist locally first. Its external artifacts
are pinned by exact byte size and SHA-256 in `assets.lock.json` and are fetched into the ignored
`downloads/` directory.

## Build

Run from the repository root. The launcher builds missing dependency images in order, fetches and
verifies the locked assets, runs the build with networking disabled, and writes logs under
`runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build tool-shellcheck
containers/build-all.ps1 build tool-shellcheck
```

Equivalent direct build once the dependency images exist and `downloads/` holds the verified assets:

```text
docker build --network=none --pull=false \
  --file containers/tools/shellcheck/Dockerfile \
  --build-arg TOOL_VERSION=0.11.0.1 \
  --tag appsec-review/tool-shellcheck:0.11.0.1 containers/tools/shellcheck
```

Run the startup smoke test:

```text
containers/build-all.sh smoke tool-shellcheck
```
