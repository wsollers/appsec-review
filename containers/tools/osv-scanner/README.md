# osv-scanner tool image

`appsec-review/tool-osv-scanner:1.9.2` is the tool image declared by `tool-osv-scanner` in
[`containers/catalog.toml`](../../catalog.toml). It builds `FROM` `appsec-review/base-ubuntu:24.04`,
which must exist locally first. Its external artifacts are pinned by exact byte size and SHA-256 in
`assets.lock.json` and are fetched into the ignored `downloads/` directory.

## Build

Run from the repository root. The launcher builds missing dependency images in order, fetches and
verifies the locked assets, runs the build with networking disabled, and writes logs under
`runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build tool-osv-scanner
containers/build-all.ps1 build tool-osv-scanner
```

Equivalent direct build once the dependency images exist and `downloads/` holds the verified assets:

```text
docker build --network=none --pull=false \
  --file containers/tools/osv-scanner/Dockerfile \
  --build-arg TOOL_VERSION=1.9.2 \
  --tag appsec-review/tool-osv-scanner:1.9.2 containers/tools/osv-scanner
```

Run the startup smoke test:

```text
containers/build-all.sh smoke tool-osv-scanner
```
