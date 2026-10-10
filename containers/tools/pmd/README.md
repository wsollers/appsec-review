# pmd tool image

`appsec-review/tool-pmd:7.28.0` is the tool image declared by `tool-pmd` in
[`containers/catalog.toml`](../../catalog.toml). It builds `FROM` `appsec-review/base-jre:21-noble`,
which must exist locally first. Its external artifacts are pinned by exact byte size and SHA-256 in
`assets.lock.json` and are fetched into the ignored `downloads/` directory.

## Build

Run from the repository root. The launcher builds missing dependency images in order, fetches and
verifies the locked assets, runs the build with networking disabled, and writes logs under
`runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build tool-pmd
containers/build-all.ps1 build tool-pmd
```

Equivalent direct build once the dependency images exist and `downloads/` holds the verified assets:

```text
docker build --network=none --pull=false \
  --file containers/tools/pmd/Dockerfile \
  --build-arg TOOL_VERSION=7.28.0 \
  --tag appsec-review/tool-pmd:7.28.0 containers/tools/pmd
```

Run the startup smoke test:

```text
containers/build-all.sh smoke tool-pmd
```
