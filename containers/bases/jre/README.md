# jre base image

`appsec-review/base-jre:21-noble` is the shared runtime base image declared by `base-jre` in
[`containers/catalog.toml`](../../catalog.toml).

## Build

Run from the repository root. The launcher runs the build with networking disabled and writes logs
under `runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build base-jre
containers/build-all.ps1 build base-jre
```

Equivalent direct build:

```text
docker build --network=none --pull=false \
  --file containers/bases/jre/Dockerfile \
  --tag appsec-review/base-jre:21-noble containers/bases/jre
```

Run the startup smoke test:

```text
containers/build-all.sh smoke base-jre
```
