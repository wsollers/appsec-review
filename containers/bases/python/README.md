# python base image

`appsec-review/base-python:3.12-bookworm` is the shared runtime base image declared by `base-python`
in [`containers/catalog.toml`](../../catalog.toml).

## Build

Run from the repository root. The launcher runs the build with networking disabled and writes logs
under `runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build base-python
containers/build-all.ps1 build base-python
```

Equivalent direct build:

```text
docker build --network=none --pull=false \
  --file containers/bases/python/Dockerfile \
  --tag appsec-review/base-python:3.12-bookworm containers/bases/python
```

Run the startup smoke test:

```text
containers/build-all.sh smoke base-python
```
