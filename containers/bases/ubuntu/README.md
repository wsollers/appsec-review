# ubuntu base image

`appsec-review/base-ubuntu:24.04` is the shared runtime base image declared by `base-ubuntu` in
[`containers/catalog.toml`](../../catalog.toml).

## Build

Run from the repository root. The launcher runs the build with networking disabled and writes logs
under `runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build base-ubuntu
containers/build-all.ps1 build base-ubuntu
```

Equivalent direct build:

```text
docker build --network=none --pull=false \
  --file containers/bases/ubuntu/Dockerfile \
  --tag appsec-review/base-ubuntu:24.04 containers/bases/ubuntu
```

Run the startup smoke test:

```text
containers/build-all.sh smoke base-ubuntu
```
