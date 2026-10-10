# php base image

`appsec-review/base-php:8.4-bookworm` is the shared runtime base image declared by `base-php` in
[`containers/catalog.toml`](../../catalog.toml).

## Build

Run from the repository root. The launcher runs the build with networking disabled and writes logs
under `runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build base-php
containers/build-all.ps1 build base-php
```

Equivalent direct build:

```text
docker build --network=none --pull=false \
  --file containers/bases/php/Dockerfile \
  --tag appsec-review/base-php:8.4-bookworm containers/bases/php
```

Run the startup smoke test:

```text
containers/build-all.sh smoke base-php
```
