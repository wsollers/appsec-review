---
title: "native-cpp tool image"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: ["job_cpp_compiled_analysis"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# native-cpp tool image

`appsec-review/tool-native-cpp:1.0.0` is the tool image declared by `tool-native-cpp` in
[`containers/catalog.toml`](../../catalog.toml).

Its only external artifact is the `.deb` closure for `clang-18`, `cmake` and `bear`, plus the PHP
8.3 and Python 3.12 development headers (`php8.3-cli`, `php8.3-dev`, `python3-dev`, which brings
`python3.12-dev` and `libpython3.12-dev`), pinned by exact byte size and SHA-256 in
`assets.lock.json`. `packages.manifest` lists every package, version
and SHA-256 in it. The lock URL is the Ubuntu archive root, not a downloadable file.
The catalog builder calls the acquisition helper when the tar is missing or mismatched; it can
also be invoked explicitly:

```text
containers/tools/native-cpp/acquire_assets.sh
```

The script resolves the closure inside the Dockerfile's pinned Ubuntu base against Ubuntu snapshot
`20261015T070000Z`, with the host CA bundle mounted read-only. Acquisition uses the network; APT
verifies signed archive metadata and package hashes. The tar is written deterministically to
`downloads/native-cpp-debs.tar`. The launcher removes stale locked files before acquisition and
rejects a result that still differs from the lock. A deliberate closure change requires reviewing
the new tar size/hash and `downloads/packages.manifest`, then updating `assets.lock.json` and
`packages.manifest` before the catalog build; acquisition does not silently re-lock them.

## Debug-symbol reader fallback

This image is the approved analysis-image fallback for prebuilt artifacts or legacy compiler images
without LLVM readers. The existing locked closure already includes
`llvm-18=1:18.1.3-1ubuntu1`, which supplies `/usr/bin/llvm-dwarfdump-18` and
`/usr/bin/llvm-pdbutil-18`, and `python3=3.12.3-0ubuntu2.1`. No additional acquisition or lock
refresh is needed for these utilities. The Dockerfile checks both reader versions and Python at
build time.

`tool.toml` permits `/usr/bin/python3` as an additional entrypoint, preserving the main
`/opt/appsec/native.py` entrypoint. A package-owned bounded Python exporter is mounted read-only
and invoked with that interpreter in a fresh container under the existing restricted runtime
policy; target-provided scripts are not the exporter. New compiler images inherit the same LLVM
readers from the shared native toolchain instead.

## Extension headers

`job_cpp_compiled_analysis` replays here the C compiles captured inside other build environments:
phpize extensions built in `buildenv-php` (`php-config --includes` gives
`-I/usr/include/php/20230831`, `.../main`, `.../TSRM`, `.../Zend`, `.../ext` and
`.../ext/date/lib`) and setuptools extensions built in `buildenv-python` (`-I/usr/include/python3.12`,
whose `pyconfig.h` includes `/usr/include/x86_64-linux-gnu/python3.12/pyconfig.h`). Normalization
keeps absolute system include directories verbatim, so the replay resolves them only if this image
has the same files at the same paths. Both build environments and this image are Ubuntu noble, so
installing the same packages gives the same paths. `acquire_assets.sh` pins the PHP and Python
packages at the versions those build environments' Dockerfiles install; change them together (a
test fails when they differ). The Dockerfile asserts the headers, the `php-config8.3` and
`python3.12-config` include paths, and a Clang syntax check of `php.h` and `Python.h`.

Replay uses this analysis image's fixed Clang 18 driver and header closure rather than depending
on each family image. The shared native build environments now carry both gcc and Clang; that
availability does not change the job's replay image.

A header that is still missing (for example a generated `config.h` that existed only in the build
workspace) is not hidden. The replay receipt records each translation unit's exit and stderr, and
the job records a named gap such as
`ext/x/x.c: ast replay header not found in tool-native-cpp: config.h (...)` for that unit while
indexing the units that did replay.

## Build

Run from the repository root. The launcher verifies the locked asset, runs the build with
networking disabled, and writes logs under `runs/container-builds/<run-id>/`:

```text
containers/build-all.sh build tool-native-cpp
containers/build-all.ps1 build tool-native-cpp
```

Equivalent direct build once `downloads/native-cpp-debs.tar` is in place and verified against the lock:

```text
docker build --network=none --pull=false --provenance=false --sbom=false \
  --file containers/tools/native-cpp/Dockerfile \
  --build-arg TOOL_VERSION=1.0.0 \
  --tag appsec-review/tool-native-cpp:1.0.0 containers/tools/native-cpp
```

Run the startup smoke test:

```text
containers/build-all.sh smoke tool-native-cpp
```
