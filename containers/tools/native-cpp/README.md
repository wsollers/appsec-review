# native-cpp tool image

`appsec-review/tool-native-cpp:1.0.0` is the tool image declared by `tool-native-cpp` in
[`containers/catalog.toml`](../../catalog.toml).

Its only external artifact is the `.deb` closure for `clang-18`, `cmake` and `bear`, plus the PHP
8.3 and Python 3.12 development headers (`php8.3-cli`, `php8.3-dev`, `python3-dev`, which brings
`python3.12-dev` and `libpython3.12-dev`), pinned by exact byte size and SHA-256 in
`assets.lock.json`. `packages.manifest` lists every package, version
and SHA-256 in it. The lock URL is the Ubuntu archive root, not a downloadable file, so acquire the
closure first:

```text
containers/tools/native-cpp/acquire_assets.sh
```

The script resolves the closure inside the Dockerfile's pinned Ubuntu base, so it is exactly what the
offline install needs. APT verifies the signed archive metadata and each package hash, and the tar is
written deterministically to `downloads/native-cpp-debs.tar`. The Ubuntu archive moves as updates
are published, so a later acquisition can give a different closure. When it does, build and smoke
the image, then record the new tar size and SHA-256 in `assets.lock.json` and commit the new
`downloads/packages.manifest` as `packages.manifest`. The launcher verifies the tar and stops if it
is missing or does not match the lock.

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

Replaying in each unit's own build-environment image was rejected: those images carry gcc, not this
image's Clang 18 replay driver, and the AST and IR lanes would then depend on every family image.

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

Equivalent direct build once `downloads/native-cpp-debs.tar` is in place:

```text
docker build --network=none --pull=false \
  --file containers/tools/native-cpp/Dockerfile \
  --build-arg TOOL_VERSION=1.0.0 \
  --tag appsec-review/tool-native-cpp:1.0.0 containers/tools/native-cpp
```

Run the startup smoke test:

```text
containers/build-all.sh smoke tool-native-cpp
```
