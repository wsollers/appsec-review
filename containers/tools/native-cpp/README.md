# native-cpp tool image

`appsec-review/tool-native-cpp:1.0.0` is the tool image declared by `tool-native-cpp` in
[`containers/catalog.toml`](../../catalog.toml).

Its only external artifact is the `.deb` closure for `clang-18`, `cmake` and `bear`, pinned by
exact byte size and SHA-256 in `assets.lock.json`. `packages.manifest` lists every package, version
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
