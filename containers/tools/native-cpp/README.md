# native-cpp tool image

`appsec-review/tool-native-cpp:1.0.0` is the tool image declared by `tool-native-cpp` in
[`containers/catalog.toml`](../../catalog.toml).

Its only external artifact, the 166-package `.deb` closure, is pinned by exact byte size and
SHA-256 in `assets.lock.json`. The closure is acquired separately (its lock URL is the Ubuntu
archive root, not a downloadable file), so place it at `downloads/native-cpp-debs.tar` before
building. The launcher verifies it and stops if it is missing or does not match.

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
