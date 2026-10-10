# native-cpp tool image

`appsec-review/tool-native-cpp:1.0.0` is the tool image declared by `tool-native-cpp` in
[`containers/catalog.toml`](../../catalog.toml).

The catalog declares no `assets_lock` for this image, so the launcher does not fetch its inputs. The
166-package `.deb` closure is acquired separately and must already be present as
`downloads/native-cpp-debs.tar`, matching the byte size and SHA-256 recorded in `assets.lock.json`.

## Build

Run from the repository root. The launcher runs the build with networking disabled and writes logs
under `runs/container-builds/<run-id>/`:

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
