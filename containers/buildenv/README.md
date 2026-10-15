# Build environments

Each enabled build environment is a language-only, non-root (`10001:10001`) image used by
`job_project_build` and `job_language_build`. None inherits the archived native-analysis omnibus or
carries MCP/LSP payloads; analysis tooling lives in its own images.

| Catalog id | Directory | Toolchain | Build profiles |
| --- | --- | --- | --- |
| `buildenv-native-toolchain` | `native-toolchain/` | gcc/g++ 13.3, clang/wasm-ld 18.1, make, pkg-config, python3, strace | base of every family image |
| `audit-buildenv-cpp` | `cpp/` | + CMake 3.28, Ninja, Autotools | `native` |
| `audit-buildenv-go` | `go/` | + Go 1.23.1, `GOTOOLCHAIN=local` | `go` |
| `audit-buildenv-python` | `python/` | + Python 3.12.3 headers, pip 24.0, venv | `python` |
| `audit-buildenv-php` | `php/` | + PHP 8.3.6 CLI/dev (phpize, php-config), Composer 2.7.1, Autotools | `php` |
| `audit-buildenv-rust-wasm` | `rust-wasm/` | + hash-locked Rust 1.90.0 with wasm32-unknown-unknown and wasm32-wasip1 | `rust`, `wasm` |
| `audit-buildenv-typescript` | `typescript/` | + hash-locked Node 22.23.3 (npm 10.9.9), pnpm 9.15.9, Yarn 1.22.22; node-gyp uses the shared compiler | `node` |
| `audit-buildenv-java` | `java/` | OpenJDK 21, hash-locked Maven 3.9.9, Gradle 8.9, Kotlin 2.0.21; strace, python3 | `java` |
| `audit-buildenv-android` | `android/` | JDK 17, Gradle 8.9, Android SDK 35 (Build Tools 35.0.0, platform-tools) | `android` |
| `audit-buildenv-dotnet` | `dotnet/` | .NET SDK 8.0.131 and 10.0.112, hash-locked linux-x64 8.0.31 apphost pack; strace, python3 | `dotnet` |

The C/C++, Go, Python, PHP, Rust/WebAssembly and Node/TypeScript images build `FROM` the shared
native toolchain (see `native-toolchain/README.md`), so those families compile C/C++ with the same
compiler identity. The Java, Android and .NET images do not: Java and .NET start from the
digest-pinned `ubuntu:24.04` image and Android from a digest-pinned `eclipse-temurin:17-jdk-noble`
image, each installing exact-version apt packages (including the same `strace` 6.8 and `python3`
3.12.3 the build capture uses) plus hash-locked release archives. Apt packages are pinned to exact
Ubuntu 24.04 versions; downloaded release assets are listed with their size and SHA-256 in an
`assets.lock.json` and verified before use.

Build them in dependency order (the builder resolves `dependencies`):

```sh
python3 containers/build.py build buildenv-native-toolchain audit-buildenv-cpp audit-buildenv-go \
  audit-buildenv-python audit-buildenv-php audit-buildenv-rust-wasm audit-buildenv-typescript \
  audit-buildenv-java audit-buildenv-android audit-buildenv-dotnet
python3 containers/build.py smoke buildenv-native-toolchain audit-buildenv-cpp audit-buildenv-go \
  audit-buildenv-python audit-buildenv-php audit-buildenv-rust-wasm audit-buildenv-typescript \
  audit-buildenv-java audit-buildenv-android audit-buildenv-dotnet
```

## Profile image pins

`appsec-review.toml` pins every build profile to a tag and a local Docker image id
(`[jobs.job_project_build.settings.profiles.<family>]`). A run resolves the tag and refuses to build
when the local id differs from the pin, so a pin names exactly the bytes the run accepts.

The id is produced by building the image on the host that runs reviews and reading
`docker image inspect <tag> --format '{{.Id}}'` (`build.py build` also records it as `digest` in its
summary). It is not reproducible across hosts: apt archive state, layer timestamps and builder
metadata all change the id even when the Dockerfile and pins are identical. Pins are therefore
host-local (owner decision, 2026-10-15): results are never compared across hosts, slight container
drift between hosts is acceptable, and a changed pin means rerunning, not a defect. Asset locks
(SHA-256 of downloaded inputs) stay exact. Pins are updated per host after a deliberate rebuild,
either by hand or with `appsec-review update-image-pins --run-id <run-id> --write` after a review
run's `job_tool_image_rebuild` reported them as mismatched (see
[`../../docs/operations/tool-image-rebuild.md`](../../docs/operations/tool-image-rebuild.md)); the
pipeline never rewrites them on its own. When a Dockerfile here changes, rebuild the image and
update the pin in the same change for that host. The committed pins name whichever host last
re-pinned (see the last bullet of [`../TODO.md`](../TODO.md)).

The Rust/WebAssembly image backs both the `rust` and `wasm` profiles; update both pins together.

## Still deferred

The former `audit-buildenv-cpp-resolute` variant remains deferred in the catalog.
