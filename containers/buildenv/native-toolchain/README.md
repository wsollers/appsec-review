---
title: "Shared native toolchain"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: []
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Shared native toolchain

The C/C++, Go, Python, PHP, Rust/WebAssembly and Node/TypeScript build environments share one
C/C++ toolchain: node-gyp addons, phpize extensions, setuptools C extensions, cgo,
clang `--target=wasm32` and direct native builds. Java, Android and .NET use separate bases.

It also carries the build drivers every family may meet (T-058): Autotools 2.71, libtool 2.4.7,
CMake 3.28, Ninja 1.11, Meson 1.3 and pkg-config. A Go module with cgo + CMake, a Python package
built with scikit-build or meson-python, a Rust crate using the `cc`/`cmake` crates or a node-gyp
addon finds its driver in whichever family image it lands in, and the plan reads one capability set
for the whole family. Bazel is deliberately absent — a JVM binary that fetches rules at build time
and needs a vendored repository cache to run offline is a per-target provision (T-050), not a base
ingredient. Gradle and Maven live in the JVM environments.

## Interface

There are two forms. Consumers use whichever fits; both pin the same packages.

| Form | Path or tag | Use |
| --- | --- | --- |
| Base image (preferred) | `appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1`, catalog id `buildenv-native-toolchain` | `FROM` it and add the catalog `dependencies = ["buildenv-native-toolchain"]` |
| Pin manifest | `containers/buildenv/native-toolchain/packages.lock` | an Ubuntu 24.04 image that cannot use the base installs every line verbatim |
| Identity check | `/opt/native-toolchain/check-toolchain.sh` (in the image), source `check-toolchain.sh` | every consumer runs it after installing its own packages |

`packages.lock` has one exact apt pin per line (`name=version`); lines starting with `#` are
comments. Install it with:

```sh
apt-get install -y --no-install-recommends $(grep -v '^#' packages.lock)
```

The pinned toolchain is gcc/g++ 13.3.0 (`gcc-13`/`g++-13` pinned explicitly because the `gcc`
metapackage only selects the major version), clang, wasm-ld and LLVM symbol readers 18.1.3, GNU Make 4.3,
pkg-config 1.8.1, Python 3.12.3 (node-gyp's gyp and the capture wrapper), and strace 6.8 (execution
capture). `check-toolchain.sh` fails the image build when any of these identities differ.

`llvm-18=1:18.1.3-1ubuntu1` supplies both `/usr/bin/llvm-dwarfdump-18` and
`/usr/bin/llvm-pdbutil-18`. Every inheriting family image therefore has the readers alongside its
compiler, and the build-time identity check verifies both reader versions. A package-owned bounded
Python exporter can be mounted read-only and invoked with `/usr/bin/python3` in a fresh restricted
container; it does not need to be copied into the image or installed from a target.
For prebuilt artifacts or legacy build environments without the readers, the provisioned
[`tool-native-cpp`](../../tools/native-cpp/README.md) analysis image is the approved fallback.

These package/image identities are not graph/2 native target proof. Execution and prepared-image
replay require separately accepted static compiler metadata bound to the actual immutable image,
supported effective command closure and exact recipe. No metadata acquisition, new image build
or Windows/mobile builder provisioning is delivered by the topology source change. Native CMake
without supported compiler closure remains blocked; target labels and this README cannot prove it.

## Why a base image

These six family build environments (C/C++, Go, Python, PHP, Rust/WebAssembly, and Node) are Ubuntu 24.04
images on the digest-pinned `base-ubuntu` boundary. A shared distribution makes a base image the
simplest single definition: the toolchain layer is built once, stored once on disk, and every family
image in that set inherits exactly the same compiler files. The manifest exists for an image that
must keep a different `FROM` (for example an upstream language image on Ubuntu 24.04); it still installs the
same pins and runs the same check.

The base contains no language-specific runtime or analysis framework. LLVM symbol readers are
toolchain utilities; analysis images (clang-tidy, CodeQL, Joern, Infer, LSPs) stay separate.
