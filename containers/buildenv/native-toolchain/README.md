# Shared native toolchain

Every language build environment compiles C and C++ with one toolchain: node-gyp addons, phpize
extensions, setuptools C extensions, cgo, clang `--target=wasm32` and direct native builds.

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
metapackage only selects the major version), clang and wasm-ld 18.1.3, GNU Make 4.3,
pkg-config 1.8.1, Python 3.12.3 (node-gyp's gyp and the capture wrapper), and strace 6.8 (execution
capture). `check-toolchain.sh` fails the image build when any of these identities differ.

## Why a base image

All family build environments (C/C++, Go, Python, PHP, Rust/WebAssembly, and Node) are Ubuntu 24.04
images on the digest-pinned `base-ubuntu` boundary. A shared distribution makes a base image the
simplest single definition: the toolchain layer is built once, stored once on disk, and every family
image inherits exactly the same compiler files. The manifest exists for an image that must keep a
different `FROM` (for example an upstream language image on Ubuntu 24.04); it still installs the
same pins and runs the same check.

The base contains no language runtime and no analysis tooling. Analysis images (clang-tidy,
CodeQL, Joern, Infer, LSPs) stay separate.
