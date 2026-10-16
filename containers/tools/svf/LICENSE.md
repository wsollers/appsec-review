# tool-svf: license review

Reviewed 2026-10-16 for the inputs locked in [`assets.lock.json`](assets.lock.json). No archive is
committed; the repository holds the lock, the package manifest, the wrapper and the driver source.

## SVF

SVF-3.3 is `AGPL-3.0-or-later` (`LICENSE.TXT` in the source archive, copied into the image as
`/opt/svf/LICENSE-SVF.TXT`). Its `LICENSE.TXT` lists vendored third-party code under its own
licenses: fastcluster/hclust-cpp (`svf/include/FastCluster/`, `svf/lib/FastCluster/`), LLVM's
`SparseBitVector.h` (Apache-2.0) and cJSON (MIT).

**Use decision.** The repository owner accepted the AGPL for this use on 2026-10-16: the image is
used internally, is not commercial and is not redistributed. The driver links SVF inside this image
only, and `appsec-review` exchanges files with it (bitcode and a plan in, JSON out); no SVF code is
linked into the `appsec-review` package. Redistributing the image would require offering the
corresponding SVF source, including the driver.

**Provenance and signatures.** The source archive is GitHub's tag archive for `SVF-3.3`. No detached
signature or attestation is published, so the lock records `not-published` and pins exact bytes.

## LLVM 21.1.0

`Apache-2.0 WITH LLVM-exception`. The RTTI distribution is the release asset SVF-3.3's `build.sh`
downloads (`bjjwwang/SVF-LLVM`, tag `21.1.0`); no signature is published. Only `libLLVM.so` and
`llvm-link` are copied into the runtime image.

## Z3 4.8.8

`MIT` (`LICENSE.txt` in the release archive, copied as `/opt/svf/LICENSE-Z3.txt`). Only `libz3.so` is
copied into the runtime image.

## Build-only Ubuntu packages

`zlib1g-dev`, `libzstd-dev`, `libxml2-dev` and the matching `libxml2` (zlib, BSD-3-Clause and MIT
per their copyright files) are installed in the build stage only and are not part of the runtime
image. Versions and SHA-256 are in [`packages.manifest`](packages.manifest).

## Runtime base

The runtime stage is `appsec-review/tool-native-cpp:1.0.0`; its review is that image's own.
