# audit-buildenv-cpp-resolute

C and C++ build environment on Ubuntu 26.04 LTS (resolute). Use it for targets whose
dependencies are newer than Ubuntu 24.04 packages: freeciv21 needs Qt >= 6.6 (24.04 has 6.4.2;
resolute has 6.10.2) and KDE Frameworks 6 (`libkf6archive-dev`, absent from 24.04).

Same compiler as `audit-buildenv-cpp`: LLVM/clang 21.1.0 at `/opt/llvm`, copied from
`audit-native:local`, with `CC`/`CXX` fixed to it. Adds cmake, ninja, autotools, bear and
pkg-config from the resolute archive. Build resolution installs target packages into disposable
copy-on-write layers on top; this image itself is sealed.

```bash
python3 -B images/image_build.py build audit-buildenv-cpp-resolute
```
