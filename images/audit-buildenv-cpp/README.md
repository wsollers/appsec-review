# audit-buildenv-cpp

C and C++ build environment for ADR-0012 Revision 3. It extends the host-built,
B16-registered `audit-native:local` image so build resolution and later native
analysis use the same LLVM 21.1.0 installation at `/opt/llvm`.

The image fixes `CC=/opt/llvm/bin/clang` and `CXX=/opt/llvm/bin/clang++` and adds
the autotools build prerequisites `autoconf`, `automake`, `libtool`, `make`,
`bear`, and `pkg-config`, with their Ubuntu package versions fixed in the
Dockerfile. Build-resolution trials run with no network; `bear` captures
compile commands without changing the selected compiler.

Build and verify:

```bash
python3 -B images/image_build.py build audit-buildenv-cpp
python3 -B -m unittest images.tests.test_audit_buildenv_cpp
APPSEC_LIVE_DOCKER_TESTS=1 python3 -B -m unittest \
  images.tests.test_audit_buildenv_cpp.LiveDocker
```

`image_build.py` fingerprints this folder and the immutable local image ID of
`audit-native:local`. Its successful state under `images/.build-state/` and the
B16 registry record under `appsec-review-process/pipeline/container-images/`
are host-local generated data and must not be committed.
