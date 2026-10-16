# SVF points-to tool image

`appsec-review/tool-svf:3.3.0` runs SVF-3.3's field-sensitive Andersen analysis over clang-18
bitcode of one accepted C/C++ scope for `job_svf_alias_analysis`
([design](../../../docs/architecture/svf-alias-producer.md),
[operations](../../../docs/operations/svf-alias-analysis.md)).

## Contents

| Path | What it is |
| --- | --- |
| `/opt/appsec/svf.py` | Bounded wrapper: `version`, and `run /scratch/plan.json /scratch/result.json` (compile, link, analyze per planned module). |
| `/opt/svf/bin/svf-alias-export` | Repository-owned driver ([`driver/`](driver/)), built inside the SVF source tree against `SvfCore`/`SvfLLVM`. Writes `appsec-review/svf-alias-output/1`. |
| `/opt/svf/bin/llvm-link-21` | LLVM 21.1.0 `llvm-link`, which links and upgrades clang-18 bitcode. |
| `/opt/svf/lib/extapi.bc` | SVF's external-function models. |
| `clang-18` (inherited) | The compiler of record from `tool-native-cpp`. Target bitcode is never produced by LLVM 21. |

## Build

All inputs are pinned in [`assets.lock.json`](assets.lock.json) and fetched into the ignored
`downloads/` cache by [`acquire_assets.sh`](acquire_assets.sh): the SVF-3.3 source, the RTTI LLVM
21.1.0 distribution and Z3 4.8.8 that SVF-3.3's `build.sh` names, and a deterministic `.deb` tar of
the zlib, zstd and libxml2 development headers (build stage only, listed in
[`packages.manifest`](packages.manifest)). The Docker build itself is offline (`--network none`).
SVF is compiled in its own cached layer, so a driver change rebuilds only the driver.

The catalog builder (`python containers/build.py build tool-svf`) rebuilds `tool-native-cpp`
first, which needs that image's own download cache. When `tool-native-cpp:1.0.0` is already present
locally, build this image directly with the same offline settings:

```bash
docker build --network none --pull=false --build-arg TOOL_VERSION=3.3.0 -t appsec-review/tool-svf:3.3.0 containers/tools/svf
```

Then record the new image id as `image_id` for `tool-svf` in `containers/catalog.toml`. The live
tier (`tests/live/test_svf_live.py`) runs only when the local image matches that pin.

## Runtime policy

The image runs under the central container policy: no network, read-only root, non-root
`10001:10001`, all capabilities dropped, 1 GiB memory and 600 s per scope. The target is mounted
read-only and only clang, llvm-link and the driver run; the target is never executed. A module that
exceeds a bound is a named gap in the job's coverage, never an empty clean result.

## License

SVF is `AGPL-3.0-or-later`; see [`LICENSE.md`](LICENSE.md). This image is used internally and is
not redistributed.
