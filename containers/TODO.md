# Deferred container acceptance work

- Build environments: ten pinned family images are enabled (`containers/buildenv/README.md`), with
  dependency resolution done in derived project images rather than offline. Remaining: share only
  explicit LSP payload layers and add language-server fixtures; per-family compile fixtures exist
  under `tests/fixtures/build_toolchains/` and run in
  `tests/integration/test_family_project_builds.py`.
- GCC build image: `audit-buildenv-cpp` now prefers clang (`CC=clang CXX=clang++`). A GCC counterpart
  image (`CC=gcc CXX=g++`, with the sanitizer runtimes and `-fanalyzer`) and a retry on GCC when the clang
  build fails are not built. The retry needs a second native build profile (`job_project_build` currently
  requires exactly one profile per family) and a recorded fallback in the build result.
- Native analysis: compiler tracing and C/C++ build/AST/IR/ELF evidence (`tool-native-cpp`), Infer
  (`tool-infer`), C/C++ symbol indexing (`tool-clangd-indexer`), and CPG production (`tool-joern`)
  are enabled narrow images, and CodeQL images are packaged outside the catalog
  (`containers/tools/codeql/README.md`). Remaining: decide whether the other archived `audit-native`
  capabilities (SVF, CodeChecker) earn a bounded image (Ghidra is now `tool-ghidra`), then retire or replace the deferred
  `audit-native`, `audit-codeql`, and `audit-lsp-vendor` catalog entries.
- Binary analysis: add a specialized capability only when BLint/Syft/Grype/Trivy do not satisfy a
  job contract; prohibit curl-to-shell installers and duplicated scanners.
- Ghidra (`tool-ghidra`): close the open items in `containers/tools/ghidra/LICENSE.md` (advisory
  match, full per-module license read, unused-module trim), replace the JRE-plus-JDK arrangement
  with one reviewed `base-jdk`, pin `image_id` in the catalog, lint the Dockerfile, and add a PE
  fixture.
- ScanCode: evaluate a fixed official release artifact or image, verify its license database and
  output schema, and compare its incremental value with Syft before enabling.
- Microsoft SBOM Tool and SBOM Assembly: keep replaced by Syft unless a concrete job contract proves
  a missing format or merge feature.
- Document conversion: resolve a complete hashed `.deb` closure for pandoc/poppler and add PDF/DOCX
  functional fixtures.
- Report rendering: `tool-report-latex` is enabled (hash-locked 111-package closure, deterministic PDF,
  functional smoke). Remaining: call it from a publication job (none does yet; `renderers.pdf.state`
  stays `not_rendered`), then drop `manual = true` from its catalog entry and pin its `image_id` (the pin gate
  skips it until then), and add a pdftoppm visual check.
- Dagster: orchestration is an application deployment concern; do not restore its archived image.
- Image-ID pins are host-local (owner decision, 2026-10-15). Results are never compared across
  hosts, slight container drift between hosts is acceptable, and a changed pin means rerunning, not
  a defect. The committed `image_id` pins in `appsec-review.toml`, `containers/catalog.toml` and
  `containers/tools/codeql/assets.lock.json` currently name whichever host last re-pinned
  (Zarathustra, 2026-10-15), so every other host fails its pin checks until it re-pins. Exception:
  `buildenv-rust-wasm` is pinned to `sha256:9b358785…` (replacing `sha256:38cc04b7…`), built with
  `python containers/build.py build audit-buildenv-rust-wasm` on a WSL 2 host. The pinned images
    build from this repository's Dockerfiles on any Linux Docker host (the CodeQL images with
    `containers/tools/codeql/build-source-image.sh`). Remaining:
  resolve each pinned tag to the local host's image ID when a run starts and bind that observed ID
  into the run's resolved configuration (a changed image then invalidates reuse and forces a
  rerun), drop the cross-host equality assertions in the live and integration tests
  (`tests/integration/test_node_project_builds.py`, `tests/test_live_android_build.py`, the
  `APPSEC_REVIEW_BUILDENV_PINS=local` opt-in in `tests/integration/test_family_project_builds.py`).
  Asset locks stay enforced at build time, but they record what a working build downloaded, not a
  reproducible target: when upstream moves, re-acquire and record the new hash (see
  [Moving forward, not reproducing](README.md#moving-forward-not-reproducing)).
