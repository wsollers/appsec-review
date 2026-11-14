---
title: "Native admission from builder-image compiler profiles"
kind: "history"
subsystem: "target acquisition and build"
status: "historical"
jobs: ["job_language_build", "job_project_build"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Native admission from builder-image compiler profiles

Status: **rollout step 1 implemented** (the `/2` record schema, probe script, transcript parser
and collector in `appsec_review.container_runtime.compiler_profiles`, with unit tests). Rollout
steps 2–8 remain **proposed for review**; nothing consumes `/2` records yet. The unit tests use
explicitly synthetic transcripts shaped like the default builder images and inert, structurally
valid ELF fixtures. The collector has not yet been validated against the live builder images.

## Problem

`refine_build_topology` creates a `_native_enforcement` proof for every `native_compile`,
`native_link` and `native_aot` operation. A build unit that has any unproven native operation is
blocked with `unenforced_native_target`, and `guard_action` refuses to execute it. Commit
`0bc2ffcb` introduced this check. Since then, every real C/C++, PHP-extension, Rust, Go and wasm
build ends `COMPLETED_WITH_GAPS`. The checked-in pipeline cannot prove the target of anything it
compiles natively.

There are three reasons.

1. **No compiler metadata reaches enforcement.**
   - Planning (`planning._publish_build_graph`) and `job_project_build` `plan.load_recipes` call
     `bind_actions(...)` without `profiles=`.
   - So every proof's default branch records `compiler_target_unknown`.
   - Only unit tests supply the synthetic `appsec-review/static-compiler-profile/1` mapping
     (`tests/test_native_target_enforcement._profile()`). The recipe-replay path also accepts
     such metadata through `_approved_compiler_metadata`, but nothing produces it.
2. **Enforcement understands only direct compiler commands.**
   - The default branch proves axes only when every recipe `argv[0]` equals the profile
     `executable`. In practice that means `clang`, `gcc` and similar compilers called directly.
   - The deterministic recipes the job actually emits use build drivers instead:
     - CMake: `cmake -S … -B …` and `cmake --build`;
     - phpize: `phpize`, `./configure` and `make`;
     - `cargo build`;
     - `go build`.
   - Go has its own branch (`go_explicit_target`). It needs `GOOS`/`GOARCH` in the recipe
     environment and treats `CGO_ENABLED=1` as unprovable.
3. **One profile per refinement.**
   - `refinement["profiles"]` is a single mapping, and `guard_action` requires its
     `image_digest` to equal the action's image.
   - One `bind_actions` call binds every action, and each family uses a different builder
     image. A single mapping therefore cannot cover a multi-family target.

The cpp, php, go, rust-wasm, python and typescript builder images
(`containers/buildenv/<name>/`) are built
`FROM appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1`. They share one pinned
gcc 13.3 and clang 18.1. The java, android and dotnet images are not built on that base and ship
no C toolchain. Java ships hash-locked Maven 3.9.9 and Gradle 8.9. The cpp image sets `ENV CC=clang CXX=clang++`. The rust-wasm image adds
hash-locked Rust 1.90.0 with the `wasm32-unknown-unknown` and `wasm32-wasip1` standard libraries.
The go image adds `golang-1.23` with `GOTOOLCHAIN=local`. The facts we need are therefore facts
about each **image digest**. Local pins or host tools cannot supply them.

## Goals

- Prove a native target from the builder image that will actually execute, identified by its
  immutable digest.
- Do not trust recipe text, file names or labels for that proof.
- Close the common deterministic cases: CMake, phpize/autotools/make, cargo (including wasm32),
  and go with and without cgo. Every catalogued build system must build (§4a).
- Uncatalogued tools fail by name. Nothing passes silently.
- Keep the post-build retained-binary check (`verify_native_product`, ELF/PE/archive machine) as
  an independent backstop. A profile proves only the *intended* target. The binary check proves
  the *realised* one.
- Unit tests stay Docker-free, independent and under 10 s.

Non-goals for this pass: uncatalogued cross-compilation toolchains, Windows native builds (the
existing `msbuild-mapping/1` path is unchanged), and Android NDK until it is catalogued (§4a).

## Design

### 1. Compiler profile collection (per image digest)

A new module, `appsec_review.container_runtime.compiler_profiles`, collects
`appsec-review/static-compiler-profile/2` records.

- **Granularity.** One record per *(image digest, driver)*. Drivers are `clang`, `gcc`, `rustc`,
  `cargo` and `go` (`msbuild` is later work). A family image yields every driver it ships; for
  example, rust-wasm yields `rustc` and `cargo`, plus `clang`/`gcc` when present.
- **Input.** The resolved image ID (`sha256:…`), never a tag. Before any run, collection fails
  closed unless `docker image inspect <tag> --format {{.Id}}` returns exactly that ID (the same
  `BuildContainerExecutor.resolve()` check every build uses). Identity is always checked.
  Signature verification follows the configured `[signing]` image policy and is not enabled by
  the collector: under the default `disabled` policy the verifier is `DisabledImageVerifier` and
  no signature is checked; under `required`, an image without a verifying signature is refused.
  Each record states which applied in `provenance.image_signature` (`not-enforced` or
  `verified`). A verifier that does not declare whether it enforces is refused before any Docker
  call.
- **One probe, native-protocol compatible.** The native engine broker accepts only an isolated
  `docker run` plus `image inspect {{.Id}}`, `rm` and `kill` (`native_commands.py`); it has no
  `docker create`, `docker cp` or JSON inspect. The collector therefore runs one container per
  image:
  - `--network none --read-only --user <runtime uid:gid> --cap-drop ALL --security-opt
    no-new-privileges`, bounded CPU, memory and pids, a `noexec` tmpfs `/tmp`, a timeout, and one
    rw bind mount `/out` onto a fresh, run-owned, empty directory. No target or run mounts.
  - `/bin/sh -c <fixed script>`; the script is a module constant whose hash is recorded.
  - Whatever way the run ends (success, timeout, a raised runner error or an interrupt), the
    container is force-removed and its absence confirmed before the output directory is deleted.
    If removal cannot be confirmed, the output is preserved and collection fails, naming the
    container and the preserved path.
- **Executable identity.**
  - The probe resolves each driver (`command -v`), records every symlink hop with its exact
    target (`wrapper_closure`) and the real path (`readlink -f`), and copies the real file to
    `/out/<driver>`.
  - The host computes `sha256` from the copied bytes. Exactly the expected files must be present;
    each must be a bounded regular file with a structurally valid ELF header (read with the
    bounded reader in `job_language_build/elf.py`): version 1, a SysV or Linux OS ABI, type
    `EXEC` or `DYN`, a supported machine (x86, x86_64, arm64) matching its class, and an entry
    point inside a loadable segment. A `#!` script wrapper, a bare magic number or any other
    content is a profile error, never a hashed "compiler". All copied executables of one image
    must share one class and machine, and for `rustc`/`cargo` that machine must be the host
    target's ISA. The record keeps the result as `executable_format`.
  - The real path must equal the normalized end of the recorded symlink chain. Normalization is
    lexical, so an image whose tool path crosses a symlinked directory fails closed.
  - Trust limit: the copy is made by the image's own `/bin/sh` and `cp`, so the hash binds what
    the identified image exports, not an independent read of its layers.
- **Behaviour probe.**
  - Fixed argv only: `clang|gcc -dumpmachine`, `clang|gcc --version`, `rustc -vV`, the installed
    `rustlib/<target>/lib` directories under `rustc --print sysroot`, `cargo -V`, `go version`,
    `go env -json GOOS GOARCH CGO_ENABLED CC CXX GOROOT`.
  - The transcript (`appsec-review/compiler-probe/1`) is delimited: `@@` section headers and
    `|`-prefixed payload lines, ending with `@@end`. It is untrusted data: parsed strictly with
    bounded regexes and size, line and encoding limits. Each probe's capture is bounded inside the
    container (at most 65 536 bytes and 256 lines); a larger output is reported as an explicit
    overflow section, never silently truncated, and the parser rejects it. Go's JSON environment
    may not repeat a key. Truncation, overflow, an unknown or repeated
    section, a discontinuous symlink chain, a failed probe or a malformed fact fails the whole
    image closed.
- **Image environment.**
  - Read inside the probe with `printenv` (the process environment is the image `Config.Env`;
    the probe sets only `HOME`, `LANG` and `LC_ALL`), keeping `CC`, `CXX`, `AR`, `LD`, `PATH`,
    `CARGO_BUILD_TARGET`, `RUSTFLAGS`, `GOFLAGS`, `GOOS`, `GOARCH` and `CGO_ENABLED`.
  - The proof can then tell an image-default compiler from a recipe override.
- **Record fields.** These extend `/1`; the existing fields keep their meaning.
  - `schema`, `image_digest`, `driver`, `executable` (absolute real path) and `invocation_names`
    (the probed names that resolve to the same real path, for example `cc`, `clang`).
  - `compiler_sha256`, `wrapper_closure` (each symlink hop as `{path, target}`; empty when the
    driver is not a link), `driver_semantics` (`clang-target/1`, `gcc-default/1`, `rustc-host/1`,
    `cargo-rustc/1`, `go-env/1`), `version` (first version line), `default_target` (raw triple;
    `GOOS/GOARCH` for Go) and `target_axes` (via `_compiler_axes`).
  - `supported_targets`: for rustc and cargo, the installed `rustlib` targets (must include the
    host); otherwise the default target only.
  - `driver_facts` (rustc `release`; Go `cgo_enabled`, `cc`, `cxx`, `goroot`; empty for the
    others), `executable_format` (`class`, `machine`, `type`), `image_env` (the
    selected keys only), `probe` (transcript schema, script and transcript digests, per-probe exit
    codes and output digests), and `provenance` (`{"origin": "image-probe/1",
    "collector_version": …, "image_identity": "docker-image-id/1", "image_signature":
    "not-enforced" | "verified"}`).
  - `validate_profile` checks a closed shape: no unknown or missing keys, typed and bounded
    values, every probe exit code `0` with a non-empty output digest, the probe script digest
    equal to the shipped script, `target_axes` recomputed from `default_target`, and per-driver
    facts and semantics. Any malformed record or set raises `CompilerProfileError`. Set
    admission (`profile_set`, `merge_profile_sets`) also requires every record of one image to
    share one `image_signature` outcome and one executable class and machine. This constrains
    only the executables, never the targets a C or Go compiler builds for.
  - A profile set is `appsec-review/compiler-profile-set/1`: `{"images": {digest: {driver:
    record}}}`. An image with no drivers is present with an empty map (probed, nothing found).
    Merging two sets that both contain an image is an error.
  - `/1` stays the shape `_native_enforcement` consumes. Rollout step 1 does not change
    enforcement; binding `/2` to admission is step 2 onward.
- **Caching and custody.**
  - Records are immutable run artifacts at `artifacts/build/compiler-profiles/<image>/<driver>.json`.
    They are content-addressed and referenced like the other refinement inputs.
  - They may also be reused from a host cache keyed by image digest plus collector version.
  - A cache hit is re-verified against `docker image inspect`, which needs no execution.
- **Derived images** (recipe `system_packages` or `image_repairs`):
  - Step 1 refuses to collect a derived `BuildProfile` before any Docker call. The executor's
    signature check covers only the base (`derived_from_image_id`), and a `/2` record has no
    field for that base or its recipe. So the collector does not label a derived digest
    `verified` when only its base was checked. A later step adds the base and recipe fields,
    then:
  - re-probe the derived digest;
  - record `image_recipe_digest`, which `guard_action` and `_approved_compiler_metadata`
    already require.

### 2. Profile sets in refinement

- Replace the single `profiles` mapping with an `appsec-review/compiler-profile-set/1` keyed by
  image digest: `{image_digest: {driver: profile}}`.
- Old `/1` single-mapping inputs keep their existing meaning, so tests and replay remain valid.
- `_native_enforcement` receives the set entry for the action's bound image. A unit with no
  bound image proves nothing.
- `guard_action` checks `profiles[image]` instead of `profiles["image_digest"] == image`.
- `profile_identity` stays the digest of exactly the entries used.

### 3. Where the profiles are bound

Enforcement runs at planning time, inside `bind_actions` in `plan.load_recipes`, which is before
the image step. The configured family images are pinned by `image_id` in
`[jobs.job_project_build.settings.profiles.*]`, so the digest is known at that point.

1. `plan.load_recipes` collects or loads the profile set for each configured family image
   referenced by an action's `image_profile`, then passes it to `bind_actions(profiles=…)`.
2. The image step resolves the actual image.
   - If the resolved ID differs from the configured one, or the image is derived:
     - collect the derived profile;
     - re-bind that action with the new set;
     - `guard_action(..., image_identity=…)` proves the binding. This is the same shape replay
       already uses.
3. The accepted plan's `evidence_bundle["profiles"]` stays `None`. Planning-time topology does
   not depend on images. Only refinement, the execution binding, carries compiler facts.

### 4. Enforcement per driver

Each driver gets a `driver_semantics` value and a proof kind. Every rule below *adds* unresolved
reasons. None removes the existing source, include or condition closure checks.

The last column lists inputs a driver must *resolve*, not cases it may abandon:
- If the override is a known, parseable configuration (for example a toolchain file naming a
  target, `.cargo/config.toml` `[build] target`, or a `--host` triple), honour it. The declared
  target becomes the intended target, the same as an explicit `--target`, provided the bound
  image (customised if necessary, see §4a) ships that target.
- It remains unresolved only when the override cannot be evaluated statically, for example a
  computed toolchain path. Then the realised-command capture of §4a must prove it, or the build
  fails.

| Driver | Proof kind | Proven when | Must resolve |
|---|---|---|---|
| direct `clang`/`gcc` | `compiler_explicit_target` / `compiler_pinned_default` (existing) | as today, with `argv[0]` in the profile's `invocation_names` | as today |
| CMake (`cmake-env-compiler/1`) | `build_driver_pinned_default` | recipe configures with the profile's compiler, either from image `CC`/`CXX` or an injected `-DCMAKE_<LANG>_COMPILER=<exe>`; no recipe or source toolchain override | `CMAKE_TOOLCHAIN_FILE`, `CMAKE_SYSTEM_NAME`/`PROCESSOR`, `CMAKE_<LANG>_COMPILER[_TARGET]` in source facts, `-m32`/`--target` in `CMAKE_*_FLAGS` or `add_compile_options`, `ExternalProject`/`FetchContent` (`cmake_toolchain_override_unknown`, `cmake_subbuild_target_unknown`) |
| phpize / autotools / make (`autotools-env-compiler/1`) | `build_driver_pinned_default` | `php-config --cc` or image `CC` resolves to the profile executable; recipe environment sets no `CC`/`CFLAGS`/`LDFLAGS`/`--host` | `--host=`/`--build=` arguments, Makefile `CC :=` rules (existing `make_rule_scope_unresolved`), `PHP_ADD_LIBRARY_WITH_PATH` to prebuilt objects |
| cargo (`rustc-host/1`) | `rustc_explicit_target` / `rustc_pinned_default` | exactly one target: `--target <triple>` that is in `supported_targets`, or else the rustc host triple; no `RUSTFLAGS`/`CARGO_BUILD_TARGET` override in the recipe or image | `.cargo/config.toml` `[build] target`/`rustflags`/`linker` (needs a source fact), `build.rs` that invokes `cc` (proven through the C profile with `CC` pinned, plus capture under §4a) |
| go (`go-env/1`) | `go_explicit_target` (existing) / `go_pinned_default` | `GOOS`/`GOARCH` from the recipe, else `go env` defaults from the profile; `CGO_ENABLED=1` is proved through the C profile of the `go env CC` executable | `-toolexec`, `-compiler`, `GOFLAGS` overrides (existing); cgo `#cgo LDFLAGS` with prebuilt objects |
| wasm32 (cargo or clang) | as above | target triple `wasm32-*` maps to `isa=wasm32`, and the selection policy's existing exemption list (the default includes wasm32) governs admission | WASI or unknown OS axis left `null`; required OS axes produce `unenforced_axis:os` as today |

### 4a. Known means buildable

**Rule.** If the build system or tool is in our catalog, the pipeline must be able to build with
it. If it is not, the build fails with a named reason.

**The catalog.** `build_discovery.py` already defines the known build systems: marker files
mapped to family and build system, plus the allowed executables for each family. This design
makes the catalog the single authority for three facts about each known build system:

1. **Detection.** The marker files plus content facts. For example, `build.gradle` applying
   `cpp-application`, `cpp-library`, `c` or `externalNativeBuild` is a *native* Gradle unit, not
   a Java one. Today every `build.gradle` maps to `java`.
2. **Driver semantics.** Either one of the specific rows in §4, or the generic captured
   semantics below.
3. **Image provisioning.** The image to use for the unit's family. If that image lacks the tool,
   use a pinned, hash-locked *customisation* that adds it. Example: C++ with Gradle uses the cpp
   image (pinned clang/gcc) plus the same hash-locked JDK 21 and Gradle 8.9 archives the java
   image installs.
   - Customisations reuse the existing derived-image path (`system_packages`/`image_repairs`,
     `image_recipe_digest`). The derived digest is re-probed (§1) and re-bound (§3).
   - Customisations are catalog-defined and hash-locked. The model or target text cannot
     invent them.

**Generic captured semantics** (`captured-env-compiler/1`). This applies to known drivers with
no static rule: Gradle native, Meson/Ninja, SCons, and make or autotools variants beyond §4.

- **Admission.** The recipe pins `CC`/`CXX` (and `AR`, `LD`) to the profile executables. No
  recipe or image environment contradicts them. Process-tree build capture is enabled for the
  action. The operation is admitted with proof kind `captured_compiler`, a proof that is
  *conditional on capture*: `guard_action` refuses it if capture is disabled.
- **Post-build verification, mandatory.** Every `exec` in the captured process tree that resolves
  to a compiler or linker must meet three conditions, or the iteration *fails*:
  - it is a profile `invocation_names` entry, or its bytes hash to a profiled executable;
  - it adds no `--target`, `-m32`, `-arch` or `-march` outside the profile;
  - its realised target matches the intended axes.

  This is not a gap.

**Unknown tools.**
- A recipe whose executable or build system is not in the catalog (for example "requires
  `build xxxx`") fails with `unknown_build_tool:<name>`.
- A model-proposed customisation that is not in the catalog fails with
  `uncatalogued_image_customisation`.
- Adding support means adding a catalog entry with detection, semantics, a hash-locked
  provisioning recipe, a known-topology fixture and the tests in §Testing.

#### Deterministic recipe changes

These make proofs explicit rather than default-dependent.

- **CMake.** Add `-DCMAKE_C_COMPILER=<profile exe>`, `-DCMAKE_CXX_COMPILER=<profile exe>` and
  `-DCMAKE_<LANG>_COMPILER_TARGET=<default_target>`. The existing
  `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` makes realised compiler commands available.
- **phpize.** Run `./configure CC=<exe>`.

#### Realised-command check (post-build)

- For drivers that export or capture compile commands (CMake `compile_commands.json`, and build
  capture where enabled), the iteration's product admission verifies the following:
  - every realised compiler `argv[0]` resolves to a profile `invocation_names` entry;
  - no realised command adds `--target`, `-m32` or `-arch`.
- A violation fails that iteration rather than producing a gap.
- This is a second layer, separate from the binary check.

### 5. PHP native extensions

- A `php` unit whose deterministic recipe is phpize is classified as `package` today. (The interim
  `native_components` attachment and its `native_component_requested_stage_unresolved` reason were
  retired on 2026-11-08 by T-056.2 / plan §2.1 decision 1: a phpize extension's C sources are
  evidence of a typed build point, T-056.6, or orphans.)
- `_selected_operations` will instead classify the phpize lifecycle
  (`phpize` → `./configure` → `make`, from the accepted `config.m4`) as
  `native_compile` + `native_link`, governed by `autotools-env-compiler/1`.
- Composer packages that build extensions through scripts stay `unknown`.

## Security considerations

- Probe containers execute only image-owned binaries with fixed argv, with no target content, no
  network, no host mounts and no privileges.
- Executable hashes are computed on the host from copied bytes.
- Probe output is bounded in the container, reported as overflow rather than truncated, and
  strictly parsed.
- The profile is bound to the image **digest**. A tag substitution, derived image or repaired
  image forces a re-probe.
- Image identity (`docker image inspect {{.Id}}`) is always checked before any probe. When launch
  enforcement is `required`, image signing verification also precedes any probe, so the probe
  never becomes a way to execute an unverified image. Under the default `disabled` policy no
  signature is checked, and records say so (`provenance.image_signature: "not-enforced"`).
- A profile proves only defaults and intended targets. Retained-binary machine verification
  (`verify_native_product`) remains mandatory and is never relaxed by a proof.

## Testing

We test as finely as is useful. Each of the four points below is a single concern.

### Unit (Docker-free, independent, < 10 s each)

1. **What inference says.**
   - Recorded planning-model responses go through recipe validation. Assert the accepted recipe
     and its gaps.
   - Recorded bad responses must be rejected by name. Examples: an uncatalogued tool
     (`unknown_build_tool:<name>`), an injected `--target`, a `CC` override, a network fetch.
   - No live model is called.
2. **Default images admit our default recipes.**
   - For each family's deterministic recipe, recorded `/2` profiles for the configured image
     digests go through `refine_build_topology` and `guard_action`.
   - Every native operation must be `proven`, with zero `unenforced_*` gaps.
   - The currently failing language job tests (group I: PHP, Go, Rust, wasm, cpp) use the same
     recorded profiles and must end `SUCCEEDED`.
3. **A known tool can be installed.**
   - For a catalogued customisation (first: Gradle on the cpp image), the derived-image recipe
     is the catalog's hash-locked one.
   - The derived digest forces re-probe and re-bind.
   - An uncatalogued customisation is refused.
4. **Profiles and capture.**
   - The probe parser handles recorded transcripts, including malformed, oversized and
     mismatched-hash output.
   - The collector is tested with only the `docker` subprocess faked.
   - Replaying a recorded captured process tree rejects a substituted compiler or an injected
     target.

Recorded profiles and transcripts come from the integration hello-world runs below. They are not
invented. A digest mismatch with the configured image fails with a "re-capture" message.

### Integration (real local images; explicit and user-run only)

Small hello-world builds, one per catalogued family and build-system combination. Each runs
end to end (catalog ? recorded recipe ? refine with real probed profiles ? build ? product
verification). Each asserts `SUCCEEDED` and the expected artifact type and machine.

| Family | Build systems |
|---|---|
| C/C++ | CMake, Ninja, Make, autotools, Gradle (customised image) |
| PHP | phpize extension, Composer |
| Rust | Cargo; Cargo ? `wasm32-unknown-unknown` |
| Go | `go build`; cgo |
| Java/Android | Maven, Gradle |
| .NET, Node, Python | the family's default |

One further integration case installs a known tool into a default image, re-probes it and
builds with it. This extends `tests/integration/test_family_project_builds.py`, and these runs
supply the recordings that the unit tests replay.

Live planning-model quality stays in the live tier. It is reported, not gated.

## Rollout

1. Profile record schema `/2`, parser and collector, with unit tests. **Implemented**; synthetic
   fixtures only, not yet validated against the live builder images.
2. Profile sets in refinement and `guard_action`, with `/1` compatibility.
3. Profile binding in `plan.load_recipes` and the image-step re-bind.
4. Per-driver enforcement: CMake and autotools/phpize first (cpp, PHP), then cargo/wasm, then
   go/cgo.
5. Deterministic recipe explicit-compiler fields and the realised-command check.
6. Unit tests for inference recipes, default-image admission and known-tool installation;
   migrate the language job tests (the group I fix).
7. Catalog provisioning and generic captured semantics; Gradle on the cpp image is the first
   customisation.
8. Integration hello-world matrix and the known-tool installation case (user-run). These runs
   capture the recordings that the unit tests replay.

Each step is a separately reviewable commit. Steps 1–3 change no admission outcome on their own;
proofs only change in step 4.

## Decided

- **Collection point.**
  - At run time, profiles are probed from the real image digest and cached per digest. This is
    required anyway for derived images.
  - Unit tests replay recordings captured from the integration hello-world runs.
- **Explicit versus default target.** Our deterministic recipes always name the profiled
  compiler and target explicitly. A pinned default remains a valid proof for recipes inferred by
  the model.
- **Known means buildable.**
  - A catalogued build system or tool is supported by catalog-defined, hash-locked image
    customisation.
  - Known, parseable overrides (toolchain file, cargo target, `--host`) are honoured.
  - A `build.rs` or cgo step that invokes a C compiler is proven through the pinned C profile and
    process capture.
  - Only uncatalogued tools fail, with `unknown_build_tool:<name>`.
