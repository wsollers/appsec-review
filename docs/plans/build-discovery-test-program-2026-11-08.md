# Build discovery: contract and test program

Tracking document for making build discovery the most tested piece of the review. Registry item:
T-056. Owner of the decisions below: the job pass for `job_target_catalog`
(`docs/tasks/2026-11-08-job-pass-05-target-catalog.md`) and, for ownership, T-035.

## 1. The problem stated plainly

Discovery's atom today is a **marker file** (`CMakeLists.txt`, `Makefile`, `package.json`, …): one
build unit per marker directory. Its fallback atom is a **source file**: a `.c` with no marker above
it manufactures a `direct-native` unit at its conventional `src/` parent, and a source a sibling
descriptor names is attached to that descriptor's unit as a `native_components` entry. Neither atom
is what a build system builds.

What a build system builds is a **build point**: a named thing with a recipe and products —

| Build system | Build points | Named where |
| --- | --- | --- |
| CMake | targets (`add_executable`, `add_library`, custom targets), projects | `CMakeLists.txt` and included `.cmake` |
| Make / autotools / meson / ninja | rules / targets | `Makefile`, `*.mk`, `meson.build`, `build.ninja` |
| MSBuild | solution → projects → configurations | `.sln`, `.vcxproj`, `.csproj`, `.props` |
| Cargo | packages, `[[bin]]`, `[lib]`, workspace members | `Cargo.toml` |
| Go | modules, `main` packages | `go.mod`, `go.work`, package dirs |
| npm / pnpm / yarn | packages, scripts, workspace members | `package.json`, lockfiles, `pnpm-workspace.yaml` |
| Gradle / Maven | projects (modules), tasks; `externalNativeBuild` | `settings.gradle`, `build.gradle(.kts)`, `pom.xml` |
| .NET | solution → projects | `.sln`, `*.csproj`, `Directory.Build.props` |
| Composer / pip / poetry | packages | `composer.json`, `pyproject.toml`, `setup.py` |
| Unity | player targets per platform, asmdefs | `ProjectSettings/`, `*.asmdef` |
| Xcode | projects → targets → schemes | `*.xcodeproj/project.pbxproj`, `*.xcworkspace` |

A **unit** is the smallest thing we can dispatch to a lane: a build point, or a root that drives a
set of build points (a solution, a workspace, a Gradle root, a CMake project). A **component** (T-035)
is a buildable product with one driver and one materialization root. Sources are **evidence**:
every source path belongs to exactly one build point, or to a source-only scope, or is excluded by
policy. A loose source is never a unit.

The multi-language, multi-build-system reality is the hard part, and it is where the current code
has pairwise rules and no systematic tests: build systems **nest** (a CMake project vendoring a
Makefile library that vendors a gtest CMake tree; a Gradle module whose `externalNativeBuild` runs
CMake; a Unity project with native plugin sources; an npm package that drives a Cargo/wasm crate), run
**in parallel** (a `.sln` beside a `CMakeLists.txt` for the same sources; an autotools and a meson
build in one root), **reach across trees** (`.sln` projects in sibling directories; `../common/src`
in a Makefile; a Cargo path dependency outside the workspace), and are **conditional**
(`option()`-gated subdirectories, `if(WIN32)`, platform-specific `.mk` includes).

## 2. The discovery contract (what a test asserts)

Discovery is correct for a folder when its output is a **total, explainable assignment** of the
folder's content:

1. **Units.** The set of units, each with: root, build system, family, the build points it drives
   (names, kinds), the markers and descriptors that are its evidence, its `required_image_profile`,
   and the facts the plan needs (workspace/solution membership, platform declarations, conditions).
2. **Assignment.** Every path under the folder has exactly one role: `evidence_of(<unit>)` (a
   marker, descriptor, or source a build point names), `source_only(<scope>)` (interpreted or
   unbuilt code no build point claims, with the reason), `context` (lockfiles, props, settings the
   unit reads but does not build), `excluded(<policy>)`, or `unclaimed` — and `unclaimed` is a
   discovery defect, never an accepted output.
3. **Non-units.** Everything that looks like a root but is not one is named with the reason: a
   `project.pbxproj` outside a bundle, a `Makefile` that only delegates (`$(MAKE) -C`), a
   `CMakeLists.txt` reached only by a parent's `add_subdirectory` (that is ownership, T-035, but
   discovery records the evidence), a `package.json` that is a workspace member, a `.vcxproj`
   listed by a `.sln` elsewhere.
4. **Evidence.** For each unit and each build point, the file and line (or key) that establishes
   it. A unit with no evidence is a defect.
5. **Determinism.** The same folder yields byte-identical `build-systems.json` across runs and
   hosts; ordering is by path, never by directory listing order.

A **positive test** for an item asserts 1, 4 and the relevant rows of 2 for a folder in which the
item exists. A **negative test** asserts 3 and the complementary rows of 2 for a folder in which the
item's trigger is present but the item must *not* be concluded (the same marker name in the wrong
place, a conditional that is off, a descriptor that is context, a source that is claimed elsewhere).
Both are required for every rule discovery has. The total-assignment rule makes negatives cheap: a
fixture's expectation lists the roles of all its paths, so anything discovery invents fails the
test without a test having been written for that invention.

## 3. Fixture organisation

```
test/discovery/
  README.md                      what a case is, how to add one, how to run
  cases/
    <NNN>-<slug>/
      tree/                      the folder under test (committed; small; no binaries)
      expect.json                the contract for this tree (schema below)
      notes.md                   optional: why this case exists, the real-world target it mirrors
  schema/discovery-case.schema.json
  runner: tests/test_discovery_cases.py (one parametrized test per case per section)
```

`expect.json` (schema `appsec-review/discovery-case/1`):

```json
{
  "case": "031-cmake-vendored-make-gtest",
  "mirrors": "Barracuda fsh-server/lib/libs/protobuf-2.5.0",
  "units": [
    {"root": "server", "build_system": "cmake", "family": "native", "profile": "native",
     "build_points": [{"name": "server_main", "kind": "executable", "evidence": "server/CMakeLists.txt:7"}],
     "facts": {"subdirectories": ["third_party/tinylib"]}}
  ],
  "not_units": [
    {"root": "server/third_party/tinylib/test", "marker": "Makefile",
     "reason": "sources are ../src/*.c; the rule compiles another directory's files"}
  ],
  "assignment": {
    "server/CMakeLists.txt": "evidence_of:server",
    "server/src/main.c": "evidence_of:server#server_main",
    "server/third_party/tinylib/test/check.c": "evidence_of:server/third_party/tinylib#check",
    "website/public/index.php": "source_only:php",
    "web/package-lock.json": "context:web",
    ".git/": "excluded:vcs"
  },
  "pending": {"units[0].build_points": "T-056.2 build points for CMake"}
}
```

`pending` names expectations the code does not meet yet, by registry sub-item, and the runner
treats them as strict xfails (a pending expectation that starts passing fails the suite until the
entry is removed). Everything else is a hard assertion. The existing `test/topology/monorepo` becomes
case `001-monorepo-composite` and keeps its plan-level contract; the discovery cases are
discovery-only and run in milliseconds each.

## 4. The case matrix

Each cell is at least one positive and one negative case. Cases are small (tens of files) and
single-purpose; the composite monorepo is the only large one.

**A. One build system, one root (positives establish the baseline; negatives are the look-alikes)**
- A1 CMake with targets (executable, static lib, shared lib, interface, custom target); negative: `CMakeLists.txt` with only `include()` of a non-existent file; `cmake/` helper modules.
- A2 Make with named rules; negative: delegating-only Makefile; `Makefile.in`/`Makefile.am` without configure; a `Makefile` in `docs/`.
- A3 autotools (`configure.ac` + `Makefile.am`), meson, ninja (`build.ninja` only — generated, not a root).
- A4 MSBuild: `.sln` + `.vcxproj` (C++), `.sln` + `.csproj` (C#), `.vcxproj` without a `.sln`, `.props`/`.targets` files; negative: `.vcxproj.filters`, `.user` files, a `.sln` listing a project that does not exist.
- A5 Cargo (package; `[[bin]]`s; `build.rs`); negative: `Cargo.lock` alone; `Cargo.toml` of a vendored crate under `vendor/`.
- A6 Go (`go.mod` with several `main` packages; `go.work`); negative: `vendor/modules.txt`; a `go.mod` under `testdata/`.
- A7 npm/pnpm/yarn (package; workspace; scripts); negative: `node_modules/*/package.json`; a `package.json` with no scripts and no `main` (a manifest for tooling only).
- A8 Gradle (root with build file; settings-only root; Kotlin DSL; `buildSrc/`), Maven (parent POM with modules); negative: `gradle/wrapper/`, a `build.gradle` under `buildSrc` (it *is* a build, but of the build).
- A9 .NET (`.sln` + `.csproj`; `Directory.Build.props`; `global.json`); negative: `obj/`, `bin/` leftovers with project files.
- A10 Composer, pip/poetry/pyproject; negative: `requirements.txt` alone; `setup.cfg` alone.
- A11 Unity (`ProjectSettings/ProjectVersion.txt`, `Assets/`, `Packages/manifest.json`, `*.asmdef`); negative: a folder named `Assets/` in a non-Unity repo; a Unity package (`package.json` with `unity` key) inside `Packages/`.
- A12 Xcode (`.xcodeproj`, `.xcworkspace`, `Package.swift`); negative: `project.pbxproj` outside a bundle; a `.xcodeproj` inside `Pods/`.

**B. Nesting (one build system drives another)**
- B1 CMake vendoring a Makefile library (and its gtest CMake tree) — the Barracuda shape.
- B2 CMake `ExternalProject_Add` / `FetchContent` pointing at an in-tree directory.
- B3 Gradle `externalNativeBuild { cmake { path ... } }` driving a CMake tree.
- B4 Unity project with `Assets/Plugins/<native>/CMakeLists.txt` (native plugin sources).
- B5 npm package whose `build` script runs `cargo build`/`wasm-pack` on a sibling crate.
- B6 `.sln` whose `.vcxproj` files live in sibling directories (`../engine/engine.vcxproj`).
- B7 autotools top-level with `SUBDIRS` and a vendored CMake dependency under `third_party/`.
- Negatives for each: the same nested tree with the driving reference removed (then the inner tree *is* an independent root) — this is the test that ownership evidence is literal, not positional.

**C. Parallel build systems for the same sources**
- C1 `CMakeLists.txt` and `.sln`/`.vcxproj` side by side (CMake-generated solution checked in; hand-maintained MSVC project).
- C2 `Makefile` and `meson.build` in one root; `configure.ac` and `CMakeLists.txt` in one root.
- C3 `package.json` with both `npm` and `pnpm` lockfiles.
- Expectation: one unit per build system with the same root, `parallel_with` facts, and a clear statement of which is the *primary* authority for capture (policy, recorded).

**D. Cross-tree references**
- D1 Make rule naming `../../common/src/*.c` (sibling sources) — the fixture's B shape.
- D2 Cargo `path = "../shared"` outside the workspace; Go `replace ../x`.
- D3 `.sln` with projects two directories up.
- D4 CMake `add_subdirectory(../sibling sibling-build)`.
- Expectation: the minimum materialization root is recorded per unit (what `_copy_source` must copy, T-039); negatives: a comment that mentions `../x.c` is not a reference.

**E. Conditional and platform-specific build points**
- E1 CMake `option()` default OFF gating `add_subdirectory`; `if(WIN32)`/`if(APPLE)` targets.
- E2 Make `ifeq ($(OS),Windows_NT)` branches; `include $(PLATFORM).mk`.
- E3 `.vcxproj` configurations (Debug|x64, Release|ARM64); `.sln` configuration mapping.
- E4 Gradle product flavors; Cargo `[target.'cfg(windows)']`; Go build tags.
- Expectation: build points carry `condition` facts; the plan (T-036) decides dispositions; discovery never drops a conditional build point and never claims it unconditionally.

**F. Multi-language roots**
- F1 CMake with C, C++, CUDA, and Swift/ObjC targets in one project.
- F2 Gradle with Java + Kotlin + native.
- F3 A Python package with a C extension (`setup.py` `ext_modules`), a Node package with a native addon (`binding.gyp`), a Rust crate with `cc` build script.
- Expectation: one unit, build points typed by language; `required_image_profile` is the union's demand or a named gap.

**G. Scale and hostile shapes**
- G1 2,000 marker files (generated), to pin discovery time and memory bounds.
- G2 Symlink loops, `..` escapes in descriptors, a descriptor over 64 KiB, non-UTF-8 descriptors, CRLF descriptors.
- G3 A monorepo with every shape above (the existing `test/topology/monorepo`, grown).

## 5. Implementation plan (sub-items of T-056)

1. **T-056.1 Harness.** `test/discovery/` layout, `discovery-case/1` schema, `tests/test_discovery_cases.py`
   (parametrized by case id from a sorted listing; hard assertions + strict pending), a
   `python -m appsec_review.acceptance.discovery` CLI to run discovery over any folder and print its
   assignment (so a real target's folder can be inspected the same way a case is). Migrate the
   handful of inline-dict tests in `tests/test_build_discovery.py` that encode a *shape* into cases;
   keep the function-level tests that encode a *rule*.
2. **T-056.2 Build points.** `discover_build_units` emits `build_points` per unit: CMake targets
   (bounded regex over `add_executable|add_library|add_custom_target`, recorded with line), Make
   rule names, MSBuild projects from `.sln`, Cargo packages/bins, Gradle modules, Go main packages,
   npm scripts, Unity player targets, Xcode targets (from `PBXNativeTarget` names). Sources that a
   build point names become `evidence_of:<unit>#<point>`; `native_components` is retired in favour
   of that assignment.
3. **T-056.3 Loose sources are not units.** The `direct-native` fallback becomes a
   `source_only` scope with reason `no_build_point`, unless a configuration policy opts a root in
   (the existing `confirmed-user-intent` selection row). Existing fixtures that depended on
   `direct-native` compile attempts move to explicit declared builds (T-038) or to the opt-in.
4. **T-056.4 Matrix A** (one build system, positives and look-alike negatives).
5. **T-056.5 Matrix B and D** (nesting, cross-tree; evidence-literal ownership facts and
   materialization roots).
6. **T-056.6 Matrix C, E, F** (parallel systems with recorded primary authority; conditions;
   multi-language build points).
7. **T-056.7 Matrix G** (bounds, hostile shapes, the composite).

Each sub-item lands as its own commit with its cases; a sub-item is done when its cases have no
`pending` entries. The composite monorepo's remaining xfails are re-expressed as `pending` entries
pointing at these sub-items or at T-035/T-036/T-037/T-039.

## 6. What this changes for the jobs after discovery

- The plan's topology compiler (T-035) consumes build points and facts, not markers; ownership
  becomes "which unit's build point names this" plus the driver relations, with literal evidence.
- `job_project_build` dispatches units (soon components), never sources; the `direct-native`
  selection row stays only as the opt-in.
- Capture reconciliation (`build-topology-refinement`) maps compiled TUs back to build points, so
  coverage is per build point, which is what a reviewer can act on ("`server_main` compiled;
  `tinylib_test` did not").

## 7. Status

| Sub-item | State | Notes |
| --- | --- | --- |
| T-056.1 harness | open | |
| T-056.2 build points | open | the fix for "a source is not a component" |
| T-056.3 loose sources | open | policy decision recorded in §5.3 |
| T-056.4 matrix A | open | 12 build systems × (positive, negative) |
| T-056.5 matrix B, D | open | |
| T-056.6 matrix C, E, F | open | |
| T-056.7 matrix G | open | |

Discovery changes already made in job pass 05 (settings-only Gradle roots, the Xcode unit, workspace
facts, no manufactured root for a referenced sibling source) stand as interim behaviour and become
cases A8, A12, A5/A6/A7 and D1 under this program; the `native_components` attachment introduced
there is explicitly interim and is retired by T-056.2.
