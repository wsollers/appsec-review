---
title: "Build discovery: contract and test program"
kind: "history"
subsystem: "target acquisition and build"
status: "historical"
jobs: ["job_project_build", "job_target_catalog"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Build discovery: contract and test program

> Current subsystem view: [Target acquisition and build](../architecture/target-acquisition-and-build.md). This record preserves its original decisions and validation limits; unfinished proposals are not treated as delivered.

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
2. **Assignment.** Every path under the folder has exactly one role:
   - `evidence_of:<unit>[#<build point>]` — a marker, a descriptor, or a source a build point names;
   - `context:<unit>` — lockfiles, props, settings, presets the unit reads but does not build;
   - `source_only:<language>` — interpreted code with no build step (PHP, Python, JavaScript
     without a package build, shell): reviewable as source, nothing to build;
   - `orphaned:<reason>` — a **compiled-language source that no build script, build descriptor or
     compiler line references**. This is a finding, not a fallback: it means dead code, build
     drift, an abandoned port, or a build we failed to understand, and every one of those is
     knowledge the review must report. Orphaned sources are never built and never silently
     attached to a nearby unit (decision 2026-11-08, replacing the `direct-native` fallback);
   - `inert` — not code and not build input (documentation, assets, data), still inventoried;
   - `excluded:<policy>` — a configured exclusion (`.git`, vendored binaries by policy);
   - `unclaimed` — a discovery defect, never an accepted output.
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

### 2.1 Decisions after the first fixture tranche (2026-11-08)

The three case-authoring passes (A; B+D; C+E+F) each met the same open questions. These are the
answers; the cases and the code follow them. Each is a contract statement, not a description of
today's behaviour (the status table says what is implemented).

1. **A root that drives members is the unit; the members are its build points.** A `.sln` is the
   unit and its projects are build points; a Gradle settings root is the unit and the included
   projects are build points; a Cargo/Go/npm/pnpm workspace root is the unit and its members are
   build points; a Maven parent is the unit and its modules are build points; a CMake root that
   `add_subdirectory`s, a Makefile that `$(MAKE) -C`s, a `meson.build` that `subdir`s and an
   automake `SUBDIRS` all *drive* the directories they name. Discovery records every such relation
   on the driving unit as `drives: [{path, via, evidence[, condition]}]` and the member's descriptor
   is `evidence_of:<root>#<member>`. A directory that nothing drives is a unit of its own. The
   member-as-unit-with-`workspace`-fact behaviour of job pass 05 is interim and is replaced under
   T-056.4/T-056.5 (the plan's component layer, T-035, then reads build points and `drives`,
   never membership facts). The one directory the rule does not fold is a driven directory the
   operator declares as a build of its own (T-038).
2. **Parallel systems at one root both exist; one holds capture authority.** When two build systems
   share a root (CMake beside a hand Makefile, autotools beside CMake, meson beside Make), both are
   units. The unit whose build the native lane runs to obtain a compilation database is the
   `capture_authority` (order: cmake, meson, autotools, make, msbuild); each unit names the other in
   `parallel_with`. A source two parallel units both name is `evidence_of` the authority's build
   point; the other unit's descriptors stay evidence of that unit. A Makefile at the same root as
   the system it drives whose rules only invoke that system (`cmake --build`, `meson compile`,
   `$(MAKE) -C build`) is not a unit: it is `context:<authority>`. A Makefile that `$(MAKE) -C`s
   into *other* directories is a unit with `drives` (seed case 002). Today's rule that drops the
   `make` group whenever cmake/autotools/meson shares the root is replaced by reading the Makefile.
3. **Solution family follows the listed projects.** A `.sln` listing only `.vcxproj` is
   `msbuild`/native; one listing `.csproj`/`.vbproj`/`.fsproj` is `dotnet`; a mixed solution is
   `msbuild` with a `languages` fact. A `.vcxproj` no solution lists is a unit of its own. A
   `.sln`/`.vcxproj` beside `CMakeCache.txt` is generated output: `inert`, never a unit.
4. **Generated and installed trees are never units.** `node_modules/`, `vendor/` (Cargo, Go, PHP),
   `Pods/`, `buildSrc/`, `testdata/`, `obj/`, `bin/`, a CMake build directory (`CMakeCache.txt`)
   are not roots. When the configured exclusion policy covers them the role is `excluded:<policy>`
   (cases name the policy in `exclusions`); otherwise installed dependencies are `context:<unit>` of
   the unit that installs them and build outputs are `inert`. `buildSrc/` is `context` of the
   Gradle root (a build of the build), never a member.
5. **Context, not evidence; prose is inert.** `README*`, `LICENSE*`, `CHANGELOG*`, `NOTICE` are
   `inert` everywhere. Lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `Cargo.lock`,
   `go.sum`, `composer.lock`, `poetry.lock`, `packages-lock.json`), `tsconfig.json`, presets,
   wrapper properties, `gradlew`/`mvnw`, `global.json`, `nuget.config`, `meson_options.txt`,
   `.vcxproj.user`, `Directory.Build.*` are `context:<unit>`. `.vcxproj.filters` is `inert`
   (MSBuild never reads it). A descriptor that defines build points — a module `build.gradle(.kts)`,
   a `.asmdef`, `pnpm-workspace.yaml`, `binding.gyp`, `.xcworkspacedata` at the project root — is
   `evidence_of` its unit (with the point when it defines one).
6. **A path in a comment or a string that is not a build argument is a mention, not a reference.**
   Only arguments of build constructs (`add_executable`, prerequisites, `ClCompile Include`,
   `x_SOURCES`, `$(wildcard)`, `file(GLOB)`) bind sources. Comments are stripped before reading.
7. **One role per path, `#<point>` is the first point that names it.** A source two build points of
   one unit both name is `evidence_of:<unit>#<point>` for the first point in descriptor order; the
   unit's `build_points[].sources` lists it under both. The same holds for a shared header.
8. **Every compiled language discovery knows is orphanable.** `.c/.cc/.cpp/.cxx/.cu/.m/.mm`,
   `.java/.kt/.kts`, `.rs`, `.go`, `.cs`, `.swift`, `.wat` outside any claiming build point are
   `orphaned:<reason>` (never `unclaimed`); interpreted languages (`.php .py .rb .pl .sh .ps1 .js
   .ts .lua .sql`) are `source_only:<language>` and `source_only_scopes` covers all of them, not
   only `.py`/`.php`. A `setup.cfg` alone, a `Makefile.am` without `configure.ac`, a lone
   `Cargo.lock`, a lone `build.ninja` and a `requirements.txt` alone are not roots.
9. **Fact vocabulary** (free-form names from the first tranche are rewritten to these): `drives`
   (above; replaces `subdirectories`, `external_projects`, `native_plugins`, `hosted_by`,
   `driven_by`), `includes` (modules a descriptor includes), `unresolved` (constructs discovery
   could not read, with evidence and reason; replaces `unresolved_projects`), `source_resolution`
   (`complete` | `containment`), `materialization_root` (the common ancestor a unit's build needs
   checked out, when it references paths outside its root; T-056.5), `parallel_with` (labels of
   the other units at the root), `capture_authority` (`primary` on the unit whose build the native
   lane runs, `secondary` on the others; order cmake, meson, autotools, make, msbuild),
   `generated_by` (`cmake` on a checked-in solution CMake generated), `conditions` (unit-level map
   of the conditions its points are under),
   `languages` (per unit; `build_points[].language` per point), `configurations` and
   `configuration_mapping` (MSBuild), `product_flavors` (Android), `package_manager` (node),
   `path_dependencies` and `replacements` (Cargo/Go path deps and replace directives, as
   `[{name, path, evidence}]`), `profile_gaps` (a language a point compiles that the unit's
   `required_image_profile` has no toolchain for). `workspace` membership facts are retired with
   decision 1.
10. **The harness states negatives directly.** `facts_absent` (a fact must be absent or empty),
    `build_points_exact` (the complete `(name, kind)` list, so "no build point of its own" is
    assertable), `build_points[]` keyed by `(name, kind)` with optional `condition`, `language`,
    `sources`, and the sub-checks of an undiscovered unit emitted as failures so they can be
    pending now instead of surfacing when the unit lands. `exclusions` applies a named policy to a
    case. Implicit build points with no `file:line` (Unity `Assembly-CSharp`, Cargo's default bin,
    a Go package with no module line) carry the descriptor's path and line 1 as evidence.
11. **Vocabulary fixed by the decision-1 landing (2026-11-08).** `drives[].via` names the literal
    construct: `add_subdirectory`, `FetchContent`, `ExternalProject_Add`, `recursive_make`
    (`$(MAKE) -C`, directly or through a `for d in …; do … -C $$d` shell loop), `subdir` (meson),
    `SUBDIRS` / `AC_CONFIG_SUBDIRS` (automake), `solution_project`, `settings_include` (Gradle),
    `externalNativeBuild`, `workspace_member` (Cargo, npm, pnpm), `go_work_use`, `pom_module`,
    `plugin_importer` (Unity, T-056.5), and `invokes:<tool>` when a recipe, custom command or script
    line runs another build system's tool on a directory holding that tool's descriptor (`cmake -S d`,
    `meson setup b d`, `wasm-pack build d`, `cargo … --manifest-path d/Cargo.toml`, `npm --prefix d`,
    `gradle -p d`; a `cd` earlier on the line moves the resolution directory). A drive whose `via` is a
    folding construct and whose path is the root of a unit the driver's system reads *folds* that unit:
    its markers become the driver's `descriptors`, its points the driver's points, and the catalog
    names it under `folded_roots` with the evidence. `invokes:<tool>` and `externalNativeBuild` never
    fold: the driven unit stands and carries `driven_by: {unit, via, evidence}` — the inverse relation,
    kept on the standing unit (item 9 retires `hosted_by`; `driven_by` is the one name for the inverse).
    One `drives` entry per `(path, via)`, at the first evidence. Evidence for a `recursive_make` is the
    rule line; for an `invokes:*` it is the invoking recipe line. Member points: a `.sln` lists
    `project` points (`path`, `descriptor`, `configurations`, sources from the project items; a
    project no solution lists is a unit whose own file is its marker and whose point is `project` at
    `<file>:1`); Gradle includes are `project` points named without the leading colon (`app`,
    `lib:core`), with `descriptor` the project's build file and sources by containment (plus native
    sources and `language` when the project applies a C++ plugin); Maven `<module>`s are `module`
    points; Cargo packages are `package` points (evidence the `name =` line) beside their `lib`/`bin`/
    `build-script-build`/`test` points, a workspace member's included from its own manifest; Go
    modules are `module` points (`<go.mod>:<module line>`) and directories with Go files are
    `package`/`main_package` points named by the directory relative to the unit root (the root's own
    directory by its module path), evidence the first file of the directory at line 1; npm packages
    are a `package` point (the `"name"` line) plus `script` points and `workspace_member` points
    (`path`, `descriptor`, sources by containment); a member point's descriptor is
    `evidence_of:<root>#<member>`, a folded CMake/Make/meson/automake descriptor (no member point)
    is `evidence_of:<root>`. A path two points name belongs to the point of the unit whose root
    contains it (innermost), then to the first point in descriptor order (item 7). The orphan reason
    is `no_build_point` everywhere; the `nearest_unit.why_not` text carries the distinction between
    "no unit of that family" and "no point of that unit names it". Make rule kinds are `rule`,
    `delegating` (recipe is a sub-make), `phony_or_aggregate` (no recipe, no sources); languages are
    spelled `c`, `c++`, `objective-c`, `objective-c++`, `cuda`, `java`, `kotlin`, `rust`, `go`, `c#`,
    `swift`, `wat`. `native_components` and the `workspace` facts are gone from `build-systems/4`.

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
- Automake (T-091, case 121): a variable is the union of every `=` and `+=` assignment across all `if`/`else` branches, and `$(VAR)` of a variable assigned in the same `Makefile.am` is expanded, for `SUBDIRS` and for the program, library and source lists. A directory reached that way is a member of the one build with the condition recorded on its drive; a reference with no in-file assignment is an `unresolved` record (`unassigned_variable`).

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
3. **T-056.3 Orphaned sources are reported, never built.** The `direct-native` fallback is
   removed: a compiled-language source no build point names is `orphaned:<reason>` in the
   assignment, listed in `build-systems.json` as `orphaned_sources` (path, language, reason, the
   nearest unit considered and why it did not claim it), counted in the catalog's coverage, and
   surfaced to the review as a finding class of its own. A root the operator wants compiled anyway
   is a declared build (T-038), not a guess. Existing fixtures that depended on `direct-native`
   compile attempts move to declared builds.
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

Seed cases 001–004 pass with build points (`CMakePresets.json` is context, an include-only
`CMakeLists.txt` and an un-included `.cmake` module are inert, the delegating Makefile records what
it drives, `-I` headers bind, sources bind to build points); 004 keeps one pending check
(`materialization_root`, T-056.5). The first fixture tranche (cases 010–120) is in with its pending
entries pointing at §2.1; the rules land sub-item by sub-item and each landing removes the pending
entries it satisfies (a pending check that passes fails the suite). Decision 1 landed on 2026-11-08
(313 pending entries remain, down from 542); decision 2 the same day (294), decision 3 (187), decision 4 (164);
items 5–8 on 2026-11-12 (103).

| Sub-item | State | Notes |
| --- | --- | --- |
| T-056.1 harness | done (2026-11-08) | `test/discovery/`, `discovery-case/1` schema, `tests/test_discovery_cases.py`, `acceptance.discovery assign/check/new`, `jobs/discovery_assignment.py`; seed cases 001–004 (A1 positive, A1 negative, orphans, D1) |
| T-056.2 build points | done (2026-11-08) | `jobs/build_points.py`: CMake targets (`set`, `file(GLOB)`, `target_sources`, `target_include_directories` → headers, `add_subdirectory`/`FetchContent`/`ExternalProject_Add` → `drives`, custom target/command invocations → `drives`, `include`, `if/else` conditions, generator expressions → `unresolved`), Make rules (variables, substitution references, `$(wildcard)`, object → source, `-I` → headers, `$(MAKE) -C` and shell-loop sub-makes → `drives`, recipe invocations of other build tools → `invokes:<tool>` drives, `ifeq` conditions, `delegating`/`phony_or_aggregate` kinds), `.sln` → `project` points with the listed project's items, Cargo package/lib/bins/build script/tests (workspace members included), Go modules and packages (go.work members included), npm package/scripts/workspace members (npm `workspaces` and `pnpm-workspace.yaml`), Gradle `project` points from `settings` includes (+ `externalNativeBuild`), Maven `module` points, meson, automake (primaries, `SUBDIRS`, hand rules), Xcode, package descriptors. `source_resolution` complete/containment; descriptor-only cmake/make/meson/autotools units demoted; orphan decision after points; `native_components` retired. `tests/test_build_points.py`. |
| decision 1 (members fold) | done (2026-11-08) | `build_discovery._attach_build_points` folds driven same-system units transitively (`FOLDING_VIAS`/`FOLDABLE_SYSTEMS`), records `descriptors`, `drives`, `driven_by`, returns `folded_roots`; `workspace` facts, the positional Gradle absorption and the make-drop-at-cmake-root rule's companions removed; `discovery_assignment` prefers the containing unit's point and maps member descriptors to `#<member>`; catalog emits `build-systems/4` with `folded_roots`/`demoted_markers`; the plan reader pins `/4`. Case vocabulary normalised (§2.1 item 11); 184 pending entries closed (542 → 313). Topology fixture: members `may_be_absent`, three reason codes retired. |
| T-056.3 orphaned sources | done in discovery and catalog (2026-11-08); review surfacing open | `discover_build_inventory` returns `orphaned_sources`; `direct-native`/`javac`/`rustc`/`go` source fallbacks removed; `build-systems/3` lists orphans and the catalog counts them (`BUILD_SYSTEMS_DISCOVERED`); still to do: the finding class downstream (prioritization/report) |
| decision 2 (parallel systems) | done (2026-11-08) | `build_discovery._resolve_parallel_systems`: the make-drop-at-cmake/meson/autotools-root rule is replaced by reading the Makefile — generator output (`# CMAKE generated file`, automake/configure headers) is inert, a wrapper whose rules compile nothing and invoke the co-located system's tool is `context:<authority>` (`demoted_markers[].role`), a Makefile with compile rules is a parallel unit. Units sharing a root carry `parallel_with: [labels]` and `capture_authority: primary|secondary` (`CAPTURE_AUTHORITY_ORDER`: cmake, meson, autotools, make, msbuild); a root whose descriptor was folded into a parent has that parent as the parallel. The authority's point wins shared sources in the assignment. A checked-in CMake-generated solution states `generated_by: cmake`. Without descriptor text both units stand with the authority recorded. 19 pending entries closed (313 → 294); the monorepo's tinylib Makefile is now a secondary parallel unit (`capture-authority-secondary`, plan-side T-035/T-036). |
| decision 3 (solution family) | done (2026-11-08) | `build_discovery.solution_marker`/`solution_projects`: a `.sln` is typed by the projects it lists (all `.vcxproj`/`.vcproj` → native/msbuild; all `.csproj`/`.vbproj`/`.fsproj` → dotnet; mixed → msbuild with `languages`), read before grouping; a listed project is never a marker (its file is the `project` point's `descriptor`, read wherever it sits); a project nothing lists is a unit named by `<ProjectName>` (that line is the evidence) or its stem at line 1, with `language`; a listed project missing from the target is `unresolved` with `kind: missing_project` and does not make the resolution containment; a directory holding `CMakeCache.txt` without a `CMakeLists.txt` is a build tree (`generated_trees`): nothing under it is a marker or a descriptor, every path is inert. `native_build_capability_gap` reads the solution's projects through the points. 107 pending entries closed (294 → 187). |
| decision 4 (generated/installed trees) | done (2026-11-08) | `build_discovery.installed_trees`: `node_modules/` (parent `package.json` or `.package-lock.json`), a Cargo/Go/Composer `vendor/` (parent manifest, `modules.txt`, `.cargo-checksum.json`, `autoload.php`), CocoaPods `Pods/` (parent `Podfile`, `Manifest.lock`, `Pods.xcodeproj`) are `installed`; Gradle `buildSrc/` is `build_logic`; Go `testdata/` is `fixture`. Nothing under one is a marker, a descriptor or an orphan; `installed`/`build_logic` paths are `context:<nearest standing unit>`, `fixture` paths `inert`; the catalog lists them under `installed_trees` (`build-systems/4`, with `generated_trees` from decision 3). A `vendor/` under a Make or CMake root is source the rules name, not an installed tree. 23 pending entries closed (187 → 164). |
| items 5–8 (context names, mentions, one role, orphanable and interpreted languages, roots that are not roots) | done (2026-11-12) | `discovery_assignment`: prose and `.filters` inert everywhere; context files are owned by the unit of the system that reads them (`_CONTEXT_AFFINITY`: props/targets/user → MSBuild, presets → CMake, `meson_options.txt` → meson, `.am/.ac/.m4` → autotools, wrappers and `AndroidManifest.xml` → Gradle/Maven, lockfiles → their manager, `Podfile`/`.pbxproj`/`.plist` → Xcode, `.meta`/`packages-lock.json` → Unity) among the units containing the path, innermost first, and are inert where no such unit exists; Unity scenes/shaders/assets are evidence by containment. `build_discovery.marker_lookalike`: `setup.cfg` without `setup.py`/`pyproject.toml` and `Makefile.am` without a `configure.ac` above it are not roots (`demoted_markers` names them); a Makefile whose rules name no compiled source and drive nothing is demoted; a `package.json` with no scripts and no entry point is demoted (`node_build_points` → `declares_no_build`). Descriptors that define points are evidence: `pnpm-workspace.yaml`, a root `*.xcworkspace/contents.xcworkspacedata`, Unity embedded package manifests, `.asmdef` (`unity_build_points`: `assembly` points with their C# sources; the package lock is no longer a Unity marker). Headers: a Make header prerequisite is named by its rule; meson `include_directories` (variable or inline) bind headers; a bare `${CMAKE_CURRENT_SOURCE_DIR}` is the directory; a header nothing names belongs to the first point compiling a source in its directory (`_bind_unnamed_headers`). Cargo: a `[[bin]]` at `src/main.rs` replaces the default bin. `source_only_scopes` covers every interpreted language (`INTERPRETED_LANGUAGE_SUFFIXES`). An Android application descriptor sets `descriptor_facts` at discovery, so the profile is `android`. Cases 064/065 corrected: a module `build.gradle` is `evidence_of:<root>#<project>` (item 11). 59 pending entries closed (164 → 103). |
| T-056.4 matrix A | cases written (010–036); decisions 1–4 and items 5–8 landed | 27 cases; remaining pending entries name Unity `player_target` points, Xcode target sources, SwiftPM (`Package.swift` is not yet a unit), node script/package sources, Python/Composer package sources, package-manager authority (C3) |
| T-056.5 matrix B, D | cases written (060–080); nesting and workspace folds landed, cross-tree open | `materialization_root`, `path_dependencies`/`replacements`, Unity `plugin_importer` drives |
| T-056.6 matrix C, E, F | cases written (100–120); member folds landed, rest open | parallel authority (decision 2), conditions, languages, `profile_gaps`, typed packaging points (`c_extension`, `gyp_target`, cc build scripts) |
| T-056.7 matrix G | open | |

Discovery changes made in job pass 05 (settings-only Gradle roots, the Xcode unit, workspace facts,
no manufactured root for a referenced sibling source) were interim: the Xcode unit stands (A12); the
settings-only root now folds its projects and the workspace facts are replaced by `drives` (A8, A5/A6/A7,
decision 1); the sibling source is the rule's evidence (D1); the `native_components` attachment is
retired (2026-11-08).
