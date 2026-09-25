# Build unit classification: what gets built, and how

Status: **DESIGN, not built** (2026-09-25; decisions below). Extends [build resolution](build-resolution.md) /
[ADR-0012](../decisions/ADR-0012-build-resolution.md), which assumes a single native project.

## Why

A target is rarely one native project. It is a mix of compiled code, transpiled code, code that runs
in an interpreter, container definitions and cloud infrastructure. Only some of it has to be built to
produce evidence, and building executes target code, so we build **only the pieces that need a
build**, and treat everything else statically.

## Unit and class

A **unit** is one build root: the directory of a defining manifest (`configure.ac`, `CMakeLists.txt`,
`package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `pom.xml`, `build.gradle*`, `*.csproj`,
`composer.json`, `Gemfile`, a `Dockerfile`, a Terraform root, a Helm chart, ...). A monorepo has many.
Each unit gets exactly one **class**:

| Class | Examples | Build? | What we do with it |
|---|---|---|---|
| `compiled-native` | C, C++, Rust, Go, Swift, Obj-C, Fortran; native extensions inside interpreted packages (`binding.gyp`, Python `ext_modules`/Cython `.pyx`/`maturin`, PHP `config.m4`, Ruby `extconf.rb`) | **yes** | compile database, native SAST, binaries for fuzzing and binary analysis |
| `compiled-managed` | Java, Kotlin, Scala (JVM); C#, F# (.NET) | **yes** | bytecode/assemblies for SAST that needs a build, dependency resolution, binary analysis |
| `transpiled` | TypeScript, TSX/JSX via Babel, CoffeeScript, Elm, Kotlin/JS; a bundler step (webpack, vite, esbuild) over JS | **yes (transpile)** | type-check, emitted JS and source maps, bundle contents |
| `interpreted` | Python, PHP, Ruby, plain JavaScript/Node, Perl, Lua, shell | no | source goes straight to SAST; manifests and lockfiles to SCA |
| `container` | `Dockerfile`, `Containerfile`, compose `build:` | no (v1) | Dockerfile static analysis; base image pinned and scanned |
| `infrastructure` | Terraform/OpenTofu, CloudFormation, Bicep/ARM, Helm, Kubernetes manifests, Ansible; infra-as-program (CDK, Pulumi) | never applied | static IaC analysis only; CDK/Pulumi are not synthesized |
| `unclassified` | anything the table cannot place | no | coverage gap, named with its path |

A unit can hold more than one class (a Python package with a C extension). It is then split: the
extension is a `compiled-native` unit rooted at the package, and the Python code stays `interpreted`.

## Flow

```mermaid
flowchart TD
  A[Accepted intake + partition map + D02/D03/D04 records] --> I[02-build-index: enumerate units by build root, nothing executed]
  I --> K[Classify each unit: deterministic table over manifests, extensions, markers]
  K --> Q{Placed by the table?}
  Q -- ambiguous or mixed --> L[02-build-plan asks the model to classify, cited; recorded as inferred]
  Q -- yes --> S
  L --> S{Class}
  S -- compiled-native / compiled-managed / transpiled --> BS[BUILD SET]
  S -- interpreted --> INT[No build: source to SAST, manifests and lockfiles to SCA]
  S -- container --> CT[v1: Dockerfile static analysis, base image by digest, image scan; images not built]
  S -- infrastructure --> IAC[Static IaC analysis only; no init, synth, plan or apply]
  S -- unclassified --> GAP[Coverage gap]
  BS --> E{Ecosystem supported? apt now; npm, Maven/Gradle, Go, cargo for Rust, NuGet need restore support; POC fetches from public registries}
  E -- no --> BU[BLOCKED UNSUPPORTED_ECOSYSTEM for that unit only]
  E -- yes --> P[02-build-plan per unit: LLM plan from the index]
  P --> R[02-build-resolution per unit: image, trial in B13 with network none, bounded retries]
  R -- OK --> LK[Build lock per unit, image catalogued]
  R -- attempts exhausted --> BF[FAILED BUILD_UNRESOLVED for that unit only]
  LK --> N[Native and managed evidence: compile DB, SAST needing a build, fuzzing, binaries]
  BU --> REP[Report states every unbuilt unit as a gap]
  BF --> REP
  GAP --> REP
```

A unit that cannot be built blocks only the jobs that need **that** unit's build. Every other unit,
and every lane that needs no build, continues.

## Rust units

A Rust unit is a Cargo workspace or package root (`Cargo.toml`, with `Cargo.lock` when present); a
workspace is one unit, and its member crates are listed inside it. Class `compiled-native`.

- **Dependencies:** crates come from crates.io (POC; `package-restore` grants for its hosts) during provisioning only, checked against `Cargo.lock` checksums; the
  trial runs `cargo build --locked --offline` against that restored set, never fetching. A unit with no
  `Cargo.lock` gets one generated during provisioning, recorded as a gap (the resolved versions are ours,
  not the repository's).
- **Build scripts and proc macros execute code at build time** (`build.rs`, `proc-macro = true`
  crates, including those of dependencies). That is the same exposure as `./configure` and is covered
  by the same `target-execution` grant and B13 boundary; the index lists every `build.rs` so the plan
  and the report can name them.
- **Native dependencies:** `-sys` crates and the `cc`/`cmake`/`pkg-config` build helpers need C
  toolchains and libraries; the plan adds them as apt packages, as for any native unit.
- **Toolchain:** `rust-toolchain.toml` / `rust-toolchain` pins the compiler; the image carries that
  toolchain, or the plan records the mismatch. Nightly-only features are recorded, not silently
  switched to stable.
- **Success and evidence:** every `cargo build` exits 0 with the declared features; the build lock
  records features, target triple and profile. Evidence is `cargo metadata` (the crate graph for SCA),
  the built binaries (fuzzing with `cargo fuzz` targets when declared, binary analysis), and
  `unsafe`/FFI locations for native review. Rust has no compile database; `rust-project.json` or
  `cargo metadata` stands in where a tool needs the build graph.

## Where classification happens

In `02-build-index`, deterministically, from a data table (class by manifest, marker and extension),
so it is cheap, testable and reproducible. The model is asked only for units the table cannot place or
that mix classes, and its answer is recorded as `inferred` with citations. D02/D03 keep proposing
per-project commands; the build index cross-checks them and records any disagreement, as ADR-0012
already does for build system and project root.

Intake's `families` table today maps `.js` and `.jsx` to `typescript`; classification needs them apart
(`interpreted` vs `transpiled`). Either intake gets a separate `javascript` family or the index
classifies from manifests (`tsconfig.json`, a `typescript`/`@babel/*` dependency, a bundler config)
rather than extensions alone.

## Decisions

Decided by William, 2026-09-25:

- **Transpiled units are in the build set** and go through the same resolution loop as compiled
  units (transpile and type-check in the trial).
- **Ecosystems after apt: all of them** -- npm, Maven/Gradle, Go modules, cargo (Rust), NuGet. Each is a
  `package-restore` grant for its registry host(s) plus restore support in the loop; until a unit's ecosystem has one, that unit is
  `BLOCKED(UNSUPPORTED_ECOSYSTEM)`. Order not yet set; npm first is proposed, since it unblocks the
  transpile decision above and Node native addons.
- **Containers: static in v1.** Dockerfile static analysis plus a scan of the pinned base image; the
  repository's own images are not built (their `RUN` steps are target code run with network).
- **Cloud infrastructure: static only.** IaC scanners over the files; no `terraform init`/`validate`,
  no `cdk synth` or `pulumi preview`, never `plan`/`apply`.

- **Dependency source for the POC: the public registries**, with TLS certificate verification and
  lockfile hash verification (registry-published checksums where the repository pins none, recorded as
  weaker). A local caching proxy is deferred: it is an external service outside this project.
  Tracked in `appsec-review-process/TODO.md` Phase 5f.

Proposed, not yet confirmed:

1. **Owner of classification:** the deterministic table in `02-build-index`, with the model only for
   ambiguous or mixed units.
2. **Unit granularity:** one unit per build root, not one per partition.
3. **Ecosystem order:** npm, then Maven/Gradle, then cargo (Rust) and Go modules, then NuGet.

## Open

- Mixed-class splitting rules need test fixtures: the polyglot fixture addendum
  (`appsec-review-process/TODO.md`) is the natural place.
- Windows/MSVC stays out of scope (`BLOCKED(UNSUPPORTED_PLATFORM)`), as in ADR-0012.
