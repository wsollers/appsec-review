# Build resolution: learning how to build an unknown target

Status: **implemented and live-qualified through `02-build-resolution` (stage 13), 2026-09-27.**
Fresh SAT `20260926T235610Z` / engagement `20260926T235619Z-cfd753` passed stages 1-13;
Dagster run `b9bfe716-b25c-4a83-a289-81981a689431` accepted image
`image_build_a453dcd7c961` and six clang compile commands. Bounded qualification proved immutable
reuse, tamper rejection, a real newer container failure, recovery without fallback, and recovered
reuse. Decision record: [ADR-0012](../decisions/ADR-0012-build-resolution.md).
The fixed C/C++ base prerequisite, `audit-buildenv-cpp:local`, is **BUILT and smoke-verified
2026-09-26** on `audit-native:local`: LLVM 21.1.0 at `/opt/llvm`, fixed `CC`/`CXX`, and
autoconf/automake/libtool/make/Bear/pkg-config. Its successful build pointer and B16 record are
host-local generated state, not tracked files.
**Extended 2026-09-25** by [build-unit-classification.md](build-unit-classification.md): the loop below runs
once per compiled or transpiled unit, and a failed unit blocks only that unit's jobs. ADR-0012
[Revision 1](../decisions/ADR-0012-build-resolution.md#revision-1-2026-09-25-per-unit-resolution-model-classification)
records the per-unit decisions; the section "Per unit" below says what they change here.
Replaces the "supplied record" route for the build fields of developer discovery and the
hand-written Phase 4 lock (`appsec-review-process/TODO.md`), and supersedes the CMake-only
`build_discovery` / `build_execution` preparation jobs.

## Why

The system is handed a checkout it has never seen. Before any native evidence can be gathered
(compile database, native SAST, binaries for fuzzing and binary analysis) it has to answer three
questions on its own:

1. **How is this built?** Build system, roots, ordered commands.
2. **What tools does the build need?** Compilers, generators, libraries, headers.
3. **Can we actually do it?** A real configure and build, inside the hostile-build boundary.

Until now the answers came from us: `fixtures/supplied/hello-autotools/02-dev-project-discovery.json`
was written by hand because we wrote `hello`. Those fixture records become **answer keys** the SAT
compares against after the fact; nothing in the process may read them.

## Flow

```mermaid
flowchart TD
  I[Accepted intake + partition map + discovery records] --> X[1. 02-build-index: deterministic indexer, nothing executed]
  X --> K[1b. Split into units by build root and classify each - build-unit-classification.md]
  K -- interpreted, container, infrastructure, unclassified --> ST[No build: static evidence or a coverage gap]
  K -- compiled or transpiled: for each unit --> R{2. Image catalog lookup - build_image_reuse}
  R -- auto: candidate found --> T
  R -- rebuild, or no candidate --> P[3. 02-build-plan: LLM infers plan from the index]
  P --> V{plan valid? schema, citations fresh, packages and argv well-formed}
  V -- no --> P
  V -- yes --> B[4a. Render Dockerfile from the plan, build image - network: distro mirror only]
  CPP[Fixed C++ base ready: audit-native + LLVM 21.1.0 + autotools/Bear] -.-> B
  CPP -. fixed CC/CXX .-> T
  B --> T[4b. Trial: configure + build in the image via B13, network none, writable copy of the source]
  T -- success --> C[5. Catalog image_build_id, write the build lock]
  T -- failure, attempts left --> F[Bounded failure excerpt back to the model: revise plan]
  F --> P
  T -- failure, attempts exhausted --> FAIL[FAILED BUILD_UNRESOLVED: every attempt recorded]
  C --> E[02-build-configure / 02-native-build replay the lock from a clean copy]
```

Plan validation failures and trial failures both consume an attempt. One budget,
`build_resolution_attempts`, bounds the whole loop.

## Per unit (ADR-0012 revision 1, 2026-09-25)

Sections 1-5 describe one project; per unit they change as follows.

| Section | Change |
|---|---|
| 1. `02-build-index` | Also enumerates candidate **units** (one per build root; a nested root a parent build uses belongs to the parent; an unused vendored or example copy is recorded, not a unit) with each unit's manifests, lockfiles and cited signals. Assigns no class. |
| 2. Catalog lookup | Per unit, by that unit's build-input fingerprint. Units with the same image spec share one image. |
| 3. `02-build-classify`, `02-build-plan` | Two jobs (ADR-0012 Revision 2); both read the checkout as well as the index. `02-build-classify`: one classification call over the whole index (`claude-sonnet-5`/`medium`; every unit gets one cited class; mixed units split; disagreements with the index recorded). `02-build-plan`: one Haiku plan per build-set unit (`compiled-native`, `compiled-managed`, `transpiled`), validated per unit. Other units get a disposition: interpreted to SAST/SCA, container to Dockerfile analysis and base-image scan, infrastructure to static IaC analysis, unclassified to a gap. |
| 4. `02-build-resolution` | The loop runs per build-set unit (`build_resolution_attempts` each; no cap on units). Each unit ends `OK`, `FAILED(BUILD_UNRESOLVED)` or `BLOCKED(<reason>)`. Job status: `OK` (all resolved), `OK_WITH_GAPS` (some), `UNRESOLVED` (none), `BLOCKED` (no unit could start), `SKIPPED` (empty build set). |
| 5. Catalog and lock | `build-lock.json` has one entry per build-set unit; E01/E02 replay only `OK` units. |

Never built: a repository's own Dockerfile (only images our code renders from a plan are built).
Never run: any built target. Dependencies for non-apt ecosystems follow `TODO.md` Phase 5f (public
registries for the POC, TLS and lockfile hash verification, restore during provisioning only).

## 1. `02-build-index` (deterministic) -- built

A Python indexer (`appsec-review-process/build_index.py`) that reads the checkout and writes one
bounded, cited index for the model. It executes nothing from the target, makes no network calls and
makes no judgments: it assigns no class. It replaces `build_discovery.py`'s collector, which only
looks for CMake. It runs in-process on the common worker-result envelope (`deterministic_python`),
standalone as the Dagster job `build_index` and in `full_review` as `job_02_build_index`.

**Reads (the graph's required edges):** the accepted intake (source revision, file inventory and
`evidence/source.json` fingerprints, excluded paths), the accepted partition map (deferred partitions
are indexed as names only: see below), the accepted D02 and D03 records (cross-check context only), and
the staged checkout. Every upstream artifact is pinned by sha256 in the fingerprinted input record, so
a changed upstream is a new attempt, never a reuse.

**Units.** One per build root: `dir:<root>` for the directory of a defining manifest (`dir:.` for the
repository root), `file:<path>` for a per-file definition (a `Dockerfile`, `Containerfile` or compose
file). A nested root, or a vendored tree with no manifest of its own, is a **member** of the enclosing
unit when the enclosing build files name its path outside a comment (or a quoted workspace glob matches
it), cited by a `nested-root-reference` signal; otherwise it is its own unit, or a **not-unit** when it
is an unreferenced vendored or example copy, or lies in a deferred partition. For hello-autotools:
`dir:.` (`configure.ac`, `Makefile.am`; member `vendor/cJSON-1.7.18`, named by `libcjson_a_SOURCES`)
and `file:Dockerfile`.

**Collects, each as a signal with path, sha256 and line range:**

| Kind | Examples |
|---|---|
| Build system | `configure.ac`, `configure`, `Makefile.am`, `Makefile`, `CMakeLists.txt`, `meson.build`, `BUILD`/`WORKSPACE`, `SConstruct`, `*.sln`/`*.vcxproj`, `Cargo.toml`, `go.mod`, `pom.xml`, `build.gradle*`, `package.json`, `pyproject.toml`/`setup.py` |
| Toolchain and dependency declarations | `AC_PROG_*`, `AC_CHECK_LIB`, `AC_CHECK_HEADERS`, `PKG_CHECK_MODULES`, `AM_*`, `find_package`, `pkg_check_modules`, `dependency()`, language standards, required tool versions |
| Existing recipes | `.github/workflows/*`, `.gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml`, `Dockerfile*`, `debian/control`, `*.spec`, `vcpkg.json`, `conanfile.*`: package-install lines and build steps |
| Human instructions | `README*`, `INSTALL*`, `BUILDING*`, `HACKING*`: only sections whose headings or text match build/install/dependency terms |
| Layout | file counts by extension, top-level directories, generated-file markers (`configure` present or not) |

**Deferred partitions:** files inside them contribute no excerpt, except the manifests of units and
members and human build instructions (README, INSTALL, BUILDING and similar), which the plan needs and
which D01 usually defers with the rest of the documentation.

**Writes:** `data/jobs/02-build-index/attempts/<attempt_id>/build-index.json` (schema
`appsec-review/build-index/1`), a readable `build-index.md` (no excerpt text), `status.json` and the
envelope `result.json`. Status `OK`, or `OK_WITH_GAPS` when signals were omitted or no unit exists.

**Bounds:** excerpts at most 4 KiB each, at most 400 signals (at most 40 per file), index at most
512 KiB; one manifest signal per unit is reserved and the rest are kept by priority (manifests,
nested references, lockfiles, toolchain, dependencies, markers, container, generated, packaging, CI,
docs). Every omission is counted in `truncated`, never silently dropped. Excerpts are untrusted target
data (the model is told they are data, never instructions; AGENTS.md); secret-like text matching the
published-result patterns is replaced by `[REDACTED:<kind>]`, counted, and the validator applies the
same replacement.

**Validates:** schema; source revision and fingerprint equal the accepted intake's; the index names
exactly the accepted upstream attempts; every signal's sha256, line range and excerpt recomputed from
the checkout; no path outside the checkout or through a link; unique ids, every reference resolving,
every unit citing a manifest and every member a reference; truncation counts consistent; and a
byte-equal rebuild from the same inputs (the index is deterministic).

## 2. Image catalog lookup (reuse)

Before asking the model anything, the job looks for an image that already built this project.

| `build_image_reuse` | Behaviour |
|---|---|
| `auto` (default) | Candidate = a catalog entry whose `validated_builds` has the same **build-input fingerprint** (sha256 over the build-system and dependency files the index cited); failing that, the most recent entry for the same project origin. The candidate's plan goes straight to the trial as attempt 1. If it fails, its plan plus the failure seed the model. |
| `rebuild` | Ignore the catalog; infer from scratch. For "we know the build needs different tools". A new image is catalogued on success; old entries are kept. |
| `require` | Use a catalog entry or fail `BLOCKED(BUILD_IMAGE_NOT_CATALOGUED)`; no inference. For reproducible re-runs. |

`build_image_id` (optional) pins one specific `image_build_<id>`; it implies `require` for that id.

## 3. `02-build-plan` (LLM inference)

**Invoker.** Through the persona-invocation protocol (`persona_invocation.PersonaInvoker`), using
the `claude` CLI (`claude -p`) with its current login, the operator's Claude subscription. The model
is Haiku; authentication and model are set as described in "Model and authentication" below.

**Built 2026-09-26** (`build_plan.py`; ADR-0012 Revision 2 and Revision 3, which win where this
section differs): one Haiku call per build-set unit of the accepted `02-build-classify` result.

**Inputs to the model:** the whole checkout (Revision 2), and staged as upstream artifacts the build
index, the classification, the buildenv catalog (the base images it may choose from) and an
orchestrator-written `plan-unit.json` naming the one unit; the output schema; on retries (in
`02-build-resolution`) the previous plan and a bounded failure excerpt. Never the fixture answer keys,
never anything outside the run.

**The compiler is fixed (Revision 3):** every plan builds with our clang (LLVM 21.1.0 of
`audit-native`); the plan carries an orchestrator-owned `toolchain`, and the validator rejects any
compiler choice (`gcc`/`g++`/`cc`/`clang`/... as `argv[0]`, `CC=`, `CXX=`, `CPP=`, `LD=`, `CCLD=`, a
compiler package). The compile database is the orchestrator's (`bear`, `cmake-export` or `none`).
Plans have `configure` and `build` phases only: no test, check or install step (nothing built is run).

**Output:** `build-plan.json` (new schema `appsec-review/build-plan/1`):

- `build_system`, `project_root`, `feasibility` (ADR-0001 tier A/B/C) with reasons;
- `image`: `base` (an id from `buildenv-catalog.json`, e.g. `audit-buildenv-cpp`) and
  `apt_packages` (name, why, citations);
- `commands`: ordered, phase `configure` / `build`, each an argv array with purpose,
  authorization, side effects and citations (the shape of `safe_command_plan` entries in
  `project-discovery.schema.json`), plus `compile_database` (how it is produced, e.g. `bear -- make`);
- `assumptions` and `unknowns`, each cited.

**Validation (deterministic, before anything is built):** schema; every citation resolves to a
signal in the index with a matching sha256; `base` is in the catalog; package names match
`^[a-z0-9][a-z0-9+.-]{0,62}$`, at most 60; argv arrays only (no `sh -c`, no pipes, no redirection
strings), relative `cwd` inside the tree, no absolute paths outside `/src` and `/build`; no URLs,
no extra apt sources, no `curl`/`wget`/`git` in commands; no findings. A rejected plan costs one
attempt and the rejection reasons go back to the model.

**Why a structured image spec and not a model-written Dockerfile:** the Dockerfile is rendered by
our code (`FROM <base pinned by digest>`, one `apt-get install --no-install-recommends` of the
sorted package list, lists removed). The model chooses *what*; it cannot choose *how* (no added
repositories, scripts, downloads or `COPY` of target files). Images define tools only; the target
is mounted at run time, never baked in (AGENTS.md).

## 4. `02-build-resolution` (implemented and live-qualified)

For attempt `n = 1 .. build_resolution_attempts` (default **3**, allowed 1-10):

1. **Plan:** attempt 1 uses the reused plan (step 2) or a fresh inference; later attempts ask the
   model to revise.
2. **Image:** render the Dockerfile; its spec fingerprint (base digest + sorted packages + renderer
   version) names the image `image_build_<first 12 hex>`. If that image already exists locally with
   the recorded id it is reused, otherwise built by the closed worker renderer with Docker
   BuildKit. Network is allowed
   **only here**, only to the base distribution's package mirror, under a `package-restore`
   (`ecosystem: apt`) grant (ADR-0011: network only during provisioning, never in a B13 run).
   C/C++ specs extend the B16-resolved `audit-buildenv-cpp`, whose own build fingerprint binds the
   immutable local `audit-native` image id. The base fixes `CC=/opt/llvm/bin/clang` and
   `CXX=/opt/llvm/bin/clang++`; a plan cannot replace them.
3. **Trial:** B13 mounts the checkout read-only and the trusted runner copies it into the attempt's
   sole writable `/scratch` tree (`autoreconf` and `configure` write there; the host checkout is
   never touched), then runs each `configure` and `build` command
   through B13: pinned image, `--network none`, `--pull never`, resource limits, per-command
   timeout `build_command_timeout_seconds` (default 1800). Needs a `target-execution` grant; without
   it the job is `BLOCKED(MISSING_GRANT)` before any attempt.
4. **Judge (deterministic):** every configure/build command exited 0, and for native families the
   compile database is non-empty, names files in the tree, and every compiler is allowed by the
   orchestrator-owned toolchain. There is no test phase (ADR-0012 Revision 3); built targets are
   never run.
5. **On failure:** record the attempt (plan, Dockerfile, image id, per-command exit codes, log
   tails), build a failure excerpt (last 200 lines of the failing command, redacted, at most 16 KiB,
   marked as untrusted data) and loop.

**Outcomes:**

| Status | When |
|---|---|
| `OK` | A trial succeeded. The image is catalogued and the lock written (below). |
| `FAILED(BUILD_UNRESOLVED)` | Attempts exhausted. Every attempt stays on disk; the last plan and failure are the hand-off for a human. |
| `BLOCKED(...)` | A precondition was missing (grant, catalog entry under `require`, invoker unavailable). Nothing was built. |

A failed resolution fails this job, and every native job that depends on it (`02-build-configure`,
`02-native-build`, native SAST, fuzzing) is blocked. Lanes that do not need a build still run: a
target we cannot build is still reviewed, with the gap stated in the report.

## 5. Catalog and lock

On `OK`:

- **Image catalog entry** `data/build-images/catalog/image_build_<id>.json` (host-local, outside
  every run, like the NVD feed; schema `appsec-review/build-image/1`): image id and tag
  (`appsec-build/image_build_<id>:local`), local image id (`digest_kind: image-id`), rendered
  Dockerfile and its sha256, base image and digest, package list, and `validated_builds`: one row
  per successful trial (source revision, plan sha256, run id, attempt id, date). The entry is
  immutable and validated against `schemas/build-image.schema.json` on reuse and publication.
- **Container-image record** for B13 in `data/build-images/container-images/image_build_<id>.json`
  (the B16 shape). B13 resolves tracked records in `appsec-review-process/pipeline/container-images/` and, for ids
  starting `image_build_` only, these host-local ones. This is a required B13 change.
- **Build lock** `build-lock.json` in the immutable accepted attempt (the Phase 4 `buildenv-lock` shape): image id
  and local digest, Dockerfile sha256, ordered argv for configure / build, compile-database
  producer, attempt summary, source revision. `02-build-configure` (E01) and `02-native-build` (E02)
  replay this lock from a clean copy: if the replay does not reproduce the trial, that is a failure
  of those jobs, not a silent pass.

The replay workers passed live happy-path qualification in SAT `20260927T005731Z`. `02-build-configure` executes
only the lock's configure argv and publishes `configured-build.json` plus the B13 receipts.
`02-native-build` starts from another clean scratch copy, executes configure then build, and
publishes `native-build.json`, the clang compile database and produced native binaries. Both use
the catalogued immutable image, an exact run/job/source-bound target-execution grant, no network,
a read-only target and caller-held B13 result hashes. SAT stages 14 and 15 exercise their happy
paths; fault/recovery qualification remains.

A catalogued image is deleted only by an operator (`image_build.py` prune, later); the catalog
entry is never rewritten, only appended to.

## Model and authentication

Decided by William, 2026-09-24.

| Setting | Value | Where to change it |
|---|---|---|
| Model | Haiku (`haiku`, the claude CLI alias for the current Haiku) | `appsec-review-process/model-config.json`, `unbuilt_job_defaults["02-build-plan"].model` (moves into `appsec-review-process/pipeline/job-templates/02-build-plan.json`'s own `model` field once that job template is authored -- see model-config.json's `_notes`, changed 2026-09-24) |
| Authentication | `subscription`: the claude CLI's current login, never an API key | `appsec-review-process/model-config.json`, `invocation.auth.mode` |

With `subscription`, the invoker removes `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` from the
environment of the `claude` child process only. A key left set in the operator's shell would
otherwise switch billing to the API without warning (`scripts/Test-SubscriptionAuth.ps1`); the
operator's own environment is not changed.

**To use an API key instead** (the one place to change): set `invocation.auth.mode` to `api-key`
in `model-config.json`. The invoker then passes `ANTHROPIC_API_KEY` through to `claude` and refuses
to start if it is not set. Nothing else changes: the same CLI, flags, model and prompts. A direct
Anthropic API client (no CLI) would be a second `PersonaInvoker` implementation; it is not planned.

Every attempt records the auth mode, the requested model, the model that actually answered (from
the CLI's JSON output; `--fallback-model` can substitute one under load) and the prompt hash, so a
plan can be audited and replayed.

## Job parameters

| Parameter | Default | Meaning |
|---|---|---|
| `build_resolution_attempts` | 3 | Attempts (plan + image + trial) before `FAILED(BUILD_UNRESOLVED)`. 1-10. |
| `build_image_reuse` | `auto` | `auto` / `rebuild` / `require` (section 2). |
| `build_image_id` | none | Pin one catalogued image; implies `require`. |
| `build_command_timeout_seconds` | 1800 | Per command inside the trial. |
| `image_build_timeout_seconds` | 1800 | Per image build. |

## Security notes

- The index, README text, CI files and build logs are target-controlled. They reach the model only
  as marked data; the plan's effect is limited by validation (package names from the distro mirror,
  argv only, no network, no downloads) and by the B13 boundary, not by trusting the model.
- The only network use is the image build, to one mirror host, under a named grant. Trials run with
  no network, so a build that downloads dependencies at configure time fails and the model must
  move that dependency into `apt_packages` or declare the build infeasible (tier C).
- Only apt packages in v1. pip, npm, cargo, Maven and similar need `package-restore` for their own
  ecosystem and a pinned mirror; until then a plan that needs them ends `BLOCKED(UNSUPPORTED_ECOSYSTEM)`
  with the reason recorded.
- Running `./configure` and `make` executes target code; that is the point of a trial and is why it
  is behind the `target-execution` grant and the B13 boundary.

## How it maps

| Piece | Graph job (new unless noted) | Replaces |
|---|---|---|
| Indexer | `02-build-index` | `build_discovery.py` collector (CMake only) |
| Inference | `02-build-plan` | Build fields of the supplied `02-dev-project-discovery` record; the rest of developer discovery stays a gate |
| Loop, image, catalog, lock | `02-build-resolution` | Phase 4's hand-written lock and `provision-buildenv.md` skill |
| Replay | `02-build-configure` (E01), `02-native-build` (E02), existing nodes | `build_execution.py` |

New graph nodes follow the full protocol (AGENTS.md: `job-graph.json`, `design-parity-manifest.json`,
worker contracts, output contracts, schemas, tests). Developer discovery's accepted record and the
build plan are cross-checked (build system, project root); a disagreement is recorded, not fatal.

## System acceptance test

The SAT walks these in flow order after the discovery gates and before evidence collection
(`docs/processes/system-acceptance-test.md`): `build-index`, `build-classify`, `build-plan`,
`build-resolution`, `build-configure`, `native-build`. Beyond the usual pre/post contracts:

- pre-contracts check the fixture answer keys are **not** in the run and are not among the
  invocation's inputs;
- after `build-index` the SAT checks the units: for hello-autotools, the root (`configure.ac`,
  `Makefile.am`, with the vendored cJSON compiled inside it) and the `Dockerfile`;
- after `build-plan` the SAT checks the classes (root `compiled-native`, `Dockerfile` `container`, no
  plan for the container) and compares the root unit's plan with the answer key (autotools, root `.`,
  `autoreconf`/`configure`/`make` in that order), reporting differences;
- `build-resolution` must end `OK` for the root unit within the attempt budget, catalog an image and
  write its lock entry; no image is built from the repository's `Dockerfile`;
- `build-configure` must replay exactly the configure commands and retain the caller-held B13
  receipt; `native-build` must replay configure/build and publish a non-empty clang compile database
  plus at least one native binary;
- a second SAT run with `auto` must reuse the catalogued image (no inference call), and a run with
  `rebuild` must infer again.

## Open

- Windows targets (`*.sln`, MSVC) need a Windows build environment; out of scope for v1, recorded
  as `BLOCKED(UNSUPPORTED_PLATFORM)`.
