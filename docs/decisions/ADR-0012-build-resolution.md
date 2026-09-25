# ADR-0012: Build Resolution (index, LLM plan, bounded build loop, image catalog)

Status: Proposed 2026-09-24 (design direction from William Sollers, 2026-09-24). Design:
[docs/processes/build-resolution.md](../processes/build-resolution.md).
**Revised 2026-09-25** for per-unit resolution and model classification: see
[Revision 1](#revision-1-2026-09-25-per-unit-resolution-model-classification) at the end.

## Context

The review needs a working build of the target for every native activity: compile database, native
SAST, binaries for fuzzing and binary analysis. The system does not know how to build a target it
has never seen. What exists today does not close that gap:

- `build_discovery.py` is a CMake-only regex collector; the `hello-autotools` fixture has no CMake.
- The build fields of developer discovery (`02-dev-project-discovery`) come from a hand-written
  supplied record. We could write it only because we wrote `hello`.
- `persona_invocation.py` is protocol only; no model is ever called for discovery.
- No build image has been built or locked; Phase 4 in `appsec-review-process/TODO.md` planned a
  hand-supplied lock and an agent skill, without a job, a retry budget or reuse.

The system acceptance test surfaced this as the first real gap after the discovery gates: proceeding
to evidence collection without knowing how to build means native evidence can never be complete.

## Decision

1. **Deterministic indexer first (`02-build-index`).** A Python pass gathers every build signal
   (build systems, toolchain and dependency declarations, CI and Dockerfile recipes, README build
   text) into a bounded, sha256-cited index. It executes nothing.
2. **LLM inference over the index (`02-build-plan`).** The model reads only the index, the buildenv
   catalog and the schema, and returns a structured build plan: base image, apt packages, ordered
   argv commands, feasibility tier, each claim cited. The plan is validated deterministically
   before anything is built. The model is **Haiku**, called through the `claude` CLI with its
   current login (the operator's subscription), never an API key: the invoker strips
   `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` from the child process. Both are set in
   `model-config.json` (`unbuilt_job_defaults["02-build-plan"]` until that job template is
   authored, then its own `model` field; `invocation.auth.mode`); switching to an API key is
   `invocation.auth.mode = "api-key"` there and nothing else. (Model routing redesigned
   2026-09-24: jobs declare their own model in their job-template record rather than a
   lane-keyed table -- see model-config.json's `_notes`.)
3. **Our code renders the Dockerfile.** The model chooses base and packages; it never writes a
   Dockerfile, adds repositories, downloads or copies target files into an image.
4. **Bounded loop (`02-build-resolution`).** Build the image (network to the distro mirror only,
   under a `package-restore` grant), then configure and build a writable copy of the source through
   B13 with no network, under a `target-execution` grant. On failure, feed a bounded, redacted
   failure excerpt back to the model and retry. `build_resolution_attempts`, default 3, bounds plan
   rejections and trial failures together. Exhausted: `FAILED(BUILD_UNRESOLVED)`; native jobs are
   blocked, non-native lanes continue and the report states the gap.
5. **Catalog on success.** The image is recorded as `image_build_<id>` (id from the image spec
   fingerprint) in a host-local catalog with every validated build; a B16-shaped record lets B13 run
   it; the run gets a build lock that E01/E02 replay from a clean copy.
6. **Reuse by default, overridable.** `build_image_reuse` = `auto` (try a catalogued image first; its
   failure seeds the model), `rebuild` (the build needs different tools: infer from scratch),
   `require` (catalogued image or block). `build_image_id` pins one.
7. **Fixture discovery records become answer keys.** The SAT compares the plan with them; no job may
   read them.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Widen the regex collector until it proposes commands itself | Every build system and project convention becomes code we maintain; cannot reason over README text or CI recipes; still cannot recover from a failed configure. |
| Let the model read the whole checkout (agentic, tool use) | Unbounded cost and input; harder to cite and replay; more exposure to target-controlled text. The index gives the model what it needs, bounded and cited. |
| Model writes the Dockerfile | Gives target-influenced text control over `RUN`, repositories and downloads during a networked build. A structured spec keeps the effect to "these distro packages on this base". |
| Unbounded retry / human after the first failure | Unbounded is a cost and a loop risk; human-first defeats the purpose. A small budget with full attempt records hands the human a precise state when it fails. |
| Tracked, per-project catalog in the repository | Local images are identified by a local image id that means nothing on another host, and customer project identities should not land in the tracked repository. |

## Consequences

- Three new graph nodes and their schemas (`build-index`, `build-plan`, `build-image`), under the
  full job-graph protocol; `build_discovery` / `build_execution` retire when they land.
- B13 must resolve host-local `image_build_*` records in addition to tracked ones.
- The first model call in the pre-evidence process; its prompt hash, model and output are recorded
  per attempt so a result can be audited and replayed.
- Phase 4 and the build part of Phase 5 in `appsec-review-process/TODO.md` are replaced by this
  design.
- The SAT gains `build-index`, `build-plan`, `build-resolution` stages between the discovery gates
  and `build-configure`.

## Non-decisions

- Ecosystems beyond apt (pip, npm, cargo, Maven): each needs its own `package-restore` mirror; until
  then `BLOCKED(UNSUPPORTED_ECOSYSTEM)`.
- Windows and MSVC targets.
- Pruning of catalogued images.

## Revision 1 (2026-09-25): per-unit resolution, model classification

Status: Proposed 2026-09-25 (decisions by William Sollers, 2026-09-25; recorded in
[build-unit-classification.md](../processes/build-unit-classification.md) and
`appsec-review-process/TODO.md` Phase 5g). Amends the decisions above; where they conflict, this
section wins. The build-lane nodes are still designed, not built.

### Why

The original decision assumes one native project per target. Real targets mix compiled, transpiled
and interpreted code, container definitions and infrastructure, often in one repository. Building
executes target code, so only the pieces that need a build for evidence are built, each on its own,
and a piece that cannot be built must not block the others.

### Decisions

1. **Units.** A unit is one build root: the directory of a defining manifest (`configure.ac`,
   `CMakeLists.txt`, `meson.build`, `Cargo.toml`, `go.mod`, `package.json`, `pom.xml`,
   `build.gradle*`, `*.csproj`, `pyproject.toml`, `composer.json`, a `Dockerfile`, a Terraform root, a
   Helm chart, ...). A nested root that a parent build uses (listed as a subdirectory, a sub-project or
   compiled sources of the parent) belongs to the parent unit. A vendored or example copy with build
   files that no in-scope build uses is not a unit, and is recorded as such.
2. **`02-build-index` stays deterministic** and now enumerates candidate units: for each, its root, its
   manifests and lockfiles, and its cited signals (build-system and toolchain declarations, extension
   counts, CI and Dockerfile recipes, README build text, and the markers that separate JavaScript from
   TypeScript or bundled code). It assigns no class. Bounds, citations and validation are as in
   decision 1.
3. **The model classifies every unit** in `02-build-plan`: one class per unit from `compiled-native`,
   `compiled-managed`, `transpiled`, `interpreted`, `container`, `infrastructure`, `unclassified`,
   each cited to index signals; a mixed unit (a Python package with a C extension) is split into
   parts with their own ids. A class with no resolvable citation is rejected like any other claim; a
   unit the model cannot place is `unclassified` with a coverage gap. The build set is the
   `compiled-native`, `compiled-managed` and `transpiled` units.
4. **One plan per build-set unit.** `02-build-plan` returns a plan for each build-set unit in the
   shape of decision 2 (base image, packages, ordered argv, compile-database producer, feasibility,
   citations), validated per unit before anything is built. Other units get a disposition, not a
   plan: `interpreted` to SAST and SCA as source; `container` to Dockerfile analysis and a base-image
   scan; `infrastructure` to static IaC analysis; `unclassified` to a coverage gap.
5. **One bounded loop per unit.** `02-build-resolution` runs the decision-4 loop separately for each
   build-set unit, with `build_resolution_attempts` per unit and no cap on the number of units. Units that
   need the same image spec share one catalogued image. Each unit ends `OK`,
   `FAILED(BUILD_UNRESOLVED)` or `BLOCKED(<reason>)` (`UNSUPPORTED_ECOSYSTEM`, `UNSUPPORTED_PLATFORM`,
   `MISSING_GRANT`, ...).
6. **Job status from unit outcomes**, in the worker-result contract's terms: `OK` when every build-set
   unit resolved; `OK_WITH_GAPS` when at least one resolved and the others are recorded gaps;
   `UNRESOLVED` when none resolved after bounded work; `BLOCKED` when a precondition for every unit was
   missing; `SKIPPED` (not applicable) when the build set is empty. A failed unit blocks only the
   native or managed jobs for that unit.
7. **The lock is per unit.** `build-lock.json` holds one entry per build-set unit (outcome, image id
   and digest, rendered Dockerfile hash, ordered argv, compile-database producer, attempt summary).
   `02-build-configure` and `02-native-build` replay it unit by unit; a unit without an `OK` entry is
   not replayed.
8. **Repository Dockerfiles are never built, and nothing is ever run.** The loop builds only images
   our code renders from a plan (decision 3). Running a built target (fuzzing, dynamic testing) is out
   of scope for now (`TODO.md` section 10).
9. **Ecosystems.** apt first (hello-autotools), then npm, Maven/Gradle, cargo and Go modules, NuGet.
   For the POC, dependencies are restored during provisioning only, from each ecosystem's public
   registry, with TLS verification and lockfile hash verification (registry-published checksums,
   recorded as weaker, where the repository pins none); the trial stays offline (`TODO.md` Phase 5f).
   A local caching proxy is deferred.

10. **Models** (William, 2026-09-25): the classification call (one per run, over the whole index) uses
    `claude-sonnet-5`/`medium`, like the discovery jobs; per-unit plans stay Haiku, as decided above.
11. **No unit cap** (William, 2026-09-25): every build-set unit is resolved; cost scales with the
    repository, bounded per unit by `build_resolution_attempts`.

### Consequences

- `build-index.json` gains `units[]`; `build-plan.json` becomes per unit (classification plus plans);
  `build-lock.json` becomes per unit. All three schemas are new, so no existing record moves.
- The three new graph nodes still follow the full job-graph protocol when they are built.
- The fixture answer key for the SAT becomes two units for hello-autotools: the root autotools unit
  (`compiled-native`, with the vendored cJSON compiled inside it) and the `Dockerfile` (`container`,
  not built).
