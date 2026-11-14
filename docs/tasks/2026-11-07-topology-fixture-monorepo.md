---
title: "TASK - BUILD-TOPOLOGY FIXTURE MONOREPO AND ITS TARGET CONTRACT"
kind: "task"
subsystem: "target acquisition and build"
status: "historical"
jobs: ["job_target_analysis_plan"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# TASK - BUILD-TOPOLOGY FIXTURE MONOREPO AND ITS TARGET CONTRACT

Real monorepo targets (a C++ game server, a Unity client, iOS/Android clients, a PHP website) fail in
the intake-through-build front end for four conceptual reasons, and no committed test target exercises
any of them: ownership of vendored trees, workspace materialization of sibling paths, the absence of a
deterministic recipe path for canonical build systems, and the absence of a plan-time build-mode
disposition for components that policy or platform forbids building. Testing a fix against the real
target costs an eight-hour review. This task adds a committed fixture whose shapes reproduce each
failure, a machine-readable target contract, and a harness that turns every unmet expectation into a
strict expected failure. It changes no runtime behaviour.

## What was added

| Path | Role |
| --- | --- |
| `test/topology/monorepo/` | 46 files, about 22 KB in all (half of it README.md and MANIFEST.json), no binaries, no network dependencies. One directory per shape (table below). `README.md` describes the shapes; `MANIFEST.json` pins every file's SHA-256. |
| `test/topology/monorepo.expectations.json` | Schema `appsec-review/topology-fixture-expectations/1`: per shape the expected components (root, family, build system, build mode, image profile, minimum materialization root, deterministic recipe), the ownership of every build unit, intra/cross-component relationships, and a `gaps` map naming the reason code under which the current runtime does not meet a field. |
| `docs/schemas/topology-fixture-expectations.schema.json` | JSON Schema (draft 2020-12) the expectations validate against. |
| `src/appsec_review/acceptance/topology.py` | `prepare`, `evaluate`, `score`, `manifest`; shared in-process catalog -> plan path and the comparison the test and the CLI both use. |
| `tests/test_topology_fixture.py` | The fast harness (about 150 cases, a few seconds, no Docker, no model). |

| Shape | Directory | Reproduces |
| --- | --- | --- |
| A | `server/` + `third_party/tinylib/{CMakeLists.txt,Makefile,test/Makefile}` | a vendored library's test Makefile referencing `../src/*.c` becomes an independent root |
| B | `tools/packer/` with `../../common/...` | a workspace materialized from the unit root alone cannot build |
| C | `rust/` (Cargo workspace), `go/` (go.work), `web/` (npm workspace) | workspace members are independent roots |
| D | `client-unity/` | engine project; build is a policy decision (`unity.enabled = false`) |
| E | `client-ios/App.xcodeproj` | unsupported platform; never dispatched to a Linux image |
| F | `client-android/` (`settings.gradle`, `:app`, `:lib`, no root `build.gradle`) | one project, never two roots |
| G | `website/public` (no composer) and `website/lib` (composer) | source-only scope beside a package-only unit |
| H | `server/examples/hello/` under `option(... OFF)` | conditional nested root: contained, never independent |
| I | `tools/sign/` | the control: a genuine second native root |

## Running it

Fast harness (unit tier, no Docker, no model):

```text
PYTHONPATH=src python -m pytest tests/test_topology_fixture.py tests/test_blind_target_isolation.py -q
```

The same comparison from the command line, over the committed tree or a prepared copy (exit 0 when every
expectation is met or is a declared gap; exit 1 on an undeclared failure, a declared gap that is now met,
or a unit the expectations do not describe):

```text
PYTHONPATH=src python -m appsec_review.acceptance.topology evaluate [--target DIR] [--json]
PYTHONPATH=src python -m appsec_review.acceptance.topology manifest [--write]
```

Live review against the fixture (user-owned; `targets/` is gitignored so the copy never enters Git):

```text
PYTHONPATH=src python -m appsec_review.acceptance.topology prepare --into targets/topology-monorepo
appsec-review start --target targets/topology-monorepo
PYTHONPATH=src python -m appsec_review.acceptance.topology score --run <run-id-or-dir> [--expectations PATH]
```

`score` reads the run's accepted `job_target_analysis_plan` handoff through the normal verified reader
and prints the same per-shape diff (ownership, build mode, recipe presence, materialization root). It
never raises: a missing or unreadable plan prints one line and exits 2.

## Gap report: expectations the current runtime does not meet

These are the strict `xfail` cases of `tests/test_topology_fixture.py`, grouped by reason code. Each
flips to a hard failure when the behaviour lands; the fix then removes the gap from the expectations
(and, when a code has no gap left, the code itself). Counts are per checked field.

| Reason code | Cases | What is missing |
| --- | --- | --- |
| `ownership-vendored` | 2 | `server/third_party/tinylib/test` (Make, default goal `$(CC) ... ../src/tinylib.c`) is `independent` and would be dispatched standalone. Expected: `contained` by `server`. |
| `ownership-nested-conditional` | 1 | `server/examples/hello` (no `project()`, included only under `option(SERVER_BUILD_EXAMPLES OFF)`) is `unresolved`. Expected: `contained` by `server` with the condition recorded. It is already never `independent` (hard check). |
| `ownership-workspace` | 12 | `rust/core`, `rust/cli`, `go/shared`, `go/svc`, `web/packages/api`, `web/packages/ui` are `independent`. Expected: `contained` by their workspace root. The npm descriptor package already records the membership; the topology compiler ignores it. |
| `ownership-gradle-settings` | 8 | `:app`/`:lib` are independent roots with two image profiles (`android`, `java`). Expected: `contained` by the `client-android` root. *Job pass 05 (2026-11-08):* `settings.gradle` is a marker, so the settings-only root is discovered as one `gradle` unit with profile `android` and records its modules as `workspace.members`; folding them is the topology compiler's (T-035). |
| ~~`ownership-sibling-source`~~ | 0 | *Resolved in job pass 05:* a C/C++ source a native descriptor names from another directory (`../../common/src/util.c` in `tools/packer/Makefile`) is that unit's `native_components` entry, never a manufactured `direct-native` root; `common` has no unit, which the contract allows (`may_be_absent`). |
| `workspace-materialization` | 1 | `tools/packer` would be materialized from `tools/packer` alone. Expected minimum root: `.` (the common ancestor of every `../` reference). A recipe cannot even express this: `validate_build_recipe` rejects `dependency_files` outside the unit's descriptor package. |
| `deterministic-recipe` | 7 | `server`, `tools/packer`, `rust`, `go`, `web`, `website/lib`, `tools/sign` have null recipes. Expected: the canonical recipe at the component root (`cmake -S . -B build` / `cmake --build build`; `make`; `cargo build --workspace --offline`; `go build ./shared/... ./svc/...`; `npm run build`; `composer dump-autoload --no-interaction`). |
| `build-mode-disposition` | 10 | No build action carries a build mode. Expected per component: `compiled` (A, B, C-cargo, C-go, I), `package-only` (C-npm, `website/lib`), `skipped_policy` (D, F), `unsupported_platform` (E). `website/public` already meets `source-only` through `source_only_scopes`. |
| `swift-policy-disabled` | 5 | *Replaces `discovery-marker` (job pass 05):* `project.pbxproj` under an `.xcodeproj` bundle is a marker and discovery emits a `swift`/`xcodebuild` unit (`language: swift`, profile `swift`) at `client-ios`. The plan's Swift policy (`tools.enable_swift=false`) removes Swift-derived units from executable planning, so the plan does not carry it and no Linux image is ever asked to build it; the marker is declared absorbed. The `unsupported_platform` disposition for the component is still owed (`build-mode-disposition`). |
| `relation-workspace-member` | 3 | `rust/cli -> rust/core` (`path =`), `go/svc -> go/shared` (`use`/`replace`), `web/packages/api -> web/packages/ui` are not recorded as relations. |
| `relation-gradle-module` | 1 | `client-android/app`'s `project(':lib')` stays an `unresolved` relation because the path resolver rejects the colon notation. |

Already met by the current runtime (hard checks): every marker discovered and claimed once (the legacy
`tinylib/Makefile` is deliberately absorbed by the CMake unit at the same root); every unit accounted
for exactly once in a valid graph; stable `topology_id`/`bundle_identity`; `tinylib`'s `CMakeLists.txt`
`contained` by `server`; `server`, `tools/packer`, `tools/sign`, `rust`, `go`, `web`, `website/lib`
independent at the right roots with the right image profiles; Unity discovered as an engine project
with profile `unity` and no inference; `website/public` a `php` source-only scope with no unit; nothing
under `client-ios` reaches the plan; the `client-android` settings-only root discovered with profile
`android`; the npm workspace inventory (root, two members, lockfile); Cargo and Go workspace facts
(`workspace.manager/role/root/members`) on the `rust` and `go` units; no cross-component
scheduling edges anywhere (none are expected); no unit the expectations do not describe.

## Decisions

- **H is `contained`, not `unresolved`.** The directory has no `project()` and exactly one possible
  owner, so `unresolved` says less than the declarations do and invites standalone recipe inference for a
  tree that cannot build alone. The condition is recorded on the unit (`SERVER_BUILD_EXAMPLES`); a contained
  conditional unit is not scheduled by default. The hard check is only that it is never `independent`.
- **F is `skipped_policy`.** The fixture declares no wrapper, no offline plugin cache and nothing that an
  SDK image could resolve without the network; a networked Gradle build is not a permitted recipe. If an
  Android image with a provisioned AGP cache is ever pinned, the expected mode becomes `package-only` and
  the expectation changes with it.
- **B's `common` may be absent.** The contract is "never a standalone compile root"; discovery emitting
  no unit for `common` satisfies it, and if one exists it must be `contained` by `tools/packer`.
- **No cross-component edges by design.** Each shape is its own component; the `requires_product`
  relationships in the contract are intra-component (workspace member and Gradle module dependencies) and
  must become recorded relations, never scheduling edges.
- `test/topology/**` is byte-pinned in `.gitattributes` like the acceptance keys, so `MANIFEST.json`
  holds on every platform.

## Verification record

Focused unit tests and the local compile of every compiled shape are recorded in the commit that adds
this task. The live review path (`prepare` -> `appsec-review start` -> `score`) has not been run; it is
user-owned manual validation.

## Update 2026-11-08: members fold into their driving root (T-056, plan §2.1 decision 1)

Discovery now folds a driven directory into the unit that drives it: the Cargo and Go workspace
members, the npm workspace packages, the Gradle projects `settings.gradle` includes, and the CMake
directories `server/CMakeLists.txt` adds (`third_party/tinylib`, and `examples/hello` under its
option) are build points of the root unit, never units. Their contract rows are `may_be_absent`
("never a standalone root"), which the fold satisfies, and the reason codes that described them as
independent roots — `ownership-workspace`, `ownership-gradle-settings`, `ownership-nested-conditional`
— are retired. `ownership-vendored` now covers only `server/third_party/tinylib/test`, which nothing
drives (the parent adds `tinylib`, not `tinylib/test`) and so stays a root of its own. The
`workspace` facts named above are retired with the fold (the plan reads `drives`, T-035/T-056.4). The
marker-claim test reads the catalog's units (markers, folded `descriptors`, member points' `descriptor`),
so the Xcode project is claimed by its unit and is no longer listed as absorbed; the plan still
excludes it under the Swift policy.

Decision 2 (parallel systems, same day): the legacy `server/third_party/tinylib/Makefile` compiles the
same sources as the vendored CMake tree, so it is no longer dropped by position; it is a parallel `make`
unit with `capture_authority: secondary` and `parallel_with: ["server|cmake"]`, and it leaves the
`absorbed_markers` list. The plan still treats it as an independent root, recorded as
`capture-authority-secondary` until the plan reads `capture_authority` (T-035/T-036).
