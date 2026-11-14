---
title: "Job pass 05 — `job_target_catalog`"
kind: "task"
subsystem: "target acquisition and build"
status: "historical"
jobs: ["job_build_environment_analysis", "job_ci_configuration_analysis", "job_language_build", "job_project_build", "job_source_history_analysis", "job_target_analysis_plan", "job_target_catalog"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Job pass 05 — `job_target_catalog`

Fifth job of the pass (`docs/processes/job-pass-checklist.md`). Advances T-035 (discovery-side
facts), closes the fixture's `discovery-marker` and `ownership-sibling-source` reason codes, files
T-055. Previous: `2026-11-08-job-pass-04-review-intake.md`. Next: the three catalog consumers
(`job_build_environment_analysis`, `job_ci_configuration_analysis`, `job_source_history_analysis`),
then `job_target_analysis_plan`.

## What the job does

Fourteen units in five steps: inventory and top-level partition; language census; build-system
discovery (`build_discovery.discover_build_units` over marker files, Unity engine projects,
source-only scopes, unsupported-build gaps); project manifests; `compile_commands.json`
presence; build targets (descriptor packages, Android facts, `required_image_profile`); one
"component" per manifest; manifest dependencies (npm only); four retrieval indexes (paths, symbols,
components, documents); validation and publication (`target-catalog/1`, index manifest, build index).
It is the layer that decides *what the buildable things are*; everything after inherits that.

## Fixed — discovery facts for a monorepo

Discovery states facts; the topology compiler in the plan decides ownership (T-035). These four
changes add the facts a monorepo needs and stop discovery from inventing roots.

1. **A settings-only Gradle root is one Gradle unit.** `settings.gradle`/`settings.gradle.kts` are
   markers. A root that carries only settings (modules hold the build files) is discovered as a
   `gradle` unit whose descriptor package reaches the module build files, so the Android plugin
   facts route it to the `android` profile. Its modules stay units — as before — and both sides
   record membership as `workspace: {manager: gradle, role: root|member, root, members}`. A root
   that has its own `build.gradle` keeps absorbing its modules into one unit (unchanged behaviour,
   to be unified when the plan folds members; T-035).
2. **An Xcode project is a unit.** `project.pbxproj` directly under an `.xcodeproj` bundle is a
   marker; the unit root is the bundle's parent, family `swift`, build system `xcodebuild`,
   `language: swift`, `descriptor_facts.kind = xcode-project`, profile `swift`. `language: swift`
   places it under the existing Swift policy: with `tools.enable_swift=false` the plan removes it
   from every executable planning input (`SWIFT_KNOWN_GAP`), so no Linux image is ever asked to
   build it and no inference role is needed for it. A stray `project.pbxproj` outside a bundle is
   not a marker.
3. **No manufactured root for a source a sibling descriptor names.** Before a `.c/.cc/.cpp/.cxx`
   file with no descriptor root became a `direct-native` unit at its conventional `src/` parent,
   discovery now checks whether any native descriptor (Makefile, CMakeLists, configure, meson)
   names the file — literally (`../../common/src/util.c`) or by glob (`$(wildcard ../src/*.c)`),
   resolved from the descriptor's directory. If one does, the source is that unit's
   `native_components` entry. `common/` on the fixture no longer exists as a unit.
4. **Cargo and Go workspace facts.** A `Cargo.toml` with `[workspace].members`/`exclude` and a
   `go.work` with `use` entries record `workspace` on the root (`members`) and on each member unit
   (`role: member`), the same shape npm workspaces already use through `node_workspace()`. Members
   remain units.

`DISCOVERED_BUILD_SYSTEMS` gains `xcodebuild` (derived from the marker table, so the plan's registry
accepts it).

Fixture contract: `swift-policy-disabled` replaces `discovery-marker` (the unit is discovered; the
plan's policy hides it) and `ownership-sibling-source` is retired (the optional `common` unit is
absent, which the contract allows). `client-android`'s "discovered" gaps are gone. 54 → 47 strict
xfails; `docs/tasks/2026-11-07-topology-fixture-monorepo.md`'s gap table is updated.

## Not changed here

The catalog's gaps are free text and index-coverage strings across many units (inventory,
engine, unsupported builds, index builders' `IndexIdentity.gaps`), so the job stays on the legacy
list; converting them touches the retrieval-index contract and is its own item (T-055). Typed
failure classes are also deferred to that item: today a failed unit is a `RuntimeError`/`ValueError`
with a specific message, which the tests assert.

## Test audit

Before: discovery itself is well covered — `tests/test_build_discovery.py` (44), `test_native_discovery.py`
(39), `test_streaming_project_discovery.py` (10, the job's units with hand-built inputs) — but no
test ran the job through the runner over a monorepo-shaped target, nothing covered the job's
failure paths or telemetry, and none of the four shapes above had a test (they were the fixture's
xfails).

Added:

| Behaviour | Test |
| --- | --- |
| Settings-only Gradle root: one unit, modules kept, membership facts, no javac roots; root with build file still absorbs | `test_a_settings_only_gradle_root_is_one_unit_that_names_its_modules`, `test_a_gradle_root_with_its_own_build_file_still_absorbs_its_modules` |
| Xcode project: root, family, language, facts, profile, Swift policy, stray pbxproj ignored | `test_an_xcode_project_is_a_swift_unit_rooted_at_the_bundles_parent_under_the_swift_policy` |
| Sibling source → component; unreferenced source → fallback root; no text → old behaviour | `test_a_source_a_sibling_descriptor_names_is_that_units_component_not_a_new_root` |
| Wildcard reference inside a vendored tree; matching root wins first | `test_a_wildcard_reference_in_a_vendored_test_makefile_binds_the_sources_it_globs` |
| Cargo members/exclude globs and go.work `use` facts; members remain units | `test_cargo_and_go_workspace_facts_are_recorded_without_deciding_ownership` |
| The job over the fixture monorepo: every shape in `build-systems.json`/`build-targets.json`, profiles, lifecycle, `REVIEW_SCOPE_CATALOGED` receipts, index manifest | `tests/test_target_catalog_job.py::test_the_catalog_of_a_monorepo_names_every_build_shape_once` |
| Injected failure in three units: attempt fails, upstream evidence kept, no handoff/event, lifecycle | `test_a_failing_unit_fails_the_attempt_keeps_upstream_evidence_and_publishes_nothing[partition,targets,validate]` |
| Reuse on resume; a changed target re-runs intake and INVALIDATEs the catalog (two attempts) | `test_the_catalog_is_reused_on_resume_and_rebuilt_when_the_target_changes` |
| Configured topology = units | `test_configured_topology_matches_the_job` |

Commands and results (cloud clone, Python 3.13, no Dagster, no Docker):

```
pytest tests/test_build_discovery.py tests/test_native_discovery.py tests/test_streaming_project_discovery.py
       tests/test_topology_fixture.py tests/test_cataloging_languages.py              342 passed, 47 xfailed   5 s
pytest tests/test_target_catalog_job.py                                               6 passed                 8 s
pytest tests/test_todo_registry.py                                                    5 passed
Consumer sweep, differential against the base commit (same environment):
pytest tests/test_build_topology.py tests/test_build_topology_feedback.py tests/test_target_analysis_plan.py
       tests/test_project_build.py tests/test_language_build.py tests/test_jvm_language_build.py
       tests/test_language_build_node.py tests/test_live_android_build.py
       base:  51 failed, 277 passed, 2 skipped   179 s
       head:  51 failed, 277 passed, 2 skipped   178 s     identical failure set; 0 new, 0 fixed
```

The 51 are the post-merge failures in `job_target_analysis_plan` (3), `job_project_build` (20) and
`job_language_build` (28) noted at the start of the pass (T-047); they are those jobs' audits.
`tests/test_engine_commissioning.py` (Unity commissioning, 1 failure + 54 fixture errors) also fails
on the base and is not a catalog test.

Not run: parallel (`-n`), integration/live.

## Carried forward

- T-055: catalog gaps as records (inventory, engine, unsupported builds, index coverage) so the
  job can be `strict_gaps`; typed failure classes.
- T-035 consumes the new facts: fold `workspace.role == member` and Gradle members as `contained`,
  then remove the Gradle root-with-build-file absorption so both Gradle shapes are treated alike.

## WSOLLERS1 c094 criterion, 2026-11-10

Before dispatch on `2026-11-10-0003`, the catalog must preserve intake's 344 retained files,
four configured `.gitignore` exclusions and raw source fingerprint. Every source inventory entry
must resolve to the tagged file's bytes. All eleven `projects/native/case-094` files must remain
queryable; that directory has exactly one build descriptor, `CMakeLists.txt`, declaring C++17
executable `case094` from `access`, `blocks`, `console`, `directory`, `echo`, `main`, `notes` and
`title` `.cpp` files. It must appear as exactly one CMake/native build unit and target, routed to
the native profile, with its descriptor package intact and none of those sources orphaned.

The target contains no `compile_commands.json`: unavailable compile-unit coverage is expected
before building, never fabricated as complete. Every other discovery/index gap must be checked
against named target evidence and declared policy before acceptance. The source, analysis,
components, documents and build shards must all publish with resolving manifest hashes; catalog
source/project/build receipts and `BUILD_SYSTEMS_DISCOVERED` counts must agree with the actual
artifacts and lifecycle. The catalog must not manufacture security findings.

## Found on the WSOLLERS1 run

Attempt 1 (`bfbe9e5a-fe31-42fb-b8e6-6c9d787247b1`) completed in 93,490 ms with a passing envelope
and filesystem audit, but **is not accepted**: content verification found document-ingestion
defects. The valid `northwind.postman_environment.json` (`_postman_variable_scope: environment`)
is misclassified as an invalid collection; collection operations also disappear with
`unresolved_span` gaps. These are job-content defects, not image/signing/host faults. A bounded
job-specific repair context owns the document reader and focused offline regressions. Observation
time is `2026-11-10T13:24:33-05:00`; replay and measurement records are
`runs/failure-job_target_catalog.json` and `runs/c094-catalog-content-fault.json`.

Independent checks already confirm all 344 retained file hashes/sizes, five published shard hashes
and the c094 unit: exactly one CMake/native unit, executable `case094`, all eight named C++ sources
and the intact descriptor routed to the native profile. The run discovers 51 build units and
reports 13 orphan sources. Five are native sources beneath non-native units (Node/PHP/Python/Wasm);
their membership claims require checking before acceptance, rather than silently treating that
diagnostic as proof they cannot build. No c094 source is orphaned. Missing compile databases are
the expected pre-build gap. Deferred non-npm dependency parsers and unknown dependency delivery
status are named capability/knowledge gaps, not newly inferred failures.

The bounded repair context returned `f0d2930f2b061e2422120b5ab72691f2bd29a199` (exclude standard
Postman environment exports from collection discovery, retaining source inventory) and
`e60f1041aab94d588192c782582ef694b352b868` (structural JSON member spans instead of whitespace-sensitive
global matches). Inline URLs previously failed to resolve, and repeated URL text could incorrectly
cite a body/saved response. The fix binds actual request members, preserves distinct same-line
requests, and refuses duplicate JSON keys or exceeded structural bounds explicitly. Parser identity
advances to `target-documents/3`; output schemas and job contracts are unchanged.

The child's own Linux environment verified **59 passed in 10.84 s**, slowest 8.409 s, no skips,
using `scripts/run-tests.sh --parallel --test-workers 4 --shuffle-seed 11014 --
tests/test_target_documents.py
tests/test_target_catalog_job.py::test_catalog_publishes_postman_requests_not_environments_and_keeps_real_parse_gaps`.
The regressions failed before the repair (one classification failure and ten span failures).
An intermediate four-launch publication fixture exceeded ten seconds under contention; the same
positive/negative assertions were consolidated into one real graph launch, not dropped. Read-only
parsing of the two observed files now resolves all 17 requests without gaps. Full commands, elapsed
times and intermediate results are retained in the repair handoff.

Before integration, `verify-repair-stop` confirmed the original dispatch terminal with worker
`NOT_FOUND`. This is a content-repair cycle despite the framework's original `SUCCEEDED` status;
the catalog remains unaccepted until its real rerun is checked.

### Recovery prerequisites and admitted replay

The document fixes were integrated unchanged as `ddcac4170` and `5a6e919cb`. Reload succeeded,
but planning exposed a T-051 consumer regression: the debug-symbol job's input-identity probe
still required an image ID in the raw recipe catalog. A separate bounded repair context returned
`dbeca3e3f876bf8f7f1a02e49f9f6d20eafe47ec`, integrated unchanged as `0a4652b1c`. All execution-plan
callers now use verified run-owned configuration/host bindings and the frozen declared release.
No schema, image, target or signing policy changed.

That repair's 14 new host-binding regressions pass. Its shuffled four-worker affected set reported
108 passed / 3 failed in 19.00 s, no test over ten seconds. The remaining two strict-runner cases
use unsupported synthetic upstream handoff locations; a documentation-link check needs an absent
target checkout. Those paths were not repaired or represented as passing. Exact commands/results:
`runs/c094-debug-binding-repair-handoff.json`. The original identity-probe reproduction failed before
the fix; the live repair planner now completes.

The first complete plan refused missing stopped-worker receipts for the four earlier successful
dispatches: stepwise recovery checks every recorded dispatch, not only the failed/content-rejected
one. Each was verified terminal/`NOT_FOUND` through the existing command; no receipt or lease was
fabricated or deleted. The resulting plan is admissible with zero refusals.

The inspected plan says `RUN` for connectivity, image verification and acquisition because all three
explicitly declare `always_execute`. It says `RUN` for intake because these fixes changed shared
implementation/validator files, and `INVALIDATE` for the catalog. This is not a demonstrated
release-scoping defect: `runtime/release.py` hashes each job's package and imported job packages,
plus shared common/validator/script inputs. A future job-local edit that invalidates unrelated
builds/CodeQL would be the relevant counterexample.

William explicitly authorized admitting this replay and adding guarded stepwise rewind, while
leaving release scoping and gate policies unchanged. Admission is recorded in
`runs/c094-catalog-repair-admission.json`; the exact plan is `runs/c094-catalog-repair-plan.json`.
Its admitted release is `9966930659bf5359aa3f1503192d4793de96a3dae5f00120c249d2700cc2fa3a`;
frozen configuration remains `9988548fec8e92de1c0d8ec298b2600814a4adb95b31893e680253a068cbf1d8`.
The operator rewind must preserve prior acceptance evidence and compare replayed outputs with
those keys before reacceptance. No job has rerun yet, so the first fault-to-rerun turnaround
remains open; it includes both the consumer repair and missing operator-rewind capability.

### Guarded rewind and validation-scope incident

The operator-only rewind arrived as `cfe3e19938597a5300b70db8819be1fd462b95aa`, integrated
unchanged as `5bd73e8f1`. It changes no measured runtime source, so no further reload or
re-admission was required. The live `stepwise.py rewind --app-run 2026-11-10-0003 --plan
runs/c094-catalog-repair-plan.json` applied successfully, preserving the previous state,
keys/provenance/claims and checks under the walk's immutable `rewinds/` evidence. The first
reopened job is model connectivity. Replays must match the preserved key before reacceptance;
only verified admission/checkpoint bookkeeping changes are reported separately.

The rewind implementation's delegated mechanical test command accidentally included a trailing
`.` pytest selector. This was an execution-scope violation: it ran a broad suite including
unapproved integration/acceptance/live paths for **7,951.49 seconds (132.52 minutes)**.
Those results are not authorized validation and were not used to justify unrelated fixes.
The corrected focused command, with exact file selectors, reported **33 passed in 38.00 seconds**,
no test over ten seconds. Exact commands, failures and artifact paths are preserved in
`runs/c094-rewind-validation.json`.

After disclosure, the parent checked that no Bash commands or persistent Dagster runs remained
active, the persistent Dagster dispatch list had not gained any jobs, all five stack services
were healthy, and the c094 raw fingerprint was unchanged. This is not a complete audit of every
historical side effect. William explicitly selected continuation of the authorized rewind/replay
rather than a broader incident audit. This accidental run must be included in the process report
and measured wall time, not hidden as useful test coverage.

The first replayed gate (connectivity, dispatch `47ed2253-d097-4589-8869-81a608e0ee15`,
attempt 2) succeeded in 39,973 ms, with no gaps/audit findings. The new comparison guard refused
reacceptance because Copilot's advertised catalog gained one unrequested model, `gemini-4-carbon`
(21 to 22 listed models). There were no removals; every checked-model result and required pair
was identical. The refusal is preserved in `runs/c094-connectivity-inventory-drift-check.json`.

William approved narrowly accounting for unrelated advertised-model inventory changes while
retaining/reporting the exact difference and still refusing changes to configured/checked models,
their availability/results, transport/error state or other semantic fields. This is an explicit
comparison-policy refinement, not a producer failure or permission to mask arbitrary hashes.
The operator-only follow-up covers both connectivity and intake's identical preflight contract.
The existing successful attempt can then be rechecked; another model dispatch is not required
merely to repeat the comparison.

### Verified completion of the first repair cycle

The inventory-drift correction (`13a20cfe`, integrated unchanged as `46708d681`) passed 35
explicitly selected tests in 26.85 s, slowest 5.003 s; no nested test delegation or broad selector
was used. Connectivity's completed attempt was rechecked, not redispatched. The three remaining
predecessors then replayed and matched their preserved keys. A pin-gate begin refusal exposed
one operational requirement: each newly completed replay dispatch also needs its stopped-worker
receipt before the next replacement attempt. Verifying those workers through the existing command
resolved it without changing code or relaxing admission.

Catalog attempt 2 (`7ad4db0c-eb42-419a-87f6-55c610997d0f`) started at
`2026-11-10T17:32:48.202827-05:00`, completed in **87,877 ms**, and was accepted at
`2026-11-10T17:38:23.206258-05:00`. All **17 distinct Postman requests** now have source-hash-bound
locations; every byte span resolves to its actual request URL member and agrees with independent
collection order/methods. The environment export remains in the source inventory but has no
document/request records. No Postman parse/span gap remains.

The original catalog criterion holds: all 344 file hashes/sizes and five shard hashes resolve,
all eleven c094 files remain queryable, and its one native CMake build action retains all eight
sources. Total build actions remain 51. The remaining **69 unique named gaps** (80 occurrences,
down from 85/152) are explicit policy exclusions, pre-build missing compile databases, deferred
dependency parsers/delivery knowledge, unsupported materialized-OpenAPI extraction from TypeScript,
and conservative same-family source-ownership gaps. The five native sources under Node/PHP/Python/
Wasm units are retained alongside those build units; the discovery's same-family rule does not
establish that they cannot build. Their actual capture remains a later build-job obligation.
These gaps are not hidden or evidence that the target is clean. Audit findings remain zero.

**T-057 measurement 1:** first observed defect to catalog rerun = **248.25 minutes**; to verified
acceptance = **253.84 minutes**. This is one compound repair cycle, not several successes counted
from its internal tooling failures. It includes the **132.52-minute unauthorized broad test run**.
Exact timestamps, admission/plan references and outcomes are in
`runs/c094-catalog-cycle-metrics.json`; replay and acceptance logs use `runs/c094-replay-*.log`
and `runs/c094-target-catalog-{rerun,accept}.log`. Prior keys/provenance/seeds remain unchanged,
with immutable reacceptance receipts in the walk's `rewinds/` directory.
