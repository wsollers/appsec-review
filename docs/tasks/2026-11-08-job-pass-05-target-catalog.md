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
