# Job 10/47 audit — job_project_build

## Scope and result

- **Source:** `/home/wsollers/projects/appsec-review`, Ubuntu-22.04 on WSOLLERS1, SSH `wsl-ubuntu`, branch `main`, commit **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**. HEAD and Git cleanliness were verified before validation and after investigation; unchanged and clean. `.venv/bin/python` imported this checkout's `src/appsec_review/__init__.py`.
- **Authorization:** read-only functional audit of this job. No real image resolution/build, target compilation/execution, provider call, integration/acceptance/live suite, Dagster review, service operation, source edit, commit or push. Synthetic fixtures create only audit evidence under ignored `test/tmp/`. A synthetic one-task source producer used by an existing unit fixture is not a real review or compiler execution.
- **Activation:** registered, enabled by default, `review_graph`, checkout access, propagating handoff, `always_execute=False`. There are **six steps / 39 tasks**, all traced below.
- **Result:** **four medium findings reproduced**, with overlap explicitly distinguished: PB-F03 extends T-5039; PB-F04 extends the accepted-payload observation issue in the preceding planner audit. PB-F01/PB-F02 were not found in the inspected existing findings. One low documentation discrepancy. Historical package-removal/unreachable-repair behavior remains, but is not counted as a new discovery.
- **Focused tests:** **187 passed, 0 failed, 0 skipped, no case over 10 seconds**; pytest report 4.98 s, supervised wrapper total 10.873 s. Four additional safe reproductions completed in 2.12 s. Passing units do not certify real compiler products or live review quality.

All evidence paths below are repository-relative. `project job.py` means `src/appsec_review/jobs/job_project_build/job.py`.

## Intended contract and accepted inputs

The job admits recipes and project images, preserves the complete accepted executable graph and recipe-bound refinement, emits static/build dispatch descriptions, and owns the real captured execution of isolated native units plus configured Unity builds. Other families and product-connected native units are prepared for downstream iteration execution. Neither image preparation nor a dispatch record is compiler/scanner execution.

`src/appsec_review/jobs/job_project_build/datasets.py:42-90` declares 18 input requirements:

| Producer | Declared datasets | Actual use / limit |
| --- | --- | --- |
| `job_target_analysis_plan` | Required/reject `handoff`; optional/gap `planning_feedback_cache`, `analysis_plan`, `analysis_plan_documents` | `load_accepted_plan` reads the pinned handoff and accepted plan artifact; verifies raw identity, graph/source binding, current environment and whole-bundle graph/refinement derivation. Project planning and every shared refinement guard use it. It does not consume feedback-cache contents as planning authority. Payload observation is missing in that shared reader, already planner finding TA-F04. |
| `job_build_environment_analysis` | Optional/gap `handoff`, `build_environment`; operational authority | Indirectly read by `load_accepted_plan` when the plan records an environment contract. Expected-current versus optional-prior availability and identities are rechecked. |
| `job_target_catalog` | Optional/gap `handoff`, `target_artifact_inputs`, `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units`, `catalog_documents` | No direct catalog-data projection in these handlers. Accepted catalog-derived documents/facts are embedded in the plan; shared environment/input-manifest paths may need this ancestry. Declaration/supply is not evidence that each payload was read. |
| `job_review_intake` | Optional/gap `handoff`, `model_preflight`, `binary_evidence`, `review_intake` | No explicit intake/model-preflight/binary processing in the 39 handlers. Shared input-manifest/frozen configuration ancestry does not imply a new preflight. |

`runtime/consume.py:173-214` requires a declared envelope and exact supplied pin inside runtime scope, verifies handoff bytes and records envelope access. Project-build does not read another producer's mutable pointer directly. The shared reader's operator fallback outside a scope is not runtime authorization.

`job_target_analysis_plan/job.py:168-197` and `build_topology_artifacts.py:68-244` are the important intake/selection boundaries. Refinement publication retains complete inputs, original plan and graph, policy, releases and selected recipe; the source graph is not rewritten by choosing a recipe.

### Registration, configuration and dispatch

- `runtime/registry.py:146-147` registers `build_project_build(infer=infer)`. The supplied inference callback is **not called by any current handler**.
- `runtime/selection.py:11-24`: absence of a job-level `settings.enabled` means enabled. Nested model/Unity flags do not disable the job.
- `datasets.py` schedules after `job_target_analysis_plan`; `orchestration/topology.py:46-80` derives dependencies from schedule plus consumed producers and projects through disabled predecessors. The project-build composite in `orchestration/dagster/adapter.py:474-494` places it between planning and language-build.
- TOML `:1270-1381` declares native/rust/go/java/node/dotnet/python/php/wasm image profiles and all tasks. Android is an **image profile**, not a tenth family; Java Android actions route through `recipe.image_profile`.
- Shipped project settings: command timeout 1,800 s, image-build timeout 1,800 s, preview bound 8 MiB, artifact-count bound 10,000, retired force-probe false, repair attempts 3, Unity disabled. Capture overrides: 250,000 events, raw traces retained, 64 MiB raw-trace bound.
- `job.py:956-988` validates exact step/task order, all nine families plus Android profiles, repair/model setting shapes. `config/loader.py:1184-1199,1245-1250` parses build selection/Unity/capture and rejects force-probe true. Profiles require immutable image IDs and numeric non-root users (`container_runtime/build_executor.py:53-74,1042-1051`).
- Build-selection policy is typed and hash-bound: explicit OS/ISA rules, ambiguity blocking, default allowed 32-bit exemption `wasm32`. Native unavailable-capability checks preserve Visual C++/autotools/Make limitations rather than pretending a Linux placeholder compiled them.
- Native execution here retains the **project job's UnitContext/configuration** when calling the language implementation. Therefore project timeout/output/count/capture settings govern that execution; see PB-D01.

## Every declared step/task

Handlers are constructed at `job.py:1179-1549`; unit wiring is `:1533-1542`. Each task has its own central configuration entry. Family loops are deterministic in `BUILD_FAMILIES` order.

| Task | Actual implementation / dependency | Processing, output and coverage limit |
| --- | --- | --- |
| `plan.load_recipes` | `plan`, `:1181-1261`; no unit dependency | Load accepted plan/graph; choose deterministic CMake, bounded direct JVM or phpize recipe, else accepted recipe; remove package suggestions into hints; honor selected promoted recipe; bind immutable refinement; evaluate build-capture and source-only decisions; return actions, complete graph, selections, decisions and gaps. PB-F01/PB-F02. |
| `image.native` | `image_handler`, `:1263-1365`; plan | Capability/recipe/refinement/image guard, native profile, resolver and repair-cache revalidation; image preparation only. |
| `image.rust` | Same handler; plan | Rust profile, Cargo dependency-image preparation when requested; no compiler receipt here. |
| `image.go` | Same handler; plan | Go profile and module dependency preparation; no Go execution receipt here. |
| `image.java` | Same handler; plan | Java or Android selected profile; Maven/Gradle restore preparation when requested. Not bytecode compilation proof. |
| `image.node` | Same handler; plan | Node profile, accepted lockfile/package-manager restore, dependency-root/workspace layout. Not a JS/TS build receipt. |
| `image.dotnet` | Same handler; plan | Generic .NET profile; skips Unity, which has its own engine capability path. |
| `image.python` | Same handler; plan | Python profile and bounded declared requirements restores. |
| `image.php` | Same handler; plan | PHP profile; Composer dependency preparation or phpize base preparation. |
| `image.wasm` | Same handler; plan | Selected Wasm profile and image preparation, not module execution. |
| `static_dispatch.global` | `static_handler`, `:1367-1396`; plan | Retains scanner paths outside every planned action root; publishes `global_jobflow_static` descriptions. No scanner called. |
| `static_dispatch.native` | Same handler; plan | Per-native-action applicable scanner scopes under its root; `lang_jobflow_static`. |
| `static_dispatch.rust` | Same handler; plan | Per-Rust-action scope description. |
| `static_dispatch.go` | Same handler; plan | Per-Go-action scope description. |
| `static_dispatch.java` | Same handler; plan | Per-Java-action scope description. |
| `static_dispatch.node` | Same handler; plan | Per-Node-action scope description. |
| `static_dispatch.dotnet` | Same handler; plan | Per-.NET/Unity-action scope description; independent of engine/build success. |
| `static_dispatch.python` | Same handler; plan | Per-Python-action scope description. |
| `static_dispatch.php` | Same handler; plan | Per-PHP-action scope description. |
| `static_dispatch.wasm` | Same handler; plan | Per-Wasm-action scope description. |
| `probe.native` | `probe_handler`, `:1398-1446`; image.native | Skip graph-edge-connected units for iteration owner. Failed preparation yields empty blocked receipt. Isolated successful preparation calls real language `_execute_one` with accepted-plan handoff pin; captured result retained once. Unexpected OSError/ValueError/RuntimeError writes failure diagnostic and raises `ProjectBuildFailed`. |
| `probe.rust` | Same handler; image.rust | Intentionally no production probe; empty receipts, `NOT_APPLICABLE`. |
| `probe.go` | Same handler; image.go | Intentionally no production probe; empty receipts, `NOT_APPLICABLE`. |
| `probe.java` | Same handler; image.java | Intentionally no production probe; empty receipts, `NOT_APPLICABLE`. |
| `probe.node` | Same handler; image.node | Intentionally no production probe; empty receipts, `NOT_APPLICABLE`. |
| `probe.dotnet` | Same handler, `:1431-1442`; image.dotnet | Only Unity actions call `execute_unity_build`; generic SDK actions have no probe here. Disabled Unity returns not-requested receipt with explicit gap. |
| `probe.python` | Same handler; image.python | Intentionally no production probe; empty receipts, `NOT_APPLICABLE`. |
| `probe.php` | Same handler; image.php | Intentionally no production probe; empty receipts, `NOT_APPLICABLE`. |
| `probe.wasm` | Same handler; image.wasm | Intentionally no production probe; empty receipts, `NOT_APPLICABLE`. |
| `build_dispatch.native` | `build_dispatch_handler`, `:1448-1481`; image.native + probe.native | Successful image preparation creates exact recipe/image/preparation dispatch. Existing native receipt adds `execution_owner=job_project_build`, receipt digest and enforcement; connected units remain downstream-owned. Failed preparation becomes gap, not dispatch. |
| `build_dispatch.rust` | Same handler; image.rust + probe.rust | Prepared dispatch for downstream language/iteration execution; no successful compiler claim. |
| `build_dispatch.go` | Same handler; image.go + probe.go | Prepared dispatch for downstream execution. |
| `build_dispatch.java` | Same handler; image.java + probe.java | Prepared Java/Android dispatch for downstream JVM execution. |
| `build_dispatch.node` | Same handler; image.node + probe.node | Prepared dispatch for downstream Node execution. |
| `build_dispatch.dotnet` | Same handler; image.dotnet + probe.dotnet | Generic SDK dispatches only; Unity is represented by engine receipts, not replayed as SDK work. |
| `build_dispatch.python` | Same handler; image.python + probe.python | Prepared dispatch for downstream Python execution. |
| `build_dispatch.php` | Same handler; image.php + probe.php | Prepared dispatch for downstream Composer/phpize execution. |
| `build_dispatch.wasm` | Same handler; image.wasm + probe.wasm | Prepared dispatch for downstream configured Wasm producer. |
| `acceptance.publish_handoff` | `publish`, `:1483-1524`; all static/build-dispatch tasks | Gather images/probes/dispatches, finalize decisions only when actual receipt exists, aggregate scoped gaps and counts, write accepted dispatch JSON. PB-F02/PB-F03. Publication is followed by shared runtime validation, not a new compiler/scanner run. |

All handlers are wrapped by `typed` (`:1526-1531`), which converts text gaps through `scoped_gaps`; the Job sets `strict_gaps=True`.

### Actual execution and image processing

**Image preparation:** `container_runtime/project_images.py` was read in full. Recipe identity binds operational recipe except explanatory reason, dependency-file hashes, pinned base image, generator identity and platform/build-toolchain releases. The resolver checks the live base tag ID even for a noncustomized base-image result. Customized images additionally verify base signing policy, use a run/builder namespace, re-resolve cached tags and require a retained definition file; broker mode also verifies the preparation receipt. Otherwise it calls the admitted bounded builder. The cache branch checks the definition's existence, not a recomputed Dockerfile digest; exact retained-definition byte validation was not established here. Dependency copies, generated Dockerfile and image manifest are retained. Timeout/nonzero exit raises `ProjectImageBuildError`; expected builder unavailability becomes blocked at the handler. No such external operation was executed in this audit.

Family restores are explicit code: Cargo fetch, Go module download, Maven offline dependency preparation, Gradle dependencies, NuGet restore, lock-aware npm/pnpm/Yarn restore, Composer install, and accepted Python requirements installation. `network_required` selects this image customization; it is not a generic configure/build egress switch. A native `network_required` recipe has separate admission constraints.

**Native execution:** `job_language_build/job.py:1089-1669`, specifically its native branch, retains output under `data/build/probes/units/<unit>/attempts/<attempt>/`. It:

1. Revalidates selected action/refinement and plan pin; disables the language executor's private cache because project-job receipt reuse owns this execution.
2. Copies unit-root source and declared parent dependencies, prepares build directory/CMake File API query, snapshots files, constructs the pinned native executor with network none.
3. Uses the shared recipe/cwd adapter for each configure/build argv; `:839-904` requires captured execution and verifies record path, scope, hashes, collector events and secret-scan identities.
4. Retains complete command/log/protected-command/capture references, reconciles captured compiler/link activity with declaration metadata, catalogs changed/eligible existing artifacts and marks their origin, records exclusions/dependency classifications and truncation gaps.
5. Validates required outputs; failed build commands/output requirements suppress accepted artifacts. Retains workspace manifest, compile/link records, native components and `build_outcome`.
6. Measures image compiler profiles; `job_project_build/enforcement.py` derives one captured native proof with driver identity, axes, translation units and byte-checked native products. Unknown/mixed/cross-target evidence remains a named gap; unproven outputs move to `rejected_artifacts`. `build_outcome` remains separate from receipt cleanliness.

The acceptance unit test mocks `_execute_one`, so the 187 passes do not independently prove this entire sequence. Enforcement/helper tests exercise real local parsing and proof decisions using synthetic bytes/events.

**Unity:** `jobs/unity_build.py` was read fully. It validates dotnet/unity identity, exact configured editor/version/revision/module/backend/architecture and license-readiness declarations; copies into a disjoint run workspace; injects a bounded reviewed bridge; checks actual editor/preflight response, invokes one BuildPlayer operation, validates output structure and hashes, and records cancellation/failure/manifest gaps. It deliberately reports unsupported compiler/linker capture even after a successful engine build. Default `enabled=false` is an explicit gap, not a fabricated build.

**Retained but uncalled helpers:** `_probe_one`, `_probe_with_repairs`, `_infer_repair` and their diagnostic/cache helpers remain callable and heavily unit-tested, but are not dispatched by `build_job`. The declared Haiku/Claude CLI model, DevOps persona, nine family roles, `build_image_repair` generated task sentence, registered runtime procedure and response schema therefore describe no current production inference call. Guidance was read only as data. Typed repair is schema `/3`, bounded package/environment/manager/manifest choices, with runtime family restrictions stricter than its general JSON Schema.

## Output publication, schemas and downstream use

| Dataset | Actual writer/payload | Contract match / limit |
| --- | --- | --- |
| `topology_refinement_inputs` | `build_topology_artifacts._retain` writes immutable plan/graph/action/refinement/acceptance JSON below `artifacts/build/topology/**`, plus accepted index under `data/build/topology/**` | Protected, both roots covered. Complete derivation is rechecked; not a target-facing retrieval payload. |
| `project_build_dispatch` | `job.py:80-84,1506-1516`, attempt `artifacts/project-build/accepted-project-build-dispatch.json`, schema `/3` | Sensitive artifact-only, declared glob covers actual output. Includes nested image preparations and language-build receipts, not just one homogeneous record kind. |
| `probe_workspaces` | Native executor and Unity under `data/build/probes/**` | Protected glob covers both actual layouts, including captures, compiler-profile scratch, commands, manifests and outputs. |
| `image_build_streams` | Per-image task/build-unit stdout/stderr; retained helper repair diagnostics below image/probe task descendants | Protected declared task globs cover these paths. Active resolver streams are bounded previews; full command-stream retention is a separate captured-build behavior. |

There is no indexed dataset owned by project-build. Protected/artifact-only retrieval routes provide metadata, not direct raw argv/source/log access.

The Job has `_validate_config` as an input validator and **no bespoke output validator** (`job.py:1545-1549`). Shared unit/publication validation checks closed status/disposition/gap records and accepted artifact/configuration/outcome identities (`interchange.py:521-570`, `runtime/runner.py:1014-1063`, `runtime/handoff.py`). It does not deeply validate every payload key merely because the outer job has schema identity `/3`. `load_accepted_builds` checks the dispatch schema identifier and native receipt enforcement, while the downstream execution reader adds detailed preparation/recipe/graph checks. Enforcement itself has explicit JSON Schema and content-identity validation.

`load_accepted_builds` (`job.py:925-953`) resolves the pinned project-build handoff and dispatch artifact, verifies its hash and schema, validates one enforcement proof per commanded native receipt, and optionally guards each execution dispatch. PB-F04 concerns its missing payload observation, not bypassed byte hashing.

`job_language_build/job.py:175-262` verifies target/source identity, unique build units, immutable successful image preparation, recipe/dependency identity, owner receipt digest/enforcement and retained artifacts. Its iteration controller (`:1841-1904`) forwards native project-owned receipts instead of recompiling; other prepared units enter the shared-workspace iteration owner. Unity receipts are forwarded by the .NET load/execute path (`:2005-2007,2016-2018`).

Artifact-indexing, C++ analysis, CodeQL and artifact-security paths consume the resulting language-build receipts/index, not a second independent project-build compiler result. Review-data-indexing also reads accepted project-build capture-event artifact references for build provenance (`indexing/build_facts.py:197-211`, `job_review_data_indexing/job.py:439-445`).

**Static dispatch limit:** repository-wide source search found `static_dispatches` constructed/published only here, with no runtime scanner consumer. These are descriptive records/counts; actual scanners use their own accepted-plan paths. The current operations page accurately calls them descriptions, not executed scans. Root containment may put the same path into more than one overlapping action's description; this is not evidence of duplicate scanner execution.

## Findings

### PB-F01 — Medium: CMake canonicalization changes the build directory but keeps old output requirements

- **Evidence:** `src/appsec_review/jobs/job_project_build/job.py:1040-1067,1194-1198`; native expected-output consumption at `src/appsec_review/jobs/job_language_build/job.py:1560-1564`.
- **Trigger:** a valid accepted CMake recipe uses `build_dir=out`, `cmake -S . -B out`, `cmake --build out --target control`, and requires `out/control`.
- **Expected:** keep a coherent admitted command/layout/output contract. Canonicalization must not leave output requirements referring to the replaced build layout.
- **Actual:** eligibility accepts this valid CMake-only recipe; replacement hardcodes `build/` and Ninja/RelWithDebInfo, but copies the original `expected_outputs` unchanged. It also discards selected configure flags, target selection, environment and extra dependency files. The real plan handler prefers this replacement.
- **Reproduction:** real `validate_build_recipe` returned no errors; real `_deterministic_native_recipe` returned commands using `build/`, expected `out/control`, and empty environment. No CMake command ran.
- **Impact:** an ordinary valid nondefault CMake layout becomes an internally inconsistent build; a successful compile in the replacement directory is subsequently failed for missing outputs. Discarded feature/target options can also change what is built.
- **Confidence:** high for transformation and downstream mismatch; real compiler execution intentionally not attempted.
- **Smallest correction:** restrict deterministic fallback to absent recipes or demonstrably equivalent defaults; otherwise preserve accepted layout/options. If intentionally changing a layout, reconcile all command/output/cwd/dependency fields and republish the refinement together.
- **Overlap:** T-037 covers canonical/inferred recipe provenance generally, but the inspected entry does not describe this inconsistent directory/output transform. Distinct from historical C06-F04's package stripping.

### PB-F02 — Medium: native planning records make valid project-job checkpoints and whole-job reuse fail admission

- **Evidence:** `src/appsec_review/jobs/job_project_build/job.py:1258-1261,1508-1509`; `src/appsec_review/jobs/build_topology_artifacts.py:219-225,357-386`; callers `src/appsec_review/runtime/runner.py:597-604,622-632` and `runtime/resume.py:145-157`.
- **Trigger:** a completed project-build result contains at least one native action in `plan.load_recipes.actions` / accepted document `execution_actions`. These pre-image action records legitimately have a recipe/refinement but no image.
- **Expected:** verify planning records as planning identity, and executable records with their admitted image/receipt; unchanged valid native results should be reusable according to the Job contract.
- **Actual:** the generic recursive cache guard treats every nested mapping with a recipe/build-unit ID as an executable action. `guard_action` then demands a prospective/recorded immutable image for the image-free planning action and raises `native admission requires a bound prospective or recorded immutable image`.
- **Reproduction:** existing `accepted_native` unit fixture created a real hash-bound synthetic plan/refinement. `guard_action` and dispatch-only `guard_build_cache` passed. Adding its actual image-free planning shape caused both a plan-output and accepted-document-shaped cache check to fail. No executor or daemon was involved.
- **Impact:** native plan task checkpoints miss unnecessarily; whole project-job reuse is rejected despite unchanged inputs and valid executable dispatches, forcing repeated preparation/execution. This is false rejection, not stale-result acceptance.
- **Confidence:** high. Existing cache tests use dispatch-only synthetic output and therefore do not cover the production aggregate shape.
- **Smallest correction:** make cache validation aware of planning versus preparation/execution records, preserving source/refinement/policy validation for planning without requiring a nonexistent image. Add a production-shaped aggregate reuse unit case.
- **Overlap:** T-082 is a different missing-release/repair-guard-order question. No matching aggregate-cache defect found in inspected TODO/prior reports.

### PB-F03 — Medium: provenance-only native gaps become a synthetic processing-failure gap at acceptance

- **Evidence:** `src/appsec_review/jobs/job_project_build/job.py:1495-1505`; `src/appsec_review/applicability.py:521-537`; real receipt distinction at `src/appsec_review/jobs/job_language_build/job.py:1597-1600,1672-1687`; contract `src/appsec_review/jobs/build_outcome.py:1-25`.
- **Trigger:** native receipt has `build_outcome=built`, `terminal_status=COMPLETED_WITH_GAPS`, and only `provenance_unavailable`, such as unknown captured compiler provenance.
- **Expected:** preserve built-versus-failed distinction and classify incomplete capture evidence accurately. Do not restore rejected artifacts or pretend the capture is complete.
- **Actual:** acceptance equates successful processing with `terminal_status == SUCCEEDED`. It passes `succeeded=False` and `evidence_complete=False`; `finalize_processing` gives the former precedence, returns `PROCESSING_FAILED`, and acceptance adds a new `producer_reported_gap` alongside the actual provenance gap.
- **Reproduction:** real acceptance handler with a typed, built/provenance-only receipt wrote both `unknown_compiler_in_capture/provenance_unavailable` and `<unit>: PROCESSING_FAILED/producer_reported_gap`.
- **Impact:** canonical gap cause/counts imply a build-processing failure where the original receipt reports completed build and incomplete evidence. It makes recovery/expected-gap decisions less accurate; it does not change the original `build_outcome` or admit rejected artifacts.
- **Confidence:** high.
- **Smallest correction:** distinguish command/product outcome from capture completeness when supplying `finalize_processing` arguments; retain the actual provenance reason and rejected-artifact boundary.
- **Overlap:** **T-5039**, explicitly open, owns remaining build-outcome consumers. This acceptance consumer is another reproduced instance; consolidate rather than create duplicate backlog. T-5040/T-5044 are related reporting/provenance work, not fixes for this aggregation.

### PB-F04 — Medium: the accepted-build reader never records consumption of the dispatch dataset

- **Evidence:** `src/appsec_review/jobs/job_project_build/job.py:925-953`; `src/appsec_review/runtime/consume.py:173-202`; `src/appsec_review/runtime/inputs.py:453-470,528-551`; downstream `src/appsec_review/jobs/job_language_build/job.py:184`.
- **Trigger:** language-build calls `load_accepted_builds` inside a normal typed, pinned input-read scope.
- **Expected:** record both envelope access and actual `project_build_dispatch` payload consumption with its accepted artifact identity.
- **Actual:** reader obtains/observes the envelope and reads/verifies JSON directly; no `observe_output` call identifies the payload dataset.
- **Reproduction:** synthetic hash-bound project-build handoff plus the real language-build contract and `input_read_scope`; the returned artifact digest matched, but observations contained only `handoff`, not `project_build_dispatch`.
- **Impact:** dispatch dataset is supplied-but-unread in consumption telemetry even though execution reads it; payload-level authority/schema observation is not exercised. Hash validation still protects bytes.
- **Confidence:** high.
- **Smallest correction:** observe the declared output after obtaining its pinned reference, then assert both observations using the real reader.
- **Overlap:** **planner audit TA-F04** already identified the same missing-observation pattern in `load_accepted_plan`; this is its independently reproduced project-build sibling. Consolidate in cumulative tracking. T-113/T-147 are related framework/declaration work, not a recorded fix for this reader.

### PB-D01 — Low documentation discrepancy: project settings are described as legacy-only despite active native use

- **Evidence:** `docs/operations/project-build.md:136,139` says production commands use language-build settings and describes the project artifact-count limit as a retained-helper bound.
- **Actual:** `job.py:1420-1423` passes the project UnitContext directly to `_execute_one`; `job_language_build/job.py:1216-1222,1417-1420` reads its timeout/output/artifact settings. Isolated native execution therefore uses project settings; downstream-owned units use language settings.
- **Correction:** describe the execution-owner distinction. No configuration change is required. No exact documentation TODO found; T-147 is broader binding documentation work.

## Existing behavior and non-new issues

1. **Historical C06-F04 remains visible:** `plan` strips `system_packages` into `package_hints`, and the model-repair loop is unreachable from production handlers. Current operations documentation now admits the unreachable loop. This audit did not reclassify package hints as installation authority or add another new high finding. Any change needs the existing bounded-image/recovery policy, not automatic package installation inferred by this auditor.
2. **T-039/T-040:** isolated native materialization is unit-root plus declared dependencies; component-root/sibling-source completeness and per-component dispatch remain documented work. No real sibling-source compile was run.
3. **T-5044:** CMake/compiler-identification provenance can reject outputs. Existing enforcement remains fail-closed; this audit does not propose accepting unproven target artifacts.
4. **T-082:** `_reuse_accepted_repair` currently supplies `profile.image_id` to the early guard. The existing hypothetical missing-profile/no-release scenario was not rerun and is not asserted as a newly confirmed defect.
5. **Retained helper mismatch, not active failure:** `_probe_with_repairs` catches broad exceptions (`job.py:882-923`), while `apply_repair` raises `RepairStopped` for non-image/no-op outcomes. The helper does not specially stop on that subclass, despite runtime-procedure prose saying it stops immediately. No current task calls the helper; this was not counted as an active finding or exercised with a real model.
6. **No exact live output assertion:** unsupported tracing/toolchains, unavailable builders, Unity capture limits and absent optional inputs remain named coverage gaps, never proof that the target is clean.

## Focused validation

All commands ran via the shared brief's PowerShell base64 transport into plain Bash through:

```powershell
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Common Linux setup:

```bash
set -euo pipefail
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
mkdir -p test/tmp/job-audit-job_project_build-20261118/runtime
export TMPDIR="$PWD/test/tmp/job-audit-job_project_build-20261118/runtime"
export TMP="$TMPDIR" TEMP="$TMPDIR"
```

Before testing, environment-selector discovery reported no inherited `APPSEC_*`, `DAGSTER_*` or `PYTEST_*` variables. The test harness supplies synthetic host pins and its production-environment preflight. No host binding was edited.

### Collection and tests

```bash
/usr/bin/time -f 'collection_elapsed=%e seconds' \
  .venv/bin/python -m pytest --collect-only -q -o addopts='' \
  --basetemp=test/tmp/job-audit-job_project_build-20261118/collection \
  tests/unit/job_project_build \
  > test/tmp/job-audit-job_project_build-20261118/collection.log
```

Result: **187 collected**, pytest collection 0.60 s, process wall 1.57 s, exit 0. All eight mapped unit files were read before execution. They use synthetic files/profiles/events and fake executors/resolvers/inference; no real external boundary was invoked.

Initial wrapper attempt:

```bash
scripts/run-tests.sh --expect-tests 187 --parallel --test-workers 4 \
  --shuffle-seed 111810 -- tests/unit/job_project_build
```

Result: **refused before collection/execution**, exit 2: `selector must name an existing, unredirected test file under tests/`. Directory selectors are not allowed by this wrapper. Elapsed was not separately measured; no tests ran. Corrected without changing scope/bounds:

```bash
scripts/run-tests.sh --expect-tests 187 --parallel --test-workers 4 \
  --shuffle-seed 111810 -- \
  tests/unit/job_project_build/test_job_graph.py \
  tests/unit/job_project_build/test_contract.py \
  tests/unit/job_project_build/test_project_build_helpers.py \
  tests/unit/job_project_build/test_family_recipe_helpers.py \
  tests/unit/job_project_build/test_repair.py \
  tests/unit/job_project_build/test_enforcement.py \
  tests/unit/job_project_build/test_build_recovery.py \
  tests/unit/job_project_build/test_handlers.py
```

Result: **187 passed**, failures/errors/skips 0, slow cases 0, exit 0. Fixed report `elapsed_s=4.98`; wrapper collection 1.799 s, execution/supervision 8.755 s, total 10.873 s. Cleanup confirmed no remaining owned processes. No integration/acceptance/live selector was admitted.

Persisted evidence, under the authorized checkout:

- `test/tmp/reports/tests-custom-20261118-113225-945264-2500303.json`
- `test/tmp/logs/tests-custom-20261118-113225-945264-2500303.log`
- `test/tmp/logs/tests-custom-20261118-113225-945264-2500303.collection.log`
- `test/tmp/tests-custom-20261118-113225-945264-2500303.collection.json`
- `test/tmp/tests-custom-20261118-113225-945264-2500303.junit.xml`
- `test/tmp/tests-custom-20261118-113225-945264-2500303.timings.sqlite`

The wrapper owns its unique `tests-custom-*` base-temp name and refuses overriding it. Manual collection/reproductions use the job-labelled descendant. Both stay under repository `test/tmp/`.

### Reproduction attempts and results

| Attempt | Result | Time |
| --- | --- | --- |
| First inline four-case script | PB-F01 verified. Existing `accepted_native` fixture then refused absent synthetic host pins in its scratch config root; cases 2–4 did not complete. Python exit 1, initially masked by `tee` because that first script used `set -eu`, not pipefail. Never counted as pass. | 0.88 s |
| Second inline script, explicitly bound unit fixture host pins | PB-F02 positive and negative controls verified. PB-F03 handler produced its artifact, then the auditor's assertion used lowercase `processing_failed` instead of actual enum `PROCESSING_FAILED`; script stopped, PB-F04 not run. Python/shell exit 1. | 1.97 s |
| Third inline script, corrected enum assertion | PB-F03 and PB-F04 verified; exit 0. | 1.57 s |
| Final consolidated script below | All four conditions and PB-F02 positive control verified; exit 0. No images/compilers/providers invoked. | **2.12 s** |

Logs: `test/tmp/job-audit-job_project_build-20261118/reproductions.log`, `reproductions-2.log`, `reproductions-3.log`, `reproductions-final.log`. Final individual body timings: PB-F01 0.001 s; PB-F02 1.045 s; PB-F03 0.007 s; PB-F04 0.118 s.

The fixture setup failure is audit-harness setup, not a source defect; the lowercase assertion is auditor error, not an application failure. Only the successful final script supports the four reported reproductions.

Final executed command (use a new scratch basename if rerunning, because it intentionally refuses an existing directory):

```bash
/usr/bin/time -f 'reproduction_elapsed=%e seconds' .venv/bin/python - <<'PY' \
  | tee test/tmp/job-audit-job_project_build-20261118/reproductions-final.log
import json, os, time
from pathlib import Path
from types import SimpleNamespace
from appsec_review.config.host_pins import HOST_PINS_ENV
from appsec_review.jobs.job_project_build import job as project
from appsec_review.jobs.build_discovery import validate_build_recipe
from appsec_review.jobs.build_topology_artifacts import guard_action, guard_build_cache
from appsec_review.applicability import evaluate_applicability, facts_from_build_unit, ProcessingFeature
from appsec_review.interchange import producer_gap
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.jobs.job_language_build.datasets import CONTRACT as LANGUAGE_CONTRACT
from tests.test_native_target_enforcement import _native
from tests.test_build_topology_refinement import accepted_native
from tests.unit.job_project_build.test_job_graph import _publish_context
from tests.handoff_fixture import write_fixture_handoff
os.umask(0o022)
os.environ[HOST_PINS_ENV]=str(Path('test/tmp/tests-custom-20261118-113225-945264-2500303.host-pins.toml').resolve())
base=Path('test/tmp/job-audit-job_project_build-20261118/repro-final').resolve()
base.mkdir(parents=True)
start=time.monotonic()
action=_native(); target=base/'recipe-target'; target.mkdir()
for doc in action['descriptor_package']['documents']:
    (target/doc['path']).write_text(doc['content'])
action['recipe'].update(build_dir='out',environment={'BUILD_FLAVOR':'selected'},
    configure_commands=[['cmake','-S','.','-B','out','-DBUILD_SHARED_LIBS=ON']],
    build_commands=[['cmake','--build','out','--target','control']],expected_outputs=['out/control'])
assert validate_build_recipe(action['recipe'],action)==[]
replacement=project._deterministic_native_recipe(SimpleNamespace(job=SimpleNamespace(target_root=target)),action)
assert replacement['build_dir']=='build' and replacement['expected_outputs']==['out/control']
assert replacement['environment']=={}
print('PB-F01: valid out/control recipe becomes build/ commands, still expects out/control; elapsed',round(time.monotonic()-start,3))
start=time.monotonic(); (base/'resume').mkdir()
runner,run,graph,bound=accepted_native(base/'resume')
releases=runner.config.review_policy.releases.view()
guard_action(run,bound,releases=releases)
guard_build_cache(run,'job_project_build',{'build_dispatches':[bound]},releases=releases)
planned={k:v for k,v in bound.items() if k!='image'}
for label,output in [('plan',{'actions':[planned]}),('accepted',{'execution_actions':[planned],'build_dispatches':[bound]})]:
    try: guard_build_cache(run,'job_project_build',output,releases=releases)
    except ValueError as exc:
        assert 'bound prospective or recorded immutable image' in str(exc)
        print('PB-F02:',label,str(exc))
    else: raise AssertionError('expected image-free plan-action rejection')
print('PB-F02: dispatch-only positive control passed; elapsed',round(time.monotonic()-start,3))
start=time.monotonic(); action=_native()
action['build_unit_id']='build-unit-'+'a'*20; action['recipe']['build_unit_id']=action['build_unit_id']
decision=evaluate_applicability(feature=ProcessingFeature.BUILD_CAPTURE,policy='required',
    facts=facts_from_build_unit(action),configuration_sha256='a'*64)
receipt={'build_unit_id':decision.project_id,'family':'native','terminal_status':'COMPLETED_WITH_GAPS',
    'build_outcome':'built','artifacts':[],'commands':[{'ordinal':1,'exit_code':0}],
    'gaps':[producer_gap('provenance_unavailable','unknown_compiler_in_capture',scope_id=decision.project_id)]}
ctx=_publish_context(base/'status',probe_receipts=[receipt],decisions=[decision.as_dict()])
ctx.outputs['probe.native']['gaps']=receipt['gaps']
published={u.unit_id:u for u in project.build_job().units}['acceptance.publish_handoff'].handler(ctx)
assert published['processing_decisions'][0]['reason_code']=='PROCESSING_FAILED'
assert any(g['code']=='producer_reported_gap' for g in published['gaps'])
print('PB-F03: built/provenance-only receipt adds PROCESSING_FAILED/producer_reported_gap; elapsed',round(time.monotonic()-start,3))
start=time.monotonic(); run=base/'reads'
attempt=run/'data/jobs/job_project_build/attempts/attempt_0001'
artifact=attempt/'artifacts/project-build/accepted-project-build-dispatch.json'
atomic_json(artifact,{'schema':project.SCHEMA,'source_fingerprint':'f'*40,
    'execution_graph':{'edges':[]},'probe_receipts':[],'build_dispatches':[]})
ref={'path':artifact.relative_to(run).as_posix(),'sha256':file_sha256(artifact),'size_bytes':artifact.stat().st_size}
handoff=attempt/'handoff.json'
write_fixture_handoff(run,handoff,{'job_id':'job_project_build','attempt_id':'attempt_0001',
    'source_fingerprint':'f'*40,'outputs':{'acceptance.publish_handoff':{
    'terminal_status':'SUCCEEDED','artifact':ref,'gaps':[]}}})
sha=file_sha256(handoff)
atomic_json(run/'data/jobs/job_project_build/latest.json',{'attempt_id':'attempt_0001',
    'handoff_path':handoff.relative_to(run).as_posix(),'handoff_sha256':sha})
ctx=SimpleNamespace(run_root=run,config=SimpleNamespace(job_id='job_language_build'),
    contract=LANGUAGE_CONTRACT,upstream_handoffs={'job_project_build':sha})
with input_read_scope(ctx) as reads:
    loaded=project.load_accepted_builds(run); observed=reads.document()['reads']
assert loaded['project_build_artifact_sha256']==ref['sha256']
assert [r['output_kind'] for r in observed]==['handoff']
print('PB-F04: accepted dispatch loaded, observed datasets:',[r['output_kind'] for r in observed],'; elapsed',round(time.monotonic()-start,3))
print('4 reproduced conditions, 0 real images/compilers/providers invoked')
PY
```

Other read-only tool limitations: Linux `rg` was absent, so searches used the UNC-aware `rg` tool; UNC `glob` returned no matches and was replaced by direct directory reads/SSH listing. A guessed test-log path and nonexistent `runtime/schemas.py` read failed; the actual persisted report/log and control-validation implementation were subsequently located. None was a test pass or a source change.

## Coverage and handoff limits

**Read fully:**

- Shared audit brief; authorized `AGENTS.md`; canonical multi-session skill.
- `jobs/job_project_build/job.py`, `datasets.py`, `enforcement.py`, `repair.py`.
- `container_runtime/project_images.py`; `jobs/build_topology_artifacts.py`; `jobs/unity_build.py`; `jobs/build_outcome.py`.
- All eight mapped `tests/unit/job_project_build/*.py` test files.
- `runtime/consume.py`; runtime selection helper.
- Existing synthetic fixture helpers in `tests/accepted_topology_fixture.py`, `tests/handoff_fixture.py`; relevant exact fixture definitions in native-target/runtime/topology-refinement tests.
- Canonical `docs/operations/job_project_build.md`; all nine family role files, DevOps persona, build-image-repair procedure and repair JSON Schema.

**Read relevant ranges/searches, not claimed fully:**

- Language-build intake/controller/publication and native `_execute_one` path, source copy/catalog, capture/read/checkpoint/enforcement boundaries; deeper native reconciliation/ELF/product parsers were followed only at their call boundaries and through enforcement unit fixtures.
- Build-discovery recipe validation/capability checks, topology/variant/selection/refinement interfaces, applicability evaluation/finalization, accepted-plan/environment reader.
- Project TOML block, typed loader/profile settings, registry, topology/Dagster placement, shared input observation, runner cache/publication, handoff/control validation and dataset declarations.
- Build/capture/topology architecture and project-build operations pages, worker bundling/registry records, exact job-test map, conftest/environment guard, test-wrapper options/command/report code.
- TODO T-036–T-040, T-082, T-113 references, T-147, T-5039/T-5040/T-5044; historical C06 findings, preceding individual audit reports by relevant searches and planner findings. Local branches/history were inspected without modifying/fetching them.

**Material unread/unexecuted scope:**

- No actual target tree, answer key, production run output, installed image, provider readiness, deployed service or live accepted publication at this revision was inspected.
- No end-to-end real project-build acceptance, real native/Unity capture, compiler-profile acquisition, image customization/cache recovery, connected-component iteration, or downstream indexing/scanning was executed.
- Full build-container broker/tracer, signing/admission internals, all compiler-specific reconciliation and archive formats, every downstream job, and complete schema/architecture history were not audited as separate systems.
- Job-folder units exercise substantial uncalled legacy helpers; active handler tests fake admission, graph construction and `_execute_one`. Their green result is not full production-seam coverage. Historical integration results in documentation were not inherited as this audit's evidence.
- This report is the only authored session deliverable. Source/TODO files were not changed. Unique ignored test logs, manifests and synthetic reproduction artifacts remain as audit evidence; no services/background processes were left running.

Stop after this job; coordinator owns cumulative attribution and deduplication.
