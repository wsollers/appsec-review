# Job 11/47 audit — `job_language_build`

## Result and authority

- **Revision:** `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`, branch `main`.
- **Source:** `/home/wsollers/projects/appsec-review`, Ubuntu-22.04, accessed through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu` and the brief's UNC path. The Windows `F:` checkout was not audited or tested.
- HEAD and tracked/untracked Git cleanliness were verified before work, before test execution, and at completion. The editable import resolved to `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.
- Read-only functional audit: no repository edits, commits, pushes, real builds, compiler/tool/provider executions, container/service operations, integration/acceptance/live tests, or Dagster executions.
- **Findings:** six medium findings demonstrated with real Python functions and synthetic inputs/fake external boundaries; one low, statically verified ignored-bound finding. The Rust reproduction verifies the erroneous generated argv, not an actual Cargo failure. The stale JVM shard finding is currently masked from ordinary retrieval by the separate missing-composition finding.
- **Focused validation:** **98 passed**, zero failed/skipped, zero cases over ten seconds. Two shuffled, two-worker runs: 77 in 6.82 s and 21 in 2.92 s, as reported by pytest. A corrected six-case reproduction took 1.054 s. One earlier reproduction script had an auditor-owned `KeyError`, recorded below.
- These results **do not certify every language/toolchain combination or live output correctness**. Every declared task is traced below; material unread and unexecuted matrix scope is explicit.

## Registration, intended behavior, and accepted inputs

`runtime/registry.py:148` registers `build_language_build`; `job.py:2155-2180` constructs twenty units. The dev recipe enables the job. Its contract is `REVIEW_GRAPH`, checkout access, `always_execute=False`, and `propagate_handoff=True`; its explicit schedule predecessor is `job_project_build` (`datasets.py:44-104`). `orchestration/topology.py:46-80` derives enabled graph dependencies from schedule and consumed-producer declarations. The generated operations page's review-graph placement agrees with this source.

Intended behavior: execute each admitted, dependency-ready build once, or preserve its project-owned native/Unity receipt; bind exact source/recipe/image/product identities; retain capture and outputs; distinguish command success, capture completeness, product acceptance, delivery knowledge and policy skips; publish accepted receipts plus queryable build provenance.

All **23** declared input requirements are handoff-channel inputs:

| Producer | Declared datasets | Requirement and observed use |
|---|---|---|
| `job_project_build` | `handoff`; `topology_refinement_inputs`; `project_build_dispatch`; `probe_workspaces`; `image_build_streams` | Only its envelope is required/reject; other datasets optional/gap. `_dispatches` reads accepted builds with execution guards, validates source, unique unit IDs/workflow, immutable preparation, image/profile/recipe/dependency identities, and project-owned native receipt hashes/artifacts (`job.py:175-262`). |
| `job_build_environment_analysis` | `handoff`; `build_environment` | Optional/gap, **operational** authority. Indirect accepted-plan/refinement revalidation needs these declarations. Historical missing-contract defect was repaired before this revision; the historical task report is not a current live test. |
| `job_review_intake` | `handoff`; `model_preflight`; `binary_evidence`; `review_intake` | Optional/gap, producer-evidence authority. Available to transitive plan/target/admission readers, not all directly opened by this job's handlers. |
| `job_target_analysis_plan` | `handoff`; `planning_feedback_cache`; `analysis_plan`; `analysis_plan_documents` | Optional/gap. Execution guards/refinement and `.NET selected_project_topology` re-read accepted plan authority. Selected recipe promotions are rebound and cannot change the structural topology (`build_iterations.py:990-1051`). |
| `job_target_catalog` | `handoff`; `target_artifact_inputs`; `source_files`; `declaration_symbols`; `components`; `target_documents`; `build_units`; `catalog_documents` | Optional/gap. Catalog/descriptor and transitive plan authority; declaration/supply is not evidence that each dataset was read. |

Every non-environment requirement has producer-evidence authority. Envelope schema is `appsec-review/job-handoff/2`; domain schemas and exact fields were checked in `datasets.py` and the complete contract tests. Source content is separately fingerprinted against the accepted target.

**Read-observation limitation:** upstream `load_accepted_builds` lacks dispatch-dataset observation, already reported as **PB-F04**. This job's downstream reader repeats the same pattern: `load_accepted_language_build` calls `accepted_upstream`, then `_safe_artifact` directly (`job.py:127-173`); no payload `observe_output` call records `language_build_receipts`. `runtime/consume.py:173-202` only observes the envelope. This is a statically traced additional instance of the existing audit theme, not another independently reproduced/new finding in the six-case count. Byte hashing remains in place.

## Every declared step/task

All task declarations in `appsec-review.toml:1494-1533` have handlers. No task selects a model/persona/runtime prompt here. Missing formal tool/task binding metadata remains **T-147**, not proof that execution is absent. Actual builds are performed by `iterations.dispatch` through the internal transaction job, before the family `load`/`execute` tasks.

| Step/task | Actual implementation | Processing/output and audit limit |
|---|---|---|
| `iterations.dispatch` | `job.py:1910-1919`; controller `:1841-1904`; transaction `:1003-1086` | Rejects legacy mode; selects/rebinds revisions; derives applicability; preserves failed preparation and native-owned receipts; serial dependency/product-ready controller invokes registered `job_build_iteration`. The production callback routes Java, matched Wasm, or generic executor. Cleanup/product/recovery checks sampled in the shared controller. No real controller/Dagster run; **T-084/T-092** remain relevant. |
| `load.native` | Shared load closure `job.py:1921-2011` | Revalidates native dispatch authority, excludes Wasm-routed recipes, evaluates capture/artifact decisions, retains unavailable-unit gaps. Native execution may already have occurred in project build. |
| `load.go` | Same closure; `go.validate_dispatch`, `job.py:1960-1964` | Validates Go build-only policy and central typed settings. Declared module/workspace inputs, output-path/tool-substitution rules. Full Go parser/vendor matrix not read. |
| `load.dotnet` | Same closure, `:1937-1942,2004-2007` | Separates ordinary unavailable probes from Unity engine receipts; evaluates decisions. Platform topology is also checked in controller/generic executor. **LB-F05**. |
| `load.node` | Same closure | Excludes configured Wasm producers; decisions and upstream failures retained. Generic execution separately validates package identity and reachable lifecycle graph. Installer parser matrix unread. |
| `load.python` | Same closure | Family selection/decisions; actual package-only validation and metadata happen in generic executor. Frontend selection is an unresolved configuration-semantic observation below. |
| `load.rust` | Same closure; `rust.validate_dispatch`, `:1955-1959` | Cargo-only/build-only validation, lock/target/profile checks. Runtime command rewriting has **LB-F03**. |
| `load.php` | Same closure | Family selection/decisions; Composer/phpize validation and policy application are in generic execution. **LB-F06**. |
| `load.java` | Same closure | Selects Java family; JVM executor handles Java/Android profile, wrappers and tool instrumentation. JVM provenance publication has **LB-F01/F02**. |
| `load.wasm` | Same closure; `:1927-1936,1993-1997` | Rules use family + tool + indicator, not file suffix alone; unmatched `.wasm` intent is named as a load gap. This load result is later than controller execution; unmatched producer paths were not executed. |
| `execute.native` | Shared execute closure `job.py:2013-2120`, production branch `:2016-2030` | Takes native controller receipts, not a second build. Keeps delivery/capture gaps and typed `build_outcome`. Native rejection and downstream status issues overlap **T-5039/T-5044**. |
| `execute.go` | Same closure | Takes Go controller receipts. Empty lane `NOT_APPLICABLE`; existing receipt gaps produce `COMPLETED_WITH_GAPS`. Fake generic Go execution/target facts tested. |
| `execute.dotnet` | Same closure | Takes controller receipts and appends Unity receipts once. The topology-aware unavailable conversion at `:2039-2041` belongs to the retained non-iterative branch, not the admitted production path. |
| `execute.node` | Same closure | Takes controller receipts; fake dependency-refusal and bounded lifecycle selectors tested. No real npm/pnpm/yarn run. |
| `execute.python` | Same closure | Takes controller receipts; fake wheel production, content listing and checkpoint identity checks tested. |
| `execute.rust` | Same closure | Takes controller receipts; fake default Cargo metadata/compile path tested. Nondefault metadata argv defect separately reproduced. |
| `execute.php` | Same closure | Takes controller receipts; fake Composer autoload/metadata path tested. No real Composer/phpize. |
| `execute.java` | Same closure | Takes JVM receipts, including embedded `retrieval_index`; does not publish/compose that index itself. **LB-F01**. JVM policy/graph/fingerprint selectors tested, not real JVM compilation. |
| `execute.wasm` | Same closure | Takes receipts whose output family is `wasm`. A matched Rust/native/Node recipe is routed once in the production callback. Pure producer routing/classification tested; no real Wasm tool. |
| `acceptance.publish_handoff` | `job.py:2122-2153` | Joins all nine family outputs, controller graph/gaps and processing dispositions; adds unsupported-family gaps; writes `accepted-language-builds.json` with upstream project handoff hash; builds aggregate index/manifest. Missing JVM composition is **LB-F01**. |

The retained non-iterative execute branch is exercised by several existing handler tests, but `iterations.dispatch` rejects such dispatches before production can reach it. Passing those tests is not validation of the complete admitted iterative path.

## Language processing and configured bounds

### Common execution

- Settings: command timeout **1800 s**, output preview **8 MiB**, artifact count **10,000** (`appsec-review.toml:1388-1393`). Generic workspace snapshots cap at ten times the artifact count; the generic reconciler defaults to 16,384 invocation rows and eight event ordinals per invocation.
- Job workers 8, load workers 1, execute workers 4, acceptance workers 1, iteration-dispatch workers 1. These are configured scheduler bounds; the shared production controller is serial. The retained non-iterative branch additionally serializes `.NET`.
- Job capture overrides: 250,000 events, retain raw traces, raw trace byte limit **64 MiB**. `_captured_command` passes the resolved capture configuration and validates returned scope/record/manifest identities (`job.py:839-904`). No actual kernel/container enforcement was tested.
- Generic `_execute_one` snapshots/materializes or uses the admitted shared workspace; applies recipe/cwd guards; executes configure/build plus applicable Rust metadata/Go package catalog commands; retains protected argv/streams/capture; checks target drift; catalogs outputs; validates Go/native target proof; publishes hashes/workspace manifest; suppresses artifacts from failed generic commands.
- Generic checkpoint reuse requires supported release declarations, successful receipt, intact manifests/artifacts/capture, and complete capture; it is disabled for project-owned native execution and bypassed for the shared workspace path. JVM/Wasm adapters have separate keys/guards; their private-cache semantics cannot be inferred from the generic completeness condition.
- Failed JVM/Wasm adapter receipts can temporarily contain cataloged files, but the **admitted controller** clears `artifacts` on failed transactions (`build_iterations.py:580-593`). This was not incorrectly reported as an active failed-artifact leak.

### Family implementation matrix

| Family | Actual processing inspected | Bounds/policy and remaining evidence limit |
|---|---|---|
| Native | Shared capture descriptor; compile/link enrichment; `native_components` database; native output layout/attribution; ELF loader facts; target enforcement. | Capture CWD deduplication defect **LB-F04**. Layout parser internals/ELF internals not fully read. Existing enforcement rejection **T-5044** retained, not weakened. |
| Go | Build-only validation; `-x`; post-build `go list -deps -json`; syscall-authoritative tools; package mapping; embedded ELF build-ID/settings admission. | Catalog 20,000 packages; module/buildinfo bounds declared; only little-endian Linux ELF/known ISA proof is supported. Vendor parser and most buildinfo parser internals unread. |
| .NET | Accepted selected-member topology, Windows capability gaps; build-only command list; diagnostic verbosity; Roslyn/SDK hosted-tool classification; generated source/assembly/resource/package catalog. | Supported config allows publish/pack/AOT restrictions but executor ignores them: **LB-F05**. No Windows/Unity execution. |
| Node | Package/lock identity; bounded script graph; before/after invocation outputs; diagnostic/script provenance; artifact/source-map/catalog and npm package delivery; installer summary orchestration. | Script depth 8, visits 256, workspace members 512; manifest 4 MiB; source maps 16 MiB; package members 4,096; metadata 64 MiB and artifacts 512 MiB. Installer parser and full workspace selector implementation unread. |
| Python | Package-only recipe validation; pyproject/Poetry/uv or legacy metadata; wheel/sdist members; package/native-tool facts. | Archive member limit 100,000; invocation rows sliced at 4,096. No target code imported/executed in audit. Large archive/complete-stream behavior not validated. |
| Rust | Cargo validation and argument rewriting; metadata/packages/features/proc macros; syscall reconciliation; rustc output naming/Cargo same-digest uplift; artifact classification. | Nondefault target/profile incorrectly modifies metadata command: **LB-F03**. Metadata package limit 20,000. Toolchain-selector semantics noted below. |
| PHP | Composer/phpize descriptors; plugin/script switches; metadata/packages/autoloader inference; installed-catalog dispatch; artifact classification. | Lock requirement ignored: **LB-F06**. Composer JSON 16 MiB and package list 10,000 per section. Installed-package parser/role implementation mostly unread. |
| JVM/Android | Detached wrappers/evidence; Maven compiler fork; pinned wrapper replacement; Gradle init injection; bounded trace/argfile parsing; class mapping; declared versus observed compilation; `.class`/archives/APK catalog and JVM shard. | Trace 8 MiB, provenance 20,000, argfile 1 MiB, source read 64 KiB. Wrapper/Gradle records are **not** standardized syscall capture. Groovy init-script body unread; **LB-F01/F02**. |
| Wasm | Configured producers: Rust, Emscripten, WASI SDK, AssemblyScript, WAT; source-family image retained; output-family receipt; changed-file catalog; verbose stream facts/native-components capture. | Workspace file limit 100,000. Without native components uses plain executor, a documented boundary, not claimed syscall capture. No real producer/toolchain/format validity test. |

Go/Python/Node fixed-policy values rejected by `_validate_config` are not configurable execution modes merely because their dataclasses use booleans. PHP and `.NET` nondefault policies in findings are accepted by the real job validator.

## Publication and downstream trace

| Dataset | Declared ownership/schema | Actual result |
|---|---|---|
| `language_build_receipts` | `acceptance`, artifact-only, sensitive; `appsec-review/language-build-handoff/2` | Actual aggregate at `data/jobs/job_language_build/attempts/<attempt>/artifacts/language-build/accepted-language-builds.json` matches its glob. Nested generic/JVM receipts use `language-build-receipt/1`; Wasm uses `wasm-build-receipt/1`. |
| `build_actions` | `acceptance`, indexed `build`, shard prefix `language-build`, retrieval-index `/2` | Aggregate contains sanitized top-level command/artifact rows and Cargo package relationships; does not generally emit every `tool_invocations` row. Exact argv is not included in its payload projection. |
| `jvm_build_actions` | `execute`, indexed `build`, prefix `jvm-`, retrieval-index `/2` | Adapter writes a real shard and returns its identity, but the acceptance manifest drops it: **LB-F01**. |
| `build_workspaces` | `execute`, protected octet streams; nine families plus `jvm` tree | Generic/JVM/Wasm diagnostics lie under their declared `data/build/<family>/...` roots. Shared workspace/transaction state also has separate internal `job_build_iteration` declarations; this audit did not prove the entire immutable shared-object publication inventory end to end. |
| `topology_refinement_inputs` | `execute`, protected `build-topology-refinement/1` | Refinement paths declared under both `artifacts/build/topology/**` and `data/build/topology/**`; admitted guards/promotions bind identity. Full promotion/replay transaction matrix unexecuted. |

`Job` has a config input validator, not a complete per-receipt domain output validator (`job.py:2177-2180`). Common control validation checks closed producer statuses/dispositions and gap shapes, not arbitrary domain payload fields (`interchange.py:521-573`). The job is not `strict_gaps=True`: legacy text remains accepted and canonicalized at publication. `_receipt_gaps` independently validates structured causes and deduplicates them.

Downstream `job_artifact_indexing` reads the **accepted language-build manifest** (`job.py:374-390`) and rejects duplicate units, wrong receipt schema/source identity, non-successful receipts with artifacts, and invalid workspace/artifact bindings (`:412-458`, sampled). Therefore an on-disk JVM shard is not enough to make it a queryable accepted input. Existing build-outcome versus receipt-status migrations remain **T-5039**. Other downstream jobs' entire processing paths were not audited here.

## Findings

### LB-F01 — Medium: JVM provenance shards are written but omitted from the accepted manifest

- **Evidence:** `src/appsec_review/jobs/job_language_build/jvm.py:919-920`; `src/appsec_review/jobs/job_language_build/job.py:2016-2030,1830-1837`; `src/appsec_review/retrieval/core.py:112-125`; downstream `src/appsec_review/jobs/job_artifact_indexing/job.py:374-390`.
- **Trigger:** a successful JVM build creates `receipt.retrieval_index`; acceptance publishes that receipt.
- **Expected:** compose the verified JVM shard with the aggregate and upstream shards, as the job's dataset contract and operations process describe.
- **Actual:** `_publish_build_index` starts with the pre-attempt input manifest and appends only the aggregate `language-build` shard. It never incorporates `receipt.retrieval_index`. Family execute only forwards receipts. No runtime/retrieval/internal-iteration code path consuming that field was found.
- **Reproduction:** real `jvm._index` followed by real `_publish_build_index`, with an empty pinned upstream manifest, produced `["language-build"]` only.
- **Impact:** observed JVM compiler/task rows and relationships are not exposed through the accepted `jvm_build_actions` dataset; aggregate top-level command/artifact rows are not a replacement for those details.
- **Confidence:** high, function-level reproduction plus producer-to-consumer trace; complete job publication not executed.
- **Smallest correction:** verify and compose each JVM index identity once into acceptance's manifest; test through the publisher with real shards rather than testing each builder separately.
- **TODO overlap:** T-147 concerns authoritative publication/task bindings generally; no matching JVM composition entry found. Historical language-build acceptance mentions the aggregate shard but does not prove this specialized dataset is present.

### LB-F02 — Medium: equal JVM artifact bytes reuse a stale command/provenance index

- **Evidence:** `src/appsec_review/jobs/job_language_build/jvm.py:594-611,662-672`.
- **Trigger:** another attempt for the same unit/image/source produces identical artifact bytes but different command IDs/argv, invocation/declaration rows, or coverage.
- **Expected:** the index identity changes when any indexed facts change.
- **Actual:** fingerprint input contains artifact hashes and fixed tool/parser metadata, not command/invocation/declaration/coverage content. Existing path is attested and reused without comparing those rows.
- **Reproduction:** index receipt with `old-command`, then index identical artifacts with `new-command`; second call returned `reused=True`, and SQLite still contained `old-command`, not `new-command`.
- **Impact:** stale provenance and coverage can be associated with a new receipt. **Currently latent for ordinary accepted retrieval because LB-F01 omits the shard**; fix both, rather than exposing a stale shard when composing it.
- **Confidence:** high for cache behavior; no live retry executed.
- **Smallest correction:** fingerprint the full normalized indexed projection, including gaps/status and command/invocation identities; assert the changed rows in the rebuilt shard.
- **TODO overlap:** no matching entry found in the inspected TODO/prior reports.

### LB-F03 — Medium: nondefault Rust target/profile adds build-only flags to `cargo metadata`

- **Evidence:** `src/appsec_review/jobs/job_language_build/job.py:1247-1249,1259-1269,1381-1384`; `src/appsec_review/jobs/job_language_build/rust.py:90-120`.
- **Trigger:** supported central Rust `target` is set or `profile` differs from `dev`.
- **Expected:** metadata is invoked with metadata-supported options; build-specific target/profile flags modify build/rustc/check commands only.
- **Actual:** the inserted metadata command passes through `rust.build_argv`, which unconditionally appends `--target` and `--profile`. Cargo metadata uses neither build option (`--filter-platform` is its target-filtering option). Metadata is first, and a failed command ends the command plan before compilation.
- **Reproduction:** real functions generated `cargo metadata --format-version 1 --manifest-path Cargo.toml --target x86_64-unknown-linux-gnu --profile release`.
- **Impact:** supported nondefault settings can stop Rust builds at metadata discovery instead of executing the admitted build. Default `dev`/unset-target tests do not expose it.
- **Confidence:** high for argv/control flow; **no Cargo process ran**, so command rejection itself is a static CLI-contract conclusion, not a measured compiler result.
- **Smallest correction:** make rewriting subcommand-specific; supply any metadata platform filtering deliberately, and add target/profile cases covering the complete command plan.
- **TODO overlap:** no matching entry found; T-004 is broader applicability/acceptance work.

### LB-F04 — Medium: capture reconciliation merges identical argv across different working directories

- **Evidence:** `src/appsec_review/jobs/job_language_build/capture.py:268-294`; correct directory derivation exists at `:108-127` and `container_runtime/capture_files.py:158-179`.
- **Trigger:** one captured recursive build launches `clang -c main.c -o main.o` in both `a/` and `b/`.
- **Expected:** preserve both source/output mappings because cwd changes the command's meaning.
- **Actual:** row key contains capture ordinal, argv identity and executable, but not cwd. Directory is used only when constructing the first row; later equal-argv execs increment its count.
- **Reproduction:** two successful exec events in different directories yielded one row, exec count two, only `a/main.o`, and **no gap**.
- **Impact:** native/.NET/Rust shared descriptor reconciliation can omit or misattribute inputs/outputs, affecting receipt tool provenance and native link/output attribution. The separate `native_components.compile_entries` uses directory in its key, so this is not a claim that every native compile database loses the second compile.
- **Confidence:** high, real reconciler and real directory resolver used with synthetic events.
- **Smallest correction:** include resolved cwd in row identity and scope wrapper matching consistently; test equal argv in two directories.
- **TODO overlap:** no matching entry found. Not the enforcement/capture-policy question tracked by T-5044.

### LB-F05 — Medium: accepted `.NET` publish/pack/AOT prohibitions are not enforced

- **Evidence:** `src/appsec_review/config/loader.py:421-433,1343-1349`; `src/appsec_review/jobs/job_language_build/job.py:1185-1196,1266-1267,1705-1710`; `src/appsec_review/jobs/job_language_build/dotnet.py:34-48`.
- **Trigger:** set `allow_publish=False`, `allow_pack=False`, or `allow_aot=False` while an accepted recipe requests that operation.
- **Expected:** refuse the prohibited recipe before external execution, or explicitly reject unsupported restrictive configuration.
- **Actual:** validation accepts the booleans; `.NET` recipe validation always allows publish/pack and never examines AOT policy. Repository source search found these fields only in configuration construction/validation, not execution decisions.
- **Reproduction:** real config validation with all three false, then real `_execute_one` with fake capture/container boundary, executed `dotnet publish App.csproj -p:PublishAot=true --verbosity diagnostic` and returned `SUCCEEDED`.
- **Impact:** operator's accepted restrictions do not control which `.NET` build operations run. The reproduction directly demonstrates publish/AOT; pack is verified statically through the same unconditioned allowlist.
- **Confidence:** high. No real .NET tool or target code executed.
- **Smallest correction:** pass typed `.NET` settings into recipe/selected-operation validation and reject each prohibited operation before resolving/executing the builder.
- **TODO overlap:** no matching policy-field entry found.

### LB-F06 — Medium: PHP `require_lockfile=True` still permits manifest-only resolution

- **Evidence:** `src/appsec_review/jobs/job_language_build/job.py:1176-1184`; `src/appsec_review/jobs/job_language_build/php.py:27-38,41-55,77-87`.
- **Trigger:** explicit PHP lockfile requirement, Composer recipe declares only `composer.json`, no accepted/workspace `composer.lock`.
- **Expected:** fail/refuse before dependency resolution when the required lock identity is absent.
- **Actual:** `validate_php_dispatch` checks for `composer.json`, never `composer.lock`; the caller raises only if that validator returned errors. Metadata emits the ordinary unlocked warning and execution continues.
- **Reproduction:** real job config validator accepted `require_lockfile=True`; real generic executor with a fake Composer/capture boundary ran `composer install --no-plugins --no-interaction` and returned `SUCCEEDED` with no lockfile.
- **Impact:** reproducible/locked dependency policy is silently bypassed. The default `require_lockfile=False` behavior is not itself a defect and should remain supported.
- **Confidence:** high.
- **Smallest correction:** require the admitted lock path/hash and its actual bytes when configured; preserve the manifest-only branch only when explicitly allowed.
- **TODO overlap:** no matching entry found; T-011 concerns dependency summarization, not lock policy.

### LB-F07 — Low: non-JVM `diagnostic_tail_bytes` is accepted but does not bound tails

- **Evidence:** `appsec-review.toml:1411-1453`; `src/appsec_review/jobs/job_language_build/job.py:692-727,1216-1222`; `src/appsec_review/container_runtime/build_executor.py:527-533,731-743`; `docs/operations/language-build.md:1103-1114`.
- **Trigger:** change Go/Python/Rust/PHP/Node `diagnostic_tail_bytes` from the shipped value.
- **Expected:** configured tail bound controls retention/on-demand diagnostic material as documented.
- **Actual:** these settings occur in dataclass construction/validation but are not passed to the generic executor or applied by `_stream_identity`. The executor uses `min(32768, output_bytes)`; the generic helper retains the returned tail. Shared controller failure diagnosis also slices a fixed 32768 bytes (`build_iterations.py:232-238`). JVM separately applies its configured tail in `_stream`.
- **Impact:** nondefault tail settings do not do what the typed/documented bound promises. Default behavior remains 32 KiB.
- **Confidence:** high static dataflow/search; no separate runtime reproduction or large-stream test.
- **Smallest correction:** wire the family bound to retention/failure reads, or reject/remove unsupported per-family configuration and correct the docs.
- **TODO overlap:** no matching ignored-tail entry found.

## Existing issues, unresolved observations, and non-findings

1. **T-084** remains a material validation gap: no executed test drives a ready production unit all the way through `iterations.dispatch` → real controller → registered internal transaction → final publisher. Existing graph tests fake the controller or call legacy handlers. This audit deliberately did not run Dagster to fill it.
2. **T-092** owns pre-receipt command refusal versus sibling continuation. The controller does propagate pre-prepared failures and can stop the job; this is a recorded decision gap, not a newly invented recovery requirement.
3. **T-5039/T-5040/T-5044** and prior **PB-F03** cover build-outcome/status interpretation, report visibility, and unproven native capture rejection. Rejected artifacts must not be admitted merely to make downstream counts nonzero.
4. **PB-F01/PB-F02/PB-F04/PB-D01** were read before attributing findings. CMake recipe canonicalization, image-free planning-record cache refusal, dispatch read observation, and project-owned native settings ownership are upstream findings, not re-counted here.
5. **Declared controls needing a dedicated semantic decision/test:** `PythonBuildSettings.frontend` and `RustBuildSettings.toolchain` are validated/fingerprinted but no selection use was located in this job's execution path. Accepted recipe/image authority may constrain how these should act; no alternative interpreter/toolchain was launched. This is not asserted to be a proved wrong-toolchain build.
6. **Compiler-artifact disabled mode:** applicability can record `SKIPPED_POLICY`, while generic/specialized catalog paths appear unconditional. A product-transaction test is needed to distinguish mandatory product bookkeeping from the disabled compiler-artifact publication policy. Not counted as a reproduced finding; relate to T-004 rather than assume tests of decision objects prove suppression of artifact processing.
7. **Large streams/bounds:** Go/Rust metadata parsers use `result.stdout` even where complete captured streams may also exist; several JVM/Wasm readers materialize files before applying parsing limits. Large-stream correctness/resource behavior was not exercised. No new limit was invented and no bounds were increased.
8. **No speculative JVM/Wasm capture migration:** plain Wasm execution without native components and JVM wrapper/Gradle instrumentation are documented boundaries. Their absence of standardized syscall capture is not newly labeled a failure.

## Validation commands and outcomes

All Linux bodies were transported through SSH using the brief's UTF-8/base64 pattern; there was no `wsl -e` execution. Common test prefix:

```bash
set -eu
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
unset APPSEC_REVIEW_PROFILE APPSEC_REVIEW_OVERLAY APPSEC_REVIEW_CONFIG DAGSTER_HOME \
  APPSEC_ACCEPTANCE_ROOT APPSEC_ACCEPTANCE_RUNS_DIR APPSEC_REVIEW_HOST_PINS PYTEST_ADDOPTS
while IFS= read -r name; do unset "$name"; done < <(compgen -v APPSEC_NATIVE_)
export APPSEC_PYTHON="$PWD/.venv/bin/python"
```

### Selection A — core tasks and generic families

```bash
.venv/bin/python -m pytest --collect-only -q \
  --basetemp=test/tmp/job-audit-job_language_build-20261118-collect \
  tests/unit/job_language_build/test_contract.py \
  tests/unit/job_language_build/test_job_graph.py \
  tests/unit/job_language_build/test_execution_lanes.py \
  tests/unit/job_language_build/test_adapters_and_capture.py \
  tests/unit/job_language_build/test_go.py \
  tests/unit/job_language_build/test_rust.py \
  tests/unit/job_language_build/test_php.py \
  tests/unit/job_language_build/test_python.py | tail -5

scripts/run-tests.sh --expect-tests 77 --parallel --test-workers 2 \
  --shuffle-seed 1118 --strict -- \
  tests/unit/job_language_build/test_contract.py \
  tests/unit/job_language_build/test_job_graph.py \
  tests/unit/job_language_build/test_execution_lanes.py \
  tests/unit/job_language_build/test_adapters_and_capture.py \
  tests/unit/job_language_build/test_go.py \
  tests/unit/job_language_build/test_rust.py \
  tests/unit/job_language_build/test_php.py \
  tests/unit/job_language_build/test_python.py
```

- Preliminary collection: **77**, 0.63 s.
- Supervised result: **77 passed**, 6.82 s pytest elapsed; no failed/skipped/over-10-second cases.
- Supervisor stage wall times: collection 1.713 s, execution/cleanup 10.589 s; cleanup confirmed, zero remaining processes.
- Evidence stem: `tests-custom-20261118-114752-623620-2571897`.

### Selection B — previously uncovered Node/JVM/Wasm adapter policy

```bash
.venv/bin/python -m pytest --collect-only -q \
  --basetemp=test/tmp/job-audit-job_language_build-20261118-adapters-collect \
  tests/unit/job_language_build/test_node_scripts.py \
  tests/unit/job_language_build/test_wasm.py::test_wasm_producer_validation_and_output_classification \
  tests/unit/job_language_build/test_jvm.py::test_android_gradle_policy_allows_assembly_but_rejects_execution_tasks \
  tests/unit/job_language_build/test_jvm.py::test_android_gradle_policy_rejects_tasks_that_do_not_produce_an_apk \
  tests/unit/job_language_build/test_jvm.py::test_gradle_build_requires_an_explicit_test_exclusion \
  tests/unit/job_language_build/test_jvm.py::test_jvm_topology_has_independent_dagster_unit \
  tests/unit/job_language_build/test_jvm.py::test_jvm_checkpoint_fingerprint_invalidates_on_capture_or_upstream_change | tail -3

scripts/run-tests.sh --expect-tests 21 --parallel --test-workers 2 \
  --shuffle-seed 1119 --strict -- \
  tests/unit/job_language_build/test_node_scripts.py \
  tests/unit/job_language_build/test_wasm.py::test_wasm_producer_validation_and_output_classification \
  tests/unit/job_language_build/test_jvm.py::test_android_gradle_policy_allows_assembly_but_rejects_execution_tasks \
  tests/unit/job_language_build/test_jvm.py::test_android_gradle_policy_rejects_tasks_that_do_not_produce_an_apk \
  tests/unit/job_language_build/test_jvm.py::test_gradle_build_requires_an_explicit_test_exclusion \
  tests/unit/job_language_build/test_jvm.py::test_jvm_topology_has_independent_dagster_unit \
  tests/unit/job_language_build/test_jvm.py::test_jvm_checkpoint_fingerprint_invalidates_on_capture_or_upstream_change
```

- Preliminary collection: **21**, 0.55 s.
- Supervised result: **21 passed**, 2.92 s pytest elapsed; no failed/skipped/over-10-second cases.
- Supervisor stage wall times: collection 1.593 s, execution/cleanup 6.665 s; cleanup confirmed, zero remaining processes.
- Evidence stem: `tests-custom-20261118-115157-887381-2588358`.

For each evidence stem, retained WSL artifacts are:

```text
test/tmp/reports/<stem>.json
test/tmp/logs/<stem>.log
test/tmp/logs/<stem>.collection.log
test/tmp/<stem>.junit.xml
test/tmp/<stem>.timings.sqlite
test/tmp/<stem>.collection.json
```

The mandatory multi-file wrapper owns scratch names and rejects `--basetemp` overrides. Consequently execution used its unique `test/tmp/tests-custom-...` directories, not the preferred `job-audit-...` prefix; collection and manual reproductions used the requested audit prefix. No wrapper checks were bypassed. No dependencies were installed.

### Tool-free reproduction — exact successful Python body

Used the common prefix, then the fixture host-pins file from **this audit's own** first run:

```bash
export APPSEC_REVIEW_HOST_PINS="$PWD/test/tmp/tests-custom-20261118-114752-623620-2571897.host-pins.toml"
.venv/bin/python - <<'PY'
from pathlib import Path
from types import SimpleNamespace
from dataclasses import replace
from unittest.mock import patch
import json, sqlite3, time, atexit
from appsec_review.jobs.job_language_build import job, jvm, rust, capture, native
from appsec_review.config import RustBuildSettings
from appsec_review.retrieval import write_manifest
from appsec_review.storage import file_sha256
from appsec_review.jobs.cataloging import source_fingerprint
from tests.unit.job_language_build import support
from tests.capture_fakes import simulated_executor
started=time.monotonic(); atexit.register(lambda:print('ELAPSED_SECONDS',round(time.monotonic()-started,3)))
root=Path('test/tmp/job-audit-job_language_build-20261118-repro2').resolve()
root.mkdir(parents=True,exist_ok=False)
u=support.unit_context(root/'jvm','acceptance.publish_handoff')
r={'build_unit_id':'build-unit-'+'a'*20,'family':'java','fingerprint':'8'*64,
 'build_system':'javac','image':{'image_id':'sha256:'+'5'*64},'terminal_status':'SUCCEEDED','gaps':[],
 'commands':[{'command_id':'old-command','tool':'javac','tool_kind':'compiler','argv_sha256':'1'*64}],
 'tool_invocations':[], 'artifacts':[{'workspace_path':'build/A.class','sha256':'4'*64,
 'size_bytes':4,'kind':'jvm-class','build_unit_id':'build-unit-'+'a'*20,
 'mapping':'exact-workspace-path','mapping_confidence':1.0}]}
first=jvm._index(u,r); r['retrieval_index']=first
prior=u.job.run_root/'data/indices/manifests/prior.json'
write_manifest(prior,run_id=u.job.run_id,target_snapshot=u.job.source_fingerprint,target_root=u.job.target_root,indexes=())
with patch.object(job,'resolve_context_manifest',return_value=(prior,file_sha256(prior))):
 published=job._publish_build_index(u,[r])
manifest=json.loads((u.job.run_root/published['path']).read_text())
shards=[x['shard_id'] for x in manifest['indexes']]
assert shards==['language-build'],shards
print('JVM_SHARD_NOT_COMPOSED',json.dumps(shards))
changed={**r,'commands':[{**r['commands'][0],'command_id':'new-command','argv_sha256':'2'*64}]}
second=jvm._index(u,changed)
with sqlite3.connect(u.job.run_root/second['identity']['relative_path']) as db:
 commands=[json.loads(x[0]).get('command_id') for x in db.execute('select payload_json from entities')]
assert second['reused'] and 'old-command' in commands and 'new-command' not in commands
print('JVM_STALE_COMMAND_INDEX',second['reused'],json.dumps(commands))
settings=RustBuildSettings('stable','x86_64-unknown-linux-gnu','release',(),False,False,True,32768)
argv=rust.build_argv(rust.metadata_argv({},settings),settings)
assert argv[1]=='metadata' and '--target' in argv and '--profile' in argv
print('RUST_METADATA_BUILD_ONLY_FLAGS',json.dumps(argv))
ws=root/'capture'; ws.mkdir()
for d in ('a','b'):
 (ws/d).mkdir(); (ws/d/'main.c').write_text('int '+d+';'); (ws/d/'main.o').write_bytes(d.encode())
events=[]
for i,d in enumerate(('a','b')):
 events += [{'kind':'directory_change','pid':100+i,'ordinal':i*2+1,'timestamp_ns':i*2+1,'path':'/workspace/'+d,'result':0},
 {'kind':'process_exec','pid':100+i,'ordinal':i*2+2,'timestamp_ns':i*2+2,'executable':'/usr/bin/clang',
 'argv':['clang','-c','main.c','-o','main.o'],'result':0}]
cap=SimpleNamespace(identity={'sha256':'a'*64},document={},gaps=(),tool_calls=[],events=lambda:events)
rec=capture.reconcile_captured_build([(1,cap)],ws,'.',native.CAPTURE_DESCRIPTOR)
assert len(rec.rows)==1 and rec.rows[0]['evidence']['process_exec']['count']==2
assert [x['workspace_path'] for x in rec.rows[0]['outputs']]==['a/main.o']
print('CAPTURE_CWD_COLLAPSE',len(rec.rows),rec.rows[0]['evidence']['process_exec']['count'],json.dumps(rec.rows[0]['outputs']),json.dumps(rec.gaps))
for family,marker,contents,raw in (
 ('dotnet','App.csproj','<Project/>',['dotnet','publish','App.csproj','-p:PublishAot=true']),
 ('php','composer.json','{"name":"acme/demo"}',['composer','install'])):
 sub=root/family; target=sub/'target'; target.mkdir(parents=True); (target/marker).write_text(contents)
 unit=support.unit_context(sub,'execute.'+family,target_root=target,source_fingerprint=source_fingerprint(target))
 cfg=unit.job.config; opts=dict(cfg.settings); opts[family]=dict(opts[family])
 if family=='dotnet':
  opts[family].update(allow_publish=False,allow_pack=False,allow_aot=False)
  typed=replace(cfg.typed_settings,dotnet=replace(cfg.typed_settings.dotnet,allow_publish=False,allow_pack=False,allow_aot=False))
 else:
  opts[family]['require_lockfile']=True
  typed=replace(cfg.typed_settings,php=replace(cfg.typed_settings.php,require_lockfile=True))
 unit.job.config=replace(cfg,settings=opts,typed_settings=typed); job._validate_config(unit.job,None)
 uid='build-unit-'+('d' if family=='dotnet' else 'e')*20
 disp={**support.dispatch(uid,family,build_system='dotnet' if family=='dotnet' else 'composer',commands=[raw]),
 'source_fingerprint':unit.job.source_fingerprint,'topology_refinement':{'path':'unused','sha256':'7'*64},
 'image':{'image_tag':family+':fake','image_id':'sha256:'+'5'*64,'user':'1000:1000','dependency_hashes':{}},
 'recipe':{'source_dir':'.','build_dir':'bin' if family=='dotnet' else 'vendor','environment':{},'dependency_files':[marker],
 'configure_commands':[],'build_commands':[raw],'expected_outputs':['bin' if family=='dotnet' else 'vendor'],'network_required':False}}
 calls=[]
 def behavior(argv,workspace,cwd,env,sim):
  calls.append(argv); sim.exec('/usr/bin/'+family,argv)
  if family=='dotnet':
   sim.exec('/usr/bin/dotnet',['dotnet','/sdk/csc.dll','Program.cs','/out:bin/App.dll'])
   out=workspace/'bin/App.dll'; out.parent.mkdir(exist_ok=True); out.write_bytes(b'fake managed output')
  else:
   out=workspace/'vendor/composer/autoload_real.php'; out.parent.mkdir(parents=True,exist_ok=True); out.write_text('<?php // generated')
  return 0,b'',b''
 with patch('appsec_review.jobs.build_topology_artifacts.guard_cache_action',return_value={}),patch.object(job.dotnet,'selected_project_topology',return_value=([],[],[])):
  receipt=job._execute_one(unit,disp,support.accepted(disp),lambda _u,p:simulated_executor(p,behavior))
 assert calls and receipt['terminal_status']=='SUCCEEDED'
 if family=='php': assert not (target/'composer.lock').exists() and receipt['composer_policy']['require_lockfile']
 print('IGNORED_FAMILY_RESTRICTION',family,json.dumps(calls),receipt['terminal_status'])
print('REPRODUCERS_CONFIRMED',6)
PY
```

Observed output:

```text
JVM_SHARD_NOT_COMPOSED ["language-build"]
JVM_STALE_COMMAND_INDEX True ["old-command", null]
RUST_METADATA_BUILD_ONLY_FLAGS ["cargo", "metadata", "--format-version", "1", "--manifest-path", "Cargo.toml", "--target", "x86_64-unknown-linux-gnu", "--profile", "release"]
CAPTURE_CWD_COLLAPSE 1 2 [{"workspace_path": "a/main.o", "sha256": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "size_bytes": 1, "mapping": "exact-workspace-path", "mapping_confidence": 1.0}] []
IGNORED_FAMILY_RESTRICTION dotnet [["dotnet", "publish", "App.csproj", "-p:PublishAot=true", "--verbosity", "diagnostic"]] SUCCEEDED
IGNORED_FAMILY_RESTRICTION php [["composer", "install", "--no-plugins", "--no-interaction"]] SUCCEEDED
REPRODUCERS_CONFIRMED 6
ELAPSED_SECONDS 1.054
```

The initial version used scratch `...-repro`, queried `second['identity']['path']` instead of the actual `relative_path`, and exited with auditor-script `KeyError: 'path'` after the first composition assertion. Its elapsed time was not captured. No product assertion failed in that attempt; remaining cases were not run until the corrected command above. Both manual scratch trees were removed after recording outputs. Test reports/logs remain under `test/tmp`.

One inspection command encountered missing Linux `rg` (exit 127); subsequent source searches used the UNC `rg` tool. It did not run tests or tools and did not require package installation.

## Read scope and coverage gaps

### Read fully

- Shared brief, authorized `AGENTS.md`, and multi-session coordination skill.
- `docs/operations/job_language_build.md`; historical `docs/tasks/2026-11-11-job-pass-11-language-build.md`.
- `src/appsec_review/jobs/job_language_build/`: **`job.py`, `datasets.py`, `capture.py`, `dotnet.py`, `native.py`, `native_components.py`, `native_outputs.py`, `node.py`, `python.py`, `rust.py`, `jvm.py`, `wasm.py`**.
- Shared `jobs/build_outcome.py`; internal transaction `job_build_iteration/job.py` and `datasets.py`; `runtime/consume.py`.
- The eight complete test files in selection A; `test_node_scripts.py`; `test_wasm.py` (only its producer-routing case executed); `support.py`, `tests/capture_fakes.py`, `tests/handoff_fixture.py`, `tests/release_support.py`, root/unit `conftest.py`, and `test_000_unit_environment_guard.py`.
- `scripts/run-tests.sh` and `scripts/lib/common.sh`.

### Sampled/search-read, not fully audited

- `appsec-review.toml:1384-1536`; `config/loader.py:255-492,1261-1421`; exact policy-field searches over `src`.
- `go.py:1-230,306-417,495-618`; `php.py:1-205,379-410`; `gradle_provenance.py:367-514`; `native_layout.py:693-738`; `node_scripts.py:1-180,470-589`.
- `build_iterations.py:1-345,469-724,737-855,990-1051`; `build_workspace` only called through tested helpers/transaction wiring, not a full independent implementation review.
- `retrieval/core.py:50-185`; index identity/schema locations; `runtime/units.py:106-242`; `interchange.py:521-594`; `runtime/inputs.py:453-470`; registry/topology relevant registration/dependency sections.
- `job_artifact_indexing/job.py:360-458` and language-reader call sites; other downstream paths only navigation/search.
- `docs/operations/language-build.md`: headings/settings and relevant prose; not its complete 1,193-line historical/live narrative.
- Architecture: `job-interchange.md:26-165`; `build-topology-and-iterations.md:300-436`; `build-environments-and-execution-capture.md:518-640`.
- `docs/TODO.md`: targeted matching entries/headings, including T-004, T-084, T-092, T-147, T-5039/T-5040/T-5044; prior project-build report findings/overlap section and keyword search of other available audit reports. This was not a complete historical backlog review.
- `test_jvm.py:1-210` containing all selected policy/fixture/fingerprint cases; `ops_tests.py` runner-selection/report sections. No unselected JVM cache fixture was executed.

### Material unread/unexecuted matrix

- **Native:** `elf.py`, most `native_layout.py`, and `output_attribution.py`; CMake/Meson/Ninja/vcpkg/Conan/MSBuild layout corners, ELF segment/section variations, static archive/linker/target enforcement matrix.
- **Go:** most low-level buildinfo decoder and `VendoredCatalog`; `go_vendored.py`; CGO, multi-main-package, vendoring/replacement and nondefault target/output matrices.
- **JVM:** Groovy `gradle_provenance.py:1-366`; live wrapper/JDK resolution, Java/Kotlin/KAPT/KSP, Android dexing/provenance, retained-private-cache recovery and large-argfile matrix.
- **Node:** `node_installed.py`; full `node_scripts.py` workspace resolver middle section; npm/pnpm/yarn installer/version combinations, package/archive/source-map matrix.
- **PHP:** most installed-catalog implementation and `php_installed.py`; Composer plugin/lifecycle, phpize/Autoconf/native extension and installer-version matrices.
- **Python/Rust/Wasm:** live backend/compiler/toolchain compatibility, complete stream/large archive behavior, all five Wasm producers, native components and replay/reuse across output-policy changes.
- **Controller/runtime:** full workspace custody/generation/recovery/promotion internals, dataset publication closure and complete actual read receipts across a production run. No claim that individual helper tests prove the entire transaction.
- Of 30 mapped unit files, nine were executed completely and two partially; **19 mapped files were not executed**. `test_build_outcome.py` also exists but is absent from this job's map; it was not run. Mapping absence is not claimed to mean absence of behavior tests.
- All mapped integration, acceptance and live selectors were deliberately unexecuted. No existing run's binaries/captures/accepted findings were opened to certify current output quality. No target answer key was read.

## Completion

Final HEAD remained the required SHA; `git status --short` was empty. No audit scratch files appeared at repository root. Only the two manual reproducer trees were removed; supervised evidence remains. This report is the only newly authored persistent audit document. Stop after `job_language_build`; coordinator owns cumulative attribution and any later repair authorization.
