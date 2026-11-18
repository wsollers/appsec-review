# Job 19/47 audit — job_evidence_collection

## Identity, authorization, and result

- **Source:** `/home/wsollers/projects/appsec-review`, Ubuntu-22.04, accessed through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu` and the corresponding WSL UNC path.
- **Revision:** `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`, branch `main`. HEAD and clean tracked/untracked Git status verified before tests and at completion; required ancestor check succeeded. Editable import resolved to this checkout's `src/appsec_review/__init__.py`.
- **Ownership:** one of the coordinator's at-most-four read-only auditors; only this job audited. No source/configuration/environment installation or service changes, commits, providers, actual scanners, target execution, nested agents, integration, acceptance, or live runs.
- **Verdict:** exact functional correctness is **not established**. Seven evidence-backed findings below: **two high, five medium**, including two explicitly overlapping historical findings. All **110 selected unit cases passed** (107 job cases + three environment-guard cases), in **8.92 s pytest / 18 s shell elapsed**, two workers, shuffle seed 1919, no skips/failures/cases over 10 s.
- Three additional synthetic probes exercised real parsers/normalizers, fake-executor task paths, and the downstream reader. Passing fixtures do not verify native tool-output compatibility or actual review quality.

## Intended contract and activation

The job is registered by `src/appsec_review/runtime/registry.py:86,156`. The typed contract is `jobs/job_evidence_collection/datasets.py:44-93`: review-graph dispatch, schedule after `job_target_analysis_plan`, checkout target access, propagated handoff, not always-execute. The registry/topology unit tests passed. The central recipe declares the job and all 62 units (`appsec-review.toml:2514-2626`); it is enabled in the dev recipe. There are **seven steps, 20 scanner chains, 62 tasks**, no model worker or runtime-prompt call in the implementation.

Intended behavior: execute selected, applicable source/configuration/inventory/advisory/binary scanners; retain exact native results and execution references; normalize/redact/bound observations; publish one observation shard per tool plus a corroborated SAST artifact and final handoff. These are scanner observations, not confirmed vulnerabilities: both evidence and domain handoff deliberately retain `security_findings: []`.

### Inputs and actual reads

All handoff requirements below are optional / missing=`gap` / allow-partial in the declaration. The catalog and plan loaders nevertheless read their envelopes unconditionally with `required=True`: absence is a validation exception, not an empty scan. This mismatch is recorded as a contract/coverage limitation, not permission to fabricate input.

| Declared producer / output kinds | Actual role and admission trace |
| --- | --- |
| `job_target_catalog`: handoff, target_artifact_inputs, source_files, declaration_symbols, components, target_documents, build_units, catalog_documents | `load_target_catalog`, `job.py:167-205`, calls `accepted_upstream`, verifies domain-artifact hashes/schema, then reads partition, projects, build targets and compile-database inventory. It does not query all declared catalog datasets individually. Built target records feed SpotBugs/blint applicability. |
| `job_target_analysis_plan`: handoff, planning_feedback_cache, analysis_plan, analysis_plan_documents | Every scan reloads accepted plan; `job.py:1338-1356`. `job_target_analysis_plan/job.py:168-200` verifies plan artifact/schema, source-bound topology and environment identity. Planning-feedback cache is not read by this job. Scope path hashes were validated at plan acceptance (`planning.py:827-845`); the scanner handler itself extracts paths only. |
| `job_review_intake`: handoff, model_preflight, binary_evidence, review_intake | Optional intake lookup supplies `target.path` to the catalog object (`job.py:188-199`); model preflight and binary-evidence documents are not read here. Runtime additionally requires the graph-provided target root. |
| `job_build_environment_analysis`: handoff, build_environment | Transitive read only when the accepted build-topology-v2 plan carries an environment contract (`job_target_analysis_plan/job.py:185-196`). Declared correctly rather than relying on ancestry. |
| `job_third_party_data_sync`: external feed_snapshot, reference authority | OSV snapshot verification and required ecosystem mounts; Grype consumer settings, snapshot and image/database compatibility. No maintenance-job handoff required in the review run (`job.py:337-360,931-934`; `osv_offline.py`). |

`runtime/consume.py:162-204` enforces typed envelope permission and exact claim pins under runtime scope, and records reads; outside scope the verified latest pointer is operator lookup, not admitted consumption. Most direct job tests use that **unscoped fixture** path. They do not establish complete runner-mediated admission/read receipts for this 62-task job.

### Configuration followed through execution

- Typed `EvidenceCollectionSettings`: retries 0–3, OSV memory 512m–64g, OSV lockfiles/invocation 1–500, corroboration cap 1–1,000,000; booleans/coercible strings refused for integer fields (`config/evidence_collection.py:17-69`, loader `1458-1460`).
- Recipe: `tool_retries=1`, `osv_memory="3g"`, `osv_max_lockfiles_per_invocation=50`, `max_findings_per_scope=5000`; job workers 8 and step workers 1/4/1/2/4/1/1. Audit testing used only two workers; it did not run this production task graph.
- OSV memory and chunk setting reach `_plan_invocations` / `_run_invocation` (`job.py:558-585,991-999`). Retry safety intentionally allows one attempt when execution-safety is active (`591-607`). No retry limit was increased.
- `tools.disable_grype=true`, `tools.enable_swift=false` in recipe (`appsec-review.toml:146-151`). Grype disablement occurs before prerequisites/checkpoint reuse (`job.py:876-890`). Swift path filtering, staged target hashes, and derived-output rejection are present. Positional reconstruction at `1342-1346` drops the three optional target-artifact fields (historical C09-F16), but the current adapters use `catalog.artifacts`, which is retained; no demonstrated active scanner consequence is newly asserted.
- Cppcheck profile is parsed/closed, frozen, passed to argv, and included in checkpoint identity (`config/cppcheck.py`; `adapters.py:94-137,262-271`; `job.py:402-419,676-684`). Warning-only recipe and fixed XML/output flags are tested. This audit does not change the explicitly retained inline-suppression policy.
- Cross-scanner cap setting reaches final assembly, but an earlier independent per-tool cap still removes data: **EC-02**.

## Complete declared task/step trace

For every scanner row below, the three **explicit task names** share the exact dispatch chain:

1. `_scan`: closure `job.py:1338-1359` → accepted catalog/plan selection → Swift/support partition → `_prerequisites` → `_execute_tool` → `_run_invocation`.
2. `_normalize`: `job.py:1080-1090,1360-1361` checks evidence schema and identical terminal status, then forwards the already normalized artifact; it does not reparse native output.
3. `_index`: `job.py:1093-1212,1362-1363` verifies accepted source hashes, builds/reuses an `observations` SQLite shard, evidence/observation entities and derived/source relations, count and coverage.

| Step | Every declared task | Selection, invocation/parser specifics; verified limits |
| --- | --- | --- |
| secrets | `gitleaks_scan`, `gitleaks_normalize`, `gitleaks_index` | Any cataloged file; generic rules required; directory-mode `/target`, redacted JSON, exits 0/1. Worktree not history. Generic list parser. **EC-01, EC-05**. |
| source_sast | `semgrep_scan`, `semgrep_normalize`, `semgrep_index` | Supported source suffixes; security/review/banned/CERT rules; exit 0, report JSON; native selectors, CWE/rule metadata, optional traces, errors/skips and unscanned-path reconciliation. **EC-02/03**; missing trace-request flag noted below. |
| source_sast | `opengrep_scan`, `opengrep_normalize`, `opengrep_index` | C/C++/Java, excludes Semgrep security baseline; same native parser and coverage reconciliation. Kotlin limitation named. **EC-02/03**. |
| source_sast | `gosec_scan`, `gosec_normalize`, `gosec_index` | Selected `.go` paths become deduplicated containing package directories; offline-context limitation; `Issues` JSON and CWE mapping, exits 0/1. Error-shaped reports accepted: **EC-01**. Per-file scope is broadened to package semantics. |
| source_sast | `mobsfscan_scan`, `mobsfscan_normalize`, `mobsfscan_index` | Java/Kotlin/Swift paths, JSON report, exits 0/1; rule→files native pointers with metadata/line arrays; Swift policy applies. **EC-01**. |
| source_sast | `shellcheck_scan`, `shellcheck_normalize`, `shellcheck_index` | `.sh` plus bounded shebang check; stdout json1/list, exits 0/1; SC1071 becomes not-applicable input, not finding. Real fake-executor false-clean reproduced: **EC-01**. |
| source_sast | `phpcs_scan`, `phpcs_normalize`, `phpcs_index` | PHP paths; PSR12 fixed standard, stdout JSON files/messages, exits 0/1/2/3. Project standard not inferred. **EC-01**. |
| source_sast | `phpstan_scan`, `phpstan_normalize`, `phpstan_index` | PHP paths, no installs; stdout JSON files/messages, exits 0/1. Top-level non-file errors disappear: **EC-01**. |
| source_sast | `psalm_scan`, `psalm_normalize`, `psalm_index` | PHP paths; stdout generic list parser, exits 0/1/2, config/stubs limitation. Native Psalm field-shape fidelity not established by synthetic fixtures. **EC-01**. |
| source_sast | `spotbugs_scan`, `spotbugs_normalize`, `spotbugs_index` | Accepted built JVM bytecode only; XML report, exit 0; `BugInstance` native ordinal and `SourceLine`; priority kept as native value. Wrong XML root accepted: **EC-01**. |
| source_sast | `cppcheck_scan`, `cppcheck_normalize`, `cppcheck_index` | C/C++ source or single accepted/sanitized compile database; typed profile; exit 0; XML error ordinals, CWE mapping; missing-include/configuration IDs become diagnostics. **EC-01, EC-07**. |
| source_sast | `pmd_scan`, `pmd_normalize`, `pmd_index` | Java list file, supplied security rules, exits 0/4; JSON violations/priority mapping; configurationErrors fail, per-file processingErrors gap. Native top-level processing-error variants not verified. **EC-01**. |
| software_inventory | `syft_scan`, `syft_normalize`, `syft_index` | Directory inventory `/target`, exit 0; `artifacts` packages, version/PURL/repository/raw selector and first location. Exact successful source inventory retained; no built/OCI completeness claim. **EC-01, EC-05**. |
| vulnerability_matching | `osv_scanner_scan`, `osv_scanner_normalize`, `osv_scanner_index` | Supported lockfiles; verified available ecosystem partition; deepest-project grouping and bounded chunks; needed mounts only; exits 0/1, narrowly recognized exit 128 no-packages; partial siblings retained and original pointers preserved when merged. **EC-01, EC-04**. |
| vulnerability_matching | `grype_scan`, `grype_normalize`, `grype_index` | Scan depends explicitly on `software_inventory.syft_scan`; honors disablement before reuse. Otherwise requires successful/partial Syft scanner output and compatible verified DB; SBOM argv, exit 0, matches JSON. **EC-01**. |
| configuration | `hadolint_scan`, `hadolint_normalize`, `hadolint_index` | Dockerfile predicate, stdout JSON list, exits 0/1, config-lint category. **EC-01**. |
| configuration | `checkov_scan`, `checkov_normalize`, `checkov_index` | Current support table accepts any cataloged file; tool arbitrates framework applicability; stdout JSON, exits 0/1; failed checks, parsing errors, passed/skipped accounting and suffix-based path matching. Malformed shape can become all-not-applicable: **EC-01/04**. |
| configuration | `trivy_scan`, `trivy_normalize`, `trivy_index` | Selected Terraform/HCL/Dockerfiles staged separately; embedded config checks/no updates, exit 0, Results/Misconfigurations JSON; stderr fallback limitation. **EC-01**. |
| configuration | `zizmor_scan`, `zizmor_normalize`, `zizmor_index` | GitHub workflows, offline/no-exit-codes JSON, accepted exits 0/1; generic list parser, CI-security category. Native nested output shape not certified. **EC-01**. |
| binary_hardening | `blint_scan`, `blint_normalize`, `blint_index` | Accepted built binary suffixes; reports directory, exit 0; bounded host assembly; exact native findings.json pointers. Empty `analyzed` and assembly truncation produce gaps. Partial missing binaries inside a nonempty analyzed set not independently reconciled. |
| evidence_publication | `assemble_manifest` | Depends on all 20 index tasks; `job.py:1235-1293`: read evidence, corroborate, unsupported-language inventory, remove previous same-job shards, write/verify combined manifest; **EC-02/03/04/06**. |
| evidence_publication | `publish_handoff` | Depends on assembly; `job.py:1370-1400`: domain handoff with dispositions/gaps/telemetry/corroboration ref and no confirmed findings. Runner projection boundary: **EC-06**. |

### Error, reuse, normalization, and publication paths

- Prerequisite absence → BLOCKED envelope; unselected/unsupported-only → NOT_APPLICABLE with reasons or SKIPPED_NA accounting; disabled Grype → CONFIGURED_DISABLED. Source/catalog/schema/hash disagreement raises rather than publishing a fabricated scan.
- Image-resolution error → FAILED evidence; timeout/OOM/unaccepted exit/missing/oversized report/recognized parse failure → retries then failed diagnostic retention. Failed native output is not normalized into findings. OSV siblings remain partial when only some fail (`job.py:701-857,998-1069`).
- Native selectors are resolved and provenance validated before nonempty evidence is returned (`job.py:770-792,806-825,494-500`). Empty reports bypass that record-level validation, exposing **EC-01**.
- Scan checkpoint binds catalog/scope/image, declared releases, settings, non-platform mounted inputs and normalizer. Supplied rule mounts deliberately use release identities instead of per-customer content hashing; existing tests explicitly enforce this. Successful/partial results may be reused; failed results use retry marker. Index reuse separately checks evidence fingerprint and actual shard hash. No live cache/restart acceptance was run.
- `build_envelope` redacts secrets/text, resolves catalog paths and source hashes, coalesces exact references/CWE spans, bounds fields/records/bytes, and retains native provenance. New bounds gaps do **not** change the passed producer status; `_build_producer_shard` uses only that status for its simple complete/partial row. A 9000-byte ShellCheck message reproduced `SUCCEEDED`, a truncation gap, and SQLite `complete/null`. The canonical handoff can still report partial through the gap, and the operations document explicitly warns that the simple shard mapping is not canonical coverage. **Recorded inconsistency/limit, not an additional false-clean finding.**
- Dataset declarations (`datasets.py:12-36`): indexed `static_tool_observations`/retrieval-index/2; artifact-only `static_tool_evidence`/2 and `corroborated_sast_evidence`/1; protected `static_tool_io`/container-execution/1. Globs cover scan evidence, domain handoff, checkpoints, raw scratch/staged inputs and merged OSV report. They describe heterogeneous payload families; a schema label is not per-payload validation. Domain corroboration schema was read and its existing JSON-schema unit passed.
- No domain output validators are registered (`job.py:1404-1409`; contract test). Shared `interchange.validate_unit_output` validates **control fields**, not every native/domain payload. Do not infer validation from a declared schema alone.
- Consumers use observation shards for review/indexing and Syft package/advisory extraction (`job_dependency_intelligence/job.py:170-240`), preserving version/PURL where emitted. Corroboration/disposition consumers have the boundary mismatch in **EC-06**.

## Findings

In abbreviated follow-on citations, `job.py`, `adapters.py`, `evidence.py` and `datasets.py` mean files under `src/appsec_review/jobs/job_evidence_collection/`; `config/`, `runtime/`, `indexing/`, and named `job_*/` modules mean their corresponding directories under `src/appsec_review/` and `src/appsec_review/jobs/`.

### EC-01 — High — Malformed/error-shaped native reports become successful zero-result scans

- **Evidence:** `src/appsec_review/jobs/job_evidence_collection/adapters.py:367-383,797-812,889-907,919-929,995-1035`; default-empty native collections across the registry. XML parsers likewise accept any well-formed root with no matching elements (`:932-951,973-993`). Execution accepts these parsed empty lists (`job.py:742-846`), then selects SUCCEEDED when no invocation error/gap exists (`:1004-1010`).
- **Trigger:** scanner exits with an accepted code but returns `{}`, `{"error":"analysis failed"}`, an unrelated XML root, or a PHPStan report containing top-level `errors` and no file messages.
- **Expected / actual:** recognize a supported empty native result shape and surface engine diagnostics; instead 19/20 parser probes returned zero observations **and zero parser diagnostics** for error-shaped documents. Blint alone added its missing-analysis diagnostic. Semgrep's later scanned-path check can still add a job-level gap; this is not a claim all 19 become gap-free at job level.
- **Reproduced real handler path:** fake ShellCheck exit 0 plus `{"error":"scanner failed"}` → `SUCCEEDED`, count 0, `gaps=[]`, normalized shard `complete/null`. PHPStan exit 1 plus `{"totals":{"errors":1,"file_errors":0},"files":{},"errors":["No files found to analyse."]}` → SUCCEEDED/count 0; only the generic Composer limitation survives, not the actual error.
- **Impact:** parser/schema drift or recognized non-file diagnostics can erase unavailable coverage and publish authoritative-looking emptiness, including Syft inventory used downstream.
- **Confidence:** high for reproduced synthetic-input behavior; no real tool failure was induced.
- **Smallest correction:** validate minimum per-adapter native report shape and consume native diagnostic collections before allowing zero observations. Keep legitimate empty arrays/documents accepted. Add cases against captured native formats, not `{}` as a universal empty fixture.
- **Overlap:** similar class to prior job audit **CI-01**, but separate adapters/handler. No matching evidence-collection TODO found; T-113/T-5021 concern testing, not this validation behavior. `test_adapters.py:69-82` and `support.py:60-76` currently institutionalize `{}` as a successful fixture.

### EC-02 — High — Cross-scanner “pre-cap” corroboration receives already capped per-tool evidence

- **Evidence:** `src/appsec_review/jobs/job_evidence_collection/evidence.py:55-58` fixes `max_records=5000`; `src/appsec_review/jobs/job_evidence_collection/job.py:476-487` does not supply another bound; `evidence.py:379-415` admits clusters in incoming order and drops over cap. Assembly reads only those emitted records (`job.py:1258-1266`; `evidence.py:449-455`) before applying configured scope ranking/cap (`evidence.py:525-546`).
- **Trigger:** a tool has over 5000 distinct normalized clusters, with a later high-value finding; even `max_findings_per_scope=1000000` cannot recover it.
- **Expected / actual:** perform cross-scanner clustering/ranking before information-losing observation caps as T-170 specifies. Synthetic 5000 LOW observations followed by one CRITICAL at another location yielded raw=5001, per-tool=5000, final=5000, **CRITICAL absent** despite the million-record scope setting.
- **Impact:** a useful later observation/trace and its cross-scanner agreement may never reach the corroborator or downstream lead menu. A local count-bound gap does survive; this is **not** an assertion the drop is wholly unreported.
- **Confidence:** high; real normalizer/corroborator reproduced. Probe deliberately omitted native refs to isolate transform order; its provenance-unavailable gap is not production evidence.
- **Smallest correction:** move cross-tool normalization/ranking before the lossy per-tool count cap, or give it a bounded retained-record stream independent of the published per-tool cap. Preserve byte/resource bounds and explicit omitted counts.
- **Overlap:** **existing C09-F03** (arrival-order truncation) in `docs/reviews/system-review-2026-11-13.md:1639-1649`; **T-170 marked done** at `docs/TODO.md:2799-2806`, but current pipeline does not fulfill the pre-cap cross-scanner objective. Do not count as entirely new.

### EC-03 — Medium — Greedy CWE clustering is order-dependent, changing counts and identities

- **Evidence:** `src/appsec_review/jobs/job_evidence_collection/evidence.py:248-256,337-364` chooses the first intersecting/bucket candidate, widens only it, and never merges another now-connected cluster. Same pattern exists across envelopes (`:466-484`).
- **Trigger:** three same-file, same-CWE observations at lines 1, 4 and 6 in different native report orders.
- **Expected / actual:** a stable clustering policy over the same observation set. Actual `(1,4,6)` → **one** span `(1,6)`; `(6,1,4)` → **two** spans `(4,6)` and `(1,1)`.
- **Impact:** counts, provenance grouping, cluster IDs and competition for caps depend on native result arrival order; consistent reprocessing and agreement ranking are not guaranteed.
- **Confidence:** high; pure real-function reproducer.
- **Smallest correction:** deterministically sort observations and define/implement a canonical grouping policy (e.g. connected interval/bucket groups), including merging multiple connected existing groups; test permutations of the same records.
- **Overlap:** related **T-170**; no matching order-dependence finding/TODO found in searched reports.

### EC-04 — Medium — Final not-applicable totals are recomputed from truncated detail samples

- **Evidence:** `src/appsec_review/tool_inputs.py:179-187` preserves full count but only 200 items per tool. Assembly uses `skipped["count"]` for per-tool dispositions yet concatenates only `skipped["items"]` (`src/appsec_review/jobs/job_evidence_collection/job.py:1243-1252`), then re-summarizes that sample (`:1292`).
- **Trigger:** any scanner has more than 200 skipped inputs (unsupported paths, Checkov unreported files, OSV no-package lockfiles).
- **Expected / actual:** final full total remains the sum of tool totals with bounded/truncated detail. A 250-input tool summary has count=250/truncated=true; the same final re-summary path yields **count=200/truncated=false**, although disposition count remains 250.
- **Impact:** published handoff counts contradict its dispositions and falsely describe complete detail. Operators cannot reconcile planned/scanned/skipped totals.
- **Confidence:** high; real shared-helper chain reproduced and assembly call sites traced.
- **Smallest correction:** aggregate full counts and by-reason counters separately from bounded samples; carry any upstream truncation to final summary.
- **Overlap:** no matching TODO/prior finding found; T-157 is declarative applicability metadata, not this numerical bug.

### EC-05 — Medium — Directory scanners do not enforce the accepted path selection

- **Evidence:** handler extracts accepted scope (`src/appsec_review/jobs/job_evidence_collection/job.py:1347-1356`), but Gitleaks and Syft argv ignore `selection.files` and scan `/target` (`src/appsec_review/jobs/job_evidence_collection/adapters.py:1061-1064,1100-1102`). `job.py:609-644` stages an exact subset only for the special disabled-Swift-present path; ordinary execution mounts the complete target (`src/appsec_review/container_runtime/executor.py:173-199`).
- **Trigger:** an accepted plan selects a subset, or the catalog excludes paths still present in the target directory. `validate_plan` checks each selected path/hash but does not require all-directory equality (`planning.py:827-845`).
- **Expected / actual:** scope/path provenance should describe the actual input set. Real fake-executor Gitleaks path: envelope declares only `selected.txt`, but launch is `dir /target` and the mounted target also contains `excluded.txt`.
- **Impact:** scanner can inspect/emit results from uncataloged or unselected files, producing unresolved/out-of-scope observations or spending work outside declared coverage. This is a functional scope/provenance mismatch, not a target-security claim.
- **Confidence:** high for request/mount behavior; no actual Gitleaks/Syft run performed. Syft's intentional directory semantics are acknowledged.
- **Smallest correction:** either materialize a hash-checked accepted directory snapshot for directory scanners or explicitly model/validate the whole directory as the admitted scope (including required package context). Do not label a path subset as the complete executed scope.
- **Overlap:** no identical finding found; historical C09-F02 concerned scanner suppression policy, which this finding does not reopen.

### EC-06 — Medium — Corroboration/disposition consumers read fields removed by handoff projection

- **Evidence:** publisher returns `corroborated_sast_evidence`, `telemetry`, `dispositions` and also writes them to its domain artifact (`src/appsec_review/jobs/job_evidence_collection/job.py:1377-1396`). `src/appsec_review/runtime/runner.py:819-823` projects only `interchange.UNIT_OUTPUT_KEYS` (`src/appsec_review/interchange.py:110-115`), which excludes all three.
- **Downstream:** `job_review_prioritization/composite.py:564-585` looks for the corroboration reference directly in projected unit output, never follows the domain handoff artifact. Even with an unprojected reference it reads `cluster.path/start_line`, while the producer emits `cluster.location` (`evidence.py:550-558`). `job_review_data_indexing/job.py:425-430` similarly reads projected assembly `dispositions`, defaulting to `[]`; `indexing/sast.py:100-102` therefore cannot use them.
- **Expected / actual:** consumers read the persisted domain artifact using its pinned reference and correct cluster schema. Projection probe retained only `artifact,gaps,index_manifest,item_count,schema`. Real `_collect_sast_spans` returned `{}` for a valid location-bearing corroboration document both with projected output and with an artificially supplied raw-result reference (shard enumeration faked empty to isolate this route).
- **Impact:** explicit corroboration-product and scanner-disposition routes are ineffective. Ordinary observation-shard fallback remains and can recover basic spans/partial rows; this is not a claim all SAST evidence disappears.
- **Confidence:** high static boundary mismatch and bounded reader reproduction; no full runner publication executed.
- **Smallest correction:** consume `publish_handoff`'s pinned domain artifact for these payload fields, read `cluster.location`, and test actual runner-projected handoffs rather than direct task return dictionaries. Do not casually widen the standardized control projection.
- **Overlap:** **T-170/T-171** related delivery promises; T-147 generic documentation bindings. No identical current job-audit finding found.

### EC-07 — Medium — Cppcheck compile-database mode claims selected units it does not submit

- **Evidence:** natural selection includes all C/C++ selected files (`src/appsec_review/jobs/job_evidence_collection/adapters.py:226-259`); prerequisite sanitization keeps only entries actually present in the compile database (`src/appsec_review/jobs/job_evidence_collection/job.py:311-336`); project-mode argv omits all remaining selected files (`adapters.py:267-270`); evidence coverage still lists the original selection (`job.py:478-482`).
- **Trigger / reproduction:** accepted files `a.c,b.c`; compile database contains only `a.c`. Claimed paths remain both files, staged database contains only `a.c`, argv contains only `--project=/inputs/compile_commands.json`, and selection gaps are empty.
- **Expected / actual:** do not count absent translation units as submitted; scan remaining selected units separately or explicitly gap them. Sanitized driver/flag loss was also observed (`cc -DMODE=1 a.c` → `c++ /target/a.c`), but this audit does not claim experimentally verified C-vs-C++ parser behavior.
- **Impact:** selected source can be unscanned without a file-specific gap. The generic source-mode limitation is not an accounting substitute.
- **Confidence:** high, actual applicability/prerequisite/argv functions reproduced.
- **Smallest correction:** reconcile selected translation units with sanitized entries and explicitly scan or gap the remainder; identify removed build context separately. No execution of captured compile commands is needed or recommended.
- **Overlap:** **existing C09-F04**, `docs/reviews/system-review-2026-11-13.md:1651-1659`; not a new discovery. **T-5018** config profile work does not repair this scope mismatch.

## Other verified limits and documentation/test drift

- Missing `--dataflow-traces` in both actual Semgrep-family argv (`adapters.py:1065-1076`): parser tests inject traces/SARIF; production argv requests JSON without this flag. **T-126** already names trace-request flags as prerequisites (`docs/TODO.md:2037-2044`). No scanner was run to establish trace yield; T-170's parser success is not proof of end-to-end trace preservation.
- T-170 file `test_taint_and_corroboration.py` is **absent from `tests/job-test-map.json:302-318`**; it was discovered, fully read and explicitly included here. The mapped `tests/unit/runtime/test_wave5_contracts.py` mostly concerns target-catalog and language-build legacy strictness; relevant portions inspected but not executed as unrelated to this job's behavior.
- `config/cppcheck.py:7-9` suggests profile-layer widening, while current operations page/TOML say recipe-only and forbid profile/overlay semantic edits. No profile/overlay-specific tests were run in this audit. T-5018 remains open partly pending the next authorized smoke; this is not evidence the already-present typed profile is missing.
- Old report C09-F05's demand to hash supplied rules during customer prerequisites conflicts with current deliberate `supplied_platform`/release policy and its tests; it is **not re-reported** as a defect. Old C09-F01 zero Rust/Ruby rules and C09-F18 all-ecosystem mounts were not blindly copied; current code has expanded rules support and needed-ecosystem filtering respectively.
- Blint only checks whether **any** analyzed metadata exists, not equality with all requested binaries; duplicate-basename report behavior and subset analysis need captured native-output testing. Numeric SpotBugs priorities, native Psalm/zizmor formats, PMD top-level processing errors, Go loader errors, symlink/large-tree behavior remain **unproven native compatibility/coverage risks**, not additional confirmed findings.

## Focused validation — exact commands and outcomes

All Linux scripts below were transported from PowerShell as:

```powershell
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

### Preflight

```bash
cd /home/wsollers/projects/appsec-review
git --no-pager status --short
git rev-parse HEAD
git branch --show-current
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD
git --no-pager branch --list
git --no-pager log --all -4 --oneline --grep='evidence.collection\|T-170\|T-5021'
.venv/bin/python -c 'import os; from tests.test_000_unit_environment_guard import offending_environment; print("unit_environment_offences=", offending_environment(os.environ))'
```

All succeeded; no Git status entries, expected HEAD/main/import path, `unit_environment_offences=[]`. History included `3c76b820e`, `e007c15cc`, `7c9dcdc5b`, `7dce14645`; no modification/integration attempted. These were identity/inspection commands, not timed test runs.

### Collection

```bash
set -eu
cd /home/wsollers/projects/appsec-review
start=$(date +%s)
.venv/bin/python -m pytest --collect-only -q -o addopts= --basetemp=test/tmp/job-audit-evidence-20261118-collection-a tests/test_000_unit_environment_guard.py tests/unit/job_evidence_collection/test_contract.py tests/unit/job_evidence_collection/test_evidence.py tests/unit/job_evidence_collection/test_adapters.py tests/unit/job_evidence_collection/test_cppcheck_profile.py tests/unit/job_evidence_collection/test_rulepacks_and_checkpoints.py tests/unit/job_evidence_collection/test_job_graph.py tests/unit/job_evidence_collection/test_taint_and_corroboration.py | tail -5
printf 'collection_shell_elapsed_seconds=%s\n' "$(( $(date +%s) - start ))"
```

**110 collected in 2.59 s**, shell 4 s; output showed no collection error. This pipeline did not use pipefail; the subsequent supervised wrapper independently confirmed exact successful collection.

### Shuffled, two-worker execution

```bash
set -eu
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
start=$(date +%s)
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 1919 --max-tests 110 --expect-tests 110 --timeout-seconds 180 -- tests/test_000_unit_environment_guard.py tests/unit/job_evidence_collection/test_contract.py tests/unit/job_evidence_collection/test_evidence.py tests/unit/job_evidence_collection/test_adapters.py tests/unit/job_evidence_collection/test_cppcheck_profile.py tests/unit/job_evidence_collection/test_rulepacks_and_checkpoints.py tests/unit/job_evidence_collection/test_job_graph.py tests/unit/job_evidence_collection/test_taint_and_corroboration.py
printf 'validation_shell_elapsed_seconds=%s\n' "$(( $(date +%s) - start ))"
```

**Exit 0; 110 passed, 8.92 s pytest, 18 s shell; zero failed/error/skipped/slow cases.** Wrapper collection/execution cleanup both confirmed, zero remaining processes. No baseline suppression.

Wrapper-owned run stem:
`test/tmp/tests-custom-20261118-122658-026954-2868405`

- basetemp: that exact stem; unique microsecond/PID identity, not the shared default.
- junit: `<stem>.junit.xml`; timings: `<stem>.timings.sqlite`; collection manifest: `<stem>.collection.json`.
- execution/collection logs: `test/tmp/logs/tests-custom-20261118-122658-026954-2868405{,.collection}.log`.
- persisted report: `test/tmp/reports/tests-custom-20261118-122658-026954-2868405.json` (read back, exit_code 0, counts and command verified).

### Probe P1 — parser shapes, order, cap chain, skip counts

Executed `.venv/bin/python - <<'PY'` with the following complete body, from the authorized checkout; exit 0, body elapsed **0.901486 s**, no files written:

```python
import json, time
from pathlib import Path
from appsec_review.jobs.job_evidence_collection.adapters import ADAPTERS
from appsec_review.jobs.job_evidence_collection.evidence import build_envelope, corroborate_sast_records
from appsec_review.tool_inputs import not_applicable_summary
start=time.perf_counter()
wrong={}
for tool, adapter in ADAPTERS.items():
    payload=b'<unexpected/>' if tool in {'tool-cppcheck','tool-spotbugs'} else b'{"error":"analysis failed"}'
    try:
        out=adapter.parse(payload)
        wrong[tool]={'observations':len([r for r in out if not r.get('gap_only')]),'diagnostics':len([r for r in out if r.get('gap_only')])}
    except ValueError:
        wrong[tool]='rejected'
print('error_shaped_reports=',json.dumps(wrong,sort_keys=True))
def env(observations):
    return build_envelope(tool={'id':'tool-semgrep'},target_fingerprint='f'*64,applicability={'applicable':True},coverage_scope={'kind':'source_files'},gaps=(),raw_artifacts=(),parser_identity='undeclared',observations=observations,cataloged_paths=['src/a.py'],terminal_status='SUCCEEDED',run_root=Path('.'))
def finding(line,rule='test-CWE-78', severity='LOW'):
    return {'rule_id':rule,'message':str(line),'path':'src/a.py','start_line':line,'end_line':line,'category':'source_sast','severity':severity}
for lines in [(1,4,6),(6,1,4)]:
    out=env([finding(n) for n in lines])
    print('greedy_order=',lines,'records=',out['record_count'],'spans=',[(r['location']['start_line'],r['location']['end_line']) for r in out['records']])
obs=[finding(i*10+1,rule=f'custom-rule-{i}') for i in range(5000)]
obs.append(finding(50011,rule='last-critical-CWE-78',severity='CRITICAL'))
a=env(obs)
b=corroborate_sast_records({'tool-semgrep':a},target_fingerprint='f'*64,max_findings_per_scope=1000000)
print('cap_chain=',json.dumps({'raw':a['telemetry']['raw_scanner_findings'],'per_tool_count':a['record_count'],'configured_cross_cap':b['max_findings_per_scope'],'cross_count':b['cluster_count'],'critical_present':any(r['severity']=='CRITICAL' for r in b['clusters']),'terminal':a['terminal_status'],'gaps':a['exclusions_and_gaps']}))
first=not_applicable_summary({'tool':'tool-shellcheck','path':f'f{i}.bat','reason':'unsupported'} for i in range(250))
second=not_applicable_summary(first['items'])
print('skip_summary_chain=',json.dumps({'tool':{k:first[k] for k in ('count','truncated')},'published':{k:second[k] for k in ('count','truncated')}}))
print('pure_reproducer_elapsed_seconds=',round(time.perf_counter()-start,6))
```

Outputs are reported exactly in EC-01/02/03/04; 20 parser shapes tested, none rejected, blint alone supplied a diagnostic.

### Probe P2 — real scan/normalize/index with fake execution; scope/prerequisites

Executed `.venv/bin/python - <<'PY'` with the following complete body; exit 0, body elapsed **0.435359 s**. Only the unique audit directory under `test/tmp/` was created; `finally` removed it. FakeExecutor never launches Docker or a scanner.

```python
import json, os, shutil, sqlite3, time
from pathlib import Path
from dataclasses import replace
from appsec_review.jobs.job_evidence_collection import job
from appsec_review.jobs.job_evidence_collection.adapters import ADAPTERS, Applicability
from tests.unit.job_evidence_collection.support import ROOT, FakeExecutor, make_unit_context, attempt_scope
os.umask(0o022)
base=Path('test/tmp/job-audit-evidence-20261118-repro-a').resolve()
base.mkdir(exist_ok=False)
start=time.perf_counter()
try:
    cases=[('shell-error-object','tool-shellcheck','source_sast.shellcheck_scan',{'run.sh':'#!/bin/sh\necho ok\n'}, {'error':'scanner failed'},0),
           ('phpstan-errors','tool-phpstan','source_sast.phpstan_scan',{'app.php':'<?php echo 1;\n'}, {'totals':{'errors':1,'file_errors':0},'files':{},'errors':['No files found to analyse.']},1),
           ('shell-truncated-field','tool-shellcheck','source_sast.shellcheck_scan',{'run.sh':'#!/bin/sh\necho ok\n'}, {'comments':[{'file':'/target/run.sh','line':2,'endLine':2,'code':2086,'level':'warning','message':'x'*9000}]},1)]
    for name, tool_id, unit_id, target, payload, code in cases:
        unit,cat,_=make_unit_context(base/name,unit_id=unit_id,target_files=target,settings_override={'tool_retries':0})
        class FakeReport(FakeExecutor):
            def execute(self,request):
                res=super().execute(request)
                (self.run_root/res.stdout_path).write_text(json.dumps(payload),encoding='utf-8')
                return replace(res,exit_code=code)
        with attempt_scope(unit):
            result=job._execute_tool(unit,ADAPTERS[tool_id],cat,lambda u:FakeReport(ROOT,u.job.run_root,[]),None)
        unit.output=lambda _:result
        normalized=job._normalize_tool(unit,'scan')
        unit.output=lambda _:normalized
        indexed=job._build_producer_shard(unit,'normalized')
        with sqlite3.connect(unit.job.run_root/indexed['artifact']['path']) as db:
            coverage=db.execute('SELECT area,status,gap FROM coverage').fetchall()
        print('fake_execution=',json.dumps({'case':name,'terminal':result['terminal_status'],'records':result['record_count'],'gaps':result['gaps'],'shard_coverage':coverage}))
    unit,cat,_=make_unit_context(base/'scope',unit_id='secrets.gitleaks_scan',target_files={'selected.txt':'test\n','excluded.txt':'test\n'},settings_override={'tool_retries':0})
    captures=[]
    class ScopeCapture(FakeExecutor):
        def execute(self,request):
            captures.append({'argv':list(request.argv),'excluded_path_in_mount':(request.target_root/'excluded.txt').exists()})
            return super().execute(request)
    with attempt_scope(unit):
        result=job._execute_tool(unit,ADAPTERS['tool-gitleaks'],cat,lambda u:ScopeCapture(ROOT,u.job.run_root,[]),None,Applicability(True,'selected subset',('selected.txt',),'cataloged_repository'))
    envelope=json.loads((unit.job.run_root/result['artifact']['path']).read_text())
    print('selected_scope_request=',json.dumps({'coverage_scope':envelope['coverage_scope'],'capture':captures}))
    unit,cat,_=make_unit_context(base/'cpp',unit_id='source_sast.cppcheck_scan',target_files={'a.c':'int a;\n','b.c':'int b;\n'})
    (unit.job.target_root/'compile_commands.json').write_text(json.dumps([{'directory':str(unit.job.target_root),'file':'a.c','arguments':['cc','-DMODE=1','a.c']}]))
    cat=replace(cat,compile_commands=({'path':'compile_commands.json'},))
    selection=ADAPTERS['tool-cppcheck'].applicability(cat)
    actual,mounts,_,blocked=job._prerequisites(unit,ADAPTERS['tool-cppcheck'],selection)
    entries=json.loads(next(m.source for m in mounts if m.target=='/inputs/compile_commands.json').read_text())
    print('cpp_scope=',json.dumps({'claimed_paths':list(actual.files),'staged_entries':entries,'gaps':actual.gaps,'blocked':blocked,'argv':ADAPTERS['tool-cppcheck'].argv('cppcheck',actual)}))
    print('fake_reproducer_elapsed_seconds=',round(time.perf_counter()-start,6))
finally:
    shutil.rmtree(base)
```

The three scan cases returned SUCCEEDED, counts 0/0/1, and `complete/null` shard coverage respectively. Gaps were `[]`, the Composer limitation, and normalized-field truncation respectively. Scope and Cppcheck outputs are recorded in EC-05/07.

### Probe P3 — projected payload and real corroboration reader

Executed `.venv/bin/python - <<'PY'` with this complete body; exit 0, body elapsed **0.001664 s**, no files written:

```python
import json,time
from pathlib import Path
from unittest.mock import patch
from appsec_review.interchange import UNIT_OUTPUT_KEYS
from appsec_review.jobs.job_evidence_collection.evidence import corroborate_sast_records
from appsec_review.jobs.job_review_prioritization import composite
start=time.perf_counter()
doc=corroborate_sast_records({'tool-semgrep':{'records':[{'category':'source_sast','native_rule_id':'CWE-78','message':'synthetic','severity':'HIGH','location':{'path':'src/a.py','start_line':10,'end_line':12}}]}},target_fingerprint='f'*64)
raw={'schema':'appsec-review/evidence-collection-handoff/1','artifact':{'path':'data/handoff.json','sha256':'a'*64},'index_manifest':{'path':'data/manifest.json','sha256':'b'*64},'corroborated_sast_evidence':{'path':'data/corroborated.json','sha256':'c'*64},'telemetry':doc['telemetry'],'dispositions':[{'tool_id':'tool-semgrep','terminal_status':'SUCCEEDED'}],'gaps':[],'item_count':1}
projected={key:raw[key] for key in UNIT_OUTPUT_KEYS if key in raw}
print('handoff_projection=',json.dumps({'retained':sorted(projected),'dropped':sorted(set(raw)-set(projected))}))
for label,out in [('real_projection',projected),('unprojected_producer_result',raw)]:
    with patch.object(composite,'has_handoff',return_value=True),patch.object(composite,'accepted_handoff',return_value=({'outputs':{'evidence_publication.publish_handoff':out}},'d'*64)),patch.object(composite,'read_json',return_value=doc),patch.object(composite,'producer_entities',return_value=()):
        print('corroborated_consumer=',label,composite._collect_sast_spans(Path('.'),{}, {'semgrep':True}))
print('boundary_reproducer_elapsed_seconds=',round(time.perf_counter()-start,6))
```

This reproduces the projection rule and real reader behavior with I/O boundaries faked; it is **not** a JobRunner admission test.

### Inspection failures and hygiene

No validation command failed. Initial inventory probes had harmless inspection failures: nonexistent `adapters/*.py` (adapters is one file), guessed `config/` and `schemas/` directories, unavailable Linux `rg`, and an old T-170 task-doc filename. Subsequent UNC searches and actual `docs/schemas`/central TOML/current task-doc reads resolved them; no install or edit was made. A too-large initial operations-page read was replaced by full ranged reads.

Final `git rev-parse HEAD` / `git --no-pager status --short` again showed exact revision and clean status. Repository-root listing inspected; no root files were created by this audit. Existing root `.coverage` and `wsl-git-connectivity-probe.txt` were not created, modified, or removed. Audit-owned P2 scratch was removed; test logs/reports remain under the wrapper's unique `test/tmp` stem for evidence.

## Read/unread evidence matrix

| Scope | Read/executed status |
| --- | --- |
| Root guidance and relevant skills | Full authorized `AGENTS.md`, multi-session coordination skill, shared audit brief; canonical skill descriptions listed. No runtime skill treated as instructions. |
| Entire owned job implementation | **Fully read:** all five package files (`__init__.py`, `job.py`, `adapters.py`, `evidence.py`, `datasets.py`), including every handler and parser. |
| Typed settings and immediate helpers | **Fully read:** `config/evidence_collection.py`, `config/cppcheck.py`, `runtime/consume.py`, `tool_inputs.py`, `osv_offline.py`, `blint_report.py`. Loader job branch and container executor target validation sampled. |
| Owned unit coverage | **Fully read and executed:** seven job test modules plus full `support.py`; three root environment guards fully read/executed. Fixtures create only synthetic source/reports/feed zips and fake external execution. |
| Mapped extra runtime tests | `test_wave5_contracts.py` sampled (1–220 and 422–end, symbols searched), **not executed**; no job-specific behavior test there located. |
| Canonical job docs/schema | **Fully read:** operations page, corroborated-SAST JSON schema, T-170 current task doc. Job-interchange/input-contract architecture relevant sections read; not every architecture document. |
| Registration/config/topology/guidance | Registry matches and central TOML block read/searched; topology through typed contract and passing registry/topology unit. No job runtime guidance binding found. Container catalog relevant tool records sampled, not every lock/manifest/image recipe. |
| Output/admission/consumers | Actual runner projection, unit status summary, interchange controls, plan reader/validator, Syft/advisory consumer, corroboration/span consumer and scanner-correlation disposition handling sampled. Full runtime admission/artifact closure/equivalence/provenance modules and all downstream job bodies **not read end-to-end**. |
| Prior work | TODO relevant entries T-013/T-126/T-147/T-157/T-170/T-171/T-5018/T-5021; system review C09 relevant ranges; cumulative/prior session reports searched for symptoms. No historical report accepted as current proof without source/probe comparison. |
| Native-tool matrix — **material unread/unexecuted** | Actual outputs for Gitleaks, Semgrep, OpenGrep, gosec, MobSFScan, ShellCheck, PHPCS, PHPStan, Psalm, SpotBugs, Cppcheck, PMD, Syft, OSV, Grype, Hadolint, Checkov, Trivy, zizmor, blint; native version/error/empty/truncated schemas not independently captured. Per-rule detection quality and package/advisory accuracy unverified. |
| Runtime matrix — **material unexecuted** | All 62 tasks through a real JobRunner/typed claim; disabled whole-job propagation; active guardian stop, feed/image verification, process/OOM/timeouts, concurrent checkpoints, cross-attempt repair, publication rollback, complete dataset artifact closure, every downstream consumer. Some direct fake-unit paths pass; that is not full-runtime coverage. |
| Scale/input matrix — **material unverified** | Full ecosystem/language/platform/native-format combinations; large native report parsing memory, huge reference sets, batch-isolation recovery, all symlink/changed-file paths, native binary basename collisions, unsupported/partial files within nonempty scanner output. P1 synthetic 5001-record transform is not a scale benchmark. |
| Integration/acceptance/live | All mapped paths intentionally unexecuted and not used as output-quality evidence. No actual runs, user targets, or answer keys read. |

**Stop condition met:** one-job read-only audit completed, report persisted. No repair or additional job audit started.
