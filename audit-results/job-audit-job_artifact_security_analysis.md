# Job 18/47 — job_artifact_security_analysis

## Scope, source, and outcome

- Audited the clean WSL checkout `/home/wsollers/projects/appsec-review`, branch `main`, **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**. HEAD, ancestor containment, cleanliness, and the editable import were verified. Final HEAD and cleanliness were unchanged.
- Linux execution used `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu`; source reads used the corresponding Ubuntu-22.04 UNC checkout, never the different Windows working checkout.
- Functional correctness audit only. No source/environment installation or configuration edits, real scanner/provider launches, services, target programs, integration/live/acceptance runs, or subagents.
- **50 existing focused units passed**, no failures/skips/slow cases; additional bounded reproductions established the findings below. Passing these units does not establish correct live scanner output.
- **Three high and seven medium finding groups**: nine functional defects and one explicitly distinguished unwired-capability/implementation-claim gap (ASA-F06). ASA-F08 concerns the immediate prioritization consumer, not loss from the original artifact index.

## Registration, contract, configuration, and publication

`runtime/registry.py:84,154` imports/registers the job. The actual registry has 47 jobs; the projected review-graph predecessor is exactly `job_artifact_indexing`. `datasets.py:38-78` declares `REVIEW_GRAPH`, checkout target access, propagation enabled, and `always_execute=False`. `orchestration/topology.py:46-80` derives dependencies from contracts and reduces transitive edges. The alternative project-build graph additionally waits for debug-symbol indexing when present (`orchestration/dagster/adapter.py:501-506`). The dev recipe enables the job.

All fourteen units are constructed at `job.py:826-836`. There is no model call, task prompt, persona, or runtime-skill load in these handlers. The guidance registry contains no artifact-security binding. Missing generated task/tool declarations remain the already-open **T-147**, not evidence that scanners do not execute.

### Accepted inputs

All requirements use the handoff channel, producer-evidence authority, and allow-partial coverage:

| Producer | Required/reject | Optional/gap | Actual use |
|---|---|---|---|
| `job_artifact_indexing` | `handoff` (`job-handoff/2`), `artifact_index_summary` (`artifact-indexing/1`) | `artifact_catalog`, `archive_members`, `artifact_relationships` (`retrieval-index/2`) | Loader verifies accepted summary binding, hash/schema and full manifest; this job compares language handoff/snapshot, retains index identity, and admits target-intake artifacts. It does not independently query every optional index. |
| `job_language_build` | `handoff` (`job-handoff/2`), `language_build_receipts` (`language-build-handoff/2`) | `topology_refinement_inputs` (`build-topology-refinement/1`), `build_actions`, `jvm_build_actions` (`retrieval-index/2`), `build_workspaces` (`application/octet-stream`) | Receipt artifacts supply actual bytes and producer/build identities; optional declarations do not prove those datasets were read. |

`job.py:86-152` verifies matching snapshot/build lineage, manifest hash, each artifact's path/hash/optional size, canonical identity, and platform exclusion. Build artifacts deduplicate on retained `(sha256,path)`, not basename/content alone. Target intake requires unknown scope, matching catalog provenance, canonical identity, and content-addressed custody. Structured upstream producer gaps are converted with `gap_text`; delivery-unknown and no-artifact cases remain gaps.

**Existing read-accounting limitation, not counted again:** the shared accepted-language and artifact-index loaders directly open payload JSON rather than `observe_output` for those payload datasets (`job_language_build/job.py:127-173`, `job_artifact_indexing/job.py:958-976`). The inspected real unit receipt from this audit's publication test recorded only the two envelope reads, although it read the receipt set/summary. This repeats the prior language-build/artifact-index audit theme. `accepted_upstream` still enforces typed envelope permission and admitted handoff hashes. Hash checks are not absent.

### Central bounds and selection

`appsec-review.toml:1656-1705`: job/analyze concurrency 8 in the recipe; tasks default to one application worker. Audit tests used only two pytest workers. Job settings: timeout 600 s, retained diagnostic streams 8 MiB, tails 32 KiB, parser input 64 MiB, archive members 10,000, expanded bytes 512 MiB, member bytes 128 MiB, ratio 1,000, depth 4, OSV memory `3g`; six scanner identities are configured. `_validate_config` checks exact step/task order, required settings, positive integer bounds, scanner-identity mapping, and memory syntax (`job.py:556-573`).

Global `tools.disable_grype=true` and `tools.enable_cve_bin_tool=true` are honored before scanning/checkpoint reuse (`job.py:604-615`). Disabled capability results carry `CONFIGURED_DISABLED` events/gaps and `NOT_APPLICABLE`, not clean vulnerability coverage.

Delivery policy precedes format inspection (`jobs/delivery_scope.py:17-98`): target-lane artifacts are candidates; supply-chain artifacts use inventory/packages/Syft/Grype/OSV/CVE-bin-tool; runtime native dependencies additionally get blint; evidence-lane artifacts get inventory only. `tool_inputs.py:254-278,327-365` partitions external scanner inputs, preserving unsupported-input skips. OSV decides by original/presented filename and recognized offline lockfile ecosystem.

### Every step/task

Paths in this table are relative to `src/appsec_review/jobs/job_artifact_security_analysis/`.

| Unit | Actual implementation and outputs | Audit result / limit |
|---|---|---|
| `load.accepted_artifacts` | `job.py:594-599` → `_accepted_artifacts`; returns verified/sorted artifact rows, upstream identities/count, producer reasons. | Lineage/custody, empty input, platform exclusion, duplicate handling exercised by units. Shared payload-read accounting limitation above. |
| `analyze.inventory` | `job.py:601-717`, `_scan_one:336-553`; `formats.py:346-355` classifies every policy-allowed input and lists archive metadata. | ASA-F05/F06/F09; metadata traversal is not recursive nested-member analysis. |
| `analyze.native` | Same closure; native/.NET family gate; bounded ELF or PE/COFF facts (`formats.py:358-369`). | No built-in security-rule verdict; native symbols/hardening remain pinned-scanner gaps. Thin Mach-O reaches unsupported builtin fallback. ASA-F06 distinguishes unused new helper. |
| `analyze.jvm` | Same closure; JVM class version/header or archive metadata (`formats.py:370-379`). | Explicit pinned-rule gap except resource-only archive inventory; FAT Mach-O misroutes here (ASA-F05). |
| `analyze.packages` | Same closure; container/node/python/php gate; metadata reader (`formats.py:383-387`). | Named SBOM/vulnerability-data gap, not a synthetic dependency finding. ASA-F06/F09. |
| `analyze.wasm` | Same closure; `parse_wasm`, imports/exports/tables/memories/custom sections (`formats.py:256-343,380-382`). | Always retains separate policy-validator gap. Imported-resource summary facts wrong (ASA-F04). |
| `analyze.spotbugs` | JVM-class/archive support; pinned `tool-spotbugs`; XML file and BugInstance ordinal parser (`scanners.py:104-122,160-161`). | Exit 0 accepted; full output/timeout/schema concerns ASA-F02/F03; FAT binary wrongly selected (ASA-F05). |
| `analyze.blint` | Native/.NET/COFF/Mach-O/Android support; pinned `tool-blint`; directory report assembled by `blint_report.py`. | Per-binary metadata required; findings cite original `findings.json`; unexpected reports reject. ASA-F02/F05/F08. |
| `analyze.syft` | Any non-media artifact; pinned `tool-syft`, `file:/target/...`, JSON output. | Inventory only. Installer record staged as package-lock, dev dependencies explicitly included; covered anchors skipped, unreported anchors become gaps. ASA-F02/F03/F10. |
| `analyze.grype` | Any non-media artifact if enabled; pinned tool plus verified immutable DB/image release. | Installer-record optimization names dev-only omissions; disabled default honored. ASA-F02/F03/F07/F10. |
| `analyze.osv` | Supported lockfile names; pinned `tool-osv-scanner`; accepted exit 0/1; verified offline feed/ecosystem mounts and OSV memory. | Missing ecosystem precondition is gap; exact exit-128/no-package-sources is skip with retained closure. ASA-F02/F03/F10. |
| `analyze.cve_bin_tool` | Supported machine-code formats; pinned wrapper/offline flags, verified database/NVD lineage, accepted exit 0/1. | Positive native array results fail index provenance (ASA-F01); ASA-F02/F03/F05. |
| `index.observations` | `job.py:719-804`: split scans into summary/findings, bound to 5,000 findings, metadata gaps, verify native selectors, add artifact entities/OBSERVED_AT edges including installer anchors, compose/verify inherited manifest. | ASA-F01/F03/F07. Raw missing severity/subject are correctly preserved locally. Builtin/Syft inventory does not become ordinary vulnerability findings. |
| `acceptance.publish_handoff` | `job.py:806-826`: writes `accepted-analysis.json`, upstream identities, artifact/scan/finding counts, capability dispositions, installer coverage/reasons/manifest. | Any indexed reason makes completed-with-gaps. ASA-F07 can make reported finding count disagree with actual reused index; no independent reconciliation here. |

`_scan_one` fingerprints artifact/canonical/build/index identity, classification, delivery policy, resolved tool identity, component releases, parser/normalizer, settings, and installer presentation. Reuse verifies referenced raw/native artifacts. Raw diagnostic streams and parser-input bounds are independent. Parser/native truncation, no execution evidence, no exact parser bytes, unsupported outputs, failure/timeout, and missing blint analysis are generally retained as gaps. Active execution safety can stop before fallback publication; tests explicitly cover that behavior. ASA-F02/F03/F07 are exceptions to the intended bounds/completeness/cache behavior.

### Published datasets and immediate consumers

| Dataset | Owner/schema/location | Status |
|---|---|---|
| `artifact_security_results` | analyze; `artifact-security-observation/1`; `data/artifact-security/shards/*/*/result.json` | Actual writer/glob/schema agree; mutable retry defect ASA-F07. |
| `artifact_security_observations` | index; `retrieval-index/2`, `observations`, `artifact-security` shard prefix | Entities contain domain `artifact-security-record/2` plus common observation provenance; `query_artifacts`/precomputed routes. |
| `artifact_security_acceptance` | acceptance; `artifact-security-analysis/1`; attempt `artifacts/artifact-security/accepted-analysis.json` | Correct current split/ownership. Loader calls `observe_output`, checks handoff artifact membership/hash/schema (`job.py:576-590`). |
| `artifact_scanner_io` | analyze; protected `container-execution/1`; attempt `artifacts/asa/**` and `steps/analyze/tasks/*/containers/**` | Diagnostic/native/receipt files claimed; staging placeholder directories omitted (ASA-F10). |

Domain payloads are schema-ID-bearing records, not fully shape-validated scanner documents. Shared task/handoff/producer statuses and native references use runtime/interchange validation. No dedicated artifact-security JSON schema was found under `docs/schemas`; this is not itself called a defect, but generic JSON parsing does not validate a scanner's output contract (ASA-F03).

Eight direct consumer contracts reference this producer: CodeQL analysis, document issue analysis, inference review, OWASP controls, review data indexing, review package assembly, security tagging, and review prioritization. Seven have the exact result-schema/absence-of-unused-acceptance contract regression; prioritization is not included in that parametrized list. The operations acceptance loader has separate positive/negative permission tests.

`review/lead_families.py:470-515` deliberately promotes only finding records, never scan summaries, and uses artifact relations rather than invented source spans. `indexing/links.py:239-311`/`indexing/products.py:310-320` consume artifact scanner advisory projections. `retrieval/core.py:885-930` exposes bounded artifact facets. Prioritization's separate promoted-lead reader is incompatible with artifact-native locationless identities (ASA-F08). Full downstream jobs were not audited.

## Findings

### ASA-F01 — High — Every positive CVE-bin-tool array has a nonresolving native selector

- **Evidence:** `scanners.py:75-86` wraps a native JSON array as `{"records": ...}` only in normalized memory. `findings.py:229-259` generates `/records/<index>` pointers. `job.py:507-516,749-752` retains the original array bytes and validates finding provenance; `provenance.py:149-164` rejects nonnumeric array indexing.
- **Trigger:** supported binary produces at least one ordinary CVE-bin-tool JSON-array match.
- **Expected/actual:** a match references native `/0`; actual pointer `/records/0` raises **`ValueError: native JSON array index is invalid`** during indexing. Zero matches avoid the bug.
- **Impact:** successful scanner detection blocks artifact-security publication and downstream review instead of publishing its finding.
- **Reproduction:** real `_scan_one` → `scan_records` → `validate_observation_provenance`, fake scanner/receipt boundary: one finding, selector `/records/0`, exact error above.
- **Confidence:** high, reproduced. **Correction:** root-array selectors for native CVE-bin-tool records; regression must validate real retained native bytes through the index path, not only normalized dicts.
- **Overlap:** T-102 mentions the adapter/finder but does not record this defect; its “scanner deferred” wording is stale at this revision.

### ASA-F02 — Medium — Scanner adapter ignores execution bounds and eagerly reads unbounded report files

- **Evidence:** `job.py:430` passes configured timeout/stream limit. `scanners.py:268-269,318-330` never applies those parameters, submits no file-size bound, and calls `output.read_bytes()` before parser limits. `container_runtime/executor.py:40-58,295-302,319` uses catalog timeout/output limits; catalog defaults are 600 s/16 MiB (`containers/runtime-policy.toml:12-15`). Job diagnostic default is 8 MiB.
- **Trigger:** operator lowers job timeout/stream settings, or scanner writes a report beyond the configured parser bound.
- **Expected/actual:** execution and ingestion honor declared job bounds; actual request uses catalog values and no `file_size_limit_bytes`, and the entire native file is materialized before `_scan_one` rejects it.
- **Reproduction:** fake executor, requested timeout 1 s and stream limit 8 bytes: catalog remains 600 s/16,777,216 bytes; file limit `null`; 1,026 native bytes returned intact. This proves ignored dispatch/ingestion bounds, not an actual long-running scanner.
- **Impact:** jobs run longer/capture more than the selected bounds; arbitrarily large native files can exhaust application memory before the later bound check.
- **Confidence:** high on ignored parameters/eager read; no memory-exhaustion run attempted. **Correction:** one authoritative typed execution-limit path and bounded file read/stat before materialization; apply available execution file limits where appropriate.
- **Overlap:** no exact TODO found; T-010's broad bounded-scanning work is related, not this defect.

### ASA-F03 — Medium — Incompatible scanner JSON becomes a complete zero-finding scan

- **Evidence:** `scanners.py:75-86` accepts any JSON root; `ScannerAdapter.parse:163-164` has no per-tool structure validation. `findings.py:132-137,184-199,324-328,359-379` converts wrong collection types to empty lists, skips malformed entries, and infers completion from absent gaps.
- **Trigger:** accepted-exit Grype returns valid JSON with wrong-shaped/missing matches, e.g. `{"matches":"wrong-type","error":"database failed"}`. Related generic adapters share this structural blind spot; XML parsing likewise does not validate the expected root/error contract.
- **Expected/actual:** malformed/incompatible scanner output is a named parser/coverage gap; actual `_scan_one` returns `SUCCEEDED`, `gaps=[]`; summary has `scan_outcome=completed`, `findings_complete=true`, `finding_count=0`. Native provenance validation still passes because the document is retained correctly.
- **Impact:** incompatible/error-shaped output is indistinguishable from completed negative evidence.
- **Confidence:** high, reproduced for Grype; other adapter shapes are static exposure, not separately reproduced. **Correction:** validate each pinned tool's required container/record structure and preserve malformed-record omissions as gaps.
- **Overlap:** same broad theme as the prior CI audit, but this is independently reproduced artifact-scanner code, not a duplicate call site.

### ASA-F04 — Medium — Wasm resource/feature summaries omit imported memories and tables

- **Evidence:** `formats.py:289-310` retains memory/table imports only inside `imports`; `:337-343` derives `has_memory`, `has_tables`, shared-memory/memory64/reference-table/multi-memory flags only from locally defined lists.
- **Trigger:** valid module imports its memory and/or table rather than defining them.
- **Expected/actual:** resource presence/features account for imported and defined resources; an imported shared memory and externref table are retained in `imports`, but `has_memory=false`, `has_tables=false`, `shared_memory=false`, `reference_tables=false`.
- **Impact:** incorrect artifact capability facts reach retrieval/review even though the separate validator-policy gap remains explicit.
- **Confidence:** high, reproduced with a tiny valid import section. **Correction:** derive aggregate flags from both imported and defined resources while preserving their distinct provenance.
- **Overlap:** no exact TODO found; T-157 is metadata inventory, not this parser correction.

### ASA-F05 — Medium — Universal Mach-O files are classified as Java classes

- **Evidence:** `formats.py:48-55` checks thin Mach-O magics but assigns all `CAFEBABE` inputs to JVM. `tool_inputs.py:255-258,273-275` then excludes them from blint/CVE-bin-tool and includes SpotBugs.
- **Trigger:** a FAT_MAGIC universal Mach-O artifact, including accepted kind `executable`.
- **Expected/actual:** classify native fat Mach-O or explicitly distinguish unsupported native format; actual `format=jvm-class`, `family=jvm`, SpotBugs selected, blint/CVE-bin-tool skipped.
- **Reproduction:** structurally consistent one-slice fat header plus 64-bit Mach-O header; observed exact selection above. No binary executed.
- **Impact:** native coverage is lost or mislabeled not-applicable while an incompatible bytecode tool is selected.
- **Confidence:** high. **Correction:** bounded fat-header/architecture validation to distinguish shared magic; preserve real JVM classification and explicit unsupported handling.
- **Overlap:** no exact TODO found.

### ASA-F06 — Medium, implementation/coverage gap — New packaged-risk helpers never participate in a job task

- **Evidence:** `formats.py:416-452,454-539` implements packaged-config and ELF risk helpers; `__init__.py:6-7` exports them. Repository source search found no executing callers. `builtin_observation` (`formats.py:346-390`) never emits `security_risks`; `findings.py:262-291,359` only splits that field when already supplied. `test_lead_promotion.py:47-124` directly invokes helpers/injects risks, not the producing job path.
- **Expected/actual:** T-170's task document describes artifact/container defect promotion (`docs/tasks/2026-11-17-t170-sast-flows-dedupe-and-sca-reachability.md:27-29,50-54`); actual job cannot produce these newly introduced builtin packaged-risk records. Test config yields two helper risks versus zero pipeline risks; ELF helper yields four versus zero builtin risks.
- **Impact:** passing helper tests overstate the newly added extraction capability. Existing blint findings still get promotion; the pre-existing header-only builtin contract deliberately names pinned-scanner gaps and is not itself a false-negative verdict.
- **Confidence:** high on disconnection, qualified on intended activation. This is **not** a request to broaden worker authority or treat header heuristics as adjudication.
- **Correction:** reconcile the completed T-170 claim with an explicitly designed/validated bounded producer path, or mark this extraction capability deferred; test actual task-to-index wiring.
- **Overlap:** **T-170** is directly relevant and marked done; the test docstring incorrectly cites T-171 (which is prioritization wiring).

### ASA-F07 — High — Nonreusable reruns overwrite published result identities and reuse stale observation content

- **Evidence:** `job.py:342-346,375-388` disables checkpoint reuse without complete release identities, but `:551-553` overwrites the same input-fingerprint `result.json`. Index fingerprint uses only scan input fingerprints (`:722-729`), then reuses existing SQLite/manifest (`:737,778-799`) while recomputing current `finding_count` (`:800-803`).
- **Trigger:** same accepted input and settings are rescanned without required release identities; fake boundary returns no matches on attempt 1 and one match on attempt 2.
- **Expected/actual:** fresh result has immutable identity and current index. Actual second acceptance data reports one finding while reused SQLite has **zero**; scan/index fingerprints stay identical; attempt 1's referenced result file hash changes.
- **Impact:** silent loss/staleness of findings and invalidation of already-published artifact references. Even repeated deterministic observations can change result metadata/receipt bytes at that path.
- **Confidence:** high, reproduced using two distinct attempt claims, real `_scan_one`, real index handler/provenance/SQLite, unchanged upstream manifest, and fake scanner responses.
- **Correction:** separate immutable per-execution results from input cache lookup; key index materialization by immutable result content/identity and applicable coverage facts, or prohibit shard reuse for nonreusable rescans.
- **Overlap:** T-010/T-012 discuss cache/retry optimization and missing releases but do not identify stale index content or overwritten publication bytes. Related upstream language-build stale-index theme was not re-counted.

### ASA-F08 — Medium — Prioritization collapses different artifact findings and upgrades unknown severity

- **Evidence:** producer deliberately writes no source location (`job.py:757-766`). Consumer `job_review_prioritization/composite.py:404-443` derives IDs from `(path,line,rule,attack_class)`, ignoring original observation/subject/artifact identity; locationless findings share null path/line and overwrite in `leads`. `:429` invokes `_norm_severity(..., default="high")`; `:106-116` maps `unknown` to that default.
- **Trigger:** same hardening rule in two different binaries, or a lead-capable finding with missing scanner severity (the producer explicitly preserves `severity_hint="unknown"`).
- **Expected/actual:** two attributable leads and preserved uncertainty; reproduced two distinct artifact findings become one lead (“NX disabled: client”), with no subject identity. A separate unknown-severity input becomes `high`.
- **Impact:** composite prioritization loses per-artifact context and inflates uncertain severity. Original artifact index/common lead-family path still retains findings; this is not a claim that every inference route drops them.
- **Confidence:** high, reproduced real consumer with fake accepted-entity boundary. **Correction:** use retained observation/artifact/subject identity for lead keys, carry resolving artifact provenance, and retain unknown severity.
- **Overlap:** T-170/T-171 cover producer promotion/consumer wiring but no exact defect entry found.

### ASA-F09 — High — Negative ar member size makes the builtin archive reader stop making progress

- **Evidence:** `formats.py:155-156` parses signed size without a nonnegative check; special symbol-table entries bypass normal member-count accounting (`:179-192`); `:193-197` computes the next offset directly from that size.
- **Trigger:** malformed ar special member `/` with size `-60`. With the 60-byte header, next offset equals current offset.
- **Expected/actual:** bounded malformed-archive gap; actual parser repeatedly seeks offset 8 and never reaches the member limit. Inventory/package analysis can stall until outer cancellation/process termination.
- **Reproduction:** 68-byte in-memory ar file, real `inspect_archive`/`_ar_members`, fake file stream stopping after five seeks. Recorded offsets **`[8,8,8,8,8]`** despite the 10,000-member bound; no unbounded/hanging test was launched.
- **Confidence:** high. **Correction:** reject negative/invalid sizes and require advancing bounded offsets; apply iteration accounting to special entries as well.
- **Overlap:** no exact TODO found. This is malformed-input functional termination analysis, not a separate vulnerability hunt.

### ASA-F10 — Medium — Scanner staging files have no dataset owner

- **Evidence:** `scanners.py:280-297` creates empty mount placeholders under `target-inputs/<token>/` and `installer-records/<token>/`; `datasets.py:29-31` only claims `containers/**` and `artifacts/asa/**`. Runtime task declarations (`indexing/inventory.py:105-113`) do not cover staging directories. Full-tree auditing marks such files `unaccounted_file` (`:651-653`).
- **Trigger:** target-intake artifact or npm installer-record scanner invocation, even before successful external execution.
- **Expected/actual:** every produced run file has an owner; real runner staging plus fake executor generated both paths and real `FileClaims` returned no owner for either.
- **Impact:** strict/full-customer-evidence dataset audit can fail after otherwise correct scans. Managed accepted-publications-only audit deliberately excludes scratch, so that narrower mode is not claimed to fail.
- **Confidence:** high for ownership; downstream entire inventory job not executed. **Correction:** stage within declared protected scratch or add precise protected staging declarations/cleanup; test actual staging against dataset ownership.
- **Overlap:** T-147 broadly concerns task/dataset bindings; its earlier acceptance/result split is repaired, but it does not name these staging paths.

## Validation record

### Existing units

All commands ran from the exact clean WSL checkout and used its `.venv`. Environment-selector discovery found no inherited `APPSEC_*`, `DAGSTER_*`, `PYTEST*`, or `PYTHON*` variables. Unit-tier process/network/Dagster guards and existing xdist environment preflight remained enabled. No missing dependency was installed.

Exact selector array:

```bash
selectors=(
  tests/unit/job_artifact_security_analysis/test_contract.py
  tests/unit/job_artifact_security_analysis/test_formats.py
  tests/unit/job_artifact_security_analysis/test_findings.py
  tests/unit/job_artifact_security_analysis/test_scanners.py
  tests/unit/job_artifact_security_analysis/test_job_graph.py
  tests/unit/job_artifact_security_analysis/test_lead_promotion.py
  tests/unit/runtime/test_wave2_contracts.py::test_artifact_security_declarations_and_real_publication_ownership
  tests/unit/runtime/test_wave2_consumers.py::test_artifact_security_consumers_declare_exact_results_and_no_unused_acceptance
  tests/unit/runtime/test_wave2_consumers.py::test_artifact_security_acceptance_loader_and_admission_enforce_observe_output
)
timeout --kill-after=3s 27s .venv/bin/python -B -m pytest \
  --collect-only -q --basetemp=test/tmp/job-audit-asa-collect-20261118-1828 \
  "${selectors[@]}"
scripts/run-tests.sh --expect-tests 50 --max-tests 50 --parallel \
  --test-workers 2 --shuffle-seed 181847 --strict -- "${selectors[@]}"
```

- Standalone collection: **50 collected, 0.90 s**, exit 0.
- Wrapper preflight collection: **50**, **1.965 s** supervised stage.
- Execution: **50 passed in 10.12 s**; failures/errors/skips **0**, cases over 10 s **0**; wrapper supervised execution **14.137 s**, total **16.448 s**, exit 0. Cleanup confirmed no owned processes remained.
- Wrapper-owned unique session basename: `tests-custom-20261118-122814-141485-2877533`. The wrapper internally uses that same session's base for its collection and execution phases; neither phase shared another auditor's base. Standalone collection used the separate path above. This is the existing wrapper behavior, not a claim that it assigns different internal-phase bases.
- Evidence retained:
  - `test/tmp/logs/tests-custom-20261118-122814-141485-2877533.log`
  - `test/tmp/logs/tests-custom-20261118-122814-141485-2877533.collection.log`
  - `test/tmp/tests-custom-20261118-122814-141485-2877533.collection.json`
  - `test/tmp/tests-custom-20261118-122814-141485-2877533.junit.xml`
  - `test/tmp/tests-custom-20261118-122814-141485-2877533.timings.sqlite`
  - `test/tmp/reports/tests-custom-20261118-122814-141485-2877533.json`

`tests/job-test-map.json` declares the five main unit files and three runtime selectors above; `test_lead_promotion.py` exists but is omitted from the map. It was independently inspected and included. Three integration files and one acceptance selector were deliberately not executed.

### Cheap reproductions, commands, results, and failures

Each reproduction was transported as a base64-encoded Bash script through the same SSH command, executing **`.venv/bin/python -B - <<'PY' ... PY`** in the checkout. No reproducer source file was written. Synthetic state used only the unique `test/tmp/job-audit-asa-repro-20261118-{a,b,c,d}` roots; each was removed by `finally`. `os.fsync` was faked where publication tests wrote many tiny files; scanner/image/feed/executor and accepted-entity boundaries were fake. Parsing, normalization, identity derivation, native retention/selector verification, index materialization, and owner matching under test were real.

| Invocation | Outcome | Timed body elapsed |
|---|---|---|
| `...-a` | **Fixture setup failure before findings:** invalid guessed scope string `customer_deliverable`; real enum rejected it. No product defect inferred. Cleaned root. | 0.537 s |
| `...-b` | Reproduced F01/F02/F03/F04/F05/F06/F08. Later F07 setup failed because existing `_seed_artifact` supplies a noncanonical fixture identity; real index parser rejected it. No product defect inferred from that setup error. | 0.954 s |
| `...-c` | Corrected fixture with real `canonical_artifact_identity`; reproduced F07 and F09; exit 0. | 0.907 s |
| `...-d` | Reproduced F10 and F08 unknown→high; verified 47 registered jobs and graph predecessor; exit 0. | 0.709 s |

These timings cover the measured bodies, not SSH/module-import startup, and are not pytest counts. Exact behavioral outputs are recorded in each finding. The first two commands exited 1 for the disclosed fixture errors; they are not reported as wholly passing executions.

Core reproduction expressions sufficient to repeat the defects with the inspected existing fixtures:

```python
# Common setup: use a fresh test/tmp descendant; os.umask(0o022); remove it in finally.
from tests.unit.job_artifact_security_analysis.test_job_graph import _unit_context, _seed_artifact
from appsec_review.config.assurance import ScopeRole
from appsec_review.jobs.job_artifact_indexing import canonical_artifact_identity
from appsec_review.jobs.job_artifact_security_analysis import job as j, formats as fmt
from appsec_review.jobs.job_artifact_security_analysis.findings import scan_records
from appsec_review.provenance import validate_observation_provenance
from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner

ctx, events = _unit_context(run_root, declared_releases=False)
artifact = _seed_artifact(run_root, scope_role=ScopeRole.DELIVERABLE.value)
artifact["canonical_identity"] = canonical_artifact_identity("a"*64, "u1", artifact).value
# receipt_ref is path/hash of a tiny fake execution receipt in ctx.job.attempt_root.
def fake(payload, receipt_ref, code=0):
    return lambda *args: dict(stdout=b"", stderr=b"", exit_code=code,
                             payload=payload, execution_receipt=receipt_ref)

# F01: shared publication scope required for real native retention.
with publication_scope_for_owner(SharedArtifacts.for_job(ctx.job)):
    scan = j._scan_one(ctx, artifact, "cve_bin_tool", fake(
        b'[{"product":"zlib","version":"1.2.11","cve_number":"CVE-2018-25032","severity":"HIGH"}]',
        receipt_ref, 1))
    summary, findings = scan_records(scan)
    validate_observation_provenance(run_root, [summary.payload, *(f.payload for f in findings)],
                                   parser_identity=j.PARSER_IDENTITY)
# Raises native JSON array index is invalid.

# F03: same scope, fresh root:
scan = j._scan_one(ctx, artifact, "grype", fake(
    b'{"matches":"wrong-type","error":"database failed"}', receipt_ref))
summary, findings = scan_records(scan)
# SUCCEEDED / [] gaps / completed / findings_complete True / zero findings.

# F04: imports a shared memory (min 1/max 2) and externref table.
imports = b"\x02" + b"\x03env\x03mem\x02\x03\x01\x02" + b"\x03env\x03tab\x01\x6f\x00\x01"
value = fmt.parse_wasm(b"\0asm\x01\0\0\0" + bytes([2, len(imports)]) + imports)
# imports exist, but has_memory/has_tables/shared_memory/reference_tables are False.

# F05: no execution; classify these file bytes.
fat = (struct.pack(">II", 0xcafebabe, 1)
       + struct.pack(">IIIII", 0x01000007, 3, 28, 32, 0)
       + struct.pack("<IIIIIIII", 0xfeedfacf, 0x01000007, 3, 2, 0, 0, 0, 0))
# classify(..., {"kind":"executable"}) -> jvm-class.

# F09: actual parser with budgeted fake file, not a hung process.
header = f"{'/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{-60:<10}".encode() + b"`\n"
data = b"!<arch>\n" + header
seeks = []
class BudgetReached(RuntimeError): pass
class Stream(io.BytesIO):
    def seek(self, offset, *args):
        seeks.append(offset)
        if len(seeks) > 4: raise BudgetReached
        return super().seek(offset, *args)
class File:
    def stat(self): return type("Stat", (), {"st_size":len(data)})()
    def open(self, *args): return Stream(data)
fmt.inspect_archive(File())  # budget reached; seeks == [8,8,8,8,8].
```

Other reproduction setup details:

- **F02:** `ContainerScannerRunner` with `identity=lambda ...: {"scanner":"fixture"}`; replace its executor with a callback capturing the real `ExecutionRequest`, writing `output.json = b" "*1024+b"{}"` and empty stream/fake receipt files, returning an `ExecutionResult`-shaped namespace. Call `runner("syft", path, artifact, 1, 8)`. Inspect captured request/catalog and returned payload.
- **F06:** make a ZIP containing `Dockerfile` text `FROM base\nUSER root\nEXPOSE 9229\n`. Compare real inventory's absent `security_risks` with `inspect_packaged_text_risks` (two). Use existing `_minimal_elf64()` fixture for helper/native comparison (four versus none).
- **F07:** construct a real empty artifact SQLite shard/manifest with `IndexBuilder`/`write_manifest`; route `ctx.output` to that loaded manifest and capability outputs. In two separate attempt publication scopes, invoke `_scan_one("grype")` with `{"matches":[]}` then one ordinary CVE match; create attempt 2 claim using its actual new `attempt_id/attempt_path`. Invoke actual `index.observations` after each. Compare result references, returned index identities, and SQL `SELECT payload_json FROM entities WHERE kind='tool_observation'`: same index, second reported count 1, actual finding count 0, old result hash changed.
- **F08:** patch only `composite.has_handoff`, `accepted_handoff`, and `producer_entities` to supply accepted-boundary fixtures. Two `CHECK_NX` findings with different `subject_artifact`/`subject` and `location=None` yield one `_load_artifact_leads` row. Repeat with one lead's `severity_hint="unknown"`/`severity=None`: output is `high`.
- **F10:** fake scanner identity and executor that raises a sentinel at invocation. Call the real runner once with installer-record metadata and once with target-intake original name. Both stage empty package-lock placeholders. Combine `runtime_claims` and actual job DATASETS in `FileClaims`; `.file(relative_path)` returns `None` for both.

Other non-test command failures, disclosed for completeness: Linux `rg` was unavailable (exit 127); subsequent source searches used the UNC `rg` tool. An initial registry read used `registry.job_ids` rather than `registry.job_ids()` (TypeError, exit 1); corrected in the final topology probe. Neither implies a product/test failure.

## TODO overlap, documentation drift, and read limits

- Read/search overlap: prior cumulative report and artifact-index/language-build report boundaries; T-010/T-012 cache/installer follow-ups, T-102 scanner/finder, T-147 publication/task declarations, T-157 applicability metadata, T-170/T-171 promotion/wiring. No prior exact F01–F05/F07–F10 entry was found. F06 is explicitly tied to the completed T-170 claim.
- Operations documentation generally describes the actual four stages and accepted/native-provenance boundaries accurately. Additional drift: T-102 still calls the CVE-bin-tool scanner deferred although it is enabled; the test map omits `test_lead_promotion.py`; that file's T-171 label does not match the risk-helper task.
- `archive_depth_limit` reaches a `depth > limits.depth` check, but all production calls pass default depth zero and no recursion exists. Documentation's depth-policy wording should not be read as implemented nested archive inspection. This is an explicit coverage/description limit, not another counted defect.
- Scanners' actual pinned binaries, installed rule assets, feed databases, Docker identities/runtime custody, and real scanner stdout/report formats were **not executed or independently revalidated**. The CVE native-array fixture is also the shape asserted by existing adapter tests.
- No end-to-end live job, external scanner failure/timeout, real maximum-size output, integration, or acceptance output was examined. No performance claim is made for huge archives/binaries.

### Files read fully

- Exact shared brief; WSL `AGENTS.md`; coordination skill; development-skill pointer; canonical skill names were listed.
- `docs/operations/job_artifact_security_analysis.md`.
- All six job Python files: `__init__.py`, `datasets.py`, `job.py`, `formats.py`, `scanners.py`, `findings.py`.
- Six job-specific unit files, their `support.py`; `tests/unit/conftest.py`, `tests/test_000_unit_environment_guard.py`, `tests/artifact_input_support.py`, `tests/container_fixture.py`.
- `src/appsec_review/provenance.py`, `jobs/delivery_scope.py`, `retrieval/observations.py`, `blint_report.py`, `container_runtime/catalog.py`, `jobs/job_review_prioritization/inputs.py`.
- `scripts/run-tests.sh`, `scripts/lib/common.sh`, `containers/runtime-policy.toml`.

### Files read in relevant ranges/searches

- `runtime/registry.py`, `runtime/consume.py:1-230`, `runtime/inputs.py:448-565`, `runtime/handoff.py:61-142` and required-publication searches; `orchestration/topology.py:1-170`, Dagster adapter placement.
- `tool_inputs.py:1-150,250-430`; container executor request/policy/dispatch/retention excerpts; storage shared publication ownership excerpts.
- Accepted-language and artifact-index loaders/canonical-identity/safe-file boundaries; index inventory runtime declarations, ownership matching/tree enumeration/audit; immediate consumer contract references; `review/lead_families.py:470-530`; prioritization composite inputs/promotion/normalization; advisory links/products and retrieval artifact API excerpts.
- Full relevant runtime unit fixtures/selected tests from `test_wave2_contracts.py` and `test_wave2_consumers.py`; root conftest through collection ordering; exact test-map entry; base TOML job/global settings; guidance registry and schema searches.
- `ops_tests.py` command construction and supervised-run/report sections; ops dispatch; testing architecture working loop; job-interchange architecture through native/common-observation section; T-170 task document in relevant ranges; TODO and prior-report overlap searches.
- Owned synthetic unit receipt and wrapper JSON report. Test logs/JUnit/timings retained at the listed paths.

### Material unread scope

Full transitive container runtime/admission/signing/custody implementation, feed verifiers, all possible tool-native document schemas, complete retrieval/index store implementation, remaining shared runtime/fixture helpers, and full bodies of downstream jobs were not independently audited. Runtime tests validate selected synthetic publication/admission/ownership paths, not every task-to-consumer combination. No other job's audit was undertaken.

Final check: exact HEAD unchanged; Git status clean; all four owned reproducer scratch roots removed. Existing unit-run logs/results were retained as audit evidence. Only this session report was authored.
