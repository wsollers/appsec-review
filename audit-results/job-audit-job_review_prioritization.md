# Job 30/47 — job_review_prioritization

## Scope and verdict

- Audited **main, `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, in `/home/wsollers/projects/appsec-review` through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu`. Source reads used the corresponding Ubuntu-22.04 UNC checkout, **not** the Windows checkout.
- HEAD and clean tracked/untracked status were verified at entry and after validation. The editable import resolved to `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.
- Read-only functional audit: no source/configuration/environment edits, installs, real scanners, providers, target execution, services, integration/live/Dagster execution, commits, or subagents. Only invocation-private unit/probe state was written beneath `test/tmp/`.
- **41 focused unit tests passed**, no skips or tests over 10 seconds. This does **not** establish exact correctness: nine local findings follow, including a **high-severity downstream score inversion reproduced from the passing test's own artifacts**.
- Five confirmation groups consolidate earlier upstream reports; do not count those groups as new defects.

## Registration, activation, and contract

`runtime/registry.py:101,172` registers the actual factory. The dev configuration enables this job; `job_is_enabled` and the computed topology confirmed this. Configuration is `appsec-review.toml:988-1090`. The factory declares seven units, `strict_gaps=False`, checkout access, `always_execute=False`, and handoff propagation (`jobs/job_review_prioritization/job.py:1059-1072`, `datasets.py:151-157`).

The generated graph has direct predecessors **CodeQL, dependency intelligence, profile data, test coverage** and direct successor **code-graph indexing**. This is a reduced scheduling graph, not the input permission set. It is computed from contracts (`orchestration/topology.py:49-82`); `schedule_after` explicitly names CodeQL.

There are **55 optional handoff-channel input declarations across 12 producers**. Their normal policies are missing→gap and partial coverage allowed. Intake/catalog/AST are nevertheless operationally required: `_load_inputs` calls their required readers unconditionally. The documentation calls them required, but the declarations do not fail absence at required-input admission.

### Declared versus actual inputs

All paths below are under `src/appsec_review/` unless otherwise stated.

| Producer | Declared datasets, in addition to `handoff` | Actual read/use |
|---|---|---|
| `job_review_intake` | `model_preflight`, `binary_evidence`, `review_intake` | Domain intake artifact; snapshot fingerprint. No direct preflight/binary payload processing. |
| `job_target_catalog` | `target_artifact_inputs`, `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units`, `catalog_documents` | Domain catalog and nested partition/component JSON; inventory hashes, language, scope, component roots. Other kinds are not explicitly read by this job. |
| `job_tree_sitter_ast` | `tree_sitter_ast`, `tree_sitter_coverage`, `tree_sitter_node_shards`, `tree_sitter_acceptance`, `generated_source_backing`, `tree_sitter_tool_io` | Acceptance document, dispositions and generated-source backing, streamed node shards; **explicit dataset receipts** for acceptance and node shards. No tool IO processing. |
| `job_source_history_analysis` | `history_signals`, `history_documents`, `raw_git_history`, `history_tool_io` | Domain history, per-source documents and SII ranking artifacts; exact file and symbol-byte-span joins. No raw Git/tool IO processing. |
| `job_evidence_collection` | `static_tool_observations`, `static_tool_evidence`, `corroborated_sast_evidence`, `static_tool_io` | Domain dispositions and Semgrep observation shards; SAST observation locations. Direct corroboration-output lookup is broken (EC-06). No tool IO processing. |
| `job_codeql_analysis` | `codeql_predecessor_import`, `codeql_graph_export`, `codeql_observations`, `codeql_plan_and_summary`, `codeql_scope_material` | Summary scope statuses and observation-shard flows. No direct graph-export/import/scope-material processing. |
| `job_change_context_analysis` | `change_context`, `change_context_documents` | Domain `priority.top` file/function entries, not detailed signals artifact; function fields are lost upstream (CC-05). |
| `job_test_coverage` | `test_coverage`, `test_coverage_handoff` | Domain build-unit/file counts, line sets and function coverage; no indexed coverage read. |
| `job_profile_data` | `profile_data`, `profile_data_handoff` | Domain rows; rank/population or count normalization and file/symbol/line joins. |
| `job_ci_configuration_analysis` | `ci_observations`, `ci_findings`, `ci_documents` | Domain security findings, otherwise tool-observation shard fallback; `lead_candidate` promotion. |
| `job_artifact_security_analysis` | `artifact_security_observations`, `artifact_security_results` | Domain acceptance artifact and observation shards. **Acceptance dataset is not declared**, and raw artifact reading does not enforce its ownership (RP-05). |
| `job_dependency_intelligence` | `dependency_context`, `dependency_intelligence_handoff`, `sca_reachability` | Domain handoff→SCA artifact fallback and advisory call sites; producer field mismatch DI-06. |

`inputs.accepted_handoff/has_handoff` use `runtime.consume.accepted_upstream`, with admitted digest pins inside a runtime scope. JSON reads enforce run containment and SHA-256. However, most raw payload and SQLite reads do not make dataset-level observations (RP-05). `load` probes history/Semgrep/CodeQL envelopes even when their feature flags are false; feature-disabled branches subsequently avoid those payloads and emit policy gaps.

### Every declared step/task

| Step / task | Dispatch and processing | Validation, publication, limits |
|---|---|---|
| `load.accepted_inputs` | `job.py:259-278` → `_load_inputs:191-229`; intake/catalog/AST fingerprint agreement, component ownership, generated backing, Swift policy, optional producer availability | Fails incompatible schema/hash/snapshot. Writes `catalog-files.json`. Required operational inputs are declared optional. RP-05 receipts. |
| `extract.syntax_metrics` | `:284-476`; resource lease then metadata prefilter, `ShardRowIndex`, one-file AST reconstruction, functions/complexity, import extraction, all heuristic/suppression passes | File/byte/function/signal limits; parse/unsupported/language gaps; streamed `syntax-facts.json`. RP-09 suppression truncation. |
| `extract.dependency_graph` | `:479-501` → `dependencies.GraphBuilder`; local inventory resolution, module/component Ca/Ce and instability | `max_import_records`, confidence floor, unresolved/dynamic and global truncation gaps; `dependency-graph.json`. RP-07 underqualified coupling. |
| `extract.semantic_evidence` | `:503-553` → `semantic.semgrep_signals/codeql_paths`; accepted Semgrep pack IDs and shortest bounded CodeQL flows; catalog/hash binding; owning functions | Disabled/unavailable reasons, path/step limits, unbound-path rejection; `semantic-evidence.json`. RP-03 coverage collapse; RP-06 wrong same-line owner. |
| `prioritize.score` | `:595-725`; exact-history joins; separate file/function percentile populations; weighted available-feature mean; composite change/coverage/profile/SCA/silence boosts and lead promotion | Full `priority.json`, attempt-level `prioritization-signals.json`, file/function prefix selections. RP-01 scale; RP-08 threshold validation; confirmation groups C1–C5. |
| `publish.index_priority` | `:735-969`; fingerprint four computation artifacts, signal artifact, settings and identities; selected source-resolved items/signals/flows/dependency context; compose manifest | Bounded evidence links and graph context; verified immutable SQLite/manifest. RP-02 promoted leads not indexed; RP-04 cache gap loss. |
| `publish.publish_handoff` | `:971-1057`; load prior products, settings/identities, total versus selected counts, top summaries, telemetry, promoted leads/hunt queue, artifact map | Domain `review-prioritization.json` and publication reference. Its own `gaps=[]`/`SUCCEEDED` intentionally do not repeat upstream gaps; canonical outcomes aggregate units. This alone is **not** a false-success finding. |

All seven units are reachable in the configured order. Dependency graph and semantic extraction independently depend on syntax, and scoring requires both. The direct `UnitExecutor` implementation executes the supplied ordered units and skips children of failed receipts (`runtime/units.py:83-210`). There are no model/tool launches, task prompts, personas, or runtime skills in this job; the guidance registry search found no prioritization binding. T-147 remains the pre-existing missing declarative deterministic-task binding, not evidence of hidden inference.

### Math, identity, and bounds checked

- Every named function/lambda is a distinct unit; nested-unit decisions are excluded from parent complexity. Cyclomatic counts, optional Go/Rust error propagation, cognitive approximation/deviations, SLOC and threshold shares are in `complexity.py`. Language tables and all heuristic rules/passes were read.
- Import resolution is intentionally heuristic and local. Module Ca/Ce counts use sets, external dependencies remain separate, and isolated instability is `null`. Call-name resolution, missing Python scoring, macro/preprocessor and fuller import resolution are existing **T-031**, not newly discovered requirements.
- `scoring.py:44-76`: zero→0; positive percentile `(below + .5*equal)/count`; missing values excluded; weighted means renormalized; weighted feature coverage retained. Scope/language populations and deterministic score/boundary/coverage/path/line/name tie-breaking agree with implementation.
- Composite terms are **additive**, not renormalized into the base scale. Coverage/profile/change/SCA missing data produce zero modifiers; these optional dimensions are not added to base `missing_features`. Profile uses `(population-rank+1)/population`, otherwise count/max-count. Coverage combines named functions, line sets, then aggregate counts. These choices were traced, not certified against live runs.
- Semantic dedup keeps the shortest flow per rule/source/sink; flow ordering is retained. Syntax/suppression IDs use exact byte positions; Semgrep IDs and function attribution lose finer location distinctions. Artifact lead identity loss is already ASA-F08.
- Selection honors explicit counts over fractions and gives file selections first use of the shared item ceiling. Evidence and neighbor bounds are separate from that ceiling. Full lead/hunt arrays have no additional dedicated bound beyond upstream/ranked populations.

## New local findings

### RP-01 — High — Composite scores above one are divided by 100 downstream

- **Evidence:** `jobs/job_review_prioritization/composite.py:765-777`; `job_review_prioritization/job.py:843-873`; `review/units.py:188-196,433-437`.
- **Trigger:** additive modifiers push a valid normalized base score above 1.0.
- **Expected / actual:** increasing review priority must not sharply reduce its downstream LPS contribution. The producer emits an unbounded additive score with the unchanged `llm-prioritization-score/1` identity, while `_unit_score` interprets anything above 1 as a percentage.
- **Reproduction:** the passing rewiring unit's actual `file:rust/src/lib.rs` has base **0.356061**, composite **1.086061**. The real downstream `_unit_score` maps these to **356** and **11** points respectively. No hypothetical custom weight is required.
- **Impact:** strongly boosted vulnerable-dependency/under-tested/hot/change-sensitive code can receive much less review allocation than before boosting.
- **Confidence:** high, reproduced from retained real producer-unit output and real downstream conversion.
- **Smallest correction:** establish an explicit versioned composite scale and update consumers monotonically; do not infer scale from the numeric value. Add a producer→review-unit regression crossing 1.0.
- **Overlap:** T-171 is related and marked done; no existing exact score-scale finding/TODO found.

### RP-02 — Medium — Promoted leads and the full hunt queue stop at artifact publication

- **Evidence:** `datasets.py:27-32` claims promoted leads/hunt candidates are also indexed; `job.py:843-880` indexes only selected ranked file/function items and their pre-composite evidence; `composite.py:805-827` builds separate arrays. `job_review_data_indexing/datasets.py:310-311` declares the signal artifact, but its handler reads prioritization only for syntax and priority-shard metrics (`job.py:419-437`); no `promoted_leads`/`hunt_queue` reader was found in `src`.
- **Trigger:** CI/artifact/SCA promotion or a silence candidate outside the normal selected item prefixes.
- **Expected / actual:** the claimed structured routing products should reach the priority/derived inference route. In the passing rewiring fixture, publication contains **3 promoted leads and 12 hunt candidates**, but the priority shard has **4 priority items, 21 review signals, zero payloads with `lead_source`**. No promoted-lead entities or dedicated full-queue consumption exists.
- **Impact:** this new promotion route cannot deliver its structured leads/full hunt queue to review. Original CI/artifact/dependency indices and selected boosted priority items remain available through other routes; this is **not** a claim all such findings disappear.
- **Confidence:** high static consumer trace plus real fixture index inspection.
- **Smallest correction:** either index bounded, source/artifact-resolving promoted leads and hunt entries and consume them downstream, or implement a bounded verified reader of the signal document; correct the declaration's false indexed claim.
- **Overlap:** T-170/T-171/T-172 describe intended delivery. Distinct from ASA-F08/DI-06, which corrupt lead content before this delivery seam.

### RP-03 — Medium — One successful CodeQL scope hides failed scopes and imputes zero coverage

- **Evidence:** `semantic.py:93-101`; `job.py:601-615,632,658,942-945`; producer summary retains per-scope root/build-unit/query-profile/status (`job_codeql_analysis/job.py:1736-1750`).
- **Trigger:** two scopes/query profiles of one language, one successful and another failed/partial.
- **Expected / actual:** retain failed scope coverage and do not call unprocessed files observed-zero. The consumer reduces scopes by language, and any `SUCCEEDED` permanently wins. It ignores scope root/profile and summary gaps. A two-scope cpp input reproduced `languages={"cpp":"SUCCEEDED"}`, `status="SUCCEEDED"`, **`gaps=[]`**.
- **Impact:** every scored C/C++ file then treats the semantic-path dimension as available, including the failed scope, often with value 0; the CodeQL index coverage row can say complete. This changes normalization and masks missing semantic work.
- **Confidence:** high, real reducer reproduced with fake accepted-storage boundary.
- **Smallest correction:** preserve scope/profile coverage and bind file coverage to successful analyzed scope; at minimum aggregate failures conservatively instead of success-wins. Global path caps/rejected paths also need item-level lower-bound/missing semantics rather than an unqualified zero.
- **Overlap:** T-031 documents language/tool limitations but not this success-wins reducer. The current contract unit explicitly expects success-wins (`test_contract.py:503-513`), so green tests do not rebut it.

### RP-04 — Medium — Reusing an existing priority shard drops its local context-bound gap

- **Evidence:** `job.py:773,781,905-920,954-969`.
- **Trigger:** re-execute the index handler for identical artifacts/settings after the SQLite shard exists, e.g. retry following index creation.
- **Expected / actual:** identical immutable index content should retain identical loss accounting. The local `gaps` list starts empty and is populated only inside `if not path.exists()`. The cache-hit branch neither reloads nor recomputes its gaps.
- **Reproduction:** two direct executions on the same seeded unit context produced identical shard SHA; first reported `dependency_graph_context_bound_reached` (twice), second `gaps=[]`, and its aggregate no longer contained the bound.
- **Impact:** the new manifest/domain handoff understates truncation, despite reusing the same incomplete index. Stored SQLite coverage can still expose partial prioritization, so not every view becomes clean.
- **Confidence:** high, full seven-unit fake-upstream execution reproduced. This is the handler's existing-shard branch, **not** a claim that ordinary runner receipt reuse always re-executes it.
- **Smallest correction:** persist/reload local build-gap metadata with the immutable shard or deterministically recompute it on reuse; assert gap equivalence, not only hash equivalence.
- **Overlap:** no exact existing TODO found; T-171 does not cover this older cache branch.

### RP-05 — Medium — Non-AST payload readers bypass dataset consumption enforcement/receipts

- **Evidence:** `inputs.py:17-23,48-68`; `job.py:193-205`; `composite.py:207-220` and the other domain loaders. `runtime/consume.py:196-213` observes only the envelope; payload/shard requirements are enforced by `runtime/inputs.py:474-549`, which these readers do not call.
- **Trigger:** any catalog/intake/history/engineering JSON or observation-shard consumption through these helpers.
- **Expected / actual:** hash-verification is necessary but not sufficient for a typed dataset read. Retained real load-unit receipts listed only intake/catalog/AST handoffs plus AST acceptance, although intake/catalog/partition/components were parsed. A narrow-contract probe declaring **only** the coverage envelope successfully imported a coverage file's 10/1 totals, with just one `handoff` receipt; no coverage payload permission was required.
- **Impact:** consumed-versus-supplied accounting is wrong; removing a dataset permission need not block its actual read. In particular, `_load_artifact_leads` reads the separate artifact acceptance document although that dataset is absent from this job's contract.
- **Confidence:** high; real runtime receipts and real loader under `input_read_scope`. This is instrumentation/functional authority accounting, not a penetration-test claim.
- **Smallest correction:** use dataset-aware JSON and shard reader boundaries, recording/checking the original producer kind before parsing; declare actual acceptance use or stop reading it. Keep envelope and payload receipts distinct.
- **Overlap:** same broader reader-instrumentation limitation as CC-07 and other jobs' prior reports; record this as **this job's additional occurrence**, not a newly invented system-wide root cause. T-147 is related publication-binding work, not an exact completed fix.

### RP-06 — Medium — Same-line functions receive another function's semantic evidence

- **Evidence:** `job.py:249-255,525,536-544`; CodeQL coordinates are retained in `semantic.py:133-143`.
- **Trigger:** multiple sibling callbacks/functions on one physical line, or a nested function later on the same line as an earlier location.
- **Expected / actual:** ownership should use the actual location, or remain ambiguous when only lines are available. `_innermost` considers only line containment, then chooses greatest `start_byte`, even if that function begins **after** the evidence. Two sibling spans `[0,20]` and `[21,40]` on line 1 reproduce owner `b` for an event in `a`.
- **Impact:** function semantic-path/ingress/sink counts and evidence links move to the wrong function. CodeQL already has columns, but the caller discards them; Semgrep normalization also drops finer ownership coordinates.
- **Confidence:** high, pure helper reproduction and direct call-site trace.
- **Smallest correction:** map line/column to accepted byte position and choose a containing interval; preserve ambiguity for genuinely line-only locations rather than selecting an unrelated sibling.
- **Overlap:** T-031's call-resolution approximation is different; this concerns exact available source positions. CI's earlier missing-column report concerns its own adapter and is not this consumer bug.

### RP-07 — Medium — Dependency bounds omit edges without marking affected coupling as a lower bound

- **Evidence:** `dependencies.py:359-374,386-393,420-429`; `job.py:485-498,617-619,644,680`.
- **Trigger A:** `max_import_records` exhausts before a later file's imports.
- **Actual A:** with `a.c→b.h→c.h` and cap 1, `b.h` reports zero outgoing imports, Ce=0, instability=0, **`coupling_lower_bound=false`**, although its import was not examined. The global truncation flag is true.
- **Trigger B:** import resolves exactly to an accepted inventory target omitted from syntax facts (file/AST bound, unscored target).
- **Actual B:** `a.c`'s import is `resolved`, confidence 1, target `b.h`, but `target not in self.files` silently removes the edge. Ce=0 and `coupling_lower_bound=false`.
- **Impact:** per-item score vectors and inherited function metrics appear exact despite known missing graph work. A global syntax/import gap does not qualify the individual metric.
- **Confidence:** high, both cases reproduced with the real graph builder.
- **Smallest correction:** propagate omitted/truncated edge uncertainty to affected modules and items; retain inventory context nodes when appropriate, or explicitly record excluded targets. Module members sharing incomplete module metrics also need shared qualification.
- **Overlap:** T-031 covers expanding import resolution; these already-resolved/budget-omitted edges and incorrect bound flags are distinct.

### RP-08 — Low — The silence-hunt threshold is not validated and bad values silently change policy

- **Evidence:** `job.py:64-73,109-169`; `composite.py:72,79,756`; `appsec-review.toml:1013`.
- **Trigger:** configure a negative, boolean, string, or non-integer `sast_silence_min_complexity`.
- **Expected / actual:** a centralized typed threshold should fail closed on invalid configuration. `_settings` accepts `-7`, `"invalid"` and infinity; the effective threshold is respectively `-7`, `5`, `5`. Negative values remove the complexity gate; invalid types silently revert to a hard-coded default.
- **Impact:** operator configuration can select substantially different hunt populations without an error.
- **Confidence:** high, real settings validators and typed-settings constructor reproduced.
- **Smallest correction:** include this field in bounded integer validation and eliminate the silent coercion/fallback for explicitly supplied invalid values.
- **Overlap:** related T-171; no exact item found.

### RP-09 — Low — Suppression-only truncation has no named extraction gap

- **Evidence:** `job.py:398-404,415-432,474-476`.
- **Trigger:** a file exceeds `max_signals_per_file` in suppressions but not in ordinary heuristic signals.
- **Expected / actual:** both lists are sliced, but only `len(signals)>limit` emits a gap. Suppression counts remain complete while stored suppression evidence is dropped silently.
- **Impact:** the syntax product can report no truncation gap despite missing evidence records supporting the suppression-density feature.
- **Confidence:** high static defect. A real extractor probe established a valid two-suppression/zero-signal input; final syntax-handler truncation was **not** independently executed for that input.
- **Smallest correction:** account for suppression truncation separately, retaining the complete count and omitted-record count.
- **Overlap:** no exact existing TODO found.

## Prior findings confirmed — do not count twice

| Group | Prior IDs / severity | Consumer confirmation |
|---|---|---|
| C1 | **ASA-F08, medium** | `composite.py:404-443`: locationless artifact leads key only path/line/rule/class, discard original observation/subject/artifact identity and overwrite collisions; unknown severity defaults high (`:106-116,429`). Confirmed by source; prior auditor's reproduction retained, not rerun here. |
| C2 | **EC-06, medium** | `composite.py:564-585` reads corroboration fields from projected unit outputs and reads top-level cluster path rather than nested `location`. `runner.py:819-823` / `interchange.py:110-115` omit those control fields. Ordinary shard fallback still exists. |
| C3 | **DI-06, medium** | `composite.py:470-473,502-515` expects `package`/top-level `ffi_boundaries`, rather than the reported producer's `package_name`/per-advisory mechanism/site fields. Confirms lost package/FFI classification; not a fresh upstream audit. |
| C4 | **TC-08 + PD-08, low — one status-convention defect** | Every engineering loader reads envelope `terminal_status`; `/2` envelopes carry `completion_status` (`runner.py:826-830`). Extend the same confirmation to change-context, CI, artifact and dependency loaders (`composite.py:146,213,276,330,392,460`). A six-loader probe returned `UNAVAILABLE` for envelopes with `completion_status="SUCCEEDED"`. Imported data can still contribute boosts. |
| C5 | **CC-05, medium** | Prior report additionally located and read. `job_change_context_analysis/job.py:850-857` strips function names/spans. `composite.py:154-178,708-717` never resolves the detail artifact and promotes function scores to a file-wide maximum. Confirmed, not newly counted. |

Related TODOs: **T-170/T-171/T-172** marked done; **T-031** and **T-147** open. No TODO entries were changed.

## Output schemas, publication, and downstream limits

- `priority_items`: required, indexed `priority` shard `review-prioritization`, schema `appsec-review/retrieval-index/2`, routing authority.
- `prioritization_documents`: artifact-only glob `data/jobs/job_review_prioritization/attempts/*/steps/*/tasks/*/artifacts/*.json`; includes catalog-file mapping, syntax/graph/semantic/ranking and final domain document. This is a heterogeneous artifact family advertised under the final `/1` domain schema, not proof every file has that schema.
- `prioritization_signals`: attempt-level `artifacts/prioritization-signals.json`, closed documented schema `appsec-review/review-prioritization-signals/1`; the dedicated test validates it with JSON Schema. Primary final domain schema is still `review-prioritization/1`.
- No per-unit output validators are attached. The job input validator validates settings and topology; common runtime control validation is not full payload schema validation. The signal-artifact field and telemetry are absent from runner-projected unit control output but retained in the referenced domain document and collected artifacts; this by itself is not data deletion.
- `query_hotspots` reads indexed priority items by scope/path/minimum score and rank (`retrieval/core.py:1210-1258`); generic find/trace exposes evidence/flow/context relations. Downstream review-unit ranking uses the score conversion in RP-01; metric vectors join priority/history (`indexing/metrics.py:58-132`). Code-graph alternate routes consume priority items/signals (`job_code_graph_index/alternate_cpg.py:2277-2280`).
- Registry-derived consumers: code graph, document issues, dossier, inference security review, OWASP, PoC, remediation planning, review data indexing, package assembly, security tagging, threat-model generation. Only directly necessary consumer seams were traced; this is not a full audit of those jobs.

### Documentation / contract drift (not additional defect counts)

- Canonical operations page accurately describes the original seven-unit flow but omits the new composite processing; older architecture/operations pages still describe only the base weighted score.
- T-171/task design specifies separate lane scores, `review-prioritization/2`, guard-removal factors and a low-test-coverage/exposure conjunction for silence hunting. Actual code keeps `/1`, one additive score, and a complexity+any-surface+no-observation-overlap gate; coverage is an independent modifier. This is verified implementation/design drift, not proof a particular alternate heuristic was approved.
- Dataset text says promoted leads/full hunt candidates are indexed when they are not (RP-02).
- Architecture's “generated file not scored” row is stale: accepted in-scope generated backing is admitted/scored.
- Required intake/catalog/AST prose differs from optional typed declarations. More precise deterministic task bindings remain T-147.

## Focused validation

### Environment and transport

Every Linux body below ran from the pinned checkout through the brief's quote-preserving transport:

```powershell
$script = @'
set -eu
cd /home/wsollers/projects/appsec-review
# Exact Linux validation body below
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Preflight `.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'` resolved correctly; `offending_environment(os.environ)` returned `[]`. No environment was repaired or shared dependencies installed.

Inspected fixtures before execution: golden AST bytes and source fixtures, synthetic accepted handoffs, temporary SQLite builders, resource ledgers, fake Tree-sitter executor, and recorded intake/catalog units. The new rewiring “end_to_end” test runs deterministic units, **not** external tools/Dagster. `tests/unit/conftest.py` blocks real engines/network and disables fsync for that tier.

### Run A — all dedicated prioritization units and two relevant rule-lock cases

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 3030 \
  --max-tests 45 --expect-tests 39 --strict -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/test_review_prioritization.py \
  tests/test_syntax_metrics_streaming.py \
  tests/unit/job_review_prioritization/test_contract.py \
  tests/unit/job_review_prioritization/test_signals_and_rewiring.py \
  tests/test_cpp_memory_safety_rules.py::test_the_semgrep_bundle_lock_matches_the_rule_files \
  tests/test_cpp_memory_safety_rules.py::test_the_new_signals_are_sinks_for_c_and_cpp_and_only_leads
```

**39 collected, 39 passed, 0 failures/errors/skips, 0 over 10 s; exit 0.** Pytest **8.35 s**; wrapper collection **5.104 s**, execution **12.606 s**, total **18.056 s**.

Private stem: `test/tmp/tests-custom-20261118-130426-893290-3183068`. Wrapper sequential collection/execution reused only this fresh invocation's base. Logs: `test/tmp/logs/<stem-name>.log` and `.collection.log`; JUnit/timings/collection manifest: `<stem>.junit.xml`, `<stem>.timings.sqlite`, `<stem>.collection.json`; fixed report: `test/tmp/reports/tests-custom-20261118-130426-893290-3183068.json`.

### Run B — only this job's real runtime AST receipt cases

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 3031 \
  --max-tests 2 --expect-tests 2 --strict -- \
  'tests/unit/runtime/test_wave2_consumers.py::test_tree_sitter_consumers_align_node_shards_and_scope_acceptance_permissions[job_review_prioritization]' \
  tests/unit/runtime/test_wave2_consumers.py::test_review_prioritization_units_record_and_enforce_tree_sitter_reads
```

**2 collected, 2 passed, 0 failures/errors/skips, 0 over 10 s; exit 0.** Pytest **5.72 s**; collection **2.062 s**, execution **9.851 s**, wrapper total **12.280 s**.

Private stem: `test/tmp/tests-custom-20261118-130547-196372-3196358`; matching log/collection/JUnit/timings/report paths follow Run A's convention. These cases run real runtime intake/catalog fixtures and AST publication with a **fake executor**, then only prioritization load/syntax units. They do not test real scanner quality.

Mapping note: `tests/job-test-map.json` lists contract, main metrics, streaming, C++ rules and wave2 consumers, but **omits the existing `test_signals_and_rewiring.py`**. It was found and included, not mistaken for absent coverage.

### Probe A — retained test artifacts and real downstream conversion

Executed with `.venv/bin/python -`:

```python
import json, sqlite3, time
from pathlib import Path
from appsec_review.review.units import _unit_score
start = time.perf_counter()
base = Path('test/tmp/tests-custom-20261118-130426-893290-3183068/popen-gw1/test_end_to_end_engineering_si0/runs/2026-11-17-ws-b')
job = base/'data/jobs/job_review_prioritization/attempts/attempt_0001/steps'
r = json.loads((job/'prioritize/tasks/score/artifacts/priority.json').read_text())
x = max(r['files'] + r['functions'], key=lambda i: i['score'])
print(x['item_id'], x['base_score'], x['score'], _unit_score(x['base_score']), _unit_score(x['score']))
h = json.loads((job/'publish/tasks/publish_handoff/artifacts/review-prioritization.json').read_text())
mf = json.loads((base/h['index_manifest']['path']).read_text())
shard = next(s for s in mf['indexes'] if s['name'] == 'priority')
with sqlite3.connect(f"file:{base/shard['relative_path']}?mode=ro", uri=True) as db:
    print(len(h['promoted_leads']), len(h['hunt_queue']))
    print(db.execute('select kind,count(*) from entities group by kind').fetchall())
    print(db.execute("select count(*) from entities where payload_json like '%lead_source%'").fetchone()[0])
p = Path('test/tmp/tests-custom-20261118-130547-196372-3196358/popen-gw1/test_review_prioritization_uni0/runs/2026-11-18-0001/data/jobs/job_review_prioritization/attempts/attempt_0001/steps/load/tasks/accepted_inputs/status.json')
print([(r['producer'], r['output_kind']) for r in json.loads(p.read_text())['input_consumption']['reads']])
for stem in ['tests-custom-20261118-130426-893290-3183068', 'tests-custom-20261118-130547-196372-3196358']:
    rr = json.loads((Path('test/tmp/reports')/(stem+'.json')).read_text())
    print(stem, rr['total_elapsed_s'], {k:v['elapsed_seconds'] for k,v in rr['stages'].items()})
print(time.perf_counter() - start)
```

Successful output: RP-01 **356→11**, RP-02 **3 leads/12 hunts→zero indexed lead payloads**, RP-05 envelope-only intake/catalog reads. Measured body **0.004 s**, exit 0. An earlier read-only glob lookup matched no truncated pytest directory names and produced only timing output; it was not evidence for any defect and was corrected using exact private paths.

### Probe B — real pure functions, fake accepted storage only

Executed with `.venv/bin/python -`:

```python
import time, json
from pathlib import Path
from unittest.mock import patch
from appsec_review.jobs.job_review_prioritization import semantic, composite
from appsec_review.jobs.job_review_prioritization.job import _innermost, _settings
from appsec_review.jobs.job_review_prioritization.dependencies import GraphBuilder
from types import SimpleNamespace
from appsec_review.config import load_config
start = time.perf_counter()
with patch.object(semantic, 'has_handoff', return_value=True), \
     patch.object(semantic, 'accepted_handoff', return_value=({'outputs': {
         'acceptance.publish_handoff': {'artifact': {'path':'summary'},
                                       'index_manifest': {'path':'index'}}}}, 'a'*64)), \
     patch.object(semantic, 'read_json', return_value={'scopes': [
         {'language':'cpp','scope_id':'ok','terminal_status':'SUCCEEDED'},
         {'language':'cpp','scope_id':'bad','terminal_status':'FAILED'}]}), \
     patch.object(semantic, 'producer_entities', return_value=[]):
    out = semantic.codeql_paths(Path('.'), limit=5)
    print(out)
    assert out['status'] == 'SUCCEEDED' and out['gaps'] == []
units = [
    {'function_id':'a','start_line':1,'end_line':1,'start_byte':0,'end_byte':20},
    {'function_id':'b','start_line':1,'end_line':1,'start_byte':21,'end_byte':40}]
print(_innermost(units, 1))
assert _innermost(units, 1) == 'b'
files = {
    'a.c': {'grammar':'c','imports':[{'kind':'include','specifier':'b.h','line':1}]},
    'b.h': {'grammar':'c','imports':[{'kind':'include','specifier':'c.h','line':1}]},
    'c.h': {'grammar':'c','imports':[]}}
g = GraphBuilder(files, files, lambda p:b'', min_confidence=.8, max_records=1).build({})
print(g['truncated'], g['files']['b.h'])
assert g['truncated'] and not g['files']['b.h']['coupling_lower_bound']
g = GraphBuilder({'a.c':files['a.c']}, files, lambda p:b'', min_confidence=.8, max_records=5).build({})
print(g['files']['a.c'])
assert g['files']['a.c']['efferent_coupling'] == 0 and not g['files']['a.c']['coupling_lower_bound']
settings = load_config().job('job_review_prioritization').settings
for raw in [-7, 'invalid', float('inf')]:
    c = {**settings, 'sast_silence_min_complexity':raw}
    try:
        _settings(SimpleNamespace(config=SimpleNamespace(settings=c)))
        accepted = True
    except ValueError:
        accepted = False
    print(repr(raw), accepted, composite.CompositePrioritizationSettings.from_settings(c).sast_silence_min_complexity)
print(time.perf_counter() - start)
```

**Exit 0, 0.847 s.** Outputs substantiate RP-03, RP-06, RP-07 and RP-08. First exploratory version used an empty `{}` index-manifest placeholder; the reader correctly returned `UNAVAILABLE`, so the assertion expecting `SUCCEEDED` failed (exit 1). The corrected nonempty fake reference above reached the intended reducer. That failed probe is fixture construction error, not a failed pytest case; its timer was not reached.

### Probe C — existing-shard reuse and envelope-only payload permission

Executed with `.venv/bin/python -`:

```python
import time, json, os
from pathlib import Path
from appsec_review.jobs.job_review_prioritization import build_job
from appsec_review.jobs.job_review_prioritization.composite import _load_test_coverage
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.runtime.contracts import JobContract, InputRequirement
from tests.unit.job_review_prioritization.test_contract import (
    _seed_upstream_run, _job_context, _artifact_ref, _publish_handoff,
    GOLDEN, BASE_CONFIG, JOB_ID)
os.umask(0o022)
start = time.perf_counter()
scratch = Path('test/tmp/job-audit-review-prioritization-probes-20261118-1309').resolve()
scratch.mkdir(parents=True, exist_ok=False)
run, target, snapshot, pins = _seed_upstream_run(scratch/'reuse', golden_paths=tuple(sorted(GOLDEN['files'])))
ctx = _job_context(scratch/'reuse', run, target, snapshot, pins, settings_override={
    'sources': {'history':False, 'semgrep':False, 'codeql':False},
    'index': {**BASE_CONFIG.job(JOB_ID).settings['index'],
              'file_top_count':2, 'function_top_count':1, 'max_graph_neighbors':1}})
j = build_job()
a, b = j.execute(ctx), j.execute(ctx)
x, y = a['outputs']['publish.index_priority'], b['outputs']['publish.index_priority']
print(x['index_identity']['sha256'] == y['index_identity']['sha256'], x['gaps'], y['gaps'],
      'dependency_graph_context_bound_reached' in y['aggregated_gaps'])
assert x['gaps'] and not y['gaps'] and x['index_identity']['sha256'] == y['index_identity']['sha256']
ref = _artifact_ref(run, run/'fixture/coverage.json', {
    'schema':'appsec-review/test-coverage-handoff/1',
    'build_units':[{'files':[{'path':'go/store/store.go',
                            'totals':{'lines_total':10,'lines_covered':1}}]}]})
sha = _publish_handoff(run, 'job_test_coverage', {'acceptance.publish_handoff':{'artifact':ref}})
ctx.contract = JobContract(inputs=(InputRequirement('job_test_coverage','handoff','appsec-review/job-handoff/2'),))
ctx.upstream_handoffs = {'job_test_coverage':sha}
with input_read_scope(ctx) as reads:
    status, data = _load_test_coverage(run, True)
    print(status, data['go/store/store.go']['lines_total'],
          [(r['producer'],r['output_kind']) for r in reads.document()['reads']])
    assert data['go/store/store.go']['lines_total'] == 10 and len(reads.document()['reads']) == 1
print(time.perf_counter() - start)
```

**Exit 0, 1.067 s.** Same hash; first local gap present, second absent; coverage totals imported with only envelope permission/receipt. The umask is subprocess-private fixture custody, not a persistent/shared environment change.

### Probe D — suppression input and shared status convention

Executed with `.venv/bin/python -`:

```python
from pathlib import Path
import time
from unittest.mock import patch
from appsec_review.jobs.job_review_prioritization import composite
from appsec_review.jobs.job_review_prioritization.complexity import function_units
from appsec_review.jobs.job_review_prioritization.heuristics import Extractor
from appsec_review.jobs.job_review_prioritization.languages import SPECS
from appsec_review.jobs.job_review_prioritization.syntax import SourceFile, Node
start = time.perf_counter()
data = b'// nosemgrep\n// nosemgrep\n'
r = Node('program', None, True, False, 0, len(data), 1, 3, 1, 1)
offset = 0
for i, line in enumerate(data.splitlines(keepends=True), 1):
    c = Node('comment', None, True, False, offset, offset+len(line.rstrip(b'\n')),
             i, i, 1, len(line), parent=r)
    r.children.append(c)
    offset += len(line)
sf = SourceFile('comments.js', 'a'*64, 'javascript', 'JavaScript', data, r, 0)
u, _ = function_units(sf, SPECS['javascript'], count_error_propagation=True, limit=5)
e = Extractor(sf, SPECS['javascript'], u, (), {
    'custom_parsing_min_operations':6, 'custom_parsing_min_density':.5,
    'state_mutation_min_operations':3})
e.run()
print(len(e.signals), len(e.suppressions), len(u))
assert len(e.signals) == 0 and len(e.suppressions) == 2
for fn in [composite._load_change_context, composite._load_test_coverage,
           composite._load_profile_data, composite._load_ci_leads,
           composite._load_artifact_leads, composite._load_sca_reachability]:
    with patch.object(composite, 'has_handoff', return_value=True), \
         patch.object(composite, 'accepted_handoff',
                      return_value=({'completion_status':'SUCCEEDED','outputs':{}}, 'a'*64)):
        print(fn.__name__, fn(Path('.'), True)[0])
print(time.perf_counter() - start)
```

**Exit 0, 0.002 s.** Two suppressions/zero signals; all six loaders report `UNAVAILABLE`. An earlier synthetic AST used hard-coded offsets that truncated `nosemgrep`, produced zero matches, and failed its precondition assertion (exit 1, no elapsed print). The corrected offsets above verified the input; final syntax-bound behavior remains explicitly static.

Read-only topology/config probe completed in **1.135 s** and confirmed the registration/predecessors/consumers listed above. Initial inventory-only shell probes encountered a `wc` directory operand and missing Linux `rg`; neither was a test failure. Switched to existing tools/UNC reads; no installs.

## Read coverage and remaining gaps

**Read fully:** audit brief; authorized AGENTS; multi-session skill; canonical job operations page; architecture and dedicated operations prioritization pages; T-171 task document; all fourteen Python files in `jobs/job_review_prioritization/`; both dedicated unit files; main metrics and streaming tests; C++ rules test file; wave2 consumer test file; root/unit conftests; handoff fixture helper; unit environment guard; signal JSON Schema; `orchestration/topology.py`; `indexing/metrics.py`; shell wrapper/common launcher.

**Read relevant ranges/searches:** exact job configuration; registry; test-map entry; TODO T-031/T-147/T-170/T-171/T-172 and relevant title/term searches; prior reports ASA-F08, EC-06, DI-06, TC-08, PD-08, CC-05; runtime consume/inputs/job/units/runner and dataset declarations; retrieval manifest verification and hotspot query; downstream review-unit score conversion, indexing handler/contract and alternate-CPG routing; CodeQL summary and change-context publication fields; wave2 fixture's configured runner, recorded intake/catalog and fake Tree-sitter producer; wrapper test-runner portions. Guidance registry was searched, not loaded as instructions.

**Material unread/unverified:** full shared runtime/retrieval/consumer implementations, whole upstream jobs and their other findings, complete TODO registry, all source fixture/golden AST payloads by manual line review, generated-source dependency resolution across every language/build topology, real parser versions re-parsing all fixture languages, real producer-to-consumer payload combinations beyond the inspected seams, actual target output quality, large production-scale performance/memory, real crash/restart/release replay, final runtime publication of a complete real review. No integration/acceptance/live tests or providers ran. The test fixtures use synthetic field layouts that mask several real producer seams (especially EC-06/DI-06/CC-05); passing them is not schema-parity proof.

Unit/probe logs and evidence remain only in the private paths above. No repository files were changed and no TODOs were added. Stop after this job; the coordinator owns deduplication and accumulation.
