# Job 35/47 — `job_review_data_indexing`

## Scope and verdict

- Audited **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, clean `main`, only in `/home/wsollers/projects/appsec-review` on `wsl-ubuntu`. Verified before and after validation. Editable import resolved to this checkout's `src/appsec_review/__init__.py`.
- Read-only functional audit: no source/configuration/environment installation changes, commits, models, native tools, containers, services, target execution, integration/acceptance/live runs, or subagents.
- **Six new medium findings.** Independently reproduced the high-severity canonical threat-model mismatch, then reconciled it with the newly delivered **TM-01** report: **RDI-F01 is confirmation, not another new finding**. Also reproduced this job's additional instance of the already reported missing payload-read-observation problem; kept it separate from the six new defect families.
- **23 pytest executions passed**, including two executions of the environment guard: 13 in **10.20 s**, 10 in **4.92 s**, two workers, shuffled, no failures/skips/tests over 10 seconds. A standalone probe initially failed because its scratch run root was relative; its completed observations remain identified below, and the remaining probes succeeded after using an absolute root. This was a probe-construction error, not a pytest or production failure.
- Passing small synthetic units does **not** establish whole-pipeline admission, actual feed/image validation, large-run resource behavior, or useful review findings.

## Registration, settings, and intended contract

`src/appsec_review/runtime/registry.py:103,174` registers this job. It is enabled by the dev recipe, has seven steps and **17 tasks** (eleven product tasks), eight output declarations, and 169 input requirements: 168 handoff-channel requirements across 34 graph producers, plus one external feed interface. `datasets.py:409-418` sets review-graph dispatch, checkout access, `always_execute=False`, handoff propagation and seven scheduling dependencies. The reduced all-registered graph has direct predecessors `job_sanitizer_build` and `job_threat_model_generation`; the other declared producers are ancestors, not missing dependencies. Ten registered jobs are downstream, including package assembly, document analysis and inference.

Intended behavior from `docs/operations/job_review_data_indexing.md:12-17,1144-1210`: reconcile accepted datasets, restore dropped accepted shards, build exact/qualified links and bounded reusable products, distinguish declarations/availability/supply/reads, fail publication on inventory violations, and publish a queryable inventory plus coverage matrices. No model task/prompt is dispatched. The one possible external tool is the optional/required FTS validation image; it was replaced by the inspected SQLite-only fake in executed units.

`appsec-review.toml:1143-1170` supplies:

| Setting | Observed use |
|---|---|
| `max_run_files=500000` | Full-customer run-tree enumeration; reaching it fails the audit. Managed-publication mode instead inventories authenticated publications and explicitly says scratch was not audited. |
| `max_facts_per_product=200000` | Base product truncation or scanner complete-menu refusal; **F07** shows appended metric/command products escape this bound. |
| `max_links_per_rule=200000` | Link context; **F03** shows it is not an actual maximum for multi-edge candidates. |
| `menu_partition_size=20` | Source-SAST high/critical and unknown menus; included in scanner reuse identity. |
| `max_build_exec_events=20000`, `max_commands_per_action=64` | Protected captured exec filtering and safe per-action facts. |
| `feed_max_age_days=14`; overrides KEV 7, EPSS 3, MITRE 365 | Snapshot verification/freshness, product feed identities and gap states. |
| `osv_version_matching="index"` | PURL-resolved OSV affected-version/range matching; unsupported/unresolved identities remain qualified leads. |
| FTS optional; 100000 records, 16 MiB input, 128 KiB text | Export refuses over-bound/sensitive/nonlogical streams; optional failures retain gaps, required failures raise after retaining a receipt. |

`_validate` checks exact step/task topology (`job.py:277-283`). All 17 units have zero job-specific input/output validators; processing functions perform their own checks. `strict_gaps=False`: valid literal producer statuses and legacy gap strings are normalized by shared outcome accounting. `interchange.py:521-571` validates control fields, **not arbitrary nested payload semantics**.

## Accepted inputs: declaration versus actual reading

The following inventories every handoff producer and declared dataset group, excluding the additional `handoff` requirement present for **each** row. Exact schemas/authority are in the fully read `jobs/job_review_data_indexing/datasets.py:56-408`. Most are optional/gap; native advisory outputs use when-declared/not-applicable. Operational inputs, routing-context inputs and producer evidence retain distinct declared authorities. The external requirement is `job_third_party_data_sync/feed_snapshot`, `appsec-review/public-feed-use/1`, reference authority.

| Producer suffix (`job_`) | Declared datasets besides handoff | Actual processing after declaration/admission |
|---|---|---|
| model_connectivity | model_connectivity | Envelope/status/artifact inventory, not semantic model output. |
| image_pin_verification | image_pin_verification | Envelope/status/artifact inventory; FTS independently reads its catalog pin. |
| target_acquisition | target_acquisition | Envelope/status/artifact inventory. |
| artifact_indexing | artifact_catalog, archive_members, artifact_relationships, artifact_index_summary | Artifact shards drive representation, inventory and build-provenance joins; summary is accounted, not deeply interpreted. |
| artifact_security_analysis | artifact_security_observations, artifact_security_results, artifact_scanner_io | Observation/shard joins and metadata accounting; no raw scanner rerun. |
| binary_evidence_indexing | binary_functions, binary_pseudo_c, binary_evidence_summary | Shard inventory/forwarding and retained backing metadata; no decompiler. |
| build_environment_analysis | build_environment | Envelope/status/artifact inventory. |
| change_context_analysis | change_context, change_context_documents, operator_exports, change_context_tool_io | History/CI joins use indexed signals; documents/raw exports remain accounted. |
| ci_configuration_analysis | ci_observations, ci_findings, ci_documents, ci_tool_io | Finding-source links and workflow-grouped CI trust facts. |
| clang_static_analysis | clang_static_observations, clang_static_scope_coverage, clang_static_summary, clang_static_raw | Source-SAST leads plus inventory; no Clang invocation. |
| code_graph_index | code_graph_facts, code_graph_stages, code_graph_checkpoints, code_graph_summary, alternate_cpg_index, alternate_cpg | Inventory/forwarding and graph-family coverage matrices. Unlike inference/package consumers, this job **does** declare the alternate index. |
| codeql_analysis | codeql_predecessor_import, codeql_graph_export, codeql_observations, codeql_plan_and_summary, codeql_scope_material | Observation leads/reference joins; accepted graph export is not reparsed here. **F02** in language coverage. |
| cpg_analysis | cpg_graph_coverage, cpg_scope_coverage, cpg_summary, cpg_binary | Inventory/forwarding; no raw CPG execution or parse. Legacy matrix calls CPG graph unavailable. |
| cpp_compiled_analysis | cpp_build_graph, clang_ast, llvm_ir, infer_observations, binary_symbols, cpp_blocked_branches, cpp_plan_and_summary, cpp_case_material | Build representation/source chains, SAST observations, inventory and lane coverage. |
| cpp_symbol_index | clangd_symbols, clangd_coverage, clangd_summary, clangd_tool_io | Symbol-to-syntax and symbol link products; no clangd process. |
| debug_symbol_indexing | normalized_symbols, symbol_coverage, target_decision, raw_artifact_refs, reader_executions, debug_symbol_summary | Inventory and forwarding; no new symbol reader. |
| dependency_intelligence | native_discovery, native_component_curation, native_metadata_investigation, native_inference_metrics, native_spdx, native_sbom_provenance, native_sbom_metrics, native_advisory_observations, native_advisory_lookup, dependency_context, scorecard_responses, dependency_intelligence_handoff, sca_reachability | Dependency inventory/native advisory shards are semantically joined to pinned feeds; other outputs inventoried/forwarded, not proof they were individually semantically read. |
| evidence_collection | static_tool_observations, static_tool_evidence, static_tool_io, corroborated_sast_evidence | Observation shards and publication dispositions drive leads/reference/advisory joins. Corroborated artifact is declared, but not explicitly loaded by scanner handler. |
| language_build | topology_refinement_inputs, build_actions, jvm_build_actions, language_build_receipts, build_workspaces | Build shards plus protected, handoff-listed `events.jsonl` for safe command facts; arbitrary workspaces are not executed. |
| owasp_control_assessment | owasp_model_receipts, owasp_workbench, owasp_documents, owasp_control_gaps | Correct accepted specialized-manifest path for product assembly, but independent inventory path incorrectly uses mutable pointer (**F04**). Control gap retrieval projects control-result rows, not the new gap artifact. |
| post_build_security_assessment | build_security, build_security_documents | Build-security representation/product joins, inventory and forwarding. |
| profile_data | profile_data, profile_data_handoff | Inventory/forwarding, not a new `profile_data` precomputed set. Known PD-05/06/07 remain. |
| project_build | topology_refinement_inputs, project_build_dispatch, probe_workspaces, image_build_streams | Envelope/ownership plus protected capture references when available. |
| review_intake | model_preflight, binary_evidence, review_intake | Envelope/status/artifact inventory. |
| review_prioritization | priority_items, prioritization_documents, prioritization_signals | Priority metrics/semantic flows plus directly read syntax artifact. Promoted leads/full hunt queue remain unconsumed (known RP-02); syntax read lacks payload receipt (K01). |
| sanitizer_build | sanitizer_build_summary, sanitizer_build_workspaces | Dataset-level inventory/forwarding only, not per-unit readiness (known SB-F05). |
| security_tagging | tag_assignments, tagging_documents | Inventory/forwarding; no task explicitly projects tags into new scanner facts. |
| source_history_analysis | history_signals, history_documents, raw_git_history, history_tool_io | History links/context/metric vectors use shards; no Git execution. |
| svf_alias_analysis | svf_alias_sets, svf_alias_scope_coverage, svf_alias_summary, svf_alias_raw | Inventory/forwarding; graph producer owns semantic fusion. |
| target_analysis_plan | planning_feedback_cache, analysis_plan, analysis_plan_documents | Envelope/artifact/shard inventory, not model planning execution. |
| target_catalog | target_artifact_inputs, source_files, declaration_symbols, components, target_documents, build_units, catalog_documents | Exact source/catalog anchors, units, symbols, documents and component joins. |
| test_coverage | test_coverage, test_coverage_handoff | Inventory/forwarding; no new coverage precomputed set. Known TC-03 retrieval declaration remains. |
| threat_model_generation | generated_dfd, generated_threat_model, generated_model_evidence, generated_model_views, threat_model_documents | DFD/model/result JSON explicitly loaded and observed; evidence document/views only inventoried. Canonical shape mismatch **F01**. |
| tree_sitter_ast | tree_sitter_ast, tree_sitter_coverage, tree_sitter_node_shards, generated_source_backing, tree_sitter_tool_io, tree_sitter_cfg | Accepted syntax nodes/spans for joins and syntax coverage; no grammar/parser/tool execution. |

`load` enumerates active graph producers excluding downstream jobs, resolves their accepted envelopes through `accepted_upstream`, and records status/identity summaries (`job.py:302-362`; `indexing/store.py:37-54`). Shard opens call `observe_shard`, which requires the exact producer/output schema/authority and verifies artifact membership/bytes (`store.py:85-97`; `runtime/inputs.py:474-499`). Inventory opens many shards merely to count/inspect coverage; these are actual reads, **not evidence that every dataset contributed to a product**.

Receipts: runner-mediated execution opens `input_read_scope` and writes `input_consumption` in each status (`runtime/runner.py:684-715`). `read_input_observations` verifies these status references and preserves unknown historical receipts (`runtime/inputs.py:565-587`). Matrices distinguish available/supplied/read/cited-null (`indexing/matrix.py:224-245`). However, current-job receipts are not included in the accepted-consumer map until this job is accepted, so its own producer-consumer rows may have unknown read/supply despite current work; do not treat that as a claim of zero reads. The selected full-handler test uses `UnitExecutor` directly, not the runner admission wrapper; it cannot prove complete production read-contract parity.

## Every step/task and actual implementation

Paths below are under `src/appsec_review/`; `job.py` abbreviates `jobs/job_review_data_indexing/job.py`.

| Task | Dispatch and processing | Outputs/mismatch/validation limit |
|---|---|---|
| `load.accepted_inputs` | `job.py:302-362`: manifest/snapshot verification, active registry/config reconciliation, accepted handoffs, restored shard verification, feeds, OWASP and threat-model summaries, unit statuses. | `accepted-inputs.json` `/2`; restores only absent accepted owner shards; records conflicts for later failure. Real unit covers dropped shard/snapshot rejection; no actual global feeds. |
| `links.cross_domain` | `job.py:364-382`; five `LINK_RULES` in `indexing/links.py:473-489`. | One shard per rule, exact/ambiguous edges, derived receipts and gaps. **F03**. |
| `precompute.build_provenance` | `products.py:175-280`: catalog artifacts, GENERATED_FROM/COMPILES_TO/LINKS_INTO through exact representation links, four-level source traversal; `job.py:443-455` appends safe commands from `build_facts.py:230-300`. | Per-artifact chain facts plus per-build-action command/environment facts. **F07** append bypass; command payload read seam K01. Protected raw argv/env remain protected. |
| `precompute.artifact_inventory` | `products.py:117-170`: group catalog artifacts by build unit, count kinds/formats/archive membership, report absent units and bounded detail. | `qs-artifact_inventory`; max 40 displayed artifacts per unit with explicit omitted count. |
| `precompute.dependency_advisories` | `products.py:282-753`: scanner pairs and dependency inventory, PURL ecosystem/name/resolved version, OSV decisions, bounded CVE aliases, NVD/KEV/EPSS joins. | Qualified applicability/reference facts; feeds pinned and hashed, connections closed on normal product iteration. Shared matcher/feed internals were not re-audited. |
| `precompute.scanner_correlation` | **Special handler**, `job.py:419-435` → `indexing/sast.py:87-249`, **not** similarly named `products._build_scanner_correlation`. | Every classified source-SAST observation becomes a lead; correlation retains duplicates/suppressions; high/critical/unknown component menus plus membership audit; complete-or-fail fact bound. RP-02 remains; K01 syntax read receipt. |
| `precompute.ci_trust` | `products.py:930-1000`: accepted CI observation/finding shards grouped by workflow, category co-location, deployment-event count. | Explicitly partial trust candidates, not proven trigger-to-privilege paths; no inferred CI-to-build mapping. |
| `precompute.history_context` | `products.py:1005-1086` plus `indexing/metrics.py:57-128`: file history/change/rank, exact/ambiguous source bindings, priority metric vectors. | **F07** merged limit/count mismatch. Metrics preserve unavailable values instead of zero. |
| `precompute.control_evidence` | `products.py:1091-1369`: accepted specialized workbench shards; re-resolve original evidence; references preserve deep authority instead of lossy duplication. | Qualification/no-evidence remain gaps. Existing **T-5006/T-5009** unresolved/unassessed projection remains, not a newly invented finding. |
| `precompute.reference_intelligence` | `products.py:764-848`: CWE rule metadata joined to pinned MITRE index. | Weakness facts; CAPEC/ATT&CK and discarded producer CWE metadata explicitly unavailable. |
| `precompute.symbol_links` | `products.py:1374-1443`: accepted symbols, syntax links and CALLS/REFERENCES counts. | Exact/ambiguous binding retained; overload/template/indirect dispatch limitations explicit. |
| `precompute.document_context` | `products.py:1722-1790`: normalized target document records grouped by exact method/route or boundary ID. | Intent/declaration context only; missing declarations and bounded subject/relation populations retained as gaps. Parsing is upstream, not repeated. |
| `precompute.threat_boundaries` | `products.py:1446-1719`; accepted generated DFD/model and catalog documents. | **F01** canonical field mismatch; **F05** unaccounted nested truncation. |
| `fts.image_validation` | `job.py:468-501`; `fts_worker.py:38-210`: bounded safe FTS export; pinned fake/real executor probe, build, verify; count/hash/probe comparison. | Validation receipt only, never replaces retrieval authority. Optional unavailable/disabled retains gap; required missing/mismatch raises. Executed tests use fake in-process SQLite, not image. |
| `audit.inventory` | `job.py:503-546`; `inventory.py:462-707`: strict scan or managed authenticated publication inventory; dataset owner resolution, counts, file references, snapshot, declarations, required outputs. | Retains JSON **before raising** on violations; **F04** specialized OWASP exception. Full scan bounds/hash/stray/retained-attempt tests passed. |
| `matrix.coverage` | `job.py:548-583`; `matrix.py`, `input_matrix.py`: language/build/producer-consumer/input-source/query/follow-up cells. | **F02** CodeQL presence falsely implies complete; source-SAST/build lanes similarly use presence rather than comprehensive coverage (static limit). |
| `publish.inventory_index` | `job.py:585-688,735-813`: combine upstream rows with self projections; indexed dataset/audit/cells; combined verified manifest; telemetry/summary. | Inventory row count excludes audit/cell entities by design; summary must not be read as total entity count. Final task gaps list product status summaries; earlier task outcomes retain other gaps. |

Five link rules were all traced: representation (`links.py:79-163`), finding-source (`174-223`), package-advisory (`269-315`), symbol-syntax (`355-409`), history-code (`428-470`). Representation uses source path/hash or build-unit/path/hash; nonunique content matches remain ambiguous. Symbol line-only joins remain ambiguous; exact column joins do not constitute general call-graph proof. History/function links use accepted spans. No raw source/IR/CPG tool is run by these rules.

## Publication, identities, schemas and downstream

Eight declarations (`datasets.py:15-48`):

1. `accepted_input_summary`: `appsec-review/review-data-indexing-inputs/2`, `load/.../accepted-inputs.json`.
2. `cross_domain_links`: retrieval-index/2, `links/links-*`.
3. `precomputed_products`: retrieval-index/2, `precomputed/qs-*`; entities carry `appsec-review/precomputed-fact/1`.
4. `derived_checkpoints`: `appsec-review/derived-shard/1`, legacy `data/indexing/checkpoints/**` and attempt `shared/derived-index/*.json`.
5. `fts_image_validation`: `appsec-review/sqlite-fts-validation/1`, `data/indexing/fts/**`; grouped supporting JSONL/SQLite/container receipts keep their own formats.
6. `dataset_audit_report`: `appsec-review/dataset-inventory/1`, `audit/.../inventory.json`.
7. `coverage_matrices`: `appsec-review/coverage-matrices/2`, `matrix/.../coverage-matrices.json`.
8. Required `dataset_inventory`: retrieval-index/2, `inventory/dataset-inventory`.

`derive.py:109-185` fingerprints schema/index/shard/rule/version/snapshot/inputs, verifies shared or legacy checkpoint reuse, publishes immutable SQLite plus receipt/dependencies, deduplicates entity/relation IDs and recomputes actual counts. Link/product identity settings are explicit in `job.py:370-379,399-453`; inventory binds rows/audit/matrices/FTS digests. This audit did not demonstrate an admitted stale-cache replay; do not infer one from a helper accepting changed fixtures.

Coverage and projections are not equivalent: derived shard metadata stores up to 50 shortened gap strings, checkpoint returns up to 200, self inventory rows up to ten plus count, matrix product cells up to ten. `bounded_gaps` explicitly accounts for omissions on fact-display paths, but some older slices do not. **F05** is a concrete incorrect total/completeness case, not a demand to make every display unbounded. `publish_derived` actual entity counts remain correct in **F07**, while its inherited `facts` counter does not.

The self inventory's hash cannot embed itself; it intentionally resolves through the accepted manifest (`job.py:795-813`). Protected payloads are not copied wholesale. `IndexBuilder` applies depth/string/list/key sanitization (`retrieval/index.py:282`; `retrieval/model.py:234-278`); retrieval adds protected-field filtering (`core.py:515-530`). No general claim is made that all arbitrary nested payloads survive those projections.

Package assembly requires indexing's exact accepted manifest or bound lineage, then verifies the packages (`job_review_package_assembly/job.py:66-100`). Source-SAST lead state/audit is consumed from accepted scanner-correlation facts (`review/lead_families.py:533-576`); high/critical membership count disagreements fail rather than silently dropping leads. Known RP-02 is not repaired by this path. Generic precomputed and inventory queries use bounded SQL, pinned manifests, read observations, response-byte limits and cursors (`retrieval/core.py:1260-1317,1550-1618`). New threat-boundary retrieval takes a different full-materialization route (**F06**).

## Findings

### RDI-F01 — High, confirmation of TM-01 — The threat-boundary product does not understand its actual producer's schema

- **Evidence:** `src/appsec_review/indexing/products.py:1515-1542,1572-1611`; canonical producer fields `src/appsec_review/threat_model/contract.py:346-415,455-479`; actual serialized documents `threat_model/documents.py:81-105`.
- **Trigger:** accepted, canonical generated DFD/model output, not malformed external data.
- **Expected:** preserve boundary members/components, place entry points in their process boundary, attach declared threats, and retain source-resolving evidence.
- **Actual:** consumer looks for `elements/element_ids/node_ids/members` instead of boundary **`inside`**, scalar element `component_id` instead of **`component_ids`**, entry-point `element_id/node_id` instead of **`process`**, and threat `boundaries/boundary_id/target_id` instead of **`boundary_ids`/`element_ids`**. Evidence references have `entity_id` and `locator`, but consumer only obtains paths from nonexistent `path` and keeps opaque `ev:*` refs.
- **R1:** constructed actual `Element/Boundary/Flow/EntryPoint/Threat` dataclasses, serialized them with real `build_documents`/`plain`, and passed them to the real product. **One boundary/one entry/one explicitly boundary-bound threat became two indexed boundary records, zero threats, zero component IDs/source paths, an artificial `boundary:entry_surface`, and `unassigned_threat`.** The real flow retained its crossing but interaction became `protocol="unspecified"`.
- **Impact:** ordinary generated threat context is lost/misrouted; source-filtered lookup cannot find the known source, and declared threats are incorrectly reported unassigned. This is not a claim of final model findings.
- **Confidence:** high, canonical producer serializer → actual product reproduced. No producer job/model was run.
- **Smallest correction:** consume canonical typed fields (prefer existing codec), map process membership and evidence locators/identities, preserve explicit uncertainty, and add a real producer-document→product regression.
- **Tests/TODO overlap:** **TM-01** in `job-audit-job_threat_model_generation.md:76-86` is the same defect, reported while this audit was running; retain one cumulative defect with both producer- and consumer-side reproductions. Related **T-172** is marked done. Existing passing `tests/unit/test_t172_indexing_and_retrieval.py:235-260` uses invented `trust_boundaries/nodes/node_ids/target_id` shapes, not canonical serialized producer documents. Canonical artifacts and the independent behavior-loader route are not claimed broken.

### RDI-F02 — Medium — Failed CodeQL coverage is published as a complete language lane

- **Evidence:** `src/appsec_review/indexing/matrix.py:126-128,155-157`; producer explicitly emits unavailable or partial coverage at `jobs/job_codeql_analysis/job.py:1444-1453`.
- **Trigger:** a failed/partial CodeQL query suite still has its valid accepted coverage/observation shard.
- **Expected/actual:** propagate unavailable/partial scope coverage. Instead the matrix tests only whether a language has any CodeQL shard.
- **R2:** real SQLite CodeQL shard with `coverage=("codeql-python","unavailable","suite failed")` produced language cell **`state="complete"`**, basis “accepted CodeQL observation shards”.
- **Impact:** queryable language coverage contradicts the producer and inventory, hiding incomplete analysis in the summary surface.
- **Confidence:** high, real shard and matrix reproduced.
- **Smallest correction:** aggregate coverage by relevant scope/language, as the graph-family lane already does; retain unavailable/partial states and explicit reasons.
- **Overlap:** same general false-completeness theme as prioritization **RP-03**, but an **independent indexing reducer**, not a re-audit of prioritization. Existing T-031 scope limitations do not authorize this conversion. Presence-only build-unit/source-SAST lane logic (`matrix.py:163-167,214-218`) was noted statically, not separately reproduced/count-expanded.

### RDI-F03 — Medium — `max_links_per_rule` does not bound emitted relationships

- **Evidence:** `src/appsec_review/indexing/links.py:62-66,274-296`; additional candidate fan-out at `:129-133,149-153,355-365,383-392,441-454`.
- **Trigger:** an advisory candidate emits its AFFECTED_BY plus two DERIVED_FROM edges, or one representation/symbol/history candidate has multiple matches.
- **Expected/actual:** the configured relationship ceiling is a true ceiling with explicit omissions. `_bounded` checks before a multi-edge bundle, or a row bound is substituted for a relation bound.
- **R3:** with **`max_links=1`**, one real scanner pair emitted **three relationships** and no bound-exhaustion gap. Only the separate name-only identity gap existed.
- **Impact:** output/memory/work can exceed the selected relationship bound; truncation accounting is false at the boundary.
- **Confidence:** high for advisory reproduction; other fan-out paths statically traced.
- **Smallest correction:** reserve the whole candidate's edge budget or check before every emitted relation; count candidates/edges omitted and avoid half-admitted facts where that would lose provenance.
- **Overlap:** no exact existing TODO/prior finding found; T-147 concerns declaration bindings, not enforcing this runtime limit.

### RDI-F04 — Medium — Inventory trusts the floating OWASP pointer rather than the admitted publication

- **Evidence:** `src/appsec_review/indexing/inventory.py:443-455,561-580`; compare correct accepted reader `jobs/job_review_data_indexing/job.py:164-194`; intended rule `docs/architecture/job-input-contracts.md:109-117`.
- **Trigger:** a residual/unadmitted/different-attempt specialized `data/indexes/owasp/accepted.json` exists while the current consumer has no corresponding admitted handoff, or the pointer differs from its pinned producer.
- **Expected:** inventory must describe the supplied accepted workbench only, and validate its member identities/counts.
- **Actual:** `_owasp_shards` verifies only the pointer-selected manifest's hash/location. It does not bind to the admitted handoff, check manifest run/schema, verify member files or recompute counts, or record an output read; `build_inventory` marks listed families indexed/complete from manifest `record_count`.
- **R4:** no OWASP handoff; pointer-selected manifest said **different run**, named a **nonexistent member file**, and declared 17 records. Correct `owasp_status` returned **unavailable**, but real inventory returned **audit PASSED**, an **indexed/complete workbench row with record_count=17**.
- **Impact:** the publication audit can positively inventory nonexistent/unadmitted workbench evidence and disagree with the very product input it audited. Malformed residual pointer JSON can also fail the audit even outside actual workbench consumption.
- **Confidence:** high, actual inventory and accepted-status functions reproduced; complete runner publication not executed.
- **Smallest correction:** pass the verified `owasp_status`/admitted manifest into inventory; verify specialized membership and recompute/verify counts under the same receipt boundary. Do not use a mutable pointer as permission.
- **Overlap:** OCA report correctly describes the **product** reader at its line 142; it does not cover this independent inventory reader. No exact TODO found. Related contract/read-observation work is not proof this reader was upgraded.

### RDI-F05 — Medium — Threat-boundary nested caps corrupt totals without a truncation gap

- **Evidence:** `src/appsec_review/indexing/products.py:1563-1570,1578-1585,1604-1611,1647-1652,1687-1693`; `_finish` at `:90-108`.
- **Trigger:** more than 32 flows/entries/threats associated with one boundary (well within the 200000-fact job bound).
- **Expected/actual:** preserve full totals, report detail omission counts and partial coverage. Lists are stopped at 32, displayed at 16, and totals are calculated from the already stopped list.
- **R5:** **40 canonical cross-boundary flows → `flow_count=32`, 16 displayed, no product gap, coverage `complete`**. This fixture deliberately has no upstream gaps to isolate the local loss; ordinary upstream gaps do not excuse incorrect totals.
- **Impact:** misleading threat-boundary scale/completeness; consumers cannot tell which flows/entries/threats were discarded.
- **Confidence:** high for actual flow records/product; analogous entry/threat caps statically verified.
- **Smallest correction:** count before retention, publish omitted counts for every bounded dimension, and propagate local omissions into row and product coverage.
- **Overlap:** **T-172** owns the feature. Distinct from F01's canonical-name mismatch and CGI-F13's graph scorecard totals.

### RDI-F06 — Medium — Specialized threat retrieval materializes every matching fact before pagination

- **Evidence:** `src/appsec_review/retrieval/core.py:1735-1788,1792-1826`; contrast bounded SQL at `:1287-1316`.
- **Trigger:** `query_threat_boundaries(limit=1)` on a large accepted threat-boundary shard; applies also to sibling methods sharing `_query_precomputed_filtered`.
- **Expected:** bound query work/materialized results to the requested page/cursor and honor the deadline during filtering.
- **Actual:** selects all `precomputed_fact` rows without LIMIT/filter predicates in SQL, decodes every row and converts every match into a result, then slices the accumulated list. The Python row/filter loop has no deadline check (SQLite still has its progress-handler bound).
- **R6:** actual immutable shard/manifest and real RetrievalCore, 80 matching facts: specialized query **materialized 80**, returned one; ordinary `query_precomputed(...,limit=1)` **materialized two**, returned one. Both retained cursors.
- **Impact:** result count/byte limits do not bound this intermediate work/memory; every page repeats a full pass. No large-run timeout or memory exhaustion was induced.
- **Confidence:** high, actual query measured by counting `_entity` calls; no transport/admission bypass was needed for the explicit fixture manifest.
- **Smallest correction:** push stable filters into SQL where possible and use bounded incremental scan/pagination for array filters, with an explicit scan budget and checks inside Python processing.
- **Overlap:** **T-172/T-173**; analogous graph synthesis bound concerns do not cover this retrieval implementation.

### RDI-F07 — Medium — Appended metric/command products bypass the per-product fact ceiling

- **Evidence:** `src/appsec_review/jobs/job_review_data_indexing/job.py:388-394,436-455`; `indexing/products_base.py:122-152`; `indexing/metrics.py:87-128`; `indexing/build_facts.py:251-299`.
- **Trigger:** base history/build product plus appended metric/command facts exceed `max_facts_per_product`.
- **Expected/actual:** limit applies to the final product, with deterministic priorities/omission accounting; it currently applies to the base product only. `merge_product` appends every extra fact without a bound or updating the base `facts` counter.
- **R7:** real history handler, two history rows and two priority rows, configured maximum **1**: final **fact_count/entities=3**, but **counts.facts=1**. Base history reported its one omitted file; there was no limit accounting for the two appended metric facts.
- **Impact:** accepted product violates the configured size budget and contradicts its own fact counters; base truncation alone does not explain final size.
- **Confidence:** high for actual history handler/publication; analogous command append statically traced. Synthetic accepted-input selection was used, not a changed frozen production configuration.
- **Smallest correction:** apply a total budget after composition, or allocate explicit sub-budgets and recompute totals; scanner complete-menu refusal must remain intact.
- **Overlap:** no exact TODO/prior finding found. This is not a stale-reuse claim.

## Confirmations / deduplication, not additional new defects

### K01 — Medium — Additional instance of the existing payload-read receipt gap

`job.py:419-425` calls accepted prioritization handoff then `_read` on its syntax artifact; `_read` at `:85-89` only verifies path/hash and JSON. `build_facts.py:211-228,262-264` similarly reads protected capture bytes after envelope lookup. Neither reports the corresponding payload output kind. `runtime/inputs.py:528-549` is the actual output-observation boundary; `storage/shared.py:566-576` observes the envelope/receipts, not every payload.

**R8:** under actual `input_read_scope`, accepted prioritization envelope + actual hash-verified syntax artifact returned the expected file data, but observations contained **only `handoff`**, not `prioritization_documents`. Smallest correction is the shared/typed artifact reader or explicit exact `observe_output` calls, not pretending inherited shared receipt verification is a semantic read. Group with **TA-F04/PB-F04/TS-F09/PBS-F10** and the language-build read observation note; preserve this job's concrete call sites.

Other previously reported seams:

- **TM-01:** RDI-F01 above is independent consumer-side confirmation and excluded from the six-new-findings count. The newly arrived report was read only for this seam and overlapping finding headings; the producer was not re-audited.
- **SB-F05:** confirmed `job.py:603-631,679` builds dataset-level rows and a handoff-exists telemetry flag, not per-unit readiness. No sanitized summary-to-readiness projection exists in these tasks. Do not count generic inventory rows or `sanitizer_readiness_indexed=1` as successful per-build retrieval.
- **RP-02:** confirmed only syntax/priority metrics are explicitly consumed in `job.py:419-437`; promoted leads/full hunt queue are not read. Original observations/selected priority items remain available.
- **TC-03 / PD-05:** no `test_coverage`/`profile_data` precomputed query-set names exist; inventory copies their advertised routes without proving endpoint semantics. PD-06/07 are separate existing engineering-query issues, not re-executed here.
- **CGI-F12 / OCA-F01:** this indexer declares and forwards `alternate_cpg_index`; missing downstream grants are not repaired by forwarding. Existing graph fact correctness issues were not re-audited.
- **T-5006/T-5009:** actual control product still projects unassessed/unsupported rows with named gaps; no new count for a known open issue.
- **Documentation drift (low):** operations prose `docs/operations/job_review_data_indexing.md:1168-1171,1236` says ten product tasks, but configuration/code have eleven, including threat boundaries. Handler-test title/name still says sixteen units (`tests/unit/job_review_data_indexing/test_handlers.py:1,940`), while it now executes 17. The stale “planned code graph” comment at `datasets.py:13-14` is also not current registration truth. Generated task table is correct. Related T-147, not an execution failure.

## Validation commands and results

All Linux commands ran using the brief's quote-preserving transport:

```powershell
$script = @'
set -eu
cd /home/wsollers/projects/appsec-review
# Exact Linux command below
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Preflight: `git rev-parse HEAD`, `git branch --show-current`, `git status --short`, `.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'`. Environment probe called `tests.test_000_unit_environment_guard.offending_environment(os.environ)` and asserted its returned **empty list**. No environment was repaired or dependency installed.

Inspected `tests/conftest.py`, `tests/unit/conftest.py`, unit fixtures and exact selected functions first. Dedicated FTS executor uses only in-process SQLite and never spawns a tool; missing catalog branches fail before executor use, and default executor branch is monkeypatched. Unit tier blocks native/model engines and nonloopback sockets. Root fixtures prevent report-container rendering. Broader legacy `_accepted_run` / `LocalSqliteFts` / `_run` helpers that can run JobRunner or a subprocess were **not selected**.

### A — Complete dedicated job unit files

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 351118 \
  --max-tests 13 --expect-tests 13 --timeout-seconds 180 -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_review_data_indexing/test_contract.py \
  tests/unit/job_review_data_indexing/test_handlers.py
```

**13 collected, 13 passed, 10.20 s, exit 0; zero skipped/failed/error/over-10-second tests.** Wrapper's normal private root:

`test/tmp/tests-custom-20261118-132111-717796-3303309`

Log `test/tmp/logs/tests-custom-20261118-132111-717796-3303309.log`; junit, timings and collection manifest use the same stem with `.junit.xml`, `.timings.sqlite`, `.collection.json`; report `test/tmp/reports/tests-custom-20261118-132111-717796-3303309.json`. Sequential wrapper-owned collection/execution share this fresh root; no concurrent auditor does.

Actual full-handler output retained **48 dataset rows**, five link shards, eleven product shards, inventory shard and restored history shard. Scanner product held three facts for one observation (lead/menu/audit); build/history one each. The other small-fixture products were unavailable. This confirms task wiring, not meaningful nonempty coverage for all eleven products.

### B — Exact threat projection and inventory/resume units

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 351119 \
  --max-tests 10 --expect-tests 10 --timeout-seconds 180 -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/test_t172_indexing_and_retrieval.py::test_t172_threat_boundaries_product_and_indexing_contract \
  tests/unit/test_t172_indexing_and_retrieval.py::test_unassigned_threat_is_not_attached_to_first_boundary \
  tests/unit/test_t172_indexing_and_retrieval.py::test_bounded_fact_gaps_account_for_omitted_records_and_text \
  tests/test_review_data_indexing.py::test_inventory_rejects_truncated_or_unreadable_run_tree \
  tests/test_review_data_indexing.py::test_inventory_rehashes_accepted_handoff_artifacts \
  tests/test_review_data_indexing.py::test_inventory_claims_the_runner_written_attempt_input_manifest \
  tests/test_inventory_resume.py::test_retained_attempts_are_owned_without_becoming_publication_evidence \
  tests/test_inventory_resume.py::test_historical_backing_files_do_not_satisfy_required_accepted_output
```

**10 collected, 10 passed, 4.92 s, exit 0; zero skipped/failed/error/over-10-second tests.** Private root:

`test/tmp/tests-custom-20261118-132558-387165-3348047`

Log `test/tmp/logs/tests-custom-20261118-132558-387165-3348047.log`; sibling junit/timings/collection files and `test/tmp/reports/tests-custom-20261118-132558-387165-3348047.json`.

### C — Small in-memory/function reproductions

Both executed with `.venv/bin/python - <<'PY' ... PY` inside the transport above, imports from the verified checkout. Each used its own UUID directory under `test/tmp/job-audit-job_review_data_indexing-repro-*`, process-private umask, no source/target execution. Native boundary was absent, not merely assumed mocked.

**First command:** R1–R5 completed with outputs recorded verbatim in findings; then the attempted R6 publication failed in `storage/shared.py:75` because a relative `run_root` was passed to `publish_derived`:

```text
ValueError: '/home/wsollers/projects/appsec-review/test/tmp/.../data/indexing/checkpoints/...json'
is not in the subpath of 'test/tmp/.../2026-11-18-0035'
```

Exit 1. Timer was at the end and was **not reached**, so elapsed for this aborted standalone command was not captured. It is a named probe-harness gap, not a production defect and not an unreported passing validation.

Smallest reproduction recipes (real functions, synthetic contents):

```python
# R1: canonical objects, not the test's invented schema.
from appsec_review.threat_model.contract import *
from appsec_review.threat_model.assemble import Assembly
from appsec_review.threat_model.documents import build_documents, plain
from appsec_review.indexing.products import ProductContext, _build_threat_boundaries
from appsec_review.indexing.store import ShardSet
from appsec_review.retrieval import LogicalIdentity, EntityKind
snap = "target-sha256:" + "9" * 64
src = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snap, {"path": "src/api.c"})
pub = Publication("job_target_catalog", "source_files", "source", "catalog", "1"*64)
ev = cite(EvidenceRecord(src.value, "source_file", "api", {}, pub,
          SourceSpan("src/api.c", "2"*64, 1, 1)), Basis.DECLARED, "fixture/1")
pid, bid, fid, eid, tid = [element_id(p, p) for p in ("proc","tb","flow","ep","threat")]
external = element_id("ext", "client")
elem = Element(pid, ElementKind.PROCESS, "API", NameBasis.DECLARED_NAME,
               Basis.DECLARED, (ev,), component_ids=("component-api",))
ext = Element(external, ElementKind.EXTERNAL_ENTITY, "Client",
              NameBasis.DERIVED, Basis.DERIVED, (ev,))
boundary = Boundary(bid, BoundaryKind.NETWORK, (pid,), Basis.DECLARED, (ev,))
flow = Flow(fid, external, pid, Interaction.NETWORK_RECEIVE, Basis.DECLARED, (ev,), crosses=(bid,))
ep = EntryPoint(eid, pid, Interaction.NETWORK_RECEIVE, "network", None, Basis.DECLARED, (ev,))
threat = Threat(tid, ThreatState.CANDIDATE, Stride.SPOOFING, "fixture-template",
                "Spoofing input", "Is identity verified?", (pid,), (fid,), (bid,),
                (ev,), (), Mitigation(MitigationState.NOT_EXAMINED))
docs = build_documents(Origin(run.name, "attempt_0001", snap, {}),
    Assembly(elements=(elem, ext), flows=(flow,), boundaries=(boundary,), entry_points=(ep,)),
    (threat,), (), ())
ctx = ProductContext(run, snap, ShardSet(run, ()), {}, {}, {}, 100, threat_model={
    "status":"accepted", "handoff_sha256":"3"*64,
    "dfd":plain(docs.dfd), "threat_model":plain(docs.threat_model), "gaps":[]})
derived = _build_threat_boundaries(ctx, ())
# Inspect [e.payload["result"] for e in derived.entities] and derived.gaps.
# R5: replace assembly flows with 40 Flow(element_id("flow",n), external,pid,
#     Interaction.NETWORK_RECEIVE,Basis.DECLARED,(ev,),crosses=(bid,)); no entries/threats.
#     Rebuild canonical documents and ProductContext. Result flow_count=32, shown=16,
#     derived.gaps=[], derived.coverage=[("threat_boundaries","complete",None)].
```

Here `run` was a newly created fixture run path, not a real review. R2 used real `IndexBuilder`/`IndexIdentity` for an empty CodeQL observation shard with producer language `python` and unavailable coverage, then `matrix.language_matrix(ShardSet(run,[shard]), {})`. R3 used the same builder for one `tool_observation` with `{"package":"pkg","advisory":"CVE-2026-12345"}` and called `links._build_advisories(links.LinkContext(snap,store,1),store.shards)`. R4 used real `atomic_json`, OWASP `DATASETS` and `build_inventory(InventoryInputs(...))`, with no handoffs and this specialized manifest/pointer:

```python
{"schema":"appsec-review/owasp-index-manifest/1", "run_id":"different-run",
 "shards":[{"family":"control-result","shard_id":"invented","sha256":"7"*64,
            "path":"data/indexes/owasp/control-result/missing.json",
            "record_count":17,"gaps":[]}]}
# Pointer contains manifest_path plus the real SHA of these exact bytes.
```

**Second command: exit 0, total Python probe time 1.443 s.** R6 used a fresh **absolute** root, real `publish_derived` for 80 threat facts, real `write_manifest`, real `RetrievalCore`, and a wrapper counting calls to the original `_entity`; outputs:

```text
R6 filtered retrieval {'materialized': 80, 'returned': 1, 'cursor': True}
R6 standard retrieval {'materialized': 2, 'returned': 1}
R7 merged product limit {'max_facts': 1, 'fact_count': 3,
 'counts': {'facts': 1, 'history_context:metric_vectors:history_files': 2,
 'history_context:metric_vectors:history_symbols': 0,
 'history_context:metric_vectors:metric_vectors': 2, 'entities': 3, 'relations': 2},
 'gaps': ['truncated: 1 file(s) exceeded the fact bound',
 'history_context:metric_vectors: history window unavailable: no accepted hotspot entry published its window']}
R8 syntax-read receipts {'files_in_payload': ['src/app.c'], 'observed_kinds': ['handoff']}
```

R7 used the inspected `_seed_unit_run` fixture with `max_facts_per_product=1`, two real history and two priority entities at distinct source paths, a hash-referenced synthetic accepted-input summary and no link rows, then the actual `precompute.history_context` handler and publisher. R8 gathered that fixture's real envelope pins into `replace(ctx,upstream_handoffs=pins)` and ran:

```python
with input_read_scope(readctx) as reads:
    handoff = accepted_handoff(run2, "job_review_prioritization")
    ref = handoff.handoff["outputs"]["extract.syntax_metrics"]["artifact"]
    data = _read(run2, ref)
    print(list(data["files"]), [r["output_kind"] for r in reads.document()["reads"]])
```

These are bounded function/publication probes, not accepted full JobRunner scenarios. Disposable probe roots were cleaned after recording results; wrapper test logs/results remain for inspection.

## Read coverage and material gaps

**Read fully:** audit brief; authorized AGENTS and coordination skill; job package `__init__.py`, `datasets.py`, `job.py`; indexing `store.py`, `derive.py`, `products_base.py`, `products.py` (all eleven rule bodies, including the scanner body bypassed by dispatch), `links.py`, `inventory.py`, `matrix.py`, `input_matrix.py`, `sast.py`, `metrics.py`, `build_facts.py`, `fts_worker.py`; retrieval precomputed name contract; threat-model `documents.py`; threat-boundary JSON schema; both dedicated job test files; root/unit conftests; handoff fixture; shell wrapper/common launcher.

**Sampled/traced:** canonical operations purpose/generated task and contract portions/process/gaps/acceptance/resume; architecture indexing/query-reuse opening sections and job-input admission/receipts; central TOML job block; registry/topology; actual threat-model dataclass field definitions and job serialize calls; CodeQL coverage publication; OWASP output declaration and canonical accepted reader; retrieval manifest/database/envelope/query-precomputed/query-inventory/query-threat paths; runtime inputs/shared handoff/outcomes/runner receipt blocks; IndexBuilder sanitization; package assembly and review lead/scope consumers; selected legacy inventory/resume and T-172 tests (not their unselected execution helpers); test-map row and wrapper supervision implementation; relevant TODO entries and prior report seams, including later-available OCA comparison.

**Material unread/unverified:**

- Full shared runtime admission/resume/storage signing implementation, full managed-publication audit execution, every propagated producer dataset's admission closure, and complete indexing→package→inference execution.
- Real global feed snapshots, feed publishing internals/OSV matcher internals, actual FTS image, tool transport, production deployment, live review outputs and targets. All were outside this read-only authorization.
- Upstream document parsers (`indexing/target_documents.py`, `document_interfaces.py`) were not re-audited: this job consumes their normalized records. Raw graph producer/normalizer correctness was not re-audited; prior report retained.
- Most of the 600-line architecture document and large generated operations dataflow table were not read line-by-line; source contract was read fully instead.
- Legacy whole-job/worker acceptance fixtures, full scanner/advisory/product suites, downstream unit suites, all integration/acceptance/live selectors, other T-172 API drift/combined retrieval cases. No full-suite pass claimed.
- Large/multi-shard boundedness, overflow/resource stress, admitted replay under changed snapshots/feeds, nontrivial real-world product quality. Reproduction sizes were intentionally tiny.
- Threat-model producer report arrived during report finalization. TM-01 was read and deduplicated against F01; its remaining producer findings were only scanned for overlap. It did not report F05's nested index-projection cap.

No fixes made. Stop after this one job; coordinator owns cumulative attribution and any future repair authorization.
