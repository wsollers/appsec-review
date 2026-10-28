# Dossier data, queries and provenance

Status: source-verified inventory, initially at contract commit
`5f5548da3d039f73c7d6858d2b28a4593a264efe`, reconciled through integration `b702eb7`
and assurance fix `7641fa5`, then reader/metric checkpoint `18eae9f`, remediation `e769645f` and
index-admission `3f28d871`, final integration `dd9c9ad`, rendering `e9a8333a` and metric parity
`0ece65d3`, then combined source `6975aef29eb09e1fb57385db98cb7d859108e362`
(including main `093f26d5`) and stable `a709a10b` (product trees identical to owner-tested
`039b24e4`), followed by contracts-only OpenVEX handoff `967d1c7f`, 2026-10-28,
and reconciliation with main `799ea3c2` for debug symbols and native SBOM evidence, then
standalone OpenVEX integration over completed main `c47e3fea`. Operative OpenVEX default-policy
rows are reconciled at `74d93127`, containing landed main `83e67b23`; historical evidence below
retains its original source attribution.
The combined inventory contains **44 registered/configured
jobs, 145 dataset kinds, 21 public retrieval tools, 19 logical SQLite indexes and 16 allowed
query sets (10 produced, 6 pending)**. This is a catalog of implemented input surfaces,
**not** evidence that a particular run produced them. Chain, remediation and dossier producers,
central wiring, process metrics, immutable PoC `/2`, gate/report `/2` and chain/base isolation now
exist. The owner verified the seeded PDF sample and historical native all-lane semantics with
offline model/compiler/renderer boundary doubles; neither is live execution or current-main
acceptance. Shared completion
schema identities and assurance remain in
[`completion_contracts.py`](../../src/appsec_review/jobs/completion_contracts.py).
The delivery contract is
[evidence completion, section 11](evidence-completion-and-remediation.md#11-parallel-implementation-decisions);
the [documentation implementation record](../reviews/evidence-completion-documentation-inventory.md)
tracks reconciliation separately.

## 1. Dossier membership and authority

A **confirmed-finding dossier** means one document per accepted finding package whose state is
`confirmed`, whether the investigation began in source, a document, configuration, a dependency
or another lead family. It does not mean one dossier per target document. Supported findings
remain in the verification backlog, not confirmed-finding dossiers or remediation intake.
A separate **PoC dossier** is required for every accepted PoC candidate outcome, including
unsuccessful or unavailable outcomes; a supported claim can therefore have a PoC dossier without
becoming a confirmed finding.

These are implemented downstream projections. Dossier rendering must not adjudicate a claim,
re-score it, strengthen its evidence, or clear its shipment decision. The authoritative existing
records are the accepted inference handoff, its verified single claim ledger, exact finding and
score packages, and the accepted evidence manifest. `FindingBinding` contains exactly
`claim_id`, `finding_package_id`, `sha256`; the full upstream provenance must also retain the
adjudication and review identities. `DossierKind` is `confirmed_finding` or `poc`.

The distinction between **available**, **admissible**, and **publishable** is essential:

| Layer | What it establishes | Resolver / rule |
| --- | --- | --- |
| Dataset declaration | A producer may emit this kind of output, with a stated visibility and query route. It does not establish that bytes exist. | [`runtime/datasets.py`](../../src/appsec_review/runtime/datasets.py), `DatasetDeclaration`, `dataset_contract` |
| Accepted artifact / shard | Exact run-owned bytes, schema, producing attempt and upstream identities have been accepted. Acceptance alone is not a security finding. | [`indexing/store.py`](../../src/appsec_review/indexing/store.py), `accepted_handoff`; [`jobs/bound_artifacts.py`](../../src/appsec_review/jobs/bound_artifacts.py), `resolve_bound`, `read_bound_json`; [`retrieval/index.py`](../../src/appsec_review/retrieval/index.py), `load_verified_manifest` |
| Evidence relation | A citation resolves to accepted bytes with a predicate-specific admissibility class and completeness flag. | [`review/evidence.py`](../../src/appsec_review/review/evidence.py), `resolve_relation`, `classify`, `satisfies`; [`review/admission.py`](../../src/appsec_review/review/admission.py) |
| Adjudication / finding | Deterministic obligations and independent verification determine state, independently of model agreement or document rendering. | [`review/adjudication.py`](../../src/appsec_review/review/adjudication.py), `adjudicate`; [`review/independence.py`](../../src/appsec_review/review/independence.py), `verify_independence` |
| Protected dossier projection | Only cited direct/analyst-assessed relation rows, bounded resolving excerpts and allowlisted finding/score/chain/PoC/remediation/provenance fields enter the model. Inventory availability does not automatically copy every dataset into it. | [`job_dossier_publication/job.py`](../../src/appsec_review/jobs/job_dossier_publication/job.py), `_excerpts`, `_chains`, `_remediation`; [`reporting/dossiers.py`](../../src/appsec_review/reporting/dossiers.py), `build_dossier` |
| Public projection | Only approved fields and hash-bound references leave the protected developer artifact. | Shared [`jobs/accepted_review.py`](../../src/appsec_review/jobs/accepted_review.py), `project_finding`, `project_score`; [`job_final_publication_gate/attachments.py`](../../src/appsec_review/jobs/job_final_publication_gate/attachments.py) certifies closed attachment projections. Report assembly reads only that certified snapshot. |
| Protected standalone export | Default-on deterministic local OpenVEX generation/validation projects all and only gate-publishable confirmed findings as `affected`, retaining exact certified context/exclusions in a protected companion. Truthful tool author and accepted-snapshot namespace require no setup; explicit disable is opt-out. This is a separate post-gate consumer, never a dossier/report input or completion barrier. | [`jobs/job_openvex_export/job.py`](../../src/appsec_review/jobs/job_openvex_export/job.py), [`contracts.py`](../../src/appsec_review/jobs/job_openvex_export/contracts.py), [`settings.py`](../../src/appsec_review/jobs/job_openvex_export/settings.py); [shared-contract boundary](../schemas/openvex-export/README.md), [design](openvex-export.md), [verification record](../reviews/openvex-export-implementation.md). Registration and unit coverage do not establish a commissioned real-run output. |

Only complete `direct` and `direct_for_mapped_predicate` relations count toward obligations.
`analyst_assessed` and `indirect` evidence remains useful context, not counted proof. The six closed
predicates are `affected_construct`, `attacker_input_control`, `source_to_sink_reachability`,
`missing_or_ineffective_guard`, `configuration_enables`, and `security_impact`.
Judge-derived citations are retained but are not counted by `adjudication-rules/1`.
Document declarations, tags, hotspots, history, feed intelligence and precomputed summaries
cannot establish target behavior merely because retrieval returns them.

No inventory work here inspects a target checkout, evaluator answer key, ground truth, credentials,
or raw prompts. Existing source resolvers are described as product capabilities, not exercised
against a target for this document. Target-owned guidance is not dossier authority.

## 2. Identity spine and effective review inputs

| Input | Effective data available now | Provenance, restrictions and dossier use |
| --- | --- | --- |
| Intake and source scope | Run id, target snapshot / source fingerprint, accepted catalog, exclusions, source and artifact intake, project/component/build-unit partitions. | [`job_review_intake/job.py`](../../src/appsec_review/jobs/job_review_intake/job.py), `resolved_configuration`; [`jobs/cataloging.py`](../../src/appsec_review/jobs/cataloging.py); [`job_target_catalog/job.py`](../../src/appsec_review/jobs/job_target_catalog/job.py). Host paths and complete intake documents are not public output. An excluded file is outside observed coverage, not safe. |
| Acquired system provenance | Requested system/component identities, pinned acquisition plan/result, run-owned system-manifest copy/hash and component gaps; intake binds the composed source fingerprint. | [`job_target_acquisition/job.py`](../../src/appsec_review/jobs/job_target_acquisition/job.py), `selection.resolve_system`, `acquisition.acquire_components`, `publication.publish_handoff`; [operations](../operations/target-acquisition.md). Direct `--target` has no requested-system acquisition. A source component pin is not a deployed product/version identity. |
| Frozen binary publications | Intake binds configured binary hash, Ghidra publication identity/manifest hash and availability; indexing re-verifies them, builds bounded binary shards and detaches hash-bound pseudo-C into the run. | [`job_binary_evidence_indexing/job.py`](../../src/appsec_review/jobs/job_binary_evidence_indexing/job.py), `accepted_binary_evidence`, `verified_publication`; `source_resolution.publish_binary_source`. Functions/calls require a resolving binary/address/line anchor; imports/strings are navigation, not citeable proof. |
| Frozen configuration | Original TOML layers, runtime profile, capacity overlay, canonical resolved JSON, configuration manifest and resolved SHA-256; job-local settings, policy hashes and opaque operator release declarations. | [`config/loader.py`](../../src/appsec_review/config/loader.py), [`runtime/runner.py`](../../src/appsec_review/runtime/runner.py), `runtime/job.py::Job.identities`. Use frozen configuration, not checkout defaults. Supplied platform payloads are excluded from customer-source fingerprinting; retained rendering template provenance is not automatic code/template reuse invalidation. Follow [operator releases](../operations/performance-assurance.md#operator-declared-releases), never rewrite frozen declarations. |
| Guidance identity | Hash-pinned bundle, registry/fragments/procedures and generated capability/budget receipt identities; provider/model/reasoning and role assignments. | [`guidance/compose.py`](../../src/appsec_review/guidance/compose.py), `bundle_sha256`; `data/guidance/<bundle-sha256>/`. Record hashes and allowed metadata, never copy raw guidance/prompts into a dossier or reinterpret it as evidence. |
| Accepted review scope | Accepted retrieval manifest hash/path, source snapshot, package manifest hash, exact shard set, evidence map and scope gaps. | [`review/scope.py`](../../src/appsec_review/review/scope.py), `AcceptedScope`; inference `scope.accept_manifest`. No broad target scan or later mutable accepted pointer substitutes for this identity. |
| Lead packages | Scanner/rule, reported/native/assessed severity and basis, family, exact location, suppression and duplicate state, KEV/advisory/CWE context, obligations, graph and build context. | [`review/packages.py`](../../src/appsec_review/review/packages.py), `lead_record`, `PackageSettings`, `verify_package_manifest`; stored inference package schema is `review-package/6`. Suppressed and duplicate leads remain accounted; lead urgency is not accepted finding severity. |
| Hunt packages | Ranked review units, complete partitioned lead menus, selected source/artifact identities, bounded sink/entry/guard/range/path/caller/memory context, retrieval grants and omitted counts. | Same module, `build_units` / `rank_units` integration; [`review/units.py`](../../src/appsec_review/review/units.py). Context nominates investigation; it is re-resolved before it counts. |
| Pre-adjudication document packages | `finding_lead`, scanner `hunt`, `document_hunt`; exact route/boundary subject, document member identities, declarations/intents, proof obligations and restricted retrieval. | Separate [`review_packages.py`](../../src/appsec_review/review_packages.py), `assemble_review_packages`, `validate_packages`, `verify_review_packages`: `review-package/3`, `review-package-manifest/2`. Do not confuse these with inference's `review-package/6` and `review-package-manifest/1`. |
| Document-source candidate ledger | Exact route mapping status (`unique`, `ambiguous`, `unmapped`), accepted source/file/shard hashes and line, document evidence, empty proof slots, candidates and gaps. | [`document_issues.py`](../../src/appsec_review/document_issues.py), `analyze_document_hunts`, `verify_document_issue_ledger`. Automatic analysis does **not** supply independent red/blue/verifier proof: the verified ledger rejects nonempty findings/scoring inputs. Inference currently consumes indexing, not this ledger. A mapping is navigation, never an accepted confirmed finding. |
| Claims and evidence | Canonical affected entities, CWE/security consequence, preconditions, origin cells; support/contradict/qualify relations with predicate, entity kind, admissibility, shard, content hash, locator, completeness and retrieval receipt hash. | [`review/models.py`](../../src/appsec_review/review/models.py), `Claim`, `EvidenceRelation`; [`review/claims.py`](../../src/appsec_review/review/claims.py), [`review/evidence.py`](../../src/appsec_review/review/evidence.py). Preserve unresolved/qualified/contradictory evidence, not just supporting excerpts. |
| Ledger and adjudication | Hash-chained per-stream shards, deterministic merged events, ledger head, projection bytes/hash, predicate outcomes, counted relations, deciding row, gap ids and policy hash. | [`review/ledger.py`](../../src/appsec_review/review/ledger.py), `project`; [`job_inference_security_review/stages.py`](../../src/appsec_review/jobs/job_inference_security_review/stages.py), `merge_verified`, `write_ledger`, `finding_packages`. Dossiers reference, never rewrite, the sealed review. |
| Independence and judge | Actor/provider/model/fresh-conversation facts; separate provider/model distinctness, verifier evidence receipts; shuffled/de-shuffled judge verdicts and per-predicate citations, including disagreement with state. | [`review/independence.py`](../../src/appsec_review/review/independence.py), [`review/judge.py`](../../src/appsec_review/review/judge.py). An independent actor is mandatory for confirmation; distinct-model policy separately affects shipment blocking. Raw actor conversations are not dossier material. |
| Scores and shipment | Separate technical severity, exploitability confidence, environmental/business impact, remediation priority; provider/native values, missing factors, severity bounds and cited score identities; exact `ship-block-policy/1` result. | [`review/scoring/`](../../src/appsec_review/review/scoring/), [`review/ship_block.py`](../../src/appsec_review/review/ship_block.py), `decide`. Default `application_risk_matrix/3` decides technical severity. Null remediation priority stays null; planner text, CVSS/SSVC context and chain severity sums must not replace it. |
| Accounting | Expected/terminal cells, lanes, failed/capped/not-launched work, duplicates, coverage matrix, gap classes, incomplete-gap ratio and accepted review outcome. | [`review/accounting.py`](../../src/appsec_review/review/accounting.py); inference stages `audit`, `coverage_matrix`, `completeness_gaps`, `remediation_partition`. Keep review coverage distinct from later enhancement/render coverage. |
| Process telemetry | Run/job/attempt/step/task and invocation identities, lifecycle/duration/reuse/disposition/gap counters, receipt-resolved review/build/CodeQL scope, resource/work measurements and emitted model usage; fixed completion-lane event/outcome/counter/duration views. | [`observability/events.py`](../../src/appsec_review/observability/events.py), `PipelineLog`, `EventLog`; [`observability/telemetry.py`](../../src/appsec_review/observability/telemetry.py), `aggregate_run_metrics`, `_receipt_json`, `emit_model_event`; [`observability/completion.py`](../../src/appsec_review/observability/completion.py), `completion_metrics`. Operational context only; producer instrumentation and unknown-usage gaps remain separate from aggregate availability. |
| Judge PoC basis | Exact finding/package binding, supported/confirmed state, accepted judge verdict, `poc_basis` brief/hash and evidence refs. | Inference stages `poc_candidates`; [`job_poc_generation/candidates.py`](../../src/appsec_review/jobs/job_poc_generation/candidates.py), `brief.build_brief`. Entry/path use exact entity identities resolved through package-view `ref` rows, not display labels. Unknowns remain limitations, not invented evidence. Unresolved basis identities stop before writer dispatch; a judge's approval is not runtime proof. |
| Compile-only developer artifact | Inert test/control source, setup/debugger instructions, policy verdict, classified compiler commands, syntax/object/sanitizer-object checks, symbol checks, diagnostics and artifact/provenance hashes. | [`job_poc_generation/brief.py`](../../src/appsec_review/jobs/job_poc_generation/brief.py), `build_brief`; [`buildctx.py`](../../src/appsec_review/jobs/job_poc_generation/buildctx.py), `AcceptedBuilds`; [`buildcheck.py`](../../src/appsec_review/jobs/job_poc_generation/buildcheck.py), [`package.py`](../../src/appsec_review/jobs/job_poc_generation/package.py). Protected files now live under immutable `package.files` attempt paths; existing candidate directories are refused, not replaced. |
| Attack chains | Pre-seal proposals, blind refutation/required weakest-link challenges, typed single-ledger events, terminal artifacts and exact manifest accounting. | [`job_inference_security_review/chains.py`](../../src/appsec_review/jobs/job_inference_security_review/chains.py), [`review/attack_chains.py`](../../src/appsec_review/review/attack_chains.py). Five continuity dimensions require commissioned native facts; the default producer allowlist is empty. Source narrative or seed prose cannot establish deployment continuity. |
| Remediation | Confirmed-only outcomes, inert exact byte-edit patches, separate regression specifications, independent semantic assessments, bounded static/native syntax comparisons and cleanup receipts. | [`job_remediation_planning/job.py`](../../src/appsec_review/jobs/job_remediation_planning/job.py), [`job_remediation_validation/job.py`](../../src/appsec_review/jobs/job_remediation_validation/job.py); [operations](../operations/remediation.md). PoC context is not consumed in this slice (`poc_handoff: null`), despite ordering after PoC. No runtime regression or target mutation. |
| Dossiers | Closed protected model, bounded redacted excerpts/inert PoC source, per-finding/PoC-outcome membership, immutable JSON/LaTeX/PDF/receipt references and omitted/render-gap accounting. | [`job_dossier_publication/job.py`](../../src/appsec_review/jobs/job_dossier_publication/job.py), [`reporting/dossiers.py`](../../src/appsec_review/reporting/dossiers.py), [`dossier_render.py`](../../src/appsec_review/reporting/dossier_render.py); [operations](../operations/dossier-publication.md). Gate `/2` verifies accepted membership/files/receipts; particular run artifacts and live rendering still require their own resolving evidence. |
| Certified completion snapshot | Fixed five-capability enabled/disposition/item/omitted/gap accounting; sanitized PoC, chain, remediation and dossier attachments; every nested binding and frozen configuration hash. | [`job_final_publication_gate/attachments.py`](../../src/appsec_review/jobs/job_final_publication_gate/attachments.py), `verify_attachments`, `bind_tree`, `reverify_snapshot`; [`job_final_report_publication/job.py`](../../src/appsec_review/jobs/job_final_report_publication/job.py), `_verify_bindings`. Gate `/2` verifies producer envelopes, exact candidate/intake/dossier partitions, nonexecution, plan/patch/upstream custody and pointer stability. Report `/2` rejects uncertified refs and discovers no later optional producer. |

The shared accepted-review verifier now accepts handoff `/3` and re-hashes the ledger, individual
lead/hunt review packages and their manifests, findings, scores, coverage, scope and chain artifacts.
The hunt manifest content hash must equal required `package_manifest_sha256`; the separate lead
manifest content hash must equal required `lead_package_manifest_sha256`. Both identities are
retained in the verified review spine; verifying only one lane does not certify the other.
It checks run identity, duplicate finding/claim/score identities, canonical PoC-basis digest and
finding chain membership against the ledger, retaining these nested refs in its bindings.
It also verifies the chain manifest through `chains.verify_publication`
and proves that `remediation_intake` (confirmed) and `verification_backlog` (supported) exactly
partition accepted finding packages. Its current projection is intentionally narrower than a
developer dossier. A dossier needing the claim, adjudication or evidence content must resolve the
bound underlying artifacts rather than invent content omitted by `project_finding`.

## 3. Bounded query catalog

The complete public tool catalog is
[`mcp/schema.py::TOOLS`](../../src/appsec_review/mcp/schema.py), with OWASP defined separately in
[`mcp/owasp.py`](../../src/appsec_review/mcp/owasp.py). Implementations are
[`retrieval/core.py::RetrievalCore`](../../src/appsec_review/retrieval/core.py),
[`retrieval/graph.py`](../../src/appsec_review/retrieval/graph.py) and
[`retrieval/neighborhood.py`](../../src/appsec_review/retrieval/neighborhood.py), with syntax-only
navigation in [`retrieval/syntax.py`](../../src/appsec_review/retrieval/syntax.py).
These query accepted indexes; none launches CodeQL, parses arbitrary IR/CPG, or scans a target tree.

Unless noted, `limit` is 1-100 (also constrained by the consumer's configured maximum).
Paginated tools accept a bounded `cursor`; cursors bind the request and accepted manifest, not an
arbitrary offset into a changing dataset. The core library defaults are 100 results, 256 KiB
response, 2,000 ms deadline, trace depth 8, excerpt 64 KiB. These are library defaults, not a
promise that every model role is granted them. Results include provenance, coverage gaps and
pagination/truncation; exhausted bounds are never evidence of absence.

| Exact tool | Selectors / modes beyond `limit`, `cursor` | Data / important bound |
| --- | --- | --- |
| `search` | required `query`; `indexes`, `kinds` | FTS over accepted sanitized text; query 1-4096 characters. |
| `find` | `identity`, `kind`, `name`, `path`, `indexes` | Exact structured lookup of canonical `asr:<kind>:<sha256>` identities and source locations. |
| `read_excerpt` | required `identity`; `context_lines` 0-20 | Hash-verified UTF-8 excerpt; no `limit`/`cursor`; changed bytes are rejected, long excerpts explicitly truncated. |
| `trace` | required `identity`; `relations`, `depth` 1-8 | Typed bounded relationships; no cursor. |
| `resolve_evidence` | required `identity` | Observation/artifact/finding to supporting identities; no cursor; retain unresolved dependencies and coverage gaps. |
| `coverage` | `indexes` | Accepted producer, entity/relation counts and scoped coverage/gaps. |
| `query_artifacts` | `artifact_identity`, `sha256`, `kind`, `format`, `language`, `runtime`, `platform`, `architecture`, `build_unit`, `project`, `component`, `producing_build_action`, `package`, `purl`, `scanner`, `tool`, `coverage_status`, `shard` | Exact artifact and linked evidence facets. Coverage is `complete`, `partial`, `unavailable`, `stale`. |
| `query_debug_symbols` | required `mode`; exact `subject` or `artifact_identity`; optional build-relative `address`, `limit`, `cursor` | Accepted build-bound DWARF/PDB evidence, not inferred call graphs. Address and coverage require an artifact identity; source ranges require verified source identities. Layout queries use an artifact or exact normalized type identity. |
| `query_build_security` | `project`, `build_root`, `build_action`, `configuration`, `compile_unit`, `linked_artifact`, `producer`, `shard` | Accepted build-hardening and source/build/artifact scope, not deployment proof. |
| `query_ci_configuration` | `provider`, `pipeline`, `workflow`, `stage`, `job`, `step`, `tool`, `rule`, `category`, `canonical_finding`, `shard` | CI observations and correlated canonical CI records, not automatically inference-confirmed findings. |
| `query_codeql` | `language`, `source_language`, `scope`, `build_unit`, `rule`, `level`, `path`, `shard` | CodeQL observations; `shard` must match `codeql-*`. Tool severity remains scanner-reported. |
| `query_change_context` | `scope` (`file`, `function`, `component`), `path`, `component`, `signal` | Ranked review-priority context; exact signal vocabulary below. |
| `query_hotspots` | `scope` (`file`, `function`), `path`, `min_score` 0-100 | Priority-index metrics, evidence links and rank; not finding severity or an assertion of a flaw. |
| `query_precomputed` | required `query_set`; `subject`, `path` | Sixteen allowed names, only ten currently produced; see [query sets](#5-precomputed-query-sets-and-cross-domain-links). |
| `query_syntax` | required `mode` (`definitions`, `calls`, `imports`, `references`) and exact `source_file` or `ast_node` `subject`; optional exact written `name` (maximum 512 UTF-8 bytes) | Build-independent accepted Tree-sitter `analysis` projections, not semantic binding/call/dataflow. Default page 20, at most 100/core cap; an AST subject further bounds the byte span. Manifest/request-bound cursor; all names/imports/call targets remain unresolved. |
| `query_code_graph` | required `mode`, `subject`; `depth` 1-4, `sink_class`, `source_class` | Nine closed modes; subject kinds and applicable filters below. Reads accepted graph facts only. |
| `list_codeql_databases` | `language` | Accepted database cards: scope/language/root/build unit, seed ledger, depth/mode, family coverage, upstream producers and gaps. Language syntax is bounded to 64 characters. |
| `query_codeql_neighborhood` | required `database`; exactly one of `seed` (`path:line`), `symbol`, `observation`; `direction` (`callers`, `callees`, `both`), `depth` 0-4, `include` | `include`: `calls`, `sinks`, `entry_points`, `guards`, `ranges`, `paths`, `flow`, `diagnostics`, `symbols`, `cpg`; default calls/sinks. Seeded scope/depth/frontier restrictions still apply. |
| `query_observations` | `scanner`, `rule`, `severity`, `observation_class`, `suppressed`, `duplicate`, `source`, `artifact`, `path`, `start_line`, `end_line`, `shard`, `seed`, `function`, `fix_it`, `min_trace_length` 0-100000 | Native severity and normalization rule accompany normalized reported severity. Seed/function/fix-it/trace filters select Clang diagnostics; no automatic confirmation. |
| `query_dataset_inventory` | `record_type`, `job`, `family`, `disposition`, `coverage_state`, `sensitivity`, `cell_type` | Dataset/audit/coverage-cell records; dispositions and visibility below. Cell types: language, build unit, producer/consumer, input source, query set, graph follow-up, FTS validation. |
| `query_owasp_workbench` | `family`, `standard`, `version`, `profile`, `control`, `component`, `project`, `evidence_mode`, `validator`, `batch`, `disposition`, `shard` | Separate accepted OWASP store; families: `standards`, `component-classification`, `applicability`, `validation-work`, `control-result`, `finding-package`. Workbench dispositions are not inference claim states. |

`query_change_context.signal` is exactly `fast_review_change_count`,
`stale_approval_change_count`, `unapproved_mainline_change_count`, `off_hours_change_count`,
`pre_deployment_change_count`, `sprawling_change_count`, `repeated_repair_peak`,
`fix_on_fix_event_count`, `untested_production_change_count`, `lifetime_principal_author_share`,
or `departed_dominant_owner`.
`query_observations.severity` is `critical`, `high`, `medium`, `low`, `info`, `unknown`;
`observation_class` is `source_sast`, `secret`, `dependency`, `configuration`, `inventory`,
`binary`, `diagnostic`, `other`. Normalization is defined in
[`retrieval/observations.py`](../../src/appsec_review/retrieval/observations.py).

### Graph facts and support ceilings

[`graph/contract.py`](../../src/appsec_review/graph/contract.py) defines these supported modes.
`depth` applies only to callers/callees; class filters are limited to the modes shown.

| Mode | Accepted subject kinds | Family / optional class filter |
| --- | --- | --- |
| `callers`, `callees` | `symbol` | `call_site`; depth up to 4, producer/settings may be lower |
| `sinks` | `symbol`, `source_file`, `component`, `review_unit` | `sink_site`; `sink_class` |
| `entry_points` | `symbol`, `source_file`, `component`, `review_unit` | `entry_point`; `source_class` |
| `paths` | `sink_site`, `entry_point`, `symbol`, `source_file` | `dataflow_path`; `sink_class`, `source_class` |
| `guards` | `sink_site` | `guard_fact` |
| `ranges` | `sink_site` | `range_fact` |
| `summary` | `symbol` | `flow_summary` (indirect evidence for every predicate) |
| `sarif_path` | `tool_observation` | `dataflow_path`, retaining SARIF correlation limits |

Source classes: `remote`, `local_user`, `argv`, `environment`, `file`, `ipc`, `database`,
`internal`, `unclassified`. Sink classes: `memory_write`, `memory_read`, `allocation_size`,
`format_string`, `command_execution`, `path_access`, `sql_query`, `code_injection`,
`deserialization`, `integer_conversion`, `crypto_misuse`, `log_output`,
`server_side_request`, `xml_external_entity`, `ldap_query`, `xpath_query`, `html_output`,
`template_injection`, `url_redirect`, `header_injection`, `regex_injection`,
`unsafe_reflection`, `unclassified`.
Only the contract's attacker-reachable source classes can directly support attacker input control.

Exact location, complete coverage, acceptable cross-check state (`agree` or `not_covered`),
classified endpoints and a mapped predicate are necessary for direct graph-fact admissibility.
An unresolved indirect call, unsupported range, ambiguous mapping or partial/disagreeing
cross-check cannot silently become a direct proof. A dominating guard is not necessarily an
effective bound: `graph.bounds.fact_bounds_destination` and the citing role determine whether a
guard contradiction counts or is weakened to `qualifies`.

The graph catalog now has language aliases for C/C++, Java/Kotlin, JavaScript/TypeScript,
Python, Ruby, Go, C#, Rust and Swift; a catalog alias is not accepted extraction/coverage.
`graph.normalize.RANGE_ANALYSIS_METHODS` distinguishes C++ simple range analysis, Java range
analysis, C# constant/sign analysis, Go constants/dominating guards and Swift literal-only
analysis. JavaScript/Python/Ruby/Rust exports are `not-performed`; empty/nonintegral ranges
remain explicit family/operand gaps, not proof of a bound. See
[CodeQL graph facts](code-graph-precomputation.md) for per-language commissioned coverage.

Producer settings default to call depth 3, 200 neighbors/function, 8 paths/sink, 40 path steps,
16 guards/sink, 200000 facts/family/scope, 256 MiB export, 1800-second export timeout.
The run's resolved settings are authoritative. Neighborhood assembly additionally bounds its
walk to 500 call-site rows, 8 resolved subjects, 25 attached fact functions and 25 attached sinks;
listing retains at most 20 seeds, 3 sources/seed, 10 gaps/card. Producer-neighborhood copies cap
flow functions at 200, diagnostics at 1000, symbols at 500, CPG functions at 200, related symbols
at 20 and diagnostic traces at 50 steps
([`job_code_graph_index/producers.py`](../../src/appsec_review/jobs/job_code_graph_index/producers.py)).
The response names every reached frontier/bound; it is not a whole-program closure.

`aliases`, `slice_backward`, `slice_forward`, `type_layout`, `buffer_bounds` and a raw `cfg`
mode are **not** implemented modes at the inventory baseline. SVF points-to/memory-object records,
Clang AST type text and LLVM/Clang flow records already exist, but they do not imply those query
APIs or complete alias, layout, path-sensitive buffer or deployment proofs. The dedicated
[alias/slice/layout design](graph-alias-slice-layout-modes.md) records that proposed work.

### Consumer-specific source windows and queries

These are distinct surfaces; granting one does not grant another:

| Consumer | Effective retrieval | Bounds / limitations |
| --- | --- | --- |
| MCP client | Public catalog above, accepted manifest and read-only shards. | No arbitrary SQL, shell, analyzer invocation or raw database/target traversal. |
| Inference cell | [`review/capability.py`](../../src/appsec_review/review/capability.py), `CellCapability.authorize`, grants a subset of catalog tools (not OWASP in-process) plus application-only `expand`. | Package entity/index/query-set/graph-family/scope grants, page/depth/response caps and per-cell/run budgets apply. Locator convenience is limited to displayed package paths. `expand` accepts label/ref/files navigation and still runs authorized typed requests, with helper call depth capped at 3. |
| Chain continuity resolver | [`review/attack_chains.py`](../../src/appsec_review/review/attack_chains.py), `resolve_edge`, `_artifact_resolution`; job `chains.py::_BoundedResolutionCore`. | `trace(identity=output_entity, relations=..., depth=1, limit=max_page_size)` over `SAME_AS`, `FLOWS_TO`, `SUPPORTS`, `GENERATED_FROM`, `COMPILES_TO`, `LINKS_INTO`, `OBSERVED_AT`; artifact/configuration/deployment identities use `find(identity, limit=1)` and native artifact traces at depth `min(3,max_depth)`, limit `min(100,max_results)`. Each physical `trace`/`find` charges the run budget and per-edge resolution budget (default 12). Exhaustion resets obligations unresolved; truncated/gapped/ambiguous/capped evidence cannot prove continuity. |
| Labelled package view | [`review/package_view.py`](../../src/appsec_review/review/package_view.py), `build_view`; source/function, type, sink, range, guard, caller/callee, flow, entry, memory, build, tag and gap labels. | Library defaults: 48 KiB view, 160 function lines, 6 type declarations; fallback window is +/-12 lines, type extent 30 lines, displayed line 200 characters. Trimming has explicit omissions and material gaps; remaining gaps/corroboration have hash-referenced JSONL pages. Secret lead lines are redacted. A display label is not a durable evidence id. |
| Source resolver | `RetrievalCore.read_source_lines`, `read_excerpt`; [`retrieval/source_resolution.py`](../../src/appsec_review/retrieval/source_resolution.py), `read_source_bytes`. | Re-resolves an accepted location and exact file hash; UTF-8, source-byte and excerpt bounds. Ordinary target bytes must still match. Generated backing binds artifact/build handoff; binary backing binds publication/binary/function address. Both detach immutable run-owned bytes and verify run, target, logical path and source digest; no mutable workspace/publication fallback. Source verification limit is 16 MiB; backing metadata limit is 8192 bytes. |
| PoC writer | [`job_poc_generation/writer.py`](../../src/appsec_review/jobs/job_poc_generation/writer.py), `read_source`, `find_declaration`, answered by the application, not general model tools. | Hash-verified accepted native workspace and include scope; `read_source` at most 120 lines; declarations/types bounded by brief settings/file counts/bytes. Exact compile argv/environment remains protected; writer sees safe classified facts. |
| Remediation writer | [`job_remediation_planning/inputs.py`](../../src/appsec_review/jobs/job_remediation_planning/inputs.py), `SourceReader.resolve`, `retrieve`. | `find(identity, limit=1)` joins counted evidence to accepted native workspace hashes; defaults admit 8 files / 64000 total bytes, 262144 bytes/file ceiling and 32 evidence rows. A request names exactly `path`, `start_line`, `end_line`, at most 120 lines, within admitted files. No user-target fallback. |
| Dossier producer | `job_dossier_publication.job._excerpts`, accepted review/projection and hash-bound source manifest. | Sorted cited direct/analyst-assessed identities, default 4 excerpts, `read_excerpt(context_lines=2)`, 24 evidence rows, 40 lines / 4000 characters per code block. Trimming/redaction/omissions remain explicit; it does not gain a general model retrieval grant. |

`query_syntax` reads only `job_tree_sitter_ast` analysis shards using the partial SQLite
`syntax_lookup` expression index over source identity/category/written name; it never reparses
or accepts a query program/path/glob. Exact signed source-file grants admit returned nodes, not
AST-kind prefixes or sibling paths. Missing mappings, parse errors and bounded projections remain
coverage gaps. AST evidence is direct only for construct existence; interpreting guards, flow
or input control stays analyst-assessed, never direct merely because navigation succeeded.
[Tree-sitter architecture](tree-sitter-ast.md#bounded-syntax-navigation) lists the language subsets.

Native continuity payloads are **supported contract vocabulary, not currently commissioned
deployment evidence**. `resolve_edge` admits only an exact accepted relation between the edge's
output/input, a manifest-bound allowlisted `job_id/rule_id`, no ambiguity, and payload keys
exactly `schema`, `dimension`, `observed_scope`, `values`. Schema is
`chain-continuity-fact/1`; observed scope must equal the proposed environment. `_fact_outcome`
requires these exact dimension-specific `values`, not a producer/model's asserted success:

| Dimension | Closed native values / test |
| --- | --- |
| `identity` | `output_identity`, `input_identity`; equality. |
| `privilege` | `principal_out`, `principal_in`, `provided`, `required`; same principal and nonempty required privileges contained in provided privileges. Lists are unique, at most 64 items. |
| `trust_boundary` | `destination_zone`, `source_zone`, `transport_out`, `transport_in`, `enforcement_point_out`, `enforcement_point_in`; matching zone, transport and enforcement identities. |
| `artifact_deployment` | `artifact_out`, `artifact_in`, `deployment_out`, `deployment_in`, `configuration_out`, `configuration_in`; matching identities plus resolving source/configuration-to-artifact and artifact-to-deployment paths. Artifact entity kinds: object file, library, executable, build artifact, package, managed assembly, bytecode module, WASM module; deployment must be a deployment event, configuration a build action/compile unit. |
| `temporal` | Integer `a_start`, `a_end`, `b_start`, `b_end`, `output_at`, `input_at`; output precedes input inside both validity intervals. `version_out`, `version_in`, `configuration_out`, `configuration_in` must match; artifact/temporal configuration disagreement contradicts continuity. |

Identity text is nonempty and bounded to 2000 characters. Missing/unknown/invalid fields are
unresolved; truncation, query/row caps and gaps cannot establish a clean prefix. Every retained
native relation includes accepted index/shard/relation identity, shard hash, native-content hash,
outcome and reason. Default `continuity_producers=[]` means none of this authorizes a model,
target document or source-only producer to invent deployed identity/privilege/time facts.

## 4. Physical indexes, shards and producer ownership

The 19 logical retrieval indexes are defined by
[`retrieval/index.py::INDEX_NAMES`](../../src/appsec_review/retrieval/index.py).
Each immutable SQLite/FTS shard carries `name`, `shard_id`, schema, SHA-256, fingerprint,
run-relative path, producer and gaps. Its `entities`, `locations`, `relations`, `coverage`,
`metadata` and `search_fts` tables retain identity, exactness, mapping confidence/ambiguity and
source hash/span. The accepted manifest hashes every shard and upstream manifest.
No single file named after an index should be assumed when it has multiple shards.

| Index | Source owner(s) and shard selector | Effective contents / resolver |
| --- | --- | --- |
| `source` | `job_target_catalog` | Accepted source-file inventory with file hashes/locations; `find`, `read_excerpt`, source resolver. |
| `components` | `job_target_catalog` | Project/component membership and partition identity; `find`, `trace`. |
| `build` | Catalog build units; `job_language_build` (`language-build*`, `jvm-*`); `job_cpp_compiled_analysis` (`cpp-*-compiled`) | Recipes, actions, compile units, source/object/link relationships; `trace`, `query_artifacts`, `query_build_security`, `build_provenance`. |
| `artifacts` | `job_artifact_indexing`: `catalog-*`, `members-*`, `relations-*` | Produced/accepted-input artifact identities, formats, content hashes, archive members and build relations; `query_artifacts`, `resolve_evidence`. |
| `build_security` | `job_post_build_security_assessment` | Accepted compile/link/artifact hardening observations, symbols/sections and coverage; `query_build_security`. |
| `compiled` | `job_cpp_compiled_analysis`: `cpp-*-binary` | Binary symbols and resolving source/build relationships, not a deployed process. |
| `debug_symbols` | `job_debug_symbol_indexing`: `symbols-*` | Build-bound normalized DWARF/PDB symbols, layouts, inline frames, compilation units and explicit coverage; `query_debug_symbols`. Raw symbol input and reader execution receipts remain protected. |
| `analysis` | Catalog declarations; Tree-sitter syntax/coverage; target plan (`target-analysis-plan*`); C++ `cpp-*-ast`, `cpp-*-ir` and blocked branches; clangd `clangd-*`; SVF `svf-cpp-scope-*`, `svf-coverage-*`; test/profile `test-coverage-*`, `profile-data-*` | AST/IR/symbols, planning, alias/memory, coverage/profile facts; `query_syntax` for Tree-sitter projections, `find`, `trace`, `read_excerpt`, precomputed joins, and scoped neighborhood copies where produced. |
| `observations` | Evidence collection per tool; CodeQL `codeql-*`; Clang `clang-static-*`, `clang-static-coverage-*`; C++ `cpp-*-infer`; CI `ci_*`; artifact scans `artifact-security*`; Joern `joern-*`, `joern-coverage-*` | Normalized scanner evidence, severity/suppression/duplicate/location/flow metadata and coverage; `query_observations`, `query_codeql`, `query_ci_configuration`. Coverage-only output is not successful semantic analysis. |
| `evidence` | CI `ci_findings*` | Correlated canonical CI findings; resolve to observations/source. The entity kind `finding_package` here is not sufficient to make it an inference-confirmed package. |
| `history` | `job_source_history_analysis`: `git-history*`; `job_change_context_analysis`: `change-context*` | Pseudonymous history/churn/hotspot/change/review/deployment-context signals; `query_change_context`, `find`, `trace`. |
| `priority` | `job_review_prioritization` | Ranked file/function review work, metrics, heuristics and semantic prioritization context; `query_hotspots`. |
| `tags` | `job_security_tagging` | Faceted basis-qualified language, stack, interface, weakness/control tags; `find`, `trace`. |
| `documents` | `job_target_catalog` | Hash/source-mapped declarations and intent records; `search`, `find`, `read_excerpt`, `document_context`. |
| `links` | `job_review_data_indexing`: `links-<family>` | Typed cross-domain representation, source, advisory, syntax and history links; `trace`, `resolve_evidence`. |
| `precomputed` | `job_review_data_indexing`: `qs-<query_set>` | Ten currently commissioned bounded products below, each pinned to the exact shards/rules/settings it read; `query_precomputed`. |
| `inventory` | `job_review_data_indexing` inventory; `job_dependency_intelligence`: `dependency-intelligence*` | Dataset/audit/coverage matrices and dependency/repository/Scorecard context. Distinguish inventory producer and entity kind; `query_dataset_inventory`, artifact/precomputed joins. |
| `graph` | `job_code_graph_index`: `graph-<scope_id>-<family>`, `graph-<scope_id>-database`, `graph-<scope_id>-producers` | CodeQL-first normalized facts, database cards, bounded producer-neighborhood copies; `query_code_graph`, database/neighborhood tools. |
| `binary` | `job_binary_evidence_indexing`: `binary-<binary_id>` (128-character shard-id cap) | `binary_function`, `binary_call_site`, `binary_import`, `binary_string`, `CONTAINS`/`CALLS`/`REFERENCES`; existing `search`, `find`, `trace`, `read_excerpt`, `coverage`, not a new binary query tool or CodeQL graph shard. |

OWASP remains a separate accepted JSON-shard store, not a nineteenth SQLite index. Its six families
and resolver are listed in the query table. Ghidra binary-decompilation publications remain a
separate hash-addressed pre-run facility, now admitted through the frozen intake and binary job:
[`binary_decompilation/publication.py`](../../src/appsec_review/binary_decompilation/publication.py),
`publish_export` / publication verification, retain program, functions, calls, imports, exports,
strings, gaps, hash-bound pseudo-C and p-code by binary/function address. Native decompilation is
not managed-bytecode evidence. Detached pseudo-C lives under `data/binary-evidence/sources/`,
with logical path `@binary/<binary-sha256>/<function-address>.c`; `binary_anchor` requires that path
to match the entity payload and pseudo-C lines. Imports/strings have no citeable source location.
Under `predicate-admission/2`, anchored functions/calls are direct for `affected_construct` only,
analyst-assessed for input control/reachability/guards, and indirect for configuration/impact.
The dossier can retain a cited bounded resolving excerpt, not bulk Ghidra tables or fabricated
semantic/deployment proof.

Central binary-index defaults cap 200000 functions, 1000000 call sites, 20000 imports,
200000 strings, 64 string cross-references, 4096 characters/string and 65536 text bytes/entity.
Truncation, unresolved/unlocated calls, unavailable/managed publications and unapplied debug
symbols remain gaps. No managed decompiler or binary-only `start --binary` review is commissioned;
see [binary architecture](binary-decompilation.md) and [operations](../operations/binary-decompilation.md).

## 5. Precomputed query sets and cross-domain links

Allowed names come from
[`retrieval/precomputed.py::QUERY_SETS`](../../src/appsec_review/retrieval/precomputed.py);
actual products and special additions are in
[`indexing/products.py::PRODUCT_RULES`](../../src/appsec_review/indexing/products.py) and
[`job_review_data_indexing/job.py`](../../src/appsec_review/jobs/job_review_data_indexing/job.py).
The input matrix's *design* endpoint labels (`core`, `query_datasets`) are not public tool names:
use the exact tools above, especially `query_dataset_inventory`.

| Query set | Effective accepted inputs / output now | Evidence ceiling |
| --- | --- | --- |
| `symbol_links` | Catalog/clangd symbols joined to accepted Tree-sitter syntax, definitions, call/reference counts and mapping metadata. | Name/line-only joins remain ambiguous; no universal overload/template/indirect-dispatch resolution. |
| `build_provenance` | Artifact/build/build-security/source relations; exact representation links; classified build commands/environment facts from accepted language/project receipts and capture events. | Public facts omit raw argv/env. Missing source maps or ambiguous producing actions remain gaps; no deployment identity is inferred. |
| `artifact_inventory` | Accepted catalogs/archive members grouped by build unit, family/format/hash, bounded artifact lists and omissions. | Inventory is not vulnerability, runtime use or reachability evidence. |
| `dependency_advisories` | Accepted scanner package/advisory pairs and dependency inventory joined to verified run-pinned OSV, NVD, KEV, EPSS and cve-bin-tool reference context; versions, aliases, fixed-version hints, CVSS and feed freshness. | An advisory does not establish the target version, vulnerable code use or reachability. Missing joins/freshness are explicit. |
| `scanner_correlation` | Source-SAST observations, suppression/duplicate mappings, exact source spans, syntax, dispositions; complete partitioned high/critical and unknown lead menus plus membership audit. | Nominates claims; tool findings are direct only for the rule's predicate mapping. A complete lead menu cannot be silently truncated. |
| `ci_trust` | CI observations/canonical records grouped by workflow and security categories, same-workflow path candidates, deployment-event count. | Always qualified for unresolved dynamic/reusable/external workflows and absent CI-to-build/artifact/deployment identity mapping. Co-location is not a proven privilege path. |
| `history_context` | History, change context, hotspots/priority, exact history/source links plus metric vectors (including accepted coverage/profile/dependency context). | Churn, ownership, approval timing and sampled hotness rank work; they do not prove a flaw or that missing tests mean no testing. |
| `control_evidence` | Accepted OWASP control results with applicability/status, worker/independent obligations, contradictory evidence, observations, coverage/bounds and manifest/shard/row references. `indexing.products.load_control_assessment` expands hash-verified full authority instead of trusting a depth-bounded payload and re-resolves typed citations against pinned upstream evidence. | Eligibility requires assessment mode, applicable/conditional status, not-satisfied control, resolving evidence and an anchored adverse mechanism. It nominates a provisional review lead; it is analyst-assessed context, never direct vulnerability or component-safety/runtime proof. Qualification-only/unresolved citations stay gaps. |
| `reference_intelligence` | Accepted weakness/CWE references joined to the pinned MITRE catalog, source observation identities and general weakness metadata. | Reference context is indirect for every target predicate. |
| `document_context` | Exact method/route joins among OpenAPI, Postman and recognized unit-test requests; DFD boundary/threat-model joins; member ids/counts, source locations and gaps. | Declarations/intent only. AsyncAPI/protobuf/GraphQL records can be indexed without being included in these route joins. No declaration or test proves enforcement. |
| `hotspot_context` | `pending_follow_up`: stage-3 composition with accepted graph families. | Named API support is not an implemented product. |
| `review_package` | `pending_follow_up`: stage-3 query-set composition. Existing package jobs are real but do not implement this query set. | Do not confuse an artifact package with an accepted `qs-review_package` shard. |
| `redacted_secret_exposure` | `pending_follow_up`: secret-scanner sink joins. Secret leads/normalization already exist. | No raw secret value belongs in a dossier; missing joins are not negative evidence. |
| `contract_enforcement` | `pending_follow_up`: interface-contract enforcement producer. | Parsed API/IDL declarations are not implementation-enforcement proof. |
| `deployment_exposure` | `pending_follow_up`: deployment-topology producer. Configuration scan observations already exist. | No verified runtime/deployment topology is manufactured from IaC or build output. |
| `test_intent` | `pending_follow_up`: assertion semantics and negative-case links beyond `document_context`. | Test names/requests/coverage counts do not prove a safety invariant. |

The retired graph query sets `call_graph`, `control_flow`, `dataflow`, `sarif_correlation`,
`ast_ir_cpg_mapping`, `guards_ranges`, `entrypoint_paths` are rejected names, not fallback
requests. Use graph modes or the producer-neighborhood `flow` records as appropriate.

[`indexing/links.py::LINK_RULES`](../../src/appsec_review/indexing/links.py) owns five independent
link shards: `representation`, `finding_source`, `package_advisory`, `symbol_syntax`,
`history_code`. They preserve `exact`, confidence, ambiguity and mapping method.
Equal text/name/line or content hash alone is not a universal exact identity join.
Derived facts preserve query-set/rule version, subject, coverage/gaps, basis and upstream
identities; following `DERIVED_FROM` is necessary when a dossier needs the original evidence.

Reference feeds start in shared publications, but indexing's `feed_pins` verifies and freezes each
snapshot and manifest/file hashes for a run. Stale snapshots remain explicitly stale.
NVD, OSV, MITRE, KEV and EPSS have verified SQLite feed indexes; cve-bin-tool's database is
retained as its own published feed asset. A current shared feed pointer must not silently replace
the pin a finding used. See [dependency intelligence](dependency-intelligence.md) and
[third-party operations](../operations/third-party-data-sync.md).

## 6. Per-dataset visibility and retention

This table accounts for all 145 `DATASETS` output kinds in the 44 integrated job `datasets.py` modules:
47 indexed, 64 artifact-only and 34 protected declarations
(120 kinds / 37 modules at the original contract baseline; 126 / 40 before the main integration).
Each producer name links to that declaration, which owns artifact patterns, schema and query route;
the [physical index catalog](#4-physical-indexes-shards-and-producer-ownership) identifies its shards.
These declarations are **not** actual run
inventory rows.

`I` = indexed/internal; `A` = artifact-only/internal; `P` = protected/sensitive.
`A(s)` denotes artifact-only but sensitive, which is not public merely because it is not declared
`protected`. Current declarations use no secret/public sensitivity overrides in these rows.
`artifact_only` and `protected` expose only sanitized identity/hash/status/coverage through dataset
inventory unless an explicitly scoped consumer reads accepted artifacts. No designation authorizes
bulk disclosure. Dossiers and PoC reproducer source are protected developer artifacts; their
sanitized public references do not make those bytes public.

| Producer declaration | I: indexed datasets | A: artifact-only datasets | P: protected datasets |
| --- | --- | --- | --- |
| [`job_model_connectivity`](../../src/appsec_review/jobs/job_model_connectivity/datasets.py) | none | `model_connectivity` | none |
| [`job_image_pin_verification`](../../src/appsec_review/jobs/job_image_pin_verification/datasets.py) | none | `image_pin_verification` | none |
| [`job_target_acquisition`](../../src/appsec_review/jobs/job_target_acquisition/datasets.py) | none | `target_acquisition` | none |
| [`job_review_intake`](../../src/appsec_review/jobs/job_review_intake/datasets.py) | none | `model_preflight`, `binary_evidence`, `review_intake` | none |
| [`job_target_catalog`](../../src/appsec_review/jobs/job_target_catalog/datasets.py) | `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units` | `target_artifact_inputs`, `catalog_documents` | none |
| [`job_target_analysis_plan`](../../src/appsec_review/jobs/job_target_analysis_plan/datasets.py) | `analysis_plan` | `analysis_plan_documents` A(s) | `planning_model_transcripts` |
| [`job_source_history_analysis`](../../src/appsec_review/jobs/job_source_history_analysis/datasets.py) | `history_signals` | `history_documents` | `raw_git_history`, `history_tool_io` |
| [`job_change_context_analysis`](../../src/appsec_review/jobs/job_change_context_analysis/datasets.py) | `change_context` | `change_context_documents` A(s) | `operator_exports`, `change_context_tool_io` |
| [`job_ci_configuration_analysis`](../../src/appsec_review/jobs/job_ci_configuration_analysis/datasets.py) | `ci_observations`, `ci_findings` | `ci_documents` | `ci_tool_io` |
| [`job_tree_sitter_ast`](../../src/appsec_review/jobs/job_tree_sitter_ast/datasets.py) | `tree_sitter_ast`, `tree_sitter_coverage` | `tree_sitter_node_shards`, `generated_source_backing` | `tree_sitter_tool_io` |
| [`job_project_build`](../../src/appsec_review/jobs/job_project_build/datasets.py) | none | `project_build_dispatch` A(s) | `probe_workspaces`, `image_build_streams` |
| [`job_language_build`](../../src/appsec_review/jobs/job_language_build/datasets.py) | `build_actions`, `jvm_build_actions` | `language_build_receipts` A(s) | `build_workspaces` |
| [`job_artifact_indexing`](../../src/appsec_review/jobs/job_artifact_indexing/datasets.py) | `artifact_catalog`, `archive_members`, `artifact_relationships` | `artifact_index_summary` | none |
| [`job_debug_symbol_indexing`](../../src/appsec_review/jobs/job_debug_symbol_indexing/datasets.py) | `normalized_symbols` | `symbol_coverage`, `target_decision`, `debug_symbol_summary` | `raw_artifact_refs`, `reader_executions` |
| [`job_artifact_security_analysis`](../../src/appsec_review/jobs/job_artifact_security_analysis/datasets.py) | `artifact_security_observations` | `artifact_security_results` | `artifact_scanner_io` |
| [`job_cpp_compiled_analysis`](../../src/appsec_review/jobs/job_cpp_compiled_analysis/datasets.py) | `cpp_build_graph`, `clang_ast`, `llvm_ir`, `infer_observations`, `binary_symbols`, `cpp_blocked_branches` | `cpp_plan_and_summary` A(s) | `cpp_case_material` |
| [`job_clang_static_analysis`](../../src/appsec_review/jobs/job_clang_static_analysis/datasets.py) | `clang_static_observations`, `clang_static_scope_coverage` | `clang_static_summary` | `clang_static_raw` |
| [`job_cpp_symbol_index`](../../src/appsec_review/jobs/job_cpp_symbol_index/datasets.py) | `clangd_symbols`, `clangd_coverage` | `clangd_summary` | `clangd_tool_io` |
| [`job_binary_evidence_indexing`](../../src/appsec_review/jobs/job_binary_evidence_indexing/datasets.py) | `binary_functions` | `binary_pseudo_c`, `binary_evidence_summary` | none |
| [`job_svf_alias_analysis`](../../src/appsec_review/jobs/job_svf_alias_analysis/datasets.py) | `svf_alias_sets`, `svf_alias_scope_coverage` | `svf_alias_summary` | `svf_alias_raw` |
| [`job_cpg_analysis`](../../src/appsec_review/jobs/job_cpg_analysis/datasets.py) | `cpg_graph_coverage`, `cpg_scope_coverage` | `cpg_summary` | `cpg_binary` |
| [`job_sanitizer_build`](../../src/appsec_review/jobs/job_sanitizer_build/datasets.py) | none | `sanitizer_build_summary` | `sanitizer_build_workspaces` |
| [`job_post_build_security_assessment`](../../src/appsec_review/jobs/job_post_build_security_assessment/datasets.py) | `build_security` | `build_security_documents` | none |
| [`job_evidence_collection`](../../src/appsec_review/jobs/job_evidence_collection/datasets.py) | `static_tool_observations` | `static_tool_evidence` | `static_tool_io` |
| [`job_codeql_analysis`](../../src/appsec_review/jobs/job_codeql_analysis/datasets.py) | `codeql_observations` | `codeql_predecessor_import`, `codeql_graph_export`, `codeql_plan_and_summary` | `codeql_scope_material` |
| [`job_code_graph_index`](../../src/appsec_review/jobs/job_code_graph_index/datasets.py) | `code_graph_facts` | `code_graph_stages`, `code_graph_checkpoints`, `code_graph_summary` | none |
| [`job_test_coverage`](../../src/appsec_review/jobs/job_test_coverage/datasets.py) | `test_coverage` | `test_coverage_handoff` | none |
| [`job_profile_data`](../../src/appsec_review/jobs/job_profile_data/datasets.py) | `profile_data` | `profile_data_handoff` | none |
| [`job_dependency_intelligence`](../../src/appsec_review/jobs/job_dependency_intelligence/datasets.py) | `dependency_context` | `native_discovery`, `native_spdx`, `native_sbom_provenance`, `native_sbom_metrics`, `scorecard_responses`, `dependency_intelligence_handoff` | none |
| [`job_owasp_control_assessment`](../../src/appsec_review/jobs/job_owasp_control_assessment/datasets.py) | `owasp_workbench` (separate store) | `owasp_documents` | `owasp_model_receipts` |
| [`job_review_prioritization`](../../src/appsec_review/jobs/job_review_prioritization/datasets.py) | `priority_items` | `prioritization_documents` | none |
| [`job_security_tagging`](../../src/appsec_review/jobs/job_security_tagging/datasets.py) | `tag_assignments` | `tagging_documents` | none |
| [`job_third_party_data_sync`](../../src/appsec_review/jobs/job_third_party_data_sync/datasets.py) | none | none | `feed_sync_work` (published snapshots are pinned separately) |
| [`job_review_data_indexing`](../../src/appsec_review/jobs/job_review_data_indexing/datasets.py) | `cross_domain_links`, `precomputed_products`, `dataset_inventory` | `accepted_input_summary`, `derived_checkpoints`, `fts_image_validation`, `dataset_audit_report`, `coverage_matrices` | none |
| [`job_review_package_assembly`](../../src/appsec_review/jobs/job_review_package_assembly/datasets.py) | none | `review_packages` | none |
| [`job_document_issue_analysis`](../../src/appsec_review/jobs/job_document_issue_analysis/datasets.py) | none | `document_issue_ledger` | none |
| [`job_inference_security_review`](../../src/appsec_review/jobs/job_inference_security_review/datasets.py) | none | `accepted_scope`, `review_packages`, `claim_ledger`, `scores_and_findings` | `lead_triage`, `review_cells`, `attack_chains` |
| [`job_poc_generation`](../../src/appsec_review/jobs/job_poc_generation/datasets.py) | none | `poc_generation_summary` | `poc_writer_cells`, `poc_reproducers` |
| [`job_remediation_planning`](../../src/appsec_review/jobs/job_remediation_planning/datasets.py) | none | `remediation_planning_summary` | `remediation_proposals` |
| [`job_remediation_validation`](../../src/appsec_review/jobs/job_remediation_validation/datasets.py) | none | `remediation_validation_summary` | `remediation_validation_receipts` |
| [`job_dossier_publication`](../../src/appsec_review/jobs/job_dossier_publication/datasets.py) | none | none | `dossier_publications` |
| [`job_final_publication_gate`](../../src/appsec_review/jobs/job_final_publication_gate/datasets.py) | none | `publication_gate_decisions` | none |
| [`job_openvex_export`](../../src/appsec_review/jobs/job_openvex_export/datasets.py) | none | none | `openvex_verified_inputs`, `openvex_documents`, `openvex_export_accounting` |
| [`job_final_report_publication`](../../src/appsec_review/jobs/job_final_report_publication/datasets.py) | none | `final_report_publications` | none |

The runtime also owns configuration, attempt/status/unit/handoff/claim and orchestration receipts,
bounded event logs, sanitized retrieval audit receipts, and shared-object custody receipts.
[`runtime/datasets.py::RUNTIME_SHARED_NAMESPACES`](../../src/appsec_review/runtime/datasets.py)
accounts for `index-shard`, `owasp-shard`, `guidance`, `review-package`, `review-cell`, `cell-check`,
`feed-snapshot`, `shared-input`. These bookkeeping identities are not an additional source of
security truth. The pre-review indexing audit excludes downstream review/publication jobs; a
future dossier manifest and gate must account for their outputs directly rather than pretending
they were present in that earlier inventory.

For an actual run, `query_dataset_inventory` and the accepted inventory/audit artifacts supply
each dataset's producer, schema, sensitivity, disposition, exception reason, accepted artifact
hashes, query route and coverage state. An expected but absent output becomes `unavailable`
with a named reason. Disabled jobs can be excluded from inventory, so the frozen configuration
must accompany coverage interpretation. `indexed` is a disposition, not a complete-coverage
claim. See [review-data indexing operations](../operations/review-data-indexing.md).

### Operational telemetry and derived views

The existing canonical stream is `data/logs/pipeline.jsonl` (`telemetry-event/1`), with correlated
attempt logs under each attempt. `EventLog.write` mirrors local events to `PipelineLog.write`;
the central writer limits records to 64 KiB, nested depth to 6, collections to 200 entries and
strings to 8192 characters. Producer allowlists are still required: the local attempt write occurs
before central redaction, and raw patches/PoCs must never be logged under arbitrary keys.

`aggregate_run_metrics` / `write_run_metrics` in
[`observability/telemetry.py`](../../src/appsec_review/observability/telemetry.py) produce
`data/telemetry/summary.json` (`run-metrics/4`) from that stream, not from a target scan.
Available views include event and deduplicated lifecycle counts/conflicts/gaps, job/task and
operation timing, queue/reuse/disposition/work/throughput counters, bounded slow-operation
rankings, resource admissions/spans, emitted model invocations/tokens, authoritative
`FINDING_TRANSITION` counts and receipt-resolved source/build/artifact/CodeQL review metrics.
Overlapping spans are not additive resource totals. Missing model usage/cost and absent platform
measurements retain null/unavailable reasons where producers preserve them.

| Added operational view | Source identity / available measurements | Interpretation boundary |
| --- | --- | --- |
| `owasp` | `_owasp_metrics` resolves `OWASP_ASSESSMENT_RECORDED` hash-bound workbench reports: publication attempts/latest denominator, input retrieval versus source/citation resolution, requested expansions, model dispositions/roles/replay and verified reuse. | Latest invalid/missing receipts leave coverage unavailable, not an older-success fallback. Assessment counters and protected `owasp_model_receipts` are not independent evidence. |
| `review_flow` | `_review_flow_metrics` retains control-evidence/package/lane milestones, manifest pins and latest disposition per attempt/cell, fresh dispatch/query counts and verified reuse. | Reused historical retrievals are not fresh queries. Missing milestones mean unrecorded execution, not zero work. |
| `model_invocations` | Shared `observability/model_calls.py::call_model` emits correlated transport starts/completions, job/attempt/task/role/persona/cell/package/batch identities, request/guidance hashes, served identities and nullable usage. | Transport success does not validate assessment output. Recorded replay is separately labelled and excludes historic tokens/new-inference totals; raw requests/responses/source/errors are not copied into logs/dossiers. |
| `tree_sitter` | `_tree_sitter_metrics`, `tree-sitter-metrics/1`, verifies start/execution/output receipts and invocation/run/job/attempt identity; per-invocation file/node/truncation/resource counts, job-attempt groups, reuse, summed duration, elapsed window, covered wall time and concurrency. | Missing/conflicting/changed receipts create accounting gaps. Missing resources remain null; peak memory is the maximum individual container peak, not concurrent aggregate memory. |
| `codeql` | `_codeql_metrics`, `codeql-execution-metrics/1`, resolves action execution receipts plus `codeql-query-metrics/1`; database/analyze/compile/export rows grouped by pack/language/source language and pack-language, bounded per-query/rule rows and timings. | Reused/skipped actions count but do not enter fresh runtime statistics. Missing per-query source or runtime is a named gap, not zero analysis. |

The summary now also contains `completion`, with
`appsec-review/completion-process-metrics/1` semantics. Seven fixed lanes report `observed` and
per-event counts, allowlisted counters/outcomes/capability maps/flags/dimensions, separate null-token
measurements and missing-turn counters, nonadditive configured-limit ranges and duration
count/p50/p95/max/summed-work. Invalid measurements retain a total and at most 200 named gaps.
This is attempted event-scoped work, including retries, not unique accepted findings; overlapping
stage summaries must not be added. An unobserved lane is not an observed zero or a complete
missing-producer audit. Remediation `e769645f` now preserves unknown token dimensions as null and
genuine measured zeros, with explicit missing-turn/no-completed-turn metadata.
`872ca63d` adds fixed `certified_outcome_counts` to capability counters, including genuine zero
counts; report attachment counts are not disposition strings or unique finding counts.
Persistence/replay tests cover stale-summary replacement, idempotent regeneration, unchanged
source-log bytes and newly appended events without recounting old work. Legitimate source,
evidence or redaction gaps in dossiers/review remain distinct from zero telemetry measurement gaps.

These are regenerable operational views, not another retrieval index or an evidence-admission
route. Hash-bound metric receipts resolve run-owned artifacts; malformed/changed/escaping receipts
remain integrity gaps. Dossiers may retain safe scope/status references and omissions, not raw
logs or prompts. [Telemetry architecture](telemetry.md#evidence-completion-tracking-commissioned)
and [metrics operations](../operations/metrics.md#completion-rollout-tracking)
record actual completion aggregates, producer events and remaining instrumentation gaps.

## 7. Engineering evidence and explicit gaps

| Evidence family | Data that can actually be retained / queried | What must not be inferred |
| --- | --- | --- |
| CodeQL | Accepted per-language/scope observations and ordered SARIF flows, exported BQRS/hash identities, source/sink/call/guard/range/path facts, seed cards and bounded closures. | Build/source mode, language support and extraction coverage vary. A seeded sample is not whole-program negative coverage; a CodeQL path is not a deployed attack chain. |
| Clang AST / LLVM IR / clangd | Source-mapped AST nodes, declarations/types; IR entities and function flow (blocks, edges, dominance/post-dominance, def-use); optional replayed Clang source CFG; clangd definitions/references/calls cross-referenced to CodeQL. | LLVM control flow is not source-level path feasibility. Source CFG may be absent and has no block-to-source-line mapping; compiler/layout text does not implement a general layout query. These are C/C++ cross-check inputs, not alternative primary graph truth. |
| Clang analyzers / Infer | Check id, diagnostic location/message, fixes, trace length/steps and seed/function context over accepted native compile scopes. | Tool diagnostics are not independent confirmations; omitted/truncated trace and failed compile scope remain named gaps. |
| SVF | Opt-in linked `-O0` bitcode points-to sets, indirect-call targets and memory objects/allocation/accessor fan-in; exact line joins for C/C++ lead memory context. | Open-world/truncated sets can support a possibility, never rule out every alias/target/accessor. The general graph alias and slice modes remain proposed. |
| Joern CPG | Raw protected binary plus coverage and optional seeded bounded function rows (calls, branches, reaching-definition counts) copied into producer neighborhoods. | Shipped opt-in/disabled, not a primary graph producer. Binary existence is not graph coverage; bounded name-only callee matching/no block-line mapping is not complete CPG semantics. |
| Artifacts / SBOM | Accepted-input/build-output family, hash, format, language/runtime/platform/architecture, archive members, PURL/version, package/scanner/tool, producing action, source/object/link relations and scanner matches. | Artifact existence or package name is not deployed use. Media/asset filtering and unsupported formats are applicability accounting, not clean scans. |
| Dependencies / CVEs | Declared/manifest/lock/package-manager/SBOM, native linker/loader identities, repository resolution basis and OpenSSF Scorecard responses; NVD/OSV/KEV/EPSS/CWE joins and freshness. | Repository identity may be unresolved; version constraints may not be exact versions. `maximal_exposure` is maximum structured observed evidence or a conservative production default, **not** confirmed deployment. Scorecard and KEV are context, not target exploitation evidence. |
| CI / IaC / configuration | Cataloged CI hierarchy across recognized providers, static/security scanner observations, IaC/config leads and exact definition bytes. | No general evaluated dynamic workflow, cloud live-state, identity permission, CI-to-artifact or deployment topology proof. Missing `deployment_exposure` stays a gap. |
| Build / provenance / hardening | Accepted recipes/actions/workspace and image manifests, safe command/flag/environment hashes, source-to-output identities, compile/link symbols, hardening checks and processing dispositions. | Protected raw argv/env/logs are not public; a source/build chain does not prove installation, execution, reachability or release approval. A successful build is not a fixed vulnerability. |
| Test coverage | Bounded LCOV, Cobertura, JaCoCo and LLVM imports, line/branch/function totals/rates with source/build/report identity. | Importing retained coverage does not run tests, prove assertion semantics or close a security obligation. Missing/zero/partial coverage is not absence of tests. |
| Execution profiles | Folded stacks, perf-script, Callgrind, LLVM sample profiles; bounded symbol/module/event/count and source bindings, hotness rank. | Historical sampled execution is not a newly authorized run, attacker trace or proof of non-reachability. Name-only/ambiguous symbols stay qualified. |
| History / change context | Git/GitHub change/review metadata, pseudonymous authorship, churn/repair/revert/approval/deployment proximity, ownership and file/function/component rankings. | Temporal correlation, fast review or owner departure does not establish vulnerability or malicious intent; Perforce and missing metadata remain unsupported/unknown. |
| Controls / tags / priority | OWASP applicability/control results, cited evidence, taxonomy/crosswalk/basis-qualified tags, complexity/coupling/boundary heuristics and LLM prioritization context. | Assessment, tag basis or review priority is not accepted severity, target truth, or independent verification. |
| Documents / tests / interfaces | Selected design/threat-model/DFD text, headings/threats/boundaries/flows, OpenAPI/Postman requests, AsyncAPI/protobuf/GraphQL operations, recognized test cases/requests and source-backed record spans. | Collection/parser coverage is bounded; target documents describe intent/declarations, never worker authority. Missing tests/controls or route search misses cannot prove missing enforcement. |
| Sanitizers / PoCs | Instrumented object/binary catalog and instrumentation evidence; generated function/control policy, compile/symbol outcomes and developer files. | Neither pipeline executes the artifacts. No crash, before/after failure, passing negative control, `runtime_verified`, or resolved/fixed finding follows from compilation. |
| Chains / remediation | Five-dimension native continuity contract, candidate/challenge/ledger receipts; exact baseline-bound patch bytes, semantic assessments, seven validation dimensions, syntax-only baseline/patched diagnostics and cleanup custody. | Empty commissioned continuity allowlist prevents source prose from proving deployed chains. Native syntax covers one exact translation unit, not arbitrary languages, header/new-file/multi-build patches, full rebuilds or semantic/runtime fixes. |

Source implementations for these distinctions include
[`job_code_graph_index/producers.py`](../../src/appsec_review/jobs/job_code_graph_index/producers.py),
[`review/memory_context.py`](../../src/appsec_review/review/memory_context.py),
[`job_dependency_intelligence/resolution.py`](../../src/appsec_review/jobs/job_dependency_intelligence/resolution.py),
[`job_test_coverage/parsers.py`](../../src/appsec_review/jobs/job_test_coverage/parsers.py),
[`job_profile_data/parsers.py`](../../src/appsec_review/jobs/job_profile_data/parsers.py),
[`job_ci_configuration_analysis/discovery.py`](../../src/appsec_review/jobs/job_ci_configuration_analysis/discovery.py),
[`indexing/target_documents.py`](../../src/appsec_review/indexing/target_documents.py),
[`indexing/document_interfaces.py`](../../src/appsec_review/indexing/document_interfaces.py) and the
producer declarations above. Document collection defaults cap 128 files, 256000 bytes/file,
2000 records, 80 lines/4096 bytes per text chunk; structural parsing caps depth/nodes and records
unsupported constructs. Document-source mapping separately caps accepted files/bytes and currently
recognizes a narrow router-call pattern; it is not universal framework resolution.

## 8. Completion change map and unresolved integration

The table preserves the original contract-time change map. Delivered status is summarized below;
it must not be read as a claim that final end-to-end acceptance has passed. Detailed acceptance
remains in the [completion design](evidence-completion-and-remediation.md).

| Architectural piece | Baseline / required change | Pages and implementation surfaces to reconcile when merged |
| --- | --- | --- |
| Accepted-review reader | Today lives under gate `verify.py`; extract shared model-free verification for PoC, remediation, dossiers and gate without accepting unchecked dictionaries. | [Final report](../operations/final-report.md), [jobs/runtime](jobs-and-runtime.md); `jobs/accepted_review.py` (proposed), gate/PoC input readers and schema validators. |
| Single acyclic final gate | Today optional PoC follows gate and report separately discovers it. Move every enabled evidence/remediation/dossier producer before **one** final gate; report reads only the gate-certified snapshot. | [PoC operations](../operations/poc-generation.md), [final report](../operations/final-report.md), [wave1 operations](../operations/wave1-review.md); registry, direct graph, topology, CLI manual admission/upstream binding, Dagster pools/dependencies. |
| Immutable attempts | Today `write_candidate` replaces `data/poc/<claim-id>/`; use attempt-owned source/compile/provenance and accepted manifest refs so retries cannot mutate prior accepted bytes. | PoC operations, [dossier operations](../operations/dossier-publication.md); package writers, input identities, resume, artifact resolver and dataset patterns. |
| Chains before review seal | Today only red `chain-seeds.json` hints; add bounded composition, independent edge refutation/required weakest-link verification, typed ledger events and manifest before completeness/publication. No second ledger or post-seal mutation. | [Inference design](inference-security-review.md), [inference operations](../operations/inference-security-review.md), [red output](red-discovery-output.md); ledger/projector/closed validators, stages/settings, chain package references. |
| Exact finding attachments | `FindingBinding` already fixes claim/package/hash; retain adjudication, evidence/build/settings/tool/guidance provenance and reject cross-review mixing. Do not rebuild immutable findings to append PoC/patch state. | This inventory, [package contract](review-package-contract.md), gate/report contracts and new versioned attachment schemas. |
| Confirmed-only remediation | Confirmed intake already exists; add planning and nonexecuting validation with accounted outcomes, inert patches, exact baselines, safe regression specifications and independent semantic review. | Completion design, final-report/dossier operations; new job handlers/settings/schemas/datasets. Runtime regression remains `not_performed_by_policy`; `build_checked` is not `fixed`. |
| Dossier semantic job | Add `job_dossier_publication` after review and optional PoC/planning/validation, before gate; one per confirmed finding and per accepted PoC outcome. | [Dossier operations](../operations/dossier-publication.md), jobs/runtime, this inventory; producer manifest, strict schemas, typed limits, run-owned immutable output declarations. |
| Protected vs public | Developer JSON/LaTeX/PDF can carry bounded resolving source and inert PoC function text, never credentials/raw prompts/arbitrary transcripts. Public JSON/Markdown/HTML/PDF show sanitized summaries/statuses and refs only. | [Rendering](../operations/report-rendering.md), final report and dossier operations; renderer-neutral models, loaders, escaping/redaction, public schemas and leak tests. Existing diagnostic full-run rendering is not automatically a safe dossier/public loader. |
| Rendering outcomes | Retain deterministic JSON and LaTeX even if PDF fails; real PDF only with receipt/hash and an explicit render status. Failed/capped/missing rendering is an accounted named gap, not an empty or fabricated PDF. | Dossier/rendering operations; commissioned LaTeX image/template/palette and hardened execution, cleanup receipts and retry behavior. The originally required live seeded sample and real PDF smoke are now owner-verified; see [retained sample](../operations/dossier-publication.md#verified-seeded-sample). |
| Versioning / configuration | Shared `/1` completion schema ids are declared, not implemented schema files/producers. Version review/ledger/PoC/gate/report contracts together; strict exact-version dispatch, no rewriting old runs. | Completion design, jobs/runtime and schema links; typed central TOML/loader/profile allowlists, topology validators, target-independent launch, dataset/input matrix/planned consumers. Exact new settings/defaults wait for integration. |
| Telemetry / metrics | Existing correlated events and regenerable `run-metrics/3` support generic lifecycle/usage/scope accounting; add completion lane/stage/candidate outcomes, caps/gaps, adapter/render failures and durations from the outset. | [Telemetry architecture](telemetry.md), [metrics operations](../operations/metrics.md), dossier operations; producer `context.events`, `observability.telemetry.aggregate_run_metrics`, summary schema and focused coverage/redaction tests. Low-cardinality rollups only; no separate backend, raw payloads or inferred runtime/fixed assurance. |
| Resume / audit / acceptance | Bind accepted artifacts/settings/schema and operator-declared implementation/tool releases; invalidate dependent closure; enabled missing/failed/capped differs from disabled/empty scope. Supplied platform bytes are not customer fingerprints. | Wave1, jobs/runtime, [operator releases](../operations/performance-assurance.md#operator-declared-releases), indexing/dossier operations, implementation record; resume/manual dispatch/Dagster parity, exact candidate partitions, tamper tests, deterministic outputs and actual PDF evidence. |

### Delivered source and remaining integration

Integration `b702eb7` contains chain `ec9257bf`, dossier `065f736c`, remediation `6278e580`,
typed defaults/profiles, registration, input matrix, CLI/Dagster ordering and completion metrics;
`7641fa5` restores assurance validation within full schema-validated producer rows. Checkpoint
`18eae9f` includes shared reader `/3` alignment (`6f168400`) and metric parity. Final integration
`dd9c9ad` contains chain isolation/hardening `dd1f8018`, PoC/gate/report `c44eddc1`, remediation
`e769645f` and index-admission `3f28d871`. Combined checkpoint `6975aef2` merges main `093f26d5`
with that completion lane, retaining topology-derived CLI order, both required review manifest
hashes, identity-resolved PoC briefs and summary persistence/report-count regressions.

| Delivered surface | Source-verified state / remaining boundary |
| --- | --- |
| Shared review reader | `jobs/accepted_review.py` verifies handoff `/3`, ledger-bound chain publication/memberships, original actor/cell receipts, nested review-package refs, run identity, duplicate identities and the PoC-basis digest. |
| Pre-gate topology | Registry and central config contain the same 44 jobs. CLI `_graph_order` derives its pre-/post-index split from `wave1_dependencies`; direct execution remains linear while Dagster follows dependencies over the same enabled jobs. Acquisition/binary indexing, debug symbols, security tagging and OWASP are retained before indexing; PoC/planning/validation/dossiers precede one gate. Report and default-on OpenVEX independently consume that gate. New configurations enable all four completion jobs; old frozen settings remain immutable. PoC has no gate dependency. |
| Chains | Three pre-seal units, strict native continuity policy, protected dataset/manifest and exact actor-receipt accounting exist. `stages.base_review_projection` validates exact enhancement-cell coverage while excluding those cells/gaps from base completeness accounting; the full ledger/projection retains them and publication exposes enhancement gaps separately. Integrity failures still fail. |
| PoC / gate / report | Immutable protected PoC attempt files and exact `/2` producer/provenance contracts; gate `/2` verifies all optional nested artifacts, candidate partitions and five-capability accounting; report `/2` consumes only the frozen certified snapshot. Disabled manual PoC requires explicit authenticated upstream admission, never silent pointer discovery. |
| Remediation | Real planning/validation producers and `/1` strict schemas, exact-patch format and `native_syntax` adapter exist. Job-scoped validated role bundles are hash-pinned; uncommissioned native profiles retain manual outcomes. Neither PoC context nor regression-function compilation is commissioned. |
| Dossiers | Real semantic job, strict typed bounds, closed projection, hardened renderer and `dossier-rendering-receipt/1` exist. Gate certification is implemented. Owner-verified seeded PDFs, navigation and repeat rendering are recorded in [operations](../operations/dossier-publication.md#verified-seeded-sample); the historical all-lane check separately uses a renderer double and preserves inherited/source gaps. |
| Metrics | `run-metrics/4.completion` preserves `completion-process-metrics/1` alongside OWASP/review-flow/Tree-sitter/CodeQL/model views. Fixed lane/status/capability maps include `not_launched` and certified report outcome counts; limits are nonadditive and unknown tokens remain unavailable. `b9e69d17` scopes enabled/disposition maps to the gate certification event. Historical owner all-lane checks observe seven lanes / zero measurement gaps without clearing review/evidence gaps; current-main/live acceptance remains separate. |
| Index admission / resume inventory | `3f28d871` excludes the three new completion consumers from active pre-review acceptance. `registry_providers` still returns **all registered file owners and dataset declarations** for resume auditing; do not remove downstream ownership just because its output is not yet a pre-review input. |
| OpenVEX | At `74d93127`, checked-in and typed defaults automatically generate/verify protected local outputs: author kind `tool`, `AppSec Review`, conservative action and `source_snapshot` repository namespace; no setup, guessed external URL or release assertion. Explicit overrides remain strict, explicit disable opts out, and historical frozen disabled runs remain unchanged. Three protected dataset kinds, strict gate `/2` and review `/3` verification, seven-schema closure and canonical affected-only output remain. Shared gate authority rejects uncertified nested refs without optional-head discovery. `run-metrics/4.openvex` preserves historical accepted semantics versus current latest/operator state. Report `/2` remains gate-only, not an export completion barrier. Focused units/installed-only pure-boundary packaging remain separate from real-run, integration, acceptance and live validation. |

Current versions are explicit, not implicit upgrades of old accepted runs:

| Contract family | Delivered identities / source |
| --- | --- |
| Review | `inference-review-handoff/3`, `ledger-event/1`, `finding-package/2`, `score-package/3`; shared `jobs/accepted_review.py` and inference schemas. Typed chain events did not bump the ledger to `/2`. |
| Source navigation / admission | `syntax-projection/1`, generated/binary source backing `/1`, `predicate-admission/2`; syntax navigation is unresolved, and located binary functions/calls require exact binary/address/line anchors. These do not upgrade arbitrary retrieved rows to counted proof. |
| PoC | `poc-generation/2`, `poc-generation-handoff/2`, `poc-provenance/2`, candidate schema `/2`; [PoC operations](../operations/poc-generation.md). Existing `/2` publication constants live in shared [`jobs/engineering_contracts.py`](../../src/appsec_review/jobs/engineering_contracts.py). |
| Chains / remediation / dossiers | `attack-chain/1`, `attack-chain-manifest/1`, `remediation-plan/1`, `remediation-planning/1`, `remediation-planning-handoff/1`, `remediation-validation/1`, `remediation-validations/1`, `remediation-validation-handoff/1`, `dossier/1`, `dossier-publication/1`, `dossier-publication-handoff/1` in [`jobs/completion_contracts.py`](../../src/appsec_review/jobs/completion_contracts.py), alongside `FindingBinding` and shared nonexecution assurance. |
| Rendering | `dossier-rendering-receipt/1`; exact template tree/files and configured renderer/image/settings refs. Public Markdown renderer is `final-report-markdown/2`; consolidated public PDF remains not rendered. |
| Final publication | `final-publication-gate/2`, `final-publication-gate-handoff/2`, `final-report/2`, `final-report-handoff/2`; shared engineering constants and [final-report schemas](../schemas/final-report/). |
| Telemetry | `telemetry-event/1`, `run-metrics/4`, `completion-process-metrics/1`, `tree-sitter-metrics/1`, `codeql-execution-metrics/1`; observational operator data, not evidence-admission schemas. Completion was first added to `/3`; current `/4` also includes CodeQL action/query views. |

The [bounded acceptance ledger](../reviews/evidence-completion-documentation-inventory.md#acceptance-ledger)
records owner source `039b24e4`: two checks passed in 306.43 s, including actual seven-lane
producer flow, zero telemetry measurement gaps, exact inherited gaps, unchanged finding
state/score/ship decisions and deterministic second report hashes. Model/compiler/renderer
boundaries are doubles, not live runtime/compiler reproduction. Stable `a709a10b` has the same
product trees. Separate remediation Linux 256 / zero skips and real seeded PDF results remain
attributed to their own snapshots.

Final immutable `967d1c7f` has 309 focused Linux passes, including all 180 cases in both OpenVEX
files and coupled completion/integrity/profile checks; no residual feature-coupled failure is
reported. Named phase results are the primary attribution. The final deduplicated coupled ledger
across incremental frozen XMLs is 1527 unique passes, six independently main-baseline failures
and one optional PowerShell-parser skip, covering all 40 selected files. This is not one clean
aggregate run; overlapping phase totals must not be added.
Fifteen named baseline selectors independently reproduce on main `093f26d5`;
this is not full-repository clean acceptance. The broad 111-file attempts remain partial.
Current-main merged-source validation, user-owned live validation and residual historical
consumer metadata are not closed by the historical native result. No target scan, assumed
deployment, doubled compile outcome or generic metrics pass substitutes for those boundaries.
