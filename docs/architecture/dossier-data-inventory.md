# Dossier data, queries and provenance

Status: source-verified inventory at contract commit
`5f5548da3d039f73c7d6858d2b28a4593a264efe`, 2026-10-28. This is a catalog of
implemented input surfaces, **not** evidence that a particular run produced them. Completion,
remediation and dossier publication remain proposed at this commit, except for the shared
constants and binding helpers in
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

These are proposed downstream projections. Dossier rendering must not adjudicate a claim,
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
| Public projection | Only approved fields and hash-bound references leave the protected developer artifact. | Existing [`job_final_publication_gate/verify.py`](../../src/appsec_review/jobs/job_final_publication_gate/verify.py), `project_finding`, `project_score`; proposed attachment certification in [section 8 of the design](evidence-completion-and-remediation.md#8-gate-limitations-and-reporting) |

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
| Frozen configuration | Original TOML layers, runtime profile, capacity overlay, canonical resolved JSON, configuration manifest and resolved SHA-256; job-local settings and policy hashes. | [`config/loader.py`](../../src/appsec_review/config/loader.py), [`runtime/runner.py`](../../src/appsec_review/runtime/runner.py). Use the run's frozen configuration, not today's checkout defaults. Capacity and semantic identity have different reuse rules. |
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
| Judge PoC basis | Exact finding/package binding, supported/confirmed state, accepted judge verdict, `poc_basis` value/hash and evidence refs. | Inference stages `poc_candidates`; [`job_poc_generation/candidates.py`](../../src/appsec_review/jobs/job_poc_generation/candidates.py). Basis labels resolve through the accepted package view; a judge's approval is not runtime proof. |
| Compile-only developer artifact | Inert test/control source, setup/debugger instructions, policy verdict, classified compiler commands, syntax/object/sanitizer-object checks, symbol checks, diagnostics and artifact/provenance hashes. | [`job_poc_generation/brief.py`](../../src/appsec_review/jobs/job_poc_generation/brief.py), `build_brief`; [`buildctx.py`](../../src/appsec_review/jobs/job_poc_generation/buildctx.py), `AcceptedBuilds`; [`buildcheck.py`](../../src/appsec_review/jobs/job_poc_generation/buildcheck.py), [`package.py`](../../src/appsec_review/jobs/job_poc_generation/package.py). Current mutable `data/poc/<claim-id>/` packaging is a known change boundary, not safe immutable retry storage. |
| Chains / remediation / dossiers | Shared versioned schema ids, exact `FindingBinding`, capability/kind/status enums and `nonexecution_assurance()` exist. Full producer manifests, patches, validations and dossier receipts do not yet exist at this baseline. | [`completion_contracts.py`](../../src/appsec_review/jobs/completion_contracts.py). Chain seeds are untrusted hints, not accepted chains. See [change map](#8-completion-change-map-and-unresolved-integration). |

The existing gate verifier re-hashes the ledger, package manifests, findings, scores and coverage,
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
[`retrieval/neighborhood.py`](../../src/appsec_review/retrieval/neighborhood.py).
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
| `query_build_security` | `project`, `build_root`, `build_action`, `configuration`, `compile_unit`, `linked_artifact`, `producer`, `shard` | Accepted build-hardening and source/build/artifact scope, not deployment proof. |
| `query_ci_configuration` | `provider`, `pipeline`, `workflow`, `stage`, `job`, `step`, `tool`, `rule`, `category`, `canonical_finding`, `shard` | CI observations and correlated canonical CI records, not automatically inference-confirmed findings. |
| `query_codeql` | `language`, `source_language`, `scope`, `build_unit`, `rule`, `level`, `path`, `shard` | CodeQL observations; `shard` must match `codeql-*`. Tool severity remains scanner-reported. |
| `query_change_context` | `scope` (`file`, `function`, `component`), `path`, `component`, `signal` | Ranked review-priority context; exact signal vocabulary below. |
| `query_hotspots` | `scope` (`file`, `function`), `path`, `min_score` 0-100 | Priority-index metrics, evidence links and rank; not finding severity or an assertion of a flaw. |
| `query_precomputed` | required `query_set`; `subject`, `path` | Sixteen allowed names, only ten currently produced; see [query sets](#5-precomputed-query-sets-and-cross-domain-links). |
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
`deserialization`, `integer_conversion`, `crypto_misuse`, `log_output`, `unclassified`.
Only the contract's attacker-reachable source classes can directly support attacker input control.

Exact location, complete coverage, acceptable cross-check state (`agree` or `not_covered`),
classified endpoints and a mapped predicate are necessary for direct graph-fact admissibility.
An unresolved indirect call, unsupported range, ambiguous mapping or partial/disagreeing
cross-check cannot silently become a direct proof. A dominating guard is not necessarily an
effective bound: `graph.bounds.fact_bounds_destination` and the citing role determine whether a
guard contradiction counts or is weakened to `qualifies`.

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
| Labelled package view | [`review/package_view.py`](../../src/appsec_review/review/package_view.py), `build_view`; source/function, type, sink, range, guard, caller/callee, flow, entry, memory, build, tag and gap labels. | Library defaults: 48 KiB view, 160 function lines, 6 type declarations; fallback window is +/-12 lines, type extent 30 lines, displayed line 200 characters. Trimming has explicit omissions and material gaps; remaining gaps/corroboration have hash-referenced JSONL pages. Secret lead lines are redacted. A display label is not a durable evidence id. |
| Source resolver | `RetrievalCore.read_source_lines`, `read_excerpt`; [`retrieval/source_resolution.py`](../../src/appsec_review/retrieval/source_resolution.py), `read_source_bytes`. | Re-resolves an accepted location and exact file hash; UTF-8, source-byte and excerpt bounds. Ordinary target bytes must still match. Accepted generated source has detached immutable backing bound to artifact/build unit, source hash, build handoff, logical path, target and run; no mutable build-workspace fallback. Source verification limit is 16 MiB. |
| PoC writer | [`job_poc_generation/writer.py`](../../src/appsec_review/jobs/job_poc_generation/writer.py), `read_source`, `find_declaration`, answered by the application, not general model tools. | Hash-verified accepted native workspace and include scope; `read_source` at most 120 lines; declarations/types bounded by brief settings/file counts/bytes. Exact compile argv/environment remains protected; writer sees safe classified facts. |

## 4. Physical indexes, shards and producer ownership

The 17 logical retrieval indexes are defined by
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
| `analysis` | Catalog declarations; Tree-sitter syntax/coverage; target plan (`target-analysis-plan*`); C++ `cpp-*-ast`, `cpp-*-ir` and blocked branches; clangd `clangd-*`; SVF `svf-cpp-scope-*`, `svf-coverage-*`; test/profile `test-coverage-*`, `profile-data-*` | AST/IR/symbols, planning, alias/memory, coverage/profile facts; `find`, `trace`, `read_excerpt`, precomputed joins, and scoped neighborhood copies where produced. |
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

OWASP is a separate accepted JSON-shard store, not an eighteenth SQLite index. Its six families
and resolver are listed in the query table. Ghidra binary-decompilation publications are also a
separate hash-addressed pre-run facility:
[`binary_decompilation/publication.py`](../../src/appsec_review/binary_decompilation/publication.py),
`publish_export` / publication verification, retain program, functions, calls, imports, exports,
strings, gaps, hash-bound pseudo-C and p-code by binary/function address. Native decompilation is
not managed-bytecode evidence. These files are **not** an automatically granted dossier query or
graph proof; an accepted run binding and resolving artifact references are still required.

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
| `control_evidence` | Accepted OWASP control results with applicability/status, resolving evidence citations and workbench row/shard references. | Unresolved freeform citations stay gaps; the referenced workbench is authoritative for its assessment, not an independent runtime observation. |
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

This table accounts for all 120 `DATASETS` output kinds in the 37 baseline job `datasets.py` modules.
Each producer name links to that declaration, which owns artifact patterns, schema and query route;
the [physical index catalog](#4-physical-indexes-shards-and-producer-ownership) identifies its shards.
These declarations are **not** actual run
inventory rows.

`I` = indexed/internal; `A` = artifact-only/internal; `P` = protected/sensitive.
`A(s)` denotes artifact-only but sensitive, which is not public merely because it is not declared
`protected`. Current declarations use no secret/public sensitivity overrides in these rows.
`artifact_only` and `protected` expose only sanitized identity/hash/status/coverage through dataset
inventory unless an explicitly scoped consumer reads accepted artifacts. No designation authorizes
bulk disclosure. Planned dossiers are protected developer artifacts even when an existing PoC
source declaration is currently `artifact_only/internal`.

| Producer declaration | I: indexed datasets | A: artifact-only datasets | P: protected datasets |
| --- | --- | --- | --- |
| [`job_model_connectivity`](../../src/appsec_review/jobs/job_model_connectivity/datasets.py) | none | `model_connectivity` | none |
| [`job_image_pin_verification`](../../src/appsec_review/jobs/job_image_pin_verification/datasets.py) | none | `image_pin_verification` | none |
| [`job_review_intake`](../../src/appsec_review/jobs/job_review_intake/datasets.py) | none | `model_preflight`, `review_intake` | none |
| [`job_target_catalog`](../../src/appsec_review/jobs/job_target_catalog/datasets.py) | `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units` | `target_artifact_inputs`, `catalog_documents` | none |
| [`job_target_analysis_plan`](../../src/appsec_review/jobs/job_target_analysis_plan/datasets.py) | `analysis_plan` | `analysis_plan_documents` A(s) | `planning_model_transcripts` |
| [`job_source_history_analysis`](../../src/appsec_review/jobs/job_source_history_analysis/datasets.py) | `history_signals` | `history_documents` | `raw_git_history`, `history_tool_io` |
| [`job_change_context_analysis`](../../src/appsec_review/jobs/job_change_context_analysis/datasets.py) | `change_context` | `change_context_documents` A(s) | `operator_exports`, `change_context_tool_io` |
| [`job_ci_configuration_analysis`](../../src/appsec_review/jobs/job_ci_configuration_analysis/datasets.py) | `ci_observations`, `ci_findings` | `ci_documents` | `ci_tool_io` |
| [`job_tree_sitter_ast`](../../src/appsec_review/jobs/job_tree_sitter_ast/datasets.py) | `tree_sitter_ast`, `tree_sitter_coverage` | `tree_sitter_node_shards`, `generated_source_backing` | `tree_sitter_tool_io` |
| [`job_project_build`](../../src/appsec_review/jobs/job_project_build/datasets.py) | none | `project_build_dispatch` A(s) | `probe_workspaces`, `image_build_streams` |
| [`job_language_build`](../../src/appsec_review/jobs/job_language_build/datasets.py) | `build_actions`, `jvm_build_actions` | `language_build_receipts` A(s) | `build_workspaces` |
| [`job_artifact_indexing`](../../src/appsec_review/jobs/job_artifact_indexing/datasets.py) | `artifact_catalog`, `archive_members`, `artifact_relationships` | `artifact_index_summary` | none |
| [`job_artifact_security_analysis`](../../src/appsec_review/jobs/job_artifact_security_analysis/datasets.py) | `artifact_security_observations` | `artifact_security_results` | `artifact_scanner_io` |
| [`job_cpp_compiled_analysis`](../../src/appsec_review/jobs/job_cpp_compiled_analysis/datasets.py) | `cpp_build_graph`, `clang_ast`, `llvm_ir`, `infer_observations`, `binary_symbols`, `cpp_blocked_branches` | `cpp_plan_and_summary` A(s) | `cpp_case_material` |
| [`job_clang_static_analysis`](../../src/appsec_review/jobs/job_clang_static_analysis/datasets.py) | `clang_static_observations`, `clang_static_scope_coverage` | `clang_static_summary` | `clang_static_raw` |
| [`job_cpp_symbol_index`](../../src/appsec_review/jobs/job_cpp_symbol_index/datasets.py) | `clangd_symbols`, `clangd_coverage` | `clangd_summary` | `clangd_tool_io` |
| [`job_svf_alias_analysis`](../../src/appsec_review/jobs/job_svf_alias_analysis/datasets.py) | `svf_alias_sets`, `svf_alias_scope_coverage` | `svf_alias_summary` | `svf_alias_raw` |
| [`job_cpg_analysis`](../../src/appsec_review/jobs/job_cpg_analysis/datasets.py) | `cpg_graph_coverage`, `cpg_scope_coverage` | `cpg_summary` | `cpg_binary` |
| [`job_sanitizer_build`](../../src/appsec_review/jobs/job_sanitizer_build/datasets.py) | none | `sanitizer_build_summary` | `sanitizer_build_workspaces` |
| [`job_post_build_security_assessment`](../../src/appsec_review/jobs/job_post_build_security_assessment/datasets.py) | `build_security` | `build_security_documents` | none |
| [`job_evidence_collection`](../../src/appsec_review/jobs/job_evidence_collection/datasets.py) | `static_tool_observations` | `static_tool_evidence` | `static_tool_io` |
| [`job_codeql_analysis`](../../src/appsec_review/jobs/job_codeql_analysis/datasets.py) | `codeql_observations` | `codeql_predecessor_import`, `codeql_graph_export`, `codeql_plan_and_summary` | `codeql_scope_material` |
| [`job_code_graph_index`](../../src/appsec_review/jobs/job_code_graph_index/datasets.py) | `code_graph_facts` | `code_graph_stages`, `code_graph_checkpoints`, `code_graph_summary` | none |
| [`job_test_coverage`](../../src/appsec_review/jobs/job_test_coverage/datasets.py) | `test_coverage` | `test_coverage_handoff` | none |
| [`job_profile_data`](../../src/appsec_review/jobs/job_profile_data/datasets.py) | `profile_data` | `profile_data_handoff` | none |
| [`job_dependency_intelligence`](../../src/appsec_review/jobs/job_dependency_intelligence/datasets.py) | `dependency_context` | `scorecard_responses`, `dependency_intelligence_handoff` | none |
| [`job_owasp_control_assessment`](../../src/appsec_review/jobs/job_owasp_control_assessment/datasets.py) | `owasp_workbench` (separate store) | `owasp_documents` | none |
| [`job_review_prioritization`](../../src/appsec_review/jobs/job_review_prioritization/datasets.py) | `priority_items` | `prioritization_documents` | none |
| [`job_security_tagging`](../../src/appsec_review/jobs/job_security_tagging/datasets.py) | `tag_assignments` | `tagging_documents` | none |
| [`job_third_party_data_sync`](../../src/appsec_review/jobs/job_third_party_data_sync/datasets.py) | none | none | `feed_sync_work` (published snapshots are pinned separately) |
| [`job_review_data_indexing`](../../src/appsec_review/jobs/job_review_data_indexing/datasets.py) | `cross_domain_links`, `precomputed_products`, `dataset_inventory` | `accepted_input_summary`, `derived_checkpoints`, `fts_image_validation`, `dataset_audit_report`, `coverage_matrices` | none |
| [`job_review_package_assembly`](../../src/appsec_review/jobs/job_review_package_assembly/datasets.py) | none | `review_packages` | none |
| [`job_document_issue_analysis`](../../src/appsec_review/jobs/job_document_issue_analysis/datasets.py) | none | `document_issue_ledger` | none |
| [`job_inference_security_review`](../../src/appsec_review/jobs/job_inference_security_review/datasets.py) | none | `accepted_scope`, `review_packages`, `claim_ledger`, `scores_and_findings` | `lead_triage`, `review_cells` |
| [`job_poc_generation`](../../src/appsec_review/jobs/job_poc_generation/datasets.py) | none | `poc_generation_summary`, `poc_reproducers` | `poc_writer_cells` |
| [`job_final_publication_gate`](../../src/appsec_review/jobs/job_final_publication_gate/datasets.py) | none | `publication_gate_decisions` | none |
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

This is the documentation reconciliation boundary, not a claim that the producers below shipped.
Detailed acceptance remains in the [completion design](evidence-completion-and-remediation.md).

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
| Rendering outcomes | Retain deterministic JSON and LaTeX even if PDF fails; real PDF only with receipt/hash and an explicit render status. Failed/capped/missing rendering is an accounted named gap, not an empty or fabricated PDF. | Dossier/rendering operations; commissioned LaTeX image/template/palette and hardened execution, cleanup receipts and retry behavior. A live seeded sample and real PDF smoke remain pending. |
| Versioning / configuration | Shared `/1` completion schema ids are declared, not implemented schema files/producers. Version review/ledger/PoC/gate/report contracts together; strict exact-version dispatch, no rewriting old runs. | Completion design, jobs/runtime and schema links; typed central TOML/loader/profile allowlists, topology validators, target-independent launch, dataset/input matrix/planned consumers. Exact new settings/defaults wait for integration. |
| Resume / audit / acceptance | Fingerprint every consumed artifact/settings/schema/implementation/tool; invalidate only dependent closure; enabled missing/failed/capped differs from disabled/empty scope. | Wave1, jobs/runtime, indexing/dossier operations, implementation record; resume/manual dispatch/Dagster parity, exact candidate partitions, tamper tests, deterministic outputs and actual PDF evidence. |

Unresolved at this inventory baseline: final producer/summary shapes beyond the shared constants,
registered topology and defaults; actual chain manifest/ledger event version; final review/PoC/gate/
report schema versions; protected dossier dataset declarations and loader allowlist; exact render
receipt/manifest fields; availability of safe validation adapters; end-to-end accepted-run and
live PDF evidence. None is substituted with a target scan, an assumed deployment, or a compile
success. A later source-verified reconciliation should name the implementation commits and checks.
