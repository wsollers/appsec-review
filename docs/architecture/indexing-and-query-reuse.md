# Review data indexing and reusable retrieval products

Status: design plus first-batch implementation. The dataset inventory and audit, cross-domain links,
stage-1 precomputed sets, `query_observations` and `query_dataset_inventory` are implemented by
`job_review_data_indexing` (see [First indexing batch](#first-indexing-batch-implemented-coverage)).
Review packages and a private document candidate ledger now follow the accepted index.
Finding and scoring retrieval indexes remain dependent work. A missing product is reported as
unavailable.
This document describes review-worker evidence, not instructions to review workers.

## Goal and authority

One accepted run should let retrieval resolve a hotspot to source bytes, syntax, build context,
compiled representations, artifacts, scanner observations, CI and deployment context, history,
control assessments, reference intelligence, and bounded graph paths. A score or graph edge
prioritizes investigation; it is not a vulnerability finding. Every returned source location must
resolve against the run's accepted target snapshot, and every non-source fact must name a run-owned
artifact and producer. Unresolved mappings and missing coverage are explicit gaps.

The immutable index manifest remains the authority boundary. Jobs may reuse accepted upstream
shards and artifacts whose hashes and configuration identities match. Retrieval must never parse
raw source, LLVM IR, or a CPG during an inference call.

**Default rule:** every gathered or generated dataset gets a run-owned inventory record and
coverage disposition. Index its safe, bounded identities, facets, locations, relationships, and
summaries if they can affect review decisions. Precompute expensive cross-dataset joins and graph
questions. Retain raw binaries, bulky logs, credentials, exact build environments, and model
transcripts only as protected artifacts; index their sanitized metadata and provenance. An
indexable dataset without a queryable representation or an explicit exception is a publication
gap, not silent success.

## Current material and missing links

| Material | Current producer and accepted index | What is indexed now | Next indexable addition |
|---|---|---|---|
| Source snapshot | `job_target_catalog`, `source` | file identity, hash, excerpt location | link all representations to the exact snapshot file |
| Tree-sitter syntax | `job_tree_sitter_ast`, `analysis` | bounded AST nodes, spans, parent relations across configured grammars | stable symbol/call-site links and parse-gap coverage |
| C/C++ compiled syntax | `job_cpp_compiled_analysis`, `analysis` AST shard | selected Clang AST records | resolved definitions, references, template and macro origin links |
| C/C++ symbol graph | `job_cpp_symbol_index`, `analysis` | accepted clangd symbols, `CALLS` and `REFERENCES` | bridge symbols to syntax, IR, CPG, and priority items |
| LLVM IR | `job_cpp_compiled_analysis`, `analysis` IR shard | function definitions and uniquely resolved direct `CALLS` | basic blocks, CFG, def-use, memory operations, guards, source mapping |
| Joern CPG | `job_cpg_analysis`, run-owned artifact and unavailable observation shard | retained binary CPG; no retrievable nodes or edges | bounded export of calls, CFG, PDG, data dependencies, and source mappings |
| CodeQL flows | `job_codeql_analysis` observations; `job_review_prioritization`, `priority` | SARIF paths, ordered source-resolved `review_flow_step` nodes and `FLOWS_TO` edges | correlate path steps to symbols, AST, IR, and CPG nodes |
| History and ranking | `job_source_history_analysis`, `job_change_context_analysis`, `job_review_prioritization` | metrics, SII, ranked hotspot items, evidence, one-hop import context | bounded graph context package per selected hotspot |

The AST and IR rows describe their present **partial** extraction. A successful producer run must
not be interpreted as complete semantic or control/data-flow coverage. PHP has no configured
CodeQL extractor; a language without a compiler or CPG branch still gets source and Tree-sitter
coverage when its grammar is supported.

## Other gathered and generated datasets

This inventory is by producer family, not by file extension. It records what is queryable today
and what the dataset audit must still prove or add. Existing domain-specific MCP queries may be
reused; a new copy of the same evidence is unnecessary.

| Dataset family | Producer | Present query surface | Required audit or addition |
|---|---|---|---|
| Resolved configuration, intake, target validation, tool and guidance identities | review intake and runtime | accepted run artifacts and handoffs | index sanitized provenance, enabled/disabled lanes, and reasons; keep secrets and prompt text protected |
| Repository partitions, languages, projects, components, declared dependencies | target catalog and analysis plan | `source`, `components`, `analysis`, `build` | verify all accepted project/build-unit edges and language coverage resolve |
| Build plans, captured actions, file accesses, compile/link flags, repair outcomes | project/language build and post-build assessment | `build`, `build_security` | index safe normalized ordered command facts, security-relevant environment classes and provenance; expose repair decisions and failed scopes; keep exact argv/env protected |
| Produced packages, archives, binaries, bytecode, WASM, symbols, SBOMs | artifact indexing and compiled analysis | `artifacts`, `compiled`, `build_security` | link member/package/symbol to producing action, source unit, and scanner observations |
| Artifact vulnerabilities, dependency advisories, license and secret leads | artifact security and evidence collection | `observations`, `artifacts`, `evidence` | normalize scanner-specific facts, deduplicate findings, link package/advisory/version evidence; keep secret values redacted |
| SAST, CodeQL SARIF, fuzz or dynamic evidence when present | evidence collection and CodeQL | `observations`, `priority` flow steps | retain native and normalized severity, rule identity, result location, ordered flows, suppressions, coverage, and artifact hash; correlate duplicate leads; include every High/Critical SAST lead in review-package nomination |
| CI workflows, steps, permissions, secrets usage and canonical findings | CI configuration analysis | `observations` and `evidence` CI shards; `query_ci_configuration` | connect workflow trust edges to build/deployment artifacts and source revisions |
| Commits, diffs, blame, reviews, deployments, ownership, SII, change context | history and change-context jobs | `history`, `priority`; `query_change_context` | index bounded review-unit links, exact fixes and ownership; leave raw diffs protected when large |
| OWASP applicability, controls, validators, dispositions | OWASP workbench | accepted workbench shards; `query_owasp_workbench` | cross-link controls to accepted findings, tests and source evidence without duplicating the workbench |
| Security tags and review-priority scores | tagging and prioritization | `tags`, `priority`; `query_hotspots` | link tag rationale and ranked items to exact supporting identities and coverage gaps |
| NVD, OSV, MITRE, CVE tool database and other reference feeds | third-party sync | verified global feed snapshots and metadata, outside the run manifest | pin feed snapshot per run; index advisory/weakness/technique facets and join them to observed target packages/findings |
| API contracts, deployment topology, tests, docs, dynamic traces | bounded OpenAPI, test and doc records indexed; exact route and boundary context derived; other formats planned or partly scanner-observed | `documents`, `precomputed/document_context`, and scattered source/scanner observations | distinguish declared, intent, computed, and observed evidence; derive route and boundary context without claiming enforcement |
| Run logs, raw tool outputs, exact environment, model transcripts, credentials | runtime and tool jobs | protected run-owned artifacts | only sanitized status, hashes, durations, producer and coverage enter retrieval; never index secret or raw model content |

### Input-source and retrieval matrix

This matrix is exhaustive for the **21 job families in the current registry/configuration** and
the planned input families named in the review architecture. It describes logical datasets,
not every file emitted by a tool. `Current` means an accepted index/query path exists today;
`extend` means a producer exists but the listed links or product do not; `planned` means the
input producer is not built. The emitted-dataset audit below remains the enforcement mechanism
for every configured step, language, scanner and newly added output, so this table cannot become
a silent allowlist. `query_precomputed` is abbreviated `QP`; existing generic `find`, `trace`,
`search`, `read_excerpt`, `resolve_evidence` and `coverage` are abbreviated `core`.

| Input source / current producer | Used for | Indexed state / required representation | Precompute | MCP endpoint; skill decision |
|---|---|---|---|---|
| Resolved TOML, model/tool/guidance identities, target fingerprint; `job_review_intake` | Bind run, enabled lanes and provenance | Extend: sanitized configuration identity, lane status, hash and gap; raw secrets/guidance protected | `review_package` coverage/basis | `coverage`/dataset catalog; no retrieval skill |
| Source snapshot bytes, paths, hashes; `job_target_catalog` | Resolve every cited location | Current `source` identities/excerpts; extend exact links to all representations | `symbol_links`, `hotspot_context` | `core`; no skill |
| Repository partitions, languages, projects, components and dependencies; `job_target_catalog` | Scope review and language routing | Current `components`, `analysis`, `build`; audit project/build-unit edges | `artifact_inventory`, `review_package` | `core`; existing `target-analysis-planning` skill is for operator planning only |
| Build recipes, compile database, dependency manifests; catalog/plan | Select tools, units and package identities | Current catalog/build facts; extend normalized manifest and build-target edges | `build_provenance`, `artifact_inventory` | `core`, `query_artifacts`; planning skill only |
| Analysis-plan proposals and routing; `job_target_analysis_plan` | Choose bounded producer work | Current `analysis`; index accepted rationale, scope and skipped lanes | `review_package` coverage | `coverage`, `core`; planning skill only |
| Local Git commits, diffs, blame and line/function history; `job_source_history_analysis` | Churn, entropy, fix-on-fix, SII, ownership | Current `history` and hotspot index; extend exact symbol and review-unit links | `history_context`, `hotspot_context` | `query_hotspots`, `query_change_context`, `QP`; no skill |
| GitHub PR/review metadata; history enrichment | Review cadence and direct-push signals | Conditional current history facts; unavailable when disabled; protect raw API payload | `history_context` | `query_change_context`, `coverage`; no skill |
| Review/deployment external facts and co-change/test association; `job_change_context_analysis` | Process anomalies and change context | Current `history`/priority facts; extend source/build/deployment identities | `history_context`, `ci_trust` | `query_change_context`, `QP`; no skill |
| Tree-sitter CST/AST; `job_tree_sitter_ast` | Syntax, symbols, boundaries and complexity basis | Current bounded `analysis` nodes/spans; extend stable symbols/call sites and parse gaps | `symbol_links`, `call_graph`, `hotspot_context` | `core`, `QP`; no skill |
| Cyclomatic, cognitive, coupling, taint-proximity and LPS features; `job_review_prioritization` | Rank review attention | Current `priority`; extend metric provenance and package vectors | `hotspot_context`, `review_package` | `query_hotspots`, `QP`; no skill |
| Project build probes/repairs; `job_project_build` | Establish build feasibility and selected recipe | Current `build`; extend repair decisions, failed scopes and sanitized provenance | `build_provenance` | `query_build_security`, `coverage`; existing `build-image-repair` skill is operator-only |
| Compile/link/archive commands, file accesses, env and toolchains; `job_language_build` | Reproduce source→artifact provenance and security flags | Current `build`/`build_security`; extend ordered redacted argv facts and allowlisted env classes; exact argv/env protected | `build_provenance`, `ci_trust`, `review_package` | `query_build_security`, `QP`; no worker skill |
| Language package-manager metadata and SBOM inputs; `job_language_build`/artifact jobs | Dependency identity and lock resolution | Current build/artifact/package facets; audit each ecosystem and version resolution | `artifact_inventory`, `dependency_advisories` | `query_artifacts`, `QP`; no skill |
| Files produced by builds: native, archives, packages, bytecode, assemblies, WASM; `job_artifact_indexing` | Artifact membership and source/build binding | Current `artifacts`; extend member/symbol/action links | `artifact_inventory`, `build_provenance` | `query_artifacts`, `QP`; no skill |
| Artifact security scans, format and vulnerability observations; `job_artifact_security_analysis` | Binary/package leads | Current `observations`/`artifacts`; extend dedup and advisory evidence | `scanner_correlation`, `dependency_advisories` | `query_artifacts`, `query_observations`, `QP`; no skill |
| Clang AST and compile-unit diagnostics; `job_cpp_compiled_analysis` | Resolved C/C++ types, definitions, macro/template context | Current partial `analysis`/`compiled`; extend origin and symbol links | `symbol_links`, `ast_ir_cpg_mapping` | `core`, `QP`; no skill |
| LLVM IR, binary symbols, Infer output; `job_cpp_compiled_analysis` | Compiled calls, CFG/def-use, hardening and leads | Current partial IR and observations; extend CFG, memory, guards, source maps | `call_graph`, `control_flow`, `dataflow`, `guards_ranges` | `core`, `query_build_security`, `QP`; no skill |
| clangd symbol graph; `job_cpp_symbol_index` | Definitions, references and direct calls | Current `analysis`; bridge to source/AST/IR/CPG | `symbol_links`, `call_graph`, `ast_ir_cpg_mapping` | `core`, `QP`; no skill |
| Joern CPG; `job_cpg_analysis` | Call, CFG and data-dependency graph | Binary artifact only; planned bounded graph export with source maps | `call_graph`, `control_flow`, `dataflow`, `ast_ir_cpg_mapping` | `QP` after export; `coverage` reports unavailable now; no skill |
| CodeQL database and SARIF paths; `job_codeql_analysis` | Analyzer leads and ordered flows | Current `observations`, priority flow steps; DB protected; extend graph correlation | `sarif_correlation`, `dataflow`, `scanner_correlation` | `query_codeql`, `QP`; no skill |
| Post-build flags, hardening and deterministic/model assessments; `job_post_build_security_assessment` | Artifact security posture | Current `build_security`; keep model judgment distinct from measured facts | `build_provenance`, `review_package` | `query_build_security`; existing `post-build-security-assessment` skill is operator-only |
| CI definitions, permissions, triggers, steps and scanner results; `job_ci_configuration_analysis` | Workflow trust and build/deploy exposure | Current CI observations/evidence; extend typed trust edges | `ci_trust`, `scanner_correlation` | `query_ci_configuration`, `QP`; no skill |
| Secret leads; Gitleaks and build-capture checks in `job_evidence_collection` | Identify possible credential exposure | Current observations; redacted fingerprint/location only; secret value protected | `redacted_secret_exposure`, `scanner_correlation` | `query_observations`, `QP`; no skill |
| Source SAST: Semgrep, Opengrep, gosec, mobsfscan, ShellCheck, phpcs, PHPStan, Psalm, SpotBugs, cppcheck, PMD; `job_evidence_collection` | Candidate defects, including High/Critical lead menu | Current observations; extend native/normalized severity, suppression, duplicate and membership audit | `scanner_correlation`, `review_package`, `hotspot_context` | `query_observations` for exact severity/scanner filters; `QP`; no skill |
| Syft software inventory; `job_evidence_collection` | SBOM/package identities | Current observations/components; extend package→artifact links | `artifact_inventory`, `dependency_advisories` | `query_artifacts`, `QP`; no skill |
| OSV-Scanner and Grype matches; `job_evidence_collection` | Dependency vulnerability leads | Current observations when enabled; retain feed/version identity and uncertainty | `dependency_advisories`, `scanner_correlation` | `query_observations`, `query_artifacts`, `QP`; no skill |
| Hadolint, Checkov, Trivy and Zizmor config scans; `job_evidence_collection` | IaC/container/workflow leads | Current observations; link to declared deployment/CI identity when possible | `scanner_correlation`, `ci_trust`, `deployment_exposure` | `query_observations`, `QP`; no skill |
| Blint binary scan; `job_evidence_collection` | Binary hardening leads | Current observations; link exact produced artifact | `scanner_correlation`, `artifact_inventory` | `query_artifacts`, `query_observations`; no skill |
| OWASP catalogs, applicability, validators and assessments; `job_owasp_control_assessment` | Control coverage and evidence obligations | Current workbench shards; extend links to findings/tests | `control_evidence`, `review_package` | `query_owasp_workbench`, `QP`; no skill |
| Taxonomy, crosswalk and assignments; `job_security_tagging` | Security facets and review routing | Current `tags`; retain assignment basis and gaps | `scanner_correlation`, `hotspot_context` | `core`, `QP`; no skill |
| NVD feed; `job_third_party_data_sync.nvd_sync` | CVE/CVSS/advisory reference | Current global snapshot; pin version per run and join to packages | `reference_intelligence`, `dependency_advisories` | `QP` or typed reference query if exact filters exceed it; no skill |
| OSV feed; `job_third_party_data_sync.osv_sync` | Package advisory reference | Current global snapshot; pin version per run and join PURLs/versions | `reference_intelligence`, `dependency_advisories` | `QP` or typed reference query; no skill |
| MITRE ATT&CK, CAPEC and CWE; `job_third_party_data_sync.mitre_sync` | Weakness/technique context | Current global snapshot; pin version per run and join exact mappings | `reference_intelligence`, `control_evidence` | `QP` or typed reference query; no skill |
| cve-bin-tool derived database; `job_third_party_data_sync.cve_bin_tool_db_build` | Binary-component advisory matching | Current global artifact; pin source NVD snapshot and database version | `reference_intelligence`, `dependency_advisories` | `QP` or typed reference query; no skill |
| Materialized OpenAPI 3 JSON; `job_target_catalog` | Declared routes, methods and parameters | Current `documents`; enforcement still needs source/graph proof; other interface formats remain planned | `contract_enforcement`, `entrypoint_paths` | `search`, `find`, `read_excerpt`; no skill |
| IaC, rendered Helm/Kustomize, proxy and runtime config; planned `job_deployment_topology` | Exposure, privileges and limits | Planned `deployment`; scanner observations alone are not topology | `deployment_exposure`, `ci_trust` | Planned `query_deployment` if typed exposure filters are needed; no skill |
| Unit-test source and Postman collections; `job_target_catalog`, `job_review_data_indexing` | Developer intent and request examples | Current bounded `documents` and `document_context`; exact route joins are review context, assertions do not prove enforcement | Current `document_context`; later `review_package` nominations | `search`, `find`, `read_excerpt`, `query_precomputed`; no skill |
| Markdown under `docs/`, including design, STRIDE and DFD; `job_target_catalog`, `job_review_data_indexing` | Stated architecture and trust boundaries | Current bounded `documents` and `document_context`; target text remains untrusted intent | Current `document_context`; later `review_package` nominations | `search`, `find`, `read_excerpt`, `query_precomputed`; no skill |
| Target-owned agent guidance; planned doc index | Owner statements only, never instructions | Planned `docs` with `target_guidance` flag and quarantine | None beyond nomination | `search` only if scope permits; no skill |
| Sanitized text/facet streams from accepted source, observations, contracts, docs, tests and feeds; `tool-sqlite-fts` image | Nominate exact identities for later resolution | Current in-process FTS5; registered image can build/validate bounded FTS5 document shards when a producer is wired | Safe term/facet dictionaries, corpus counts and entity→document links | Existing `search` then `find`/`read_excerpt`; no new MCP endpoint or skill |
| Fuzz, runtime and authorized dynamic traces; future producer | Observed behavior and path validation | Planned run-owned `observations`/trace identities and coverage | `dataflow`, `entrypoint_paths`, `review_package` | Planned `query_observations`/typed trace query if acquired; no skill |
| Runtime logs, raw tool output, exact argv/env, credentials and model transcripts; runtime/all jobs | Audit producer status and failures | Protected artifacts; only safe status, hashes, producer and gap indexed | Coverage and provenance summaries only | `coverage`/dataset catalog; no raw-content MCP or skill |
| Normalized claims, reviews, adjudication, PoC receipts and final finding packages; future inference/publication | Review decisions and final evidence | Planned typed ledgers; publish sanitized final findings only | `review_package` input is separate; final claim/evidence closure | `resolve_evidence` and scoped finding query when built; no worker skill |

An MCP endpoint is justified only when `core`, an existing domain query, and `QP` cannot give a
bounded typed answer. `query_observations` (implemented) is the endpoint for scanner severity,
suppression, rule, provider and location filters; it keeps tool findings distinct from confirmed
findings. Other named planned endpoints above are conditional on their producers.
Skills are operator procedures, not a way to provide target facts to review workers. New sources
do not require new skills by default; add one only for a repeated operator workflow with its own
validation steps. Worker access remains through accepted MCP indices and packages.

An implementation task must enumerate actual artifacts and handoffs for every enabled job. Each
dataset gets `producer`, `scope`, `schema`, `hash`, `snapshot`, sensitivity, disposition
(`indexed`, `artifact_only`, `protected`, `unavailable`), index shard or exception reason, and
coverage. The inventory itself is immutable and accepted with the run. An acceptance validator
compares emitted datasets with this inventory so newly added jobs cannot silently omit indexing.

### Publication contract and completeness audit

The publisher treats a **dataset** as one logical output of a job step, even when it spans many
files. Every enabled step declares its output kinds before execution and reports one row per
actual output and one row per expected output that was skipped or failed. A row has a stable
`dataset_id` derived from run, job, step, scope and output kind; producer attempt and artifact
hashes; accepted target snapshot; schema and producer version; language/build unit where
applicable; sensitivity; disposition; index shard identity or protected artifact reference;
query route; record and truncation counts; coverage state and reason. Paths are logical target
paths or run-owned references, never arbitrary host paths. Inventory and shard metadata are
hash-pinned in the accepted manifest.

| Disposition | Required publication | Acceptance rule |
|---|---|---|
| `indexed` | Accepted shard, exact query route, provenance and coverage | Shard hash, schema, snapshot and scope resolve; row counts agree with shard metadata |
| `artifact_only` | Run-owned artifact plus queryable sanitized metadata | Named reason why detailed indexing is not useful or feasible; no review-critical facts hidden here |
| `protected` | Protected artifact plus safe status/hash/producer metadata | Named sensitivity reason; raw bytes cannot enter source search, facts or model context |
| `unavailable` | No fabricated facts; scoped gap record and attempted producer status | Distinguish disabled, unsupported, skipped, failed, timed out and truncated |

The validator compares the step's declared outputs, emitted artifacts and index handoffs with
inventory rows. It rejects missing/duplicate identities, dangling shard or artifact references,
snapshot/hash mismatches, an `indexed` row without a query route, and any safe review-useful
output filed as `artifact_only` without a concrete exception. A failed or skipped optional lane
may be accepted only with scoped `unavailable` coverage. A failure in this audit prevents final
index acceptance; it does not erase already captured evidence. Audit results themselves are
run-owned, indexed status facts.

The implementation should enumerate the current pipeline from its registry and resolved
configuration, including `job_review_intake`, `job_target_catalog`,
`job_source_history_analysis`, `job_target_analysis_plan`, `job_tree_sitter_ast`,
`job_project_build`, `job_language_build`, `job_artifact_indexing`,
`job_artifact_security_analysis`, `job_cpp_compiled_analysis`, `job_cpp_symbol_index`,
`job_cpg_analysis`, `job_evidence_collection`, `job_change_context_analysis`,
`job_codeql_analysis`, and `job_review_prioritization`. Other enabled jobs, including CI,
OWASP, tagging, post-build assessment and standalone feed sync, are in scope when present in
the resolved run. Registry/configuration discovery is authoritative; this list is a review
check, not a hardcoded allowlist.

### Indexing levels

| Level | Use | Example |
|---|---|---|
| Identity and metadata | Every safe dataset, including artifact-only material | artifact hash, source/job identity, language, scope, status |
| Search and facets | Bounded text/facts needed to nominate and filter | symbol, rule, package/PURL, CWE, route, CI workflow |
| Typed relationships | Evidence or provenance crossing entities | source→build→artifact→observation; advisory→package; control→evidence |
| Precomputed products | Expensive joins or graph questions used repeatedly | entrypoint-to-sink path, vulnerable dependency reachability, review package |
| Protected artifact only | Raw or sensitive data that must not enter LLM retrieval | exact env, secrets, huge binary CPG, unredacted logs |

The protected-artifact exception still requires queryable sanitized metadata and a named reason.

### SQLite FTS tool-image reuse

The current `IndexBuilder` already creates SQLite FTS5 tables inside immutable index shards and
MCP opens accepted shards read-only. The registered `tool-sqlite-fts:1.0.0` image is an
**offline index-build and validation worker** for bounded sanitized text streams. It builds the
same `search_fts(identity, name, path, text)` FTS5 table and `unicode61` tokenizer used by the
in-process builder. It also stores input SHA-256, record count, schema and SQLite version in
metadata. The tested image ID is pinned in `containers/catalog.toml`; the image uses the pinned
`base-python` runtime with SQLite 3.40.1 and built-in FTS5. Its manifest records provenance and
the no-network runtime policy with a read-only root and target mount. The image is not a search server and does not replace
the accepted manifest or MCP access checks. The tool currently produces an FTS-only database;
no production indexing job consumes it yet. A producer must be wired through typed configuration
and a versioned shard publisher before its output can be accepted for MCP retrieval.

The producer first emits a bounded, sanitized document stream with stable entity IDs, safe text,
facets, source/artifact location and upstream hashes. The tool image builds or validates the FTS
portion of a shard in an isolated no-network container. One publisher owns the shard; the image
must not mutate an accepted SQLite file. The resulting file is integrity-checked, hash-pinned
and published through the existing `IndexBuilder`/manifest contract or a schema-compatible
versioned builder. Tokenizer, normalization, SQLite version, image digest and input document
hashes enter the shard fingerprint. FTS is a **nomination** layer; exact `find`/`trace` and
source/artifact resolution still establish facts. FTS never indexes raw secrets, exact env/argv,
protected logs, model transcripts or target guidance as instructions.

The image passed a live FTS5 build/verify fixture and catalog startup/security checks. Verify
schema compatibility and deterministic outputs at the producer boundary when wiring it into a
job; until then, the in-process builder remains the current path. Precompute corpus statistics,
safe term/facet dictionaries and exact
entity-to-document links where they improve candidate retrieval; do not precompute LLM answers
or treat a search rank as evidence.

## Reusable job boundaries

1. **Acquire and parse once.** Reuse the accepted catalog, build capture, Tree-sitter, Clang AST,
   LLVM IR, clangd, CodeQL, and Joern outputs. Each extraction job is keyed by snapshot, exact
   input artifact hashes, language/tool identity, typed configuration, and versioned mapping rules.
2. **Normalize per representation.** Publish bounded AST, IR, CPG, and symbol shards independently.
   Preserve native IDs, exact or ambiguous source mapping, edge kind and direction, confidence,
   producer artifact, and parse/extraction bounds. A CPG binary alone is an artifact reference,
   not graph coverage.
3. **Bridge representations.** A separate linker consumes accepted shards. Exact byte spans,
   compiler debug/source maps, and resolved symbol identities can establish links. Name-only or
   line-only matches remain ambiguous and carry their method; no prompt may silently promote them.
4. **Precompute query products.** Independent jobs consume normalized data and publish one
   `precomputed` shard per query set and scope. A changed query rule rebuilds its product, while
   unchanged source/AST/IR/CPG shards are reused. The immutable accepted manifest includes every
   product and its gaps. Query jobs never execute target code.
5. **Assemble review context.** Join selected priority items with bounded source excerpts,
   ownership/complexity features, import neighbors, calls, flow paths, guards, findings, artifacts,
   CI/deployment exposure, and controls through accepted identities. Keep ranking and supporting
   evidence distinguishable.
6. **Audit publication.** Each job declares datasets it emitted and why each is indexed,
   artifact-only, protected, or unavailable. The final accepted manifest publishes the inventory
   and fails validation for an indexable emitted dataset with no shard or named gap.

Run outputs remain under `runs/<run-id>/data/`. Configuration, limits, timeouts, and worker pools
belong in central TOML. Producers publish independently testable handoffs; skipped and failed
scopes publish unavailable or partial coverage instead of empty-success records.

## Precomputed query sets and implementation batches

Each set is an allowlisted `query_set`, with a versioned producer, an exact subject identity or
source path, a bounded result, upstream hashes, and a coverage row named for the set. Products
should reuse the current `IndexBuilder`, `IndexIdentity`, and accepted-manifest publication path.

| Query set | Reused inputs | Suggested bounded fact | Essential gap |
|---|---|---|---|
| `symbol_links` | Tree-sitter, Clang AST, clangd, build maps | declarations, definitions, references, call sites per symbol | unresolved overload, generated source, or parse error |
| `call_graph` | clangd, LLVM direct calls, CPG calls, CodeQL | callers and callees with dispatch method and provenance | unresolved indirect/virtual calls and tool disagreement |
| `control_flow` | LLVM CFG, CPG CFG, syntax | basic blocks, branch edges, exits, exception paths | missing TU, inline asm, or non-exact source map |
| `dataflow` | CPG PDG, LLVM def-use, CodeQL | bounded def-use and source-to-sink subgraphs | unmodeled external call, aliasing, path/step limit |
| `entrypoint_paths` | ingress catalog, summaries, call/dataflow graph | shortest bounded entrypoint-to-sink paths | path depth/count bound and unresolved dispatch |
| `guards_ranges` | CFG dominators, AST conditions, LLVM values | dominating guards, branch polarity, operand width/range | unknown range, optimization, non-exact mapping |
| `sarif_correlation` | CodeQL observations and normalized graphs | each SARIF step mapped to graph nodes/edges | broken or ambiguous hop |
| `ast_ir_cpg_mapping` | source spans, Clang AST, LLVM IR, Joern CPG | cross-representation node links with method/confidence | missing debug/origin information |
| `hotspot_context` | priority, history, all accepted graph products | bounded evidence package around a ranked file/function | per-source missing coverage and context truncation |

| Query set | Reused inputs | Suggested bounded fact | Essential gap |
|---|---|---|---|
| `build_provenance` | capture, plans, compiled and artifact indices | source/build action/compiler flags class/artifact chain | missing capture, non-replayable build, redacted exact argv |
| `artifact_inventory` | build and artifact indices, SBOM | package/member/binary inventory by build unit | unrecognized format or truncated extraction |
| `dependency_advisories` | SBOM, scanner output, pinned OSV/NVD/CVE snapshots | package/version→advisory matches with evidence and fix range | stale feed, uncertain package identity, missing version |
| `scanner_correlation` | SAST, artifact scanners, CodeQL, suppression and tags | deduplicated leads with independent supporting observations | conflicting locations or rules, unavailable scanners |
| `ci_trust` | CI graph, build artifacts, deployment metadata | untrusted trigger→permission/secret/build/deploy paths | dynamic expression or external workflow |
| `redacted_secret_exposure` | secret scanners and safe build/CI facts | location, sink and redacted fingerprint only | scanner unavailable; never return secret bytes |
| `history_context` | Git, review/deployment data, SII and change context | bounded change/owner/fix/test context per file or symbol | missing VCS/review metadata or attribution |
| `control_evidence` | OWASP workbench, findings, validators | control→evidence/disposition links | assessment unavailable or validator gap |
| `reference_intelligence` | pinned NVD/OSV/MITRE feeds | advisory, CWE, CAPEC, ATT&CK links relevant to target facts | feed freshness or identity mismatch |
| `document_context` | accepted OpenAPI, Postman, unit-test, STRIDE and DFD records | exact method/route and trust-boundary groups with source identities | unsupported formats, unmatched declarations, bounded truncation; intent never proves enforcement |
| `contract_enforcement` | future API/IDL contracts, handlers, validators | declaration→handler→enforcement chain | contract unavailable or declaration not enforced |
| `deployment_exposure` | future topology, CI/build/artifact graph | service→image→binary→source and privilege/exposure | environment not captured or image not bound |
| `test_intent` | accepted document context and future source-symbol links | richer test assertion and negative-case links | tests are not executed; intent is not enforcement |
| `review_package` | all accepted indices and products | compact evidence bundle for a bounded review question | every missing contributing lane and package truncation |

The [inventory and first-stage batch](../tasks/review-data-indexing-prompt.md) enforces dataset
accounting across enabled jobs, adds safe query routes and cross-domain links, and publishes
products over already accepted inputs. The dependent
[graph and advanced-query batch](../tasks/review-graph-precomputation-prompt.md) exports Joern
and LLVM graphs, links representations, and publishes graph and review-context products. Each
batch verifies every language's available producer path, names unsupported combinations, and
tests selective reuse when one query rule changes.

### Product scheduling and invalidation

Each query-set producer declares its exact upstream shard/artifact identities, rule version,
tool version, configuration hash, scope and output schema. The product key is a hash of those
inputs, not a run-wide timestamp. Product dependencies form a DAG; only descendants of a
changed input rebuild. A producer may publish `partial` with bounded facts and explicit missing
inputs, or `unavailable` with no facts. It must never publish complete empty results when an
input failed. Publishing a product is an independent handoff; a failure in one set does not
invalidate unrelated accepted sets.

| Stage | Product sets | Prerequisite |
|---|---|---|
| 1: broad inventory | `build_provenance`, `artifact_inventory`, `dependency_advisories`, `scanner_correlation`, `ci_trust`, `history_context`, `control_evidence`, `reference_intelligence`, `symbol_links`, `document_context` | Existing accepted domain shards and pinned feed identities |
| 2: code graphs | `call_graph`, `control_flow`, `dataflow`, `sarif_correlation`, `ast_ir_cpg_mapping`, `guards_ranges`, `entrypoint_paths` | Bounded AST/IR/CPG export, source mappings and available analyzer evidence |
| 3: review context | `hotspot_context`, `redacted_secret_exposure`, `contract_enforcement`, `deployment_exposure`, `test_intent`, `review_package` | Accepted upstream sets; richer contract/deployment/test semantics remain pending even though `document_context` is indexed |

Within a stage, implement one complete producer→shard→manifest→MCP vertical slice before
replicating the pattern. `review_package` is a compact composition of accepted identities,
counts, paths and gaps, never a copy of every source excerpt or graph. A query may filter a
product by exact subject/path but cannot cause product generation.

## Review input packages for hunters and red-team analysts

The machine-readable contract is
[`review-packages.schema.json`](../schemas/review-packages.schema.json), version
`appsec-review/review-package/3`. It describes the output of `assemble_review_packages` and
the bounded input planned for the `hypothesis_hunter` and `red_team_analyst` roles in
[`inference-security-review.md`](inference-security-review.md). It is distinct from the
post-adjudication `appsec-review/finding-package/1` used for final findings. The assembler reads
accepted scanner-correlation facts, fingerprints packages from accepted identities, and emits
one `finding_lead` package per source-SAST lead and one `hunt` package per accepted menu partition.
Stable partition keys and bounds prevent silent lead loss.

| Field | Required content |
|---|---|
| Identity and authority | package ID/kind, run, accepted manifest and snapshot, producer/rule version, component/trust-boundary scope, source and artifact identities |
| Lead menu | observation IDs, provider, rule, category, native and normalized reported severity, suppression/duplicate state, exact or ambiguous location, flow IDs |
| Review priority | LPS/SII rank and metric vector, each value's producer and availability; never technical finding severity |
| Code and flow context | symbols, ingress/sinks, ordered path IDs, typed graph edges, guards, source-excerpt references and unresolved mappings |
| Build and deployment context | build-action/artifact IDs, safe ordered command facts, safe environment classes, hardening, dependency/CI/deployment links and unavailable scopes |
| Evidence and questions | supporting/contradicting evidence IDs, provenance, proof obligations, allowed retrieval scope and available typed MCP queries |
| Bounds | source-specific coverage gaps, omitted counts, truncation reason, next cursor/partition |

**SAST High/Critical inclusion invariant:** every accepted source-SAST observation whose
normalized *reported* severity is High or Critical is reachable from a finding-lead package and
appears in at least one hunt menu for its component/trust boundary. Preserve the scanner's
native severity, normalization rule, suppression status and duplicate relationship. A suppressed
or duplicate lead remains traceable and marked; it is not silently discarded. Unknown/unmapped
severity stays queryable in a separate menu and is never interpreted as Low. Scanner severity
only orders attention; it does not become adjudicated technical severity or proof of a defect.
The package audit compares accepted observations with package membership and fails on an
unaccounted High/Critical lead. Disabled or failed scanners produce coverage gaps rather than
an empty clean menu.

Packages carry the exact history and complexity features that support ranking: added/deleted
lines, relative churn, revision count, author count/entropy, fix-on-fix cadence, SII and tier;
per-function/file cyclomatic score, complexity density, mean, high-risk tail, cognitive score
and parser coverage. Each metric names its scope, window, language, algorithm/version, producer,
source hash and availability. The authoritative definitions remain in
[`source-history-analysis.md`](source-history-analysis.md) and
[`review-prioritization.md`](review-prioritization.md). A missing history/AST lane is `unknown`
with a gap, not zero. Packages contain bounded metric vectors and references, not raw diffs or
whole ASTs.

Build actions are linked to the accepted source, compile unit and produced artifact. Safe
retrieval preserves command-token **order** and classification (tool identity, source/output
roles, include/library paths as logical identities, security-relevant flags, defines with
redacted/allowlisted values, linker and hardening settings) plus working-directory identity,
toolchain version and the protected exact-command artifact hash. Environment retrieval exposes
allowlisted non-secret values and classified names/presence for security-relevant
variables; credentials, tokens, arbitrary values and exact `argv`/`envp` remain protected
run-owned artifacts. The normalization rule and redaction status travel with each fact. A
reviewer can ask whether a flag or environment class was present and which artifact it affected;
the LLM cannot request the raw command or environment through MCP.

## Fact and MCP contract

The `precomputed` index holds `precomputed_fact` entities. An accepted shard's manifest producer
contains its `query_set`. Each fact payload carries
`schema = appsec-review/precomputed-fact/1`, the same `query_set`, `subject_identity` and/or
`subject_path`, bounded computed result, basis, upstream identities, and coverage status. A source
location is attached when it resolves; otherwise the artifact reference and mapping gap remain.
Facts do not inherit the authority of tool findings or source observations.

`query_precomputed(query_set, subject?, path?, limit?, cursor?)` reads only accepted shards for an
allowlisted set. It reports unavailable sets and incomplete coverage. It cannot run analyzers,
accept SQL or graph programs, or scan target files. `query_hotspots(scope?, path?, min_score?,
limit?, cursor?)` returns ranked priority items with metric vectors and evidence links. Existing
`find`, `search`, `trace`, `read_excerpt`, and `coverage` remain the tools for exact nodes,
relationships, source bytes, and gap inspection. Retrieval responses stay run and manifest pinned,
size/time bounded, auditable, and cursor bound to the exact request.

The first indexing batch adds `query_observations` because the current generic and domain tools
cannot filter all scanner observations by normalized reported severity, suppression state,
provider, rule and exact source/artifact scope. It reads accepted observation shards only,
returns native severity and normalization rule alongside the filter value, and reports skipped
or failed scanner coverage. It does not elevate a tool result into a confirmed finding. Hunter
package assembly uses it only as a query surface over a precomputed complete lead menu; package
membership is validated by a deterministic publication job.

The existing domain queries (`query_artifacts`, `query_build_security`,
`query_ci_configuration`, `query_codeql`, `query_change_context`, and
`query_owasp_workbench`) remain first-class access paths. The dataset inventory is discoverable
through the bounded `query_dataset_inventory` catalog query, so the model never guesses index
names or inspects raw run directories.

## First indexing batch: implemented coverage

`job_review_data_indexing` (operations: [`review-data-indexing.md`](../operations/review-data-indexing.md))
publishes the accepted inventory before `job_review_package_assembly`. Implemented:

- **Inventory and audit.** All 23 registered jobs declare datasets in their own `datasets.py`.
  The audit compares declarations with the resolved configuration, accepted handoffs, every
  accepted shard (recomputed counts) and the run-owned `data/` tree, plus runtime receipts,
  configuration, telemetry, guidance and manifests. Violations block acceptance. Shards a producer
  published but a later manifest rewrite dropped are restored and recorded as repairs. Inventory
  rows, the audit record and coverage cells are indexed in `inventory/dataset-inventory` and
  queried through `query_dataset_inventory`.
- **Input-source matrix.** `appsec_review.indexing.input_matrix` encodes every row of the matrix
  above. The job reconciles it with the registry and the run's inventory rows and publishes one
  `input_source` cell per row; a registered job absent from the matrix, or a matrix producer
  absent from the registry, is a published discrepancy. A test pins the table row count.
- **Links.** `links-representation`, `links-finding-source`, `links-package-advisory`,
  `links-symbol-syntax` and `links-history-code` shards. Exact links require equal identity, hash or
  byte span; other joins are separate ambiguous relations.
- **Stage-1 products.** All nine stage-1 sets publish independent shards keyed by rule version,
  upstream shard identities, pinned feed/OWASP identities and dependent settings.
  `scanner_correlation` is the complete High/Critical and unknown-severity lead menu with a
  membership audit. `history_context` adds schema-conformant metric vectors (churn, revisions,
  author entropy, fix-on-fix, SII and tier, cyclomatic, cognitive, density, high-risk share,
  parser coverage), with an `unavailable` status and gap id, never zero, for a missing value.
  `build_provenance` adds safe ordered command and environment facts per build action.
- **Language and build-unit matrices** are published as coverage cells: source and Tree-sitter per
  catalogued language; compiled/clangd only for C/C++ with accepted shards (partial extraction);
  Joern always `unavailable` (binary artifact only); CodeQL only where an accepted shard exists.
- **SQLite FTS image.** The in-process FTS5 builder remains the only producer of accepted shards.
  `fts.image_validation` rebuilds this job's link and product shard text with the pinned
  `tool-sqlite-fts:1.0.0` image (image ID verified against the catalog pin, FTS5 probe, record
  count, input hash and probe-term equality) and keeps the result as a validation receipt only.

Remaining gaps after this batch:

- Graph products (`call_graph`, `control_flow`, `dataflow`, `sarif_correlation`,
  `ast_ir_cpg_mapping`, `guards_ranges`, `entrypoint_paths`), `hotspot_context`,
  `redacted_secret_exposure` and `review_package` are not produced; the matrix publishes them as
  `pending_graph_batch` follow-ups with their missing prerequisite.
- Joern CPG remains a binary artifact; no CPG graph coverage is claimed.
- Source-to-build-action mapping exists only through captured compile commands (`source_input`
  tokens) and C/C++ compile databases; captured file-access inventories are protected and not
  normalized.
- CI facts carry no build-unit, artifact or deployment identity, so `ci_trust` cannot link CI to
  build or deployment; dynamic expressions and external workflows are unresolved.
- Reference feeds are pinned per run only when a verified `current.json` snapshot exists under the
  configured feed root; CAPEC/ATT&CK relationships are not normalized.
- Inline suppression state comes from accepted prioritization syntax facts (bounded per file); a
  suppression directive with block or declaration scope is reported as `possibly_suppressed`.
- `cyclomatic_mean` is not produced by `job_review_prioritization` and is always `unavailable`.
- `IndexBuilder` sanitizes payloads but not FTS `text`; the FTS validation receipt counts
  secret-pattern documents as a gap against the producing shard.
## Acceptance checks across both batches

- Every supported language has a catalog-to-source-to-AST route; compiled/CPG coverage is scoped
  to languages and build units that actually produce it.
- Every enabled producer has an emitted-dataset inventory, safe metadata index or explicit
  exception, and a query route. New outputs cannot pass acceptance with an unclassified dataset.
- A source-resolved graph path contains ordered nodes and typed edges, not just endpoint line
  numbers. Every missing or ambiguous hop is visible.
- In the graph batch, Joern output is decoded by a pinned, bounded exporter into accepted graph
  shards; a binary-only CPG continues to report unavailable graph coverage.
- A fact can be traced back through exact upstream identities and hashes; stale or mismatched
  source mappings are rejected.
- Re-running an unchanged input reuses immutable shards; changes invalidate only dependent
  products. MCP queries read the accepted set and report missing sets truthfully.
