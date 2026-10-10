# Review data indexing and reusable retrieval products

Status: design and current-state inventory. The MCP query contract in this document is
implemented; the dataset audit, additional index producers, and precomputation jobs are separate
work. A missing product is reported as unavailable.
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
| Build plans, captured actions, file accesses, compile/link flags, repair outcomes | project/language build and post-build assessment | `build`, `build_security` | index safe normalized facts and provenance; expose repair decisions and failed scopes; keep exact argv/env protected |
| Produced packages, archives, binaries, bytecode, WASM, symbols, SBOMs | artifact indexing and compiled analysis | `artifacts`, `compiled`, `build_security` | link member/package/symbol to producing action, source unit, and scanner observations |
| Artifact vulnerabilities, dependency advisories, license and secret leads | artifact security and evidence collection | `observations`, `artifacts`, `evidence` | normalize scanner-specific facts, deduplicate findings, link package/advisory/version evidence; keep secret values redacted |
| SAST, CodeQL SARIF, fuzz or dynamic evidence when present | evidence collection and CodeQL | `observations`, `priority` flow steps | retain rule identity, result location, ordered flows, suppressions, coverage, and artifact hash; correlate duplicate leads |
| CI workflows, steps, permissions, secrets usage and canonical findings | CI configuration analysis | `observations` and `evidence` CI shards; `query_ci_configuration` | connect workflow trust edges to build/deployment artifacts and source revisions |
| Commits, diffs, blame, reviews, deployments, ownership, SII, change context | history and change-context jobs | `history`, `priority`; `query_change_context` | index bounded review-unit links, exact fixes and ownership; leave raw diffs protected when large |
| OWASP applicability, controls, validators, dispositions | OWASP workbench | accepted workbench shards; `query_owasp_workbench` | cross-link controls to accepted findings, tests and source evidence without duplicating the workbench |
| Security tags and review-priority scores | tagging and prioritization | `tags`, `priority`; `query_hotspots` | link tag rationale and ranked items to exact supporting identities and coverage gaps |
| NVD, OSV, MITRE, CVE tool database and other reference feeds | third-party sync | verified global feed snapshots and metadata, outside the run manifest | pin feed snapshot per run; index advisory/weakness/technique facets and join them to observed target packages/findings |
| API contracts, deployment topology, tests, docs, dynamic traces | planned or partly scanner-observed | scattered source/scanner observations only | add producer-specific indices when acquired; distinguish declared, intent, and observed evidence |
| Run logs, raw tool outputs, exact environment, model transcripts, credentials | runtime and tool jobs | protected run-owned artifacts | only sanitized status, hashes, durations, producer and coverage enter retrieval; never index secret or raw model content |

An implementation task must enumerate actual artifacts and handoffs for every enabled job. Each
dataset gets `producer`, `scope`, `schema`, `hash`, `snapshot`, sensitivity, disposition
(`indexed`, `artifact_only`, `protected`, `unavailable`), index shard or exception reason, and
coverage. The inventory itself is immutable and accepted with the run. An acceptance validator
compares emitted datasets with this inventory so newly added jobs cannot silently omit indexing.

### Indexing levels

| Level | Use | Example |
|---|---|---|
| Identity and metadata | Every safe dataset, including artifact-only material | artifact hash, source/job identity, language, scope, status |
| Search and facets | Bounded text/facts needed to nominate and filter | symbol, rule, package/PURL, CWE, route, CI workflow |
| Typed relationships | Evidence or provenance crossing entities | source→build→artifact→observation; advisory→package; control→evidence |
| Precomputed products | Expensive joins or graph questions used repeatedly | entrypoint-to-sink path, vulnerable dependency reachability, review package |
| Protected artifact only | Raw or sensitive data that must not enter LLM retrieval | exact env, secrets, huge binary CPG, unredacted logs |

The protected-artifact exception still requires queryable sanitized metadata and a named reason.

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

## Precomputed query sets for the next task

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
| `contract_enforcement` | future API/IDL contracts, handlers, validators | declaration→handler→enforcement chain | contract unavailable or declaration not enforced |
| `deployment_exposure` | future topology, CI/build/artifact graph | service→image→binary→source and privilege/exposure | environment not captured or image not bound |
| `test_intent` | future test/doc index, source symbols | test assertion and negative-case links | tests not indexed or not executed; intent is not enforcement |
| `review_package` | all accepted indices and products | compact evidence bundle for a bounded review question | every missing contributing lane and package truncation |

The next task should first enforce dataset inventory and metadata coverage across all enabled
jobs, then fill the highest-value index gaps. Precompute products in stages, prioritizing
cross-domain review questions and graph paths that are expensive to answer at inference time. It
must verify each language's available producer path and name unsupported combinations. It should
test reuse by changing one query rule and proving unrelated upstream shards are not rebuilt.

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

The existing domain queries (`query_artifacts`, `query_build_security`,
`query_ci_configuration`, `query_codeql`, `query_change_context`, and
`query_owasp_workbench`) remain first-class access paths. The future dataset inventory should be
discoverable through a bounded catalog query or an enriched `coverage` result; it must not require
the model to guess index names or inspect raw run directories.

## Acceptance checks for the next task

- Every supported language has a catalog-to-source-to-AST route; compiled/CPG coverage is scoped
  to languages and build units that actually produce it.
- Every enabled producer has an emitted-dataset inventory, safe metadata index or explicit
  exception, and a query route. New outputs cannot pass acceptance with an unclassified dataset.
- A source-resolved graph path contains ordered nodes and typed edges, not just endpoint line
  numbers. Every missing or ambiguous hop is visible.
- Joern output is decoded by a pinned, bounded exporter into accepted graph shards; a binary-only
  CPG continues to report unavailable graph coverage.
- A fact can be traced back through exact upstream identities and hashes; stale or mismatched
  source mappings are rejected.
- Re-running an unchanged input reuses immutable shards; changes invalidate only dependent
  products. MCP queries read the accepted set and report missing sets truthfully.
