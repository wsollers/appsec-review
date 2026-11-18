# Job 31/47 — `job_code_graph_index`

## Audit identity and result

- Authorized checkout: `/home/wsollers/projects/appsec-review`, Ubuntu-22.04, branch `main`, exact revision **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**. Initial/final HEAD matched; `git status --porcelain` and final diff stat were empty. Import resolved to this checkout's `src/appsec_review/__init__.py`.
- Read the complete updated shared brief, authorized AGENTS and coordination skill. Inspection used the authorized WSL UNC path; Linux execution used `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu`. The Windows default checkout was not audited or tested.
- **13 new findings: six high, six medium, one low.** The previously reported high clangd reference-to-call conversion is confirmed statically and **not counted again**. Other inherited upstream defects are separately attributed.
- **53 focused units passed in 13.15 s**; wrapper total **22.446100 s**, two workers, shuffle seed 31047, no failures/skips/tests over ten seconds. Six offline reproduction invocations exercised 16 numbered scenarios. Two invocations stopped on mistakes in the reproducer, subsequently corrected; one deliberately demonstrated the runtime's sticky input-contract rejection.
- No repository source/configuration edits, installs, compilers, CodeQL/Joern/images/providers, service operations, integration/acceptance/live/Dagster execution, commits, or nested agents. Reproducer trees were removed. Only this report and private harness validation artifacts remain.

This is a functional correctness audit, not certification of native output quality or review conclusions.

Paths below are repository-relative. In tables, `job.py`, `scopes.py`, `producers.py`, `alternate_cpg.py`, and `datasets.py` mean files in `src/appsec_review/jobs/job_code_graph_index/`. Other abbreviated package paths are relative to `src/appsec_review/`.

## Registration, purpose, and input authority

`runtime/registry.py:97,167` registers the factory. `appsec-review.toml:2247-2283` declares five tasks; `job_is_enabled(load_config(), "job_code_graph_index")` returned **True**. The contract has review-graph dispatch, checkout target access, `always_execute=False`, and propagating handoff. Its scheduling list includes CodeQL, compiled C++, Clang static, clangd, SVF, Tree-sitter, and prioritization. Topology combines schedule/input dependencies, projects disabled jobs out, and removes transitive edges (`orchestration/topology.py:46-80`); the generated operations page shows prioritization as the reduced predecessor.

Intended outputs:

1. Source-resolving CodeQL call/sink/source/summary/path/guard/range facts with explicit admissibility, independent cross-check states, correlation, coverage, database cards, and bounded producer neighborhoods.
2. An alternate CPG composed from admitted syntax/CFG, semantic facts, clangd, scanner flow and routing context, with provenance tiers, interprocedural paths and slices.
3. Immutable retrieval publication, checkpoint identities and a validated quality scorecard. These products supply context/evidence within their declared limitations, not confirmed vulnerabilities.

### Declared input inventory and actual reads

The contract declares **53 input requirements across nine producers** (`datasets.py:64-189`):

| Producer | Declared non-envelope datasets | Actual consumption |
|---|---|---|
| CodeQL | predecessor import, graph export, observations, plan/summary, scope material | **Required envelope**; accepted result, plan, export index, succeeded export manifests/documents, scope observation shards. Not every declared artifact is semantically opened. |
| Compiled C++ | build graph, AST, IR, Infer, binary symbols, blocked branches, plan/summary, case material | Restores/selects producer-owned AST/IR analysis shards; reads call/reference/flow information. |
| clangd | symbols, coverage, summary, tool IO | Restores symbols; cross-check reads CALLS/definitions/locations; alternate collector reads all symbol relations, including REFERENCES (known CSI-F01). |
| Clang static | observations, scope coverage, summary, raw | Project-root-matched observations; sink corroboration and diagnostic neighborhoods. |
| SVF | alias sets, scope coverage, summary, raw | Located points-to/indirect-target records for optional cross-check. |
| Joern CPG | graph/scope coverage, summary, binary | Optional project-root-matched function-context rows, not primary graph evidence. No Joern launch. |
| Tree-sitter | AST, coverage, node shards, CFG, generated backing, tool IO | Restores syntax analysis shards; native call cross-check; alternate path additionally resolves the exact admitted CFG manifest/nodes/edges. Broken AST fallback is F07. |
| Target catalog | artifact inputs, source files, declaration symbols, components, documents, build units, catalog documents | Alternate collector reads source-file hashes and symbol declarations **only if catalog source shards are in the supplied manifest**; it does not restore this producer like secondary producers. |
| Prioritization | priority items, documents | Optional signal/flow-step context for correlation; alternate collector treats review signals/priority items as route candidates. Authority is routing context, not producer evidence. |

Every producer also has an envelope declaration. Except CodeQL's required/reject envelope, these are optional/gap declarations. No model or runtime-prompt task executes in this job.

`scopes.load_codeql_inputs:138-214` reads through `indexing.store.accepted_handoff` → `runtime.consume.accepted_upstream`. It verifies the admitted digest/producer/snapshot, binds result/plan/export-index artifacts to the envelope, compares scope language/root/build-unit, rejects duplicate or omitted export scopes, and requires a bound manifest/pack for successful exports. The older `export.scopes` fallback is supported but is not another declared task.

`scopes.verify_exports:217-236` checks the accepted manifest hash and delegates to `codeql/runtime.py:759-809`: listed files only, aggregate bytes, exact sizes/hashes, export schema/column-row/count/sort/BQRS agreement. `scope_sources:239-257` rehashes each planned target-relative source. It does not discover unplanned source files. Thus an upstream omitted scope remains omitted (CQ-01 below).

`runtime/consume.py:170-209`, `runtime/inputs.py:359-366,474-499`, and `indexing/store.py:35-73,85-90` distinguish declared/admitted envelopes from actual shard reads. Claim pins select historical accepted attempts if latest advances. Instrumented shard reads check original output ownership/schema/authority/hash and retain receipts. The job's direct result/plan/source reads additionally verify bytes but are not all distinct dataset-level observed reads.

## Every task and processing stage

| Declared task | Actual dispatch, processing and publication | Findings / limits |
|---|---|---|
| `load.accepted_inputs` | `job.py:147-199`: load CodeQL inputs and pinned retrieval manifest; load operator-declared catalog release; verify successful exports/sources; restore producer-owned secondary/analyzer shards; assign secondary shards by maximum file overlap to **one successful native scope**, ties by scope ID; match analyzer roots; attach per-scope observations and optional priority; compute/reuse scope identity; write inputs summary. | No whole-target source scan. Tree-sitter call cross-check assignment is intentionally native-only; alternate synthesis later handles other languages. Unknown releases disable scope reuse. Upstream CQ-01/CQ-02/CQ-05 propagate. |
| `normalize.scopes` | `job.py:201-226`: for each nonreused successful scope, verify exports/sources again, execute `graph.normalize.normalize_scope`, write normalized stage, report noncomplete family rows. | All seven families traced below. F11 rounds integer bounds. No external analyzer. |
| `crosscheck.scopes` | `job.py:228-303`: decode stage; read scope-owned clangd/IR/AST/syntax/SVF shards; compute call cross-check/symbol links; optionally corroborate sinks from Clang diagnostics; apply SVF; add disagreement/secondary-only gaps; write crosschecked stage. | Primary graph preserves disagreements. F03 loses them later in alternate synthesis. Per-producer availability is not a majority vote. |
| `correlate.scopes` | `job.py:305-386`: return verified checkpoint if reusable; otherwise unavailable exports get seven coverage-only shards plus database/neighborhood; successful exports correlate observations/priority, bound broken-flow messages to 20, apply seeded coverage; publish seven family shards, database card and producer-neighborhood shard; compute scope scorecard and checkpoint. | F10 accepts reversed intermediate flows as exact/bridged. Neighborhood coverage is separately partial/unavailable; top-level scope gaps reduce family coverage, not every neighborhood gap. F13 affects scorecard totals after list caps. |
| `acceptance.publish_handoff` | `job.py:388-489`: reverify pinned manifest; require every consumed secondary/analyzer/observation/priority shard still present/restored; replace own earlier shards, preserve upstream; build/publish alternate CPG; write verified composed manifest, scorecard JSON/text and summary; combine family/alternate gaps and counts. | F01–F09 and F12 affect the new product. Alternate synthesis has no separate task/reuse checkpoint. Scorecard validates against its closed schema; alternate schema is tested but not invoked as a publication validator. |

Exactly these five `Unit` declarations exist (`job.py:491-502`), with input validation of configured steps/tasks/settings (`job.py:102-115`). `runtime/units.py:84-213` records successful task execution separately from its terminal disposition; exceptions fail the task and skip dependents. A scope exception inside the thread-pool map is not isolated into an independent per-scope failure result. Successful task receipts can accompany `COMPLETED_WITH_GAPS`; that is deliberate.

### All primary fact families

| Family | Actual implementation / bounds / exactness |
|---|---|
| `sink_site` | `graph/normalize.py:554-597`: groups by source span + operand index; catalog tier/rank selects classification; maps operand and enclosing symbol; unclassified/inexact facts remain explicitly ineligible; CONTAINS from function. |
| `entry_point` | `normalize.py:599-641`: groups source spans; catalog API/model/source-type classification; enclosing symbol and CONTAINS; named model-coverage limitation. |
| `guard_fact` | `normalize.py:693-792`: attaches to retained sink, validates vocabulary/integer fields, maps conditions/operands, handles macro/inexact/no-condition states, retains unknown constraints/post-dominating-only distinctions; least protective state wins collisions; caps guards/sink; GUARDS relation. |
| `range_fact` | `normalize.py:803-867`: attaches ranges/conversion chains to sinks; names unsupported/nonintegral cases and missing chains; location fallback is inexact; DERIVED_FROM. **F11:** decimal integer strings pass through binary float. |
| `call_site` | `normalize.py:869-921`: maps caller/callee/name spans and expression; closed dispatch vocabulary; unresolved indirect is named; deterministic per-function neighbor cap; CONTAINS and CALLS edges. |
| `flow_summary` | `normalize.py:923-960`: per-function pairs, sanitizer/opaque calls, missing/truncated query gaps; explicitly indirect family; DERIVED_FROM function. |
| `dataflow_path` | `normalize.py:962-1134`: groups source/sink flows, enumerates simple terminal trails, sorts shortest/hash-first, caps paths/sink and displayed steps, retains source/sink/guard/sanitizer identities and class parity, emits FLOWS_TO path references. Enumeration has a 4096 terminal-path count cap; no independent visited-state budget was found. Real export path completeness was not tested. |

`_Locator` (`normalize.py:287-385`) maps paths using the CodeQL SARIF mapper and derives UTF-16 coordinates against accepted bytes. Missing files drop rows with named gaps; invalid columns degrade to line-only; macro/name mismatches remain ambiguous. The shared hidden-path bug CQ-02 is inherited, not new.

`normalize.py:1136-1223` applies frozen dispositions: non-first-party facts are counted/excluded, a path with a first-party endpoint and its boundary sink survive, all function symbols remain callee boundaries. A deterministic family cap follows, and relations with dropped endpoints are removed. Fact identity/admissibility is validated by `graph/contract.py` and `GraphFact.to_entity`; no assertion here that a complete individual fact means exhaustive family/target coverage.

### Cross-check, correlation, producer neighborhoods

- **clangd:** `graph/crosscheck.py:192-233,319-457` derives exact/ambiguous SAME_AS symbol links, resolves each bounded reference point against verified bytes, assigns innermost CodeQL call span, preserves exact agree/name-only partial/direct disagree/dynamic partial, and emits ineligible secondary-only calls. Counts omitted occurrence locations. Known CSI-F02/F04 losses cannot be recovered downstream.
- **IR/AST:** `crosscheck.py:459-587` confirms names within a TU, never contradicts from absence; IR unmatched calls become secondary-only; AST requires `CallExpr.referenced_decl`.
- **Tree-sitter:** `crosscheck.py:589-704` uses `payload.syntax.category`, exact byte span and written callee; text mismatch is partial, not contradiction; unmatched calls only in files with CodeQL call coverage are capped at 2000.
- **Analyzer sinks:** complete `graph/analyzers.py` uses a closed check-to-sink mapping, same-file/class/line corroboration; new analyzer-only point sinks are partial/inexact and capped at 500. Unmapped checks/unlocated diagnostics are explicit.
- **SVF:** complete `graph/svf_crosscheck.py` handles target membership and guard/sink points-to intersections. Closed-world complete absence may disagree; open-world absence cannot. Unresolved indirect targets remain secondary-only. Shared function-name tails and producer limits remain boundaries, not newly verified native resolution.
- **Correlation:** complete `graph/correlate.py` groups flat SARIF steps by flow/thread, exact-matches endpoints, ranks candidate paths, records line-only/unmatched intermediate positions and broken flows, and adds DERIVED_FROM/SAME_AS context. **F10** is an ordering defect, not a claim that every correlation is wrong.
- **Neighborhoods:** complete `producers.py` copies at most 200 IR-flow functions, 1000 diagnostics, 500 linked clangd symbols, 200 CPG functions; related symbols 20, diagnostic trace 50, display gaps bounded. Selects nearest/seed-related rows deterministically. Rows preserve original entity identities and scoped producer payloads; populated neighborhood is partial, empty unavailable. Full-mode upstream IR rows lacking `flow` remain absent (previous compiled report).

### Alternate CPG's complete internal path

| Internal stage | Implementation and mismatch |
|---|---|
| Admission/harvest | `alternate_cpg.py:2026-2307`: exact admitted Tree-sitter scope/index matches, observed CFG reads, manifest/snapshot/hash/size checks; parse CFG JSONL; enrich from analysis rows; read present catalog/clangd/CodeQL-observation/priority and newly published graph shards. F07: enrichment expects a nonexistent `node_type` vocabulary. No debug-symbol producer input is wired despite T-169 design text. |
| Function/CFG registration | `alternate_cpg.py:521-945`: path/language/name maps, heuristic entrypoints, CFG blocks/flow/guards, def-use reachability until redefinition; declaration fallback. F05: proximity merges distinct functions. All adjacency structures materialize in memory. |
| Semantic fusion | `alternate_cpg.py:946-1355`: clangd symbols/relations; graph symbols, entrypoints, sinks, calls, dataflow; CodeQL relations; SARIF flow; routing candidates. Known CSI-F01; F03/F04/F06. `guard_fact`/`range_fact`/`flow_summary` have no corresponding alternate ingestion branch; primary graph retains them separately. |
| Syntactic completion | `alternate_cpg.py:1357-1603`: inferred entrypoint nodes, optional symbol-reference hints (not supplied by run collector), name/path/qualified/language target heuristics, at most four candidates, argument-to-first-parameter links, heuristic sinks. F04 pair-level guard fusion. Argument binding is a heuristic, not verified positional dataflow. |
| Paths/slices | `alternate_cpg.py:1605-2008`: BFS over CALLS/TAINT_STEP/FN_TO_SINK/ENTRYPOINT_TO_FN; per-path cycle avoidance; default 10 call hops, hard 16 total edges, 200 precomputed results; forward/backward slices. F08/F09. |
| Publish/reload | `alternate_cpg.py:2309-2569`: JSONL nodes/edges/paths; typed retrieval entity/relationship projection; grouped edges retain embedded originals; SQLite round-trip. F01/F02/F03. Schema exists, but production publisher does not call its validator. |

### Configuration and checkpoint identities

Central graph settings (`appsec-review.toml:2251-2263`): two concurrent scopes; call depth 3, 200 neighbors/function, 8 paths/sink, 40 displayed steps, 16 guards/sink, 200,000 facts/family/scope, 256 MiB exports, 1800-second export setting. `GraphSettings` validates positive integers and call depth ≤4. Export timeout is producer-side/shared configuration, not an analyzer launched here. `query_code_graph` consumes run-bound graph depth; normalizer uses the corresponding normalization caps.

Alternate defaults: enabled true, 10 hops (1..16), 200 precomputed paths (1..2000), slice depth 8 (1..16), parsed by `AlternateCpgSettings.from_mapping`. **Enabled and configured slice depth are unused** (F08). Its block/function/edge collections have no graph-size cap. Scope workers coerce/clamp a value in `_workers`; the top-level worker setting is not checked by the closed graph-settings dataclass.

`scopes.scope_identity:406-428` binds snapshot/scope/language/root/build unit/database/export status/reasons, bounded seed ledger, source files/languages/dispositions, operator catalog/columns/normalizer releases, rules, GraphSettings, CodeQL version and each secondary/analyzer/observation/priority shard digest. Required release declarations include validation. Operator releases rather than rehashing supplied catalog contents are an existing intentional boundary (also confirmed by CodeQL audit); changing catalog bytes without bumping its declaration is **not called a new defect**.

`reuse_checkpoint:437-469` verifies matching scope/result/shard hashes; unverifiable matching local outputs are discarded and rebuilt. Partial/unavailable results can be reused intentionally. Stages and checkpoint are scope-local working artifacts. Alternate publication always runs afterward and lacks a content-sensitive shard identity (F02).

### Datasets, retrieval and downstream

- `code_graph_facts`: `graph/graph-<scope>-<family|database|producers>`; exactly nine shards per scope in the tested path. Physical schema remains `retrieval-index/2`, logical dataset `graph-fact/1`.
- `code_graph_stages`: `data/code-graph/scopes/*/work/**`; normalized and crosschecked JSON.
- `code_graph_checkpoints`: each scope's `checkpoint.json`.
- `code_graph_summary`: input summary and accepted summary under their actual load/acceptance task directories.
- `code_graph_scorecard`: acceptance JSON/text; closed schema validation is executed by `assemble_scorecard`.
- `alternate_cpg_index`: `analysis/alternate-cpg`; logical `alternate-cpg/1`, physical `retrieval-index/2`.
- `alternate_cpg`: `data/code-graph/alternate-cpg/**` and attempt summary. Fixed JSONL paths are not immutable per computation (F02).

The representative dataset/glob tests passed. Generic manifest verification validates shard bytes/metadata and relation resolution; it cannot repair semantic adapter errors. Job `strict_gaps` remains false; generic handoff projection converts legacy text reasons rather than traversing every nested scope/SQLite row.

Complete `retrieval/graph.py` was read: primary query modes validate exact logical subjects, family/class/depth/result bounds, SQL reads and gaps; callers/callees traverse stored CONTAINS/CALLS. Alternate queries instead load all alternate nodes/edges and recompute paths/slices, with checks before the Python traversal but no deadline inside it (F09). `read_excerpt` rehashes physical source and rejects fabricated alternate digests (F01).

`job_review_data_indexing/datasets.py:132-143` admits the alternate datasets. However inference/package consumers omit them (F12); the source-context view explicitly selects only `code_graph_facts` (`jobs/bound_artifacts.py:107`). Current in-process cells recognize the new queries, so the older MCP adapter's missing tool allowlist must **not** be misreported as proof that all current cells lack dispatch. Read-contract failure was separately reproduced with the actual inference contract.

## New findings

### CGI-F01 — High — Alternate nodes fabricate source digests when catalog shards are absent

- **Evidence:** `src/appsec_review/jobs/job_code_graph_index/alternate_cpg.py:2253-2263,2344-2367`; source verification `src/appsec_review/retrieval/core.py:710-737,771-776`.
- **Trigger:** valid admitted syntax/clangd/graph evidence, but no matching catalog source-file hash in the present manifest. This is allowed optional input; dropped catalog shards are not restored by `scopes.restored_secondary`.
- **Expected / actual:** preserve the original verified source hash or explicitly report unresolved source. Instead `file_sha256` is SHA-256 of `snapshot:path`, not file bytes, and byte bounds are zero. **R9:** published `handle` exists, but real `RetrievalCore.read_excerpt` returns no result with **`target source changed after indexing`**, although source never changed.
- **Impact:** source-confirmation/retrieval fails for otherwise usable alternate graph nodes; the diagnostic incorrectly blames target mutation.
- **Confidence:** high, real publication and retrieval reproduced.
- **Smallest correction:** collect original verified source identities from all admitted inputs/scope sources, retain actual coordinates/backing, and never invent a digest to fill an evidence field.
- **Overlap:** T-169 (done), T-5016; no exact pre-existing entry/finding found.

### CGI-F02 — High — Same-count alternate rebuild overwrites a previously referenced shard

- **Evidence:** `src/appsec_review/jobs/job_code_graph_index/alternate_cpg.py:2327-2332,2458-2485`; fingerprint includes snapshot and counts, not content/input/settings identity; existing shard is unlinked.
- **Trigger:** a corrected/enriched/reconfigured graph changes nodes/edges without changing counts; even changed-count outputs reuse the fixed JSONL paths.
- **Expected / actual:** a new immutable computation gets distinct paths; earlier accepted references continue verifying. **R11:** changing one node's qualified name produced the **same shard path with different bytes**; loading the old manifest then failed **`target evidence integrity mismatch`**.
- **Impact:** reruns invalidate earlier manifests/evidence/checkpoints. Shared immutable receipt checks can detect the damage; they do not make replacing the path correct. This is not a claim that corrupt evidence bypasses verification.
- **Confidence:** high for actual publisher/manifest failure; full live runtime publication was not run.
- **Smallest correction:** content/input/settings-sensitive fingerprint, immutable per-computation JSONL paths, reuse/attestation rather than unlinking a published object.
- **Overlap:** T-169; no exact prior report/TODO found.

### CGI-F03 — High — Alternate projection erases disagreement and republishes the call as exact

- **Evidence:** `src/appsec_review/jobs/job_code_graph_index/alternate_cpg.py:1026-1202,1232-1286,2414-2431`; primary eligibility contract `src/appsec_review/graph/contract.py:263-295`.
- **Trigger:** a canonical CodeQL call fact with `cross_check.state=disagree` and `direct_eligible=false` still has its contextual CALLS relation.
- **Expected / actual:** retain contradiction/uncertainty and original producer authority in the alternate edge. **R10:** the real publisher emits **`exact=1, confidence=0.95, ambiguity=NULL`**, with `codeql_semantic` provenance; contradiction/admissibility is absent. The converter also treats collected secondary/analyzer graph facts as CodeQL branches without preserving their original producer; that additional case is static, not separately reproduced.
- **Impact:** a deliberately disputed graph edge becomes apparently exact alternate reachability/context. No claim that a final review finding was generated from it.
- **Confidence:** high.
- **Smallest correction:** project original producer, exactness, coverage and cross-check state; do not infer exactness solely from a resolution-tier name.
- **Overlap:** T-169/T-5016; distinct from known CSI-F01, which promotes a non-call reference.

### CGI-F04 — High — Canonical call positions are lost and separate call guards are combined

- **Evidence:** expected canonical shape `src/appsec_review/graph/normalize.py:893-901`; consumer `src/appsec_review/jobs/job_code_graph_index/alternate_cpg.py:1157-1202,1232-1255,1484-1505`.
- **Trigger:** real call payload uses `result.caller.symbol` and `result.callee.{symbol,display}`, with Tree-sitter enclosing functions. Consumer instead looks for flat `caller_id`/`callee_id` and stringifies the callee object. Its relation fallback uses caller **definition** line. Later fusion matches a whole caller/callee pair regardless of occurrence.
- **Expected / actual:** preserve each call-site span and its own dominating conditions. **R8:** real-shaped source call at line **5** moves to function definition line **4**. **R13:** two CFG call occurrences with opposite arms of guard G become **one edge containing both `true_branch` and `false_branch`**.
- **Impact:** invalid call-site explanations and impossible combined guard conditions on paths; can wrongly make another occurrence appear guarded.
- **Confidence:** high; real canonical call shape plus bounded synthetic occurrence metadata. No real compiler/CFG execution.
- **Smallest correction:** consume canonical nested fields; use occurrence/span identity when fusing; never union dominance claims across distinct occurrences.
- **Overlap:** T-169/T-5016; known CSI-F01 also mentioned clangd occurrence positions, but these are independently broken **CodeQL shape/fusion** paths.

### CGI-F05 — High — Nearby functions with the same simple name collapse into one node

- **Evidence:** `src/appsec_review/jobs/job_code_graph_index/alternate_cpg.py:535-577`.
- **Trigger:** distinct qualified methods/overloads in one file whose ranges overlap or lie within two lines.
- **Expected / actual:** retain separate identities or an explicit ambiguous relationship. **R2:** `A::f` at line 1 and `B::f` at line 3 become one function named `A::f`, span 1..3. Matching keys ignore qualified name/signature/build scope; the new-node hash also omits these identities.
- **Impact:** conflates calls, parameters, guards and reachability of unrelated functions. Same-line overload/method definitions are especially exposed.
- **Confidence:** high, real synthesizer reproduced.
- **Smallest correction:** fuse only source/symbol identities proven equivalent; use qualified signature/scope and exact span, otherwise keep candidates separate.
- **Overlap:** T-169; no exact prior report/TODO found.

### CGI-F06 — Medium — Alternate SARIF fusion ignores the producer's flat flow-step format

- **Evidence:** `src/appsec_review/jobs/job_code_graph_index/alternate_cpg.py:1288-1322`; actual flat consumer/format `src/appsec_review/graph/correlate.py:140-153`, fixture `tests/fixtures/graph/job/builder.py:111-121,250-259`.
- **Trigger:** accepted CodeQL `payload.flows` is a flat list of steps with flow/thread/ordinal/location.
- **Expected / actual:** group/order these steps and synthesize their bounded flow context. The alternate loop treats each step as a flow object and looks for `step["steps"]`, finding none. **R3:** flat producer format emits **zero TAINT_STEP edges**; otherwise identical nested `code_flows:[{steps:...}]` control emits one.
- **Impact:** advertised scanner-flow fusion silently disappears, particularly when no exported semantic path covers the scanner observation.
- **Confidence:** high.
- **Smallest correction:** reuse the existing canonical flow grouping/ordering helper; preserve incomplete/unindexed-flow gaps.
- **Overlap:** T-169; no exact existing issue found. Existing alternate fusion test supplies the nested nonproducer format.

### CGI-F07 — Medium — AST fallback reads fields the Tree-sitter producer does not publish

- **Evidence:** consumer `src/appsec_review/jobs/job_code_graph_index/alternate_cpg.py:2175-2213`; producer `src/appsec_review/jobs/job_tree_sitter_ast/normalize.py:206-224`.
- **Trigger:** accepted AST shard without usable separate CFG artifacts (including historical cache output described by upstream Tree-sitter report).
- **Expected / actual:** fall back to `grammar_native_type` and `syntax.category/written_name`, and actual `cfg_nodes/cfg_edges` fields. Consumer requires `payload.node_type` equal to `function`, `call`, or `route_candidate`, and looks for CFG nodes inside `cfg`. **R12:** seven producer-shaped AST rows (definitions/calls) become **zero functions and zero calls**.
- **Impact:** the intended degraded-build/absent-CFG fallback does not recover existing syntax information.
- **Confidence:** high; production shape inspected; real SQLite extraction reproduced with only the absent-CFG lookup boundary faked.
- **Smallest correction:** explicit adapter for the current Tree-sitter normalizer/CFG contract, tested from actual normalized rows rather than invented `node_type` records.
- **Overlap:** T-169/T-168. Upstream stale cache without CFG is a separate known input cause; this consumer fallback failure is new.

### CGI-F08 — Medium — `enabled` and `max_slice_depth` settings have no effect

- **Evidence:** declarations/validation `src/appsec_review/jobs/job_code_graph_index/alternate_cpg.py:225-262`; unconditional synthesis/publication `job.py:416-434`; synthesis uses only hop/path settings at `alternate_cpg.py:1605-1620`; retrieval hardcodes defaults/ceiling in `src/appsec_review/retrieval/graph.py:509-579`.
- **Trigger:** operator sets alternate `enabled=false` or a smaller configured slice-depth bound.
- **Expected / actual:** honor or reject the setting. **R1:** false versus true yields identical nonempty graph. `max_slice_depth` has no references outside its declaration/parser; retrieval still accepts up to 16.
- **Impact:** disabled work still runs/publishes; configured query bounds are misleading.
- **Confidence:** high (disabled reproduced, slice setting statically exhaustively referenced).
- **Smallest correction:** explicit disabled disposition and settings-aware run-bound query limits; do not weaken existing capability checks.
- **Overlap:** T-169; no exact TODO found.

### CGI-F09 — Medium — Alternate traversal bounds do not bound work or faithfully report cuts

- **Evidence:** `src/appsec_review/jobs/job_code_graph_index/alternate_cpg.py:1740-1828,1937-1964,1615-1621,2502-2503`; query boundary `src/appsec_review/retrieval/graph.py:457-506,564-579,634-648`.
- **Triggers / actual:**
  - **R7:** a 27-node/105-edge layered DAG with an unreachable sink visits **3906 queue states even with `max_paths=1`**. Per-path cycle sets do not bound the number of simple prefixes; the queue has no work/frontier cap or deadline. Larger branching graphs grow combinatorially within admitted hop limits.
  - **R4:** selecting five matching seeds with `max_nodes=1` returns **five nodes, `truncated=false`**; seeds bypass the cap. Depth exhaustion also does not set truncation.
  - **R14:** setting precomputed paths to 1 rather than 2 drops a reachable witness with **no named gap/cut count**. Publication calls coverage complete whenever CFG admission supplied no gaps.
- **Expected:** separate deterministic visited/frontier/node budgets and truthful hop/result-cut reporting.
- **Impact:** work/memory can far exceed the apparent output cap, while bounded coverage can look complete. No large or deliberately slow stress test was run.
- **Confidence:** high for the small reproductions and missing checks; no live performance claim.
- **Smallest correction:** bound work as well as output, cap seeds, check deadlines inside traversal, and return structured truncation/omission metadata through publication/retrieval.
- **Overlap:** T-169 explicitly promises memory-bounded synthesis; no exact existing defect found.

### CGI-F10 — Medium — Reversed SARIF intermediate steps are marked exactly bridged

- **Evidence:** `src/appsec_review/graph/correlate.py:156-162,176-197`.
- **Trigger:** all individual spans exist in a candidate path, but scanner intermediates appear in the opposite order.
- **Expected / actual:** ordered correlation must reject/degrade nonmonotonic matching. `_ordered_match` falls back to an earlier exact step when none occurs after `previous`. **R6:** matched indices **`[0,2,1,3]`**, state **`bridged`**, exact correlation relation.
- **Impact:** incorrectly reports an ordered scanner trace as corroborated by a different graph path and propagates false scorecard/retrieval bridge state.
- **Confidence:** high; actual `correlate` over fixture source bytes and canonical step records.
- **Smallest correction:** enforce monotonic subsequence matching, including endpoints; report out-of-order as partial/broken rather than restarting at an earlier exact match.
- **Overlap:** T-5016/T-126 are related quality/multiproducer work, not an exact existing finding.

### CGI-F11 — Medium — Integer range bounds are rounded through binary float

- **Evidence:** `src/appsec_review/graph/normalize.py:401-409,845`; downstream `src/appsec_review/graph/bounds.py:125-143`.
- **Trigger:** exact integer text beyond IEEE-754's exact integer range, common in 64-bit analysis.
- **Expected / actual:** exact integer semantics. **R5:** `"9007199254740993"` becomes **9007199254740992**. The interval then carries the wrong integer and can feed destination-bound reasoning.
- **Impact:** quantitative graph evidence differs from export; thresholds can be compared incorrectly.
- **Confidence:** high, actual conversion reproduced; no claim of a final false finding.
- **Smallest correction:** parse integer syntax directly with `int`, preserving unknown/noninteger bounds explicitly instead of a float round-trip.
- **Overlap:** no exact TODO/prior report found; T-5016 is broadly related.

### CGI-F12 — High — Inference cannot legally read the alternate dataset it is offered

- **Evidence:** `src/appsec_review/jobs/job_inference_security_review/datasets.py:180-189` and `job_review_package_assembly/datasets.py:77-86` omit `alternate_cpg_index`; producer declaration `job_code_graph_index/datasets.py:50-54`; enforcement `runtime/inputs.py:359-366,474-499`; actual query loads `analysis/alternate-cpg` at `retrieval/graph.py:457-485`.
- **Trigger:** graph job publishes a real accepted alternate shard; an in-process inference query asks `query_call_paths` or `query_cpg_slice`.
- **Expected / actual:** properly scoped, explicitly declared read access. **R15:** real staged/accepted graph output + actual inference contract + `input_read_scope` + `RetrievalCore.query_call_paths()` raises **`undeclared consumption by job_inference_security_review: job_code_graph_index/alternate_cpg_index`**. Scope exit raises the expected sticky **input contract violation** as well.
- **Impact:** the advertised product is unusable through this actual downstream read boundary; catching a query exception does not make the unit's read legal.
- **Confidence:** high, real accepted fixture, runtime reader and contract reproduced. No inference/model invocation.
- **Smallest correction:** declare the intended alternate output in legitimate consumers, include it in the appropriate source view, and align tool index/row grants with its actual analysis index; retain explicit package scope rather than widening access generally.
- **Overlap:** T-169/T-173; neither inspected entry records this exact missing contract. Older MCP adapter also lacks these tools, but current cells have separate dispatch, so that was not counted as the root cause.

### CGI-F13 — Low — Scorecard totals count only the truncated displayed lists

- **Evidence:** `src/appsec_review/graph/scorecard.py:181-188,202-207`.
- **Trigger:** >5000 first-party functions or >1000 paths in a scope.
- **Expected / actual:** totals cover all analyzed rows, with separate display omission counts. `first_party_functions` sums kept functions only; `paths_eligible` considers only kept paths. **R16:** lowering the display cap to one for a two-function fixture gives total **1**, `functions_omitted=1`, actual **2**. Analogous eligible-path truncation is static, not separately reproduced.
- **Impact:** summary metrics undercount larger runs despite explicit omitted lists.
- **Confidence:** high.
- **Smallest correction:** compute totals before truncating detail rows and carry those totals into assembly.
- **Overlap:** T-5016 directly owns scorecard completeness; no exact existing defect entry found.

## Previously reported defects and documentation limits

- **CSI-F01 — High, known:** `alternate_cpg.py:946-991` unconditionally registers clangd variables as functions and converts REFERENCES into CALLS. Read the full `job-audit-job_cpp_symbol_index.md`; confirmed the consumer branch, did **not** re-audit/re-execute the entire upstream producer. Exclude from this report's new count.
- **CQ-01 — High, known:** CodeQL plan can omit compiled files with missing build receipts. Graph's exact plan/export-set comparison cannot detect files never present in that plan. Graph count/NOT_APPLICABLE is not whole-target coverage.
- **CQ-02 — Medium, known shared mapper:** graph `_Locator.path` calls CodeQL `map_location`, inheriting leading-dot stripping/wrong-file mapping. No duplicate reproducer/count.
- **CQ-05 — Medium, known:** per-scope global seed-gap misaccounting survives `bounded_seeded` and database coverage/cards.
- Previous compiled/Clang/CPG/SVF report references were consulted selectively. Their upstream losses (IR/AST semantics/flow availability, diagnostic metadata, CPG names/counts, SVF coverage) are input limitations, not rerun or independently certified here.
- **Documentation:** T-169 is marked done but its task page still promises debug-symbol fusion, override/macro data, primary-query integration and `code-graph-shard/2` not present in this job. Current implementation publishes an **analysis** alternate shard and two separate query tools. The operations/current architecture narratives largely describe the older primary graph. The task's “validate alternate schema at publication” is not implemented by the publisher. These are implementation/claim mismatches, not authorization to add missing layers.
- Alternate code does not reapply first-party dispositions after harvesting boundary symbols/CFGs, nor preserve every CodeQL guard/range/summary in its projection. Consequences beyond the reproduced issues were not independently measured; do not assert full semantic fusion.
- Scope scorecard excludes alternate graph metrics except the separate acceptance counts. The summary's `shards` count is primary graph shards, excluding the alternate analysis shard. Treat it as that narrower count, not a full manifest count.
- No new catalog hash/signing requirement is proposed. Operator-declared release reuse remains intentional.

## Validation record

All Linux snippets used the shared brief's exact transport:

```powershell
$encoded = [Convert]::ToBase64String(
  [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Working directory was always `/home/wsollers/projects/appsec-review`. Initial identity checks:

```bash
git rev-parse HEAD
git branch --show-current
git status --porcelain
git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
```

Before collection/execution:

```bash
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
.venv/bin/python -c 'from tests.test_000_unit_environment_guard import offending_environment; import os; x=offending_environment(os.environ); print("unit environment:", x); assert not x'
```

Environment offences **[]**. Fixtures were read first: all seven job files, both graph fixture builders, root/unit conftests and guard. Fixtures stage inert source text, recorded exports, SQLite shards and accepted handoffs; they do not compile/execute target code. The job itself launches no analyzer. Tests for CFG synthesis operate on in-memory AST data, not a parser process. Unit guards refuse engines/network/Dagster.

### Collection

```bash
base="test/tmp/job-audit-code-graph31-collect-$(date +%s)-$$"
.venv/bin/python -m pytest -o addopts= -q --collect-only --basetemp="$base" \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_code_graph_index
```

Exit 0: **53 collected in 3.02 s**. Actual private base: `test/tmp/job-audit-code-graph31-collect-1795025060-3182566`.

### Rejected wrapper selection

```bash
bash scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 31047 \
  --max-tests 53 --expect-tests 53 --timeout-seconds 180 --strict -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_code_graph_index
```

Exit **2 before pytest**: directory selector rejected; wrapper requires existing test-file selectors. No tests executed/no test elapsed time exists for this rejected invocation.

### Executed focused selection

```bash
bash scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 31047 \
  --max-tests 53 --expect-tests 53 --timeout-seconds 180 --strict -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_code_graph_index/test_alternate_cpg.py \
  tests/unit/job_code_graph_index/test_contract.py \
  tests/unit/job_code_graph_index/test_datasets.py \
  tests/unit/job_code_graph_index/test_handlers.py \
  tests/unit/job_code_graph_index/test_producers.py \
  tests/unit/job_code_graph_index/test_scopes.py \
  tests/unit/job_code_graph_index/test_secondary_assignment.py
```

Wrapper execution command:

```bash
/home/wsollers/projects/appsec-review/.venv/bin/python -m pytest \
  -p ops_test_guard -c /home/wsollers/projects/appsec-review/pyproject.toml \
  --rootdir=/home/wsollers/projects/appsec-review -o addopts= -q -rfE \
  --basetemp=test/tmp/tests-custom-20261118-130439-750722-3183901 \
  --junitxml=test/tmp/tests-custom-20261118-130439-750722-3183901.junit.xml \
  -o junit_family=legacy -n 2 --shuffle-seed=31047 \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_code_graph_index/test_alternate_cpg.py \
  tests/unit/job_code_graph_index/test_contract.py \
  tests/unit/job_code_graph_index/test_datasets.py \
  tests/unit/job_code_graph_index/test_handlers.py \
  tests/unit/job_code_graph_index/test_producers.py \
  tests/unit/job_code_graph_index/test_scopes.py \
  tests/unit/job_code_graph_index/test_secondary_assignment.py
```

Wrapper collection uses the same fresh private base sequentially with `-n 2` removed and `--collect-only` added. Exact count 53. **53 passed**, pytest **13.15 s**, total **22.446100 s**, failures/errors/skips **0**, tests over 10 s **0**. Collection/execution both completed and cleanup reported zero remaining processes.

Retained evidence under `test/tmp`:

- `logs/tests-custom-20261118-130439-750722-3183901.log`
- `logs/tests-custom-20261118-130439-750722-3183901.collection.log`
- `tests-custom-20261118-130439-750722-3183901.collection.json`
- `tests-custom-20261118-130439-750722-3183901.junit.xml`
- `tests-custom-20261118-130439-750722-3183901.timings.sqlite`
- `reports/tests-custom-20261118-130439-750722-3183901.json`

The map lists the six older job files, but **omits `test_alternate_cpg.py`**. It was discovered, inspected and included explicitly here; mapping omission is not absence of tests.

### Offline reproductions, including unsuccessful invocations

Each used `set -eu; cd /home/wsollers/projects/appsec-review; umask 022; .venv/bin/python - <<'PY' ... PY` through SSH. Unique absolute scratch derived from `Path("test/tmp") / ("job-audit-code-graph31-repro-<letter>-" + uuid4().hex)`. Timers start after imports; `finally` removed only that invocation's own tree. No pytest collection, external engine or provider occurred.

| Invocation / exact scratch suffix | Outcomes actually reached | Body seconds / exit |
|---|---|---|
| A / `a-40a77393394b406cbf6ea8f8c3beabf6` | R1 disabled ignored; R2 merge; R3 flat SARIF ignored; R4 seed cap bypass; R5 integer rounding. Then R6 used invalid fixture observation identity `observation-1`, causing **reproducer** `ValueError: invalid logical identifier`; R7 not reached. | **0.012946**, exit 1 |
| B / `b-703efe448ee04af492384333800f1948` | Corrected R6 with real LogicalIdentity: bridged `[0,2,1,3]`; R7 3906 states; R8 real nested call moves 5→4. Then retrieval fixture used invalid run ID `r1`, causing **reproducer** `ValueError: invalid run id`; R9–R12 not completed there. | **0.050254**, exit 1 |
| C / `c-35b581d8bc824c85b9869cdbe5a6e205` | Corrected run ID `2026-11-18-0031`: R9 excerpt rejects fabricated digest; R11 same-path overwrite invalidates prior manifest; R12 seven AST rows → zero functions/calls. All assertions passed. | **0.081438**, exit 0 |
| D / `d-67ea0d47d7a146d0a73d9cc772fbec60` | R10 rejected semantic fact becomes exact alternate relation; R13 contradictory guard arms merge; R14 cap omits path without gap; enabled probe true. All assertions passed. | **0.577917**, exit 0 |
| E / `e-ef492f5a83734ed28daf544e082f54a3` | R15 real job handler/accepted fixture/read: inner expected undeclared-dataset error verified. On context exit the runtime intentionally raises sticky **input contract violation**; this is the reproduced product failure, not another fixture error. | **2.362445**, exit 1 |
| F / `f-6276c2b7d8db4a95ae4dd9ab90bcc3aa` | R16 real scorecard with display cap reduced in memory: two functions, one omitted, total incorrectly one. All assertions passed. | **0.014246**, exit 0 |

Smallest reproduction recipes (compacted equivalents of executed bodies, not claims of additional test runs):

```python
# R1/R2/R3/R4: real synthesizer; data only.
from appsec_review.jobs.job_code_graph_index import alternate_cpg as a
ts = {"path": "a.py", "language": "python", "functions": [
    {"name": "handle", "start_line": 1, "end_line": 5},
    {"name": "helper", "start_line": 10, "end_line": 15}]}
assert a.synthesize_alternate_cpg(tree_sitter_files=[ts]) == \
       a.synthesize_alternate_cpg(tree_sitter_files=[ts],
                                 settings=a.AlternateCpgSettings(enabled=False))
# Feed symbol_declarations A::f line 1, B::f line 3, same a.cpp, kind=function.
# Feed sarif_observations payload.flows = flat ordinal/code_flow/thread_flow/location steps
# at a.py lines 2,12; compare nested code_flows:[{steps: same_steps}].
# Select five non-entrypoint function nodes in x.py with compute_cpg_slice(path="x.py",max_nodes=1).

from appsec_review.graph.normalize import _bound
assert _bound("9007199254740993") == 9007199254740992  # R5
```

- **R6:** inspected `build_secondary` fixture, no native producers; use `fixture.entry("read(0, buf, sizeof buf)")`, `fixture.sink("memcpy(out, buf, k)")`, and `fixture.path` with steps `read → n*2 → m+1 → memcpy`. Canonical SARIF steps visit `read → m+1 → n*2 → memcpy`; actual `correlate` returns bridged.
- **R7:** one entry + five layers of five function nodes, every layer fully linked to the next, plus disconnected sink; instrument only `deque.popleft` with a counting subclass, no algorithm alteration. `find_interprocedural_paths(source="entry",max_paths=1,max_hops=5)` returns none after 3906 pops.
- **R8/R10:** inspected fixture's real symbol entities and call fact (`process` definition line 4, `helper(n)` at line 5). Set its cross-check to disagree and recompute admissibility. Pass entity rows, CONTAINS, CALLS, and Tree-sitter function spans to actual synthesizer/publisher; inspect line and SQLite relation exactness.
- **R9/R11:** synthesize two functions and a call, publish without `file_shas`, create real manifest/core over unchanged tiny source, request excerpt. Then alter one node's qualified name without changing counts, republish, and verify the old manifest.
- **R12:** inspected `build_secondary(...,clangd=None,ir_calls=None,ast_calls=None)` creates real producer-shaped Tree-sitter SQLite. Fake only `_accepted_cfg` as absent, execute `_extract_tree_sitter_files`.
- **R13:** add two CFG call blocks for one caller/callee at lines 5 and 8 with opposite arms of G to R8 input; inspect one fused edge's guard list.
- **R14:** one `handle` function with two distinct sink calls (`eval`, `open`), compare max_precomputed_paths 1 and 2; inspect missing truncation/gap metadata.
- **R15:** actual `stage_run`, `_execute_units`, `_publish_unit_handoff`; create `RetrievalCore` and `SimpleNamespace` read context with actual inference CONTRACT and accepted graph handoff digest; invoke `core.query_call_paths()` inside `input_read_scope`. No model/cell service.
- **R16:** two fixture function symbols, real `scope_scorecard`/`assemble_scorecard`, in-memory `patch.object(scorecard,"MAX_FUNCTIONS",1)` only.

One source-inventory command also encountered nonexistent historical `src/appsec_review/retrieval/code_graph.py` and exited 1 before the remaining inventory prints; inspection resumed on actual `retrieval/graph.py`. This was not a validation failure. No dependency failures or installations.

Final verification returned the same SHA, empty status/diff, and **no own reproduction leftovers**:

```bash
git rev-parse HEAD
git status --porcelain
git diff --stat
```

## Read scope and material gaps

**Read fully:** updated brief; authorized AGENTS/coordination skill; operations `job_code_graph_index.md`; all six Python files in this job package; all eleven nonempty/helper graph modules (`analyzers`, `bounds`, `catalog`, `contract`, `correlate`, `crosscheck`, `normalize`, `scorecard`, `settings`, `svf_crosscheck`, plus trivial initializer inventory); all seven job unit-test files; two complete graph fixture builders; root/unit conftests and unit-environment guard; `retrieval/graph.py`; `indexing/store.py`; `runtime/consume.py`, `runtime/units.py`; alternate CPG JSON schema; T-169 task page; `docs/architecture/job-input-contracts.md`; shell test wrapper/common helper; full clangd and CodeQL audit reports.

**Sampled / exact relevant portions:** central TOML/test-map; registry, selection/topology; graph export directory validator; runtime input/read/handoff/publication boundaries; retrieval core/index/source verification; shared immutable named publication; Tree-sitter normalizer fields; downstream source-context selection and dataset declarations; current cell capability/query filtering and older MCP allowlist; current code-intelligence architecture (1–180), historical graph design (intro/decisions, not its complete 1462-line history); TODO searches plus T-169/T-5016/T-5017 entries; other upstream report matching paragraphs.

**Material unread or unexecuted matrix:**

- All native compiler/clangd/CodeQL/SVF/Joern behavior, releases/images, real targets, original native export recordings and source-to-export quality. Fixtures consumed recorded JSON during tests; every raw exported row was not manually audited.
- Per-language primary normalizer/export tests in `tests/graph/test_*_export.py`, full graph helper test matrix, primary retrieval/admissibility/scoring suites, and all integration/live mapped tests were **not run**. Nine-language alternate tests are hand-authored ASTs, not grammar/parser/native language acceptance.
- Full runtime runner/admission/storage verification and concurrent publication races; the report does not claim a full real JobRunner-to-model-to-final-report run. Read-contract R15 is a focused real reader over staged accepted fixtures.
- Entire downstream jobs, model prompting, package assembly, final-report scorecard rendering, and all role/capability permutations were not audited. The current in-process path and legacy MCP path are not interchangeable.
- Full exported graph-language column/catalog semantics, generated-source backing, macro/Unicode/overload/dynamic-dispatch matrices, alternate positional argument semantics, graph-size/resource stress, every scope/checkpoint interleaving and all shuffled test orders remain unverified.
- No file changes/TODO additions were made. T-115/T-123 (native provenance/acceptance), T-126 (multi-producer design), T-147/T-157 (bindings/applicability), T-169/T-173 (alternate product/inference use), T-5016/T-5017 remain relevant ownership/validation context, not proof that this audit resolved them.

The individual report is the only document created. Work stopped after this job.
