# Job 12/47 audit — `job_tree_sitter_ast`

## Scope and verdict

- **Audited revision:** `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`, clean `main`, `/home/wsollers/projects/appsec-review`, Ubuntu-22.04 through `ssh wsl-ubuntu`. The Windows default checkout was not audited.
- **Environment:** `.venv/bin/python` imported `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`. HEAD and cleanliness were checked before execution; no repository source/configuration edits, commits, image operations, providers, builds, network clients, services, or live/integration/acceptance reviews were performed.
- **Verdict:** NOT exact-correct. The input/routing/raw-AST/publication path has substantial focused coverage, but the new CFG path drops real Rust control structures, mishandles finally and do/while flow, and silently loses bounded work. Further contract, retrieval, and cache defects are detailed below.
- **Validation:** **57 passed**, no failures/skips and no cases over 10 seconds; pytest 6.24 s, supervised wrapper 14.828 s. This includes 54 job-package cases and 3 environment guards. Additional offline reproductions establish the findings, including replay of hash-verified recorded native grammar output. No live grammar was loaded.
- **Finding totals:** 2 high, 7 medium functional/contract findings; 1 low documentation/test-map finding. Separate non-findings and unverified risks are explicitly distinguished.

## Registration, intended contract, configuration

`runtime/registry.py:76,145` imports/registers the job. `job_tree_sitter_ast/datasets.py:93-98` specifies `REVIEW_GRAPH`, checkout access, propagated handoff, ordinary enabled execution, and ordering after language build. `orchestration/topology.py:47-80` derives actual dependencies from scheduling plus consumed producers and removes redundant ancestors. Default `appsec-review.toml:959-987` enables this job by absence of a disabling override:

- Job, parse step, parse task and parser setting workers: 8.
- `max_file_bytes=2097152`, `max_nodes_per_file=20000`, `max_nodes_per_scope=20000`.
- `max_files_per_scope=128`, `max_source_bytes_per_scope=16777216`.
- `_validate`, `job.py:104-119`, verifies topology and positive non-boolean integers, ceilings of 32 workers, 16 MiB/file, 1024 files/scope, 128 MiB/scope, and 500,000 nodes/file or scope. It does not check the cross-bound inconsistency in TS-F08.
- Frozen source-disposition rules are inherited by `config/first_party.py:25-43`.
- The grammar lock routes C, C++, C/C++, C#, Go, Java, JavaScript, Kotlin, PHP, PowerShell, Python, Ruby, Rust, Shell/Bash, TSX and TypeScript. Swift is policy-excluded or unavailable; it has no fallback grammar.
- There is **no model task or prompt execution**. The only external invocation is the locked `tool-tree-sitter` parser. Undeclared generated task execution metadata remains existing **T-147**, not evidence of nonexecution.

### Accepted input surface

The exact declaration is `job_tree_sitter_ast/datasets.py:54-90`:

| Producer | Declared datasets | Actual use |
|---|---|---|
| `job_target_catalog` | Required/reject `handoff`; optional/gap `target_artifact_inputs`, `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units`, `catalog_documents` | Handoff → catalog artifact → repository partition, component and build-target artifacts. Required source snapshot agreement. Indexed catalog/source entities are propagated through the input manifest, not queried to plan scopes. |
| `job_review_intake` | Optional/gap `handoff`, `model_preflight`, `binary_evidence`, `review_intake` | Handoff and intake artifact are nevertheless unconditionally required in code. The fingerprint is compared with catalog; no model/binary payload processing here. TS-F07. |
| `job_language_build` | Optional/gap `handoff`, `topology_refinement_inputs`, `build_actions`, `jvm_build_actions`, `language_build_receipts`, `build_workspaces` | Optional admitted receipt set → selected generated-source artifacts and verified workspace manifest → detached source bytes. No workspace-tree scan. Missing producer creates a generated-source gap only when builds make it relevant. |

`runtime/consume.py:165-203` verifies admitted producer pins, envelope schema and handoff bytes; actual readers do not directly choose another producer's `latest.json`. However, reading a handoff is not a dataset read receipt; TS-F09 records the missing artifact-level observations.

### Published outputs and consumer expectations

| Dataset | Actual output and validation |
|---|---|
| `tree_sitter_ast` | `data/indices/analysis/<fingerprint>.sqlite`, retrieval-index/2 physical database containing normalizer/1 AST payloads, exact byte/point-derived locations, `CONTAINS`, syntax projections, and new embedded CFG payloads/relations. Indexed `analysis`; syntax/find/search/trace, plus separate CFG query APIs. |
| `tree_sitter_node_shards` | `data/treesitter/shards/<fingerprint>.jsonl`, normalizer/1 raw nodes, sorted by row bytes. No embedded CFG payload in this JSONL; CFG is in SQLite and separate CFG artifacts. |
| `tree_sitter_cfg` | `data/treesitter/cfg/<fingerprint>/{cfg-nodes.jsonl,cfg-edges.jsonl,cfg-manifest.json}`, cfg/1. Artifact-only; downstream code graph consumes references admitted through scope dispositions. |
| `tree_sitter_scope_results` | Shared `<fingerprint>.json` metadata and attempt-local `parse/dynamic_scopes/dynamic/<scope_id>.json`; schema tree-sitter-ast/1, including failed parser outcomes. |
| `tree_sitter_coverage` | Attempt-level `tree-sitter-coverage-<attempt>.sqlite`; per-disposition status and language metadata. Per-file AST and syntax-projection coverage also lives in scope SQLite shards. |
| `tree_sitter_acceptance` | Attempt-local `accepted-tree-sitter-ast.json`: target/lock/image, generated backing/build handoff, dispositions, AST/CFG counts, source dispositions, gaps and composed manifest. Item count is AST nodes, not functions/CFG nodes. |
| `generated_source_backing` | `data/treesitter/sources/<hash>.json` → immutable shared object; schema generated-source-backing/1. |
| `tree_sitter_tool_io` | Protected parser work and detached parser input trees; metadata inventory only, not public payload retrieval. |

Declarations/globs: `datasets.py:14-44`. Producer publication: `normalize.py:309-347`, `cfg.py:1522-1596`, `scope_execution.py:145-157`, `job.py:214-290`.

Manifest publication replaces this job's old manifest entries, keeps upstream shards, verifies composed lineage and all shard bytes, and binds scope language metadata (`job.py:236-252`; `retrieval/index.py:364-489`). Existing unit inventory auditing found no undeclared artifact violation for its fake-parser run.

Downstream checks inspected:

- `job_review_prioritization/streaming.py:53-115` observes `tree_sitter_node_shards`, hashes the same JSONL bytes it indexes, and reads bounded per-file rows; row ordering is therefore compatible.
- `job_code_graph_index/alternate_cpg.py:2037-2095` matches exact admitted scope/index identities, observes `tree_sitter_cfg`, verifies manifest/target/scope and nodes/edges references. Missing CFG becomes a downstream gap, not substituted data.
- `retrieval/syntax.py:39-121` retains source-identity/span bounded unresolved syntax lookup and separate projection coverage. Its new CFG APIs have the processing bound defect TS-F06.
- `retrieval/source_resolution.py:93-125,170-233` revalidates generated run/target/origin/canonical artifact/hash/size and never falls back to a target file with a matching logical name.

## Every declared step/task

| Step/task | Dispatch and real work | Audit outcome / coverage limits |
|---|---|---|
| `load.accepted_inputs` | `job.py:59-90,123-134`. Read admitted intake/catalog, verify JSON hashes/schemas and snapshots, select generated files, reject logical collisions, load lock, resolve image. Generated lane: `generated_sources.py:26-126`; bounds, accepted origins, roles, workspace validation, UTF-8, immutable backing. | Unit-tested with synthetic accepted producers; generated backing/tamper/limits tested. Optional intake mismatch TS-F07; dataset read observations TS-F09. No real image resolution. |
| `plan.route_scopes` | `job.py:136-171`; `model.py:53-139`. Source-in-scope language inventory, deepest component/build ownership, generated translation domains, TSX routing, first-party ordering, deterministic chunks, lock partition, Swift/generation/orphan-exclusion dispositions. | Unit-tested routing and count/byte chunking. A single oversized source defeats scope-byte bound, TS-F08. Disposition cache identity caveat below. |
| `parse.dynamic_scopes` | `job.py:173-212`: read all present dynamic records or bounded thread pool over scopes; sorted results and gaps. `scope_execution.py:60-157`: isolated source domains, verified reuse, staged request, container execution, output identity checks, hash-verified source reread, normalize and write metadata. | Fake container success/failure/omitted-output and cross-attempt reuse tested. Real recorded CST replay found TS-F01; synthetic control-flow cases TS-F02/03; normalized output TS-F04. Cache issue TS-F05. No image or real parser execution. |
| `acceptance.publish_handoff` | `job.py:214-290`: build attempt coverage, merge manifests, sum successful-index counts, write accepted summary and return item count/dispositions/status. Runtime units/handoff validate control records and canonicalize legacy text gaps. | Isolated JobRunner plus direct Dagster op-function tests exercised full publication/inventory. CFG incompleteness never becomes an upstream gap in TS-F04. Real multi-language/output quality remains unverified. |

Standalone Dagster adapter: `dagster.py:24-137` has begin, load, route dynamic outputs, mapped scope parse, collect, publish and finalize. It persists dynamic outcomes, then invokes the same parse aggregation and acceptance handlers. Its execution concurrency comes from Dagster max concurrency/pool limits; inline parsing uses `settings.workers`. Tests call decorated functions with fake context/executor; **no Dagster job execution** occurred.

Parser code inspected: `containers/tools/tree-sitter/parser.py:54-119` verifies request identity/language/source hashes, emits byte-limit and scope-node-limit file truncations, walks all CST children in preorder with parent-prefix ordinals, retains fields/flags/points, and emits tool/version identity. `scope_execution.py:37-56` checks tool/grammar/image/lock versions; `normalize.py:88-164,191-205` checks scope/path/hash and source byte extents. `ContainerExecutor` overrides the image entrypoint correctly and applies non-root, read-only, network-none, CPU/memory/PID/timeout policy (`container_runtime/executor.py:250-302`). These were static checks only.

## Findings

### TS-F01 — HIGH — Real Rust CST statement wrappers erase branches, loops and early returns

**Class:** reproduced functional failure using checked-in recorded parser output; high confidence.

**Evidence:** `src/appsec_review/jobs/job_tree_sitter_ast/cfg.py:1099-1117,1259-1315,1393-1398,1423-1444`. Dispatch checks only the current node's type. `expression_statement` is not a block wrapper and reaches the generic statement branch; it does not recursively lower its `if_expression`, `loop_expression`, `match_expression` or `return_expression`.

**Trigger:** normal Rust emitted by the locked grammar, not malformed input. `tests/fixtures/review_prioritization/target/rust/src/wire.rs:8-16` checks `buf.len() < 5` and returns an error before indexing the buffer. The hash-verified `ast-golden.json.gz` record has `if_expression` at line 9 and `return_expression` at line 10, both under `expression_statement`, with `root_has_error=false`.

**Expected vs actual:** `read_header` needs a conditional and early-error exit dominating later buffer accesses. The real synthesizer emits **zero guards**, treats the whole `if` as an ordinary statement, and continues unconditionally. The same recorded `lib.rs:24-34` `walk` function emits zero guards and no loop-header node despite its loop and nested conditions.

**Impact:** the always-available Rust CFG/call-path fallback lacks ordinary control flow and guarding evidence, while AST success and CFG counts look normal. The nine-language unit fixture masks this by putting Rust control expressions directly under blocks rather than replaying the grammar's wrappers (`test_cfg_and_guards.py:66-204`).

**Smallest correction:** grammar-aware lowering of executable expression wrappers, including nested terminating expressions, with frozen real-parser CST regressions. If a construct is not modeled, mark CFG coverage partial instead of implying a modeled straight-line statement.

**TODO overlap:** T-168/T-169 are marked done; this contradicts their delivered universal-CFG claim. T-5016 is related quality work, not an existing entry for this failure.

### TS-F02 — HIGH — `finally` is bypassed by terminating paths

**Class:** reproduced control-flow failure; high confidence.

**Evidence:** `src/appsec_review/jobs/job_tree_sitter_ast/cfg.py:1340-1398`: finally is connected only to `normal_tails` at 1382, while return immediately emits `return_exit` to the function exit at 1397. Exception targets without catches also point directly to exit (`cfg.py:1338-1341,1425-1431`).

**Trigger:** a function containing `try { return 1; } finally { cleanup(); }`.

**Expected vs actual:** finally executes before the pending return. The real builder's graph makes `cleanup()` unreachable from entry and connects the return directly to exit. Synthetic reproduction reports `cleanup_reachable=False`, `return_goes_direct_to_exit=True`.

**Impact:** misses guaranteed cleanup/sanitization/sink execution and creates incorrect reachability/guard facts in otherwise modeled syntax. Break/continue/exception paths need the same pending-control-transfer treatment; only return was dynamically reproduced.

**Smallest correction:** route all abrupt completions through applicable finally bodies, then resume their pending destination; add focused return and exceptional-path fixtures.

**TODO overlap:** T-168/T-169 (done). No matching prior job-audit finding found.

### TS-F03 — MEDIUM — `do … while` is lowered as a precondition loop

**Class:** reproduced control-flow failure; high confidence.

**Evidence:** `src/appsec_review/jobs/job_tree_sitter_ast/cfg.py:146-151` includes `do_statement`; the same file at `1259-1315` always connects incoming flow to the loop header, makes the body the true arm, and emits a false exit from the header.

**Trigger:** `do { work(); } while (false);`.

**Expected vs actual:** body must execute once before the condition. Actual CFG permits entry → header → false exit with no body execution and attaches guard `false/true_branch` to the body. Reproduced with the real synthesizer.

**Impact:** wrong reachability and dominance for post-test loops, including incorrectly guarding a mandatory body call.

**Smallest correction:** distinguish post-test loop entry/continue/condition targets from while/for lowering; exercise zero-condition/one-body behavior.

**TODO overlap:** T-168/T-169 (done); no dedicated existing item found.

### TS-F04 — MEDIUM — CFG node-cap loss and unsupported flow are not surfaced as CFG coverage gaps

**Class:** reproduced silent incompleteness plus verified static coverage omission; high confidence.

**Evidence:** `src/appsec_review/jobs/job_tree_sitter_ast/cfg.py:175,1068-1072` silently breaks sequence construction at 2048 nodes. `FunctionCfg.to_summary`, `cfg.py:557-581`, and CFG manifest publication `cfg.py:1566-1596` have no truncation/unmodeled counter or reasons. `src/appsec_review/jobs/job_tree_sitter_ast/normalize.py:285-313,334-345` reports AST parser limits/diagnostics, not CFG synthesis loss. `scope_execution.py:154-155` derives success solely from index gaps.

**Trigger:** one completely parsed function with 2050 simple statements, fewer than the default 20,000 CST-node limit.

**Expected vs actual:** retain a bounded CFG but publish omitted work and partial CFG status. Reproduction normalized **2054 AST nodes**, retained **2046 statements + entry/exit = 2048 CFG nodes**, reported **zero gaps**, and wrote raw-AST coverage `complete`. That raw-AST status is valid in itself; what is missing is independent partial CFG coverage, not a requirement to relabel the raw AST.

The recorded native fixture supplies another coverage example: `target/native/src/codec.c:29-36` has `goto done` and a labeled return. `synthesize_file_cfg` treats both as ordinary statements, with no unmodeled-construct report. The architecture explicitly promises `unmodeled_constructs` (`docs/architecture/tree-sitter-ast.md:114`).

**Impact:** downstream graph synthesis and guard queries cannot distinguish complete CFGs from truncated/unmodeled ones. No matching CFG-query response gap is added when a function exists (`retrieval/syntax.py:256-265,412-420`).

**Smallest correction:** track CFG-specific truncation and unsupported control constructs per function/file; propagate them into scope counts, manifest, accepted gaps and CFG retrieval. Preserve independent AST completeness.

**TODO overlap:** T-168/T-169 and T-5016. The explicit coverage/accounting failure is not already captured by their current wording.

### TS-F05 — MEDIUM — CFG generation is absent from the scope cache validity contract

**Class:** reproduced permissive cache admission; static repair/replay risk. High confidence in the omitted checks; no actual historic review restart was performed.

**Evidence:** `src/appsec_review/jobs/job_tree_sitter_ast/model.py:143-162` fingerprints syntax-projection and normalizer schema, source/grammar/image/limits, but not CFG schema/implementation. `src/appsec_review/jobs/job_tree_sitter_ast/normalize.py:27,30-51` retains normalizer/1 and accepts metadata with **no `cfg_artifacts`**; CFG hashes are checked only if a mapping already exists. `scope_execution.py:85-94` reattests and immediately returns such metadata. `normalize.py:54-66` explicitly supports reattestation under a changed implementation.

**Trigger:** an admitted retry/repair encounters a compatible-key legacy AST/index pair created before CFG generation, or a CFG implementation change that does not change the existing AST/projection key.

**Expected vs actual:** a job promising new CFG outputs must invalidate incompatible computations or explicitly recompute the new product. The cache reader accepts matching JSONL/index hashes without any CFG record and parsing is skipped. Downstream code graph later reports `has no accepted CFG artifacts` (`alternate_cpg.py:2075-2078`); it does not fix the skipped production.

**Smallest correction:** include an explicit CFG implementation/version identity in the fingerprint and require the expected CFG artifact set for that version before reuse. Test genuine pre-CFG metadata and CFG-version changes.

**TODO overlap:** T-168 schema-version/replay criterion and T-169; no dedicated existing cache item found.

**Important limit:** a separate reproduction showed disposition changes can leave the same scope ID/fingerprint (`first_party` → `vendored`). This is documentation/key incompleteness, **not a demonstrated ordinary same-run cache bug**, because `runtime/runner.py:79-88` refuses changed frozen configuration and repair retains it. It is not counted as another functional finding.

### TS-F06 — MEDIUM — New CFG retrieval paginates only after processing every matching function

**Class:** reproduced bound failure; high confidence.

**Evidence:** `src/appsec_review/retrieval/syntax.py:241-265,352-420`: both CFG and guard queries execute SQL with no row bound, decode complete CFG payloads for every matching function, retain matches, sort, and only then slice by `offset:offset+limit`. Unlike `query_syntax`, these queries do not use a bounded SQL page.

**Trigger:** `query_cfg_function(path="page.js", limit=1)` against a file containing many indexed functions. The 30-function reproduction returned one result but invoked `_sanitize_cfg_function_record` **30 times**. Every following page repeats the full processing.

**Expected vs actual:** result and execution work should be bounded against the accepted index. The response size is bounded later, but processing/memory scales with all functions and their full CFG payloads. `query_guard_dominators(node_id=...)` has a particularly broad candidate scan when no path/source bound is supplied.

**Impact:** large source files/accepted shard sets can incur needless full-payload work, memory growth and timeouts for a one-result query. No large-host OOM or timeout was attempted. Existing SQLite deadline and final response-byte envelope still apply; this finding does not claim they are absent.

**Smallest correction:** indexed selector fields and stable bounded/keyset SQL pages; find a block's function before loading full CFG data; test the number of materialized candidate functions as well as returned results.

**TODO overlap:** T-168/T-169 promise bounded query exposure; no dedicated existing entry found.

### TS-F07 — MEDIUM — Declared optional intake is unconditionally required by the load handler

**Class:** reproduced contract mismatch; high confidence.

**Evidence:** `src/appsec_review/jobs/job_tree_sitter_ast/datasets.py:67-74` leaves intake requirements at optional/gap defaults. `src/appsec_review/jobs/job_tree_sitter_ast/job.py:54-61` calls `accepted_upstream` through `_accepted_handoff` with default `required=True`, before attempting catalog processing. `src/appsec_review/runtime/consume.py:185-193` raises for absent supply.

**Trigger:** otherwise valid source/catalog work with no admitted intake pin, which the declared optional contract allows. A bounded empty-run/pin-scope reproduction fails immediately with `UpstreamIntegrityError: accepted job_review_intake handoff is required`.

**Expected vs actual:** optional/gap inputs must be gap-tolerant, or admission must declare them required/reject. The mismatch moves failure into execution. The normal enabled review graph generally supplies intake, so this is not evidence its default path always fails.

**Smallest correction:** make intake handoff and actually required intake document required/reject, consistent with the intended fingerprint authority; alternatively implement a specifically defined missing-input disposition, without inventing a snapshot.

**TODO overlap:** existing T-113 optional-reader/admission work is related, but the reviewed reader still has this mismatch. T-147 concerns metadata and does not make it harmless.

### TS-F08 — MEDIUM — Valid scope-byte configuration can generate an oversized scope and then fail generated parsing

**Class:** reproduced planning bound failure; static generated execution consequence. High confidence.

**Evidence:** `src/appsec_review/jobs/job_tree_sitter_ast/model.py:105-113` applies byte splitting only when `current` is nonempty, then appends any single file unconditionally. `_validate`, `job.py:110-119`, permits `max_file_bytes > max_source_bytes_per_scope`. `src/appsec_review/jobs/job_tree_sitter_ast/scope_execution.py:76-78` rejects oversized generated scopes, but performs no equivalent target-scope check. Generated intake can admit such a file through the worker-multiplied lane allowance (`job.py:75-79`).

**Trigger:** a file below the configured per-file limit but above the scope-byte limit. The reproduction plans 32 source bytes into a scope configured for 8 bytes. Realistic settings can make the same error with a generated 1.5 MiB file, 2 MiB/file allowance, and 1 MiB/scope.

**Expected vs actual:** either refuse the inconsistent configuration or publish a bounded exclusion disposition. Target scope exceeds its declared ceiling; generated scope raises `AST source scope exceeds configured bounds` and aborts the task rather than yielding bounded coverage.

**Smallest correction:** define oversized-single-file behavior at planning time, or enforce compatible per-file/per-scope settings. Ensure both source domains obey the same scope contract.

**TODO overlap:** no exact existing item found; related T-5016 bounded first-party processing.

### TS-F09 — MEDIUM — Actual artifact reads are missing from typed input-consumption receipts

**Class:** reproduced provenance/accounting omission; high confidence.

**Evidence:** `src/appsec_review/jobs/job_tree_sitter_ast/job.py:41-50,62-70` reads intake/catalog/partition/component/build artifacts with a private hash reader but never calls `observe_output`. Generated receipt/workspace selection likewise uses private readers (`generated_sources.py:37,94-118`; `job_language_build/job.py:142-156`). `src/appsec_review/runtime/inputs.py:528-552` is the dataset/schema/admitted-artifact observation and recording boundary that is not used here.

**Observed unit artifact:** the successful fake-parser full job test wrote:

`test/tmp/tests-custom-20261118-120112-355079-2642142/popen-gw2/test_job_runner_end_to_end_han0/runs/2026-10-10-0001/data/jobs/job_tree_sitter_ast/attempts/attempt_0001/steps/load/tasks/accepted_inputs/status.json`

Its `input_consumption` contains only two reads:

```json
{
  "schema": "appsec-review/input-reads/1",
  "citation_observation": "not_observed",
  "reads": [
    {"producer": "job_target_catalog", "output_kind": "handoff", "read": true},
    {"producer": "job_review_intake", "output_kind": "handoff", "read": true}
  ]
}
```

The excerpt projects the exact identifying fields; the actual receipt also retains hashes, attempt, target, authority, channel and coverage.

**Expected vs actual:** the datasets whose payload bytes drive parsing should have typed observed reads, not merely handoff availability/supply. Hash checks protect referenced bytes, but do not establish per-output read/schema/authority observation.

**Impact:** consumption/retrieval inventories cannot accurately explain which inputs were read, and artifact reads bypass the declared-output membership check performed by `observe_output`. This is not a claim that arbitrary target text becomes an authorized input.

**Smallest correction:** use the shared accepted-artifact reader/`observe_output` at actual intake, catalog and generated-source artifact read boundaries, with focused assertions on input receipts.

**TODO overlap:** T-113's receipt/admission repair program and T-147 are adjacent; prior reports were searched, with no duplicate Tree-sitter artifact-reader finding found.

### TS-D01 — LOW — CFG docs, API/output vocabulary, and job test mapping lag implementation

**Class:** verified documentation/test-selection drift.

**Evidence:**

- `docs/architecture/tree-sitter-ast.md:106-115` describes a `cfg.jsonl` file and edge/polarity names including `loop_exit`, `try_edge`, `finally_edge`, `auth_check`, `type_check`, `sanitizer_call`; the actual closed enums are `cfg.py:24-42` and the cfg/1 schema. Actual files are `cfg.py:1533-1535`.
- The same paragraph promises explicit `unmodeled_constructs`; this is the functional TS-F04 omission, not merely a naming difference.
- `docs/tasks/2026-11-17-t168-retire-joern-svf-universal-treesitter-cfg.md` specifies `syntax` shards and CFG `query_syntax` modes; actual shards are `analysis`, with separate `query_cfg_function`/`query_guard_dominators` (`retrieval/syntax.py:171,270`; `mcp/schema.py:234,243`).
- `tests/job-test-map.json:849-862` and generated `docs/operations/job_tree_sitter_ast.md:86` omit the existing **25-case** `test_cfg_and_guards.py`. This audit explicitly included it.
- `docs/operations/job_tree_sitter_ast.md:250` claims the disposition table is in scope identity; `model.py:116-120,151-161` does not include it. Frozen run configuration prevents the simple cross-config reuse trigger, as noted above.

**Impact/correction:** operator acceptance and map-selected checks can target the wrong output/API or miss the new CFG tests. Correct authoritative declarations/map, reconcile prose, then regenerate generated documentation. No docs or TODOs were changed in this audit.

**TODO overlap:** T-147/T-157 remain declared gaps; T-168/T-169 are marked done but their current prose is not reconciled.

## Additional observations and limits, not additional proven defects

- Raw node coordinates are copied from zero-based Tree-sitter byte points to one-based locations; byte spans are checked against re-read accepted bytes. `SourceLocation` validates ranges but not correspondence of row/column to byte offsets (`retrieval/model.py:158-185`). There is no independent point/span reconciliation or check of the parser's `node_count`, root presence or duplicate ordinal paths. Production parser output normally supplies these invariants; no false coordinate from the actual locked parser was demonstrated.
- The container parses each within-byte-bound file **before** checking the already-exhausted scope node budget (`parser.py:82-86`); those files still incur native parsing even when no nodes will be retained. Container CPU/memory/timeout boundaries remain in place; no resource stress was attempted.
- Dynamic-result aggregation reads attempt-local JSON when every expected file exists without locally revalidating scope/fingerprint metadata (`job.py:177-181`). Attempt/checkpoint custody and full runtime resume paths were not exhaustively replayed; no stale dynamic-result defect is claimed.
- Per-scope emitted JSONL is raw normalizer data; rich CFG appears only in SQLite/separate artifacts. This is compatible with the inspected prioritization reader and the explicit CFG consumer, not a missing JSONL field defect.
- The catalog now has typed unit gaps, but its published partition artifact still carries raw inventory gaps (`job_target_catalog/job.py:258-266`). Tree-sitter's path/reason exclusion reader is compatible with that artifact. A potential typed-gap regression was investigated and ruled out.
- No independent schema validator for every CFG artifact was observed in the producer writer; the focused schema tests validate representative outputs. No invalid actual writer output was produced in this audit.
- Existing immutable run configuration blocks changing source-disposition config within the same run (`runtime/runner.py:79-88`). The identical-fingerprint cross-disposition observation is not presented as a demonstrated default-path failure.

## Validation commands and outcomes

All Linux commands below used this PowerShell SSH transport, not native Windows Python:

```powershell
$script = @'
set -eu
cd /home/wsollers/projects/appsec-review
# Exact Linux body shown below.
'@
$encoded = [Convert]::ToBase64String(
  [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu `
  "printf %s $encoded | base64 -d | bash"
```

Before tests:

```bash
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
unset APPSEC_REVIEW_PROFILE APPSEC_REVIEW_OVERLAY APPSEC_REVIEW_CONFIG APPSEC_REVIEW_HOST_PINS DAGSTER_HOME APPSEC_ACCEPTANCE_ROOT APPSEC_ACCEPTANCE_RUNS_DIR APPSEC_REVIEW_TARGET PYTEST_ADDOPTS
while IFS= read -r name; do unset "$name"; done < <(compgen -v APPSEC_NATIVE_)
export PYTHONDONTWRITEBYTECODE=1
```

### V1: inspected collection

```bash
.venv/bin/python -m pytest -q --collect-only \
  --basetemp=test/tmp/job-audit-job_tree_sitter_ast-collect-20261118 \
  tests/test_000_unit_environment_guard.py \
  tests/unit/job_tree_sitter_ast/test_contract.py \
  tests/unit/job_tree_sitter_ast/test_model.py \
  tests/unit/job_tree_sitter_ast/test_normalize_and_projection.py \
  tests/unit/job_tree_sitter_ast/test_scope_execution.py \
  tests/unit/job_tree_sitter_ast/test_generated_sources.py \
  tests/unit/job_tree_sitter_ast/test_job_and_dagster.py \
  tests/unit/job_tree_sitter_ast/test_cfg_and_guards.py
```

**57 collected in 2.47 s**, exit 0. All selected test bodies and their fake parser boundaries were inspected. Unit guards refuse engines/providers/non-loopback clients and actual Dagster execution.

### V2: focused shuffled parallel units

```bash
export APPSEC_PYTHON="$PWD/.venv/bin/python"
bash scripts/run-tests.sh --strict --parallel --test-workers 4 \
  --shuffle-seed 12047 --expect-tests 57 --max-tests 57 -- \
  tests/test_000_unit_environment_guard.py \
  tests/unit/job_tree_sitter_ast/test_contract.py \
  tests/unit/job_tree_sitter_ast/test_model.py \
  tests/unit/job_tree_sitter_ast/test_normalize_and_projection.py \
  tests/unit/job_tree_sitter_ast/test_scope_execution.py \
  tests/unit/job_tree_sitter_ast/test_generated_sources.py \
  tests/unit/job_tree_sitter_ast/test_job_and_dagster.py \
  tests/unit/job_tree_sitter_ast/test_cfg_and_guards.py
```

**57 passed in 6.24 s; wrapper total 14.827778 s; 0 failed, 0 skipped, 0 over 10 s; exit 0.** Collection and execution supervision confirmed cleanup. Default collection/total ceilings were retained at 30/300 seconds. The wrapper owns its unique scratch name (`tests-custom-*`), rather than accepting a `job-audit-*` override.

Retained evidence, relative to the WSL checkout:

- Log: `test/tmp/logs/tests-custom-20261118-120112-355079-2642142.log`
- Collection: `test/tmp/tests-custom-20261118-120112-355079-2642142.collection.json`
- JUnit: `test/tmp/tests-custom-20261118-120112-355079-2642142.junit.xml`
- Timings: `test/tmp/tests-custom-20261118-120112-355079-2642142.timings.sqlite`
- Report: `test/tmp/reports/tests-custom-20261118-120112-355079-2642142.json`

### V3: control-flow reproducer

Executed with `.venv/bin/python - <<'PY'` after `export PYTHONDONTWRITEBYTECODE=1`. The complete Python body:

```python
from appsec_review.jobs.job_tree_sitter_ast.cfg import synthesize_file_cfg, MAX_CFG_NODES_PER_FUNCTION
from time import perf_counter

def n(kind, text='', field=None, children=()):
    return {'type': kind, 'text': text, 'field': field, 'children': list(children)}
def block(*children, field='body'):
    return n('statement_block',field=field,children=children)
def cfg(*stmts, language='javascript'):
    typ = 'function_item' if language == 'rust' else 'function_declaration'
    tree=n('program',children=[n(typ,children=[n('identifier','f',field='name'),block(*stmts)])])
    return synthesize_file_cfg(tree, language=language).functions[0]
def reachable(fn):
    seen=set(); stack=[fn.entry_node_id]
    while stack:
        node=stack.pop()
        if node in seen: continue
        seen.add(node)
        stack.extend(e.target_node_id for e in fn.edges if e.source_node_id == node)
    return seen

t=perf_counter()
fn=cfg(n('try_statement',children=[block(n('return_statement','return 1')),n('finally_clause',children=[block(n('expression_statement','cleanup()'))])]))
cleanup=next(x for x in fn.nodes if x.statement_text=='cleanup()')
ret=next(x for x in fn.nodes if x.kind=='return')
print('finally:', {'cleanup_reachable':cleanup.node_id in reachable(fn), 'return_goes_direct_to_exit':any(e.source_node_id==ret.node_id and e.target_node_id==fn.exit_node_id for e in fn.edges)})
fn=cfg(n('do_statement',children=[block(n('expression_statement','work()')), n('false','false',field='condition')]))
loop=next(x for x in fn.nodes if x.kind=='loop_header')
body=next(x for x in fn.nodes if x.statement_text=='work()')
print('do_while:', {'entry_targets_header':any(e.source_node_id==fn.entry_node_id and e.target_node_id==loop.node_id for e in fn.edges), 'false_edge_skips_body':any(e.source_node_id==loop.node_id and e.target_node_id==fn.exit_node_id and e.edge_kind=='false_branch' for e in fn.edges), 'body_guards':[(g.guard_expression,g.branch_arm) for g in body.guard_dominators]})
fn=cfg(n('expression_statement',children=[n('if_expression',children=[n('identifier','authorized',field='condition'),block(n('return_expression','return'),field='consequence')])]),n('expression_statement','sink()'),language='rust')
print('wrapped_rust_if:', {'guard_count':fn.guard_count,'node_kinds':[x.kind for x in fn.nodes]})
tcap=perf_counter()
fn=cfg(*(n('expression_statement',f's{i}()') for i in range(2050)))
print('cfg_bound:', {'requested_statements':2050,'retained_statements':sum(x.kind=='statement' for x in fn.nodes),'cfg_nodes':len(fn.nodes),'ceiling':MAX_CFG_NODES_PER_FUNCTION,'summary_keys':sorted(fn.to_summary()),'elapsed_s':round(perf_counter()-tcap,3)})
print('total_elapsed_s',round(perf_counter()-t,3))
```

Exit 0; **1.550 s** measured body, cap case 1.549 s. Output establishes TS-F02/03 and the cap/wrapper behavior; these are observations of defects, not new passing pytest cases.

### V4: cache/planner/input-contract reproducer

Executed with the same stdin Python command. Complete body:

```python
from pathlib import Path
from dataclasses import asdict
from types import SimpleNamespace
from time import perf_counter
from appsec_review.jobs.job_tree_sitter_ast.model import plan_scopes, scope_fingerprint
from appsec_review.jobs.job_tree_sitter_ast.normalize import NORMALIZER_SCHEMA, reusable_shard
from appsec_review.jobs.job_tree_sitter_ast.job import _load_inputs
from appsec_review.review.dispositions import SourceDispositions
from appsec_review.runtime.consume import upstream_scope
from appsec_review.jobs.job_tree_sitter_ast.datasets import CONTRACT
from tests.unit.job_tree_sitter_ast.test_model import _lock
from appsec_review.storage import atomic_json, file_sha256
import json, shutil
start=perf_counter()
root=Path('test/tmp/job-audit-job_tree_sitter_ast-repro-20261118').resolve()
root.mkdir(parents=True,exist_ok=False)
files={'files':[{'path':'lib/vendor.py','language':'Python','sha256':'a'*64,'size_bytes':32}]}
s1=plan_scopes(files,dispositions=SourceDispositions())[0]
s2=plan_scopes(files,dispositions=SourceDispositions(vendored=('lib/**',)))[0]
def fp(scope):
    return scope_fingerprint(target_snapshot='snapshot',scope=scope,grammar=_lock(),image_id='sha256:'+'b'*64,normalizer_schema=NORMALIZER_SCHEMA,limits={'max_file_bytes':100,'max_nodes':20,'max_scope_nodes':20})
print('classification_cache_collision:',{'first':s1.files[0]['disposition'],'second':s2.files[0]['disposition'],'same_scope_id':s1.scope_id==s2.scope_id,'same_fingerprint':fp(s1)==fp(s2)})
scope=plan_scopes(files,max_source_bytes_per_scope=8)[0]
print('scope_byte_bound:', {'configured':8,'planned_bytes':sum(f['size_bytes'] for f in scope.files)})
art=root/'data/treesitter/shards/test.jsonl'; index=root/'data/indices/analysis/test.sqlite'; meta=art.with_suffix('.json')
art.parent.mkdir(parents=True); index.parent.mkdir(parents=True)
art.write_bytes(b'legacy ast\n'); index.write_bytes(b'legacy index')
atomic_json(meta,{'fingerprint':'f'*64,'artifact':{'sha256':file_sha256(art)},'index_identity':{'sha256':file_sha256(index)}})
print('legacy_cache_without_cfg_accepted:',reusable_shard(meta,art,index,'f'*64) is not None)
try:
    with upstream_scope(root,'job_tree_sitter_ast',{'job_target_catalog':'a'*64},contract=CONTRACT):
        _load_inputs(root)
except ValueError as e:
    print('optional_intake_missing:',type(e).__name__,str(e))
print('elapsed_s',round(perf_counter()-start,3))
shutil.rmtree(root)
```

Exit 0; **0.015 s**. Same classification fingerprint; planned 32 bytes vs 8 bound; cache admitted no CFG metadata; missing intake raised `UpstreamIntegrityError`. The cache probe tests the cache reader only with synthetic file bytes; it is **not** a claim that a non-SQLite file survives full manifest verification. Scratch removed.

### V5: actual normalized coverage and retrieval materialization reproducer

Executed with the same stdin Python command. Complete body:

```python
from pathlib import Path
from time import perf_counter
from unittest.mock import patch
import hashlib, json, shutil, sqlite3
from appsec_review.jobs.job_tree_sitter_ast.cfg import flatten_syntax_tree
from appsec_review.jobs.job_tree_sitter_ast.normalize import normalize_scope
from appsec_review.jobs.job_tree_sitter_ast.model import GrammarLock, Scope
from appsec_review.retrieval import IndexIdentity, RetrievalCore
from appsec_review.retrieval.index import write_manifest
from appsec_review.retrieval import syntax
from appsec_review.storage import file_sha256
root=Path('test/tmp/job-audit-job_tree_sitter_ast-normalize-20261118').resolve()
root.mkdir(parents=True,exist_ok=False)
run=root/'2026-11-18-0001'
target=root/'target'; target.mkdir()
grammar=GrammarLock('JavaScript','javascript','https://example.invalid/grammar','a'*40,'MIT','javascript.so','b'*64)
def n(kind,text='',field=None,children=()):
    return {'type':kind,'text':text,'field':field,'children':list(children)}
def fn(name,statements):
    return n('function_declaration',children=[n('identifier',name,field='name'),n('statement_block',field='body',children=statements)])
def normalize(tree,label):
    nodes,data=flatten_syntax_tree(tree)
    digest=hashlib.sha256(data).hexdigest()
    scope=Scope(label,'c','.','s','.','JavaScript',({'path':label+'.js','sha256':digest,'size_bytes':len(data),'language':'JavaScript'},))
    output={'schema':'appsec-review/tree-sitter-container-output/1','scope_id':label,'language':'JavaScript','records':[{'path':label+'.js','sha256':digest,'status':'SUCCEEDED','bytes':len(data),'grammar':'javascript','nodes':nodes}]}
    art,idx,counts=normalize_scope(run_root=run,target_snapshot='s',scope=scope,grammar=grammar,fingerprint=hashlib.sha256(label.encode()).hexdigest(),container_output=output,producer={'job':'job_tree_sitter_ast'},artifact_path=run/'data/treesitter/shards'/f'{label}.jsonl',index_path=run/'data/indices/analysis'/f'{label}.sqlite',source_bytes={label+'.js':data},cfg_dir=run/'data/treesitter/cfg'/label)
    return idx, counts, output
start=perf_counter()
idx,counts,_=normalize(n('program',children=[fn('large',[n('expression_statement',f's{i}()') for i in range(2050)])]),'budget')
print('normalization_budget:',{k:counts[k] for k in ('nodes_parsed','cfg_nodes_emitted','gap_count')},'index_gaps',idx.gaps,'elapsed_s',round(perf_counter()-start,3))
with sqlite3.connect(run/idx.relative_path) as db:
    print('raw_ast_coverage',db.execute("select area,status,gap from coverage where area='budget.js'").fetchall())
start=perf_counter()
idx,counts,_=normalize(n('program',children=[fn(f'f{i}',[n('return_statement','return')]) for i in range(30)]),'page')
manifest=run/'data/indices/manifest.json'
write_manifest(manifest,run_id=run.name,target_snapshot='s',target_root=target,indexes=[idx])
core=RetrievalCore(root,run.name,manifest_path=manifest,manifest_sha256=file_sha256(manifest))
with patch.object(syntax,'_sanitize_cfg_function_record',wraps=syntax._sanitize_cfg_function_record) as spy:
    response=syntax.query_cfg_function(core,path='page.js',limit=1)
    print('cfg_limit:',{'returned':len(response['results']),'deserialized_functions':spy.call_count,'has_next':bool(response['pagination']['next_cursor'])})
print('page_repro_elapsed_s',round(perf_counter()-start,3))
shutil.rmtree(root)
```

Exit 0. Normalization **2.713 s**, pagination **0.148 s**. Genuine normalizer/IndexBuilder/manifest/RetrievalCore code ran against synthetic CST, not mocked transforms. The wrapping spy counted calls without replacing query behavior. Scratch removed.

### V6: replay frozen real-parser fixtures, no parser execution

Complete stdin Python body:

```python
from pathlib import Path
from time import perf_counter
import gzip,hashlib,json
from appsec_review.jobs.job_tree_sitter_ast.cfg import synthesize_file_cfg
start=perf_counter()
base=Path('tests/fixtures/review_prioritization')
doc=json.loads(gzip.decompress((base/'ast-golden.json.gz').read_bytes()))
print('recorded_parser',doc['schema'],doc['tool'])
for path in ('rust/src/wire.rs','rust/src/lib.rs','native/src/codec.c'):
    record=doc['files'][path]; data=(base/'target'/path).read_bytes()
    assert hashlib.sha256(data).hexdigest()==record['sha256']
    nodes=record['nodes']; byord={tuple(n['ordinal_path']):n for n in nodes}
    result=synthesize_file_cfg(nodes,data,language=record['grammar'],path=path,file_sha256=record['sha256'])
    print(path,'parsed_without_errors',not record['root_has_error'])
    for fn in result.functions:
        print('function',fn.function_name,'guards',fn.guard_count,'nodes',[(n.kind,n.start_line,n.statement_text[:55]) for n in fn.nodes])
    if path=='rust/src/wire.rs':
        for n in nodes:
            if n['type'] in {'if_expression','return_expression'}:
                parent=byord.get(tuple(n['ordinal_path'])[:-1],{})
                print('CST',n['type'],'line',n['start_point'][0]+1,'parent',parent.get('type'))
print('elapsed_s',round(perf_counter()-start,3))
```

Exit 0; **0.037 s** measured body. Golden schema `test-tree-sitter-golden/1`, tree-sitter `0.26.0`, language pack `1.12.5`; all three file byte hashes matched and all recorded roots had no parse error. `read_header`, `walk` and `load` emitted zero guards; Rust closure emitted one. Native `goto`/label nodes were ordinary statements. Only fixture text/CST was read; no target code or fixture generator executed.

One read-only Linux search probe found `rg` absent (exit 127). It was replaced by the available UNC `rg` tool and ordinary read-only Linux commands. A final status-print SSH command had a quoting error (exit 1); the quote-preserving retry passed all exact-HEAD, clean-status, `git diff --check`, and reproducer-scratch-removal checks. Neither incident was a test failure or caused validation to be skipped.

## Files read and material unverified scope

**Read fully:** authorized `AGENTS.md` and coordination skill; canonical/independent Tree-sitter operations pages and Tree-sitter architecture; all ten Python files in `jobs/job_tree_sitter_ast/` (including all 1596 lines of `cfg.py`); all seven `tests/unit/job_tree_sitter_ast/test_*.py`; cfg/1 JSON schema; parser, Dockerfile, tool manifest, verifier and image README; `retrieval/syntax.py`, `retrieval/source_resolution.py`, `config/first_party.py`, `jobs/delivery_scope.py`; root/unit test conftest and environment guard; test container/handoff/release/host-pin helpers; shell wrapper and common library; T-168 task doc; recorded-fixture generator source (read only); fixture Rust files, native codec, JS server and Java controller listed above.

**Relevant ranges/searches:** central TOML block, tool catalog registration, asset-lock identities/grammar table, registry, topology and Dagster adapter; accepted-upstream and input observation APIs; runtime unit/handoff/runner configuration and publication; storage shared path/reference/custody and index build/manifest verification; retrieval envelope/model; language-build receipt reader and artifact-index receipt validation; prioritization row reader and code-graph accepted CFG loader; declarations of ten downstream consumers; wrapper execution/report/selector logic; job-test-map exact entry; TODO T-113/T-147/T-157/T-168/T-169/T-5016 and relevant matches; prior session job reports searched for Tree-sitter/generated-source overlap; recent job history. Recorded golden archive metadata and selected three file records were read; the archive was not fully audited.

**Material unread/unexecuted scope:** actual native grammar libraries, acquisition caches and live parser image behavior; real image signing/host enforcement and resource stress; parser integration/live tests; full source-reuse repair admission/dynamic checkpoint replay; other languages' grammar-to-CFG fidelity beyond the synthetic unit cases and the selected recorded Rust/C files; every downstream job end-to-end; full indexing inventory/runtime/storage internals outside cited ranges; real target generated-build receipts, live generated mount custody, source excerpts and review findings quality. No answer keys or user target checkout content was read.

The audit stops after this job. This report is agent-reported evidence for the coordinator, not an independently repeated review or certification of live output correctness.
