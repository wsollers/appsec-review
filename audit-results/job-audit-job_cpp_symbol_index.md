# Job 25/47 — `job_cpp_symbol_index`

## Audit identity and result

- **Source:** `/home/wsollers/projects/appsec-review`, Ubuntu-22.04, branch `main`, exact clean HEAD **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**. Initial and final `git status --porcelain` were empty. Python imported `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.
- Read the complete updated shared brief, authorized checkout's `AGENTS.md`, and multi-session coordination skill. Source inspection used the authorized WSL UNC checkout; Linux commands used `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu`.
- No source/configuration/environment-file changes, installs, service operations, real compilers/indexers/providers, integration/live execution, commits, or subagents. Reproducer source text was fixture data, never compiled or executed.
- **Result:** seven new functional findings: **one high, five medium, one low**. Two additional manifestations of previously reported shared-helper defects are recorded separately, not counted as new global defects. Documentation/contract limitations are separated below.
- **Focused units:** **36 passed** (35 job tests plus one environment guard), **5.90 s pytest**, **15.970 s wrapper total**, two workers, no failures/skips/slow tests. Nine named offline reproduction scenarios were exercised, with supplementary coordinate/consumer variants. One initial reproduction batch ended in a **reproducer path-construction error**, corrected in a fresh scratch tree; it is not attributed to the product.

Full paths below are repository-relative unless explicitly marked as session artifacts. In trace tables, abbreviated Python package paths (`jobs/`, `runtime/`, `config/`, `retrieval/`, `indexing/`, `graph/`, `review/`, `orchestration/`, `container_runtime/`) are relative to `src/appsec_review/`. Bare `job.py` means `src/appsec_review/jobs/job_cpp_symbol_index/job.py`; bare `cpp_index_scopes.py` means `src/appsec_review/jobs/cpp_index_scopes.py`.

## Registration, intended inputs, and execution inventory

`runtime/registry.py:93,163` registers the factory. `appsec-review.toml:2285-2307` declares all three tasks. `job_is_enabled(load_config(), "job_cpp_symbol_index")` returned **True**. The contract uses `REVIEW_GRAPH`, `CHECKOUT`, `always_execute=False`, and `propagate_handoff=True` (`jobs/job_cpp_symbol_index/datasets.py:35-94`). Its explicit scheduling predecessor is `job_cpp_compiled_analysis`; shared topology also incorporates semantic inputs and removes redundant ancestors (`orchestration/topology.py:47-81`). The job is upstream of CodeQL and the code graph, as exercised by the contract tests. Disabled jobs are transparent to graph construction (`orchestration/dagster/adapter.py:409-411`).

Intended product: compiler-aware accepted C/C++ symbol declarations/definitions and bounded CALLS/REFERENCES neighborhoods, not vulnerability judgments or exhaustive dynamic-call resolution. This is a **whole-supported-compile-scope indexer**, not a seed-neighborhood producer.

### All declared tasks and actual handlers

| Step/task | Actual path and processing | Outcome/coverage limit |
| --- | --- | --- |
| `load.accepted_cpp` | `job_cpp_symbol_index/job.py:360-367` → `cpp_index_scopes.accepted_cpp_scopes` → accepted compiled handoff/result/manifest; checks handoff source fingerprint; records planned scope IDs and unavailable catalogs. | Hash-verified compiled/materialized-source inputs. Required missing upstream rejects. No model or seed handler. Individual catalogs must be `SUCCEEDED`, nonempty commands. |
| `index.scopes` | `job.py:369-383`: reloads scopes, compares scope-ID set, partitions supported commands, records `SKIPPED_NA` for unsupported-only scopes, maps `_index_scope` through the publication-context-preserving thread pool. | Every declared scope is runnable, skipped, or unavailable. Exceptions in a scope escape the mapped task; there is not an independent per-scope exception-to-gap barrier. F02–F07 affect normalization/configuration; K01 affects reuse. |
| ↳ scope execution/checkpoint | `job.py:303-338`: identity includes scope, normalizer, tool pin, index limits except workers, and dispositions; verifies matching checkpoint, otherwise runs `/opt/clangd/clangd_23.1.0/bin/clangd-indexer --executor=all-TUs --format=yaml /scratch/compile_commands.json`. | No extra model tasks. `cpp_index_scopes.py:220-267` writes the accepted/rebased database into private scope scratch and invokes the injected or catalog executor. Raw IO checkpoint omission: K01. |
| ↳ YAML/identity/reference normalization | `job.py:140-293`; complete `clangd_yaml.py`. Execution/TU diagnostics, strict supported YAML subset, first-party-first symbol budget, accepted declaration/definition choice, relations/counts/location cap. | F02–F05 and F07. YAML syntax errors discard the document list and yield gaps in ordinary mode; first-error safety may stop instead. Invalid/unrecognized symbol IDs are silently ignored; no claim of full semantic YAML validation. |
| `acceptance.publish_handoff` | `job.py:385-402` → `cpp_index_scopes.publish_scope_indexes:351-393`: composes current scope shards and coverage with the pinned input manifest, writes summary, sums counts, copies aggregate status/gaps. | No independent compiler-output acceptance comparison or job-specific output-schema validator. Unsupported-only summary/coverage inconsistency: K02. |

The `Unit` declarations and dependencies are exactly the three rows above (`job.py:404-412`), and `_validate` checks matching configured step/task order (`job.py:348-356`). Ordinary `UnitExecutor` records task result/status and blocks successors of actual task failures (`runtime/units.py:84-213`). The generic handoff layer validates top-level producer control fields, not arbitrary nested symbol/scope payloads (`runtime/handoff.py:196-251`; `interchange.py:521-567`). `strict_gaps=False` remains the legacy default; text reasons become canonical producer-reported gaps. This is existing debt, not new vocabulary.

### Accepted compilation/seed inputs

- **Required:** compiled-analysis `handoff`, `job-handoff/2`, producer-evidence authority, missing policy reject.
- **Optional compiled declarations:** `cpp_build_graph`, `clang_ast`, `llvm_ir`, `infer_observations`, `binary_symbols`, `cpp_blocked_branches`, `cpp_plan_and_summary`, `cpp_case_material`.
- **Optional evidence declarations:** evidence-collection handoff plus `static_tool_observations`, `static_tool_evidence`, `static_tool_io`.
- **Optional catalog declarations:** target-catalog handoff plus `target_artifact_inputs`, `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units`, `catalog_documents`.
- These are **21 input requirements / three producer identities**, not 21 demonstrated semantic reads. Actual scope loading reads the accepted compiled result's `catalog.projects.projects` and verifies its index manifest. The optional evidence/catalog datasets are not queried for symbol seeds. No seed ledger, SAST location selector, or seeded IR/AST neighborhood bounds are applied here. Even when upstream AST/IR branches are seeded, this job uses the catalog's complete supported command set.
- `runtime/consume.py:170-209` requires declared envelope permission plus the claim's admitted digest, uses the pinned historical attempt if the pointer advances, and records an envelope read. `load_accepted_cpp` (`cpp_index_scopes.py:54-80`) additionally binds result and manifest to the envelope and verifies their hashes. Direct case-file reads are hash checks, not separately instrumented dataset-read receipts.
- `_scope` (`cpp_index_scopes.py:163-188`) verifies compile-database bytes and each accepted materialized source. Scope ID hashes schema/case/source snapshot/database digest. It uses the command array embedded in the bound result; it does not independently compare that array to decoded database contents.
- Compiled catalogs are `SUCCEEDED` after successful normalization even for usable builds with provenance gaps (`job_cpp_compiled_analysis/job.py:1101-1163`). Therefore the current loader's catalog status test is not evidence that every `COMPLETED_WITH_GAPS` **build** is rejected.
- Supported extensions are `.c/.cc/.cpp/.cxx/.c++/.m/.mm/.i/.ii` (`tool_inputs.py:49,281-282`). Unsupported assembly/CUDA inputs are recorded before launch. Database rebasing preserves accepted normalized arguments, rewrites `/scratch/source` and `/scratch/build`, changes the driver to `clang`/`clang++`, and sets the mounted directory (`cpp_index_scopes.py:96-121`). Upstream normalization has already discarded some original context: see existing CPP K03 below.

## Identity, merge, bounds, and publication trace

### Symbols and relations

- Symbol identity hashes `EntityKind.SYMBOL`, case snapshot, project ID, producer `clangd`, and the 16-uppercase-hex clangd ID (`job.py:134-137,202-234`). Different accepted scopes are not globally name-deduplicated.
- URI mapping accepts `file://`, URL-decodes the path, requires an exact accepted `/target/source/...` mapping, and hashes the corresponding target file once per scope. Definition wins over canonical declaration; external-only symbols are counted, not published (`job.py:99-131,204-220`). **F03:** coordinates are not resolved into corresponding byte intervals.
- First occurrence of a clangd ID wins; repeated ID documents are not merged. First-party candidates are ranked before other dispositions, preserving input order within each class. Only first-party exclusions create the symbol-limit gap; other exclusions have explicit disposition counters (`job.py:209-245`). The shared frozen disposition table and priority are implemented (`config/first_party.py`; `review/dispositions.py`).
- References require retained source/target IDs. The call bit is 16; otherwise a relation is REFERENCES. The producer keeps occurrence counts and up to `locations_per_relation` accepted positions (`job.py:247-278`). Missing endpoints and self-references enter `unresolved_references` without a gap; **F02** concerns resolvable recursive calls, not unknown external targets. **F04** concerns losing later instances of an already admitted edge.
- `IndexBuilder` deduplicates identical entities, rejects conflicting entity contents, sorts records, and selects deterministic strongest duplicate relations (`retrieval/index.py:112-139,251-306`). It does not perform whole-program or cross-scope semantic merging. Manifest identity is `(index name, shard_id)` and duplicate shard keys reject (`index.py:364-388`).

### Settings and tool failures

Default per-job settings: workers **2**, maximum documents **2,000,000**, symbols **500,000**, relations **2,000,000**, locations/edge **8**. These five values are consumed by `_settings`; per-task workers are 1. Disposition configuration is typed, but the five index settings themselves are not validated as a closed positive-integer structure: **F06**.

The tool declaration separately fixes **600 s**, **16 MiB stdout and stderr each**, **1 GiB**, **2 CPUs**, and **256 PIDs** (`containers/tools/clangd-indexer/tool.toml:17-23`). The source Dockerfile uses the native-C++ tool image, not a bare Ubuntu image. No actual image contents or compiler/header compatibility was verified.

Timeout/OOM/nonzero/stdout truncation, missing processed-file markers, recognized missing system headers, malformed/incomplete YAML, document cap, first-party symbol cap, and relation cap generate reasons. Stderr truncation is returned by the executor but ignored by this normalizer (**F05**). Coverage is unavailable only for nonzero exit with no symbols, partial if reasons exist, otherwise complete (`job.py:280-293`). Under active first-error safety, `failed_result`/`fail` raise `ReviewStopped` instead of publishing the ordinary gap result (`runtime/execution_safety.py:335-343`); the focused job units run without that controller. No service/controller was launched for this audit.

### Declared datasets and actual files

| Dataset | Actual publication | Assessment |
| --- | --- | --- |
| `clangd_symbols` | `analysis`, `clangd-<scope_id>` SQLite; symbol entity plus CALLS/REFERENCES, scope-local coverage | Correct broad prefix ownership; semantic findings below. |
| `clangd_coverage` | `analysis`, `clangd-coverage-<attempt>` SQLite with unavailable cases or generic empty reason | More-specific prefix wins over `clangd-` via `runtime/datasets.py:107-127`. Logical dataset schema says `cpp-index-coverage/1`; physical SQLite identity correctly remains `retrieval-index/2`. K02 affects content. |
| `clangd_summary` | `data/jobs/job_cpp_symbol_index/attempts/*/steps/acceptance/tasks/publish_handoff/*.json` | Contains `cpp-symbol-index-summary.json`; wildcard also encompasses runtime task JSON. Nominal schema is not a job-specific validation gate. |
| `clangd_tool_io` | protected `data/code-index/clangd/**`: rewritten compile database, receipt, raw streams, checkpoint | Not MCP payload-readable. K01: the scope checkpoint does not verify raw streams through the receipt. |

`publish_scope_indexes` replaces only this job's prior shards, preserves all other input-manifest shards, creates a coverage shard, binds the upstream manifest, and verifies the composed manifest. It does not edit a shared accepted pointer directly. Summary item count is admitted symbols, excluding external-only symbols; counts sum accepted per-scope symbols/relations/TUs without cross-scope deduplication.

No closed `cpp-symbol-index`/`cpp-index-coverage` JSON document schema was found under `docs/schemas`; the registered job has no specific output validator. Generic control-field and index-metadata validation must not be described as semantic validation of the summary/YAML.

### Retrieval and downstream consumers

- Core `find/search` expose accepted symbol/shard identity and location; `read_excerpt` uses lines from re-hashed source, so it does **not** itself use F03's bad byte interval (`retrieval/core.py:600-775`). `trace` traverses stored exact/ambiguous relation records with query/depth/result bounds (`core.py:778-824`). Detailed coverage is available separately.
- `indexing/store.py:85-90,124-202` uses observed read-only immutable shard access and deterministic shard/entity/relation order. The source-context allowlist retains both symbol and coverage datasets (`jobs/bound_artifacts.py:100-106`).
- `indexing/links.py:347-405` joins clangd symbol point spans to Tree-sitter identifiers, otherwise marks a line-only join ambiguous. The `symbol_links` product counts incoming/outgoing CALLS and REFERENCES separately (`indexing/products.py:1373-1420`).
- Graph secondary selection excludes clangd coverage shards, restores missing accepted secondary shards from original producer handoffs, and assigns each to one maximum-file-overlap CodeQL scope (`job_code_graph_index/scopes.py:279-299,320-367`).
- Cross-checking reads CALLS only; it reconstructs UTF-16 line/column offsets against source bytes, and explicitly counts occurrence locations omitted by the per-edge bound (`graph/crosscheck.py:97-116,135-141,192-233,319-360`). This avoids relying on the producer's whole-file byte interval, but cannot recover F02/F04's erased calls.
- **Alternate CPG compatibility is broken: F01.** Its collector reads all clangd symbols and relations (`job_code_graph_index/alternate_cpg.py:2240-2270`), then synthesizes functions/calls without respecting Variable versus Function or REFERENCES versus CALLS.
- CodeQL, code graph, review-data indexing, document issue analysis, inference review, review package assembly, OWASP, and security tagging declare symbol/coverage/summary/tool-IO inputs. Their entire downstream pipelines and final report rendering were not re-audited or run.

## New functional findings

### CSI-F01 — High — Alternate CPG turns a variable reference into a function call

- **Evidence:** `src/appsec_review/jobs/job_code_graph_index/alternate_cpg.py:946-991`, especially unconditional `_register_function` at 957 and accepting `{"CALLS","REFERENCES"}` at 970 before `_add_edge(edge_kind="CALLS")` at 979. Producer distinction is correct at `job_cpp_symbol_index/job.py:259-278`.
- **Trigger / R6b:** Accepted fixture source `int global;` followed by `int main() { return global; }`. Real symbol normalizer produces `kind=Variable` for global and `main REFERENCES global`, ref-kind 4.
- **Expected:** a variable remains a variable/non-function symbol, and a non-call reference cannot establish invocation/reachability.
- **Actual:** real `synthesize_alternate_cpg` creates a **`global` function** and **`main CALLS global`**. The first R6 used the same valid record shapes against generic fixture bytes; R6b repeated it with source-consistent global-variable bytes and reproduced the same result.
- **Impact:** false semantic graph paths and downstream reachability/context, not merely a display mismatch.
- **Related static mismatch:** producer locations are a list of occurrence dictionaries; this consumer looks for `payload.line`, defaults to caller definition line, and emits one edge. Consequently actual call-site positions/occurrence multiplicity are not faithfully transferred. This secondary detail was inspected, not separately reproduced.
- **Confidence:** high for the reproduced false call; no claim of a live review finding being affected.
- **Smallest correction:** whitelist callable symbol kinds for function nodes, consume only CALLS as invocation edges, retain REFERENCES as a distinct kind, and consume the bounded occurrence locations explicitly.
- **Overlap:** **T-169** owns alternate-CPG synthesis and is marked done; **T-5016** owns graph quality. Neither records this exact defect. No matching finding in the accumulated/current relevant reports. This is a downstream compatibility finding discovered during this job audit, not a second job audit.

### CSI-F02 — Medium — Resolved recursive calls are discarded as unresolved references

- **Evidence:** `src/appsec_review/jobs/job_cpp_symbol_index/job.py:249-258`, specifically `source == target` in the rejection condition.
- **Trigger / R1:** one accepted function, with a ref-kind 28 call whose Container ID equals the target function ID.
- **Expected:** retained exact self-CALLS relation with occurrence/location metadata.
- **Actual:** zero relations, `unresolved_references=1`, **coverage complete, gaps empty**.
- **Impact:** recursion disappears from trace/neighborhood/CodeQL corroboration although both endpoints resolve. The existing handler test encodes dropping a self-reference but does not test recursive call semantics.
- **Confidence:** high, actual normalizer reproduced.
- **Smallest correction:** distinguish declaration/non-call self references from call-bit references; permit recursive CALLS.
- **Overlap:** T-023/T-5016 are related scope/quality work, not an explicit exclusion of recursion or an exact existing defect.

### CSI-F03 — Medium — Exact symbol locations carry whole-file byte spans and unchecked coordinates

- **Evidence:** `src/appsec_review/jobs/job_cpp_symbol_index/job.py:105-131`, especially `SourceLocation(..., 0, sizes[target_path], ...)` at 126-130. Contract: `docs/architecture/python-and-retrieval.md:59-70`; structural location validation `retrieval/model.py:164-202`.
- **Trigger / R3:** helper identifier at zero-based columns 4..10 in a 92-byte source.
- **Expected:** byte span `[4,10]` agreeing with line 1 / columns 5..11.
- **Actual:** `[0,92]`, while confidence is **1.0**, ambiguous **False**, and the line/column span names only the identifier.
- **R3b:** a claimed line 1000 in the same three-line file is also accepted with confidence 1.0 and complete coverage.
- **Impact:** inconsistent canonical resolving coordinates and misleading exactness; byte-oriented joins cannot trust the published span. Core line-based excerpts and cross-check offset reconstruction partly avoid this defect; do not infer those consumers read the entire file as the symbol.
- **Confidence:** high, actual `SourceLocation` construction.
- **Smallest correction:** translate clangd coordinates against the verified bytes, respecting the producer's column unit, validate line/column/end bounds, and emit an unresolved/ambiguous reason when physical mapping fails.
- **Overlap:** analogous to CSA-F03 and CPP-F02 but in a different symbol mapper; no exact TODO located. T-5016 is broadly related.

### CSI-F04 — Medium — Relation cap drops later occurrences of already admitted edges

- **Evidence:** `src/appsec_review/jobs/job_cpp_symbol_index/job.py:261-268`.
- **Trigger / R2:** relation limit 1; one Refs document contains `main -> helper`, then new `other -> helper`, then another `main -> helper`.
- **Expected:** omit the new over-budget edge but continue aggregating the already admitted edge, or explicitly mark its occurrence count incomplete.
- **Actual:** the `break` at 265 exits the whole remaining reference list. Retained `main -> helper` has **occurrences 1 instead of 2**; skipped later references are not counted unresolved.
- **Impact:** a cap intended to bound distinct relationships also silently damages metadata of retained relationships. The overall relation-limit gap does not identify this retained-count truncation, and graph cross-check's `occurrences - locations` accounting cannot see erased occurrences.
- **Confidence:** high, real normalizer.
- **Smallest correction:** skip only over-budget new keys and continue bounded aggregation; preserve explicit dropped-edge/reference counts.
- **Overlap:** T-023 covers large-scope bounds generally, not this control-flow error.

### CSI-F05 — Medium — Truncated stderr can still yield complete symbol coverage

- **Evidence:** `cpp_index_scopes.py:258-267` retains `stderr_truncated`; `job_cpp_symbol_index/job.py:152-184` checks stdout truncation but not stderr truncation; `container_runtime/executor.py:361-377` bounds/truncates the streams independently.
- **Trigger / R4:** exit 0, intact YAML, retained stderr includes every expected Processing marker, but `stderr_truncated=True`.
- **Expected:** a named incomplete-diagnostics gap; missing tail diagnostics cannot establish clean TU coverage.
- **Actual:** **complete**, no gaps. Missing-header/failure messages after the captured prefix can be absent without any indication from this producer.
- **Impact:** incomplete clangd diagnostics can be represented as complete analysis and checkpointed.
- **Confidence:** high for the flag-handling reproduction; no large-output compiler was invoked.
- **Smallest correction:** propagate a stderr-truncation gap and reconcile TU completion conservatively when required diagnostics are incomplete.
- **Overlap:** no exact existing TODO/prior symbol finding; T-023 is related output-bound work.

### CSI-F06 — Low — Index limits are accepted without positive-integer validation

- **Evidence:** `job_cpp_symbol_index/job.py:91-95,273,348-356`; `config/loader.py:1180-1183,1240-1245,1475,1497-1515`. No symbol-index-specific typed settings branch exists.
- **Trigger / R8:** in-memory configuration reader supplies `locations_per_relation=-1`, `workers="2"`; no file/environment mutation.
- **Expected:** configuration load rejects malformed/negative bounded settings.
- **Actual:** loader accepts both; job `typed_settings=None`. `_settings` coerces the worker string, while a negative locations limit makes every `len(locations) < limit` false, silently retaining no reference positions.
- **Impact:** configuration mistakes take effect as degraded output or delayed exceptions rather than actionable validation failure. Normal defaults are positive.
- **Confidence:** high, real config loader with only its file-byte boundary faked.
- **Smallest correction:** closed typed settings with meaningful positive bounds; retain the separate validated disposition table.
- **Overlap:** no exact TODO found; T-147 concerns publication/task binding, not settings validation.

### CSI-F07 — Medium — Valid filenames containing spaces are reported as omitted translation units

- **Evidence:** `src/appsec_review/jobs/job_cpp_symbol_index/job.py:43-47,166-172,182-184`; `_PROCESSED` captures `(/\S+)`.
- **Trigger / R9:** accepted `native/a b.cpp`, successful stderr line `[1/1] Processing file /target/source/a b.cpp`.
- **Expected:** one processed TU.
- **Actual:** regex captures `/target/source/a`, so summary reports **processed 0/1, omitted 1**, with a false gap. Active first-error safety invokes `fail` before ordinary gap publication.
- **Impact:** otherwise supported source paths can unnecessarily fail/stop indexing and present false coverage omissions. The same whitespace restriction exists in related diagnostic patterns.
- **Confidence:** high for parser/count behavior; real clangd invocation with a spaced path was not authorized.
- **Smallest correction:** parse whole bounded path records/known expected names instead of treating whitespace as a filename terminator, while accounting for interleaved diagnostics.
- **Overlap:** T-023 is not an exact match; no existing report/TODO found for this symbol-job path parser.

## Previously reported shared defects — new manifestation, not new global issue

| Local ID | Evidence, reproduction, and correction | Overlap |
| --- | --- | --- |
| **CSI-K01 — Medium: raw evidence omitted from scope-checkpoint verification** | `job.py:314-317,339-346` retains only receipt/database/selected execution fields; `cpp_index_scopes.py:282-292,323-341` verifies identities reachable in that result, not the raw stream hashes inside the receipt. **R5:** fake execution writes a full-shaped receipt with correct stdout/stderr hashes; after first `_index_scope`, delete its own stdout and alter stderr. Second call returns `checkpoint_reused=True`, tool calls remain 1, stdout absent and stderr hash false. Persist raw identities or verify receipt-linked streams on reuse. This is the pre-acceptance scope-cache boundary; later full accepted-handoff checks may independently reject damage. | **CSA-F04**, **SVF-F03** identify the same shared traversal limitation with different omitted producer artifacts. Record clangd as another affected call site. No exact TODO found. |
| **CSI-K02 — Low: unsupported-only scopes disappear from summary and look unavailable** | `job.py:372-383,388-399`; `cpp_index_scopes.py:375-378`. **R7:** one assembly-only scope → correct `NOT_APPLICABLE`, one `not_applicable_scopes` record, zero tool calls; accepted summary has no skipped-scope field, zero scopes/gaps; coverage says `unavailable: no accepted C/C++ project scopes`. Carry skipped identities/counts into summary and coverage, distinguishing known unsupported input from absent accepted scope. | **CSA-F07**, same helper; **T-157** applicability metadata. Do not count globally twice. |
| **CSI-K03 — upstream compile-context loss** | Accepted commands are already normalized by `job_cpp_compiled_analysis/job.py:226-261,315-350`. Original cwd and some generated include mapping/driver semantics can be lost before this job's rebasing. No compiler replay was run here. | Prior compiled audit **CPP K03 / C08-F03**. Native-header/image compatibility remains unverified, not a new claim that every C++ scope fails. |

Partial symbol results are intentionally checkpointable per the current job documentation. This audit does **not** call every partial-result reuse a new defect merely because the input did not change.

## Documentation and unproven limitations

- `docs/architecture/code-intelligence.md:50-53` attributes `_USABLE_BUILD_STATUSES` and acceptance of partial **catalogs** to this job. That symbol belongs to compiled-analysis build handling; `cpp_index_scopes.py:196` requires catalog `SUCCEEDED`. The upstream catalog normally converts usable partial builds to successful catalogs, so this is attribution/terminology drift, not a reproduced rejection of current usable partial builds.
- `containers/tools/clangd-indexer/README.md` still describes a base-Ubuntu runtime stage; current Dockerfile's second stage is `tool-native-cpp`. `containers/tools/clangd-indexer/tool.toml:28` still calls normalization/integration pending. Task binding omissions remain **T-147**.
- Unknown symbol/document shapes can be skipped without a semantic-schema gap; duplicate clangd IDs retain the first occurrence rather than merge declaration/definition. Actual release behavior for these cases was not independently established, so no additional live incompatibility is asserted.
- Expected/processed sets collapse duplicate file paths, not distinct compile-command configurations. Whether the real all-TUs executor supplies complete per-configuration evidence was not verified.
- No complete recorded clangd Refs stream was inspected from an authorized live run. The existing helper fixture models `Container: {ID: ...}`. This audit does not certify every native clangd YAML variant, URI encoding, Unicode column, macro, virtual dispatch, clang-cl, system-header, or multi-configuration case.
- Bound selection within one disposition follows input order; real clangd output ordering and Unreal-scale behavior remain unverified. **T-023** explicitly retains TU batching, external/header-only cross-scope treatment, Windows SDK inputs, and large-scope resource work.

## Validation record

All Linux snippets used:

```powershell
$encoded = [Convert]::ToBase64String(
  [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Each script starts `set -eu` and `cd /home/wsollers/projects/appsec-review`. Initial source verification:

```bash
git rev-parse HEAD
git status --porcelain
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
```

An early inventory command attempted `rg` over SSH and exited **127** (`rg: command not found`) before its remaining inventory commands. No tests ran in that invocation and nothing was installed. Subsequent searches used authorized UNC tools or Python.

### Exact focused test command

```bash
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
.venv/bin/python -c 'from tests.test_000_unit_environment_guard import offending_environment; import os; x=offending_environment(os.environ); print("unit environment:", x); assert not x'
bash scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 25047 \
  --max-tests 36 --expect-tests 36 --timeout-seconds 180 --strict -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_cpp_symbol_index/test_contract.py \
  tests/unit/job_cpp_symbol_index/test_clangd_yaml.py \
  tests/unit/job_cpp_symbol_index/test_handlers.py \
  tests/unit/job_cpp_symbol_index/test_symbol_budget.py
```

Fixture safety inspected before execution: the four selected files use fake executor objects, in-memory parsing, scratch source/index files, and a monkeypatch that replaces the default executor branch before it can launch. The root and unit-tier conftests were read; guards block real engines/network/Dagster and use private scratch. YAML/stderr fixtures are read as inert bytes. Fixture contents were also subsequently read in full.

Wrapper invocation **`tests-custom-20261118-124925-993933-3031061`**:

- Exact selection count **36** (35 job cases + 1 guard), verified before execution and by both workers; guard environment `[]`.
- Collection command was the following execution command with `-n 2` removed and `--collect-only` appended. Wrapper collection and execution sequentially used its fresh private directory, never shared with another auditor.

```bash
/home/wsollers/projects/appsec-review/.venv/bin/python -m pytest \
  -p ops_test_guard -c /home/wsollers/projects/appsec-review/pyproject.toml \
  --rootdir=/home/wsollers/projects/appsec-review -o addopts= -q -rfE \
  --basetemp=test/tmp/tests-custom-20261118-124925-993933-3031061 \
  --junitxml=test/tmp/tests-custom-20261118-124925-993933-3031061.junit.xml \
  -o junit_family=legacy -n 2 --shuffle-seed=25047 \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_cpp_symbol_index/test_contract.py \
  tests/unit/job_cpp_symbol_index/test_clangd_yaml.py \
  tests/unit/job_cpp_symbol_index/test_handlers.py \
  tests/unit/job_cpp_symbol_index/test_symbol_budget.py
```

- **36 passed**, pytest **5.90 s**, no failures/errors/skips, **0 cases over 10 s**.
- Wrapper collection **4.953506 s**, supervised execution **10.671052 s**, total **15.969763 s**. Both stages completed; process cleanup confirmed.
- Retained audit evidence:
  - `test/tmp/logs/tests-custom-20261118-124925-993933-3031061.log`
  - `test/tmp/logs/tests-custom-20261118-124925-993933-3031061.collection.log`
  - `test/tmp/tests-custom-20261118-124925-993933-3031061.collection.json`
  - `test/tmp/tests-custom-20261118-124925-993933-3031061.junit.xml`
  - `test/tmp/tests-custom-20261118-124925-993933-3031061.timings.sqlite`
  - `test/tmp/reports/tests-custom-20261118-124925-993933-3031061.json`

### Offline reproduction invocations

These were **three `.venv/bin/python - <<'PY' ... PY` stdin commands**, not additional pytest collections. They imported `_make_scope_and_unit` / `FakeClangdExecutor` from the inspected job test file, called actual normalizer/scope/publisher/consumer functions, and changed only their own fixture trees or in-memory function boundaries. They used zero test workers/real tool processes. The script timers below start after imports.

| Invocation and private scratch | Executed checks / result | Timing / exit |
| --- | --- | --- |
| A: `test/tmp/job-audit-cpp-symbol25-repro-ec1d4dba9853498cb6c787749848e613` | R1 recursive call erased; R2 cap retains occurrences 1 not 2; R3 bytes `[0,92]` not `[4,10]`; R3b line 1000 accepted; R4 stderr truncation ignored; R5 raw-damaged checkpoint reused; R6 reference promoted to call. All assertions passed. Then R7's **reproducer** used a relative `run_root` against a resolved absolute manifest and raised `ValueError: ... is not in the subpath of ...`; R8 was not reached. | **0.800040 s**, exit **1**, finally removed only its own scratch. |
| B: `test/tmp/job-audit-cpp-symbol25-repro-b-2e56624a6ac54b44a5b3d37af8548958` | Corrected base with `.resolve()`: R7 unsupported-only `NOT_APPLICABLE` plus unavailable generic coverage; R8 negative/string settings accepted; R6b source-consistent variable reference again became a function/call. All assertions passed. | **0.801498 s**, exit **0**, own scratch removed. |
| C: unique `test/tmp/job-audit-cpp-symbol25-repro-c-<uuid>` | R9 accepted spaced filename marked omitted; default enabled probe True. All assertions passed. | **0.942357 s**, exit **0**, own scratch removed. The generated UUID was not printed. |

Smallest reproductions, using the inspected helper (compacted equivalents of the executed bodies, not a claim of another execution):

```python
# Run through .venv/bin/python on stdin from the authorized checkout.
# Use a fresh test/tmp/<unique-name> base for EACH invocation and remove only that base.
from pathlib import Path
from dataclasses import asdict
from tests.unit.job_cpp_symbol_index.test_handlers import _make_scope_and_unit
from appsec_review.jobs.job_cpp_symbol_index.job import normalize_scope
from appsec_review.retrieval import IndexBuilder

base = Path("test/tmp/<unique-name>").resolve()
run, target, scope, unit = _make_scope_and_unit(
    base, sources={"native/a.cpp": (
        "int helper() { return 1; }\n"
        "int main() { return helper(); }\n"
        "int other() { return helper(); }\n")})
limits = dict(max_documents_per_scope=100, max_symbols_per_scope=100,
              max_relations_per_scope=100, locations_per_relation=8)
raw = run / "raw"
raw.mkdir()
(raw / "stderr").write_text("[1/1] Processing file /target/source/a.cpp\n")
execution = dict(timed_out=False, oom_killed=False, exit_code=0,
                 stdout_truncated=False, stdout_path="raw/stdout",
                 stderr_path="raw/stderr")
builder = IndexBuilder(run / "shard.sqlite", name="analysis",
                       fingerprint="f"*64, target_snapshot=unit.job.source_fingerprint,
                       shard_id="clangd-fixture")
```

Feed `raw/stdout` supported YAML documents:

- **R1:** `Symbol ID=1111111111111111`, accepted Definition; `Refs ID=1111111111111111`, one `Kind=28`, same Container ID, accepted Location. Call `normalize_scope`; inspect zero edges, unresolved 1, complete.
- **R2:** three accepted symbol IDs; one Refs document to helper containing main, other, main call containers; set `max_relations_per_scope=1`. Inspect retained edge occurrences 1.
- **R3/R3b:** accepted Definition Start `{Line:0,Column:4}`, End `{Line:0,Column:10}`; then another fresh fixture with both Lines 999. Inspect `asdict(builder.entities[0].location)`.
- **R4:** valid symbol YAML plus `execution["stderr_truncated"]=True`; no other failure flags. Inspect complete/no gaps.
- **R5:** call `_index_scope(unit, scope, lambda _: fake)`; fake subclasses the existing fake executor and writes `asdict(ExecutionResult)` plus actual raw stream hashes into the receipt. Delete its raw stdout and overwrite its stderr, call `_index_scope` again; assert reused and only one fake invocation.
- **R6b:** use source `int global;\nint main() { return global; }\n`. YAML publishes `global` kind Variable, `main` kind Function, and ref-kind 4 from main to global. Pass normalized entities as `{identity,kind,name,payload,location=asdict(...)}` and relations as `{kind,source_id,target_id,payload}` to `synthesize_alternate_cpg`. Inspect a global function and CALLS edge.
- **R7:** replace only the fixture scope's command array with `native/boot.S`; use a real empty upstream manifest and bind it as `unit.job.input_manifest_path`/sha; fake `accepted_cpp_scopes` to return it; invoke the three real task handlers. Read summary and coverage SQLite.
- **R8:** patch `Path.read_bytes` only for the real config path to return an in-memory string changing this job's `locations_per_relation` to `-1` and settings workers to `"2"`; call `load_config`. Original file bytes are never written.
- **R9:** fresh fixture source `native/a b.cpp`, empty YAML, stderr `[1/1] Processing file /target/source/a b.cpp\n`; normalize; inspect processed 0, omitted 1.

Final verification command returned the same exact revision and no changes:

```bash
git rev-parse HEAD
git status --porcelain
git diff --stat
```

## Read scope and remaining gaps

**Read fully:** shared brief; authorized AGENTS; coordination skill; job operations page; all four files in `src/appsec_review/jobs/job_cpp_symbol_index/`; `jobs/cpp_index_scopes.py`; all four job unit-test files; both `tests/fixtures/cpp_symbol_index/` YAML/stderr fixtures; integration test file **as text only**; `tests/conftest.py`, `tests/unit/conftest.py`, environment guard; `config/first_party.py`, `review/dispositions.py`; `runtime/consume.py`; `runtime/units.py`; `retrieval/model.py`; `docs/architecture/job-input-contracts.md`, `docs/architecture/python-and-retrieval.md`; tool README/Dockerfile/tool.toml; wrapper shell entry/common shell helper. Relevant TODO entries T-023, T-147, T-5016, T-169 and relevant prior CPP/Clang/SVF report sections were read.

**Read selectively / traced relevant portions:** central TOML and test map; config loader; tool input support; registry/topology/Dagster adapter; container executor; safety and publication-thread context; runtime datasets/handoff/interchange; retrieval builder/manifest/core; source-view declarations; indexing store/links/products/matrix; graph secondary scope restoration/assignment and cross-check; alternate-CPG collector, function registration and clangd symbol/relation ingestion; compiled producer normalization/catalog preparation; wrapper Python collection/execution supervision; cumulative report.

**Material unread/unverified scope:** complete runtime runner/storage admission internals, complete downstream jobs/alternate-CPG synthesis beyond the relevant ingestion path, MCP authorization/session lifecycle, all generic retrieval edge cases, full schema collection, unrelated TODOs, all historical reports, native clangd/LLVM source/binary internals, actual image inventories/header compatibility, real target/run outputs, and full publication/claim/admission-to-retrieval end-to-end behavior. No real clangd/Clang, Docker, CodeQL, provider, integration, acceptance, live or Dagster execution occurred. Passing focused units does not establish native index quality or complete review correctness.

The individual report is the only persistent document created by this auditor. Wrapper reports/logs remain in their private `test/tmp` namespace; custom reproduction trees were removed. No work continues beyond this job.
