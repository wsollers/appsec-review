# Job 20/47 — `job_cpp_compiled_analysis`

## Scope and verdict

- Audited **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, branch `main`, in `/home/wsollers/projects/appsec-review` on `wsl-ubuntu` / Ubuntu-22.04. HEAD and clean Git status were verified before collection, before execution, and after reproduction. Editable import resolved to this checkout's `src/appsec_review/__init__.py`.
- Read-only functional audit. No source/environment edits, installs, services, real builds/compilers/scanners/providers, integration/live/acceptance runs, subagents, commits or pushes. Native-driver symbol reproduction used an in-process fake `subprocess.run`; replay tests used fixture playback or the existing tests' fake Python compiler.
- **71 focused unit tests passed in 4.54 s**, two workers, shuffled. Wrapper total 10.860 s. No test failures, skips, or tests exceeding 10 s. Passing tests do **not** establish exact correctness.
- **Eight functional findings below: three high, five medium**, plus one low schema/declaration mismatch. Several older defects were separately reconfirmed and must not be counted as new.
- Synthetic reproductions use actual normalizers, handlers, parsers and SQLite builders. They are not demonstrations of live compiler quality or the fully admitted runtime. Error-to-gap/caching reproductions use ordinary unit-mode execution: an active `first-error-no-retry` safety controller can instead stop at the earlier `safety.fail` call.

## Registration, configuration, input and output contracts

Registered by `src/appsec_review/runtime/registry.py:89,159`, enabled in the central recipe, review-graph dispatch, checkout target access, `always_execute=False`, propagating handoff. `datasets.py:47-110` declares the job contract. Scheduling parents are `job_language_build` and `job_evidence_collection`; graph ancestry is projected from the contract, not a separate authority grant (`orchestration/topology.py:46-81`).

All **nine declared steps/tasks** have handlers. No model worker, runtime prompt or runtime skill is invoked by this job. Generated “undeclared tool” cells are T-147 metadata debt, not evidence of missing dispatch.

`appsec-review.toml:1707-1761` sets job workers 8 and every task's step workers 1. The actual units batch projects sequentially. This audit's test-worker limit was separately 2. Typed lane must be `cpp` (`config/loader.py:461-467,1427-1428`). Mode/depth/seed limit are copied from CodeQL's export settings; this job's `function_limit=400`, `unit_limit=64`, `block_limit=2000`, and `include_scan_files=4000` are validated/folded by `config/seeding.py` and `config/loader.py:1525-1536`. No separate per-branch enable switch is read.

External declarations inspected: `containers/tools/native-cpp/tool.toml` and `containers/tools/infer/tool.toml`: pinned catalog tool identities, linux/amd64, network none, read-only root/target, writable scratch, 1 GiB, 2 CPUs, 256 PIDs, 600 s, 16 MiB captured output. Native replay has an additional 180 s subprocess timeout per invocation; Infer explicitly requests two jobs. Actual image contents and enforcement were not tested.

### Accepted inputs and actual use

The 22 declared input rows cover:

| Producer | Declared datasets | Actual path inspected |
| --- | --- | --- |
| `job_language_build` | Required/reject `handoff`; optional/gap `topology_refinement_inputs`, `build_actions`, `jvm_build_actions`, `language_build_receipts`, `build_workspaces` | `load_accepted_language_build` reads accepted envelope and receipt-set artifact; job requires matching snapshot. Native receipts, or successful mixed-family receipts with captured native rows, become actions. Preparation checks workspace manifest file-set/hash equality and bound artifacts; copies source/build trees and verifies captured native DB identity. **The accepted `link_database` is not consumed: K01.** |
| `job_evidence_collection` | `handoff`, `static_tool_observations`, `static_tool_evidence`, `static_tool_io` | Seed plan uses hash-verified observations in the attempt's input manifest. Seeded producers' own observations are excluded. The job does not separately parse raw static evidence/IO. |
| `job_target_analysis_plan` | `handoff`, `planning_feedback_cache`, `analysis_plan`, `analysis_plan_documents` | No direct planning-doc/feedback loader in this job. Manifest context may be inherited; language-build receipts, not a new build plan, drive projects. |
| `job_target_catalog` | `handoff`, `target_artifact_inputs`, `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units`, `catalog_documents` | No direct catalog-document parse. Seed ownership comes from prepared accepted-file mappings, not target-authored instructions. |

`runtime/consume.py:174-214` supplies typed contract/pin validation from the active runtime scope; omission of a `contract=` argument in the job's loader is **not** proof of bypass. Outside a runtime scope the same API is an operator lookup. The focused fixtures take that latter path. Full runtime per-artifact read-receipt accounting was not exercised.

### Every declared task/step

Paths in this table are relative to `src/appsec_review/jobs/job_cpp_compiled_analysis/`.

| Step/task | Actual implementation and processing | Result / limitation |
| --- | --- | --- |
| `plan.accepted_cpp_plan` | `job.py:982-1005`, `native_analysis_actions:885-928`; accepted snapshot, native/mixed captured builds, safe roots, native-source scan, unique keys, stable sort, plan JSON | Empty plan is `NOT_APPLICABLE`; missing required capture on materialized native receipt raises. D01 plan schema mismatch. Header/generated-only selection not independently simulated. |
| `prepare.projects` | `job.py:1007-1098`; recreate case root, retain unbuilt blocked projects, verify workspace/artifacts/captured DB, copy source and recipe build directory, source mapping | K02 drops valid nested source directories; K03 loses build/include path semantics. Re-running prepare destroys local branch checkpoints by design. |
| `catalog.projects` | `job.py:1101-1163`; block unusable build, release-keyed checkpoint, normalize compile DB, classify artifacts, normalize links | K01 accepted links lost. Normalizer rejects malformed/empty/>4096 DB or >16 MiB, skips `-cc1`; output matching assumes `build`, not arbitrary recipe build layout. |
| `compiled.projects` | `job.py:1166-1256` → `_build_entities:442-522`; project/action/source/TU/artifact entities and exact compile/link edges | F08 drops branch gap from terminal result despite partial coverage. No tool execution. |
| `ir.projects` | Same dispatcher; whole-program `_ir_index:650-718`; seeded `seeded.ir_result:213-419`; select units, replay, parse debug IR, bounded name-based neighborhood, source CFG replay, ledger/handoff | F01 overload misbinding; F03 failed CFG reuse; F04 seed header selection; F05 CFG corruption after bound; F06 unusable receipts in full mode. K04 full-mode flow loss. |
| `ast.projects` | Same dispatcher; depends on catalog **and IR**; seeded `ast_result:422-517` selects IR neighborhood TUs/names; full mode clears stale seeded replay; `_add_ast_entities:598-643` | F02 wrong exact source locations; F03 false-resolved parse failures/reuse; F06 missing receipts; K05 lossy full-mode filter. Traversal is capped at 20,000 visited nodes, without a distinct truncation gap. |
| `infer.projects` | `_run_infer:155-186`, `_infer_index:732-823`; accepted normalized DB rebased into read-only case mount; clean scratch; bounded report, exit/timeout/OOM/log capture counts, accepted path/hash mapping, diagnostics/traces | Fake-boundary tests cover report/path/count failures and changed source. Actual Infer output/version/capture grammar not verified. Trace entries retain line/column/description, not cross-file trace identity. |
| `binary.projects` | `_run_tool` → native driver `symbols:196-214` → `_binary_index:826-873`; inspect retained build artifacts, bounded symbol rows, containment | F07 subcommand errors disappear. Silent record/symbol cuts can still be `complete`; malformed JSON handled, but arbitrary JSON shapes not robustly validated. |
| `acceptance.publish_handoff` | `job.py:1259-1300`; retain unrelated inherited shards, replace prior own shards, verify composed manifest, deduplicate branch gaps, summary/dispositions | F08 discrepancy reaches summary; D01 artifact declaration overclaims schema. Physical shard/item counts intentionally include inherited shards. Empty actions' final publisher is `SUCCEEDED`, while preceding units are `NOT_APPLICABLE`; no claim that this alone is a defect. |

### Artifacts, schema and downstream seams

Programmatic `shard_owner` checks found exactly one declared owner for every produced branch shape, including blocked shapes:

| Output | Actual shape / declared owner |
| --- | --- |
| compiled build graph | `build`, `cpp-<case>-compiled` → `cpp_build_graph` |
| AST | `analysis`, `cpp-<case>-ast` → `clang_ast` |
| IR | `analysis`, `cpp-<case>-ir` → `llvm_ir` |
| Infer | `observations`, `cpp-<case>-infer` → `infer_observations` |
| binary symbols | `compiled`, `cpp-<case>-binary` → `binary_symbols` |
| build-blocked compiled/Infer/binary | `analysis`, corresponding suffix → `cpp_blocked_branches` |
| build-blocked AST/IR | Their regular `clang_ast`/`llvm_ir` declarations also own coverage-only shards |
| case material | `data/cpp/projects/**` protected: mapping, accepted copies, databases/catalogs, AST/IR/CFG/binary/Infer outputs, ledgers and checkpoints |
| plan/summary/task JSON | `_A/steps/*/tasks/*/*.json`, artifact-only `cpp_plan_and_summary`; includes multiple schemas/shapes, not just the closed summary schema: D01 |

Shards use retrieval-index/2, own producer `job` metadata, content fingerprints, immutable-style manifest identities and accepted snapshot references. `_new_builder` uses parser/normalizer/mapping identity strings; hardcoded compiler labels are not measured compiler identities. `cpp-source-mapping/3` and seeded ledger/handoff are internal case material rather than independently declared external datasets.

Downstream scope loader `jobs/cpp_index_scopes.py:54-205` requires accepted C++ handoff/result/manifest, successful nonempty catalogs, verifies compiled DB and mapped source bytes, then rebases commands for later native tools. This carries K01–K03 into clangd, Clang static, CPG and SVF consumers. SVF `planning.py:68-123` groups modules from captured output/link relationships. Graph producer `_flow_rows` (`job_code_graph_index/producers.py:103-129`) selects IR rows carrying `flow`; full-mode rows lack it. Graph cross-check consumes IR CALLS and AST references (`graph/crosscheck.py:459-584` sampled), making F01/F02 consequential rather than cosmetic. Numerous review/indexing consumers declare these datasets; they were not individually re-audited.

## New functional findings

### CPP-F01 — High — Seeded IR joins distinct C++ overloads and emits the wrong exact call

- **Evidence:** `src/appsec_review/jobs/job_cpp_compiled_analysis/seeded.py:292-295,343-364,384-403`; IR retains `callee_linkage` in `llvm_ir.py:48-53,399-410`, but the join discards it.
- **Trigger/repro R7:** One TU defines `_Z1fi(int)` and `_Z1fd(double)`, both debug-named `f`; `copy_field` directly calls `_Z1fi`. Actual parser and seeded handler emit `copy_field -> _Z1fd`, `exact=1`. No real compiler was used.
- **Expected:** join by TU plus linkage identity, preserving distinct overloads. **Actual:** neighborhood is keyed by display name, local entity map uses `setdefault("<position>:f", ...)`, and the first sorted linkage wins. The first attempted synthetic call happened to target that first member and therefore did not exhibit the defect; the non-first-member call reproduced it.
- **Impact:** wrong compiler-backed graph edge, merged neighborhoods/ranges, misleading cross-check and flow context. A name count can also understate distinct definitions.
- **Confidence:** high, reproduced in SQLite.
- **Smallest correction:** retain linkage/TU identity through walk/seed/handoff/edge joins; use display name only for presentation, or mark ambiguous and do not emit an exact edge.
- **Overlap:** adjacent to historical C07-F01 and C08-F14 (downstream name matching), but this is a distinct **producer-side** defect. T-016/T-5016 cover neighborhood/quality work broadly, not this exact bug.

### CPP-F02 — High — AST nodes get incorrect source files/lines with exact confidence

- **Evidence:** `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:402-410,623-641`.
- **Trigger/repro R6:** AST declaration `loc.file="/scratch/source/include/util.h", line=5`, compiled through `proj/src/util.cpp`; a `CallExpr` has `range.begin.line=14` and no `loc`. Published locations are respectively `proj/src/util.cpp:5` and `proj/src/util.cpp:1`, both `mapping_method="exact-path"`, confidence `1.0`.
- **Expected:** resolve actual Clang file/range/spelling/expansion/offset information against accepted mapping; qualify unresolved locations.
- **Actual:** only `loc.line/col` are read, path is always the main TU, absence becomes line 1, and `_location` hashes that wrong file. Real expression JSON commonly carries `range` rather than `loc`.
- **Impact:** incorrect evidence citations, header provenance, location-based querying and corroboration.
- **Confidence:** high, reproduced with actual entity construction.
- **Smallest correction:** map Clang locations through accepted source records, calculate elided lines from offsets/ranges, and retain ambiguity instead of fabricating exact line 1.
- **Overlap:** C07-F01 covers downstream caller-blind matching; C08-F05 covers full-mode **IR** locations. Neither is this AST producer mapping. T-5016 is related quality work.

### CPP-F03 — High — Seeded parse failures are marked resolved and cached; CFG failures are cached too

- **Evidence:** `src/appsec_review/jobs/job_cpp_compiled_analysis/seeded.py:479-517` builds seed resolution before AST parsing and sets `checkpointable=not failures`; `job.py:608-615` adds parse gaps without updating failures; `seeded.py:306-312,416` ignores CFG failures when deciding IR checkpointability. `job.py:109-130` explicitly accepts checkpointable partial results.
- **Trigger/repro R10:** Fake compiler reports success for both selected TUs but returns malformed AST JSON. Actual output: **0 AST entities, 2 resolved seeds, checkpointable=True**. Same-seed retry uses checkpoint and makes **zero** replay calls.
- **Related repro R9:** `cfg/util` fails while IR succeeds. IR result is checkpointable; retry with a healthy fake executor again makes **zero** calls and reuses the failed-CFG result.
- **Expected:** failed/unparsed unit's seeds remain unresolved with a producer failure reason, and a retry can recover missing output. Architectural contract explicitly says a failure is not checkpointed (`docs/architecture/seeded-neighborhoods.md:101-107`).
- **Impact:** false resolution accounting and permanent transient loss under otherwise unchanged releases/settings until case recreation/invalidation.
- **Confidence:** high, reproduced including second execution.
- **Smallest correction:** make parse/CFG outcomes explicit per unit; finalize ledger after parsing; disallow failure-derived checkpoints (or cache successful subparts while retrying failed parts).
- **Overlap:** T-016 is broad; no exact matching TODO/prior finding located. Intended bounded/incomplete neighborhoods must remain reusable; failure is different from intentional scope limitation.

### CPP-F04 — Medium — Header seeds through `-isystem`, `-iquote`, `-idirafter` are never selected

- **Evidence:** `src/appsec_review/seeding/units.py:44-58`, especially unconditional `break` at line 57; caller `job_cpp_compiled_analysis/seeded.py:74-79`.
- **Trigger/repro R5:** Main `a.cpp` includes `h.h`, only resolvable at `inc/h.h`, and seed is `inc/h.h:1`. `-I /scratch/source/inc` selects TU 0; changing only flag to any of the other three returns no include dirs and no selected units.
- **Expected:** all four explicitly supported include flag forms participate. **Actual:** loop exits after testing `-I`, even without a match. Relative `-I` forms also require proper working-directory resolution.
- **Impact:** real header findings receive false no-translation-unit gaps; corresponding IR/AST neighborhoods never execute.
- **Confidence:** high, reproduced with in-memory source reader.
- **Smallest correction:** break only after matching a flag, recognize paired/joined supported forms and resolve accepted relative include paths consistently.
- **Overlap:** C11-F08 concerns priority truncation and unbudgeted include probes, not this flag-dispatch defect. T-016 is broadly related.

### CPP-F05 — Medium — IR block detail limit also erases CFG edges

- **Evidence:** `src/appsec_review/jobs/job_cpp_compiled_analysis/llvm_ir.py:374-377` continues before terminator parsing at `390-397`, then computes successors/dominators/post-dominators at `413-426`.
- **Trigger/repro R8:** Three-block chain `entry -> next -> done`. Full parse retains both edges. `block_limit=1` retains three block records but changes `next.successors` from `("bb2",)` to `()`.
- **Expected:** drop instruction detail beyond the bound while preserving graph structure, as explicitly promised by `docs/architecture/seeded-neighborhoods.md:72-78` and the existing test's comment.
- **Actual/impact:** truncated blocks become false exits, invalidating published graph/dominance structure. The truncation marker does not make the retained edges accurate.
- **Confidence:** high, pure-function reproduction.
- **Smallest correction:** parse structural terminators/successor labels beyond the detail limit; bound only detail collection, or publish an explicitly incomplete graph without derived dominance assertions.
- **Overlap:** T-016 broad bounds work; no exact previous finding located. Existing `test_block_limit_truncates_with_a_named_marker_never_silently` checks missing lines but not preserved edges.

### CPP-F06 — Medium — Whole-program AST/IR accepts an unusable replay receipt as clean

- **Evidence:** `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:1225-1249`; `replay_failures:364-381` returns `None`, but full-mode dispatch still calls `_ast_index`/`_ir_index`; both coerce `None` to `{}`. Seeded equivalents explicitly reject missing outcomes at `seeded.py:254-256,473-475`.
- **Trigger/repro R11:** One real recorded AST TU, fake execution exit 0, missing `receipt.json`. Full-mode branch returns **SUCCEEDED, gaps=[], 31 entities**.
- **Expected:** unavailable/partial outcome naming receipt loss, never proof all commands succeeded.
- **Impact:** incomplete or unidentified replay can appear complete and be checkpointed. A first-error controller may stop earlier; this is still a defect in the ordinary gap-producing path.
- **Confidence:** high, actual handler reproduction.
- **Smallest correction:** treat `failures is None` as a branch gap in full mode, matching seeded behavior; do not checkpoint it.
- **Overlap:** no exact TODO/prior match; adjacent to K04's separate full-mode parsing limitation.

### CPP-F07 — Medium — Binary tool failures become successful empty symbol coverage

- **Evidence:** `containers/tools/native-cpp/native.py:207-214` ignores both subcommand return codes/stderr and returns 0; `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:826-873` marks coverage complete when JSON parses.
- **Trigger/repro R12:** Synthetic `broken.o`; fake `nm` and `readelf` both exit 1 with “file format not recognized”. Real driver produces records and exits **0**; real normalizer yields **SUCCEEDED, gaps=[], symbols=0**.
- **Expected:** preserve per-artifact tool status and named failed/incomplete inspection coverage.
- **Impact:** unsupported/corrupt artifacts or scanner failures masquerade as successful inspection. Container-level exit checking cannot detect swallowed internal failures.
- **Confidence:** high, subprocess boundary fake; neither utility was executed.
- **Smallest correction:** include subcommand receipts/exit/status in records, retain bounded stderr, propagate partial failure and reject complete coverage for failed inspection.
- **Overlap:** no exact match found; operations docs already warn separately about silent output slices, which are not the reproduced failure.

### CPP-F08 — Medium — Compiled branch records partial coverage but publishes no gap and success

- **Evidence:** `src/appsec_review/jobs/job_cpp_compiled_analysis/job.py:520-522,431-439,1271-1299`.
- **Trigger/repro R13:** Valid compile/source catalog with no resolving compile-output/link relationships. SQLite records `partial`, reason “no exact compile-output or captured link relation was available”; branch returns **SUCCEEDED, gaps=[]**.
- **Expected:** branch/result/summary explicitly preserve this coverage loss.
- **Actual/impact:** publisher reads result gaps/status rather than shard coverage, so its gap list/disposition can conceal unavailable provenance even though detailed SQLite coverage correctly names it.
- **Confidence:** high, actual builder/SQLite reproduction; not a claim that every full job's other branches are gap-free.
- **Smallest correction:** propagate the coverage reason to `_finish_index` and aggregate it; consider per-command missing relationship accounting rather than treating one resolving edge as complete for a project.
- **Overlap:** already acknowledged narratively in `docs/operations/job_cpp_compiled_analysis.md` Process/compiled and Gaps, but not found as a separately registered TODO/finding. Do not mistake documentation of the limitation for a fix.

## Contract/documentation mismatch

### CPP-D01 — Low — Declared plan/summary schema does not validate the plan

- **Evidence:** `src/appsec_review/jobs/job_cpp_compiled_analysis/datasets.py:38-42`, `job.py:995-1005`; `docs/schemas/cpp-compiled-analysis.schema.json:6-8`.
- **Repro R4:** Validate actual `accepted-cpp-plan.json` from the real plan handler against its own declared schema: five validation errors. Missing `branch_count`, `physical_shard_count`, `gaps`, `dispositions`; unexpected `actions`, `lane`, `source_fingerprint`, `topology`.
- The wildcard additionally labels task result/status and container-execution JSON as that same summary schema. Final summary shape is different and is the shape the schema describes. Summary gap count/length bounds are not enforced by the job.
- **Impact/confidence:** high-confidence nominal contract mismatch, not a reproduced publication crash. No JSON-schema output validator is attached to the job; generic control validation does not inspect arbitrary payload keys.
- **Smallest correction:** separate/narrow plan, summary and receipt declarations/schemas, or explicitly define valid variants; validate actual emitted document shapes.
- **Overlap:** T-147 broadly tracks exact publication/task metadata. This particular mismatch was not located in earlier reports.

## Previously reported issues — do not count as new

| ID | Current evidence and result | Overlap / disposition |
| --- | --- | --- |
| K01 — High, links lost | Language producer writes `receipt.link_database` outside workspace (`job_language_build/job.py:1541-1545,1589-1590`), but C++ catalog probes only `build/.appsec-review-link-commands.json` (`job.py:1143-1147`). R1: one accepted relation becomes `link_commands=[]`. | **C08-F01** remains. Correct by consuming/verifying accepted receipt identity; impacts SVF linked-module planning. |
| K02 — High, valid sources removed | `job.py:1054` recursively ignores every basename `build`/`target`; R2 proves `app/src/target/valid.cpp` absent from copied tree/mapping. A captured command for it fails catalog source resolution at `338-339`. | **C08-F02** remains. Exclude only exact generated/VCS paths or use admitted source list. |
| K03 — High, generated include paths wrong | `job.py:241-244` maps workspace project prefix to source prefix, not recipe build prefix; R3 changes `/workspace/app/build/generated` to nonexistent `/scratch/source/build/generated`, while preparation stages `/scratch/build`. Relative compile cwd is also discarded at `340`. | **C08-F03** remains; repro demonstrates non-root project too. Preserve/rebase accepted build directory and cwd. |
| K04 — High, full-mode IR drops flow | `job.py:650-718` regex path never invokes debug IR/CFG parser, places functions at TU line 1 with ambiguity, no `flow` payload; graph flow consumer requires that payload. | **C08-F05** remains; static trace plus exercised full-mode tests, not a live experiment. |
| K05 — Low, full-mode AST filter loses functions | `containers/tools/native-cpp/native.py:127-143,159-160` chooses `main`, common prefix or only the first function; namespace alternatives are joined with `|` although the filter is supplied as one string. | **C08-F16** remains statically; real Clang filtering not invoked. Do not call whole-program AST complete merely because replay returned 0. |
| K06 — Medium, include scan budget not actual reads | `seeding/units.py:72-88` counts main/header parsing but not candidate probes; R5b with `include_scan_files=1` performs six distinct file reads. Reader reads whole bytes before slicing (`seeding/plan.py:40-45`). | **C11-F08** remains. Priority-vs-alphabetical limit ordering also remains by inspection, not separately reproduced. |
| K07 — Conditional replay dependency gap | `_run_tool`/`_run_infer` use catalog tools rather than target's derived build image. Custom installed headers may be absent. Existing PHP/Python header-version and fake-image tests now pass. | **C08-F04** is not proof that every extension fails at this revision; no custom-header live test or image inspection was authorized. |

T-016 covers scaling/frontier/consumer limitations; T-5016 covers graph quality; T-157 covers applicability metadata; T-147 covers bindings. Historical C08-F09's claim that not passing `contract=` bypasses validation is **not repeated**: current consume scopes enforce it. Historical C08-F06 mount-authority claim was not adopted; current native tool declaration permits read-only target mounting. Legacy gap strings/`strict_gaps=False` remain known debt, not newly introduced vocabulary changes.

## Validation commands and outcomes

Every Linux command used the brief's base64 transport:

```powershell
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Inside each script: `set -eu; cd /home/wsollers/projects/appsec-review`.

### Collection

```bash
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
.venv/bin/python -m pytest --collect-only -q -o addopts= -p no:cacheprovider \
  --basetemp=test/tmp/job-audit-cpp-20-collection-20261118-1320 \
  tests/unit/job_cpp_compiled_analysis/test_clang_cfg.py \
  tests/unit/job_cpp_compiled_analysis/test_compile_and_replay.py \
  tests/unit/job_cpp_compiled_analysis/test_contract.py \
  tests/unit/job_cpp_compiled_analysis/test_job_pipeline.py \
  tests/unit/job_cpp_compiled_analysis/test_seeded_compiled.py \
  tests/unit/job_cpp_compiled_analysis/test_seeded_ir_and_record.py \
  tests/unit/job_cpp_compiled_analysis/test_terminal_gap.py
```

Exit 0: **71 collected in 0.61 s**. One `PytestConfigWarning: Unknown config option: cache_dir` from disabling cacheprovider; not a failed test. No execution during this collection.

### Focused execution

```bash
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 20261118 \
  --max-tests 71 --expect-tests 71 --timeout-seconds 180 -- \
  tests/unit/job_cpp_compiled_analysis/test_clang_cfg.py \
  tests/unit/job_cpp_compiled_analysis/test_compile_and_replay.py \
  tests/unit/job_cpp_compiled_analysis/test_contract.py \
  tests/unit/job_cpp_compiled_analysis/test_job_pipeline.py \
  tests/unit/job_cpp_compiled_analysis/test_seeded_compiled.py \
  tests/unit/job_cpp_compiled_analysis/test_seeded_ir_and_record.py \
  tests/unit/job_cpp_compiled_analysis/test_terminal_gap.py
```

- Exit 0: **71 passed in 4.54 s**, 0 failed/errors/skips; 0 cases over 10 s. Wrapper total **10.860197384 s**, including supervised collection/execution/cleanup.
- Wrapper automatically generated the unique run ID `tests-custom-20261118-122656-207503-2868264`, with at most two workers and 71-node collection proof. Its internal serial preflight and execution use its same owned base-temp namespace; the separate manual collection used the different path above. No other auditor's default scratch was used.
- Logs: `test/tmp/logs/tests-custom-20261118-122656-207503-2868264.log` and same basename `.collection.log`.
- JUnit: `test/tmp/tests-custom-20261118-122656-207503-2868264.junit.xml`.
- Timings: `test/tmp/tests-custom-20261118-122656-207503-2868264.timings.sqlite`.
- Collection proof: `test/tmp/tests-custom-20261118-122656-207503-2868264.collection.json`.
- Fixed report: `test/tmp/reports/tests-custom-20261118-122656-207503-2868264.json`.
- The production-environment preflight and fake host-pin fixture were the repository's normal unit harness, not manually changed environment/source. No missing dependencies required action.

### Synthetic probes and failed attempts

All ran as `.venv/bin/python - <<'PY' ... PY` through the same SSH transport, using real imports plus `tests.seeded_clang_support` and the explicitly fake helpers in `tests/unit/job_cpp_compiled_analysis/test_job_pipeline.py`. Each created only a unique `test/tmp/job-audit-cpp-20-repro-20261118-{a,b,c,d}` tree and removed it in `finally`.

| Probe command/body | Outcome |
| --- | --- |
| A: R1–R6 plus initial overload query | R1–R6 observed as listed above; **exit 1 at 0.171 s** because audit SQL requested nonexistent column `a.payload` rather than `payload_json`. Not a product failure. Later corrected. |
| B: overload query corrected; remainder gated behind assert | **exit 1 at 0.066 s**: the chosen call `_Z1fd` happened to match the erroneous first overload, so the probe's assertion was wrong. No later R8–R12 results claimed from this run. |
| C: actual call changed to non-first `_Z1fi`; R7–R12 | **exit 0, 0.286 s**. All assertions for wrong exact callee, lost edge, failed CFG reuse, malformed-AST false resolution/reuse, missing-receipt success and swallowed symbol-tool failure passed. |
| D: R1–R6 rerun with explicit asserts; R13 plus dataset ownership | **exit 0, 0.119 s**. All observations reconfirmed; all regular/blocked shard owners unique; fixed-report elapsed read; HEAD/status unchanged; no remaining reproduction directories. |

Other read-only probes: initial UNC guessed `Ubuntu` failed before brief-corrected `Ubuntu-22.04`; no wrong checkout audited. A WSL `rg` invocation failed because that executable is absent, so subsequent searches used UNC tools/standard Python. A native-driver range read started beyond EOF; the preceding read had already contained its full 237 lines. None was a test or product failure.

### Reproduction recipe details

These are small recreations of the executed C/D bodies; no external compiler is necessary.

1. **R1/R2/R3/R4/R13 fixture:** `_make_unit(base/"links", "plan.accepted_cpp_plan", repository_root=base/"empty-repo")`; `_stage_language_build(run_root,target_root,fingerprint)`. Move the fixture's `workspace/build/.appsec-review-link-commands.json` outside the workspace to `data/language_build/link-commands.json`; hash-bind it in receipt `link_database` with relationship count 1; recompute workspace manifest and rewrite the accepted test handoff with `_write_language_build_handoff`. Add `target/app/src/target/valid.cpp`. Invoke real plan, prepare, catalog handlers via `{u.unit_id:u.handler for u in build_job().units}`. Inspect lost links/source copy, apply `_sanitize_arguments` to `["cc","-I/workspace/app/build/generated","/workspace/app/main.cpp"]`, and validate actual `plan` with `Draft202012Validator` over the committed schema. For R13 call `_build_entities` with that catalog except `outputs=[]`, `link_commands=[]`; query `SELECT status,gap FROM coverage`.
2. **R5/R5b:** call `select_units` with rows `{"file":"/scratch/source/a.cpp","arguments":["cc",flag,"/scratch/source/inc"]}`, `[Seed("inc/h.h",1,1)]`, `unit_limit=1`, `include_scan_files=10`, reader `{"a.cpp":"#include <h.h>","inc/h.h":"int h;"}.get`. Repeat each of four flags. For budget: one `a.cpp` including five present `h0.h`…`h4.h`; counting reader; budget 1; observe six calls/distinct files.
3. **R6:** `sc.stage(base/"ast")`; select its util.cpp compile command. Write `analysis/ast/tu-0000.json` with the two AST nodes specified in F02. Invoke `_add_ast_entities` with an in-memory collector object exposing `.add_entity`. Inspect returned `EntityRecord.location`, not a mocked location helper.
4. **R7:** `sc.stage(..., observations=[sc.observation("proj/src/util.cpp",14)])`. Subclass only `sc.FixtureExecutor.execute`, delegate playback, then replace IR `tu-0000.ll` with the text below on mode `ir`; run actual `_run(staged,executor,"ir")`. Query `relations` joined to `entities` using `payload_json`:

   ```llvm
   define i32 @copy_field() !dbg !1 {
   entry:
     %v = call i32 @_Z1fi(i32 0), !dbg !11
     ret i32 %v, !dbg !11
   }
   define i32 @_Z1fi(i32 %x) !dbg !2 {
   entry:
     ret i32 1, !dbg !12
   }
   define i32 @_Z1fd(double %x) !dbg !3 {
   entry:
     ret i32 2, !dbg !13
   }
   !1 = distinct !DISubprogram(name: "copy_field", file: !20, line: 11)
   !2 = distinct !DISubprogram(name: "f", file: !20, line: 3)
   !3 = distinct !DISubprogram(name: "f", file: !20, line: 6)
   !11 = !DILocation(line: 14, column: 3, scope: !1)
   !12 = !DILocation(line: 4, column: 3, scope: !2)
   !13 = !DILocation(line: 7, column: 3, scope: !3)
   !20 = !DIFile(filename: "src/util.cpp", directory: "/scratch/source")
   ```

   SQL: `SELECT a.name,b.payload_json,r.exact FROM relations r JOIN entities a ON a.identity=r.source_id JOIN entities b ON b.identity=r.target_id WHERE r.kind='CALLS'`. Result is `copy_field`, target payload `linkage_name="_Z1fd"`, exact 1.
5. **R8:** `llvm_ir.parse_module` on a debug-bound function whose three labeled blocks are `entry: br label %next`, `next: br label %done`, `done: ret void`; compare default limit with `block_limit=1`. No filesystem needed.
6. **R9:** `_run(sc.stage(...), sc.FixtureExecutor(run_root, fail=(("cfg","util"),)), "ir")`; second call same staged data with healthy fixture executor. Check `checkpoint_reused` and empty `.calls`.
7. **R10:** normal fixture IR run; AST fixture subclass writes `{broken` over each `analysis/ast/tu-*.json` after successful playback. Run AST with that IR output; rerun healthy executor. Check zero entities, two resolved seeds, checkpointable/reused true and no retry calls.
8. **R11:** restrict staged catalog and normalized compile DB to its util.cpp row; refresh compile-database artifact identity. Fake executor deletes `analysis/ast/receipt.json` after playback. `_run(...,"ast",seeded_settings=None)` returns clean success.
9. **R12:** import `containers/tools/native-cpp/native.py` by `importlib.util.spec_from_file_location`; point `ROOT/BUILD/OUT` into staged scratch; create `build/broken.o` with `b"not an object"`. Under `patch.object(driver.subprocess,"run", fake)` return `SimpleNamespace(returncode=1,stdout=b"",stderr=b"file format not recognized")` for both utilities. Invoke `driver.symbols()`, then real `_binary_index` with a fake execution identity. Verify driver 0, no gaps, branch SUCCEEDED, zero symbols.

## Read inventory and material gaps

**Read fully:**

- Required shared audit brief; authorized root `AGENTS.md`; authorized `.claude/skills/multi-session-coordination/SKILL.md`; development-skills pointer. Canonical development skills were enumerated; no implementation/build/repair skill was applicable to this read-only audit.
- All six job source files: `__init__.py`, `job.py`, `datasets.py`, `seeded.py`, `llvm_ir.py`, `clang_cfg.py` (including sections initially truncated and then explicitly filled).
- All seven mapped unit-test files (2,462 lines), `tests/seeded_clang_support.py`, `tests/conftest.py`; exact job-test-map entry.
- `docs/operations/job_cpp_compiled_analysis.md`; `docs/schemas/cpp-compiled-analysis.schema.json`; `config/seeding.py`; shared `seeding/ledger.py`, `plan.py`, `record.py`, `neighborhood.py`, `units.py`.
- `containers/tools/native-cpp/native.py`; native/Infer tool manifests; `scripts/run-tests.sh`, `scripts/lib/common.sh`.

**Read relevant sections / sampled:**

- `config/loader.py` lane/typed/seeded injection; central TOML job section; registry registration; topology through its core dependency/accepted-tag logic; Dagster pool mapping.
- Language-build receipt loader (`job.py:125-173`), capture/link receipt construction (`1515-1600`), native component projection (`native_components.py:185-227`).
- `cpp_index_scopes.py:1-255`, `runtime/consume.py:1-235`, `runtime/datasets.py:1-185`, `runtime/units.py:80-239`, `interchange.py:521-598`, relevant read-boundary searches in `runtime/inputs.py`.
- `retrieval/core.py` manifest resolver; `retrieval/index.py` builder/schema/identity passages; direct graph-flow and SVF planning consumers; graph cross-check relevant branches by targeted search.
- `docs/architecture/seeded-neighborhoods.md:1-230`; T-016, T-147, T-157, T-5016 entries; relevant C08/C07/C11 prior-review findings; prior per-job artifact reports by scoped symptom search.
- Test runner `ops_tests.py:100-155,337-505` and guard/option definitions by search. Recorded IR/AST/CFG fixtures were consumed by tests; not every recording was manually read.

**Material unread / unverified:**

- No real compiler/build input, tool image filesystem/version measurement, Infer diagnostic report, retained production run or acceptance baseline was inspected/executed. No scoring of real review findings.
- No full admitted Dagster/unit publication, signing/shared-storage enforcement, dataset inventory run, or exact downstream read-receipt trace. Helper-level schema mismatch is not proof of automatic schema rejection.
- No full audit of all downstream jobs, graph name-matching implementation, retrieval/slicing APIs, provider/runtime orchestration, or build-family capture implementations; only directly necessary seams above.
- No live reproduction of platform-specific flags, response files, MSVC/PE/Mach-O/wasm semantics, generated-only or header-only projects, arbitrary build layouts, non-UTF8 compiler paths, huge AST/binary payloads or scale/resource behavior. Relevant source limitations are not “passed”.
- Retry reproductions are local branch checkpoint tests with declared fixture releases and preserved prepared cases. Prepare recreation or full runtime unit-reuse policy can change whether that local checkpoint path is reached.
- Existing PHP/Python include-closure tests are fake compiler plus configuration-string checks, not proof the actual images contain every dependency.

Only this job was audited. Final source remained clean at the required SHA; reproducer scratch trees were removed; focused test reports remain under their unique `test/tmp` paths.
