# Job 22/47 — job_clang_static_analysis

## Audit boundary and result

- **Audited revision:** `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`, branch `main`, `/home/wsollers/projects/appsec-review`, Ubuntu-22.04 via `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu`.
- HEAD and tracked/untracked cleanliness verified before and after. Editable import resolved to `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`. The default Windows checkout was not audited.
- Read-only functional audit, one job, no delegation. No real compiler, scanner, provider, target program, container, service, integration, acceptance or live review was launched. No source, configuration, environment installation or Git state was changed.
- **Findings:** seven medium and two low functional/robustness findings below. CSA-F01 extends an already reported upstream working-directory problem; do not count the overall cwd theme twice. CSA-F08 is statically verified, without an induced memory-exhaustion experiment. CSA-F09 is latent malformed-output robustness, not an output produced by the current healthy wrapper.
- **Validation:** all **37 mapped unit tests passed**, two workers, shuffled; pytest **3.33 s**, wrapper **8.882 s**, zero failures/skips and zero tests over ten seconds. Eleven numbered offline probes were investigated; the initial probe script had an auditor SQL-column error, corrected as recorded below.
- These results do **not** establish live analyzer correctness, image availability, real compiler behavior, or complete end-to-end acceptance.

## Intended contract, registration and activation

The canonical page is `docs/operations/job_clang_static_analysis.md`; also read `docs/architecture/clang-static-analysis.md`, `docs/architecture/seeded-neighborhoods.md` and the older operating page.

`runtime/registry.py:90,160` registers the builder. `datasets.py:41-94` declares `REVIEW_GRAPH`, checkout access, propagation, `always_execute=False`, and scheduling after compiled analysis. Effective topology was evaluated without Dagster execution and returned **`('job_cpp_compiled_analysis',)`**. It is enabled in the normal recipe and has no separate `settings.enabled` switch.

The 21 typed inputs are:

- Required, reject-if-missing **`job_cpp_compiled_analysis/handoff`** (`job-handoff/2`).
- Optional/gap compiled datasets: `cpp_build_graph`, `clang_ast`, `llvm_ir`, `infer_observations`, `binary_symbols`, `cpp_blocked_branches`, `cpp_plan_and_summary`, `cpp_case_material`.
- Optional/gap evidence-collection handoff plus `static_tool_observations`, `static_tool_evidence`, `static_tool_io`.
- Optional/gap target-catalog handoff plus `target_artifact_inputs`, `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units`, `catalog_documents`.

Actual reads: `cpp_index_scopes.load_accepted_cpp` calls `runtime.consume.accepted_upstream`, verifies the bound result and retrieval manifest; `_scope` verifies accepted compile-database and source-file hashes. Catalog success and nonempty command lists control scope eligibility. There is no build rerun. Seed extraction reads the attempt-pinned retrieval manifest and verified observation shards, excludes seeded producers, and maps source locations into accepted project files. The shared `ShardSet.open_shard` calls `observe_shard`; do not describe all seed reads as unrecorded. The compiled result/source mapping is still consumed through the shared direct JSON/file readers rather than job-specific `observe_output` calls; precise payload-read attribution remains a shared-reader audit limitation.

Central settings (`appsec-review.toml:1762-1791`) resolved to:

```text
workers=4
max_output_bytes=16777216
max_diagnostics_per_scope=10000
clang_tidy_checks=[clang-analyzer-*, bugprone-*, cert-*, concurrency-*, performance-*, portability-*]
clang_analyzer_checkers=[core, cplusplus, deadcode, security, unix, alpha.security,
                        alpha.unix.cstring.OutOfBounds]
seeded={mode=seeded, depth=3, seed_limit=200, unit_limit=64, include_scan_files=4000}
```

Mode/depth/seed limit derive from CodeQL export settings through `config/seeding.py`. Missing `seeded` in hand-built settings means whole-program mode. `_validated_settings` enforces positive numeric values, nonempty checks, and named—not wildcard—Static Analyzer checker packages. The production scope pool uses `settings.workers`; the audit's pytest pool was independently limited to two.

`tool-clang-static-analysis` is enabled in `containers/catalog.toml:831-844`. Its inspected tool manifest fixes offline networking, read-only target/root, writable scratch, UID 10001, 1 GiB memory, 2 CPUs, 256 PIDs, 600 seconds and 16 MiB stream output. Job execution adds an individual file-size limit of configured output bytes plus one. Dockerfile inherits LLVM 18 tooling and has **`WORKDIR /scratch`**.

## Every declared task and step

| Step/task | Actual implementation and traversal | Finding or coverage limit |
|---|---|---|
| `load.accepted_cpp` | `job.py:438-444`; `accepted_cpp_scopes` → accepted handoff/result/manifest → verified catalog/source/compile DB → planned scope dictionaries and unavailable cases. Checks job source fingerprint against upstream. | Shared input-custody functions inspected. Actual accepted-handoff admission was not run end to end; tests inject the loader. Existing upstream mapping/cwd defects remain relevant. |
| `analyze.scopes` | `job.py:446-470`; rereads scopes, compares scope-ID set, splits Clang-supported rows from unsupported rows; derives shared seed plan; maps one `_analyze_scope` per runnable scope with bounded thread pool. | All handler branches and helpers read. CSA-F01–F06, F08–F09. No applicable scopes return `NOT_APPLICABLE`; failed/unavailable scopes carry gaps. |
| `acceptance.publish_handoff` | `job.py:472-488`; `publish_scope_indexes` creates per-scope plus coverage shards and composes the upstream manifest; writes `clang-static-analysis-summary.json`; sums observations and gaps. | Real helper exercised in R10. CSA-F07. No full `JobRunner`/Dagster acceptance was authorized. |

Within `analyze.scopes`, both actual engine paths were followed:

1. **clang-tidy:** `_engine_argv` → `/opt/appsec/clang-static.py tidy ...` → database loop → `clang-tidy-18 -p <scratch> --checks=... --quiet --extra-arg=-fdiagnostics-parseable-fixits <file>` → text diagnostics and per-TU outcomes.
2. **Static Analyzer:** analogous `analyze` action → accepted row arguments with versioned compiler → `--analyze`, configured checkers, plist-multi-file output → plist diagnostics, falling back to text if no plist diagnostics.
3. **Postprocessing:** execution exception/timeout/OOM/file or stream bounds/nonzero-exit handling; seeded per-TU failures; bounded wrapper JSON; accepted-source mapping; observation/source entities and `OBSERVED_AT`; native provenance retention; seeded labels and ledger; coverage/status; checkpoint.

No model worker, role, task prompt, persona or runtime skill is dispatched by any of the three handlers. Missing generated task/tool bindings remain **T-147**, not evidence that no tool executes.

## Output, count and downstream audit

| Dataset | Actual publication | Contract check |
|---|---|---|
| `clang_static_observations` | `observations` SQLite shard `clang-static-<scope-id>`, `retrieval-index/2`; observation, source-file entities and exact `OBSERVED_AT` relations. | Prefix matches declaration. Repeated identical diagnostics collapse before native selectors create conflicting payloads. Existing regressions verify entity count and first native selector. |
| `clang_static_scope_coverage` | `observations` coverage shard `clang-static-coverage-<attempt>`. Declared semantic schema `cpp-index-coverage/1`, physical index schema `retrieval-index/2`. | More-specific prefix correctly wins over `clang-static-`; R10 exercised `shard_owner`. Applicability discrepancy in F07. |
| `clang_static_summary` | Acceptance-task `clang-static-analysis-summary.json`, `clang-static-analysis-handoff/1`, artifact-only. | Glob includes actual summary, but is broad enough to claim other task JSON. No independent summary JSON Schema/output validator was located; attached validator checks config, generic runtime validation checks control fields, not payload shapes. |
| `clang_static_raw` | `data/clang-static/**`, including rewritten compile DBs, per-engine JSON, execution receipts/streams, seed ledger and checkpoint. Protected. | Tree matches. Nominal `application/json` does not describe every raw stream byte file; sanitized inventory is not payload validation. Retained native output also has runtime shared-object provenance. |

Observed payload includes `scanner`, tool ID, source-SAST category, native rule/severity, message, trace/trace length, fix-it presence, evidence ID, common metadata and optional seeded label. Severity repair and duplicate-collapse regression are already present, not new findings.

`accepted_count` increments once per unique engine/scope diagnostic identity. Repeated diagnostics from different native selectors are counted once; observations from different engines remain distinct. Source entities are separately de-duplicated. The final summary sums scope observation counts; gap count counts scope-prefixed strings, not independently classified causes.

Whole-program mode can reuse partial checkpoints by explicit design. Seeded runs stay partial, except engine-level total failure is supposed to be unavailable, and failed engines/TUs are not checkpointed. Zero seeds launches no engine and names a gap. With the optional execution-safety controller active, `safety.failed_result` can stop on an error before fallback publication; this is documented policy, not a defect or a bypass.

Downstream sampled evidence:

- `review/scope.py:116-124` admits these shards as source-SAST.
- `job_code_graph_index/producers.py:131-157` copies diagnostics, severity, trace length/steps, fix-it, labels and seed/function data into neighborhood rows. Incorrect or discarded producer information therefore reaches—or is unavailable to—review/graph consumers.
- Typed consumers include graph, CodeQL, review-data indexing, package assembly and inference review. Their declarations were searched; complete consumer jobs were not re-audited.

## Findings

### CSA-F01 — Medium — Static Analyzer ignores accepted compile working directory

- **Evidence:** `containers/tools/clang-static-analysis/clang-static.py:41-45,114-134`; `containers/tools/clang-static-analysis/Dockerfile:20`; `src/appsec_review/jobs/cpp_index_scopes.py:96-121`.
- **Trigger:** an accepted row has `directory=/target/source`, `arguments=["clang++", "-Iinclude", "/target/source/main.cpp"]`.
- **Expected:** analyze relative include/options in that accepted directory.
- **Actual:** R1 intercepted the real wrapper's `subprocess.run`; no `cwd` was passed. The image runs in `/scratch`, so `-Iinclude` points at `/scratch/include`, not accepted `/target/source/include`. Clang-tidy does use the compilation database directory.
- **Impact:** valid accepted compilation contexts fail or analyze with different headers in CSA; the other engine can behave differently.
- **Confidence:** high for ignored cwd and generated argv; no real compiler was run.
- **Smallest correction:** pass the verified row directory to execution, preserving/rebasing accepted cwd and relative options consistently.
- **Overlap:** downstream extension of **CPP K03 / historical C08-F03**, which already records discarded upstream cwd/generated include mapping. Fixing upstream normalization alone does not fix this wrapper's omission. T-016/T-017 are broadly related, not exact fixes.

### CSA-F02 — Medium — Diagnostic traces lose resolving information and silently truncate

- **Evidence:** `containers/tools/clang-static-analysis/clang-static.py:51-65,92-112,157-164`; `job.py:371-372`; graph consumer `job_code_graph_index/producers.py:145-152`.
- **Triggers:** a clang-tidy warning followed by a note in another file; a plist note whose `location.file` names a header; or more than 256 plist path pieces.
- **Expected:** retain bounded source-resolving notes and expose truncation/omissions.
- **Actual:** R2 found tidy `notes=[]`; plist note kept line/column/message but discarded its file index/path. Supplied plist diagnostic ranges were also absent from output. R11 supplied 257 notes: output had 256, wrapper `truncated=false`, parser `gaps=[]`, exit 0. `trace_length` is consequently the retained subset size, without a truncation marker.
- **Impact:** cross-file steps cannot resolve, useful trace context disappears, and downstream cannot distinguish a complete short trace from a cut trace.
- **Confidence:** high, real parser/main/normalizer functions with fake execution boundary.
- **Smallest correction:** retain accepted file identities for trace points, attach text notes to diagnostics, preserve supported ranges, and propagate bounded trace truncation plus original/retained counts.
- **Overlap:** T-016 discusses broader seeded consumers/scaling; no exact existing TODO or prior job report matching these wrapper losses was found.

### CSA-F03 — Medium — Out-of-range diagnostic coordinates become false exact source locations

- **Evidence:** `src/appsec_review/jobs/job_clang_static_analysis/job.py:152-172`.
- **Trigger:** accepted source path with a reported presumed/out-of-range line or column, including possible line-directive output.
- **Expected:** resolve the reported coordinate against accepted bytes, or retain an unresolved/ambiguous gap rather than fabricate a physical span.
- **Actual:** R3 supplied line 1000, column 40 for a 38-byte one-line file. `_location` returned line **2**, byte interval **[38,38]**, column **40**, `confidence=1.0`, `ambiguous=False`. It clamps line/byte values, leaves incompatible columns, and drops original coordinates from `producer_location`.
- **Impact:** accepted source hash plus exact-confidence metadata can cite unrelated EOF instead of the reported location; seed/function placement still uses the original line, creating conflicting views.
- **Confidence:** high for mapping behavior; no claim that a live compiler's `#line` case was executed.
- **Smallest correction:** validate physical line/column bounds and retain original coordinates; map presumed locations explicitly or mark unresolved.
- **Overlap:** adjacent to CPP-F02's AST location fabrication, but a separate Clang diagnostic mapper. No exact TODO found.

### CSA-F04 — Medium — Scope cache reuses observations whose native evidence is missing

- **Evidence:** `job.py:224-226,298-306,411-422`; `cpp_index_scopes.py:282-292,332-341`; native verification `provenance.py:101-122`.
- **Expected:** matching checkpoints verify the raw/native artifacts supporting the observations before returning reusable results.
- **Actual:** R7 changed `tidy.json`; retry reused the checkpoint without engine calls. More importantly, R9 ran under a real `SharedArtifacts` owner, deleted the detached native object cited by an observation, and confirmed `verify_native_reference` failed. `_analyze_scope` still returned `checkpoint_reused=True`, zero engine calls.
- **Cause:** raw/native references are kept in local lists or SQLite payloads but not the checkpoint result traversed by `scope_checkpoint`; it hashes the SQLite file, not its evidence references.
- **Impact:** stale observations advance through this cache boundary despite missing resolving evidence. Later admission/retrieval may reject them; this is **not** a claim that full publication accepted corrupt provenance.
- **Confidence:** high, reproduced with native retention owner and explicit failing native verifier.
- **Smallest correction:** retain/check raw and selected native references in the checkpoint contract or verify shard observation provenance on reuse.
- **Overlap:** shared checkpoint machinery also serves other jobs; no earlier exact Clang-native-evidence finding found.

### CSA-F05 — Medium — Unchanged selected seed keys hide changed omitted-seed counts on resume

- **Evidence:** `src/appsec_review/jobs/job_clang_static_analysis/seeded.py:52-54,70-73`; `job.py:220-226`; `seeding/ledger.py:433-451` (ledger counts/gaps).
- **Trigger:** a new admitted input plan retains the same selected seed locations but changes over-limit, outside-database or unlocated counts; or updates seed provenance/neighborhood depth metadata without changing the hashed subset.
- **Expected:** refreshed ledger and coverage accounting even if engine work can be reused.
- **Actual:** R8 changed the plan from one omitted seed to six, added three outside-database and two unlocated seeds, and retained the selected key. Result reused the old checkpoint, reported `{"over_limit":1,"resolved":1}`, and made no engine calls. Expected over-limit was six plus the new shared omissions.
- **Cause:** checkpoint identity hashes selected rows/settings and selected neighborhood fields, not total/dropped/shared counts or all ledger-affecting metadata.
- **Impact:** stale coverage omissions and provenance can survive an upstream re-acceptance.
- **Confidence:** high, direct per-scope retry reproduction; no in-place production configuration was edited.
- **Smallest correction:** separate reusable engine results from freshly derived ledger metadata, or bind all output-affecting seed/plan/neighborhood fields.
- **Overlap:** T-016 is related; no exact prior Clang finding found.

### CSA-F06 — Medium — Every translation unit can fail while coverage remains partial

- **Evidence:** `job.py:279-295,309-315,398-399`; `docs/architecture/seeded-neighborhoods.md:101-107`.
- **Trigger:** wrapper reports nonzero exit and valid failed-unit records for every selected TU, from both engines.
- **Expected:** total failed execution is unavailable coverage, while preserving each failed seed's reason.
- **Actual:** R5 failed net/util in both engines. Output had **zero observations**, both seeds unresolved, four per-unit failure gaps, but SQLite coverage **`partial`**, not `unavailable`.
- **Cause:** per-unit failures populate `failed_units` but not `engine_failed`; total-failure coverage consults only the latter.
- **Impact:** consumers see partial analyzer coverage when no TU was successfully analyzed. Gaps and failure non-checkpointing still work; this is not a false `SUCCEEDED` claim.
- **Confidence:** high, actual seeded handler with inspected fake executor.
- **Smallest correction:** reconcile selected and successful TU outcomes per engine when computing coverage.
- **Overlap:** T-016's failure semantics, but no exact matching existing defect.

### CSA-F07 — Low — Unsupported-only scopes vanish from the summary and look unavailable in coverage

- **Evidence:** `job.py:451-453,467-470,473-488`; `cpp_index_scopes.py:375-378`.
- **Trigger:** accepted scope contains only unsupported assembly/CUDA compile units.
- **Expected:** preserve `SKIPPED_NA` scope identity/counts, distinct from unavailable compilation context.
- **Actual:** R10 analyzed one assembly-only scope: `NOT_APPLICABLE`, one correctly skipped scope, no tool calls. Acceptance summary then contained zero scopes/observations/gaps, no skipped-scope field, and coverage said `unavailable: no accepted C/C++ project scopes`.
- **Impact:** summary/coverage readers lose why accepted work was not applicable. The detailed analyze-unit output still contains the correct skipped record.
- **Confidence:** high, real analyze/publish helpers and manifest/SQLite readback.
- **Smallest correction:** carry skipped scopes into summary/coverage composition and avoid the generic unavailable row for known unsupported-only input.
- **Overlap:** applicability metadata is broadly **T-157**; helper affects sibling native index jobs too.

### CSA-F08 — Medium — Wrapper byte/diagnostic bounds are enforced after unbounded capture/accumulation

- **Evidence:** `containers/tools/clang-static-analysis/clang-static.py:22-24,41-45,75-88,116-140,157-164`.
- **Trigger:** compiler emits very large output or many units emit diagnostics near per-command capture size.
- **Expected:** a bounded adapter limits retained bytes/records while reading and aggregating.
- **Actual, static:** `subprocess.run(stdout=PIPE)` buffers the entire subprocess output before slicing to `MAX_CAPTURE`; each TU's parsed diagnostics extend one growing list; `maximum_diagnostics` is applied only after the complete engine loop. `RLIMIT_FSIZE` does not bound pipe memory.
- **Impact:** output intended to be cut can consume the whole 1 GiB tool memory budget and cause OOM/engine loss instead of a bounded partial result. The outer memory/timeout protections remain in force.
- **Confidence:** high for post-capture/post-aggregation placement; no real compiler, large-output process or OOM experiment was run.
- **Smallest correction:** bounded streaming capture and incremental diagnostic budget accounting, retaining explicit truncation and unit outcomes.
- **Overlap:** broader output-bound themes occur in other producer reports; this wrapper has its own implementation. T-016 scale measurement does not itself fix this bound.

### CSA-F09 — Low — Malformed optional spans escape the promised output-gap path

- **Evidence:** `job.py:107-124`, especially the unchecked `int(end_line/end_column)` conversions.
- **Trigger:** otherwise well-formed wrapper JSON contains `end_line=null` or a nonnumeric optional span.
- **Expected:** reject the diagnostic/engine output with a named parse gap, as for malformed required fields.
- **Actual:** R4 raised `TypeError` instead of returning a gap; parsing is outside the engine execution `try`, so the exception can fail the scope/task rather than preserve the other engine.
- **Confidence:** high for malformed-input behavior. The current healthy wrapper does not emit these optional end fields; reachability is a malformed/alternate-output robustness case.
- **Smallest correction:** type/range-check optional spans before conversion and return the existing malformed-output gap.
- **Overlap:** no exact TODO found.

## Additional concerns and existing overlap, not new confirmed defects

- **R6, missing per-TU outcomes:** zero-exit JSON without `units` and without diagnostics marks both seeds resolved and writes a checkpoint; only the missing-neighborhood gap remains. This was reproduced, but the current healthy wrapper always emits `units`, and aggregate exit-0 may intentionally support legacy output. Treat stricter unit-set completeness as an unresolved contract/test question, not a separately counted functional finding.
- Settings accept `max_diagnostics_per_scope >100000` although wrapper `main` rejects that value. Defaults are within bounds; early config/wrapper parity needs a focused boundary test.
- Tidy selection appends the central check list without an explicit clearing prefix/config override. Real clang-tidy project-config/check-resolution behavior was not exercised; no speculative authority/security claim is made.
- Shared seed include selection still has **CPP-F04** (`-isystem/-iquote/-idirafter` dispatch), and **CPP K06 / C11-F08** (actual include reads/priority bounds). Source/compile staging inherits **CPP K02/K03**. These are not new Clang discoveries.
- Existing **T-016** lists scale/frontier and downstream consumer gaps; **T-147** covers missing task/publication bindings; **T-157** applicability metadata; **T-5051** separately concerns rule CWE/severity ranking. None was edited.
- The accepted CPP report, cumulative report and matching prior-report references were checked. No preceding completed job was re-audited.

## Documentation drift

- `docs/operations/clang-static-analysis.md` still instructs running removed root test paths `tests/test_clang_static_analysis.py` and `tests/test_clang_static_tool.py`; mapped units now live under `tests/unit/job_clang_static_analysis/`.
- `docs/architecture/seeded-neighborhoods.md` test list likewise contains pre-move root selectors.
- TODO's historical 32-case/coverage statement at `docs/TODO.md:3775-3781` describes an earlier test inventory, not this audit's current **37 cases**. Passing line coverage never establishes the omitted behavior above.

## Focused validation: exact commands and outcomes

All Linux commands used the authorized SSH transport from the shared brief:

```powershell
$script = @'
set -eu
cd /home/wsollers/projects/appsec-review
# commands below
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Preflight:

```sh
git --no-pager status --short
git --no-pager rev-parse HEAD
git branch --show-current
git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
```

Before unit execution, a Python probe checked `offending_environment(os.environ)` from the repository guard, rejected inherited `PYTEST_ADDOPTS`, and AST-counted the exact four files: **16 + 4 + 4 + 13 = 37**. No production selectors were present; no environment repair was performed.

The only pytest run:

```sh
scripts/run-tests.sh --expect-tests 37 --parallel --test-workers 2 --shuffle-seed 221118 -- \
  tests/unit/job_clang_static_analysis/test_clang_static_analysis.py \
  tests/unit/job_clang_static_analysis/test_clang_static_tool.py \
  tests/unit/job_clang_static_analysis/test_contract.py \
  tests/unit/job_clang_static_analysis/test_seeded_clang_static.py
```

The wrapper generated:

```sh
/home/wsollers/projects/appsec-review/.venv/bin/python -m pytest \
  -p ops_test_guard -c /home/wsollers/projects/appsec-review/pyproject.toml \
  --rootdir=/home/wsollers/projects/appsec-review -o addopts= -q -rfE \
  --basetemp=test/tmp/tests-custom-20261118-123921-579658-2954286 \
  --junitxml=test/tmp/tests-custom-20261118-123921-579658-2954286.junit.xml \
  -o junit_family=legacy -n 2 --shuffle-seed=221118 \
  tests/unit/job_clang_static_analysis/test_clang_static_analysis.py \
  tests/unit/job_clang_static_analysis/test_clang_static_tool.py \
  tests/unit/job_clang_static_analysis/test_contract.py \
  tests/unit/job_clang_static_analysis/test_seeded_clang_static.py
```

Collection used that same fresh private wrapper directory, removed `-n 2`, and added `--collect-only`; this sequential wrapper reuse is explicitly allowed by the updated brief. Collection **37**, **1.413 s** supervised; execution **37 passed**, **3.33 s pytest / 7.104 s supervised**; wrapper total **8.882 s**, exit **0**. No skips/errors/failures/slow tests. Worker collection proofs and process cleanup confirmed.

Retained artifacts, all under the authorized checkout:

```text
test/tmp/logs/tests-custom-20261118-123921-579658-2954286.log
test/tmp/logs/tests-custom-20261118-123921-579658-2954286.collection.log
test/tmp/tests-custom-20261118-123921-579658-2954286.collection.json
test/tmp/tests-custom-20261118-123921-579658-2954286.junit.xml
test/tmp/tests-custom-20261118-123921-579658-2954286.timings.sqlite
test/tmp/reports/tests-custom-20261118-123921-579658-2954286.json
```

### Offline reproduction invocations

Each used **`.venv/bin/python - <<'PY' ... PY`** through the same transport, actual job/wrapper functions and the already-inspected `tests.unit.job_clang_static_analysis.support` / `tests.seeded_clang_support` fake executors. No test or fixture source was edited. Input/output files were confined to the following newly created private roots and removed in `finally`.

| Invocation / private root | Exact exercised functions and fake boundary | Result / timing |
|---|---|---|
| R1–R5 attempt; `test/tmp/job-audit-clang22-repro-a-20261118` | `driver.analyze` with patched `subprocess.run`; `_text_diagnostics`, `_plist_diagnostics`, `_location`, `_read_output`; seeded `_analyze_scope` with all-unit fake failures | R1–R4 evidence printed. **Auditor script failed**, `sqlite3.OperationalError: no such column: reason` when reading coverage for R5; schema actually uses `gap`. Root cleaned. Elapsed not recorded; not represented as a passed check. |
| R5–R8; `test/tmp/job-audit-clang22-repro-b-20261118` | Same seeded handler, query corrected to `SELECT status,gap FROM coverage`; `StaticExecutor(fail=(("tidy","net"),("tidy","util"),("analyze","net"),("analyze","util")))`; `StaticExecutor(report_units=False, diagnostics={})`; raw JSON changed before retry; `ScopeSeeds`/`SeedPlan` replaced with same selected keys plus new counts | Exit 0, **0.195 s**. R5 partial/zero observations/unresolved=2; R6 resolved=2/checkpoint; R7 cache reused/no calls; R8 stale over-limit=1 vs expected6/no calls. |
| R9–R11; `test/tmp/job-audit-clang22-repro-c-20261118` | Real `SharedArtifacts` owner/claim + `_analyze_scope`; delete only its scratch native object; `verify_native_reference` then retry; assembly-only `IndexScope` through real analyze/publish and `shard_owner`; plist with257 pieces through real parser and wrapper `main` with analysis boundary fake | Exit 0, **0.194 s**. Native verifier rejected missing object but cache reused; NA summary/coverage discrepancy; trace retained256, `truncated=false`, no parse gaps. |
| R1–R4 assertions rerun; `test/tmp/job-audit-clang22-repro-d-20261118` | Real driver with intercepted subprocess options; text/plist trace parsers; `_location`; `_read_output` | Exit0, **0.008 s**. Four explicit assertions confirmed ignored cwd, trace loss, exact EOF mapping and uncaught optional-span TypeError. |

R8's decisive calls, preserving the counterexample independently of test harness output:

```python
# r is the initial Run with seed_limit=1; old is r.scope_seeds.
changed = seeding.ScopeSeeds(old.scope_id, old.seeds, old.total + 5, old.dropped + 5)
plan = seeding.SeedPlan({old.scope_id: changed}, not_in_database=3, unlocated=2)
run = seeded.Run(r.settings, plan, changed, r.hood)
ex = sc.StaticExecutor(st.run_root)
second = job._analyze_scope(u, s, lambda _: ex, run)
# Observed: second["checkpoint_reused"] is True; ex.calls == [];
# status_counts stayed {"over_limit": 1, "resolved": 1}.
```

Other read-only command issues: WSL `rg` was unavailable during initial inventory, so that command exited127; searches switched to the provided UNC ripgrep tool. Three guessed package-directory searches (`interchange`, `provenance`) failed because these are single `.py` modules; the actual modules were subsequently read. One line-number output exceeded tool-display size; evidence was already available from bounded source reads. These are audit-tooling issues, not test failures or repository defects.

## Read coverage and material gaps

**Read fully:**

- Authorized `AGENTS.md`, coordination skill, shared audit brief.
- All four job source files (`__init__.py`, `job.py`, `seeded.py`, `datasets.py`).
- `jobs/cpp_index_scopes.py`, `jobs/cpp_seeded.py`, `jobs/engineering_contracts.py`.
- `config/seeding.py`, `seeding/plan.py`, `seeding/units.py`, `seeding/ledger.py`.
- Wrapper `containers/tools/clang-static-analysis/clang-static.py`, Dockerfile and tool manifest.
- Canonical job operations page, Clang architecture page, older operating page, seeded-neighborhood architecture.
- All four mapped unit files, their `support.py`, `tests/seeded_clang_support.py`, root and unit-tier conftests, unit-environment guard.
- `storage/verify.py`, `runtime/execution_safety.py`, `runtime/datasets.py`, `scripts/run-tests.sh`, `scripts/lib/common.sh`; wrapper report JSON.

**Sampled / exact relevant sections:**

- Central TOML, tool catalog, registry, topology implementation and evaluated predecessor result.
- `runtime/consume.py`, `runtime/inputs` entry-point usages, `interchange.validate_unit_output`, provenance retention/verifier, shared publication/context helpers, retrieval context-manifest/index builder, `indexing/store.py`.
- CPP compile normalization and seeded IR fake-fixture path; LLVM parser searched to verify its demangler is in-process, not a subprocess tool.
- Graph diagnostic consumer, review source-SAST selector and downstream typed declarations.
- Run-tests Python command/collection/worker/supervision paths, test-map entry, TODO relevant matches/sections, historical reports and relevant Git history.

**Material unread/unverified scope:**

- No installed image inspection, LLVM checker availability, package closure validation, real Tidy/CSA diagnostic capture, target build, or live output-quality comparison.
- No full accepted-handoff claim/read-receipt lifecycle, final `JobRunner` publication, downstream retrieval authorization or integration/acceptance run. R9 establishes the local cache defect only; later integrity gates were not bypassed or certified.
- No complete audit of shared storage/signing/resource/admission implementations or all consuming jobs; only immediately relevant functions were inspected.
- Full raw recorded IR/AST/CFG corpus bytes, `.clang-tidy` behavior, nested plist call-event variants and scale/resource-limit behavior were not independently validated.
- Supplemental shared tests outside the four mapped job unit files were not run.

Final source check remained clean at the exact requested SHA. Only this session report and permitted ignored test artifacts were created; the four reproducer directories were removed. No repair, TODO edit, commit or integration handoff is claimed.
