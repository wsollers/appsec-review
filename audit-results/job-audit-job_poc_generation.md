# Job 39/47 audit — `job_poc_generation`

## Scope and verdict

- **Revision:** `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`, clean `main`, `/home/wsollers/projects/appsec-review`, Ubuntu-22.04 through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu`.
- HEAD and cleanliness were checked before testing, before the repro, and after cleanup. The editable import resolved to `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`. The different Windows checkout was not audited or tested.
- This is a **functional source audit**, not an exploit-development or penetration-testing exercise. No actual provider, compiler, generated function, target program, container, service, integration test, acceptance test, or live review was run. No shared source/configuration/environment installation or modification, subagent, commit, push, or service operation occurred.
- **Result:** ten medium-severity functional findings below, each supported by source and a bounded offline reproducer. Several distinct defects concern existing C/C++ behavior, not the already-deferred nine-language implementation. The 121 selected existing unit cases passed; they do **not** establish exact correctness or live output quality.
- A direct all-seven-handler probe used the real writer loop with canned harmless `sink()` function text, fake review admission, fake build lookup, and a fake executor that only returned JSON/text or wrote inert object placeholders. It reproduced lost gaps and a publication failure for a rejected name. It did not constitute a `JobRunner`/admission/integration run.

## Registration, intended contract, and configuration

`runtime/registry.py:109,180` registers the builder. `job.py:51-58,395-410` declares the seven units and installs the typed contract/datasets. `datasets.py` declares `REVIEW_GRAPH`, accepted-evidence target access, `always_execute=False`, propagation enabled, and scheduling after inference review. Graph dependencies also include consumed producers, not only that scheduling hint (`orchestration/topology.py:47-81`).

The dev recipe enables the job (`appsec-review.toml:3563-3573`). The important distinction is **`build.compile_check = false`** (`appsec-review.toml:3652-3657`): static checks and the Clang AST policy still run for admitted native candidates, but the three project compile replays do not. A policy-passing candidate is then `artifact_generated` with an explicit reason, never `compile_verified`. Disabling the job removes it from automatic graphs; the specifically allowed manual PoC dispatch and authenticated final-gate admission remain distinct from enabling it.

Intended inputs:

1. Required accepted inference-review and language-build **handoffs** (`datasets.py`). Typed optional payload declarations cover review scope/packages/cells/ledger/chains/scores/findings and build receipts/commands/workspaces.
2. Optional original-producer source/context declarations from `bound_artifacts.source_context_inputs`: catalog; Tree-sitter; compiled analysis; C++ symbols; SVF; code graph; CodeQL; collected/Clang/CPG/CI/artifact/binary observations; dependencies; priorities; tags; and review-data cross-domain/precomputed products.
3. The actual candidate producer (`job_inference_security_review/stages.py:738-775`) selects `supported` **or** `confirmed` findings, configured risk ratings, resolved nonempty entry/path basis, and `red_correct`/optionally `partly`, or `not_convened`. This job does not independently create confirmed findings. The current accepted-verdict list is `["red_correct", "not_convened"]`.
4. Shared accepted-review verification re-proves package manifests, ledger/projection, finding/score identities and judge agreement; `candidates.py` additionally requires exact candidate keys, bounded typed identities, canonical basis digest, unique claims/evidence, and matching finding digest/claim/state/evidence. Missing `poc_candidates` is an integrity error; an explicitly empty list is valid.
5. Planning also requires a usable trigger, a bound review package, a named sink, a native accepted workspace/compile mapping, and at least one basis entry/path identity resolving in the bounded view. No target checkout is substituted.

Key configured bounds: 16 candidates, one candidate worker; writer 32,000 input/8,000 output tokens, eight queries, six turns, 600-second shared execution deadline, two attempts; 80 lines/function, 16 KiB/source file, 12 includes; 4,096 loop iterations; 65,536 array elements; 20,000 workspace files/1 GiB; 512 object outputs; 128 KiB brief. F04–F07 identify specific bounds/normalization failures; other limits are not assumed absent.

`writer.py:202-338` passes token/model settings into `ReviewModelRequest` and `Execution`, accepts only retrieve/final turns, allows at most three requests per turn, bounds source windows/responses, counts denied queries, ends repeated identical denials, and applies typed retry policy. `inference/execution.py:243-310` checks request/response byte ceilings, reported token ceilings and deadline. The model has no external tools: `read_source` and `find_declaration` are application-mediated reader operations.

Guidance selection is `poc_writer` / `write_poc_function`, no persona or stack, through `guidance/workers.py:54-55,97-179`, shared governing rules, role text, registered runtime skill, and hash-pinned bundle publication. `poc_designer` and `poc_verifier` are not dispatched. Runtime guidance was inspected as data, not followed as auditor instructions.

## Every declared step/task

| Step / task | Actual handler and dispatch | Processing / output / observed limit |
|---|---|---|
| `load.verify_inputs` | `job.py:154-199` | Shared accepted-review verifier; exact claimed review digest; confirmed-first/claim-ID ordering; bounded planned prefix and complete omitted IDs; accepted build digest when planned work exists; immutable `inputs.json`. Required handoffs may reject before this handler. |
| `plan.briefs` | `job.py:206-230`; `_plan_candidate:422-470` | Verdict/basis/package/sink checks; merge hunt unit context; locate accepted native build; construct bounded package view and declaration/build brief. Terminal `not_applicable` or `insufficient_evidence` outcomes avoid the writer. F01/F02/F06 apply. |
| `write.poc_writer` | `job.py:233-273`; `writer.py:202-338` | No pending work means no inference. Otherwise bounded thread pool, pinned guidance, closed writer response or decline, protected write result and per-claim hash/count receipt. Retrieval declaration bytes are not actually verified: F02. |
| `validate.policy` | `job.py:276-304`; `_validate_candidate:473-542` | Preserve prior terminals/declines/failures; assemble source; textual refusal; static preflight `/2`; prepare accepted-workspace scratch; fake/production executor boundary for reduced Clang AST; parse failure vs unavailable vs policy verdict. F03/F04/F07/F08/F10 apply. Accepted-byte integrity errors are intended to propagate. |
| `compile.build_check` | `job.py:307-328`; `_compile_candidate:551-581`; `buildcheck.check_build:304-393` | Preserve previous terminals; disabled replay gives generated-only gap. Enabled replay derives syntax/plain-object/sanitized-object commands, hashes objects, and checks the **plain** object's undefined symbols against project/runtime symbol listings. Never links or runs generated functions. F05/F09 apply. |
| `package.files` | `job.py:331-346`; `_package_candidate:584-634`; `package.write_candidate:104-128` | One row per planned claim; immutable attempt-owned source/compile/README/provenance for source-bearing statuses; preserve finding state/judge/hash. F09 loses qualifications; F10 uses a rejected model name as a filename. |
| `publish.publish_handoff` | `job.py:349-393` | Rehash review bindings, re-read admitted review identity, construct ordered candidate rows and exact status counts/omissions, validate summary schema, publish `/2`. F09 reports clean success despite nested gaps; F10 turns a policy refusal into a failed publication. |

The unit dependency graph is explicit, and configuration validation checks exact step/task names and order. A per-candidate exception escaping a pool fails that whole unit rather than inventing an outcome for the candidate; dependent units then skip (`runtime/units.py:83-155`).

## Findings

Paths below are repository-relative. `POC-F01`–`POC-F10` are **medium**, high-confidence static/offline findings; none is a claim of exploitability or runtime reproduction.

### POC-F01 — Build lookup stops at an unrelated workspace containing the same source

- **Evidence:** `src/appsec_review/jobs/job_poc_generation/buildctx.py:232-240`; consumer outcome `job.py:451-454`.
- **Trigger:** two successful native receipts contain the same source path in their workspace manifests, but only the later receipt compiled it. Shared whole-repository workspaces need not have identical compiled-unit sets.
- **Expected / actual:** search the remaining accepted native receipts for a covering compile command; instead the first missing command returns `no_compile_command` immediately.
- **Reproduction:** two synthetic manifests/compile databases, inert workspace only: both receipts together returned `no_compile_command`; the second receipt alone returned `found`, `build-unit-2`.
- **Impact:** an eligible candidate becomes `not_applicable`, although a usable accepted build exists. The same helper is imported by remediation planning; that consumer was not separately audited here.
- **Smallest correction:** retain the missing-command reason while continuing the receipt search; return it only after all eligible receipts are exhausted.
- **Overlap:** no matching TODO/prior report found. Existing accepted-gapped-build work is different: this repro uses `SUCCEEDED` receipts.

### POC-F02 — Declaration retrieval is not hash-verified accepted-source retrieval

- **Evidence:** `src/appsec_review/jobs/job_poc_generation/buildctx.py:428-440`; brief use `brief.py:99-110`; writer finder `job.py:251-255`, `writer.py:374-375`. Compare the explicit hash check in `writer.py:354-368`.
- **Trigger:** a header listed in the accepted workspace manifest changes before planning or a declaration request.
- **Expected / actual:** rehash the bytes against the manifest before returning any source; `declarations` checks size and decodes current text, but never compares its hash or rejects a substituted symlink.
- **Reproduction:** a synthetic accepted header originally contained `void sink();`; after changing only this private fixture to `void sink(int changed);`, declaration lookup returned the changed line while `WorkspaceReader.read_source` returned `None`.
- **Impact:** the brief/model can consume unaccepted declarations under accepted-build provenance. Later workspace materialization may catch the change, but that does not undo the already-commissioned model input; a decline need not reach materialization.
- **Smallest correction:** share the verified-byte reader across source and declaration lookup, fail on an accepted-byte mismatch, and derive lines from those verified bytes.
- **Overlap:** distinct from the shared **CC-07** payload-observation limitation; this is an absent byte-integrity check, not just absent consumption telemetry. No exact TODO found.

### POC-F03 — A sink reference counts as a sink call

- **Evidence:** `src/appsec_review/jobs/job_poc_generation/policy.py:278-297,314-319,342-350,501-506`.
- **Trigger:** a function merely references the allowed sink (for example a discarded function-address expression), without a call expression.
- **Expected / actual:** each of the two functions must actually call the sink; `function_reference` increments `sink_hits` for any matching declaration/member reference.
- **Reproduction:** a small, inert reduced-AST dictionary with two function bodies containing only sink `DeclRefExpr` nodes, **zero call nodes**, returned `violations: []`.
- **Impact:** deterministic policy can pass a harness/control that does not exercise the required function. This is weaker than the documented call check even before considering runtime behavior.
- **Smallest correction:** count only resolved callees of actual call nodes; leave reference allowlisting separate.
- **Overlap:** T-174 tracks broader syntax/semantic work, but this is an existing C/C++ sink-call checker defect, not the already-named non-C++ lexical limitation. No exact prior finding found.

### POC-F04 — Loop bounds ignore direction and inclusive endpoints

- **Evidence:** `src/appsec_review/jobs/job_poc_generation/policy.py:436-450,454-474`.
- **Trigger:** an inclusive comparison at the configured iteration cap, or a step direction inconsistent with the comparison.
- **Expected / actual:** prove a finite bound using initial value, comparison and signed step; the helper checks only that the step references the variable and returns `abs(limit - initial)`.
- **Reproduction:** synthetic AST for start 0, `<= 4096`, increment gives computed bound **4096**, although that finite loop has **4097** iterations. Substituting a decrement in the AST still returns 4096. No loop or generated source was executed.
- **Impact:** accepted policy does not enforce its stated loop cap or establish the claimed bounded progression.
- **Smallest correction:** compute the count with comparison inclusivity and signed step, reject incompatible/non-reaching progressions and uncertain body mutation/overflow rather than declaring a finite bound.
- **Overlap:** broad T-174 semantic scope; no exact loop-bound TODO or prior finding found.

### POC-F05 — Configured workspace and symbol-scan breadth limits are not honored

- **Evidence:** workspace limit is parsed in `settings.py:216-218` but the default `AcceptedBuilds` uses 100,000 (`buildctx.py:131-137,300-304`); `job.py:113` constructs it without the configured file limit; `buildcheck.py:256-262` forwards only the byte limit. Object limit: `buildcheck.py:353-366`.
- **Trigger:** a workspace above `build.workspace_file_limit` but below the loader's unrelated default; or a symbol list whose final chunk crosses `build.object_limit` (the object/shared-library lists also each get a separate allowance).
- **Expected / actual:** enforce the configured total bounds; workspace copying ignores the configured file bound, while the last symbol chunk is sliced through `chunk_start + 256` rather than the admitted prefix.
- **Reproduction:** configured file limit 1 copied all **5** accepted files, plus two job-created scratch files; loader limit remained 100,000. Configured object limit 1 passed all **3** object paths to the fake `nm` call, while recording “only the first 1 accepted outputs were read.”
- **Impact:** excess copying/scanning and inaccurate omission receipts. The separately enforced byte cap does not make these file/object limits effective.
- **Smallest correction:** pass the actual workspace limit to materialization; preselect one deterministic bounded object/shared-library prefix, then chunk that prefix and record exact omitted counts.
- **Overlap:** no exact TODO/prior finding found; not covered by T-147's missing task-binding metadata.

### POC-F06 — `max_brief_bytes` is not an enforced bound

- **Evidence:** `src/appsec_review/jobs/job_poc_generation/brief.py:130-135,152-161`.
- **Trigger:** a configured small brief budget, or large retained declarations/source after the first trim.
- **Expected / actual:** bound the final serialized brief, or return an explicit inability-to-fit outcome; the function only filters some package-view keys once and never measures the resulting document again.
- **Reproduction:** valid settings with `max_brief_bytes=400` returned a **7,917-byte** brief whose gap claimed the view was reduced to fit. The oversized `source` key is specifically retained by `_trimmed`.
- **Impact:** configured bounded prompts are not respected; the independent inference request cap can subsequently reject the oversized request instead of producing an appropriately bounded brief.
- **Smallest correction:** budget all sections and remeasure after deterministic truncation; do not claim it fits unless it does.
- **Overlap:** not T-5079, which concerns reported output/thinking token caps. The existing trimming unit test asserts the gap text, not the final byte bound.

### POC-F07 — Valid numeric trigger text can crash validation or invert its meaning

- **Evidence:** `src/appsec_review/jobs/job_poc_generation/policy.py:85,125-144`; `brief.py:31-41`; `job.py:533-545`.
- **Trigger:** a decimal with leading zero, or a negative numeric constraint, in the accepted bounded trigger string.
- **Expected / actual:** parse the stated integer or explicitly qualify it as unchecked; decimal text is passed to `int(..., 0)` and the regex omits a sign.
- **Reproduction:** `numeric_requirement("at least 08")` raised `ValueError: invalid literal for int() with base 0: '08'`; `"exactly -1"` became `operator="=="`, `low=1`.
- **Impact:** a candidate can fail the whole validation unit, or be checked against the opposite value. `_expectation` is outside the build-unavailability exception block.
- **Smallest correction:** parse signed decimal as base 10 and explicit hex as base 16; unsupported syntax must produce a retained qualification, not an uncaught parsing error.
- **Overlap:** broad T-174 semantic scope; no exact TODO/prior finding found.

### POC-F08 — AST replay drops separated `-D` and `-U` flags

- **Evidence:** `src/appsec_review/jobs/job_poc_generation/buildcheck.py:43-46,121-138`.
- **Trigger:** a captured valid command uses `-D FEATURE=1` or `-U OLD`, rather than attached forms.
- **Expected / actual:** preserve the accepted command's preprocessor context; neither flag is in `AST_VALUE_FLAGS`, while the attached-form regex requires a value on the same token.
- **Reproduction:** deriving the AST argv from `g++ -D FEATURE=1 -U OLD -c /workspace/src/demo.cpp` returned only `clang++` plus the syntax/AST-dump/source arguments, with both settings absent.
- **Impact:** the policy parser sees different declarations/branches, potentially reporting `compile_failed` for otherwise valid generated functions or examining a different conditional API. This also affects the default compile-replay-disabled path because AST validation still runs.
- **Smallest correction:** preserve and validate separated define/undefine operands, with focused equivalence tests against attached forms.
- **Overlap:** no exact TODO/prior finding found. No real compiler was used to demonstrate a consequent parse failure; the argv loss itself is reproduced.

### POC-F09 — Nested compile/brief qualifications disappear from published coverage

- **Evidence:** `src/appsec_review/jobs/job_poc_generation/job.py:365-367,467,541-542,590-612`; downstream `src/appsec_review/jobs/job_final_publication_gate/attachments.py:145-148,315-320`.
- **Trigger:** compilation passes with an explicit compile-record gap, or the accepted brief/validation has unchecked-trigger qualifications.
- **Expected / actual:** preserve compile assurance separately from gap-bearing coverage; the row copies only `validated["gaps"]`, and summary gaps are selected by terminal status. Compile-record gaps and `brief_gaps` are not aggregated; unchecked triggers remain only in the intermediate validation output.
- **Reproduction:** the real seven-handler flow with fake external edges produced `compile_verified`, row `gaps=[]`, summary `gaps=[]`, and `terminal_status="SUCCEEDED"` while packaged `compile.json` contained a nonempty symbol-scan gap. Its validation output contained `unchecked_triggers=["non-numeric condition"]`, absent from packaged compile fields.
- **Impact:** final-gate gap counting sees neither `compile_verified` in its gapped-status set nor top-level gaps, so the nested limitation does not inform capability coverage. The final gate checks compile schema/status/claim, not aggregation of these nested gaps. Static downstream trace, not an executed gate integration.
- **Smallest correction:** aggregate/deduplicate bounded brief, validation and compile qualifications into the row/summary; retain full diagnostic detail in protected receipts. Keep `compile_verified` if appropriate but use `COMPLETED_WITH_GAPS` and expose the limitation.
- **Overlap:** analogous to prior jobs' lost-gap findings but this is the PoC-specific path. T-174 already acknowledges the limits of lexical checks; that does not justify discarding actual emitted qualifications.

### POC-F10 — A rejected function name can fail publication instead of yielding `policy_denied`

- **Evidence:** `src/appsec_review/jobs/job_poc_generation/job.py:487-494,598-602,626-634`; `package.py:40-41,114-126`; artifact-path schema `docs/schemas/poc-generation/common.schema.json` (`run_path`).
- **Trigger:** a schema-valid but policy-invalid function name containing an ordinary space, such as `poc bad`.
- **Expected / actual:** retain a terminal `policy_denied` candidate and inert source under an application-chosen safe filename; source-bearing refused answers are packaged using the rejected model name verbatim.
- **Reproduction:** the real seven-handler canned-response flow correctly refused the name, then wrote a private `poc bad.cpp`; final summary schema validation failed its path, leaving job `FAILED`, `failed_units=["publish.publish_handoff"]`, and no published summary.
- **Impact:** one ordinary malformed writer answer prevents publishing all candidate outcomes, contrary to terminal policy-refusal behavior. No traversal, external write, or executable payload was attempted.
- **Smallest correction:** use a fixed/application-derived source filename for refused names, preserving the original answer as data. Do not turn this into model “repair around policy.”
- **Overlap:** no matching TODO/prior finding found.

## Publication, receipts, and downstream expectations

Three declarations match the real attempt tree:

| Dataset | Disposition / owner | Actual artifacts |
|---|---|---|
| `poc_generation_summary` | artifact-only; `publish`; handoff `/2` | load/validate/compile trees, package aggregate, publish tree |
| `poc_writer_cells` | protected; `write`; receipt `/1` | plan briefs and write/receipt results |
| `poc_reproducers` | protected; `package`; provenance `/2` | candidate source, compile JSON, README, provenance |

These nominal dataset schema labels are not claims that every matching source/raw/intermediate file is that JSON schema. Protected and artifact-only inventory routes expose sanitized metadata, not generic payload access. The writer receipt stores answer **hashes**, turn hashes, counts and usage; the answer itself is in protected `write.json`. `policy_denied` source remains inert data.

The handler explicitly validates writer-answer, static-check and summary schemas. Nested compile/provenance checks also occur at final-gate consumption (`attachments.py:95-160`). Producer unit controls use the existing closed terminal vocabulary; this legacy job does not enable `strict_gaps`, and its human-readable strings are handled by the existing runtime compatibility path. No new status vocabulary is introduced by candidate statuses.

`indexing.store.accepted_handoff` delegates to `runtime.consume.accepted_upstream`, so attempt pins and typed envelope permission are enforced; a moved latest pointer can still select the claim-pinned historical handoff. Thus the handler's accepted-review comparison is not an independent assertion that the live latest pointer never advanced. Publication/runtime acceptance and stale-attempt rejection were not exercised end-to-end.

**Known shared limitation, not counted as a new finding:** bound JSON/build payload readers do not universally call `observe_output`; accepted-envelope observations and observed retrieval shards are not proof of every payload read or model citation. This matches **CC-07** and `docs/architecture/job-input-contracts.md:130-134`. The direct handler tests bypass full runtime admission/read-observation scopes, so they do not establish complete protected dataset receipts.

The final gate:

- requires exact candidate-plus-omission partition and status counts;
- compares candidate finding/state/judge/basis/package identities;
- verifies review/build digest bindings and nonexecution fields;
- validates source-bearing provenance/compile records and rehashes nested references;
- projects status, function names and file references, not executable source or runtime proof.

Dossier inputs similarly bind accepted PoC rows and exact finding/count identities (`job_dossier_publication/inputs.py:64-133`); remediation planning imports the build helper, not a PoC finding-state upgrade. Final report construction reads gate-certified PoC attachments (`job_final_report_publication/report.py:76-126`), not later optional discoveries.

Nonexecution is implemented at the inspected paths: settings/static checks reject execution requests; every `buildcheck.run_step` invokes the command guard; actual derived commands are the AST reducer around Clang, syntax/object compiles, and `nm`. `Services.executor` uses the accepted pinned image and `network="none"`. The production executor uses the image ID as the Docker image, configured verification, read-only root, dropped capabilities and no-new-privileges (`container_runtime/build_executor.py:407-505`). **No actual image/signature/broker/compiler execution was validated here**, and this audit does not certify every arbitrary argv accepted by the generic guard as safe.

`compile_verified` remains strictly compile-only. The static helper reports `compiler_verified=false`, `runtime_verified=false`; non-Python syntax is `null`, and only Python uses `ast.parse`. The actual job still admits native C/C++ only. The negative control's runtime safety and the relation between a numeric literal and the actual triggering argument are not established by these checks. **T-174** already tracks the broader missing semantic/nine-language work; **T-175/T-026** do not authorize executing generated functions.

## Existing work, documentation drift, and test gaps

- **T-174:** explicitly in progress after reopening; nine-language parsing/semantic checks and unified eligibility remain undelivered. Do not describe the nine-language lexical helper as nine-language generation or compilation.
- **T-175:** blocked; dynamic execution/sandbox approval is not part of this audit.
- **T-026:** dynamic evidence is deferred and separately authorized.
- **T-5057:** usable hunt proof-of-trigger bases remain an upstream known gap.
- **T-5079:** writer output/thinking-token caps are already tracked; this audit did not call a model.
- **T-147:** exact declarative task/tool bindings remain open; actual dispatch was traced instead.
- **T-113:** its historical PoC coverage paragraph says `record.candidates`; actual topology is `package.files`. Its old case/coverage totals are not this audit's results.
- The prior cumulative and per-job reports were keyword-searched. The previously recorded shared payload-observation class was preserved rather than counted again. Local all-branch history searches found the original loop implementation and later known PoC/build changes, not a verified fix for these repros at the authorized HEAD.

**POC-D01 — Low, documentation drift (separate from the ten functional findings):** `docs/operations/poc-generation.md:38-39` describes unconditional compile passes despite the current default disabling replay; `:244` shows only `["red_correct"]`, omitting `not_convened`; `:148` describes the receipt as holding the answer rather than its hash. The canonical `docs/operations/job_poc_generation.md` is more accurate about compile disabling/static assurance. Reconcile the secondary operator guide; do not change behavior to match its stale prose.

**Selection gaps:** `tests/job-test-map.json:517-531` omits `tests/unit/job_poc_generation/test_t174_t175_poc_compile_and_gate.py`, which was nevertheless inspected and run. Most `tests/test_poc_writer.py` tests and workspace-backed `tests/test_poc_generation_units.py` tests use `tests/poc_support.py:56-69`, which prefers a host target checkout if present. Those fixtures were **not invoked**: this audit used the always-canned direct unit fixtures and a separate harmless fake-reader/writer probe. One compile/provenance contracts test using that fallback was deliberately deselected. This is not evidence those unrun tests pass or fail.

## Focused validation — exact commands and results

All Linux commands below ran in `/home/wsollers/projects/appsec-review`, carried through the brief's UTF-8/base64 PowerShell-to-SSH transport. Every pytest invocation had private scratch; maximum worker count was two. No shared environment variables were changed to make tests pass.

### 1. Identity/environment preflight

```bash
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
.venv/bin/python - <<'PY'
import os
from tests.test_000_unit_environment_guard import offending_environment
print('UNIT_ENV_OFFENCES', offending_environment(os.environ))
assert not offending_environment(os.environ)
PY
```

Correct source import; `UNIT_ENV_OFFENCES []`. The wrapper's normal xdist environment guard also completed without refusal.

### 2. Explicit inspection collection

```bash
.venv/bin/python -m pytest --collect-only -q -n 0 \
  --basetemp=test/tmp/job-audit-poc-collect-20261118-01 -p no:cacheprovider \
  tests/test_poc_policy.py \
  tests/unit/job_poc_generation/test_job_units.py \
  tests/unit/job_poc_generation/test_brief_inputs_and_helpers.py \
  tests/unit/job_poc_generation/test_t174_t175_poc_compile_and_gate.py \
  tests/test_poc_generation_contracts.py \
  tests/test_poc_writer.py::test_the_guidance_is_the_shared_rules_the_role_and_the_runtime_skill_only \
  tests/test_poc_writer.py::test_the_skill_is_loadable_only_by_this_job \
  -k 'not test_the_compile_record_and_provenance_written_by_the_job_satisfy_their_schemas'
```

Exit **0**: **121/122 selected**, one intentionally deselected, **2.04 s** pytest collection time. One `PytestConfigWarning: Unknown config option: cache_dir` resulted from disabling cacheprovider. No test executed during this inspection.

### 3. Wrapper refusal, then normal wrapper execution

The first wrapper command was exactly the next command **plus trailing `-p no:cacheprovider`**. It exited **2**, before collection/execution, with:

```text
error: unsupported focused pytest option '-p'; scope/report/worker options belong to run-tests
```

Elapsed time for that rejected command was not instrumented. Nothing was bypassed or installed; the retry removed only the unsupported option.

```bash
bash scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 3939 \
  --max-tests 121 --expect-tests 121 --timeout-seconds 180 --strict -- \
  tests/test_poc_policy.py \
  tests/unit/job_poc_generation/test_job_units.py \
  tests/unit/job_poc_generation/test_brief_inputs_and_helpers.py \
  tests/unit/job_poc_generation/test_t174_t175_poc_compile_and_gate.py \
  tests/test_poc_generation_contracts.py \
  tests/test_poc_writer.py::test_the_guidance_is_the_shared_rules_the_role_and_the_runtime_skill_only \
  tests/test_poc_writer.py::test_the_skill_is_loadable_only_by_this_job \
  -k 'not test_the_compile_record_and_provenance_written_by_the_job_satisfy_their_schemas'
```

Exit **0**: **121 passed, zero failed/error/skipped, zero >10 s**. Pytest **6.28 s**; wrapper **14.682803512 s** total; wrapper supervised collection **3.557350767 s**, supervised execution **10.765577560 s**. Both cleanup confirmations were true with zero remaining owned processes.

Wrapper-owned identity: `tests-custom-20261118-133746-548682-3477610`.

Retained relative evidence:

- `test/tmp/reports/tests-custom-20261118-133746-548682-3477610.json`
- `test/tmp/logs/tests-custom-20261118-133746-548682-3477610.log`
- `test/tmp/logs/tests-custom-20261118-133746-548682-3477610.collection.log`
- `test/tmp/tests-custom-20261118-133746-548682-3477610.junit.xml`
- `test/tmp/tests-custom-20261118-133746-548682-3477610.timings.sqlite`
- `test/tmp/tests-custom-20261118-133746-548682-3477610.collection.json`
- the corresponding `.processes` collection-proof/supervision directory.

### 4. Bounded offline defect probe

Command: `.venv/bin/python - <<'PY'` with the complete body below, following the same HEAD/clean checks. Exit **0**, measured probe body **0.785 s**. All synthetic files were created below `test/tmp/job-audit-poc-repro-20261118-01` and removed in `finally`. The observed defects are printed results, not claims that failing regression tests passed.

```python
import copy, hashlib, json, shutil, time, tomllib
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from appsec_review.jobs.job_poc_generation import brief, buildcheck, buildctx, job, policy, writer
from appsec_review.jobs.job_poc_generation.candidates import parse_candidates
from appsec_review.jobs.job_poc_generation.inputs import VerifiedInputs
from appsec_review.jobs.job_poc_generation.settings import PocGenerationSettings
from appsec_review.jobs.job_poc_generation.source import WriterAnswer
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.inference import ModelResult
from appsec_review.storage import canonical_json, atomic_json
from tests.unit.job_poc_generation.test_job_units import _job_context
start = time.perf_counter()
root = Path('test/tmp/job-audit-poc-repro-20261118-01').resolve()
root.mkdir(parents=True, exist_ok=False)
repo = Path.cwd()
raw = tomllib.loads(Path('appsec-review.toml').read_text())['jobs']['job_poc_generation']['settings']
settings = PocGenerationSettings.from_mapping(raw)
claim = 'claim-' + '1'*64
package_id = 'finding_lead-' + '2'*64
basis = dict(entry=['asr:entry_point:'+'3'*64], path=['asr:call_site:'+'4'*64], trigger=[dict(field='value',where='argument',constraint='non-numeric condition',why='canned input')],input_format='integer',preconditions=['offline only'],expected_observation='benign result',unknowns=[])
cd = dict(claim_id=claim, package_id=package_id,state='confirmed',judge_verdict='red_correct',poc_basis=dict(brief=basis,sha256=hashlib.sha256(canonical_json(basis)).hexdigest()),finding_package=dict(finding_package_id='finding-'+'5'*64,sha256='6'*64),evidence_refs=[])
candidate = parse_candidates([cd])[0]
ws=root/'ws'; (ws/'include').mkdir(parents=True); (ws/'src').mkdir()
(ws/'include/demo.hpp').write_text('void sink();\n')
(ws/'src/demo.cpp').write_text('void sink() {}\n')
for n in range(3): (ws/f'obj{n}.o').write_bytes(b'inert object placeholder')
manifest={p.relative_to(ws).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in ws.rglob('*') if p.is_file()}
command=buildctx.CompileCommand(('/usr/bin/clang++','-I/workspace/include','-c','/workspace/src/demo.cpp'),'src/demo.cpp','cxx','.','exact')
build=buildctx.BuildUnit('build-unit-1','cmake','.','7'*64,ws,manifest,'8'*64,'fake:unit','sha256:'+'9'*64,'10001:10001',command,tuple(f'obj{n}.o' for n in range(3)),())
acc=buildctx.AcceptedBuilds(root,loader=lambda _: {'receipts':[],'language_build_handoff_sha256':'a'*64})
acc.locate=lambda _: buildctx.Located(build,'')
results={}
try:
    # Declared workspace file limit does not reach AcceptedBuilds.materialize.
    tiny=replace(settings,build=replace(settings.build,workspace_file_limit=1,object_limit=1))
    scratch=buildcheck.prepare(acc,build,root/'prepared',name='one',poc_text='void poc_one(){int x=0;}\nvoid poc_two(){int x=0;}\n',settings=tiny)
    results['workspace_file_limit']={'configured':1,'accepted_files':len(manifest),'copied_files':sum(p.is_file() for p in scratch.root.rglob('*')),'loader_limit':acc.file_limit}
    # Declaration lookup reads changed bytes, unlike read_source/materialize.
    (ws/'include/demo.hpp').write_text('void sink(int changed);\n')
    rows=buildctx.declarations(build,buildctx.Headers(build),['sink'],source_bytes=65536,max_files=4,max_lines=30)
    reader=writer.WorkspaceReader(ws,manifest,['include'],lambda name: buildctx.declarations(build,buildctx.Headers(build),[name],source_bytes=65536,max_files=4,max_lines=30))
    results['unverified_declarations']={'rows':rows,'read_source':reader.read_source('include/demo.hpp',1,1)}
    (ws/'include/demo.hpp').write_text('void sink();\n')
    # Byte cap is only a one-shot field filter, not a cap.
    view=SimpleNamespace(document={'labels':[{'label':'E1','ref':basis['entry'][0],'summary':'entry'},{'label':'C1','ref':basis['path'][0],'summary':'sink'}], 'source': ['x'*5000]})
    b=brief.build_brief(candidate,finding={'title':'benign'},package={},view=view,sink={'name':'sink','path':'src/demo.cpp'},unit=build,headers=buildctx.Headers(build),settings=replace(settings,brief=replace(settings.brief,max_brief_bytes=400)))
    results['brief_byte_limit']={'configured':400,'actual':len(canonical_json(b.document)),'gaps':list(b.gaps)}
    # AST references alone count as sink calls; no executable code is run.
    ref={'kind':'DeclRefExpr','referencedDecl':{'id':'sink','kind':'FunctionDecl','name':'sink'}}
    def fn(name, children): return {'kind':'FunctionDecl','name':name,'type':{'qualType':'void ()'},'inner':[{'kind':'CompoundStmt','inner':children}]}
    reduced={'schema':'appsec-review/poc-ast/1','source':'/workspace/.appsec-poc/poc.cpp','project_roots':['/workspace/'],'declarations':{'sink':{'name':'sink','qualified':'sink','kind':'FunctionDecl','file':'/workspace/include/demo.hpp'}},'project_declarations':[],'nodes':[fn('poc_one',[copy.deepcopy(ref)]),fn('poc_two',[copy.deepcopy(ref)])]}
    expected=policy.Expectation(('poc_one','poc_two'),('sink',))
    results['reference_not_call']={'call_nodes':0,'violations':[v.record() for v in policy.check_ast(reduced,settings,expected)]}
    # Finite inclusive loop exceeds cap by one but is accepted; bound direction also ignored.
    var={'kind':'VarDecl','id':'i','name':'i','type':{'qualType':'int'},'inner':[{'kind':'IntegerLiteral','value':'0'}]}
    iref={'kind':'DeclRefExpr','referencedDecl':{'id':'i','kind':'VarDecl','name':'i'}}
    init={'kind':'DeclStmt','inner':[var]}; cond={'kind':'BinaryOperator','opcode':'<=','inner':[iref,{'kind':'IntegerLiteral','value':'4096'}]}
    step={'kind':'UnaryOperator','opcode':'++','inner':[iref]}
    checker=policy._Checker(reduced,settings,expected)
    computed=checker.loop_bound(init,cond,step)
    results['loop_bound']={'computed':computed,'finite_inclusive_iterations':len(range(4097)),'configured':settings.bounds.max_loop_iterations,'reverse_step_computed':checker.loop_bound(init,cond,{**step,'opcode':'--'})}
    for constraint in ('at least 08','exactly -1'):
        try:
            r=policy.numeric_requirement(constraint)
            results.setdefault('numeric_constraint',{})[constraint]={'operator':r.operator,'low':r.low}
        except Exception as e: results.setdefault('numeric_constraint',{})[constraint]={'error':type(e).__name__,'message':str(e)}
    # Captured separated preprocessor flags disappear from the AST command.
    ast_argv=buildcheck.derive_ast(['g++','-D','FEATURE=1','-U','OLD','-c','/workspace/src/demo.cpp'],'cxx',buildcheck.Names('.appsec-poc','poc.cpp'),settings)
    results['separated_preprocessor_flags']=ast_argv[ast_argv.index('--')+1:]
    # Multiple build workspaces contain the source; only the second actually compiled it.
    multi=root/'multi'; multi.mkdir()
    def bound(name,doc):
        p=multi/name; p.write_bytes(canonical_json(doc)); return {'path':name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    workspace=multi/'workspace'; workspace.mkdir()
    mref=bound('manifest.json',{'files':{'src/demo.cpp':'b'*64}})
    def receipt(n,source):
        db=bound(f'commands{n}.json',{'schema':buildctx.COMPILE_DATABASE_SCHEMA,'rows':[{'tool_kind':'compiler','argv':['clang++','-c','/workspace/'+source],'inputs':[{'workspace_path':source}]}]})
        return {'build_unit_id':f'build-unit-{n}','family':'native','terminal_status':'SUCCEEDED','workspace_manifest':mref,'protected_compile_commands':db,'workspace':'workspace','image':{'image_tag':'fake:unit','image_id':'sha256:'+'9'*64,'user':'10001:10001'},'recipe':{},'artifacts':[]}
    receipts=[receipt(1,'src/other.cpp'),receipt(2,'src/demo.cpp')]
    lookup=buildctx.AcceptedBuilds(multi,loader=lambda _: {'receipts':receipts})
    together=lookup.locate('src/demo.cpp')
    later=buildctx.AcceptedBuilds(multi,loader=lambda _: {'receipts':receipts[1:]}).locate('src/demo.cpp')
    results['multi_build_lookup']={'all_receipts':together.code,'second_only':later.code,'second_build_id':later.unit.build_unit_id}
    # Drive real writer + units using only canned harmless functions and fake compiler/review edges.
    answer={'test_function':{'name':'poc_one','includes':['demo.hpp'],'source':'void poc_one() { sink(); }'},'negative_control':{'name':'poc_two','source':'void poc_two() { sink(); }'},'setup':['inert'], 'expected_observation':'benign result','breakpoints':[], 'notes':''}
    good_ast=copy.deepcopy(reduced); good_ast['compiler_exit_code']=0
    for node in good_ast['nodes']: node['inner'][0]['inner']=[{'kind':'CallExpr','inner':[copy.deepcopy(ref)]}]
    class Fake:
        def __init__(self): self.calls=[]
        def resolve(self): pass
        def execute(self,argv,*,workspace,working_directory,environment):
            self.calls.append(list(argv)); output=b''
            if argv[0]=='python3': output=json.dumps(good_ast).encode()
            elif argv[0]=='nm': output=b'sink U\n' if '-u' in argv else b'memset T 0 1\n' if '-D' in argv else b'sink T 0 1\n'
            elif '-o' in argv:
                dest=workspace/argv[argv.index('-o')+1].removeprefix('/workspace/'); dest.write_bytes(b'inert synthetic object')
            return SimpleNamespace(exit_code=0,timed_out=False,stdout=output,stderr=b'')
    fake=Fake()
    check=buildcheck.check_build(fake,acc,build,scratch,tiny,claim_id=claim)
    results['object_limit']={'configured':1,'project_objects_read':[x for call in fake.calls if call[0]=='nm' and '-g' in call for x in call if x.endswith('.o')],'status':check.status,'gaps':check.gaps}
    for name,bad_name in [('gapped_compile',False),('invalid_name',True)]:
        ctx=_job_context(root/name)
        table=copy.deepcopy(raw); table['build']['compile_check']=True; table['build']['object_limit']=1
        ctx=replace(ctx,config=replace(ctx.config,settings=table))
        pkgpath=ctx.run_root/'package.json'; atomic_json(pkgpath,{'package_id':package_id,'neighborhood':{'function':{'name':'sink','path':'src/demo.cpp','start_line':1}}})
        pref={'path':'package.json','sha256':hashlib.sha256(pkgpath.read_bytes()).hexdigest()}
        ver=VerifiedInputs('run-1',{'path':'review-handoff.json','sha256':'a'*64},{'path':'review.json','sha256':'c'*64},'SUCCEEDED','d'*64,'manifest.json',(candidate,),{candidate.finding_package_id:{'title':'benign','finding_package_id':candidate.finding_package_id,'sha256':candidate.finding_package_sha256,'state':'confirmed','label':'F1','lane':'lead','missing_predicates':[]}},{package_id:pref},bindings=())
        result=copy.deepcopy(answer)
        if bad_name: result['test_function']['name']='poc bad'; result['test_function']['source']='void poc_bad() { sink(); }'
        engine=Fake()
        producer=job.build_job(infer=lambda request,timeout_seconds: ModelResult(proposal={'action':'final','result':result},input_tokens=1,output_tokens=1),executor_factory=lambda *_:engine,builds_factory=lambda _:acc,core_factory=lambda *_:None,view_factory=lambda *_:view,repository_root=repo)
        with patch.object(job.review_inputs,'verify_inputs',return_value=ver), patch.object(job,'accepted_handoff',return_value=SimpleNamespace(path='review-handoff.json',sha256='a'*64)):
            outcome=producer.handler(ctx)
        entry={'job_status':outcome['status'],'failed_units':outcome.get('failed_units',[])}
        published=outcome['outputs'].get('publish.publish_handoff',{})
        entry['publish']=published
        if published.get('artifact'):
            summary=job.read_bound_json(ctx.run_root,published['artifact']); row=summary['candidates'][0]; record=job.read_bound_json(ctx.run_root,row['files']['compile'])
            entry.update(row_status=row['status'],row_gaps=row['gaps'],summary_gaps=summary['gaps'],compile_gaps=record['gaps'],compile_keys=sorted(record))
            validations=job.read_bound_json(ctx.run_root,outcome['outputs']['validate.policy']['artifact'])
            entry['validation_unchecked_triggers']=validations['entries'][claim].get('unchecked_triggers')
        else:
            entry['failed_publish_output']=outcome['outputs'].get('publish.publish_handoff')
        results[name]=entry
    print(json.dumps(results,indent=2,default=str))
finally:
    shutil.rmtree(root)
print('REPRO_SECONDS',round(time.perf_counter()-start,3))
```

### Cleanup

Removed only this auditor's two pytest base directories, their synthetic host-pins files, and the probe tree. Retained the wrapper log/JUnit/timing/collection/supervision/report evidence listed above. Final HEAD remained exact and `git status --short` was empty. No repository-root output was created.

## Read coverage and material unread scope

**Read fully:**

- Brief; authorized root `AGENTS.md`; canonical multi-session coordination skill.
- All 17 Python modules under `src/appsec_review/jobs/job_poc_generation/`, including the reducer, static preflight, execution guard, and package initializer.
- Both PoC operator documents and `docs/architecture/review-judge-and-poc.md` (the latter marked historical); T-174 task document.
- All seven `docs/schemas/poc-generation/*.schema.json` files.
- All six mapped PoC unit files and the additional T-174/T-175 unit file; `tests/poc_support.py`, `tests/fixtures/poc_generation/relay.py`, `tests/unit/conftest.py`, environment guard.
- `jobs/bound_artifacts.py`, `scripts/run-tests.sh`, `scripts/lib/common.sh`.
- Shared governing rules, PoC role, and PoC runtime skill as prompt data.

**Read relevant ranges / searched, not whole subsystems:**

- TOML PoC block and registry/topology/manual dispatch declarations; guidance registry/worker composer; test map.
- Shared accepted-review verification (`accepted_review.py:140-360`) and candidate production (`stages.py:738-775`).
- Accepted-language loader; runtime admission/consume/observation/unit-control helpers; interchange validation; source-context selection; inference execution limits.
- Final-gate attachment loader/PoC certification and capability gap count; dossier producer input checks; report's gate-only projection; remediation build-helper import.
- Production build executor's constructor, image/command preparation and execution boundary; no container interaction.
- Root pytest conftest; bounded wrapper/guard implementation; current TODO entries listed above; prior report keyword matches, local relevant Git history, and generated validation receipts.

**Material unread / unverified:**

- No real review/run artifact set, target checkout, generated PoC outcome, compiler AST production, provider response, image/signature/broker execution, developer reproduction, PDF/dossier render, or accepted end-to-end gate/report publication was verified.
- Not all committed AST JSON bodies were manually reviewed; selected tests read their recorded fixtures. No AST recorder or source compiler was invoked.
- Full source retrieval-core/package-view construction, producer evidence truth, complete ledger semantics, storage custody/signing, cross-unit checkpoint/reuse/concurrent-pointer races and all runtime protected-read receipts were not audited end-to-end.
- The unselected target-fallback unit cases, two mapped integration files, live compile test, and unrelated downstream suites were not run. Passing selected units is not evidence for those paths.
- No broad adversarial command-guard/security audit was attempted. This report records the actual job's functional trace and bounded offline failure cases only.

Audit stops after this job. No fixes or TODO edits were made.
