# Job 41/47 — job_remediation_validation

## Scope and result

- Audited **main, `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, in authorized WSL checkout `/home/wsollers/projects/appsec-review`, through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu` and its UNC view. HEAD and clean tracked/untracked Git status were checked before tests and again after investigation. The editable import resolved to that checkout's `src/appsec_review/__init__.py`.
- The Windows working checkout was not audited or tested. No repository source/configuration/environment edits, installs, target modifications, commits, service operations, real compiler/model/provider calls, integration/acceptance/live runs, or subagents.
- **Seven reproduced findings: one high, five medium, one low.** F05 is a downstream interpretation defect; F06 is an exported helper not used by the current job's exact-edit path; F07 is inherited from the shared accepted-build adapter. Do not count these as seven independently broken live runs.
- **260 focused units passed in 7.36 s**; wrapper elapsed **15.194674 s**; zero failures/skips/over-10-second tests. Six bounded reproductions took **1.112701 s**, including synthetic setup/cleanup after imports. Two tiny F07 probes took **0.000325 s** and **0.000601 s** after imports.
- Passing these tests does not establish live remediation correctness, semantic-model quality, actual compiler compatibility, successful runtime regression, or a fixed finding.

## Registration, configuration and contract

`runtime/registry.py:112,183` registers the builder. `job_remediation_validation/job.py:35-44,388-391` declares three units and validates exact configured step/task ordering. `appsec-review.toml:3758-3802` enables the job. `datasets.py:22-74` declares `REVIEW_GRAPH`, `ACCEPTED_EVIDENCE`, `always_execute=False`, propagation enabled, and scheduling after planning. The topology derives consumed-producer dependencies as well as the explicit predecessor (`orchestration/topology.py:46-80`); enabled validation without planning is refused by `config/loader.py:1521-1525`. Disabled graph selection is implemented centrally in `runtime/selection.py:11-29`, not by a local handler branch.

Intended input: accepted review's exact confirmed-finding partition and independently accepted inert plans/patches, with accepted language-build bytes/command/image when available. Supported-but-unconfirmed findings never become eligible merely because a PoC exists.

| Producer | Accepted declarations | Actual relevant use |
|---|---|---|
| `job_inference_security_review` | Required/reject `handoff`; optional/gap `accepted_scope`, `lead_triage`, `review_packages`, `review_cells`, `claim_ledger`, `attack_chains`, `scores_and_findings` | `load_review` calls the shared accepted-review verifier. It checks review/schema/run, package sets, replayed ledger, findings/scores, confirmed/supported partition, ship-block counts, and returns immutable references. `confirmed_findings` applies deterministic risk-first ordering; validation uses exact claim/package/hash triples and adjudication IDs. |
| `job_remediation_planning` | Required/reject `handoff`; optional/gap `remediation_planning_summary`, `remediation_proposals` | `inputs.load_planning` verifies summary schema, run, review pin, exact ordered candidate list/count/gaps, proposal/plan presence, and plan/row status/reason agreement. `verify_plan` rehashes plan, source-context, writer receipt and patch; verifies writer role/cell/guidance/result hash and finding/review identity. |
| `job_language_build` | Optional/gap `handoff`, `topology_refinement_inputs`, `build_actions`, `jvm_build_actions`, `language_build_receipts`, `build_workspaces` | Shared `AcceptedBuilds` lazily loads the accepted receipt set, selects successful native products, rehashes manifest/protected commands, locates C/C++ sources or headers and records source/command/image/build identity. It is not a general nine-language source provider. No user target checkout is read by this job. |

The envelope route is `indexing.store.accepted_handoff` → `runtime.consume.accepted_upstream`: runtime-scoped reads require typed declarations and admitted pins, not scheduling ancestry. Outside a runtime scope the API is an operator lookup. Payload reads through `bound_artifacts.read_bound_json`, workspace hashing and direct private command reads do not themselves emit per-dataset `observe_output` receipts. This is the explicitly documented bounded-reader limitation in `docs/architecture/job-input-contracts.md:111-132`, overlapping earlier audits; not a newly alleged absence of all input admission.

Current dev bounds: 16 candidates, 10,000 packages, 8 source files/64,000 source bytes, 4 patch files/64,000 patch bytes, 262,144 bytes per edited file, 32 edits/list items, 4,000 text characters, 100,000 workspace files/1 GiB per scratch copy. Reviewer: `claude-cli` / `claude-haiku-5-5`, high reasoning, 64,000 input tokens, 8,000 output tokens, two turns, zero queries, 600 seconds. Native adapter: `["native_syntax"]`, command timeout 120 seconds, diagnostic bound 65,536 bytes. Parsing is closed and rejects wrong types/ranges/unknown adapters; **F03** concerns enforcing two declared source limits, not their parsing.

## Every declared step/task

| Step / task | Actual implementation and output | Important outcomes / coverage |
|---|---|---|
| `load.verify_inputs` | `job.py:84-94`; `inputs.py:17-52`; planning `inputs.py:18-48`, `contracts.py:104-128`. Reload accepted review/planning, exact ranked finding accounting, bounded candidate telemetry; immutable `inputs.json`. | Missing required producer, incompatible identities/schemas or changed references fail the unit. Candidate overflow is retained, not silently omitted. Unit fixture mocks the accepted-review boundary; this audit did not execute a whole admitted review. |
| `assess.validate` | `job.py:306-321` walks every planning row serially; `validate_one:96-141`, `_validate_patch:143-304`. Emit an outcome even for capped/no-proposal rows. For a plan, verify adjudication/source/evidence relations and exact patch baseline; refuse executable build/tool mutations and unsupported cross-build scope; make two bounded manifest-exact scratch trees, apply inert byte edits, verify untouched files; lexical/Python-AST/pattern checks; independent final-only reviewer; optionally compare native syntax; always retain cleanup receipt and remove scratch. Immutable `outcomes.json`, validation/static/semantic/build/cleanup documents. | Native success means only before/after syntax success. Baseline failure → inconclusive; patched failure → rejected; unsafe replay/profile/scope → manual; unavailable compiler → static-only after semantic support. Invalid/unavailable reviewer → inconclusive; contradiction → rejected. Patch errors → rejected, workspace bounds → manual, integrity/programming errors fail the unit. F01–F04/F07 affect this path. |
| `acceptance.publish_handoff` | `job.py:323-385`: reload accepted review/planning, require pins unchanged, rehash review bindings, require exact ordered one-row-per-planning-finding accounting, schema-check each validation and summary, resolve check/cleanup references, aggregate gaps and telemetry, publish immutable `remediation-validations.json`. | No rows → `SKIPPED_NA`; any row gap → `COMPLETED_WITH_GAPS`; otherwise `SUCCEEDED`. Existing write targets are refused by planning `job.py:35-40`. Publication does not change findings, ledger, ship-block decisions or execute regression specs. Schemas constrain shape/enums/nonexecution, not semantic truth of individual checks. |

### Exact patch, model and compiler trace

- Planning `patches.py:24-113,116-154,187-193`: canonical relative paths, casefold duplicate/parent overlaps, SHA-256 baselines, explicit new-file absence, ordered byte offsets, matching old text, non-no-op edits, bounds, UTF-8 output, and all-file validation before writes. `safe_file` refuses symlinks/junctions/outside-root paths. `contracts.verify_patch_scope:79-101` requires evidence-read baseline hashes and matching accepted build identity; new files are confined to evidence-related directories and selected C-family extensions.
- `workspace.py:19-40,43-76`: run-owned source, bounded manifest-driven copies and hash checks, no reuse of an existing scratch destination, post-edit manifests, named cleanup result; failed cleanup raises integrity failure. No original target is patched.
- `static_validator.py`: current artifact is **`remediation-static-patch-validation/2`**. Only Python uses `ast.parse`; other languages get lexical checks and regex function-name/guard patterns. Supplied patched text leaves `hunks_applied` null; the job's separate exact application establishes applicability. The static artifact cannot claim `build_checked`, syntax validity for other languages, runtime proof, signature preservation or guard dominance. This repairs earlier overclaims; missing nine-language parser/semantic analysis remains **T-174**, not a new discovery.
- `guidance/workers.py:58-60,140-188`, planning `model.py:32-66`: the reviewer selects the registered role and `stateful-invariant-analysis`; `remediation_assessment` is a generated structured-task sentence, not an undiscovered standalone prompt file. No persona/stack is selected. The role text was read as data; it withholds the planner's argument and requires explicit support/contradiction/uncertainty.
- `job.py:228-255`, planning `model.py:69-161`: a fresh bounded no-tools request includes accepted finding/adjudication/direct evidence, violated/corrected invariant, source context, exact patch and unexecuted regression spec. `semantic_answer:60-69` requires closed fields, accepted nonempty relation-ID citations, bounded reason/residual concerns. No retrieval callback is passed. Shared execution caps request/response bytes, calls and deadline; invalid output is terminal rather than retried into another policy; usage/guidance/result digests are retained without raw prompts in the receipt.
- `compiler.py:95-177,200-253`: immutable accepted image, absolute allowlisted Clang/GCC driver, matching C/C++ translation unit, bounded argv, classified flags, contained paths; strip output/dependency/link-producing options and reject wrappers/response files/plugins/unknown replay. Clang default config is disabled. Baseline is first; the same derived argv/workdir/environment/image is used for patched source. Fake-boundary tests cover timeouts, unavailable images, failures, output truncation and exception propagation.
- Production executor (`container_runtime/build_executor.py:350-358,410-535`) verifies the image policy and constructs network-none/no-shell execution. **Its container root is read-only, but `/workspace` is a writable bind and scratch file owner permissions are opened**; the job detects source changes afterward. Do not describe the bind itself as read-only. F01 exposes a conflict between executor-owned evidence and that after-the-fact manifest check. Active first-error safety intentionally stops on genuine tool failures; this audit does not propose weakening that policy.

## Findings

### RV-F01 — High — Successful safety-scoped compiler checks always contaminate the source manifest

- **Evidence:** `src/appsec_review/container_runtime/build_executor.py:505-514` writes `stdout`, `stderr`, and `outcome.json` under the compiler workspace's `.appsec-execution/<container>/` whenever execution safety is active. `src/appsec_review/jobs/job_remediation_validation/job.py:290-292` compares the entire post-compiler tree with the pre-compiler manifest and raises `IntegrityError` for any change. `workspace.py:46-59` includes those new regular files. The opt-in Dagster safety envelope reaches actual ops through `orchestration/dagster/fail_fast.py:61-70`.
- **Trigger:** a safety-enveloped review reaches an otherwise successful commissioned native syntax check. This is an opt-in path, not a claim that all default runs enable safety.
- **Expected / actual:** executor-owned diagnostics should be retained outside the compared source tree; unchanged source and two successful checks should permit `build_checked`. Instead the job reports **“commissioned compiler changed its read-only source workspace”**, fails `assess.validate` and blocks publication.
- **R1:** used the real job and real `BuildContainerExecutor`, canned Docker/image/signature boundaries, and an in-process safety-active indicator (no guardian service). Both fake compiler invocations returned zero; original source remained byte-identical; the unit failed with exactly the above error and scratch was removed. No source mutation was faked.
- **Impact / confidence:** high confidence in deterministic false integrity failure for the safety-active branch. The declared diagnostics policy prevents otherwise successful remediation output.
- **Smallest correction:** retain executor evidence in a separately owned protected directory outside both source manifests, with explicit references; keep exact manifest checks and first-error/cancellation policy intact. Do not broadly ignore arbitrary source-tree additions.
- **Overlap:** no exact prior/TODO match found in the bounded search. T-113 covers test migration; T-174 does not cover executor receipt placement.

### RV-F02 — Medium — Related files in the same build are mistaken for a multi-build proposal

- **Evidence:** `job_remediation_validation/job.py:165-173` enumerates **all context files**, including unmodified supporting evidence, and deduplicates `BuildUnit.identity()`. `job_poc_generation/buildctx.py:87-90` includes translation-unit source and command hash in that identity.
- **Trigger:** one patch edits only `native/src/parse.c`, while the accepted finding also cites `native/src/other.c` from the same build receipt/workspace.
- **Expected / actual:** a one-file patch with one accepted exact compile unit should not be made multi-build solely by an unmodified supporting file. It becomes `manual_validation_required: multi_build_proposal_requires_manual_validation`, before either reviewer or compiler runs.
- **R2:** both located units had identical `build_unit_id`, receipt fingerprint and workspace-manifest digest; only command/source differed. Result was manual with **zero reviewer calls and zero compiler calls**.
- **Impact / confidence:** high-confidence unnecessary loss of substantive validation for ordinary cross-function/file findings.
- **Smallest correction:** select affected build/compile units from patch paths, distinguish build identity from compile-command identity, and permit unmodified evidence from additional units without inventing a multi-file compiler adapter.
- **Overlap:** no exact existing entry found. Existing coverage-edge test intentionally creates two different build-unit IDs; it does not cover same-build/multiple-TU evidence.

### RV-F03 — Medium — Validation source-context bounds are fingerprinted but not enforced

- **Evidence:** `config/remediation.py:58-59,105-118` accepts/hashes `max_source_files` and `max_source_bytes`; `job_remediation_validation/job.py:148-153,166,240` reads and sends the planning context's files without applying those validation limits. The actual source limits are applied earlier with the **planning** configuration in `job_remediation_planning/inputs.py:86-129`.
- **Trigger:** validation is commissioned with tighter source bounds than the accepted planning attempt.
- **Expected / actual:** enforce validation's bounds or explicitly mark them inapplicable/remove misleading knobs. Instead content exceeding those declared bounds is still sent to the reviewer and can publish `build_checked`.
- **R3:** `support.validation_settings(max_source_bytes=1)` sent **49 source bytes** to the fake reviewer, ran two fake syntax checks and produced `build_checked`. No source-bound gap was emitted. File-count non-enforcement is statically verified on the same path; only byte-count was dynamically reproduced.
- **Impact / confidence:** high confidence; independent stage sizing/prompt-content limits do not do what their configuration says. The separate model-input cap still limits total request bytes; this is not an unbounded-memory claim.
- **Smallest correction:** re-admit accepted context against validation source count/byte limits before semantic dispatch, producing explicit manual/inconclusive bound outcomes without silently dropping evidence.
- **Overlap:** no exact entry found; T-5079 concerns output/thinking-token sizing, a different bound.

### RV-F04 — Medium — Legal existing C++ digit separators reject otherwise applicable patches

- **Evidence:** shared `job_poc_generation/static_compile_check.py:285-317` treats every C++ apostrophe as a quoted literal; `job_remediation_validation/static_validator.py:290-295,354-358` makes a lexical failure reject the patch set; `job_remediation_validation/job.py:201-227` stops before semantic/native checks.
- **Trigger:** an accepted C++14 source contains unchanged legal numeric syntax such as `long limit = 1'000;`, and the patch adds a guard elsewhere.
- **Expected / actual:** an incomplete lexical recognizer should handle that literal, or name an unsupported/inconclusive check rather than reject the patch as defective. Actual outcome is `rejected: static_patch_policy_failed`, diagnostic **“unterminated string literal on line 3”**, no reviewer and no native invocation.
- **R4:** an inert accepted fixture with `-std=c++14`, that unchanged numeric literal and an exact `strcpy`-guard edit reproduced the error. This proves misrecognition of legal numeric syntax, not that a real compiler accepted the whole synthetic fixture.
- **Impact / confidence:** high confidence; source-language features unrelated to the edit prevent the independently commissioned compiler from checking the patch.
- **Smallest correction:** recognize the supported numeric-literal syntax and add this narrow regression; preserve honest unknown/incomplete states for lexical constructs that cannot be validated.
- **Overlap:** concrete failure under **T-174**'s already-open lexical/parser limitations, not a new claim that all nine languages are parsed.

### RV-F05 — Medium — Dossier labels a statically failed, rejected patch `static_checked`

- **Evidence:** `reporting/dossiers.py:324-335` promotes `validation_tier` if **patch applicability alone** passed, even when the row is rejected and static checks failed. `:370` publishes the tier; `:805` renders it as “Validation tier”. `job_dossier_publication/job.py:62-80` forwards the real validation status/checks into this projection.
- **Trigger:** any exact applicable patch rejected by static policy, or a statically passed patch rejected by independent semantic review.
- **Expected / actual:** preserve rejected/inconclusive/manual outcome separately from passing check dimensions; never let applicability imply completed static validation. Actual R4 output (`status=rejected`, `static_checks=failed`, `patch_applicability=passed`) produced a dossier guide with **`validation_tier=static_checked`**.
- **R5:** fed the real validation record's projected check dimensions into the production `_build_remediation_guide`; no renderer/container was run.
- **Impact / confidence:** high-confidence misleading developer-facing headline. The detailed remediation row and nonexecution notices remain, and this does **not** alter original finding or ship-block state.
- **Smallest correction:** derive the headline from the accepted overall validation outcome, retain explicit separate check results, and test rejected/static-failed and semantic-contradicted cases.
- **Overlap:** related to completed **T-176** dossier redesign and open T-5078 misleading-output triage; no exact prior entry found. Coordinate with the dossier auditor rather than double-count this downstream manifestation.

### RV-F06 — Low — Exported unified-diff helper misplaces zero-context insertions and ignores new counts

- **Evidence:** `static_validator.py:156-171` retains only old hunk range/count; `:179` always subtracts one from nonzero old starts; `:196-203` checks only consumed old lines and reconstructs newline behavior from the original. New header coordinates/counts are not validated.
- **Expected / actual, R6:** applying `@@ -1,0 +2,1 @@\n+x\n` to `"a\nb\n"` should produce `"a\nx\nb\n"`; actual result is **`"x\na\nb\n"`**. `@@ -1 +1,99 @@\n-a\n+x\n` is accepted despite declaring 99 new lines and producing one.
- **Impact / confidence:** high confidence in helper/API correctness defect. **The current job does not call this diff-application branch**: it uses `apply_exact` and supplies `after_text`. Do not claim current job patches are applied by this broken helper.
- **Smallest correction:** implement correct zero-count hunk anchoring and validate both ranges/counts, including explicit no-final-newline semantics; add narrow in-memory tests.
- **Overlap:** T-174 helper scope; no exact prior finding found.

### RV-F07 — Medium — Native replay loses a source-relative command's build working directory

- **Evidence:** `job_poc_generation/buildctx.py:243-268` reconstructs the compile command; `_working_directory:329-348` decides whether to use `recipe.build_dir` by looking for relative includes/response files, **not a relative source argument**. `job_remediation_validation/compiler.py:112-121,163-165` then compares the wrongly rooted source argument with the accepted workspace-relative source and refuses it. Producer mapping preserves the correct workspace-relative input in `job_language_build/native.py:48-70,99-107`; its row does not preserve the captured working directory.
- **Trigger:** captured argv `["/usr/bin/clang","-c","src/parse.c"]`, accepted input `native/src/parse.c`, recipe build directory `native`, no relative include option.
- **Expected / actual:** preserve the authoritative captured working directory, or explicitly retain its absence instead of labelling an inferred command exact. Actual `CompileCommand` has `basis="exact"` but `working_directory="."`; replay returns **“compiler command contains an unexpected input”** and the job maps unsafe replay to manual validation.
- **R7:** direct actual `_command` + `compile_argv` with canned protected-command rows reproduced the refusal. A second probe used the exact producer row shape (no directory field); setting only the in-memory command's directory to `native` derived the expected safe syntax argv. No compilation or file creation.
- **Impact / confidence:** high confidence in the bounded adapter defect; ordinary out-of-root native compile commands lose automatic validation. Live occurrence/frequency unmeasured.
- **Smallest correction:** retain/bind captured cwd in native protected rows and consume it faithfully; avoid inferring cwd from the presence of include flags.
- **Overlap:** **LB-F04** in the language-build report concerns merging equal argv from different cwd, not this separate replay reconstruction. Share an upstream ownership fix rather than duplicate a general cwd project. PoC/planning audit reports were not yet available for final cross-check.

## Publication, schemas and consumers

- `datasets.py:5-16`: `remediation_validation_receipts` is **protected**, schema `remediation-validation/1`, `assess/**`; it encompasses validation/check/semantic/compiler/cleanup artifacts. `remediation_validation_summary` is **artifact_only**, schema `remediation-validations/1`, covering load/acceptance trees. Neither is indexed. Declared MCP routes expose sanitized inventory metadata, not source/private payload access.
- Main validation schema requires exact known fields and seven check dimensions; statuses are `build_checked`, `static_checked`, `rejected`, `inconclusive`, `manual_validation_required`. Assurance is fixed to `execution=not_performed_by_policy`, `runtime_verified=false`, `result_id=null`. Regression compilation remains uncommissioned; runtime regression explicitly not performed. Static `/2` schema independently prevents a non-Python syntax-valid claim and excludes `build_checked`.
- Acceptance resolves each retained check artifact and cleanup reference but does not deeply re-derive compiler/semantic decisions from their JSON. Gate `attachments.py:161-205` adds finding/adjudication/run/status/reason/upstream equality, accepted-plan and patch equality, runtime nonexecution, and complete confirmed-finding accounting. `verify_attachments:243-377` checks accepted envelope/count/gap/upstream relationships and freezes reference closure; `reverify_snapshot:380-394` checks it again. This is meaningful byte/identity verification, not proof that an actual compiler/model ran.
- Dossier `inputs.accepted_producer/load_inputs` validates accepted identities/counts/assurance and matching planning handoff; job `_remediation` keeps status/reason/checks. The presentation error is **F05**, not a missing producer.
- Final gate `classify.py:69-88` buckets the unchanged confirmed/supported partition. Compile-only attachments do not clear ship-block state. No fixed-state verifier or executed regression is introduced here; **T-061/T-074** remain the separate cross-revision work.
- Legacy string row gaps are intentional existing debt: this job is listed in `tests/test_gap_contract.py:21`; `strict_gaps` is not enabled. No new producer-status vocabulary was invented. All non-build-checked generated records get a row gap; capped/no-plan rows get explicit candidate/proposal gaps.
- No job-specific semantic resume cache was found. Attempt-local writes are immutable; generic runtime input/configuration/implementation identities govern reuse. Same hashes are rechecked at publication; scratch must be recreated. Full generic cache/shared-storage enforcement was not exercised.

## Focused validation record

All Linux commands below ran in `/home/wsollers/projects/appsec-review`, transported without quote loss as:

```powershell
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu `
    "printf %s $encoded | base64 -d | bash"
```

Preflight:

```bash
git rev-parse HEAD
git status --short
git branch --show-current
git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
```

Results: exact required SHA, `main`, empty status, ancestor exit zero, authorized source import. No production environment variables were changed. Xdist's environment-guard preflight ran before workers.

The map lists the four legacy/core unit files (247 cases); the job-local T-174 file adds 13 inspected cases absent from the map. Inspected fixtures use inert strings/files, `Writer`/`RecordingExecutor`/`Executor` doubles, fake accepted review/build boundaries, and a fake Docker runner in the production-executor argv test. The imported `relay_workspace` helper can read a real local target, but none of these selected tests or reproductions calls it. `relay_unit` alone supplies metadata.

### Collection

```bash
.venv/bin/python -m pytest --collect-only -q -o addopts= \
  -p no:cacheprovider \
  --basetemp=test/tmp/job-audit-rv41-collect-20261118-01 \
  tests/test_remediation_compiler.py \
  tests/test_remediation_models.py \
  tests/test_remediation_patches.py \
  tests/unit/job_remediation_validation/test_coverage_edges.py \
  tests/unit/job_remediation_validation/test_t174_multilang_validation.py
```

**260 collected, 1.65 s, zero tests executed**, one `PytestConfigWarning: Unknown config option: cache_dir` because cacheprovider was disabled. Initial shell piped display to `tail -n 8`; the exact collection was independently enforced by the subsequent wrapper.

### Refused wrapper attempt

```bash
scripts/run-tests.sh --parallel --test-workers 2 --max-tests 260 \
  --expect-tests 260 --shuffle-seed 4118 --strict -- \
  tests/test_remediation_compiler.py tests/test_remediation_models.py \
  tests/test_remediation_patches.py \
  tests/unit/job_remediation_validation/test_coverage_edges.py \
  tests/unit/job_remediation_validation/test_t174_multilang_validation.py \
  -p no:cacheprovider
```

**Exit 2 before collection/execution**: `unsupported focused pytest option '-p'; scope/report/worker options belong to run-tests`. No pytest run directory/count/timing report was produced; elapsed not measured. This was command admission, not a code-test failure.

### Completed shuffled/two-worker run

```bash
scripts/run-tests.sh --parallel --test-workers 2 --max-tests 260 \
  --expect-tests 260 --shuffle-seed 4118 --strict -- \
  tests/test_remediation_compiler.py tests/test_remediation_models.py \
  tests/test_remediation_patches.py \
  tests/unit/job_remediation_validation/test_coverage_edges.py \
  tests/unit/job_remediation_validation/test_t174_multilang_validation.py
```

Executed under `set -eu; set -o pipefail` and exact HEAD/clean-status checks, with display piped to `tail -n 45`.

**260 passed; 0 failed/error/skipped; 7.36 s pytest; 15.194674 s total wrapper; 0 over 10 s; exit 0.** Collection and execution cleanup both confirmed, zero remaining processes. One unique wrapper-owned root was reused sequentially for its collection/execution, never by another auditor:

```text
test/tmp/tests-custom-20261118-134033-183419-3492025
test/tmp/logs/tests-custom-20261118-134033-183419-3492025.log
test/tmp/logs/tests-custom-20261118-134033-183419-3492025.collection.log
test/tmp/tests-custom-20261118-134033-183419-3492025.junit.xml
test/tmp/tests-custom-20261118-134033-183419-3492025.timings.sqlite
test/tmp/tests-custom-20261118-134033-183419-3492025.collection.json
test/tmp/reports/tests-custom-20261118-134033-183419-3492025.json
```

The wrapper invoked this checkout's `.venv/bin/python -m pytest`, `-p ops_test_guard`, exact `-c`/`--rootdir`, `-o addopts=`, `-q -rfE`, the above private basetemp/junit, `-o junit_family=legacy`, `-n 2`, `--shuffle-seed=4118`, and the five exact selectors. All failure lists were empty. Test artifacts/logs remain in ignored `test/tmp` for the coordinator.

### Cheap reproductions

All used `.venv/bin/python -B - <<'PY' ... PY`, sequentially, not pytest, and no external compiler or model. R1–R5 used only inspected `_seed_env` / `_val_ctx`, `support.Writer`, `support.Executor`, `relay_unit`, and real job handlers. `test/tmp/job-audit-rv41-repro-20261118-01` was created uniquely and removed in `finally`.

| Probe | Minimal variation / real function exercised | Observed result |
|---|---|---|
| R1 | Real `BuildContainerExecutor` factory; canned image inspect/zero-exit compiler/removal replies and accepting signature stub; `safety.active` supplied as true locally. Real `_execute` retention and post-compiler manifest check unchanged. | 2 fake Docker runs; `assess.validate` failed with the exact false-integrity message; original unchanged; scratch absent after cleanup. |
| R2 | Context includes `parse.c` and `other.c`; `relay_unit` gives both identical build/receipt/manifest and distinct exact compile commands; only `parse.c` is patched. | Manual multi-build result; reviewer/compiler call counts both zero. |
| R3 | Default accepted one-file plan; validation `max_source_bytes=1`; inspect fake reviewer's actual task. | 49 source bytes delivered; `build_checked`; one reviewer/two compiler calls. |
| R4 | C++14 fixture containing unchanged `1'000`, with the usual exact guard patch. | Rejected/static policy failed, false unterminated-string diagnostic; no reviewer/compiler calls. |
| R5 | Pass R4 record's actual status/check dimensions into `_build_remediation_guide(..., limits=DossierLimits())`. | `rejected` + failed static check became guide tier `static_checked`. |
| R6 | `apply_unified_diff_in_memory("a\nb\n", "@@ -1,0 +2,1 @@\n+x\n")`; separately declare 99 new lines for a one-line replacement. | Wrong insertion position; bad new-count accepted. |
| R7a | Real `_command`/`compile_argv`; canned native relative-source row with an extra directory field. | Directory ignored, `"."` derived, unexpected-input refusal, 0.000325 s. |
| R7b | Repeat with exact producer row shape, no directory field; compare with only in-memory `working_directory="native"`. | Same refusal; corrected directory derives `("/usr/bin/clang","-fsyntax-only","--no-default-config","/workspace/native/src/parse.c")`, 0.000601 s. |

R1–R6 combined: **1.112701 s including fixture setup and cleanup after imports**, all listed R1–R6 outcomes reproduced, scratch removal confirmed. R7 uses no filesystem scratch. These are evidence probes, not additional passed pytest cases.

## Prior work and named gaps

- Read full updated shared brief, authorized AGENTS and multi-session skill. Consulted relevant Git history: `918154c06` (honest static assurance), `ed0b6630c` (T-173/174/175), `6bf2f52c5`. Existing report searches covered remediation, bounds, safety artifacts, read receipts and cwd; language-build **LB-F04** was compared specifically.
- **T-147**: missing generated exact task bindings are already open metadata work; actual handlers/model/tool branches were traced here.
- **T-174**: nine-language parsing/post-patch semantic analysis remains explicitly in-progress; actual Python-only AST/lexical assurance is correctly labelled in the producer. F04/F06 are concrete manifestations in that area.
- **T-176**: completed dossier redesign overlaps F05. **T-5078** is broader unresolved misleading-output triage. **T-5079** already tracks validation model output caps/thinking tokens; no live sizing test was authorized.
- **T-061/T-074**: separate fixed-state verification remains unimplemented; do not require this compile-only job to change verdicts.
- **T-113**: legacy test-map/tier migration; no newly claimed coverage percentage. T-174's 13 local tests are absent from the job map.
- Planning/PoC per-job audit reports were not yet present when checked; coordinator must reconcile shared-adapter findings once those finish. No TODO entry was added/changed.

## Read inventory and limits

**Read fully:** all seven `.py` files in `jobs/job_remediation_validation/`; `config/remediation.py`; planning `contracts.py`, `inputs.py`, `model.py`, `patches.py`, `job.py`; shared `job_poc_generation/buildctx.py`; `jobs/bound_artifacts.py`; `jobs/completion_contracts.py`; `job_final_publication_gate/attachments.py`; `job_dossier_publication/inputs.py`; the five selected test files; `tests/remediation_support.py`; root and unit conftests/environment guard; remediation operation page; relevant remediation main/static schema files listed below; selected reviewer role; multi-session skill/AGENTS/brief.

Schemas read: remediation `common`, `exact-patch`, `plan`, `planning`, `validation`, `validations`, `validation-handoff`; remediation-validation `common`, `static-patch-validation`. The selected patch test also checks all remediation schema documents mechanically.

**Read in targeted ranges/searches, not entire subsystems:** `accepted_review.py:190-359` and its helper call sites; lexical helper through `static_compile_check.py:370`; `BuildContainerExecutor:1-535`; identity/resource/safety relevant methods; `runtime/consume:1-240`, input observation boundaries, unit dispatch, selection; native accepted-loader and capture/row mapping; config-loader/registry/topology/worker assembly; dossier projection/forwarding/render call sites and gate classification; test support `poc_support:1-160`; wrapper shell/common/ops-tests collection/execution/report code; central TOML block/test map; architecture testing, input contracts, interchange and worker-prompt contracts; the named TODO entries/prior-report matches.

**Material unread/unexecuted scope:** complete ledger/package/review-verifier internals, source/risk-ranking internals, shared-store/signing/claim/reuse closure, every inherited language-build cache/capture branch, complete gate/dossier/report jobs, full runtime skill body, unrelated prompts/tests and the rest of the repository. Runtime skills were not loaded as agent instructions; their registered selection/pinning was traced and the focused guidance tests executed. The accepted-review boundaries in job fixtures are mocked; full input-read/dataset-publication receipts were not exercised end to end.

**Not run:** mapped acceptance test `tests/test_remediation_jobs.py::test_real_runner_publishes_build_checked_without_changing_original_state_or_shipment`, any real container/compiler/parser tool beyond inert Python parsing, models/providers, Dagster/services, target execution, integration/live tests, PDF rendering, native signatures/custody under deployment, real before/after compile outputs, or semantic/fix quality evaluation. No passing-unit claim substitutes for these gaps.

Final authorized checkout remained at the exact SHA with empty `git status --short`. Only this session report was added outside the repository; synthetic reproduction files were removed. Stop after this job.
