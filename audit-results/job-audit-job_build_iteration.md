# Job 46/47 — `job_build_iteration`

## Result and authority

- Audited **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, branch `main`, in `/home/wsollers/projects/appsec-review` through `ssh wsl-ubuntu` and its UNC view. Initial and final Git status were clean; the editable import resolved inside this checkout. The Windows working directory was not audited.
- Read the updated shared brief, authorized `AGENTS.md`, coordination skill, operations page, and relevant architecture. This was the assigned single-job, read-only functional audit.
- **Five verified defects: one high, four medium.** Passing units do not establish exact functional correctness.
- **53 focused units passed**, no failures/skips/over-ten-second cases: 7.25 seconds pytest, 14.592 seconds supervised wrapper total. Additional bounded reproductions used synthetic source/products, fake workers/invokers, and a simulated container/capture boundary.
- No registered manual job, real build/compiler/model/provider/container, service, integration/acceptance/live test, or subagent was launched. No repository source/environment/dependency edits, installs, commits, or pushes. Reproducer-owned scratch was removed; the ordinary wrapper's isolated reports remain.

## Registration, inputs, and execution identity

`runtime/registry.py:149` registers the job. `appsec-review.toml:1376-1382` declares one job, step, and task worker. `job_build_iteration/datasets.py:43-65` declares `INTERNAL_TRANSACTION`, no schedule predecessors, checkout access, `always_execute=True`, and `propagate_handoff=False`. `orchestration/topology.py:48-58` includes only `REVIEW_GRAPH` contracts, so this job is deliberately outside the main review graph. Dagster definitions special-case it to `registered_definition` (`orchestration/dagster/adapter.py:418-420`); it is not an ordinary unconditional review stage.

| Producer/channel | Declared inputs | Policy and actual use |
| --- | --- | --- |
| `build_controller`, transaction | `iteration_request`, `appsec-review/build-iteration-request/1` | Required/reject, operational authority. The handler verifies reference bytes, observes this transaction input, and requires an exact `pending.json` claim. |
| `job_project_build`, handoff | `handoff` (`job-handoff/2`); `topology_refinement_inputs` (`build-topology-refinement/1`); `project_build_dispatch` (`project-build-dispatch/3`); `probe_workspaces` (octet stream); `image_build_streams` (text) | Handoff required/reject; remaining datasets optional/gap. `_dispatches` reads the accepted dispatch and checks source, workflow, unique build units, successful immutable preparation, recipe/image/dependency identity, and project-owned native receipt correspondence. |
| `job_target_analysis_plan`, handoff | `handoff`; `planning_feedback_cache` (`target-analysis-proposal/3`); `analysis_plan` (`retrieval-index/2`); `analysis_plan_documents` (`target-analysis-plan/1`) | Optional/gap declarations, but the actual execution/refinement guard requires a resolvable accepted plan. The complete source graph, recipe-bound refinement, descriptors, policy, and release bindings are reverified. This is not permission to use an arbitrary previous plan. |
| `job_build_environment_analysis`, handoff | `handoff`; `build_environment` (`build-environment-analysis/1`) | Optional/gap; inherited because accepted planning may reread its environment publication. |
| `job_review_intake`, handoff | `handoff`; `model_preflight` (`model-preflight/1`); `binary_evidence` (`binary-evidence-intake/1`); `review_intake` (`review-intake/1`) | Optional/gap declarations; not all are directly read by this job. |
| `job_target_catalog`, handoff | `handoff`; `target_artifact_inputs` (`target-artifact-intake/1`); `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units` (all `retrieval-index/2`); `catalog_documents` (`target-catalog/1`) | Optional/gap declarations inherited from language-build. Availability and actual reads remain separate. |

All schema names above have the `appsec-review/` prefix except MIME types. There are **23 inherited handoff requirements plus one transaction requirement**. `CONSUMES` contains the five handoff producers, not `build_controller`. Generic admission rejects missing project-build before execution; the transaction channel is enforced by its reader/handler rather than generic handoff availability.

`iteration_inputs` selects the declared current accepted upstream pins and checks the request target's full raw fingerprint (`job.py:63-73`, `runtime/inputs.py:67-107`). Accepted readers thereafter operate under the runtime's admitted input scope. The request itself binds the graph/configuration references and selected dispatch, rather than embedding the original parent's complete upstream-handoff map. A changed graph/dispatch is rejected when the controller is reconstructed.

The immutable request has `schema`, application `run_id`, `node_id`, unique `attempt_id=iteration-<uuid>`, `controller_id`, `binding`, input `generation`, display label, target path, graph/configuration references, exact dispatch, interfaces, optional product overrides, and producer bindings (`build_iterations.py:147-164`). `NodeBinding` includes node/source/graph/configuration/recipe/image/toolchain identities, sorted upstream product-record hashes, executor identity, and output-policy/selected-proof identity (`build_workspace.py:82-110`, `build_iterations.py:113-134`). Labels such as `build_cpp1` are traversal display ordinals, not durable retry IDs. The orchestration UUID, framework attempt ID, and build iteration attempt ID are distinct.

## Every declared task, with its internal processing

Only **`execute.node`** is declared. It has no explicit unit or job input/output validator callbacks; validation is in the handler, controller, workspace, accepted-input readers, and shared runtime.

| Declared task / internal boundary | Actual implementation | Result, mismatch, or coverage limit |
| --- | --- | --- |
| `execute.node`: invocation | `job.py:16-43,58-88`; `cli.py:455-466`; parent `job_language_build/job.py:1910-1919` | Separate in-process Dagster invocation returns the `execute_build_node` output. Failed invocation raises with its UUID. The manual CLI requires run/reference, but first fingerprints an unrelated configured target: **BI-F04**. No actual Dagster invocation executed in this audit. |
| Request and frozen configuration | `job.py:46-55,93-118` | Hash-verifies request, observes transaction read, requires the exact pending reference, reloads original configuration selection, compares resolved hash, replaces only the unit's job configuration with language-build configuration, reconstructs the controller, then executes the exact request. |
| Accepted actions and revision selection | `job_language_build/job.py:175-262,1841-1904`; `build_iterations.py:990-1051` | Requires iterative mode; preserves project-owned native execution, failed preparations and policy skips; selects applicable units; applies recipe-only promotions without changing graph bytes. **BI-F02** prevents reconstruction after a promoted node commits. |
| Prior-attempt admission and selection | `build_iterations.py:274-345,468-535` | Preflights releases/refinements/images, verifies prior receipts/products, serializes the controller, materializes/resumes workspace, walks finite topological order. **BI-F01** converts legitimate changed bindings into a global block before the invalidation branch can run. |
| Writer admission | `build_iterations.py:166-211`; `build_workspace.py:775-847` | Rechecks request schema/run/dispatch/graph/config/target/products, current producer bindings, exact product interfaces and readiness, then starts the unique attempt against its expected generation. A reused attempt ID, changed generation, tainted tree, missing upstream, or already accepted node cannot silently execute. |
| Generic/JVM/Wasm production | `job_language_build/job.py:1003-1086` | Wraps the executor to force shared install mounts and track attempted/returned commands; uses request attempt/UUID; dispatches Java first, matched Wasm next, otherwise generic family execution. Shared execution does not use private per-family build checkpoints. Real adapters were source-read; no real tools ran. |
| Configure/build and capture | Generic `job.py:1089-1669`; JVM `jvm.py:676-930`; Wasm `wasm.py:267-492`; common `build_recipe_commands.py` | Revalidates source/cwd/driver before each command; applies family argv/environment policy; stops on failed commands, preserves streams/capture/provenance, checks source remained unchanged. JVM retains instrumentation rather than standardized syscall capture; nonnative Wasm can use plain execution. Those decided boundaries were not called defects. |
| Products and durable evidence | `build_iterations.py:700-855`; `build_workspace.py:860-913` | Retains artifacts in CAS; derives products from actual changed install/captured output bytes or selected overrides, checks graph/2 role/axes, captures a durable generation, protects prior accepted products. **BI-F05**: shared native-byte verification does not verify the complete physical role when explicit product declarations are used. |
| Prepare, fail, commit, complete | `build_iterations.py:213-272,541-593` | Retains receipt/prepared document, requires cleanup and `SUCCEEDED`, verifies product contract and commits, then retains completion linking request/receipt/prepared/product/binding/UUID/generation. Failed receipt gets diagnosis; failed transaction rolls back only with cleanup proof. **BI-F03**: a success-shaped receipt whose product verification fails gets no corresponding failure-context pointer. |
| Recovery, invalidation, stopping | `build_iterations.py:347-466,608-697`; `build_workspace.py:919-1254` | Recovers pinned invalidation, reconstructs orphan committed completions, reconciles exact recorded leases, otherwise restores the prior generation. Never promotes an uncommitted prepared receipt into success. Retention uses owned disposable trees and holds; no sweep was invoked. |

### Iteration and convergence boundary

This is **not an autonomous recipe-search/model loop**. The controller attempts each dependency-ready selected node once per traversal, reuses valid committed nodes, blocks failed dependencies, and can continue unrelated nodes after a prepared/cleaned failure. It emits receipts sorted by unit ID and explicit topology gaps. Missing dispatch/refinement/image/release gives a blocked/gap result; no dispatch yields skipped/blocked/not-applicable receipts as appropriate. A pre-prepared exception or unconfirmed cleanup can stop the parent.

Detached repair evaluates one explicitly supplied candidate. Candidate validation preserves source, product interfaces/variants and environment authority; normalized no-ops/duplicates stop; missing approved changed-image preparation blocks. Replay verifies commands, complete captures, expected outputs, new/changed products and cleanup. Promotion selects **recipe/products/image-profile metadata only**; trial bytes never become production success. The next authorized controller entry must execute production again. `selected_revisions` does not retire a consumed selection, which contributes to BI-F02.

### Configuration, budgets, and explicit gaps

- Internal job/step/task workers are all one. Actual node command settings come from **language-build**, not an invented iteration configuration: 1800-second command timeout, 8 MiB stream preview, 10,000 artifact count, overridden 250,000 capture-event / 64 MiB raw-trace limits; JVM 8 MiB trace / 20,000 provenance records, Wasm 100,000 workspace files (`appsec-review.toml:1384-1498`).
- Native production uses network `none`; other production families use `bridge`. Resource/capture bounds and lease checks are delegated to the real executor; this audit did not test live timeout/cancellation/resource enforcement.
- No model, prompt, persona, runtime skill, or automatic image-repair call is selected by the internal task. Missing formal task/tool binding metadata is existing **T-147**, not evidence of absent execution.
- Failed internal transactions raise and cannot publish a successful partial transaction. The parent's `states` map can use internal scheduling states such as `BLOCKED_BY_DEPENDENCY`; producer `terminal_status` remains separately normalized.
- Existing **T-092** covers pre-prepared custody refusal versus sibling continuation. It is not resolved or newly counted here. **T-084** covers the missing cheap complete ready-dispatch-to-publication unit. The tested fake controller/transaction pieces do not close that end-to-end gap.
- Scheduling observation, not a demonstrated live-cap failure: `iteration_definition` sets the descriptive tag `appsec/pool=cpp_build` but its Dagster op has `pool=None`; the outer `iterations.dispatch` is in `application` (`job.py:19-20`, `adapter.py:133-151`). The direct metadata probe confirmed those values. Live shared-pool enforcement remains unverified.

## Outputs, exact datasets, and consumers

The sole successful unit output is `{completion: <reference>, terminal_status: "SUCCEEDED"}`. A reference contains run-relative path, SHA-256 and size; requests additionally carry the application run ID. Request schema is `build-iteration-request/1`, controller summary/ledger schema is `build-iterations/1`, workspace records use `build-workspace/1`, and worker receipts are language/JVM/Wasm producer receipts. Prepared/completed/configuration/selection documents are heterogeneous internal objects validated by their consumers, not all literal `build-iterations/1` objects.

| Dataset | Declaration and complete artifact grouping | Publication/use |
| --- | --- | --- |
| `iteration_records` | Step `execute`, family `build`, schema `appsec-review/build-iterations/1`; 21 patterns: `data/build/iterations/{ledger.json,controller.lock,pending.json,pending-invalidation.json,retention.json,selection.json}`; `{prepared,failures,recompositions}/*.json`; `leases/*/*.json`; immutable `artifacts/build/iterations/{graphs,configurations,requests,receipts,prepared,failures,completed,invalidations,failure-generation-selections,contexts,selections}/*.json`. | Protected sensitive operational authority, optional, unindexed. |
| `workspace_records` | Step `execute`, family `build`, schema `application/json`; 15 patterns: workspace lock; owner/state/deletion; replay owner/state/writer lock; immutable input, generations, products, invalidations and invalidation operations; attempt intent/failure/recovery. | Same protected operational disposition; target/install working bytes themselves are not this dataset. |

Both expose sanitized inventory/coverage metadata, not payload retrieval. The global inventory deliberately excludes this job from review producer handoffs while retaining its declarations for file accounting (`tests/test_inventory_publication.py:146-152`). The parent consumes the returned immutable completion, verifies products, and indexes receipt/product/generation in its ledger. `job_language_build` normalizes controller receipts into family outputs (`job.py:2013-2033`) and publishes accepted language-build receipts plus its build index (`:2122-2152`). Downstream review jobs consume **that parent publication**, not an internal transaction count.

The framework separately persists unit result/status/read receipts, attempt result/outcomes/handoff, and a latest pointer. `always_execute` avoids top-level request substitution; within-attempt checkpoint reuse still runs build-cache admission. `iteration_input_identity` hashes the verified pending request or explicit absence, not mutable workspace contents.

## Findings

### BI-F01 — Medium: changed accepted recipes are blocked before the controller can invalidate and rebuild

- **Evidence:** `src/appsec_review/jobs/build_iterations.py:281-306,317-325`; intended changed-binding invalidation at `:496-499,516-518`, closure computation at `:378-401`.
- **Trigger:** a node already has a verified committed product; a different recipe is validly bound to the same accepted source graph.
- **Expected:** validate old durable custody, invalidate the changed node and its dependent closure, then execute the new admitted binding while preserving unaffected producers.
- **Actual:** preflight compares the retained binding to the new selection and returns `BLOCKED` for the graph. It never reaches `_run`'s mismatch/invalidation branch.
- **Reproduced:** real synthetic accepted plan/refinement + real controller/workspace, fake worker/invoker. First recipe succeeded; an independently bound recipe adding `-g` returned `BLOCKED`, gap `retained producer differs from the selected recipe binding`, and worker count stayed **one**. **2.201 s**.
- **Impact/confidence:** high-confidence functional failure of the documented selective-rebuild/resume path; changed selected inputs cannot progress through that path.
- **Smallest correction:** separate old-custody integrity verification from equality with newly selected bindings; feed valid changed bindings into serialized invalidation, rather than treating all changes as global admission failures. Preserve refusal of genuinely untrusted old state.
- **Overlap:** no exact existing item/report found. T-084/T-057 are broader verification work; T-092 is a different failure boundary.

### BI-F02 — High: successful production of a promoted recipe prevents subsequent controller reconstruction

- **Evidence:** `src/appsec_review/jobs/job_build_iteration/job.py:114-118`; `job_language_build/job.py:1841-1846`; `build_iterations.py:1004-1012`; `build_recipe_replay.py:827-836,629-632,303-316`.
- **Trigger:** select a verified detached recipe trial, rerun that node successfully in production, then reconstruct a controller for a later node or resume.
- **Expected:** retain the selected recipe identity and verify immutable trial/production provenance without requiring production still to be at the original failure generation.
- **Actual:** every reconstruction calls `load_promoted_revision` → `_verified_trial` → `_validate_context`, which requires the current production generation to equal the failure-context generation and the failed node not to be accepted. Successful retry necessarily changes both. The selection pointer remains.
- **Reproduced through real selection:** synthetic accepted failure → real `replay_recipe` using simulated captured Docker responses → verified `select_promotion` → real `selected_revisions` → real controller commits production → the next real `selected_revisions` raises **`stale_generation: production advanced since the selected failure`**. **2.874 s**. No recipe/refinement/trial/product validators were mocked. An earlier narrower context check also reproduced it in **1.066 s**.
- **Impact/confidence:** high. A repaired node can succeed but stop remaining registered node invocations/consumer progress; later resumed selection also fails.
- **Smallest correction:** distinguish validating a still-failed context for a new trial/promotion from consuming an already-selected immutable revision. Use durable trial and current compatible production/upstream custody for consumption (the separate `verify_selected_trial` already avoids a production writer), preserving exact source/config/release/recipe identity checks.
- **Overlap:** no matching TODO/prior finding found; related broad T-084/T-057 only. This is not T-092's command-refusal policy.

### BI-F03 — Medium: product-verification failure loses the current failure-context entry

- **Evidence:** `src/appsec_review/jobs/build_iterations.py:223-252,258-272,583-593,870-875`; missing output rejection in `build_workspace.py:878-881`.
- **Trigger:** the worker returns a cleaned `SUCCEEDED` receipt plus explicit products, but contract verification/commit rejects a missing or invalid product.
- **Expected:** preserve a failed transaction context for this exact request/attempt and the verification error, without changing the original command receipt or accepting products.
- **Actual:** a failure pointer is written only when the original receipt status was not `SUCCEEDED`. The catch/parent rollback marks the transaction failed, but never writes/updates that pointer. `failure_context` then raises `FileNotFoundError`, or can see an older failure if one exists.
- **Reproduced:** success-shaped fake worker removes its declared `target/build/control` before returning. Controller returns `FAILED` and one prepared record, but no failure pointer; real `failure_context` raises `FileNotFoundError`. **0.731 s**.
- **Impact/confidence:** high-confidence loss of the supported repair context for an output-contract failure. No successful artifact leak was observed.
- **Smallest correction:** publish a transaction-level failure record from post-preparation verification failures, including exact request, original receipt and error evidence; update its pointer after custody/cleanup checks. Keep T-092's pre-prepared continuation decision separate.
- **Overlap:** related T-092/T-084, but this is **after** a prepared cleaned receipt and is not the recorded pre-prepared decision gap.

### BI-F04 — Medium: manual transaction CLI requires an unrelated configured checkout before reading its request

- **Evidence:** `src/appsec_review/cli.py:452-466`; `runtime/launch.py:71-80`; `jobs/cataloging.py:244-271`; contrast authoritative request target selection in `job_build_iteration/job.py:63-73`.
- **Trigger:** use the documented `run job_build_iteration --run-id ... --iteration-request ...` for an existing request whose target is valid, but the environment/default corpus checkout is absent or unrelated.
- **Expected:** derive target/source from the verified immutable request, as the registered implementation already does.
- **Actual:** common `launch_inputs(...)` runs **before** the iteration-specific branch, resolves and hashes the default/`--target` checkout, then discards those inputs. An absent unrelated target raises before the request is used; an existing unrelated target is needlessly read.
- **Reproduced boundary:** real `launch_inputs(build_job(), target=<unique nonexistent test/tmp path>, upstream_handoffs={})` raises `FileNotFoundError`, **<0.001 s**. The CLI/manual job itself was deliberately not launched; the ordering is verified statically.
- **Impact/confidence:** high-confidence manual recovery entry failure and an undocumented unrelated-target prerequisite.
- **Smallest correction:** handle the internal-transaction branch before generic target input construction; use only request-bound target admission there.
- **Overlap:** no exact TODO/prior report match. Existing CLI integration coverage was not run.

### BI-F05 — Medium: explicit native product contracts can accept executable bytes as a static library

- **Evidence:** `src/appsec_review/jobs/build_workspace.py:194-240,288-296,893-901`; `jobs/build_topology.py:1967-1984`; explicit production products at `job_language_build/job.py:1064-1074`; replay product validation/commit at `build_recipe_replay.py:368-382,598-604`.
- **Trigger:** an admitted explicit product declaration/promotion claims `kind=library, role=static_archive`, but its path contains an x64 ELF executable.
- **Expected:** byte validation rejects the wrong physical native role even when target ISA/axes match.
- **Actual:** `native_product_axes` accepts ELF machine/class and reports `import_library=False`; `verify_native_product` checks ISA and import-library Boolean only. Thus an ordinary executable satisfies the static-archive Boolean test. Shared commit and retained-product verification use this helper.
- **Reproduced:** a synthetic ELF executable written as `libwrong.a` is independently classified by real `binary_role` as `("executable", "elf")`; real `verify_native_product` accepts its `static_archive` spec. **<0.001 s**, no binary execution.
- **Scope/impact/confidence:** high-confidence primitive defect affecting explicit override/replay product paths and truthful consumer interfaces. Automatic `product_specs(..., bound=...)` has an additional physical-role filter and is **not** claimed to exhibit this for ordinary auto-discovered products.
- **Smallest correction:** verify full byte-derived container/role, not just machine/class and import Boolean, for each native role at the shared commit/reuse boundary; preserve archive member/target checks.
- **Overlap:** searched TODO and prior reports for product roles/static archives/native verification; no exact existing defect found.

## Focused validation

All Linux bodies ran using this transport, without writing shell scripts:

```powershell
$script = @'
set -eu
cd /home/wsollers/projects/appsec-review
# Literal Linux command body below.
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Preflight used `git rev-parse HEAD`, `git status --short`, `git branch --show-current`, `git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD`, and `.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'`. `offending_environment(os.environ)` returned `[]`; no APPSEC/DAGSTER/PYTEST_ADDOPTS/PYTHONPATH selectors were inherited. No dependencies were missing for the chosen pytest command.

### Executed unit command

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 461118 \
  --max-tests 53 --expect-tests 53 --strict -- \
  tests/unit/job_build_iteration/test_admission.py \
  tests/unit/job_build_iteration/test_contract.py \
  tests/unit/job_build_iteration/test_job_graph.py \
  tests/unit/job_build_iteration/test_controller.py \
  tests/unit/job_build_iteration/test_executor_capture.py \
  tests/unit/job_build_iteration/test_workspace_resume.py \
  tests/unit/runtime/test_wave3_contracts.py::test_wave3_contract_input_policies_match_confirmed_decisions \
  tests/unit/runtime/test_wave3_contracts.py::test_wave3_admission_rejects_missing_required_and_enabled_conditional_handoffs
```

- Reviewed collection: **51 job-specific cases plus two directly relevant shared contract cases = 53**.
- Wrapper-owned unique namespace: `test/tmp/tests-custom-20261118-140105-470411-3658196`. Its sequential collect/execute reuse is private to this invocation. No shared default basetemp was used.
- Collection: 53, **2.838 s** supervised stage. Execution: 53 passed, **7.25 s pytest / 11.393 s supervised stage**. Total **14.592 s**. Exit 0, no failures/skips, no cases over ten seconds, both process cleanup proofs confirmed.
- Reports: `test/tmp/logs/tests-custom-20261118-140105-470411-3658196.log`, adjacent `.collection.log`; `test/tmp/tests-custom-20261118-140105-470411-3658196.{collection.json,junit.xml,timings.sqlite}`; `test/tmp/reports/tests-custom-20261118-140105-470411-3658196.json`.
- Unit-tier no-real-engine/network/Dagster-execution guards remained in place. Tests use fake launch/controller/invoker or simulated Docker responses. The graph-definition test directly calls an op context, not `execute_in_process`.

### Executed reproduction commands

The first three-case attempt failed in fixture setup because the ad-hoc synthetic repository lacked `deploy/dagster/host-pins.toml`; no case reached its assertion. Exit 1; elapsed time was not separately recorded. Its failing setup was `accepted_native(path)` without first creating inert fixture pins. This was repaired only in the fresh disposable fixture, using the repository's test-pin helper, not production pins or an environment edit. Initial scratch `job-audit-build-iteration-repro-da4e7e3d9ea346ac8ebed5546bff53d4` was removed.

The successful three-case body was:

```bash
.venv/bin/python - <<'PY'
import copy,json,os,shutil,socket,subprocess,time,uuid
from pathlib import Path
from unittest.mock import patch
from appsec_review.jobs.build_iterations import failure_context,decode_replay_context,read_reference,IterationOutcome
from appsec_review.jobs.build_recipe_replay import _validate_context
from appsec_review.jobs.build_topology_artifacts import bind_actions,guard_action
from appsec_review.jobs.build_workspace import BuildWorkspace
from appsec_review.storage.shared import immutable_bytes
from tests.test_build_topology_refinement import accepted_native
from tests.test_native_target_enforcement import _profile
from tests.unit.job_build_iteration.test_workspace_resume import _iterations,_invoke,_succeeding_worker
from tests.host_pins_support import write_host_pins,fixture_preinstalled
base=Path('test/tmp')/('job-audit-build-iteration-repro-'+uuid.uuid4().hex)
base.mkdir(parents=True); os.umask(0o022)
print('scratch:',base)
results=[]
def prepared_case(name):
    path=base/name; path.mkdir()
    write_host_pins(path/'deploy/dagster/host-pins.toml',runtimes=fixture_preinstalled())
    return accepted_native(path)
def refuse_external(*a,**k): raise AssertionError('unexpected external process/network boundary')
try:
  with patch.object(subprocess,'Popen',refuse_external),patch.object(socket.socket,'connect',refuse_external):
    start=time.perf_counter(); runner,root,graph,action=prepared_case('changed-recipe'); calls=[]
    original=_succeeding_worker(root,graph,action)
    def worker(request,run_id):
      calls.append(request['attempt_id']); return original(request,run_id)
    first=_iterations(runner,root,graph,action).run(worker,invoke=_invoke)
    revised=copy.deepcopy(action); revised['recipe']['build_commands'][0].append('-g')
    revised=bind_actions(root,[revised],profiles=_profile(),policy=runner.config.job('job_project_build').settings['build_selection'],releases=runner.config.review_policy.releases.view())[0]
    second=_iterations(runner,root,graph,revised).run(worker,invoke=_invoke)
    results.append({'case':'accepted recipe change','first':first['states'],'second':second['states'],'second_terminal':second['terminal_status'],'gaps':second['gaps'],'worker_calls':len(calls),'elapsed_s':round(time.perf_counter()-start,3)})
    assert first['states'][action['build_unit_id']]=='SUCCEEDED' and second['terminal_status']=='BLOCKED' and len(calls)==1
    print(json.dumps(results[-1]))

    start=time.perf_counter(); runner,root,graph,action=prepared_case('missing-product')
    original=_succeeding_worker(root,graph,action)
    def missing(request,run_id):
      outcome=original(request,run_id); (BuildWorkspace(root).paths.target/'build/control').unlink(); return outcome
    failed=_iterations(runner,root,graph,action).run(missing,invoke=_invoke)
    pointer=root/'data/build/iterations/failures'/f"{action['build_unit_id']}.json"
    try: failure_context(root,action['build_unit_id'],[])
    except FileNotFoundError as error: context_error=type(error).__name__
    else: raise AssertionError('unexpected available failure context')
    results.append({'case':'successful command missing committed product','states':failed['states'],'gaps':failed['gaps'],'prepared_count':len(list((root/'data/build/iterations/prepared').glob('*.json'))),'failure_pointer_exists':pointer.exists(),'context_error':context_error,'elapsed_s':round(time.perf_counter()-start,3)})
    assert failed['states'][action['build_unit_id']]=='FAILED' and not pointer.exists()
    print(json.dumps(results[-1]))

    start=time.perf_counter(); runner,root,graph,action=prepared_case('context-after-progress')
    stdout=immutable_bytes(root,'artifacts/audit-command/stdout',b'')
    stderr=immutable_bytes(root,'artifacts/audit-command/stderr',b'synthetic build failure')
    def failing(request,run_id):
      return IterationOutcome({'build_unit_id':request['node_id'],'terminal_status':'FAILED','gaps':['synthetic build failure'],'commands':[{'exit_code':1,'timed_out':False,'stdout':stdout,'stderr':stderr}]},(),True)
    scheduler=_iterations(runner,root,graph,action); scheduler.run(failing,invoke=_invoke)
    from appsec_review.jobs.build_topology import proven_product_axes
    from appsec_review.config.build_selection import AXES
    node=next(n for n in graph['nodes'] if n['build_unit_id']==action['build_unit_id']); product=node['products'][0]
    products=[{'path':'target/build/control','kind':product['kind'],'product_id':product['product_id'],'interface':product['interface'],'variant':product['variant'],'role':'executable','axes':dict.fromkeys(AXES)|proven_product_axes(guard_action(root,action,graph=graph))}]
    context=decode_replay_context(read_reference(root,failure_context(root,action['build_unit_id'],products)))
    with scheduler.workspace.writer() as writer: _validate_context(scheduler.workspace,context,writer)
    retried=_iterations(runner,root,graph,action).run(_succeeding_worker(root,graph,action),invoke=_invoke)
    try:
      with scheduler.workspace.writer() as writer: _validate_context(scheduler.workspace,context,writer)
    except ValueError as error: reason=getattr(error,'reason_code',None); detail=str(error)
    else: raise AssertionError('expected stale context refusal')
    results.append({'case':'promotion consumption context after production progress','before':'valid','retry_states':retried['states'],'after_reason':reason,'after_error':detail,'elapsed_s':round(time.perf_counter()-start,3)})
    assert reason=='stale_generation'
    print(json.dumps(results[-1]))
finally:
  shutil.rmtree(base); print('own repro scratch removed:',not base.exists())
PY
```

Exit 0; results and per-case times are in BI-F01/03/02. Scratch `job-audit-build-iteration-repro-7fa9f4801cfa4280b384607c822b8468` was removed.

Full selected-promotion reproduction, rather than merely the context predicate:

```bash
.venv/bin/python - <<'PY'
import copy,json,os,shutil,socket,subprocess,time,uuid
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from appsec_review.config import BuildCaptureConfig
from appsec_review.container_runtime import BuildProfile,CaptureScope
from appsec_review.jobs.build_iterations import IterationOutcome,failure_context,decode_replay_context,read_reference,select_promotion,selected_revisions
from appsec_review.jobs.build_recipe_replay import RecipeCandidate,TrialExecution,replay_recipe
from appsec_review.jobs.build_topology import proven_product_axes
from appsec_review.jobs.build_topology_artifacts import guard_action
from appsec_review.jobs.build_workspace import BuildWorkspace
from appsec_review.storage.shared import immutable_bytes
from appsec_review.signing.policy import set_default_image_verifier
from tests.capture_fakes import minimal_elf,simulated_executor
from tests.host_pins_support import write_host_pins,fixture_preinstalled
from tests.test_build_topology_refinement import accepted_native
from tests.unit.job_build_iteration.test_workspace_resume import _iterations,_invoke,_succeeding_worker
base=Path('test/tmp')/('job-audit-build-iteration-promotion-'+uuid.uuid4().hex)
base.mkdir(parents=True); os.umask(0o022); start=time.perf_counter()
print('scratch:',base)
def refuse_external(*a,**k): raise AssertionError('unexpected real process/network')
try:
  with patch.object(subprocess,'Popen',refuse_external),patch.object(socket.socket,'connect',refuse_external):
    write_host_pins(base/'deploy/dagster/host-pins.toml',runtimes=fixture_preinstalled())
    runner,root,graph,action=accepted_native(base)
    action['image'].update(family='native',image_tag='fixture:local',user='1000:1000',dependency_hashes={})
    stdout=immutable_bytes(root,'artifacts/audit-command/stdout',b'')
    stderr=immutable_bytes(root,'artifacts/audit-command/stderr',b'synthetic build failure')
    def fail(request,run_id):
      return IterationOutcome({'build_unit_id':request['node_id'],'terminal_status':'FAILED','gaps':['synthetic build failure'],'commands':[{'exit_code':1,'timed_out':False,'stdout':stdout,'stderr':stderr}]},(),True)
    scheduler=_iterations(runner,root,graph,action); scheduler.run(fail,invoke=_invoke)
    product=graph['nodes'][0]['products'][0]
    specs=[{'path':'target/build/control','kind':product['kind'],'product_id':product['product_id'],'interface':product['interface'],'variant':product['variant'],'role':'executable','axes':proven_product_axes(guard_action(root,action,graph=graph))}]
    context=decode_replay_context(read_reference(root,failure_context(root,action['build_unit_id'],specs)))
    recipe=copy.deepcopy(context.accepted_recipe)
    recipe['build_commands']=[['clang','--target=x86_64-unknown-linux-gnu','main.c','-o','build/control','-g']]
    recipe['expected_outputs']=['build/control']
    candidate=RecipeCandidate(recipe,(stderr,),'synthetic missing executable correction')
    set_default_image_verifier(SimpleNamespace(enforced=False,verify=lambda *a,**k:None))
    def execute(invocation):
      def behavior(argv,target,cwd,environment,capture):
        capture.exec('/usr/bin/clang',argv)
        (target/'build/control').write_bytes(minimal_elf())
        return 0,b'',b''
      profile=BuildProfile('native','fixture:local',action['image']['image_id'],'1000:1000')
      executor=simulated_executor(profile,behavior)
      results=[]
      for ordinal in range(len(invocation.commands)):
        argv,cwd=invocation.prepare_command(ordinal)
        results.append(executor.execute_captured(argv,workspace=invocation.paths.target,install_dir=invocation.paths.install,working_directory=cwd,environment={},capture_directory=invocation.capture_directory/f'command-{ordinal}',capture_config=BuildCaptureConfig('ptrace',100,32,4096,True,128,16384,(),1024,100,100),scope=CaptureScope(context.run_id,'job_project_build',invocation.attempt_id,action['build_unit_id'],'native')))
      return TrialExecution(tuple(results),all(r.cleanup_complete for r in results))
    trial=replay_recipe(BuildWorkspace(root),context,candidate,execute=execute)
    trial_document=read_reference(root,trial)
    assert trial_document['status']=='SUCCEEDED',trial_document
    select_promotion(root,context.view(),trial)
    selected_graph,dispatches,overrides=selected_revisions(root,{'execution_graph':graph},[action])
    changed=dispatches[0]
    controller=_iterations(runner,root,selected_graph,changed); controller.product_overrides=overrides
    production=controller.run(_succeeding_worker(root,graph,changed),invoke=_invoke)
    assert production['states'][action['build_unit_id']]=='SUCCEEDED',production
    try: selected_revisions(root,{'execution_graph':graph},[action])
    except ValueError as error: reason=getattr(error,'reason_code',None); message=str(error)
    else: raise AssertionError('expected selection failure after committed promoted recipe')
    print(json.dumps({'trial_status':trial_document['status'],'promotion':'validated and selected','production_states':production['states'],'reconstruction_error':message,'reason':reason,'elapsed_s':round(time.perf_counter()-start,3)}))
    assert reason=='stale_generation'
finally:
  set_default_image_verifier(None)
  shutil.rmtree(base); print('own promotion scratch removed:',not base.exists())
PY
```

Exit 0, **2.874 s**; scratch `job-audit-build-iteration-promotion-03a6f3c1e88e477ba2d151aa2c52b99f` removed. Image-signature verification was an inert process-local fake for the fabricated image; command/capture normalization, recipe/refinement/trial/promotion/selection/product validation were real. Real subprocess creation and network connection were explicitly refused.

CLI input boundary:

```bash
.venv/bin/python - <<'PY'
import json,time,uuid
from pathlib import Path
from appsec_review.jobs.job_build_iteration.job import build_job
from appsec_review.runtime.launch import launch_inputs
start=time.perf_counter()
missing=Path('test/tmp')/('job-audit-build-iteration-missing-target-'+uuid.uuid4().hex)
try:
    launch_inputs(build_job(),target=missing,upstream_handoffs={})
except Exception as error:
    print(json.dumps({'case':'CLI pre-branch unrelated missing target','error_type':type(error).__name__,'message':str(error),'elapsed_s':round(time.perf_counter()-start,3)}))
else:
    raise AssertionError('expected unavailable unrelated target refusal')
PY
```

Exit 0; observed `FileNotFoundError`, reported 0.000 s. No path created.

Native role boundary:

```bash
.venv/bin/python - <<'PY'
import json,shutil,time,uuid
from pathlib import Path
from appsec_review.jobs.build_workspace import ProductSpec,verify_native_product
from appsec_review.jobs.artifact_kinds import binary_role
from tests.unit.job_build_iteration.support import NATIVE_OUTPUT,NATIVE_AXES,VARIANT
base=Path('test/tmp')/('job-audit-build-iteration-product-role-'+uuid.uuid4().hex)
base.mkdir(parents=True); start=time.perf_counter()
try:
  path=base/'libwrong.a'; path.write_bytes(NATIVE_OUTPUT)
  spec=ProductSpec('target/libwrong.a','library','declared-library','cmake-target:wrong',VARIANT,'static_archive',NATIVE_AXES)
  actual=binary_role(path)
  verify_native_product(path,spec)
  print(json.dumps({'claimed_role':spec.role,'actual_binary_role':actual,'verifier':'accepted','elapsed_s':round(time.perf_counter()-start,3)}))
  assert actual[0]=='executable'
finally:
  shutil.rmtree(base); print('own role scratch removed:',not base.exists())
PY
```

Exit 0; `claimed_role=static_archive`, `actual_binary_role=["executable","elf"]`, `verifier=accepted`, reported 0.000 s. Own scratch removed.

Other inspection-only commands read wrapper JSON timing and constructed the Dagster definition without executing it:
`iteration_definition(lambda *_: {}).graph.node_named("execute_build_node").definition.pool` returned `None`, tag `{"appsec/pool":"cpp_build"}`; `_pool_for("iterations.dispatch","job_language_build")` returned `application`. An initial shell search found WSL `rg` unavailable; subsequent searches used the authorized UNC tool. No installation was attempted.

## Read scope and named gaps

### Read fully

- Updated shared brief; authorized root `AGENTS.md`; canonical coordination skill.
- `docs/operations/job_build_iteration.md`; `docs/architecture/build-topology-and-iterations.md`.
- All three `src/appsec_review/jobs/job_build_iteration/` source files.
- `src/appsec_review/jobs/build_iterations.py`; `src/appsec_review/jobs/build_workspace.py`; `src/appsec_review/jobs/build_recipe_commands.py`; `src/appsec_review/jobs/build_topology_artifacts.py`.
- `src/appsec_review/jobs/job_language_build/datasets.py`; `src/appsec_review/orchestration/topology.py`; `src/appsec_review/runtime/launch.py`.
- Six job unit test files, their `support.py`; `tests/unit/runtime/test_wave3_contracts.py` (only its two job-relevant cases executed).
- Root and unit-tier `conftest.py`; environment guard; `tests/host_pins_support.py`; wrapper shell entry/common shell helper.

### Sampled / searched, not a full subsystem audit

- `job_language_build/job.py`: dispatch `175-262`, capture/checkpoint `906-969`, complete production/generic path `970-1690`, controller `1841-1921`, iterative family consumption `2013-2033`, final publication `2122-2180`. Remaining family helper modules were not independently re-audited; prior language-build report was consulted.
- JVM `jvm.py:676-930`; Wasm `wasm.py:267-492`; `build_recipe_replay.py:223-338,368-435,491-850`, plus symbol/bound searches. Early replay dataclasses, normalization and all lower helper internals were not fully reread.
- `build_topology.py:1944-2087` and topology-order locations; not the complete descriptor compiler/legacy graph implementation.
- Runtime registry, inputs/admission/read observation, runner publication/checkpoint slices, handoff artifact collection; container executor lease, plain execution, and capture entry slices; not the complete runtime/scheduler/native broker/signing/secret-scan implementation.
- CLI `435-480`; Dagster adapter scheduling/registered-definition/begin/completion slices.
- TOML internal and language settings/tasks; test map; relevant TODO entries and search matches. No TODO edits.
- Fixture helpers in `test_build_topology_refinement.py`, `test_native_target_enforcement.py`, `test_job_runtime.py`, `capture_fakes.py`; shared inventory test expectations.
- Prior project-build and language-build report findings/overlap sections. Prior reports were attribution context, not independently rerun evidence.

### Material unread / unexecuted scope

- No actual registered Dagster/controller-to-parent-publication end-to-end execution, native compiler output, image/profile acquisition, JVM/Android instrumentation, Wasm toolchain, model call, service, or target run.
- Four mapped integration files were **not executed**, including controller crash recovery, CLI, recipe replay executor and full build-iteration orchestration. No acceptance/live suites; no real cleanup/power-loss/cancellation/pool contention/retention deletion checks.
- No exhaustive platform matrix for PE/COFF/Mach-O/archives, symlink alias chains, all producer/consumer axes, or multi-node dependent invalidation. The native role reproducer is one synthetic ELF control.
- No independent end-to-end inventory/publication proof for every file matched by all 36 protected patterns. Declaration tests passed; that alone does not prove complete runtime output inventory.
- Existing T-084/T-092/T-147 remain named limitations. Previously reported language-family defects and upstream dispatch-read observation were not counted again.

## Completion

Final verified HEAD remained `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`; Git status was clean. Repository root was inspected; only this auditor's disposable reproduction subtrees were removed. This report is the sole persistent audit deliverable outside the ordinary test wrapper artifacts. Stop after job 46; no next job started.
