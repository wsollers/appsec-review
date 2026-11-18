# Functional audit — job_remediation_planning (40/47)

## Scope and result

- **Revision:** `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`, clean `main`, `/home/wsollers/projects/appsec-review`, Ubuntu-22.04 through `ssh wsl-ubuntu`. HEAD/cleanliness checked before testing and again at completion. Python imported `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.
- Read the complete updated shared brief and authorized checkout's `AGENTS.md` and coordination skill. No audit of the different Windows checkout.
- **Three reproduced functional defects:** RMP-01 high; RMP-02 and RMP-03 medium. Documentation/test-selection drift and previously reported limitations are separate below.
- **78 focused unit cases passed in 5.65 s; wrapper total 13.955645 s.** Two workers, shuffle seed 17440, exact collection count 78, zero failures/skips/tests over 10 s.
- Three bounded reproduction scenarios completed in **0.313005 s**; an optional-loader control completed in **0.001710 s**. An earlier reproduction attempt failed because its fixture run root was relative, not because of the audited behavior; recorded below.
- No repository/environment edits, installation, target execution, actual model/provider/compiler/tool execution, target patch application, live/integration/acceptance review, service operation, commit, push, or nested agent. Patch-writing tests touched only inspected synthetic pytest fixtures. Reproduction scratch was removed. Wrapper evidence remains under its private `test/tmp/` namespace.

## Registration, contract and intended behavior

Registered by `src/appsec_review/runtime/registry.py:182`; enabled by `appsec-review.toml:3713-3718`. Typed settings are selected in `config/loader.py:1446-1448`. The job has exactly three units and no undispatched declared task. Graph selection honors `.settings.enabled` through `runtime/selection.py:11-24`; direct explicit job execution is distinct from enabled graph membership.

`jobs/job_remediation_planning/datasets.py:19-62` declares review-graph dispatch, accepted-evidence target access, reusable rather than always-execute behavior, and propagating handoffs. It schedules after inference review and PoC. Topology removes transitive edges, yielding PoC as the immediate predecessor when enabled (`orchestration/topology.py:46-80`). **PoC scheduling is not PoC consumption:** no PoC input is declared, and plan/summary provenance deliberately uses `poc_handoff: null`.

The contract has 61 handoff-channel requirements across 19 producers:

- **Required/reject:** inference-review handoff `/2`.
- Optional/gap inference datasets: accepted scope, lead triage, review packages/cells, claim ledger, attack chains, scores/findings. These are declarations of potential use, not proof every dataset was read.
- Optional/gap language-build handoff, topology refinement, native/JVM build actions, language-build receipts and protected build workspaces. Actual source resolution is still native C/C++ only.
- `source_context_inputs()` supplies the 17-producer source/index view: target catalog, Tree-sitter, C++ compiled/symbol, SVF, code graph, CodeQL, static evidence, Clang, CPG, CI, artifact security, binary evidence, dependency intelligence, prioritization, security tagging, review-data indexing. Dataset ownership filters the accepted manifest (`jobs/bound_artifacts.py:55-158`). It does not grant arbitrary target reads.

Intended outcome: one row for **each accepted confirmed finding**, including capped and nonproposal rows; no supported finding becomes eligible merely because it has PoC documentation. A proposal is inert exact-edit JSON plus a separate safe regression specification, not a fix, runtime result, or changed adjudication.

## Every step/task traced

| Step / task | Actual implementation and output | Audit result / coverage |
|---|---|---|
| `load.verify_inputs` | `job.py:61-73`; `inputs.py:18-32`; shared `accepted_review.load_accepted_review`. Verifies review `/3`, run, schema, ledger/shards/projection, review-package manifests, score/finding packages, chain publication, PoC candidate consistency, exact confirmed/supported partition and shipment accounting. Projects accepted fields, sorts confirmed candidates, writes `priority-ranking.json` and immutable `inputs.json`; reports confirmed/admitted/omitted/supported-excluded counts. | **RMP-01:** ranker does not understand the actual accepted projection. Missing required review fails, not empty success. Safe units stub the accepted-review boundary; the complete real review production/verification path was inspected but not executed. |
| `assess.propose` | `job.py:75-154`; loops in candidate order, caps after `max_candidates`; resolves all direct-evidence IDs against hash-bound projection; lazily opens accepted source index, resolves source/build identities and bounds; pins writer guidance; invokes bounded writer; validates closed answer/cites and exact patch; writes source context, writer receipt, optional patch, plan and `outcomes.json`. | **RMP-02:** missing optional native-build handoff poisons the runtime input-read scope. **RMP-03:** source gaps disappear from row/summary if writer or patch validation fails. Otherwise precise nonproposal statuses, evidence mismatch failures and inert patch checks are implemented. |
| `acceptance.publish_handoff` | `job.py:156-196`; reloads accepted review, compares review-handoff pin, rehashes review bindings; requires ordered finding triples to exactly equal loaded intake; revalidates plans and nested references; schema-validates summary; publishes summary hash/count/gaps/status and outcome telemetry. | Empty intake is `SKIPPED_NA`; nonempty no-gap outcome is `SUCCEEDED`; any row gaps produce `COMPLETED_WITH_GAPS`. No extra model task here. It aggregates row gaps, so RMP-03 survives into accepted output. No independent patch reapplication or live validation is claimed. |

`_validate` checks exact configured step/task topology and typed settings (`job.py:44-48`). Unit dependencies are explicit (`job.py:193-196`); local `UnitExecutor` and runtime runner refuse successful continuation after failed prerequisites. Dagster pools: application for load, inference_teams for assess, lifecycle for acceptance (`orchestration/dagster/adapter.py:119,125-129`).

## Inputs, source identity, model limits and patch validation

### Accepted findings/evidence

`accepted_review.py` verifies immutable inputs rather than re-adjudicating. `confirmed_findings` checks exact partition membership and confirmed states. `evidence_relations` checks that every supplied direct-evidence relation exists in the accepted claim's projection (`inputs.py:27-46`). Empty direct evidence becomes an insufficient-evidence row without invoking the writer.

The actual projection preserves technical severity inside `ship_block.technical_severity`, score dimensions inside `scores`, and chain membership in `attack_chains` (`accepted_review.py:83-111`). It does not provide ranker's top-level severity/score/chain aliases. This is the decisive RMP-01 seam.

### Source custody and bounded access

`SourceReader.resolve` (`inputs.py:66-110`) queries `core.find(identity=..., limit=1)` only for bounded accepted relations. It locates native accepted build products, requires indexed file hash equal workspace-manifest hash, rejects unsafe paths, checks actual source bytes, file/aggregate byte limits and UTF-8, deduplicates paths, and retains source-location/unowned/byte/file/relation/encoding gaps.

`AcceptedBuilds` (`job_poc_generation/buildctx.py`) uses accepted language-build receipts, native build-product outcomes, hash-bound workspace manifest and protected compiler database, exact translation-unit command or explicitly labeled header default, and image/command/workspace/receipt identity. No build is executed. Missing or unsuitable source produces a named gap, except RMP-02's optional-absence runtime defect. Non-C-family paths return `not_c_family` before build lookup.

Retrieval is exactly `{path,start_line,end_line}`, an already admitted file, 1-based valid ordered integers, at most 120 lines. Full admitted file text is already in the initial task; later retrieval only slices that same content (`inputs.py:112-159`). No generic graph query, additional caller/header discovery, shell, target access or task delegation is dispatched by the writer.

### Settings used

`config/remediation.py` uses closed keys, strict integer/bool checks, model/text bounds and `max_candidates <= max_packages`; settings are canonically hashed. Current planning TOML (`appsec-review.toml:3720-3744`):

| Bound | Value |
|---|---:|
| Candidates / packages | 16 / 10000 |
| Source files / source bytes | 8 / 64000 |
| Patch files / patch bytes | 4 / 64000 |
| Per-file bytes / edits | 262144 / 32 |
| List items / text characters | 32 / 4000 |
| Workspace files / bytes | 100000 / 1073741824 |
| Writer | claude-cli / claude-haiku-5-5 / high |
| Input / output tokens | 64000 / **32000** |
| Turns / queries / total writer timeout | 6 / 4 / 600 s |

Workspace-copy limits are shared with validation; planning does not materialize a workspace, so it does not exercise those copy bounds. Relation source resolution is bounded, but the task/context still carry the full supplied relation list; the hard model request-byte limit remains the final backstop.

### Guidance/answer boundary

`guidance/workers.py:56-59,104-193`, `job_remediation_planning/model.py:33-67` and registry role/skill records select `remediation_writer`, synthesized `remediation_proposal` task, `worker-turn/1`, relation-ID citations, no persona or stack, stateful-invariant-analysis, and additionally evidence-and-graph-querying. Actual role, governing rules and both runtime procedures were read **as audited data**, not followed as repository-agent instructions. Bundle/answer hashes are retained.

`run_model` (`model.py:70-170`) permits only retrieve/final actions, enforces turn/query limits and shared `Execution` deadline/request/response/token accounting, accumulates response bytes, stops on malformed final output rather than repairing it, records failures and usage, and propagates integrity failures. Current request ceiling is input tokens ×3 bytes; cumulative output ceiling is output tokens ×8 bytes. Tests use `ModelResult` doubles, not providers.

`PlanAnswer` (`contracts.py:42-66`) requires exact answer fields, bounded nonempty reason/invariants/citations, unique accepted citation IDs, bounded assessment lists, full nonempty regression-spec fields, and patch iff `proposal_generated`. Generated `capped` is not a model answer; the application owns caps.

### Inert exact patch and protected output

`patches.py:25-148` validates cross-platform relative paths, canonical components, reserved names, duplicate/case-folded/overlapping file paths, exact SHA or new-file absence assertion, ordered nonoverlapping UTF-8 byte offsets, non-noop edits, patch/edit/file bounds, manifest/actual baseline hashes, exact old bytes and output UTF-8. It computes bytes in memory. **The planning job never calls `apply_exact`.**

`verify_patch_scope` (`contracts.py:69-91`) limits existing files to admitted evidence sources and new C/C++ source/header files to admitted parents, re-resolves build identity, and runs in-memory exact applicability checks. Build/tool-loading policy refusal belongs to downstream validation, not an assertion that the planner executes a proposed edit.

Plans bind run/review/finding/adjudication, source context, settings, guidance and writer result hash. `verify_plan` (`contracts.py:94-119`) schema-validates, rehashes nested context/receipt/patch, checks identity/role/cell/guidance/result agreement and patch/status consistency.

Datasets (`datasets.py:4-15`):

- `remediation_planning_summary`: artifact-only/internal, acceptance schema `/1`, claims all attempt load and acceptance trees, including ranking/input snapshot.
- `remediation_proposals`: protected/sensitive, plan schema `/1`, claims all attempt assess trees, including contexts, receipts, patches and unsuccessful outcomes.
- Both have sanitized metadata inventory routes, no retrieval payload index. A dataset declaration is not a claim every candidate produced a plan.
- The ranking has its own `/2` schema; `load` writes it without explicitly invoking that schema validator. Its shape is tested. This is a validation limit, not a demonstrated malformed production ranking.
- The job remains legacy `strict_gaps=False`. Shared control validation validates statuses/gap shapes, not arbitrary payload contents (`interchange.py:521-570`); runtime canonicalizes declared strings into producer gaps (`runtime/handoff.py:195-268`). Migration is an existing C15-F12 issue, not new here.
- Runtime publication binds artifact/control/claim/configuration/outcome identities and freezes accepted pointers (`runtime/runner.py:995-1087`, sampled). No full JobRunner/Dagster publication was executed in this audit.

## Reproduced defects

### RMP-01 — High — Risk-first ordering is disconnected from real accepted findings

- **Evidence:** `src/appsec_review/jobs/job_remediation_planning/prioritization.py:17-43,57-74,89-119`; actual producer projection `src/appsec_review/jobs/accepted_review.py:83-111`; `inputs.py:27-32`; `job.py:61-66,83-90`.
- **Trigger:** confirmed findings from the normal shared reader have different accepted severities, especially more candidates than the configured cap.
- **Expected:** accepted critical/high findings and applicable risk context determine which candidates receive proposals before lower-risk items.
- **Actual:** severity is read only from top-level aliases, numeric score only from top-level aliases or singular `scoring`, and chain membership only from `chain_ids`/other absent aliases. Actual packages provide nested `ship_block`, plural `scores`, and `attack_chains`. All actual packages therefore rank as unknown severity, zero score, no chain elevation, unestablished reachability, with finding-ID tie-breaking.
- **R1:** used actual `project_finding` on synthetic low and critical packages, reversed their input order, then actual three-unit planning with fake accepted-review/index/build/model boundaries and cap 1. Result: low `finding-1` → `proposal_generated`; critical `finding-2` → `capped`. Both priority entries recorded severity `unknown`, score `0.0`, chain_elevated `false`.
- **Impact:** the default 16-candidate cap can spend every proposal slot on lower-risk IDs while omitting critical findings; ranking also discards accepted rating provenance.
- **Confidence:** reproduced functional failure, with static production producer/consumer shape confirmation. It is not a claim that mere PoC/direct-evidence/chain presence proves reachability.
- **Smallest correction:** adapt the ranker to the verified projected shape (or construct a typed ranking projection before calling it); preserve distinct score dimensions and unknown reachability, explicitly define chain/leverage use, and test this actual producer-to-planner seam rather than only flat handcrafted ranking dictionaries.
- **Overlap:** **T-174** is already in progress and includes risk-first/leverage work. Its current “Why” discusses missing multi-language parser/semantic checks and preserving unknowns, not this still-broken accepted-shape integration. This is specific new evidence under that item, not a new unrelated workstream. Existing 12 T-174 tests use top-level synthetic inputs and miss the production seam.

### RMP-02 — Medium — Missing optional build becomes a sticky input-contract failure

- **Evidence:** `src/appsec_review/jobs/job_remediation_planning/datasets.py:43-54` declares optional/gap language-build; `job.py:79,98-99`; `inputs.py:81-84`; shared `job_poc_generation/buildctx.py:130-148,215-218`; `job_language_build/job.py:136-147`; `runtime/consume.py:187-198`; `runtime/inputs.py:388-422`; runtime use at `runtime/runner.py:685-687`.
- **Trigger:** native evidence location, but no language-build handoff supplied to the planning attempt (permitted by its contract, e.g. standalone planning or disabled/missing optional producer).
- **Expected:** `run_owned_source_unavailable:<path>:no_native_build` and a bounded manual/insufficient-evidence outcome.
- **Actual:** default `AcceptedBuilds` invokes `load_accepted_language_build(required=True)`. The required accepted-upstream boundary records an input violation. `AcceptedBuilds` catches the error and returns `no_native_build`, but the violation remains and the actual input-read scope fails on exit. Catching `MissingBuild` does not make the unit publishable.
- **R2:** actual `SourceReader` + `AcceptedBuilds` inside real `input_read_scope`, empty supplied pins, fake single native index row. `resolve()` returned the expected named source gap, then scope exit raised:
  `ValueError: input contract violation: accepted job_language_build handoff is required`.
- **Control:** same objects with loader calling `load_accepted_language_build(required=False)` retained the same source gap and exited scope successfully; no source edit or enforcement bypass.
- **Impact:** the job cannot deliver the promised optional-source gap outcome; real runtime execution can fail rather than account for missing source. Default graph prerequisite behavior may stop an earlier job first; this finding specifically concerns planning's admitted optional-input boundary.
- **Confidence:** reproduced real read-boundary failure; no full pipeline run claimed.
- **Smallest correction:** give this optional consumer an explicitly optional accepted-build loader; preserve required behavior for consumers whose contracts require builds. Add one test under actual input-read scope.
- **Overlap:** related to **T-113** boundary-test coverage and historical **C15-F05/C15-F17**, but those described PoC's required declaration and synthetic tests. Here planning's declaration is already optional; the sticky required-reader call is the distinct defect. No exact existing TODO for this call-site mismatch was found.

### RMP-03 — Medium — Writer/patch failure drops already-discovered source gaps

- **Evidence:** `src/appsec_review/jobs/job_remediation_planning/job.py:98-103,117-143,144-145,173-177`.
- **Trigger:** source resolution records omissions, then writer fails/times out/returns invalid output, or returned patch fails exact scope/applicability.
- **Expected:** the candidate/summary retain source-coverage gaps as well as model/patch failure.
- **Actual:** `gap_ids.extend(reader.gaps)` is inside the successful plan-writing branch only. Failure paths retain a model/patch reason and generic insufficient-evidence gap but omit every source gap from the published row/summary.
- **R3:** fake indexed location unavailable, then invalid fake writer answer. Protected source context recorded `source_location_unavailable:evrel-1`; published row and summary contained only `remediation_planning:claim-1:insufficient_evidence`, with `plan: null` and an invalid-output reason. The named source cause was absent.
- **Impact:** downstream gap/cost accounting loses the missing-source cause exactly when planning fails; consumers cannot distinguish/fix source availability versus writer failure using the accepted outcome. Protected context still exists in attempt artifacts, so this is not total destruction of diagnostic evidence, and the job correctly stays `COMPLETED_WITH_GAPS`, not success.
- **Confidence:** reproduced writer-failure branch; patch-failure branch shares the same statically verified omission.
- **Smallest correction:** add source gaps to the candidate immediately after resolution, independent of answer/patch success, and keep deduplicated summary aggregation. Preserve links to failure context/receipt if extending the output contract.
- **Overlap:** generic gap-format migration is historical C15-F12; native-only/manual limits are C15-F03/T-174. Neither explains away losing these already-produced source gap records. No exact existing TODO found.

## Documentation, tests, known boundaries and nonfindings

- **RMP-D01 — Low documentation drift:** `docs/operations/remediation.md:112` says writer output budget 16000, actual TOML is 32000 (`appsec-review.toml:3741`). `docs/operations/job_remediation_planning.md:476` still describes claim/package sorting although the handler calls a risk-first helper. Correct these when fixing the seam; do not rely on RMP-01 accidentally making the old description true.
- **Known C15-F16:** `docs/schemas/remediation/README.md:69-70` still says no runtime skill is loaded. Current code loads two for the writer. This is not newly counted.
- **Selection gap:** `tests/job-test-map.json:593-601` maps 66 tests in three unit files, omitting `tests/unit/job_remediation_planning/test_t174_risk_first_planning.py` (12 cases). This audit explicitly included it. The listed acceptance test in `tests/test_remediation_jobs.py` was **not run**.
- **Known payload-read observation gap:** `bound_artifacts.read_bound_json`/`resolve_bound` verify bytes but do not call dataset-aware `observe_output`; shared accepted review, language-build payloads, protected compile DB and workspace source reads retain this same limitation. Envelope consumption does use `accepted_upstream`; shard queries use `observe_shard`. Group with prior TA-F04/PB-F04/TS-F09/PBS-F10/RDI-K01 and language-build notes, not another new finding or a claim no hashes/pins exist.
- **Native-only source/new-file support** remains a known C15-F03/T-174 limitation. All nine language extensions in a static helper test do not make the production planner a nine-language source reader. No target fallback was added or requested.
- **Guidance capability mismatch, static limitation:** appended evidence-and-graph-querying text asks for indexed graph/CFG exploration and cell-local labels, while this worker exposes only admitted-source line retrieval and relation-ID final citations. Governing/task contracts still restrict it. No provider run establishes its practical model-output effect; do not call this a demonstrated authority expansion. It overlaps historical C15-F06 and T-173/T-174, and should be reconciled without silently broadening tools.
- **Not re-raised:** historical C15-F02 empty-intake gate failure is addressed in current `job_final_publication_gate/attachments.py:293-298` (accepts `SKIPPED_NA` for empty rows). Local planning empty-intake tests passed. No end-to-end gate run was done.
- Existing no-retry/byte-budget behavior (historical C15-F11), post-PoC scheduling with no PoC payload (C15-F10), absence of runtime fix verification (T-074 and policy) are recorded boundaries, not recommendations to loosen authorization or execute targets.
- Runtime-bound caches/reuse and signed deployment import verification were not exercised. `write_json` refuses an existing attempt-owned artifact; no per-candidate semantic resume cache exists in this job. Generic exact-input/config/component reuse was only sampled, not independently certified.

## Downstream compatibility traced

- **Validation** `job_remediation_validation/inputs.py:17-51`: accepted planning envelope/schema, exact review/finding order/count/gap union, required plan for generated status, nested `verify_plan`, matching status/reason. `job.py:94-180` rechecks adjudication, source-context relations, plan/build scope and patch; materializes only its own scratch and retains nonexecution assurance. No compiler/model validation was run by this audit.
- **Dossier** `job_dossier_publication/inputs.py:69-118,135-154`: summary/count/finding/confirmed-state/status/upstream checks, nested attachment identity/nonexecution, planning-validation handoff agreement. Only this immediate input seam was inspected.
- **Gate** `job_final_publication_gate/attachments.py:161-211,250-316`: schema-validates plan/summary, checks confirmed finding/adjudication/status/reason/upstream, hashes nested plan references, requires successful status to have artifact and exact confirmed set, projects sanitized statuses/refs/nonexecution, retains incomplete/capped/manual outcomes as capability gaps. Its schema check is not a fresh semantic review.
- **Final report expectation:** consumes the gate-certified attachment snapshot, not an independently rediscovered later planner output. Entire final-report rendering/export implementations were not read or run here.

## Validation commands and exact outcomes

All commands used the authorized SSH transport, with Linux source below placed verbatim in `$script`:

```powershell
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

### 1. Identity and unit preflight

```bash
set -eu
cd /home/wsollers/projects/appsec-review
printf 'HEAD '; git rev-parse HEAD
printf 'STATUS\n'; git status --short
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
```

Result: expected SHA, no changed/untracked repository files, import inside authorized checkout; exit 0.

### 2. Focused tests (only pytest invocation; collection is wrapper-owned)

```bash
set -eu
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
.venv/bin/python -c 'import os; from tests.test_000_unit_environment_guard import offending_environment; errors=offending_environment(os.environ); print("Unit environment:", errors); assert not errors'
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 17440 --max-tests 78 --expect-tests 78 -- tests/test_remediation_models.py tests/test_remediation_patches.py tests/unit/job_remediation_planning/test_coverage_edges.py tests/unit/job_remediation_planning/test_t174_risk_first_planning.py
```

Environment `[]`; exact collection **78**; **78 passed in 5.65 s**; total wrapper **13.955645053996705 s**, exit 0. No skips/errors/failures/slow cases. Xdist also executes the harness environment preflight. Count by file: models 25, patches 37, coverage edges 4, T-174 12.

Wrapper executed:

```bash
/home/wsollers/projects/appsec-review/.venv/bin/python -m pytest -p ops_test_guard -c /home/wsollers/projects/appsec-review/pyproject.toml --rootdir=/home/wsollers/projects/appsec-review -o addopts= -q -rfE --basetemp=test/tmp/tests-custom-20261118-133731-726119-3468885 --junitxml=test/tmp/tests-custom-20261118-133731-726119-3468885.junit.xml -o junit_family=legacy -n 2 --shuffle-seed=17440 tests/test_remediation_models.py tests/test_remediation_patches.py tests/unit/job_remediation_planning/test_coverage_edges.py tests/unit/job_remediation_planning/test_t174_risk_first_planning.py
```

Its preliminary collection used the same private namespace, removed `-n 2` and added `--collect-only`; collection cap 30 s, total cap 300 s, no other auditor shares this namespace. Both collection and execution cleanup confirmed no remaining processes.

Durable evidence relative to the authorized checkout:

- `test/tmp/logs/tests-custom-20261118-133731-726119-3468885.log`
- `test/tmp/logs/tests-custom-20261118-133731-726119-3468885.collection.log`
- `test/tmp/tests-custom-20261118-133731-726119-3468885.collection.json`
- `test/tmp/tests-custom-20261118-133731-726119-3468885.junit.xml`
- `test/tmp/tests-custom-20261118-133731-726119-3468885.timings.sqlite`
- `test/tmp/reports/tests-custom-20261118-133731-726119-3468885.json`

### 3. Offline R1–R3 reproducer

Executed through the same SSH transport, `.venv/bin/python -` (no pytest, subprocess target or external inference). Full successful source:

```bash
set -eu
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
.venv/bin/python - <<'PY'
import json, shutil, time, uuid
from pathlib import Path
from types import SimpleNamespace
from pytest import MonkeyPatch
from tests.unit.job_remediation_planning.test_coverage_edges import _seed_planning, _ctx
from tests import remediation_support as support
from appsec_review.jobs.accepted_review import project_finding
from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.jobs.job_remediation_planning import build_job
from appsec_review.jobs.job_remediation_planning.datasets import CONTRACT
from appsec_review.jobs.job_remediation_planning.inputs import SourceReader
from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds
from appsec_review.runtime.inputs import input_read_scope
started = time.monotonic()
scratch = Path('test/tmp') / ('job-audit-remediation-planning-repro-' + uuid.uuid4().hex)
scratch.mkdir(parents=True)
print('private scratch:', scratch)
base = scratch.resolve()
try:
    with MonkeyPatch.context() as mp:
        env = _seed_planning(base / 'risk', mp, candidate_count=2)
        projected = []
        for index, severity in enumerate(('low', 'critical')):
            package = {**env.review_doc['packages'][index], 'lane': 'lead', 'label': 'confirmed',
                'ship_block': {'policy': 'ship-block-policy/1', 'policy_sha256': 'a'*64,
                    'status': 'blocks' if severity == 'critical' else 'does_not_block', 'reasons': [],
                    'inputs': {'technical_severity': {'rating': severity, 'score_id': 'score-1',
                        'severity_floor': severity, 'severity_ceiling': severity, 'missing_factors': []}},
                    'conditions': {'distinct_verification_required': False, 'verifier_model_distinct': True}},
                'independence': {}, 'judge_verdict': None, 'verification_review_id': 'verification-1',
                'analyst_assessed_evidence': [], 'missing_predicates': [], 'gaps': [], 'poc': None,
                'attack_chains': ['chain-1'] if severity == 'critical' else []}
            projected.append(project_finding({'path': f'data/finding-{index}.json', 'sha256': package['sha256']},
                package, [{'technical_severity': {'scale': 'ordinal', 'rating': severity, 'value': None}}]))
        env.review_doc['packages'] = list(reversed(projected))
        job = build_job(infer=support.Writer(), builds_factory=lambda _: env.builds,
                        core_factory=lambda *_: env.core, repository_root=support.ROOT)
        result = job.execute(_ctx(env.root, support.planning_settings(max_candidates=1), 'att-risk'))
        assert not result['failed_units'], result
        loaded = read_bound_json(env.root, result['outputs']['load.verify_inputs']['artifact'])
        ranking = read_bound_json(env.root, loaded['priority_ranking'])
        summary = read_bound_json(env.root, result['outputs']['acceptance.publish_handoff']['artifact'])
        assert [x['ship_block']['technical_severity'] for x in loaded['candidates']] == ['low', 'critical']
        assert [x['status'] for x in summary['items']] == ['proposal_generated', 'capped']
        assert [x['severity'] for x in ranking['items']] == ['unknown', 'unknown']
        print('R1 actual accepted projection =>', json.dumps({'ranked_severities': [x['ship_block']['technical_severity'] for x in loaded['candidates']], 'ranking_items': ranking['items'], 'outcomes': [x['status'] for x in summary['items']]}))

    root = base / 'optional-build'; root.mkdir()
    context = SimpleNamespace(run_root=root, config=SimpleNamespace(job_id='job_remediation_planning'),
                              contract=CONTRACT, upstream_handoffs={})
    core = SimpleNamespace(find=lambda **_: {'results': [{'location': {'path': 'src/example.c', 'file_sha256': 'a'*64}}]})
    reader = SourceReader(AcceptedBuilds(root), core, [{'relation_id': 'r1', 'entity_id': 'e1'}], support.bounds())
    try:
        with input_read_scope(context):
            reader.resolve()
            print('R2 handler observes normal optional gap:', reader.gaps)
            assert reader.gaps == ['run_owned_source_unavailable:src/example.c:no_native_build']
    except ValueError as exc:
        assert str(exc) == 'input contract violation: accepted job_language_build handoff is required'
        print('R2 runtime rejects optional absence:', type(exc).__name__, str(exc))
    else:
        raise AssertionError('Expected sticky input-contract failure')

    with MonkeyPatch.context() as mp:
        env = _seed_planning(base / 'lost-source-gap', mp, candidate_count=1)
        job = build_job(infer=support.Writer(invalid=True), builds_factory=lambda _: env.builds,
            core_factory=lambda *_: SimpleNamespace(find=lambda **_: {'results': []}), repository_root=support.ROOT)
        result = job.execute(_ctx(env.root, support.planning_settings(), 'att-gaps'))
        assert not result['failed_units'], result
        output = result['outputs']['acceptance.publish_handoff']
        summary = read_bound_json(env.root, output['artifact'])
        source = json.loads((env.root / 'data/jobs/job_remediation_planning/attempts/att-gaps/steps/assess/tasks/propose/0/source-context.json').read_text())
        assert source['gaps'] == ['source_location_unavailable:evrel-1']
        assert summary['gaps'] == ['remediation_planning:claim-1:insufficient_evidence']
        print('R3 dropped source gap:', json.dumps({'source_context_gaps': source['gaps'], 'summary_gaps': summary['gaps'], 'row': summary['items'][0], 'terminal_status': output['terminal_status']}))
finally:
    shutil.rmtree(scratch)
    print('reproducer elapsed seconds:', round(time.monotonic()-started, 6))
PY
```

Result: all three reproduced assertions matched; exit 0, **0.313005 s** (measured scenario body; Python/SSH startup excluded). Scratch `test/tmp/job-audit-remediation-planning-repro-0be3664e1c8340e3a35d17f7621a3e4d` removed.

**Earlier attempt, not hidden:** same command/scenario body initially passed `scratch / 'risk'` and `scratch / 'lost-source-gap'` directly to `_seed_planning` rather than `base = scratch.resolve()`. It imported unused `copy`, `replace`, `UnitContext`; its elapsed print was after `finally`. R1 stopped at `assert not result['failed_units']`: guidance pinning raised `ValueError` because an absolute bundle path could not be made relative to a relative fixture run root. Exit 1, R2/R3 not reached, no elapsed value emitted. Scratch `...-6b9a09667125412cb635d60df4bbabfe` was removed in `finally`. The corrected command above matches pytest's absolute `tmp_path` convention; this failure is not counted as a production defect or passing test.

### 4. Optional-loader control and final identity

```bash
set -eu
cd /home/wsollers/projects/appsec-review
.venv/bin/python - <<'PY'
import shutil, time, uuid
from pathlib import Path
from types import SimpleNamespace
from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds
from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.jobs.job_remediation_planning.datasets import CONTRACT
from appsec_review.jobs.job_remediation_planning.inputs import SourceReader
from appsec_review.runtime.inputs import input_read_scope
from tests.remediation_support import bounds
start = time.monotonic()
scratch = Path('test/tmp') / ('job-audit-remediation-planning-optional-control-' + uuid.uuid4().hex)
scratch.mkdir(parents=True)
try:
    root = scratch.resolve()
    ctx = SimpleNamespace(run_root=root, config=SimpleNamespace(job_id='job_remediation_planning'), contract=CONTRACT, upstream_handoffs={})
    builds = AcceptedBuilds(root, loader=lambda r: load_accepted_language_build(r, required=False))
    core = SimpleNamespace(find=lambda **_: {'results': [{'location': {'path':'src/example.c','file_sha256':'a'*64}}]})
    with input_read_scope(ctx) as reads:
        reader = SourceReader(builds, core, [{'relation_id':'r1','entity_id':'e1'}], bounds())
        reader.resolve()
        assert reader.gaps == ['run_owned_source_unavailable:src/example.c:no_native_build']
        assert reads.violation is None
    print('R2 control: explicit optional loader retains gap and exits input scope cleanly')
finally:
    shutil.rmtree(scratch)
    print('control elapsed seconds:', round(time.monotonic()-start,6))
PY
printf 'FINAL HEAD '; git rev-parse HEAD
printf 'FINAL BRANCH '; git branch --show-current
printf 'FINAL STATUS\n'; git status --short
```

Result: control passed, **0.001710 s**, exit 0; expected HEAD, `main`, clean status. No repository changes.

## Read inventory and named gaps

**Read fully:**

- Shared session audit brief; authorized `AGENTS.md`; `.claude/skills/multi-session-coordination/SKILL.md`; development-skill pointer and skill-directory inventory.
- All eight files in `src/appsec_review/jobs/job_remediation_planning/` (`__init__`, contracts, datasets, inputs, job, model, patches, prioritization).
- `src/appsec_review/config/remediation.py`; `jobs/accepted_review.py`; `jobs/bound_artifacts.py`; `jobs/completion_contracts.py`; `job_poc_generation/buildctx.py`; `job_remediation_validation/inputs.py`; `job_inference_security_review/schemas.py`; `guidance/workers.py`; `runtime/job.py`, `runtime/units.py`, `runtime/consume.py`; `orchestration/topology.py`.
- Planning schema files `plan`, `planning`, `planning-handoff`, `exact-patch`, `common` under `docs/schemas/remediation`; both ranking schemas under `docs/schemas/remediation-planning`.
- `docs/operations/job_remediation_planning.md`, `docs/operations/remediation.md`, `docs/architecture/evidence-completion-and-remediation.md`, T-174 task document.
- Governing rules, remediation writer role, both selected runtime skill texts as data.
- Four selected test files, `tests/remediation_support.py`, unit-environment guard; wrapper shell and `scripts/lib/common.sh`.

**Sampled / relevant sections searched:**

- Central TOML planning block; config loader typed selection; registry registration; Dagster pool map; job-test-map planning/shared selections; guidance registry role and skills.
- Runtime input scope/admission/observations, dataset declarations/helpers, publication/control outcome and reuse paths; shared `interchange.py` control validator; model `Execution` through request/response/deadline/token enforcement.
- `tests/conftest.py` safety, collection, environment, timing and no-render fixtures; wrapper Python command/collection/count/deadline/report implementation.
- Immediate remediation-validation job source through patch/source/static/semantic commissioning, gate attachment validation/projection, dossier input verification, accepted-language-build reader.
- `docs/TODO.md` remediation/risk/test topics and T-074/T-147/T-173/T-174 entries; historical C15 section of `docs/reviews/system-review-2026-11-13.md`; cumulative and prior session reports searched for overlap.
- Schema README's runtime-skill claim. Other upstream schemas and helpers are dependencies, not all independently audited.

**Material unread/unexecuted scope:**

- Complete actual inference review generation, adjudication, ledger/chain/scoring internals and their schema corpus; actual accepted run artifacts; full source-shard implementation and receipt production. The shared verifier itself was read, but its full end-to-end execution was not admitted.
- Real model/provider adapters, model competence/semantic patch quality, secret-bearing real source, compiler/language tools, real targets, deployment/signature runtime, Docker, services.
- Full generic JobRunner/Dagster admission/publication/reuse integration, concurrent accepted-input replacement, all downstream dossier/report/export rendering. Only immediate contracts/consumer seams were inspected.
- Mapped acceptance test and other integration/live/full suites intentionally not run. Passing these units does not prove an accepted live run, correct model remediation, successful build, or a fixed finding.

**Stop point:** this job only; report is the persistent deliverable. No remediation implemented and no subsequent job started.
