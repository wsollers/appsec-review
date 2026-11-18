# Job 9/47 audit — job_target_analysis_plan

## Scope and verdict

- **Source:** `/home/wsollers/projects/appsec-review`, Ubuntu-22.04, SSH `wsl-ubuntu`; branch `main`, exact commit **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**. HEAD and tracked/untracked Git cleanliness were checked before validation and after the audit; unchanged and clean. The editable import resolved to this checkout's `src/appsec_review/__init__.py`.
- **Authorization:** read-only functional audit; synthetic, offline unit tests and in-memory/scripted-provider reproductions only. No source edits, actual model/provider calls, scanner/compiler execution, target-program execution, integration/live/acceptance runs, Docker/service changes, commits or pushes.
- **Activation:** registered by `runtime/registry.py:143-144`, enabled in the dev configuration, `review_graph`, target access `checkout`, propagating handoff, not `always_execute`. There are **three steps and seven tasks**; all are implemented and were traced.
- **Result:** one high and four medium functional findings below, one low documentation discrepancy, and a repeatable test-fixture gap. The focused suite reports **142 passed, 1 failed, 0 skipped, 6.74 s**. This is not certification of real recipes, scanner coverage or live review quality.

Paths in evidence citations are repository-relative. Short Python paths such as `runtime/registry.py` abbreviate the `src/appsec_review/` prefix; the task table's `job.py` and `planning.py` are in `src/appsec_review/jobs/job_target_analysis_plan/`. Runtime prompt text was read as data, not followed as auditor instructions.

## Intended contract and actual dataflow

The planner should turn accepted catalog identities into deterministic scanner scopes and a complete accounting of build units, optionally obtain bounded recipes, and publish a validated plan plus an `analysis/target-analysis-plan` retrieval shard. Model output cannot establish ownership, scheduling, native proof or execution authority. Every action remains `executable=False`.

`jobs/job_target_analysis_plan/datasets.py:39-86` declares these input groups:

| Producer | Declared datasets and authority | Actual reads in this job |
| --- | --- | --- |
| `job_target_catalog` | Required/reject `handoff`; optional/gap `target_artifact_inputs`, `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units`, `catalog_documents`; producer evidence | `_accepted_catalog` reads the pinned handoff, target-catalog document, partition, projects, components, build systems, compile databases and build targets. Source/catalog index manifests are composed later. Target binary intake is not projected into the plan (TA-F02). Payload reads lack dataset-level observations (TA-F04). |
| `job_build_environment_analysis` | When-enabled/gap `handoff`; optional/gap `build_environment`; operational | `load_catalog` requires an authoritative launch contract and calls `load_environment`. Expected-current evidence verifies the current catalog pin; optional-prior evidence has separate admission and may become stale/unavailable. Both envelope and environment payload observations exist. |
| `job_source_history_analysis` | Optional/gap `handoff`, `history_signals`, `history_documents`, `raw_git_history`, `history_tool_io`; routing context | Accepted history document is read through the history helper; a different snapshot is marked stale. Catalog-matching file/component ranks and separately labelled changelog ranks enter the plan. No direct raw-Git/tool-I/O processing by the planner. |
| `job_review_intake` | Optional/gap `handoff`, `model_preflight`, `binary_evidence`, `review_intake`; producer evidence | No explicit intake/model-preflight/binary processing in the seven handlers; declarations also support shared input/manifest ancestry. Declaration/supply must not be reported as payload consumption. |

The explicit scheduling predecessors are CI analysis, source history and build-environment analysis. `orchestration/topology.py:46-80` derives graph edges from schedules plus consumed producers, and transparently walks through disabled graph nodes. CI has no planner input declaration or handler read. That is still the barrier described in prior report **C05-F06**, not newly measured CI integration or runtime cost.

Publication declarations:

1. Required indexed `analysis_plan`: retrieval-index/2, index `analysis`, shard prefix `target-analysis-plan`.
2. Sensitive artifact-only `analysis_plan_documents`: attempt `artifacts/analysis-plan/*.json`, containing the summary and accepted plan.
3. Protected `planning_feedback_cache`: `data/planning-feedback/*.json`; complete validated final plus exact additive documents, not a public payload route.

Artifact glob locations match the writers. The artifact-only declaration describes a document family: the summary itself has `target-analysis-summary/1`, the accepted document has `target-analysis-plan/1`, and cache files are wrapper objects containing a proposal/3. No separate schema validation of every such wrapper was established. This is not treated as an indexed-shard schema defect.

## Every declared task

| Step / task | Actual implementation and dependencies | Processing, output, validation and limits |
| --- | --- | --- |
| `catalog_summary.load_accepted_catalog` | `job.py:275-288`; root unit at `:650` | Reads `_accepted_catalog` (`:95-147`), requires claim/source equality, loads accepted history and environment. `_read_artifact` checks run custody, length, digest and object type; catalog/partition use 32 MiB, other catalog children 16 MiB. Returns catalog/history/environment. TA-F02 and TA-F04 affect this boundary; TG-01 concerns its unit fixture. |
| `catalog_summary.summarize_components` | `job.py:290-301`; depends on load | Applies Swift execution filtering, calls `summarize_catalog`, writes hash-bound `catalog-summary.json`, emits a named truncation gap. Full accepted descriptor authority is not mutated. TA-F03: trimming can make evidence impossible to request and can exceed the item limit. |
| `analysis_decisions.apply_deterministic_rules` | `job.py:303-324`; depends on load and summary | Uses full filtered catalog, exact ownership and shared tool support rules; accounts for all baseline scanner IDs and build units. Carries compile-database/source-only/history context, environment gaps, source graph, evidence bundle and refinement. Null recipes and non-executable actions are explicit. No model called here. |
| `analysis_decisions.resolve_ambiguity` | `job.py:326-514`; depends on deterministic/load/summary | No ambiguity → zero calls. Disabled/unwired model → named gap with deterministic plan retained. Excludes Unity, groups by family/system/image, partitions by count and sanitized serialized bytes, enforces scope cap, runs bounded feedback in a bounded thread pool. Merges recipes/additive evidence and recompiles the whole graph; omissions/abstentions/exhaustion remain gaps. TA-F01, TA-F03 and TA-F05 apply. |
| `plan_acceptance.validate_plan` | `job.py:516-526`; depends on resolve and load | `planning.py:827-899` checks source/catalog identities, scanner path/hash membership and mandatory accounting, accepted components/history paths, exactly one action per unit, unchanged descriptor facts, valid recipes, no inferred Unity recipes, `executable=False`, and deterministic graph equality. Writes `accepted-analysis-plan.json` within 32 MiB. It is not a build/recipe-execution acceptance test. |
| `plan_acceptance.index_plan` | `job.py:528-618`; depends on validate | Fingerprints the plan artifact with parser/normalizer/identity versions; indexes components, scanner selections, actions and source-backed facts/relations. Reattests an existing content-addressed SQLite shard; composes and verifies the manifest while retaining the stable upstream index set. Counts include graph facts. Focused synthetic runner test exercises creation and reuse. |
| `plan_acceptance.publish_handoff` | `job.py:620-645`; depends on validate/index/resolve | Publishes plan artifact, graph/schema identity, manifest/shard identity, item count, coverage gaps, model-call/scanner/build-disposition counts and terminal status. Emits completion telemetry. Shared runtime validates task receipts/control records and artifact closure. No bespoke Job output validator or result transform. |

`job.py:648-677` wires every task into `UnitExecutor`; `_validate_config` (`:200-233`) enforces exact step/task order. Dagster generates an op for each unit and a dependent finalizer (`orchestration/dagster/adapter.py:250-294`), using `JobRunner.execute_or_reuse_unit`. The runner verifies dependent receipt/result hashes, invokes the real handler under input/publication scopes, and persists input-consumption records (`runtime/runner.py:639-735`).

### Models, defaults, response acceptance and reuse

- TOML `:894-940`: summary 2,000 items / 524,288 bytes / 20 files per prefix. Model defaults: enabled, `claude-cli`, `claude-haiku-5-5`, medium reasoning, 32,000 input and output tokens, 300-second call timeout, three retries, six model workers.
- `PlanningFeedbackSettings` (`config/loader.py:510-540`) defaults/caps: 512 scopes, 16 units/scope, four calls, three evidence rounds, eight documents/request, 65,536 bytes/document, 262,144 additive bytes, 131,072 request bytes, 65,536 response bytes, 300 seconds/scope. Only positive integers up to those defaults are accepted. The effective request bound is also capped at `max_input_tokens * 4`; retries tighten total calls to `min(max_calls, 1 + retries)`.
- `guidance/workers.py:31-34,96-181` selects the DevOps persona, one of nine family roles, registered `target-analysis-planning` procedure, shared governing rules, and a generated `target_analysis_planning` task sentence. This task is not a separate task-prompt file. Guidance is hash-pinned before dispatch. All nine selected role files were read.
- Actual request component/scanner allowlists are empty; build-system/image/unit/path allowlists are group-scoped. `plan_prompt` carries these and a generated capability card. The helper supports bounded component proposals, but the real worker is instructed to return none.
- `need_evidence` checks exact inventory identity, request allowlist, root, progress, raw hash, UTF-8, redaction and document/additive limits. Unexpected custody/application failures propagate. Valid finals account for every scoped unit by recipe or abstention; hints cannot alter graph facts. TA-F01 identifies malformed nested values that bypass the intended rejection path.
- Cache keys bind request, accepted units, source, guidance/model, whole bundle, environment/profiles/rules, limits and timeout. Reads revalidate documents and final proposal; abstained/partial/failed results are not complete caches. No live provider was involved in testing.
- Whole-job resume checks configuration/source/release/dataset/upstream identities and planner environment equality (`runtime/resume.py:72-174`). `load_accepted_plan` verifies the graph, current environment and whole-bundle/refinement reproduction (`job.py:151-197`). Index reuse reattestation and cache replay were covered offline; no live resume was attempted.
- Planner legacy string gaps are normalized by shared outcomes. A producer `SUCCEEDED` label can coexist with explicit partial coverage; no claim here confuses framework completion with a clean target. Strict-gap conversion remains existing **T-089** work.

## Findings

### TA-F01 — High: malformed nested model values abort the job instead of bounded rejection

- **Evidence:** `src/appsec_review/jobs/job_target_analysis_plan/planning.py:363-366,795-805`; `src/appsec_review/jobs/build_discovery.py:1839-1842`; transport parser `src/appsec_review/inference/claude_cli.py:47-63`.
- **Trigger:** otherwise JSON/schema-bearing final response with `abstentions[0].build_unit_id=[]`, or a recipe with `image_profile={}`.
- **Expected:** reject the malformed response with bounded validation errors, permitting configured repair or named exhaustion. Actual transport parsing does not validate nested JSON Schema.
- **Actual:** hash-container membership occurs before scalar type checks. Real `bounded_feedback` raises `TypeError: unhashable type: 'list'` / `'dict'` after one scripted call. A second valid scripted response is never requested. The exceptions occur outside its recognized provider/output rejection handling.
- **Impact:** one ordinary malformed model response fails ambiguity resolution and blocks plan publication and dependent jobs, rather than preserving the deterministic plan with a model gap.
- **Confidence:** high; both cases reproduced through the real parser and feedback/recipe validators.
- **Smallest correction:** validate nested scalar/container types before normalization and membership operations; make response validation total over finite JSON, returning bounded errors. Do not broadly swallow unexpected application exceptions. Add the two cases to the existing feedback suite.
- **Overlap:** no matching specific TODO/prior finding found in inspected material. Root-cause examples extend the existing malformed-response tests rather than requesting a new inference design.

### TA-F02 — Medium: real prebuilt artifact intake never reaches plan artifact selections

- **Evidence:** `src/appsec_review/jobs/job_target_analysis_plan/job.py:107-145`; `planning.py:170-175,231-244,303-308`; actual producer `src/appsec_review/jobs/job_target_catalog/job.py:232-266,388-417`; downstream `src/appsec_review/jobs/job_evidence_collection/job.py:1346-1354`.
- **Trigger:** an accepted catalog partition contains target-owned prebuilt binaries/JARs.
- **Expected:** accurately represent these accepted inputs in artifact applicability/targets, or explicitly leave binary-scanner planning to the owning artifact lane.
- **Actual:** `_accepted_catalog` filters `build-targets.targets` for `artifact_kind == "built"`. The real producer emits discovered build units there, while accepted binary intake lives in `partition.target_artifacts`. It never transfers that intake. Consequently SpotBugs/BLint scopes and plan target/link-output collections stay empty.
- **Reproduction:** real `_accepted_catalog` with hash-verified synthetic child documents containing one partition JAR and normal discovered build units returned zero accepted artifacts and empty SpotBugs scope. No binary was executed or scanned.
- **Impact:** the plan-driven lane can mark applicable binary analysis unselected. Independent later artifact-security processing may still operate; this audit does **not** claim all final binary coverage is lost.
- **Confidence:** high. The existing contract fixture inserts an artificial `artifact_kind="built"` target (`test_contract.py:260-263`), so its passing assertion does not cover the real producer shape.
- **Smallest correction:** wire declared partition artifact intake with correct source/run-path normalization, or remove those scanner decisions from this plan and explicitly delegate them. Add a producer-shaped offline fixture.
- **Overlap:** **previously reported C05-F02**, `docs/reviews/system-review-2026-11-13.md:842-850`; still present at this SHA. Not a new cumulative discovery.

### TA-F03 — Medium: summary trimming strands accepted evidence and fails its item cap

- **Evidence:** `src/appsec_review/jobs/job_target_analysis_plan/planning.py:101-147,577-603`; request construction `job.py:370-375,389-439`.
- **Trigger:** item/byte trimming removes accepted non-marker descriptor documents; separately, accepted build-unit count exceeds `summary_max_items`.
- **Expected:** trim illustration before build evidence; keep omitted evidence discoverable within bounded feedback; enforce the declared item budget or return an explicit bound outcome.
- **Actual:** `trim_one` removes descriptor documents first, although `item_count` does not count them. Request construction uses the trimmed summary, but `feedback_request` calculates “already captured” documents from the full original catalog and excludes them from the additive inventory. Thus omitted non-marker documents can be absent from both model context and every allowed evidence-request path. The item-count loop also breaks without error once only build units remain, even if still over the configured cap.
- **Reproduction:** a two-unit summary with `max_items=2`, generous 524,288-byte bound, and accepted `node-00/tsconfig.json` produced a 1,320-byte truncated summary where that file was absent from summary documents, allowed paths and evidence inventory. With three units and `max_items=1`, three units remained and `items_emitted` reported zero.
- **Impact:** unnecessary loss of recipe evidence, unrecoverable evidence requests and misleading bounds metadata. The deterministic graph retains full source authority; the demonstrated loss is in model visibility, not deletion of accepted catalog data.
- **Confidence:** high.
- **Smallest correction:** make count/trim policy consistent, preserve evidence or offer omitted documents under the existing evidence bounds, and explicitly handle unavoidable unit-count overflow without silently widening limits.
- **Overlap:** **T-112** owns trim ordering/accounting, with related **T-111** descriptor bounds. The feedback-inventory exclusion and retained-unit over-cap consequences were reproduced here; consolidate them with that work rather than creating duplicate backlog entries.

### TA-F04 — Medium: document consumption is missing from typed input receipts

- **Evidence:** `src/appsec_review/jobs/job_target_analysis_plan/job.py:95-119,168-197`; `src/appsec_review/runtime/consume.py:173-202`; `src/appsec_review/runtime/inputs.py:453-470,527-551`.
- **Trigger:** planner reads catalog documents, or another typed job calls `load_accepted_plan`.
- **Expected:** actual payload reads carry their declared dataset identity and observation, independently of envelope access.
- **Actual:** these readers call `accepted_upstream` and `_read_artifact` but never `observe_output` for `catalog_documents` / `analysis_plan_documents`. `accepted_upstream` records only `handoff`. The successful real offline JobRunner task's `status.json` recorded exactly `job_target_catalog/handoff`, despite reading the catalog and all six child documents.
- **Impact:** catalog/plan datasets appear supplied-but-unread, payload-level consumption/provenance is incomplete, and the explicit payload-schema/authority observation boundary is not exercised. Byte/hash validation still occurs; this is not a claim that arbitrary bytes bypass hashes.
- **Confidence:** high for the catalog receipt, directly observed; high static confidence for the structurally identical accepted-plan reader. No downstream live receipt was collected.
- **Smallest correction:** add the appropriate `observe_output` calls after obtaining pinned payload references, then assert the real task receipts and a downstream accepted-plan read. Keep envelope and payload observations distinct.
- **Overlap:** related to the input-observation repairs described under **T-113** (Waves 2/4) and declaration work **T-147**, but their inspected completion text does not include these payload readers. Source-history's similar helper was sampled, not claimed as a new separate job finding.

### TA-F05 — Medium: .NET planning guidance contradicts the recipe validator

- **Evidence:** `pipeline/prompt-fragments/roles/build-engineer-dotnet.md:7-12`; selected by `job_target_analysis_plan/job.py:384-387`; `src/appsec_review/jobs/build_discovery.py:1943-1952`; `tests/test_build_discovery.py:641-659`.
- **Trigger:** .NET unit with `PackageReference`/`PackageDownload`, but no separate proof that project-image preparation must download dependencies.
- **Expected:** a recipe following the selected role's definition of `network_required` should have a compatible acceptance rule.
- **Actual:** the role explicitly says package references alone do not prove image-preparation download and limits `true` to that proof. The validator unconditionally rejects `false` whenever those package tags occur. The image implementation does use `true` to add a dependency-restore layer (`container_runtime/project_images.py:466-470`), so this is a genuine disagreement about the same field, not merely naming.
- **Reproduction:** scripted valid .NET final with `false` exhausted all four calls with `.NET recipes with accepted package references require dependency egress`; changing only the Boolean to `true` was accepted in one call.
- **Impact:** an obedient worker can repeat an otherwise valid rejected recipe or abstain; acceptance requires departing from the selected explanation. Live model behavior/frequency was not measured.
- **Confidence:** high for the prompt/validator contradiction and deterministic rejection.
- **Smallest correction:** reconcile the role's field definition with intended dependency-image behavior and validator policy; add a focused prompt/validator parity case. Do not implicitly widen build-network authorization.
- **Overlap:** no matching specific TODO/prior finding found in inspected material.

## Documentation and test/environment gaps

### TA-D01 — Low: topology input budget is overstated

`docs/operations/target-analysis-planning.md:158-160` says topology inputs/refinements are capped at 32 MiB. `src/appsec_review/jobs/build_topology.py:545-570` rejects the evidence bundle above **16 MiB**. Plan artifact readers/writers do permit 32 MiB. An operator sizing a large accepted descriptor bundle against the prose would encounter an earlier refusal. Correct the distinction in documentation; this audit does not authorize raising a bound. High static confidence; no large-bound stress run was performed. Related general bound work: T-111, not an identified exact duplicate.

### TG-01 — Repeatable stale fixture, not demonstrated production failure

`tests/unit/job_target_analysis_plan/test_contract.py::test_load_catalog_reads_supplied_environment_and_records_producer_scope` fails both shuffled/parallel and alone:

```text
E appsec_review.runtime.consume.UpstreamNotPinnedError: job_target_analysis_plan reads job_target_catalog, which is not supplied by the attempt claim; provide the declared typed input
```

The fixture supplies only the environment pin (`test_contract.py:636-642`) and mocks `_accepted_catalog`; the real expected-current `load_environment` now reads the catalog pin (`job_build_environment_analysis/job.py:238-240`). It creates a synthetic catalog pointer without the actual handoff (`test_contract.py:567-572`). Updating only the expected receipt list is insufficient: supply a real pinned catalog publication too. This is a test setup/expectation gap, not evidence that a correctly admitted graph fails. It fails alone, so it is not attributed to test ordering.

Existing limits not counted as new findings: T-035/T-036/T-037 component/build-mode/recipe-provenance work, T-089 legacy gaps, T-111/T-112 descriptor/summary bounds, T-147 task-binding declarations. CI scheduling-only behavior remains prior C05-F06; no timing benefit from changing it was measured. Prior C05-F01 mutable environment reads are not blindly repeated: current code uses admitted current/prior references.

## Focused validation record

Linux commands were transported using the brief's base64 SSH wrapper:

```powershell
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Test bodies ran after:

```bash
set -eu
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
while IFS= read -r name; do unset "$name"; done < <(compgen -v APPSEC_NATIVE_)
unset DAGSTER_HOME APPSEC_ACCEPTANCE_ROOT APPSEC_ACCEPTANCE_RUNS_DIR \
  APPSEC_REVIEW_CONFIG_OVERLAY APPSEC_REVIEW_HOST_PINS
export APPSEC_PYTHON="$PWD/.venv/bin/python" APPSEC_REVIEW_PROFILE=dev \
  APPSEC_REVIEW_CONFIG="$PWD/appsec-review.toml" PYTHONDONTWRITEBYTECODE=1
```

All five selected files and their fixtures were inspected before running: only synthetic source, hash-verified fake upstream documents, SQLite, scripted model callbacks, local schema resources and mocked provider/controller boundaries. No real external providers/tools are called. `tests/conftest.py` installs test host pins, accepting image-verifier fixtures and no-container telemetry behavior.

### Collection and suite

```bash
.venv/bin/python -m pytest --collect-only -q -o addopts= \
  --basetemp=test/tmp/job-audit-job_target_analysis_plan-collect-901 \
  tests/unit/job_target_analysis_plan/test_contract.py \
  tests/unit/job_target_analysis_plan/test_partitioning.py \
  tests/unit/job_target_analysis_plan/test_planning.py \
  tests/unit/job_target_analysis_plan/test_feedback.py \
  tests/unit/job_target_analysis_plan/test_handlers.py

./scripts/run-tests.sh --parallel --test-workers 4 --shuffle-seed 901 \
  --max-tests 143 --expect-tests 143 -- \
  tests/unit/job_target_analysis_plan/test_contract.py \
  tests/unit/job_target_analysis_plan/test_partitioning.py \
  tests/unit/job_target_analysis_plan/test_planning.py \
  tests/unit/job_target_analysis_plan/test_feedback.py \
  tests/unit/job_target_analysis_plan/test_handlers.py
```

- Collection: **143 tests, 0.55 s**, exit 0.
- Guarded suite: **142 passed, 1 failed, 0 skipped**, **6.74 s**, exit 1. No baseline/differential was used.
- **Zero tests over 10 s**; largest recorded setup+call+teardown **1.5672 s**. Collection and execution cleanup were confirmed with zero remaining processes.
- Harness uses and owns the unique `test/tmp/tests-custom-20261118-112033-918332-2445059` prefix and refuses a caller `--basetemp` override. The direct collection/single/reproducer commands used the requested job-audit prefix.
- `--help` and a `--dry-run` with these five selectors / four workers / seed 901 / max 160 were also run before collection. They executed no tests.

Retained evidence, relative to the WSL checkout:

```text
test/tmp/logs/tests-custom-20261118-112033-918332-2445059.log
test/tmp/tests-custom-20261118-112033-918332-2445059.junit.xml
test/tmp/tests-custom-20261118-112033-918332-2445059.timings.sqlite
test/tmp/tests-custom-20261118-112033-918332-2445059.collection.json
test/tmp/reports/tests-custom-20261118-112033-918332-2445059.json
```

The observed catalog input receipt was:

```text
test/tmp/tests-custom-20261118-112033-918332-2445059/popen-gw2/
test_job_runner_executes_isola0/runs/2026-11-15-0001/data/jobs/
job_target_analysis_plan/attempts/attempt_0001/steps/catalog_summary/
tasks/load_accepted_catalog/status.json
```

Its only `input_consumption.reads` entry was the accepted catalog **handoff**, with `read=true`, `cited=null`; no `catalog_documents` entry.

### Isolated failure check

```bash
.venv/bin/python -m pytest -q -o addopts= \
  --basetemp=test/tmp/job-audit-job_target_analysis_plan-single-901 \
  tests/unit/job_target_analysis_plan/test_contract.py::test_load_catalog_reads_supplied_environment_and_records_producer_scope
```

**1 failed, 1.57 s**, exit 1; same missing catalog-pin exception, zero tests over 10 s. Timings: `test/tmp/job-audit-job_target_analysis_plan-single-901.timings.sqlite`.

### Offline reproductions

Executed `.venv/bin/python -` via SSH, using the inspected `_inputs()` and `_catalog()` synthetic factories from the job unit files, real production functions, and only scripted `ModelResult` callbacks. Scratch was confined to `test/tmp/job-audit-job_target_analysis_plan-repro-901`.

The first script's complete substantive validation body was as follows (a final unsuccessful glob for a differently shortened pytest receipt directory produced no output and is omitted; the actual receipt was subsequently located as recorded above):

```python
import copy, hashlib, json, os, time
from dataclasses import replace
from pathlib import Path
from appsec_review.config import PlanningFeedbackSettings
from appsec_review.inference import ModelResult
from appsec_review.inference.claude_cli import parse_model_payload
from appsec_review.jobs.job_target_analysis_plan import job as j
from appsec_review.jobs.job_target_analysis_plan.planning import (
    bounded_feedback, summarize_catalog, feedback_request, _scanner_scope)
from appsec_review.storage import atomic_json, file_sha256, canonical_json
from tests.unit.job_target_analysis_plan.test_feedback import _inputs
from tests.unit.job_target_analysis_plan.test_partitioning import _catalog
from tests.handoff_fixture import write_fixture_handoff
os.umask(0o022)
start = time.monotonic()
root = Path("test/tmp/job-audit-job_target_analysis_plan-repro-901").resolve()
root.mkdir(parents=True, exist_ok=False)
catalog, request, final, texts = _inputs()
for label, mutate in [
    ("abstention-id-list", lambda p: p.update(build_recipes=[],
        abstentions=[{"build_unit_id": [], "reason": "unknown"}])),
    ("recipe-profile-object", lambda p: p["build_recipes"][0].update(image_profile={})),
]:
    bad = copy.deepcopy(final)
    mutate(bad)
    parsed = parse_model_payload(json.dumps(bad), request.schema)
    calls = []
    def infer(current, **kw):
        calls.append(current)
        return ModelResult(parsed if len(calls) == 1 else final)
    try:
        result = bounded_feedback(infer, request, catalog=catalog,
            limits=replace(PlanningFeedbackSettings(), max_calls=2),
            read_document=None, cache_root=root / label, identity={})
        print(label, "RETURNED", result["status"], "calls", len(calls))
    except Exception as e:
        print(label, "RAISED", type(e).__name__, str(e), "calls", len(calls))
small = _catalog(2, padding=0)
text = '{"compilerOptions":{"target":"ES2020"}}'
extra = {"path": "node-00/tsconfig.json",
         "sha256": hashlib.sha256(text.encode()).hexdigest(), "content": text}
small["build_units"][0]["descriptor_package"]["documents"].append(extra)
small["files"].append({k: v for k, v in extra.items() if k != "content"}
                     | {"size_bytes": len(text.encode())})
summary = summarize_catalog(small, max_items=2, max_bytes=524288,
                            sample_per_prefix=1)
paths = tuple(sorted({v["path"] for u in summary["build_units"]
    for v in (*u["markers"], *u["descriptor_package"]["documents"])}))
offered = feedback_request(replace(request, summary=summary, allowed_paths=paths),
                           small, PlanningFeedbackSettings())
print("TRIMMED_DOCUMENT", extra["path"], "in_summary",
      any(extra["path"] == v["path"] for u in summary["build_units"]
          for v in u["descriptor_package"]["documents"]),
      "in_allowed_paths", extra["path"] in offered.allowed_paths,
      "in_evidence_inventory",
      any(v["path"] == extra["path"] for v in offered.summary["evidence_inventory"]),
      "bytes", len(canonical_json(summary)), "truncated", summary["bounds"]["truncated"])
over = summarize_catalog(_catalog(3, padding=0), max_items=1,
                         max_bytes=524288, sample_per_prefix=1)
print("ITEM_BOUND", "configured", over["bounds"]["max_items"],
      "retained_build_units", len(over["build_units"]),
      "reported_items_emitted", over["bounds"]["items_emitted"])
run, refs = root / "artifact-input", {}
def child(name, value):
    path = run / ("data/jobs/job_target_catalog/" + name + ".json")
    atomic_json(path, value)
    return {"path": path.relative_to(run).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}
artifact = {"path": "data/shared/objects/" + "d" * 64,
    "target_relative_path": "native/prebuilt.jar", "sha256": "d" * 64,
    "size_bytes": 4, "schema": "appsec-review/target-artifact-intake/1"}
for key, name, value in [
    ("repository_discovery.partition_repository", "partition",
     {"schema": "appsec-review/repository-partition/1",
      "source_fingerprint": catalog["source_fingerprint"],
      "files": catalog["files"], "target_artifacts": [artifact]}),
    ("repository_discovery.discover_projects", "projects",
     {"schema": "appsec-review/project-catalog/1", "projects": []}),
    ("component_discovery.catalog_components", "components",
     {"schema": "appsec-review/component-catalog/1", "components": []}),
    ("build_discovery.discover_build_systems", "builds",
     {"schema": "appsec-review/build-systems/4", "systems": []}),
    ("build_discovery.discover_compile_commands", "compile",
     {"schema": "appsec-review/compile-commands/1", "files": []}),
    ("build_discovery.catalog_build_targets", "targets",
     {"schema": "appsec-review/build-targets/2", "targets": catalog["build_units"]}),
]:
    refs[key] = child(name, value)
ref = child("catalog", {"schema": "appsec-review/target-catalog/1",
    "source_fingerprint": catalog["source_fingerprint"], "artifacts": refs})
att = run / "data/jobs/job_target_catalog/attempts/attempt_0001"
hf = write_fixture_handoff(run, att / "handoff.json", {
    "job_id": "job_target_catalog", "source_fingerprint": catalog["source_fingerprint"],
    "artifacts": [*refs.values(), ref],
    "outputs": {"publish_catalog.publish_handoff": {"artifact": ref}}})
atomic_json(att.parent.parent / "latest.json", {
    "schema": "appsec-review/latest-handoff/1", "attempt_id": "attempt_0001",
    "handoff_path": hf.relative_to(run).as_posix(), "handoff_sha256": file_sha256(hf)})
loaded = j._accepted_catalog(run)
print("PREBUILT_INPUT", "partition_artifacts", 1,
      "accepted_artifacts", len(loaded["accepted_artifacts"]),
      "spotbugs_scope", _scanner_scope("tool-spotbugs", loaded["files"],
                                      loaded["accepted_artifacts"]))
print("REPRO_ELAPSED_SECONDS", round(time.monotonic() - start, 3))
```

This wrote six correctly schema-named/hash-referenced synthetic catalog child JSON files, a target-catalog document and fixture accepted handoff, with one JAR in `partition.target_artifacts` and `_inputs()`'s normal build unit in build-targets. It called real `_accepted_catalog` and `_scanner_scope`; no binary payload or target tool was needed. Combined result, **0.807 s**, exit 0:

```text
abstention-id-list RAISED TypeError unhashable type: 'list' calls 1
recipe-profile-object RAISED TypeError unhashable type: 'dict' calls 1
TRIMMED_DOCUMENT node-00/tsconfig.json in_summary False in_allowed_paths False in_evidence_inventory False bytes 1320 truncated True
ITEM_BOUND configured 1 retained_build_units 3 reported_items_emitted 0
PREBUILT_INPUT partition_artifacts 1 accepted_artifacts 0 spotbugs_scope ()
```

The corrected .NET script built a hash-correct synthetic `dotnet/App.csproj` containing a `PackageReference`, used real `discover_build_units`, and replaced the request's unit/path/system/image allowlists accordingly. Complete body:

```python
from dataclasses import replace
from pathlib import Path
import hashlib, time
from appsec_review.config import PlanningFeedbackSettings
from appsec_review.inference import ModelResult
from appsec_review.jobs.build_discovery import discover_build_units
from appsec_review.jobs.job_target_analysis_plan.planning import bounded_feedback
from tests.unit.job_target_analysis_plan.test_feedback import _inputs
start = time.monotonic()
catalog, request, final, _ = _inputs()
text = ('<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
        '<PackageReference Include="Example" Version="1.0.0" />'
        '</ItemGroup></Project>')
file = {"path": "dotnet/App.csproj",
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
        "size_bytes": len(text.encode())}
unit = discover_build_units([file])[0]
unit["descriptor_package"] = {"documents": [{
    "path": file["path"], "sha256": file["sha256"], "content": text}],
    "bounds": {}, "gaps": []}
catalog = {**catalog, "files": [file], "build_units": [unit]}
request = replace(request, summary={"build_units": [unit]},
    allowed_paths=(file["path"],), allowed_build_units=(unit["build_unit_id"],),
    allowed_image_profiles=("dotnet",), allowed_build_systems=("dotnet",))
recipe = {
    "schema": "appsec-review/build-recipe/1",
    "build_unit_id": unit["build_unit_id"], "image_profile": "dotnet",
    "source_dir": "dotnet", "build_dir": "dotnet/obj",
    "system_packages": [], "environment": {},
    "dependency_files": ["dotnet/App.csproj"],
    "configure_commands": [["dotnet", "restore", "App.csproj"]],
    "build_commands": [["dotnet", "build", "App.csproj"]],
    "expected_outputs": ["dotnet/bin"], "network_required": False,
    "reason": "No image preparation download proven; restore is a build command.",
}
for network in (False, True):
    proposal = {**final, "build_recipes": [{**recipe, "network_required": network}]}
    result = bounded_feedback(lambda *a, **k: ModelResult(proposal),
        request, catalog=catalog, limits=PlanningFeedbackSettings(),
        read_document=None,
        cache_root=(Path("test/tmp/job-audit-job_target_analysis_plan-repro-901")
                    / ("dotnet-corrected-" + str(network))).resolve(),
        identity={})
    print("DOTNET", network, "status", result["status"],
          "calls", result["calls"], "errors", result["errors"])
print("DOTNET_REPRO_SECONDS", round(time.monotonic() - start, 3))
```

- Initial attempt reproduced the `false` rejection, then failed the `true` control because the audit script supplied a **relative cache root** to a helper expecting resolved custody. Exit 1, elapsed not captured. This was an auditor reproducer error, not another candidate finding.
- Corrected absolute-root rerun: **0.054 s**, exit 0:

```text
DOTNET False status BUDGET_EXCEEDED calls 4 errors ['build_recipes[0]: .NET recipes with accepted package references require dependency egress']
DOTNET True status ACCEPTED calls 1 errors []
```

No commands in these recipes were executed. These reproductions are not additional pytest passes.

## Evidence coverage and unread scope

**Read fully:** authorized `AGENTS.md`, coordination skill and audit brief; all four files in `src/appsec_review/jobs/job_target_analysis_plan/`; all five job-specific unit test files; `docs/operations/job_target_analysis_plan.md` and `target-analysis-planning.md`; `docs/schemas/target-analysis-proposal.schema.json` and `build-recipe.schema.json`; runtime planning skill, DevOps persona, all nine `build-engineer-{family}.md` roles and governing rules; `inference/request.py`; shell test wrapper and its common launcher.

**Read relevant ranges/searches, not fully:** config loader/default TOML, registry, guidance workers/cards, CLI payload parser, inference execution, build discovery and topology compiler/evidence bundle, target catalog artifact and build-target publishers, accepted history/environment helpers, input admission/observation and consumed-handoff helpers, runner/units/handoff/resume, orchestration topology/Dagster unit generation, project-build and evidence-collection plan consumers, project-image restore behavior, runtime Wave 4 tests (`1-250`), root build-discovery .NET test, test map/conftest/environment guard/test wrapper implementation and fixed report, architecture interchange/topology docs, TODO registry relevant entries, historical system-review C05 findings and the three available earlier session reports (searched).

**Material unread/unexecuted scope:**

- The remainder of shared build-discovery/topology/refinement code and all family-specific execution/image behavior were not exhaustively audited; their independently large test suites were not run.
- Shared `tests/unit/runtime/test_wave4_contracts.py` was sampled, not executed. Only the five planner files were selected. Root legacy tests, worker-competence evaluation and the mapped integration graph file were not run.
- No actual providers, model quality, full target catalog, generated recipe execution, binaries/scanners, real source histories, image preparation, live index consumption, or downstream final review output were verified.
- No full Dagster graph, service, manual integration, acceptance or live run was launched. The two inspected synthetic JobRunner tests are offline units with canned upstreams and scripted inference, not live/integration evidence.
- Dataset-level accepted-plan reader absence was established statically; the actual receipt example is the planner's catalog-loading unit.
- Prior reports for jobs 4–8 were not present in the supplied session-files listing; the coordinator should deduplicate TA-F04 or related shared findings against those reports. Available historical reports are not validation of this revision.
- No repository code or TODO was changed. The report is the only authored non-test artifact; unit logs/receipts and isolated reproduction data remain under the checkout's ignored `test/tmp/` as audit evidence.

**Stop:** job 9 only. Ready for coordinator accumulation; no fixes or next-job audit started.
