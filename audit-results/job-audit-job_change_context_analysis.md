# Job 13/47 correctness audit — job_change_context_analysis

## Result and audited source

- Authorized WSL checkout: `/home/wsollers/projects/appsec-review`, branch `main`, exact HEAD **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**. Clean status, ancestry, and checkout-local `appsec_review` import were verified; HEAD and cleanliness were unchanged after validation.
- All **four steps / nine tasks** and all seven files in the job package were read and traced. This is a read-only functional audit, not a vulnerability review.
- **Seven reproduced findings: five medium, two low.** No high-severity finding established.
- **32 passing test executions**: 29 dedicated job cases, one shared disabled-history publication case, and the environment guard twice. That is 31 distinct cases. No failures, skips, or cases over ten seconds. Pytest time: **10.21 + 6.22 = 16.43 seconds**; supervised-wrapper total: **19.442 + 15.449 = 34.890 seconds**.
- Six in-memory reproductions completed in **1.003841 s**; the additional real-read-receipt reproduction completed in **0.011139 s**. These timings start after imports.
- No source/configuration edits, installations, commits, service operations, real tools/models/network calls, target-code execution, integration/acceptance/live runs, or nested agents. Only the authorized report was added; test-owned scratch/logs remain under `test/tmp/`.

## Registration, configuration, input contract

`src/appsec_review/runtime/registry.py:75,124` imports/registers the actual builder. `appsec-review.toml:791-892` declares the job and its ordered tasks; the dev recipe enables it. `datasets.py:91-99` declares review-graph dispatch, checkout access, propagation, `always_execute=False`, and scheduling after Tree-sitter. `orchestration/topology.py:46-79` also includes consumed producers in graph ordering and reduces transitive edges; the displayed immediate predecessor is Tree-sitter, not permission to consume only that job.

Accepted declarations (`datasets.py:43-90`):

| Producer | Inputs and availability | Actual use |
|---|---|---|
| `job_target_catalog` | Required/reject `handoff`; optional/gap artifact intake, source files, declaration symbols, components, target documents, build units, catalog documents. Producer-evidence authority. | `_load_catalog` opens the final catalog and referenced component document; checks catalog schema and matching claim source fingerprint. Other catalog datasets are not queried. **CC-07:** payload reads are not observed. |
| `job_source_history_analysis` | `handoff` is when-enabled/reject; optional/gap history signals, history documents, raw Git history, tool I/O. Routing-context authority. | Reads accepted history document, handoff-pinned full result, normalized changes, classification, GitHub/acquired reviews, ranked history, raw log and frozen source-history settings. Recomputes lifetime ownership from walked commits. Raw and intermediate payload reads use local hash checking, not dataset observations (**CC-07**, static extension). |
| `job_tree_sitter_ast` | Optional/gap handoff, AST, coverage, node shards, acceptance, generated-source backing and tool I/O. Producer-evidence authority. | Reads only accepted envelope, acceptance document and referenced node shards; explicitly calls `observe_output` for acceptance/shards (`job.py:375-385`). Missing Tree-sitter produces named function-attribution gaps. |

There are **no model workers, prompts, runtime skills or guidance assembly** in this job; no registry match was found in `pipeline/guidance/registry.json`. Generated task bindings remain undeclared under existing **T-147**, not evidence of missing execution.

The closed settings parser enforces table keys, integer/share ranges, supported sources, export pin format, positive total weight, role patterns and schedule syntax. Defaults: top 200 files/200 functions/100 components, 20 supporting changes, 300-second fast-review threshold, 60-day/four-change repair window, 100 fix/path checks, 50 blame files at at most 1 MiB, three unrelated groups/400 churn/0.5 entropy, 50 production churn, and 0.5 ownership shares. Review defaults to accepted enrichment; deployments/organization are disabled; no time zone means unavailable schedule metrics. Exports are pinned, repository-contained/outside-target JSON, bounded at 64 MiB/200,000 records; approvals are sliced at 1,000. Actual Git execution limits/tool identity come from frozen source-history settings and `tool-git`. The additional hard-coded 200-hunk bound is mishandled (**CC-03**).

## Every step/task

The ordered `Unit` definitions at `job.py:903-923` match TOML and `TOPOLOGY`. `source_lanes.per_source` wraps every task except initial history loading, substitutes source-local outputs/roots, aggregates gaps/dispositions and combines manifests/final documents. Each source is ranked independently.

| Step/task | Implementation, processing and outputs | Observed mismatch / verification limit |
|---|---|---|
| `load.accepted_history` | `job.py:165-274`; verified catalog plus accepted history/full result; split lanes; parsed raw log and lifetime normalization; exclude bulk ownership; stable author ordinals and identity hashes; `lifetime.json`; retain normalized/classified/ranked input refs. | Dedicated tests cover snapshot mismatch, absent history, no normalized artifact, lifetime shallow/truncated history, zero walked commits and source-local load errors. Real disabled-history publication additionally passed. **CC-07**; inherited SH-01/SH-05 remain upstream defects, not newly counted. |
| `load.external_sources` | `job.py:276-351`, `sources.py`; explicit export/deny/acquired export/GitHub precedence; reject ambiguous global review/deployment exports for multi-source targets; normalize deployments/organization; validate IANA zone and test policy; protected raw exports plus `external-sources.json`. | Disabled/invalid/missing/hash/bounds/ambiguous paths tested with synthetic files. **CC-02:** incomplete approval identity becomes known stale approval. Exporter/live completeness not established. |
| `attribute.line_attribution` | `job.py:353-438`, `attribution.py`; select exact, size-bounded history-ranked files by churn; verify accepted Tree-sitter snapshot/node hashes, extract callable/name/span records, bounded porcelain blame, pseudonymize authors, innermost surviving-line mapping; `attribution.json`. | Fake Git/Tree-sitter boundaries; parsing and wiring tested, including failures, bounds, unavailable/unreliable spans and extra identities. No actual blame or grammar invocation. `HEAD` is pinned by the shared runner's detached scratch HEAD, not the target checkout's live ref. |
| `attribute.fix_on_fix` | `job.py:440-504`; classified non-bulk fixes with deletions/parents; bounded fix/path list; first-parent zero-context rename-aware diff; parent ranged blame; filter prior known fixes by frozen history interval; `fix-on-fix.json`. | Disabled/no-history/failure/rename/candidate-limit cases tested. **CC-03:** 201+ hunks silently truncated while reporting complete available zero. Function-level fix-on-fix remains intentionally unavailable, T-030. |
| `analyze.change_signals` | `job.py:506-535`, `metrics.py:109-403`; observed/claimed landing time; reviews, time-zone schedule, shipping deployment ancestry/coverage, co-change/nested component grouping and entropy, review-unit test association; `change-records.json`. | Real deterministic metrics tested. **CC-01/02** review unknownness, **CC-06** duplicated review-unit churn at later aggregation. Missing review records add a task gap. |
| `analyze.unit_signals` | `job.py:537-635`, `metrics.py:446-546`; file/component touched-change sets; repeated-fix peak, fix-on-fix counts, lifetime/function ownership, organization lookup, optional surviving-line function sets; history-hotspot joins; `units.json`. | File/function/component handling, exclusions, missing optional artifacts and hotspot joins covered. **CC-01** zero-fill of entirely missing review facts; **CC-06** repeated PR totals. |
| `analyze.rank` | `job.py:637-656`, `metrics.py:555-588`; max-normalize available signals per source/scope, weighted score and weighted coverage, stable score/coverage/key ordering; `signals.json`. | Ranking/ties/missing weights tested. **CC-01** propagates false availability into score/coverage. **CC-04** emits the previous document's schema ID. |
| `publish.index_change_context` | `job.py:691-840`; fingerprint ranked/change/external artifacts plus settings/rules/history identity; real SQLite `history/change-context[-source-key]`; top-N signals, resolving file/function locations, bounded support changes, reviews/deployments, `DERIVED_FROM`/`SUPPORTS`/`CONTAINS`, coverage; immutable index and composed upstream manifest. | Local SQLite creation/reuse and source composition tested; no live retrieval/acceptance run. CC-01/02/03 reach indexed metrics. Coverage-row source status can disagree with later task gaps. |
| `publish.publish_handoff` | `job.py:842-901`; final `change-context.json`, source-local top-N, coverage/gaps/rules/export refs/manifest; unavailable history `SKIPPED_NA`; execution-failure retry dispositions; multi-source combined document. | Actual framework publication for disabled history passed. **CC-05:** function top entries omit identity fields required by prioritization; CC-01 coverage row inconsistency. Non-disabled whole-job run not executed. |

## Outputs, schemas, status and downstream compatibility

| Dataset | Declaration and actual publication |
|---|---|
| `change_context` | Routing-context, indexed `appsec-review/retrieval-index/2`, publish step, `history` shards prefixed `change-context`; bounded entity and relation publication. |
| `change_context_documents` | Sensitive artifact-only routing context, final schema family `appsec-review/change-context-analysis/1`; both ordinary and per-source `steps/*/tasks/*[/sources/*]/artifacts/*.json` globs match outputs. Intermediate documents intentionally have their own domain schemas; this is not itself a dataset mismatch. **CC-04** is a wrong intermediate schema relative to its own producer, not a demand that every document use the final schema. |
| `operator_exports` | Protected JSON, load task's `artifacts/inputs/*` and source-lane equivalent. Raw fields are not indexed. |
| `change_context_tool_io` | Protected container-execution-family scratch trees for blame/diff, including source lanes. |

All four dataset kinds are routing context, not findings. No job-specific output validators are installed (`job.py:920-923`; tested by `test_contract.py`). Shared control records/status/gap accounting remain framework validated; they do not validate each domain value or infer omissions. This legacy job has `strict_gaps=False`, is explicitly listed in the legacy gap test, and uses `SUCCEEDED`, `PARTIAL`, `SKIPPED_NA`, `SKIPPED_POLICY`; domain availability strings are separate. Publication adds retry dispositions only for `_execution_failed` reasons. Source-lane wrappers propagate ordinary lane errors and rethrow publication errors.

`retrieval/core.py:1149-1215` queries accepted matching history shards, exact facets and nonzero signals, orders/paginates records, and returns both noncomplete coverage rows **and shard identity gaps**. Therefore CC-01's inconsistent complete coverage row does **not** mean all missing-review warnings disappear from retrieval.

The concrete prioritization consumer `job_review_prioritization/composite.py:138-199,689-717` reads final `/change-context-analysis/1`, ingests top file/function entries and applies a configured change-context boost. CC-05 was reproduced against this exact consumer. Other declarations include CodeQL, review-data indexing, review-package assembly, inference, security tagging, document-issue analysis and OWASP assessment; their full processing was not re-audited.

Reuse is based on framework source/configuration/upstream/implementation identities; this job has no extra live export/Git freshness probe. Shard identity binds semantic artifacts, settings and rule identities and preserves unrelated upstream shards. Existing tests exercise local shard reuse, not a live resumed review. The whole raw history log is read into bytes at `job.py:230`; large-history memory behavior was not measured and is a scalability gap, not a reproduced OOM claim.

## Findings

### CC-01 — Medium: entirely missing review facts become trusted zero-valued ranking inputs

- **Evidence:** `src/appsec_review/jobs/job_change_context_analysis/metrics.py:456-465,568-584`; `job.py:675-680`.
- **Trigger:** a review source is present, but none of a particular unit's commits has a review record.
- **Expected:** absent review metrics remain null/unavailable, excluded from score denominator, with reduced weighted coverage and named missing signals.
- **Actual:** `review_known=[]`, but all `missing` states become `partial`, not unavailable. Each review metric becomes zero. `rank` uses non-nullness, giving all three unknown metrics full weight. Final review coverage is derived only from external-source loading and can still say `complete` despite `review_records_missing_for_changes`.
- **Reproduced:** one commit and `reviews={}` produced all three review counts `0`, availability `partial`; review-only ranking produced `score=0`, `coverage=1`, `missing_signals=[]`. Real final publication with the later missing-record gap retained `review-records: complete, gap=null`.
- **Impact:** unknown review behavior lowers a unit's score and advertises full weighted coverage. A separate task/shard gap does not correct the metric vector.
- **Confidence:** high; real per-change, aggregation, ranking and publication functions.
- **Smallest correction:** derive availability per metric from observed usable facts, leave entirely unobserved values null, and reconcile area coverage with analysis-time gaps. Preserve lower-bound partial counts only when some facts are known.
- **TODO overlap:** no exact item found. T-030 concerns extensions, not this existing missing-data guarantee.

### CC-02 — Medium: unknown approval commit is reported as a confirmed stale approval

- **Evidence:** `src/appsec_review/jobs/job_change_context_analysis/sources.py:92-110`; `metrics.py:122-143`.
- **Trigger:** a PR has valid created/merged/head fields and an approval record whose reviewed commit or timestamp is absent/invalid.
- **Expected:** incomplete identity/timing cannot prove that the final head was unapproved or that approvals were only on older heads.
- **Actual:** normalization retains null approval fields, infers `approved_by_other=True` from a nonempty list, and still sets `complete=True`. `any(commit_id == head)` then returns false for null identity, producing `merged_head_approved=False`, `stale_approval=True`, `status=known`.
- **Reproduced:** an approval `{submitted_at: null, commit_id: null}` produced exactly that output, with both speed intervals null.
- **Impact:** invents a stale-review anomaly and treats incomplete export/provider metadata as complete input.
- **Confidence:** high; real normalization and review-facts functions.
- **Smallest correction:** distinguish known nonmatching heads from unknown identities; only assert stale approval from sufficient observed approval-head data, and reflect missing timeline fields in completeness. Handle approval truncation with explicit coverage rather than silently trusting a prefix.
- **TODO overlap:** no exact item found; T-030 live-export validation is related coverage, not a deferral of null handling.

### CC-03 — Medium: the 200-hunk cutoff silently loses exact fix-on-fix evidence

- **Evidence:** `src/appsec_review/jobs/job_change_context_analysis/job.py:466-503`, especially `:478`; `attribution.py:55-67`.
- **Trigger:** one admitted fix/path diff has more than 200 removed/modified-line hunks, even though the fix/path check limit is not reached.
- **Expected:** examine the permitted bounded work and explicitly mark unexamined hunks as partial/bound-reached; never report complete zero for omitted evidence.
- **Actual:** `parse_old_hunks(diff.stdout)[:200]` discards remaining hunks without a gap or truncation counter. Status remains available/SUCCEEDED.
- **Reproduced:** fake external diff emitted 201 valid hunks; the only previous-fix line was in hunk 201. The real handler requested exactly 200 blame ranges and returned `event_count=0`, `status=available`, `gaps=[]`, `terminal_status=SUCCEEDED`.
- **Impact:** missed repeated repairs and false complete attribution coverage even for a single in-bound file check.
- **Confidence:** high; real handler/parser, only Git/storage boundaries faked.
- **Smallest correction:** name/configure the hunk bound, detect truncation before slicing and publish partial coverage/counts. A bounded chunking solution is optional; removing all bounds is not recommended.
- **TODO overlap:** not T-030's explicitly deferred function-level fix-on-fix feature; this is the implemented file/path mode.

### CC-04 — Low: signals.json advertises the units schema

- **Evidence:** `src/appsec_review/jobs/job_change_context_analysis/job.py:632,651-654`.
- **Trigger:** every successful `analyze.rank`.
- **Expected:** `signals.json` carries `appsec-review/change-context-signals/1`, as the handler explicitly constructs.
- **Actual:** later `**document` overwrites `schema` with `appsec-review/change-context-units/1`.
- **Reproduced:** real rank handler over an empty valid units document emitted `/change-context-units/1`.
- **Impact:** consumers cannot discriminate ranked signals by the advertised schema. Current internal readers are permissive; no live rejection was claimed.
- **Confidence:** high.
- **Smallest correction:** expand the input document before assigning the output schema and assert the persisted schema in the existing rank handler test.
- **TODO overlap:** no exact item found. T-147's declaration gap is distinct.

### CC-05 — Medium: final function priorities lose the fields their consumer needs

- **Evidence:** `src/appsec_review/jobs/job_change_context_analysis/job.py:850-857`; downstream `job_review_prioritization/composite.py:154-178,184-189,708-717`.
- **Trigger:** ranked function priorities are published for a source file.
- **Expected:** the concrete downstream name/span joining paths can associate function context with the matching function, or the contract explicitly provides a different resolving path.
- **Actual:** top function entries retain only key/rank/score/coverage/path/component/hash; `name`, `start_line`, `end_line` and nested function details are removed. The consumer does not parse `key` or load the signals artifact. Its name/span maps are empty; it places the function's score into a file-wide maximum.
- **Reproduced:** actual final publication for `src/a.py#10-12:function_definition`, name `hot`, score `1`, passed to the actual consumer returned file score `{'src/a.py': 1}`, no function names and no spans.
- **Impact:** function-specific context degenerates into a whole-file boost, affecting unrelated functions while the intended name/span branches cannot match actual output.
- **Confidence:** high; actual producer/consumer functions, accepted-storage access mocked only.
- **Smallest correction:** reconcile producer and consumer contracts: retain canonical callable name/span/hash or consume verified detailed signals, and keep function factors separate from file factors where selective boosting is intended. Merely adding fields will not undo the consumer's unconditional file promotion.
- **TODO overlap:** directly related to **T-171**, marked done (`docs/TODO.md:2808-2815`); not an unimplemented desired feature invented by this audit.

### CC-06 — Low: multi-commit PRs multiply test/production churn in unit details

- **Evidence:** `src/appsec_review/jobs/job_change_context_analysis/metrics.py:361-374,383,399,519-525`.
- **Trigger:** two or more commits from the same review unit contribute to one aggregated component/file/function.
- **Expected:** details report each review unit's production/test churn once, or use clearly defined per-change contributions.
- **Actual:** `change_records` attaches the same review-unit totals to every member; `aggregate` sums them again for each commit. Ambiguity counts are similarly repeated.
- **Reproduced:** two commits in PR 9 with 60 production lines and five test lines yielded aggregated `production_churn=120`, `associated_test_churn=10`.
- **Impact:** numerically incorrect published diagnostics, inflated by PR commit count. This does not by itself demonstrate that the deliberately change-count-based priority metric is wrong.
- **Confidence:** high; real change-record and aggregation functions.
- **Smallest correction:** deduplicate totals by review-unit identity, or retain distinct per-change details while keeping review-unit association decisions.
- **TODO overlap:** no exact item found.

### CC-07 — Medium: catalog/history payload reads bypass dataset-level consumption observation

- **Evidence:** `src/appsec_review/jobs/job_change_context_analysis/job.py:73-91,94-116,188,229-230`; `runtime/inputs.py:453-470,528-551`; `runtime/consume.py:162-205`.
- **Trigger:** normal `load.accepted_history` reads accepted catalog/component JSON and history payload artifacts.
- **Expected:** actual dataset reads are authorized/recorded distinctly from envelope reads.
- **Actual:** `_accepted_handoff` observes only the envelope. Local `_read`/`_read_bytes` verify containment/digest but never observe output ownership/schema/authority; `_load_catalog` has no payload observation. Tree-sitter has explicit observations, demonstrating the distinction.
- **Reproduced:** inspected the real successful shared-unit task receipt: the catalog and component document were consumed, but the only input read was `job_target_catalog/handoff`. Re-ran the actual loader against the retained immutable test fixture under `input_read_scope` with a contract containing only handoff requirements: it still read components successfully, with no violation and only an envelope receipt.
- **Impact:** consumed catalog payload is incorrectly represented as supplied-but-unread; removing the payload permission does not prevent consumption. Hash verification still occurs—this is not a claim of unpinned or arbitrary bytes being admitted.
- **Confidence:** high for catalog (runtime receipt and actual-loader reproduction); the identical unobserved raw-history/intermediate-read pattern is statically verified but was not separately executed under narrowed permissions.
- **Smallest correction:** observe the owning declared dataset before each producer-owned payload read, or use the shared artifact reader that does so, without observing every declared dataset merely because the handoff exists.
- **TODO overlap:** related to the broader T-113 contract/observation migration notes and prior audits' similar reader defects; no exact change-context payload-observation item found. T-147 is task/documentation binding, not a substitute for actual read receipts.

## Known overlaps, drift and unproven limits

- Read the earlier source-history report. **SH-01** (message-bound contamination) affects inherited classifications; **SH-05** (rename destination alias leakage) also affects this job's lifetime recomputation. They are inherited effects, not new findings in the count above.
- **T-030:** function-level exact fix-on-fix, rewritten-away function history, more deployment adapters/live export proof, richer component relatedness, and earlier planning integration are explicitly deferred. Their absence is not a defect newly discovered here.
- **T-147:** execution binding declarations remain incomplete; every actual task was nonetheless traced directly.
- **T-113:** previously recorded 100% package line/branch coverage does not prove the semantics above. Existing tests cover many branches but do not assert the problematic final schema, null-review ranking, multi-commit totals, >200-hunk behavior, or actual producer-shaped consumer joins.
- Documentation drift: the narrative prerequisites in `docs/operations/change-context-analysis.md` and the canonical page's load prose unconditionally require history, but the current when-enabled contract and successfully tested disabled-history path allow its absence. Also the canonical page warns about command `HEAD` as if it could follow a moved target ref; `job_source_history_analysis/git.py:106-118,128-159` creates a detached scratch HEAD from the accepted snapshot and uses that sanitized Git directory. This does not certify current target-byte revalidation.
- Not proven: scale/memory behavior for large accepted raw logs or all Tree-sitter node shards; current source-byte/name/span fidelity after independent target changes; >1,000 approvals, duplicate deployment identities, nonfinite weights, complete all-language callable mapping, malformed-but-accepted upstream payload behavior, full-source failure containment through actual framework execution, and all downstream transformations. No speculative defect counted for these.

## Focused validation commands and outcomes

All Linux commands used the brief's quote-safe SSH transport:

```powershell
$script = @'
set -eu
cd /home/wsollers/projects/appsec-review
# Exact Linux command/body below
'@
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu `
    "printf %s $encoded | base64 -d | bash"
```

Preflight: `git status --short`, `git branch --show-current`, `git rev-parse HEAD`, `git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD`, and `.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'` succeeded. `offending_environment(os.environ)` returned `[]`. An initial direct-quoted SSH preflight failed with Bash syntax error/exit 2; base64 retry above succeeded. This was not a test run.

### Run A — all dedicated units

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 1313 \
  --max-tests 30 --expect-tests 30 --timeout-seconds 180 -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_change_context_analysis/test_attribution.py \
  tests/unit/job_change_context_analysis/test_contract.py \
  tests/unit/job_change_context_analysis/test_handlers.py \
  tests/unit/job_change_context_analysis/test_metrics.py \
  tests/unit/job_change_context_analysis/test_settings_and_sources.py
```

- Reviewed all five files, support helpers, root/unit conftests and environment guard before execution. Git/HTTP/container boundaries are fakes; real algorithms and local SQLite run. Unit-tier process/network/Dagster guards remain active.
- Exact collection 30; **30 passed**, pytest **10.21 s**, wrapper **19.441652570 s**. No failures/skips/slow cases.
- Unique wrapper-owned name **`tests-custom-20261118-121418-437442-2758569`**, including collection and execution base temp. The wrapper owns `test/tmp/<name>`, `<name>.collection.json`, `<name>.junit.xml`, `<name>.timings.sqlite`, `logs/<name>.log`, `logs/<name>.collection.log`, `reports/<name>.json`, and supervised process manifests. Cleanup confirmed no remaining processes.
- First attempt appended `-p no:cacheprovider`; the wrapper refused that unsupported pass-through option (exit 2) **before collection/execution**. It was removed, not bypassed; no environment/source changes were made. The repository's configured cache policy remained unchanged.

### Run B — recorded catalog, real disabled-history publication

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 1314 \
  --max-tests 2 --expect-tests 2 --timeout-seconds 90 -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/runtime/test_wave3_contracts.py::test_change_context_analysis_publishes_unavailable_handoff_when_source_history_disabled
```

- Inspected the selected test, recorded catalog publisher and runner fixture. This is an existing guarded unit, not a Dagster/integration execution; source history is disabled and no Git executor runs.
- Exact collection two; **2 passed**, pytest **6.22 s**, wrapper **15.448783412 s**. No failures/skips/slow cases.
- Unique wrapper-owned name **`tests-custom-20261118-121628-832157-2789049`**; same output layout and confirmed process cleanup as Run A.
- Shared Wave 2 tests were read selectively but not run. Shared Wave 3 tests unrelated to this job were not selected.

### Reproduction A — six pure/handler/consumer cases

Ran `.venv/bin/python -` with the following body, via the SSH transport above. Exit 0; **1.003841 s** after imports. The only replaced boundaries are storage, fake Git, and accepted consumer storage; no source or scratch files are written by this body.

```python
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from copy import deepcopy
from time import perf_counter
import json
from appsec_review.config import load_config
from appsec_review.jobs.job_change_context_analysis import job, metrics, sources
from appsec_review.jobs.job_source_history_analysis.sources import GitSource
from appsec_review.jobs.job_review_prioritization import composite
from tests.unit.job_change_context_analysis.support import (
    default_settings, change_entry, HEAD, PARENT, PRIOR, T0)

start = perf_counter()
settings = default_settings()
config = load_config().job(job.PRODUCER)
root = Path.cwd()
def ref(doc):
    return {"value": doc}
def make_unit(unit_id, outputs):
    ctx = SimpleNamespace(config=config, run_root=root, repository_root=root,
        target_root=root, source_fingerprint="snapshot",
        events=SimpleNamespace(write=lambda *a, **k: None))
    return SimpleNamespace(job=ctx, unit_id=unit_id, unit_root=root,
        outputs=outputs, output=outputs.__getitem__)
def invoke(unit_id, outputs, **kwargs):
    unit = make_unit(unit_id, outputs)
    handler = next(u.handler for u in job.build_job(**kwargs).units
                   if u.unit_id == unit_id)
    return handler(unit)
def agg(records):
    return metrics.aggregate(list(records), records, fix_events=None,
        fix_on_fix_status="unavailable", owner=metrics.ownership({}, .5),
        owner_status="unavailable", organization=None, identity_of={},
        classification_status="available", settings=settings)

changes = [change_entry(HEAD, 0, T0, [("src/a.py", 2, 0)])]
records, _ = metrics.change_records(changes, {}, reviews={}, deployments=None,
    walked=[HEAD], zone=None, roots=[], settings=settings)
missing = agg(records)
ranked = metrics.rank({"src/a.py": missing}, {
    "fast_review_change_count": 1, "stale_approval_change_count": 1,
    "unapproved_mainline_change_count": 1})[0]
print("CC01", json.dumps({"review": records[HEAD]["review"],
    "metrics": {s: missing["metrics"][s] for s in metrics.REVIEW_SIGNALS},
    "availability": {s: missing["availability"][s] for s in metrics.REVIEW_SIGNALS},
    "rank": ranked}))
assert all(missing["metrics"][s] == 0 for s in metrics.REVIEW_SIGNALS)
assert ranked["coverage"] == 1

raw = {"pull_request": 1, "head_sha": HEAD,
    "created_at": "2023-11-14T20:00:00Z", "merged_at": "2023-11-14T23:00:00Z",
    "approvals": [{"submitted_at": None, "commit_id": None}]}
normalized = sources.normalize_review_record(raw)
facts = metrics.review_facts(normalized, 300)
print("CC02", json.dumps({"normalized_complete": normalized["complete"],
                         "review": facts}))
assert normalized["complete"] and facts["status"] == "known"
assert facts["stale_approval"] is True

pr_changes = [change_entry(HEAD, 0, T0, [("src/a.py", 60, 0)]),
              change_entry(PARENT, 1, T0-1, [("tests/test_a.py", 5, 0)])]
review = sources.normalize_review_record({"pull_request": 9})
pr_records, _ = metrics.change_records(pr_changes, {},
    reviews={HEAD: review, PARENT: review}, deployments=None,
    walked=[HEAD, PARENT], zone=None, roots=[], settings=settings)
pr_agg = agg(pr_records)
print("CC06", json.dumps({"actual_changes_production_churn": 60,
    "actual_changes_test_churn": 5, "aggregate_tests": pr_agg["details"]["tests"]}))
assert pr_agg["details"]["tests"]["production_churn"] == 120
assert pr_agg["details"]["tests"]["associated_test_churn"] == 10

with patch.object(job, "_read", lambda _r, identity: deepcopy(identity["value"])), \
     patch.object(job, "_write", lambda _u, _name, doc: ref(deepcopy(doc))):
    units_doc = {"schema": "appsec-review/change-context-units/1",
                 "files": {}, "components": {}, "functions": {}}
    rank_out = invoke("analyze.rank", {
        "analyze.unit_signals": {"artifact": ref(units_doc)}})
    print("CC04", rank_out["artifact"]["value"]["schema"])
    assert rank_out["artifact"]["value"]["schema"] == units_doc["schema"]

    fix_changes = [change_entry(HEAD, 0, T0, [("a.py", 201, 201)]),
                   change_entry(PRIOR, 1, T0-60, [("a.py", 1, 0)])]
    checked_ranges = []
    def fake_run(label, argv):
        if label.startswith("fof-diff"):
            data = "".join(
                f"@@ -{i*2+1},1 +{i*2+1},1 @@\n" for i in range(201)).encode()
        else:
            ranges = [argv[i+1] for i, token in enumerate(argv) if token == "-L"]
            checked_ranges.extend(ranges)
            data = "".join(
                f'{PRIOR if item == "401,+1" else PARENT} 1 1 1\n\tline\n'
                for item in ranges).encode()
        return SimpleNamespace(stdout=data, exit_code=0,
                               timed_out=False, truncated=False)
    history_cfg = load_config().job("job_source_history_analysis").settings
    with patch.object(job, "GitRunner",
                      lambda *a, **k: SimpleNamespace(run=fake_run)), \
         patch.object(job, "_resolved_job_settings", lambda *a: history_cfg):
        fof = invoke("attribute.fix_on_fix", {"load.accepted_history": {
            "available": True, "eligible": {"a.py": {}},
            "changes": ref({"changes": fix_changes}),
            "classification": ref({"classes": {
                HEAD: {"fix": "heuristic"}, PRIOR: {"fix": "heuristic"},
                PARENT: {"fix": None}}}),
            "git": GitSource("SUCCEEDED", "resolved", ".git",
                snapshot_commit=HEAD, head_commit=HEAD).as_dict(),
            "source": {"root": "."}}}, executor_factory=lambda u: None)
    print("CC03", json.dumps({"input_hunks": 201,
        "blamed_hunks": len(checked_ranges),
        "last_hunk_was_blame_fix": "401,+1" in checked_ranges,
        "output": {k: v for k, v in fof.items() if k != "artifact"}}))
    assert len(checked_ranges) == 200 and fof["event_count"] == 0
    assert fof["terminal_status"] == "SUCCEEDED" and not fof["gaps"]

    fn_key = "src/a.py#10-12:function_definition"
    signals_doc = {"rankings": {"files": [], "components": [],
        "functions": [fn_key]}, "files": {}, "components": {},
        "functions": {fn_key: {"scope": "function", "key": fn_key,
            "path": "src/a.py", "file_sha256": "a"*64, "component_id": "comp",
            "function": {"name": "hot", "type": "function_definition",
                         "start_line": 10, "end_line": 12},
            "priority": {"rank": 1, "score": 1., "coverage": 1.}}}}
    source_statuses = {s: {"status": "complete", "gaps": []} for s in
        ("review", "deployment", "schedule", "test_association", "organization")}
    outputs = {
        "load.accepted_history": {"available": True,
            "history_handoff_sha256": "h", "history_identity": "i", "gaps": []},
        "load.external_sources": {"sources": source_statuses, "gaps": []},
        "attribute.line_attribution": {"artifact": ref({}),
                                      "function_count": 1, "gaps": []},
        "attribute.fix_on_fix": {"artifact": ref({}), "gaps": []},
        "analyze.change_signals": {"gaps": ["review_records_missing_for_changes"]},
        "analyze.rank": {"artifact": ref(signals_doc)},
        "publish.index_change_context": {"manifest": {}}}
    published = invoke("publish.publish_handoff", outputs)
    doc = published["artifact"]["value"]
    with patch.object(composite, "has_handoff", lambda *a: True), \
         patch.object(composite, "accepted_handoff", lambda *a: ({
             "terminal_status": "PARTIAL",
             "outputs": {"publish.publish_handoff": published}}, "sha")), \
         patch.object(composite, "read_json", lambda _r, identity: identity["value"]):
        consumed = composite._load_change_context(root, True)
    print("CC05", json.dumps({
        "published_function": doc["priority"]["top"]["functions"][0],
        "consumer": {"files": consumed[1], "function_names": list(consumed[2]),
                     "function_spans": consumed[3]}}))
    assert consumed[1] == {"src/a.py": 1.} and consumed[2] == {} and consumed[3] == []
    print("CC01_coverage", json.dumps({"document_gaps": doc["gaps"],
        "review_coverage": next(r for r in doc["coverage"]
                                if r["area"] == "review-records")}))
print("elapsed_seconds", round(perf_counter()-start, 6))
```

### Reproduction B — retained real unit receipt and actual loader

Ran `.venv/bin/python -` with the following body after Run B. Exit 0; **0.011139 s** after imports (the executed body also printed both wrapper totals). Reads only this auditor's retained test fixture; it does not rewrite it.

```python
from pathlib import Path
from time import perf_counter
from types import SimpleNamespace
from dataclasses import replace
import json
from appsec_review.jobs.job_change_context_analysis import job
from appsec_review.runtime.inputs import input_read_scope

start = perf_counter()
base = Path("test/tmp/tests-custom-20261118-121628-832157-2789049")
claims = list(base.glob(
    "**/data/jobs/job_change_context_analysis/attempts/attempt_0001/claim.json"))
assert len(claims) == 1, claims
claim = json.loads(claims[0].read_text())
run_root = claims[0].parents[5].resolve()
status = json.loads((claims[0].parent /
    "steps/load/tasks/accepted_history/status.json").read_text())
observed = status["input_consumption"]["reads"]
print("CC07_observed", json.dumps({
    "read_kinds": [(r["producer"], r["output_kind"]) for r in observed],
    "catalog_read_document": job._load_catalog(run_root)["components"]}))
assert [(r["producer"], r["output_kind"]) for r in observed] == [
    ("job_target_catalog", "handoff")]
narrow = replace(job.CONTRACT, inputs=tuple(
    i for i in job.CONTRACT.inputs if i.output_kind == "handoff"))
ctx = SimpleNamespace(run_root=run_root,
    config=SimpleNamespace(job_id=job.PRODUCER), contract=narrow,
    upstream_handoffs=claim["upstream_handoffs"])
with input_read_scope(ctx) as reads:
    loaded = job._load_catalog(run_root)
    print("CC07_undeclared_payload", json.dumps({
        "components": loaded["components"], "observations": reads.document()}))
assert reads.violation is None
print("elapsed_seconds", round(perf_counter()-start, 6))
```

## Read coverage and remaining gaps

**Read fully:** authorized audit brief, WSL root AGENTS, coordination skill; job package `__init__.py`, `job.py`, `datasets.py`, `settings.py`, `sources.py`, `attribution.py`, `metrics.py`; dedicated `support.py` and all five job test files; canonical job page, change-context architecture and operations; `source_lanes.py`; root and unit conftests; environment guard; shell wrapper and common shell helper.

**Read targeted ranges/searches:** TOML job block; runtime registry/topology; shared Git runner/parser and accepted-history loader; runtime `UnitExecutor`, accepted-upstream/observation implementations; retrieval change-context query; prioritization composite ingestion/application; shared Wave 2 consumer tests and Wave 3 tests/fixtures through this job's disabled-history case; test map; wrapper option/collection/supervision implementation; interchange architecture through input/equivalence contracts; TODO entries T-030, T-147, T-171 and relevant T-113 notes; source-history audit findings and cumulative/prior-report keyword matches; own wrapper reports and test receipt.

**Material unread/unexecuted scope:** remainder of shared modules/tests outside this job's necessary path; complete other-job consumers and input producers; full target-acquisition exporters; generic signing/container publication internals; integration file, real Git/tool/Tree-sitter runs, all-language and real-export corpus, actual non-disabled end-to-end run, live reuse/restart, retrieval-through-MCP and output-quality comparison against a real review target. There was no full-suite, coverage-percentage, mutation, performance or acceptance claim.

The source remains clean and on the exact requested revision. Stop after this one job; coordinator owns cumulative findings and any repair decisions.
