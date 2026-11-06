# Glasswing quality experiments

`appsec_review.observability.experiments` is an offline measurement domain beside
`observability.quality`. It does not launch experiments, consume live model messages,
change telemetry dispatch, or certify detector effectiveness. Scripted fixtures are
examples, not empirical quality evidence.

## Boundary and schemas

The public API is:

```python
from appsec_review.observability.experiments import (
    csv_exports, input_schema, output_schema, population_id,
    publish_snapshot, rebuild, root_cause_id,
)

snapshot = rebuild(experiment_document)
receipt = publish_snapshot(output_directory, snapshot)
csv_documents = csv_exports(snapshot)  # filename -> UTF-8 text, no implicit writes
```

`input_schema()` and `output_schema()` return fresh JSON Schema 2020-12 documents.
All objects are closed, all fields are required, and unavailable values are explicit
JSON `null`, not omitted fields or zero. Unknown schema or normalizer versions fail.
The input schema is `appsec-review/quality-experiment/1`; output is
`appsec-review/quality-experiment-snapshot/1`. Nested matching and independent
adjudication documents have their own `/1` schemas, revision names and content hashes.
The Python input types are declared in `experiments/contracts.py`; schemas are
defined alongside them, not in a second mutable registry.

`rebuild` validates and copies its input. It does not read a target, model endpoint,
database or run directory. A future admission adapter must verify referenced source,
usage and adjudication artifacts against their exact bytes and authorize their
import. This domain preserves references and claimed independent adjudicator
identities; it cannot establish their authenticity from metadata alone.

Existing evaluation/competence metrics remain under
`observability.quality.evaluation_trend` and `competence_trend`, using their existing
scorers. Case-resolution precision is not findings precision. Do not turn scripted
competence correctness, model self-assessment, or a pipeline's rejected claims into
human TP/FP labels for this domain. F08 owns evaluator changes.

## Input records and frozen identities

An experiment contains immutable **launches** and separate immutable **completions**.
Assign the unique positive `run_index` at launch, not when results arrive. The engine
validates launch-time order; it is not a scheduler or launch-index allocator. Missing
completion means `pending`; explicit `failed`, `partial` and `cancelled` records
retain diagnostic reports and error IDs. `complete` with no findings is a real empty
observation. Conflicting duplicate run IDs, raw-report IDs or warning decisions fail;
exact duplicate deliveries are idempotent.

Each launch binds `run_id`, original `source_run_id`, index, timestamp and a frozen group:

| Identity | Meaning |
| --- | --- |
| Source revision and scope hash | Exact supplied source and target/component/CWE scope. |
| Context condition | `source_only` or `build_context`. |
| Configuration/guidance hashes | Complete resolved configuration and exact guidance. |
| Model/agent/tool/decoding hashes | Versioned execution identities, not display names. |
| Normalizer and stage | `source-root-cause-exact/1`; `candidate`, `verified` or `reproduced`. |
| Task, positive event, warning-set hash | Discovery versus fixed-warning triage, qualifying outcome, exact warning universe. |

Use a separate experiment series for each intended task/stage. If different groups
are interleaved in one launch sequence, they remain separate aggregates and adjacent
cross-group transitions are N/A. No search backward for a comparable predecessor.
One source run cannot appear twice in the same frozen group under different run IDs.
This prevents duplicate ingestion from manufacturing additional run observations.

`frozen_group_id` hashes the launch group. `comparison_group_id` additionally binds
the complete matching snapshot hash. Labels are deliberately excluded from both.
The label population binds source, scope, positive event, task and fixed warning
universe, so labels for a rank-1 experiment are not automatically reusable for an
any-vulnerability experiment.

### Root causes and independent adjudication

Discovery uses deduplicated root causes. Exact normalization hashes source revision,
CWE, stable `cause_key`, source/sink symbols and sorted unique source-relative
locations. `cause_key` identifies the underlying cause, not the report's prose.
Raw report IDs, severity and confidence never affect root identity. The conservative
normalizer does not guess fuzzy semantic equivalence or merge every report of a CWE.
Different source revisions remain different identities.

The matching snapshot may explicitly override `(run_id, raw_report_id)` with a
canonical root hash, with supporting evidence IDs. Overrides are sorted by that
pair before hashing; producers should use the same canonical order when computing
the snapshot ID (`contracts.digest` uses repository canonical JSON). Cross-source
root merges and overrides of absent reports fail. The source snapshot retains
raw reports, exact duplicate reports and override evidence; membership lists one
entry per raw-report ID with its effective root. Raw report count, exact duplicate
report count and distinct set size have different denominators.

Labels are independent of detector output and matching. Each label records
population/subject, TP/FP/unresolved/out-of-scope, separate real-bug/rank-1 flags,
independent adjudicator/method/evidence and time. An unlabelled emitted root is
unresolved, not false. Out-of-scope labels are visible but excluded from qualifying
precision and pending-label denominators. A real noncritical bug can be a
nonqualifying FP in a rank-1 experiment; retain `is_real_bug=true`.

A label-only correction changes the label revision and snapshot hash, then rebuilds
all historical precision and label-stratified recurrence. It does not change
all-finding stability. A matching change needs a new matching snapshot and an
explicit adjudication snapshot bound to it; stale labels are rejected, not
automatically transferred across a root merge. Rebuild all affected groups, never
patch a previously published metric row.

## Metrics and denominator rules

For discovery, the emitted set is distinct root causes at the frozen stage.
For fixed-warning triage, the unit is an original warning and the emitted set is
retained warning IDs, **not** root causes. Triage requires the exact hashed fixed
warning set and a retain/reject/abstain decision for every warning in a complete run.
It cannot mix discovery reports into its warning denominator.

| Metric | Definition / unavailable condition |
| --- | --- |
| Adjacent RoR | Intersection / union for indices `r-1` and `r`; first/missing/incomplete/incomparable predecessor or incomplete current run is N/A. |
| Empty transitions | Empty/nonempty is 0. Both empty is N/A, with shared/union both 0. Retention from an empty predecessor is N/A even if Jaccard is 0. |
| Retention | Shared / previous set size; directional, not Jaccard. |
| RoR-5 | Mean of defined values in the latest five scheduled transition slots, with valid and total counts. Missing slots remain in the window. |
| MPS | Mean Jaccard over all unordered complete-run pairs in one group. Both-empty pairs excluded from the mean but counted separately. |
| Change counts | New-to-previous, dropped, first-seen and reappearing. First-seen means first **observed** in earlier complete sets in this group, not proof of absence in failed runs. |
| Recurrence | Complete runs containing a subject / complete runs, including completed-empty runs. Each row retains its run IDs and label outcome. |
| Distinct precision | Unique TP / (unique TP + unique FP) over complete runs. |
| Occurrence precision | Sum of per-run TP / summed per-run TP+FP; repeated roots get repeated queue weight, not extra independent correctness evidence. |
| Macro run precision | Mean of defined complete-run precisions; valid/total counts expose empty and unresolved-only runs. |
| Pending bounds | TP/(TP+FP+U), (TP+U)/(TP+FP+U). These are **not confidence intervals**. |
| Triage TP retention | Retained known TPs / all known TPs presented, including abstained TPs in the denominator. |
| Triage FP removal | Rejected known FPs / all known FPs presented, including abstained FPs in the denominator. |
| Binary FPR | FP/(FP+TN) over decided labelled warnings; not FDR. Abstentions and unresolved inputs remain separately counted. |
| Yield | Unique qualifying TP units, never report count. Triage yield is warnings; discovery yield is root causes. |

For `{A,B,C,D}` then `{A,B,C,E,F}`, RoR is `3/6 = 0.5`, retention
`3/4 = 0.75`, new-to-previous is 2 and dropped is 1. A stable false A still
increases stability. The unit fixture deliberately includes it.

No completed runs means aggregate quality/yield is **null**, not measured zero.
A completed-empty population has zero counts but undefined precision. Ratios export
numerator, denominator, value, status and unavailable reason. No denominator is
silently inferred from LOC, partial reports or omitted attempts.

Each run keeps actual token/time/charge provenance and named missing-usage reasons.
Aggregates expose observed subtotals and missing run IDs; full totals stay null
unless every recorded attempt has the corresponding measurement. Failed-attempt
costs are included when observed. Estimated charges are retained in input, never
silently promoted to observed costs. Different currencies are not summed.
Cost per unique TP requires a complete compatible observed cost total and nonzero
yield. No usage and measured zero usage remain distinct. Coverage units and
missing denominators are preserved per run, not pooled into an invented coverage
percentage. Open-world recall is unavailable without a vulnerability universe.

Confidence kind, target, raw score and calibration revision remain separate
membership metadata. Token probabilities, margins, verbal scores and vote fractions
are not reinterpreted as calibrated correctness probabilities. This version does
not compute calibration curves, confidence intervals or a certification gate.
A predeclared policy can be preserved, but inference returns
`inference_not_implemented`; absent policy returns `not_predeclared`. Even 30/30
appearances of one TP cannot auto-certify 90% precision. Pairwise observations share
runs, and adjacent transitions share endpoints; neither is an independent sample.

## Rebuild, publication and export

Appending a late completion and calling `rebuild` recomputes the entire snapshot,
including both affected adjacent transitions, first-seen history, rolling windows,
MPS and recurrence. The input and old snapshots are not mutated. The implementation
is a bounded offline full rebuild (up to 512 launches), not a streaming database or
an incremental cache. Pairwise work grows quadratically with completed run count.

`publish_snapshot(directory, snapshot)` verifies the result by rebuilding its
source. It pins immutable launch, launch-index and completion records in separate
subdirectories, followed by content-addressed matching and adjudication documents.
The final content-addressed snapshot JSON is the publication marker. Reusing a
launch/index or completion with different bytes fails. Label/matching corrections
publish new snapshots alongside the old ones; they never rewrite run artifacts.
Consumers must not treat the supporting subdirectories as completed publications.

Publication uses the repository's exclusive `protected_json` primitive. It does
not promise a multi-file transaction or power-loss durability. A failed write may
leave an orphaned supporting artifact or truncated file; conflicting bytes cause
an explicit failure, not automatic repair/overwrite. Filesystem failures propagate.

The JSON snapshot includes the complete normalized input, source hash, matching and
label identities, per-run metrics, per-group aggregates and raw-to-subject membership.
`csv_exports` provides runs, groups, membership, launches, completions and adjudications.
Every row carries snapshot/source/matching/label revisions. Every CSV **data cell is
JSON-encoded**, including strings and `null`; parse with a CSV reader and `json.loads`
per cell. This preserves nested denominators and IDs and prevents spreadsheet
formula execution from untrusted text IDs. Empty tables retain their headers.

## Verification and remaining integration

Focused unit command (use a unique scratch suffix per invocation):

```sh
.venv/bin/python -m pytest tests/test_glasswing_metrics.py tests/test_operations_quality.py \
  -n 2 --shuffle-seed=902 --basetemp=test/tmp/fleet-f09-902 -q --durations=5
```

Fixtures cover exact numeric overlap, a stable FP, failures between complete runs,
empty/nonempty and all-empty sets, missing launches, out-of-order completion, mixed
groups/stages, label/matching revisions, duplicate reports/root causes, fixed-warning
abstention and precision, unavailable costs, zero denominators, immutable publication,
closed schemas and reproducible exports.

`tests/integration/test_glasswing_experiments.py` is a **manual, unrun** publication
and re-adjudication scenario, not an automatic gate. F10 still needs accepted-artifact
admission, live run/stage adapters, durable launch-index allocation, usage admission,
and dashboard rendering against these records. Real model effectiveness, actual
independent label quality, calibration, inferential policies and real experiment
campaigns require separately authorized validation. No central job registry,
configuration, telemetry dispatch or global pytest harness is changed by this module.
