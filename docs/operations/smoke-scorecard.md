---
title: "Smoke scorecard: funnel stages, axes, radar PDF and trend"
kind: "operations"
subsystem: "testing and operations"
status: "current"
jobs: []
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# Smoke scorecard

Previously recorded page-specific revision: `d31da01bf3a9e8d62bbe8d5e66e62d6b09ad43f4`; the
frontmatter watermark follows the repository-wide docs-sync record, not this individual revision.

`scripts/smoke-score.py` scores one completed smoke run against the smoke answer key
([test targets, "Scoring a smoke run"](test-targets.md#scoring-a-smoke-run-t-5019)). This document
describes the scorecard built on that score: the loss-funnel stage of every planted item, the per-axis
metrics, the radar chart and PDF, and the run-to-run trend. The code is
`appsec_review.reporting.smoke_score` (stages, axes, per-axis metrics) and
`appsec_review.reporting.smoke_scorecard` (document, LaTeX and PDF, receipt, trend).

```bash
.venv/bin/python scripts/smoke-score.py --run runs/<run-id> --answer-key ~/smoke-work/cpp/answer-key.json
.venv/bin/python scripts/smoke-score.py --run runs/<run-id> --answer-key ~/smoke-work/cpp/answer-key.json --no-pdf
.venv/bin/python scripts/smoke-score.py --run runs/<run-id> --answer-key ~/smoke-work/cpp/answer-key.json --compare <other-run-id>
```

With the key, the scorecard renders by default (`--pdf`); `--no-pdf` keeps the score only. `--compare`
names another scored run (a run id beside this run, or a run directory) and prints the per-axis recall and
precision deltas from that run to this one, read from both `smoke-score.json` files; nothing else.

## What it reads and what it writes

The scorecard is an operator-side consumer of the answer key. It reads only the run's published records
(the same set the score reads: accepted index shards, job handoffs, the review package assembly and
manifest admission rows, the claim projection, finding packages, the gate and report documents) and the
key the user names on the command line. It writes only under `runs/<run-id>/data/verification/`:

| File | Content |
| --- | --- |
| `smoke-score.json`, `smoke-score.txt` | the score document (`appsec-review/smoke-score/1`, closed schema `docs/schemas/smoke-score.schema.json`) and its one-screen summary; the per-item `stage`, `stage_evidence`, `axis`, `axis_basis`, `real_severity`, the lead rows' `reported_severity` and `effective_severity`, the finding rows' `technical_severity`, `keyed.by_axis` and `keyed.funnel` live here |
| `smoke-scorecard.tex` | the scorecard document rendered to LaTeX with the report template (`containers/report/latex/template`) |
| `smoke-scorecard.pdf` | the PDF, when the pinned `tool-report-latex` image rendered it (offline, read-only template and input, non-root, `SOURCE_DATE_EPOCH=0`) |
| `smoke-scorecard.log`, `smoke-scorecard.pdfinfo.txt` | the renderer's log and `pdfinfo` output, when it left them |
| `smoke-scorecard-receipt.json` | `appsec-review/smoke-scorecard-receipt/1`: status `rendered`, `render_failed` or `latex_only`; SHA-256 of the score, the `.tex` and the `.pdf`; the template file hashes; the tool identity (image tag, version, manifest hash) and the execution record (exit code, image id); page count and overfull-box count; named gaps |

A rendering problem (image absent or unpinned, no container runtime, no signing policy on the host, a
timeout, an invalid PDF) is a named gap in the receipt (`smoke_scorecard_renderer_unavailable`,
`smoke_scorecard_render_failed`, `smoke_scorecard_render_timeout`, `smoke_scorecard_pdf_invalid`,
`smoke_scorecard_tex_too_large`), never a failure of the scoring: the score and the `.tex` stand. A
re-render removes the previous `.pdf`, log and receipt first, so an older PDF never sits beside a newer
`.tex`. The staging directory for the container run lives under `data/verification/` and is removed.

**How a claim is matched to an item.** A claim is on a code item only when the claim's *primary site*
falls inside the item's span (or the function range the key names when it gives no span). The primary
site is the location of the claim's evidence relations with predicate `affected_construct` (the sink or
affected construct; whole-file entities never count); when the claim has none, the dossier `sources` rows
whose entity carries that predicate in the dossier's evidence; and finally a `path:line[-line]` locator in
the finding title. Citations with any other predicate (`attacker_input_control` entry points,
`source_to_sink_reachability`, guards, impact) are context and never a match, so a command-injection claim
whose entry point is cited at `serve_once` does not land on the item that owns `serve_once`'s lines. A
lead matches by its own location only. The claim row's `site_source` says which rule applied
(`relations`, `dossier`, `title`, `none`; `dependency` for dependency items, which match by advisory
lead, component row or the finding-lead package that carries the lead). The matching `citing_lines` are
the primary sites inside the span.

**The key is never read by a job.** No job, prompt, runtime skill, configuration or guidance bundle reads
the answer key or the score; the scorer reads the run, not the other way round. The key stays where the
user keeps it (never under `targets/`, never in the repository) and is read only when the user names it
on the command line. The unit tests (`tests/unit/reporting/test_smoke_scorecard.py`,
`tests/unit/reporting/test_smoke_score.py`) use synthetic keys and synthetic score rows only.

## The loss funnel

Every planted item gets exactly one `stage`: the furthest point it reached in the review before it was
lost, or where it arrived. The stage is decided from the item's own scored record (its leads and their
admission, the packages that carried it, the claims raised on it and their states, the finding packages
and their gate bucket, whether a matching finding reached the report, and for dependencies the
inventory component rows, and for `answer_rejected` the red cells the lane ledgers record on its packages, carried
on each package row as `red_cells`), so the same record always yields the same stage; `stage_evidence` is the one
line that justifies it. `outcome` and `observed_disposition` are unchanged and sit beside it.

| Stage | Items | Meaning | Owner (where a loss at this stage points) |
| --- | --- | --- | --- |
| `not_observed` | code true positives | no scanner lead at the planted site, not in a hunt unit, no claim | scanners |
| `not_admitted` | positives with leads | leads exist, none admitted; the evidence lists the exclusion reasons and the reported and effective severities of the leads | admission policy (lead-severity triage, dispositions) |
| `no_claim` | positives | admitted or hunted (in a hunt unit or a lead package), no claim proposed; the red cells on its packages succeeded and declined, or ended on a budget, authority or worker gap | analysts (red / hunters) |
| `answer_rejected` | positives | admitted or hunted, no claim, and every red cell (`red_team_analyst`, `hypothesis_hunter`) on the item's packages ended `invalid` with a `schema_error` gap in the lane ledger's `cell_terminal` records: the analysis was lost to the answer-shape contract, not declined | answer shape contract (compact schema, salvage, role prompts) |
| `out_of_scope` | positives with claims | every claim decided `out_of_scope` (or `duplicate`, `coverage_gap`) | scope rule |
| `refuted` | positives with claims | a claim `contradicted`, `not_reachable` or `not_exploitable_in_observed_configuration`, none pending | verifier and judge (blue) |
| `unverified` | positives with claims | a claim `supported`, `insufficient_evidence` or `proposed`, or a finding package in `verification_backlog` or `withheld`: decision pending or not independently confirmed | verifier and judge |
| `confirmed` | code true positives | a finding package `confirmed` in bucket `publishable`, or a matching finding in the report | judge |
| `not_identified` | dependency true positives | no `dependency_package` row names the package and no advisory lead | inventory (syft, cve-bin-tool) |
| `no_version` | dependency true positives | component rows exist but carry no version, and no advisory lead | inventory |
| `no_advisory` | dependency true positives | a versioned component row exists, no lead names the advisory (OSV or CVE id) | advisory matching (grype, osv-scanner) |
| `reported` | dependency true positives | the dependency finding is confirmed and publishable or in the report | gate and report |
| `correctly_passed` | fixed and false-positive items | no matching finding reached the report (the evidence names the refuting claim states, or that there was no lead and no claim) | whole pipeline |
| `false_report` | fixed and false-positive items | a matching finding reached the report | whole pipeline |

A dependency item whose advisory lead exists but was not admitted, not claimed or not decided takes the
shared middle stages (`not_admitted`, `no_claim`, `answer_rejected`, `out_of_scope`, `refuted`, `unverified`) like
a code item. Items at `no_claim` or later were looked at by the review (admitted or hunted); that set is the
*coverage* of the radar chart.

## Axes and per-axis metrics

Each item is counted on one axis. The axis is the key's `axis` field when it names a member of the
vocabulary; otherwise it is derived from the item's `cwe` through `SECURITY_PREDICATE_CWE_ROLLUP`
(`appsec_review.review.models`) and the executive report's dimension map
(`appsec_review.reporting.dimensions.DIMENSION_OF_PREDICATE`), with CWE-134 kept on `format_string`
because the roll-up folds format strings into memory corruption; a dependency item without a CWE is
`supply_chain`; anything else is `unassigned` and counted in no spoke. `axis_basis` records which rule
applied (`key`, `cwe`, `cwe_rollup`, `class`, `none`).

| Axis | Key | Axis | Key |
| --- | --- | --- | --- |
| `memory_safety` | MEM | `access_control` | ACC |
| `numeric_handling` | NUM | `secrets_crypto` | SEC |
| `control_injection` | INJ | `resource_exhaustion` | RES |
| `format_string` | FMT | `dead_code` | DEAD |
| `concurrency` | CONC | `supply_chain` | SUP |
| `parsing_data` | PARS | | |

Per axis, `keyed.by_axis` gives: `planted` (true positives), `confirmed` (stage `confirmed` or
`reported`), `recall` = confirmed / planted; `covered` and `coverage` = items at `no_claim` or later /
planted; `negatives` (fixed and false-positive items), `correctly_passed`, `false_reports`, and
`precision` = confirmed / (confirmed + false_reports); `stages` (count per funnel stage over every item of
the axis); `low_confidence` (fewer than 3 planted true positives: one item decides the whole recall); and
`severity`. Rates are `null` when their denominator is zero. `keyed.funnel` is the stage count over every
item.

**Severity handling** is keyed only when the key carries `real_severity` (`critical`, `high`, `medium`,
`low`). For each such item the axis row compares the planted severity with the most severe
`effective_severity` of the leads the review admitted (all leads at the site when none was admitted,
`admitted_basis` says which) and with the technical severity published with the finding packages
(`ship_block.inputs.technical_severity.rating`); `planted_high_admitted_below` is set when a planted
critical or high item was admitted on a lower effective severity. Without `real_severity` the row says
`keyed: false` and the PDF says "Severity handling: not keyed"; the lead rows still record each lead's
reported and effective severity.

## The radar chart

The scorecard PDF reuses the executive report's `RadarChart` block. Axes are the key's axes that carry
items, in vocabulary order, padded from the fixed list to at least three (a padded axis is drawn at zero
and marked "not keyed" in the key); twelve at most. Three series:

| Series | Line | Value per axis |
| --- | --- | --- |
| Recall | solid | confirmed / planted true positives |
| Precision | dashed | confirmed / (confirmed + false reports) |
| Coverage | dotted | items at stage `no_claim` or later / planted true positives |

Undefined JSON rates remain `null`, but this keyed diagnostic renderer maps them to a `0.0`
vertex and displays the raw fraction (for example `0/0`). That is not measured zero and differs
from the primary executive radar, which omits unknown vertices and breaks the polygon.

The key table below the chart shows the raw fraction per spoke; the legend explains each series and lists
each axis with its planted, confirmed, covered, negative and false-report counts, and marks an axis with
fewer than 3 planted items *low confidence*. Then follow the per-axis funnel table, the per-item table
(id, axis, class, expected disposition, stage, outcome, evidence), the severity-handling table, "What
this does not say" (the corpus size per axis, the low-confidence rule, what precision does and does not
count, that the key is never read by a job) and the provenance box (score document, key SHA-256,
language, tag, version, planted and chain counts).

## The key's v1.1.0 fields

The answer key keeps its schema id `appsec-review/smoke-answer-key/1`. Version 1.1.0 adds per planted
item `axis` (one of the axis ids above) and `real_severity`, and a top-level `chains` list; `version`
names the key version. The scorer accepts both: without `axis` it derives the axis from the CWE, without
`real_severity` the severity comparison is "not keyed", and `answer_key.version` / `answer_key.chains`
(the count) are recorded in the score. Chains are recorded, not yet scored.

## What the scorecard does not say

It measures the run's published records against the planted items of one small corpus: a loss is a loss
of the run on a planted item, never a statement about the target, and a high score is not a clearance of
anything. Scorecard headline/per-axis precision counts only planted negatives that were reported;
findings the run reported outside
the planted items are counted in `smoke-score.json` as unmatched and are neither right nor wrong here. An
axis with fewer than 3 planted items is low-confidence.

The separate `smoke-score.json` `keyed.metrics.precision` uses matching true-positive reported
claim IDs divided by **all** reported claim IDs; unmatched findings remain in that denominator.
It is not interchangeable with the scorecard's planted-item precision.
