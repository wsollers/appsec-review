---
title: "Reading the per-defect funnel"
kind: "operations"
subsystem: "testing and operations"
status: "current"
jobs: ["job_inference_security_review"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Reading the per-defect funnel

After a model-backed run, `stepwise.py system --tag appsec-multi-vuln-c094-v1 [--app-run ID]` (or
`--tag cpp-multivuln-v1` for the historical local corpus) prints the answer-key
lines and then the funnel: one line per seeded defect with the furthest stage it reached and why it stopped,
then four aggregate lines (stage conversion, `stopped_because` counts, model quality, retrieval). The same
data is the `funnel` section of `runs/metadata/stepwise/system/<run>-<tag>.json`. The funnel is reported,
never asserted: it cannot change `SYSTEM OK` / `SYSTEM FAILED`. The stages, the `stopped_because` codes and the
rules are in [`../processes/acceptance-and-regression-testing.md`](../processes/acceptance-and-regression-testing.md)
("Funnel: where each seeded defect stopped").

For any finished run, without Dagster or Docker, and read-only on the run tree:

```text
PYTHONPATH=src python -m appsec_review.acceptance.funnel --run runs/<run-id> [--json]
PYTHONPATH=src python -m appsec_review.acceptance.funnel --run <run id> --expectations <answer key.toml>
```

`--run` accepts a run directory or a run id under `runs/`. The default answer key is
`test/acceptance/cpp-multivuln-v1/expectations.toml`.

## Which line to read first

| `stopped_because` starts with | Look at |
| --- | --- |
| `no_tool_observation`, `file_not_in_catalog` | the deterministic producers (the answer key already fails these) |
| `no_lead_at_location`, `package_not_selected_*` | lead generation and package selection, not the model |
| `red_cells_invalid:schema_error` | model output the cell executor could not parse or admit; see first-attempt parse rate and the cell receipts under `data/jobs/job_inference_security_review/cells/` |
| `red_cells_timed_out:budget_gap` | the per-cell token cap or deadline; compare `calls_per_cell` and retrieval counts |
| `retrieval_all_denied:<code>` | the retrieval authority rejected every lookup; the aggregate lists denials by code |
| `red_no_claim` | the cells worked and found nothing to claim at the location |
| `blue_*`, `judge_*`, `verifier_*`, `claim_*` | the adjudication of a claim that did exist |
| `published_*`, `claim_supported_not_confirmed` | the defect reached the report |

A run of the older protocol has no blue cells, judge or claims; those stages read `not_applicable_in_this_run`
or the line names what is absent. Missing artifacts never fail the evaluator.

## Detector scoring

After the funnel, `stepwise.py system` prints a CASTLE-style score per producer and stores it under `scoring`
in the same report JSON (design and numbered decisions:
[`../reviews/castle-style-detector-scoring.md`](../reviews/castle-style-detector-scoring.md)). Like the funnel
it is **reported, never asserted**: it cannot change `SYSTEM OK` / `SYSTEM FAILED`, and a failure to build it
is printed as `scoring unavailable` and recorded. For any finished run, read-only on the run tree:

```text
PYTHONPATH=src python -m appsec_review.acceptance.scoring --run <run dir or run id> \
    [--expectations <key.toml>] [--no-review] [--producers codeql,cppcheck] \
    [--tolerance 2] [--max-combination 3] [--top-list castle-2025-table2|mitre-2024] [--json]
```

Each tool observation is a report of its producer (`codeql`, `cppcheck`, `semgrep`, `clang-static-analyzer`,
`infer`, ...); the accepted final findings are scored by default as producer `review` (`--no-review` scores
scanners only; report schema `appsec-review/detector-scoring/2`). `review`'s headline match is function scope
and weakness family (`scope_tp`, `scope_precision`, `scope_recall`), because a reviewer cites the missing
check and not necessarily the sink line; scanners keep the strict match below. A report hits a
defect when it lies within `--tolerance` lines of the defect's lines and one of its CWEs is accepted for the
key CWE (`data/reference/scoring/cwe-match.json`; tool rules without CWEs are mapped through
`data/reference/scoring/rule-cwe.json`). Reports inside a case's scope that miss are false positives, each
report counted; reports in no case's scope are listed as unattributed and not scored.

| Line | Meaning |
| --- | --- |
| `scoring <producer>` | TP, FP (per report), FN, TN, precision, recall, case-based accuracy, the CASTLE score (paper eq. 1-2, kept for the paper comparison), then the scope-and-family match and which match is the producer's headline |
| `scoring detection` | per producer: defects only it hit (`unique_tp`) and its false positives |
| `scoring full_set` / `scoring best` | the CASTLE combination score of all producers and of the best subsets: each true positive credited once, every other report a cumulative penalty |
| `scoring marginal` | `score(all) - score(all without p)`; `net-negative` means the producer costs more in noise than it finds |
| `scoring reference` | CASTLE-C250 only: the paper's Table 3 row beside ours |
| `scoring gaps` | e.g. `no_negative_controls` (TN not measurable, as for v1), `producer_without_cwe:<p>`, `review_report_unavailable` |

Keys: `test/acceptance/cpp-multivuln-v1/expectations.toml` (default; 7 defects, no controls, so TN and
accuracy are not measurable), `test/acceptance/appsec-multi-vuln-c094-v1/expectations.toml` (7 defects and 7
paired negative controls in `projects/native/case-094`, derived from the evaluator guide's `case-094` records
and `controls`), and `test/acceptance/castle-c250-v1/expectations.toml` (CASTLE-C250: 150 defects, 100
controls, whole-file cases; the paper's Table 3 rows are shown beside ours by producer). A CASTLE score of
1232 is the computed maximum and 200 is what a tool reporting nothing gets.

### Manual validation (user-owned)

The following is the retained implementation-time validation plan, not current permission to
publish repositories or run acceptance. Its original publication/baseline statements describe
that checkpoint; current fixture provenance is in [test targets](test-targets.md), and a new
validation follows the [walk charter](../processes/walk-charter.md).

<!-- historical:begin -->

None of these has been run by the implementing agents.

1. **Publish case-094.** In WSL, from the linked repositories:

   ```text
   git -C ~/projects/appsec-multi-vuln push origin case-094 appsec-multi-vuln-c094-v1
   git -C ~/projects/appsec-multi-vuln-guide push origin case-094
   ```

   Both branches stack on the unpushed `polyglot-case-093`; push or merge that first if it is not on the
   remote. Then put the tagged commit in a target of its own, so the pinned default
   `targets/appsec-multi-vuln` (and `../reviews/native-evaluator-guide.lock.json`) is not moved:

   ```text
   git clone https://github.com/wsollers/appsec-multi-vuln.git targets/appsec-multi-vuln-c094
   git -C targets/appsec-multi-vuln-c094 checkout appsec-multi-vuln-c094-v1
   ```

2. **Live acceptance of case-094.** The key has no baselines or seeds yet. Point
   `APPSEC_REVIEW_TARGET=/opt/app/targets/appsec-multi-vuln-c094` in `deploy/dagster/.env`, recreate the
   code location, walk and accept every job (`stepwise.py init --target /opt/app/targets/appsec-multi-vuln-c094`,
   then `stepwise.py next` and `stepwise.py accept --job <job> --tag appsec-multi-vuln-c094-v1` per job), and
   finally run `python deploy/dagster/bin/stepwise.py system --tag appsec-multi-vuln-c094-v1`. Read the
   `scoring` lines: every control a producer reports is a measured false positive.

3. **CASTLE-C250.** Prepare the blind corpus outside the repository and check its SHA against the lock:

   ```text
   git clone https://github.com/CASTLE-Benchmark/CASTLE-Benchmark.git ~/projects/castle-upstream
   git -C ~/projects/castle-upstream checkout c7391c9ec5dd944653103fbf55e7ebbf85842d82
   PYTHONPATH=src python -m appsec_review.acceptance.castle prepare \
       --upstream ~/projects/castle-upstream --output ~/projects/castle-c250-blind
   git clone ~/projects/castle-c250-blind targets/castle-c250
   git -C targets/castle-c250 checkout castle-c250-v1
   ```

   The native-cpp image must also carry the SQLite3, CURL and mysqlclient development packages (26 CASTLE
   programs link them, and the generated CMake requires them), or the whole configure fails. Review `targets/castle-c250` with `APPSEC_REVIEW_TARGET=/opt/app/targets/castle-c250`
   (a `wave1_review` run, or `stepwise.py init`/`next` without accepting), then score it:

   ```text
   PYTHONPATH=src python -m appsec_review.acceptance.scoring --run <run id> \
       --expectations test/acceptance/castle-c250-v1/expectations.toml
   ```

   Compare `codeql`, `cppcheck`, `semgrep` and `clang-static-analyzer` with the paper rows shown beside them
   (CodeQL 2.20.1 45 TP / 49 FP, Cppcheck 2.13 19 / 9, Clang Analyzer 18.1.3 13 / 2). Our tool versions and
   rule sets differ, so a large move between runs of ours is the regression signal, not distance from the paper.

<!-- historical:end -->