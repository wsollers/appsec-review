# Retained report example

These files retain the presentation reference generated from
`pipeline/report/examples/hello-autotools.review.json`:

- `appsec-review-sample.pdf` is the paginated A4 report.
- `appsec-review-sample.html` is the equivalent self-contained HTML report.

They demonstrate the report layout and publication format. They are not evidence of a live target
scan and must not be treated as an accepted review attempt.

> **PDF is stale (2026-09-29).** The sample data and `appsec-review-sample.html` were refreshed to
> the current 81-job graph and real section 3A/3B/3C records (brief P). `appsec-review-sample.pdf`
> still shows the old 42-process sample until it is re-rendered in the pinned TeX image (commands
> below). Remove this note when the PDF is replaced.

## How the sample is produced

The sample stays SAMPLE DATA: the cover, findings and evidence register are hand-kept illustrations.
Every other block is produced by `pipeline/report/sample_data.py` through the real code paths:

| Block | Produced by |
|---|---|
| `families`, `processes`, `scoring.family_weight` | One process per job in `job-graph.json`, grouped by its `lane`; kind and tools from the design-parity manifest. Statuses follow a fixed SAMPLE rule in `sample_data.py` (`SKIPPED` with the workers' own reason codes, a few `OK_WITH_GAPS`, the rest OK). A family's weight is its job count. |
| 3A `attack_chains` | Lane 14 composition and refutation workers over the canned replies of `tests/test_attack_chain_report.py` (the case-001 argv to strcpy fixture), projected by `attack_chain_report.build`. |
| 3B `dependency_reachability` | `dependency_reachability_report.build` over a schema-valid 06 summary with no SCA match (vendored cJSON has no purl or CPE). |
| 3C `threat_workbench` | `threat_workbench.join` over `examples/hello-autotools.workbench-replies.json`, the core and overlay validators, `synthesis_report.build_report` (closed schema) and `synthesis_report_presentation._threat_workbench`. |
| finding `exploit_signal`, lane-12 trail row | `synthesis_report_presentation._exploit_text` (EPSS/KEV not assessed) and the pinned `cvss4.py`. |

`python3 pipeline/report/sample_data.py --check` fails when the file is stale, and
`appsec-review-process/tests/test_sample_report_data.py` fails when the job graph gains a job the
sample lacks.

## Re-render (WSL, needs Docker)

```bash
python3 pipeline/report/sample_data.py --check
bash pipeline/report/render-in-docker.sh                 # -> pipeline/report/build/report.pdf and report.html
cp pipeline/report/build/report.pdf docs/report-examples/appsec-review-sample.pdf
cp pipeline/report/build/report.html docs/report-examples/appsec-review-sample.html
```

## Happy-path demo

The `appsec-review-happy-path-demo.pdf` and `.html` pair is the retained, deterministic render of
the completed nominal lifecycle fixture in `.artifacts/retained-final-demo-20260927`. It exercises
accepted lifecycle evidence, OWASP join reporting, scoring, completeness/resynthesis controls,
human signoff, and final publication. It is prominently marked DEMO and is not a production target
assessment.
