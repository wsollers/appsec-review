# Reading the per-defect funnel

After a model-backed run, `stepwise.py system --tag cpp-multivuln-v1 [--app-run ID]` prints the answer-key
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
