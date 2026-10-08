# Current Process Runbook

The filename is retained temporarily for inbound links. It no longer describes a manual lane
workflow.

Use the [happy-path operator guide](../docs/report-path/happy-path-operator-guide.md) for host setup,
staging, `full_review`, evidence inspection and draft-report acceptance. Use
[`../docs/dagster/dagster-launching.md`](../docs/dagster/dagster-launching.md) for launch, queue,
reconnect, cancel and recovery details.

The normal submission is:

```powershell
python -B appsec-review-process/launch_job.py --run-id <run-id> --job full_review --wait
python -B appsec-review-process/review_cli.py status --run-id <run-id>
```

Reconnect to a running launch with its recorded `launch_id`. After correcting a terminal failure,
submit a new launch for the same run so freshness and accepted reuse are validated. Cancel through
Dagster. Closing the monitoring terminal does not cancel server work.

Do not operate a new review with `run_process.py`, `stage_artifacts.py`, `create_handoff.py`,
`validate_lane_output.py`, root engagement/pregather scripts, shared scratch, or direct numbered
lane prompts. Their remaining readers and deletion gates are recorded in `TODO.md` S1.
