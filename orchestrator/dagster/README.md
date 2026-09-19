# Local Dagster runner

This stack belongs to appsec-review. It runs the default `engagement_workflow`, the retained
`phase1_intake` job and the original smoke diagnostic, with persistent queue and instance history. See
[Phase 1 acceptance](../../docs/phase-1-acceptance.md) and the
[operations guide](../../docs/phase-1-operations.md) for staging and launch configuration.
The normal entry point is `python -B appsec-review-process/launch_job.py --run-id <run_id> --wait`.
It now selects [engagement_workflow](../../docs/dagster-workflow.md): two concurrent runs globally,
one per engagement, and up to three independent preparation steps per workflow. Use
`--job phase1_intake` for the intake-only graph. The queue, monitoring and failure/cancellation
sensors use the existing persistent instance; the stopped legacy stack is untouched.
See [Dagster launching](../../docs/dagster-launching.md): the service runs the graph, while the
client only submits and monitors. Configuration resolution is a separate visible op.

Services: PostgreSQL, user-code server, webserver, daemon. Only the webserver is published, at
http://127.0.0.1:3000. Freeciv21 source and governing code are mounted read-only. No host Docker
socket or host credentials are mounted.
Run data are bind-mounted at `/runs`; metadata and compute logs use project-specific Docker volumes.
Python/PostgreSQL base images are digest-pinned; Python dependencies use `requirements.lock.txt`
and `pip check`. Git is version-pinned. Qualification records actual runtime versions.

## Service setup and smoke diagnostic

For normal engagements, follow the [submission guide](../../docs/dagster-launching.md).
The smoke command below checks orchestration plumbing; it does not stage or review a target.
From the repository root, initialize the ignored local password file once:

```text
python orchestrator/dagster/setup.py
docker compose -f orchestrator/dagster/compose.yaml up -d --build
docker compose -f orchestrator/dagster/compose.yaml ps
docker compose -f orchestrator/dagster/compose.yaml exec code-server dagster job execute -f /opt/app/definitions.py -j orchestration_smoke
```

Open the UI, select `orchestration_smoke`, and inspect `pre_validation -> smoke_work ->
post_validation`. Set `ops.smoke_work.config.fail_work: true` to exercise failure. A failing work
step prevents post-validation execution. Each smoke execution deliberately creates a fresh
`appsec-review-process/runs/dagster-bootstrap-<dagster_run_id>/data/` directory; this fixture does
not exercise engagement reuse; `phase1_intake` implements and qualifies that contract.

Every executed step writes its diagnostics under its run data directory. The tiny subprocess writes
stdout and stderr directly to distinct files, then mirrors them into Dagster compute logs. It has
a 10-second timeout and propagates nonzero exits. The engagement adapter separately qualifies
concurrent streaming, process-tree cancellation, lost-owner cleanup, disk/logging failure,
immutable attempts and same-run validated reuse. Work metadata exposes separate stdout/stderr
file paths; UI messages contain stream sizes rather than raw worker output.
Container logs rotate at 10 MB, three files; run evidence is preserved without automatic pruning.

```text
docker compose -f orchestrator/dagster/compose.yaml logs --tail 100
docker compose -f orchestrator/dagster/compose.yaml stop
docker compose -f orchestrator/dagster/compose.yaml up -d
```

Use `stop` to preserve containers and volumes. Do not use `down --volumes` to start a new
engagement. The former `lra-ingestion-harness` stack was stopped, not removed; starting its
webserver on port 3000 while this stack is running would conflict.

Follow the [Phase 1 prompt](../../appsec-review-process/phase-1-implementation-prompt.md),
[run-data contract](../../docs/run-data-and-job-execution.md), and
[flow diagram](../../docs/engagement-job-flow.md) for production job wiring.
Dagster [asset-check documentation](https://docs.dagster.io/guides/test/asset-checks) explains that
checks must be configured to block downstream execution; check visibility alone is not a gate.
The bootstrap uses explicit op dependencies and propagated exceptions.
