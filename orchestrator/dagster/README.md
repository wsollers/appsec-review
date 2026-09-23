# Local Dagster runner

This stack belongs to appsec-review. It runs the default `engagement_workflow`, the retained
`phase1_intake` job and the original smoke diagnostic, with persistent queue and instance history.
Phase 1 intake was accepted through A01-A16 on 2026-09-19 (run `20260919T104300Z-ba7b4c`). See the
[operations guide](../../docs/dagster/operations.md) for staging and launch configuration.
The normal entry point is `python -B appsec-review-process/launch_job.py --run-id <run_id> --wait`.
It now selects [engagement_workflow](../../docs/dagster/dagster-workflow.md): two concurrent runs globally,
one per engagement, and up to three independent preparation steps per workflow. Use
`--job phase1_intake` for the intake-only graph. The queue, monitoring and failure/cancellation
sensors use the existing persistent instance.
See [Dagster launching](../../docs/dagster/dagster-launching.md): the service runs the graph, while the
client only submits and monitors. Configuration resolution is a separate visible op.

Services: PostgreSQL, webserver, daemon in Compose; the user-code server is a **host process**
([ADR-0011](../../docs/decisions/ADR-0011-orchestration-boundary.md)): `code-location.sh` (or
`code-location.ps1`, which runs it under WSL) serves `definitions.py` with `dagster api grpc` on port
4000, and webserver/daemon reach it at `host.docker.internal:4000`. Ops therefore run as host
processes with the host's own Docker; no Docker socket is mounted into any container. Only the
webserver (http://127.0.0.1:3000) and PostgreSQL (`127.0.0.1:${APPSEC_PG_PORT:-55432}`, for the host
code location and its run workers) are published, both on loopback.
Run data are written by the host user under `appsec-review-process/runs/`; the instance config in
`dagster.yaml` is env-sourced so the containers and the host resolve their own Postgres address and
log directories. Compute logs live in the ignored `.host/compute-logs`, shared with the webserver.
Python/PostgreSQL base images are digest-pinned; Python dependencies use `requirements.lock.txt`
(resolved for Python 3.12, so the host venv must be 3.12) and `pip check`.

## Service setup and smoke diagnostic

For normal engagements, follow the [submission guide](../../docs/dagster/dagster-launching.md).
The smoke command below checks orchestration plumbing; it does not stage or review a target.
From the repository root, initialize the ignored local password file once:

```text
python orchestrator/dagster/setup.py
orchestrator/dagster/code-location.sh start          # separate terminal; Windows: .\orchestrator\dagster\code-location.ps1
orchestrator/dagster/code-location.sh reload         # after every code-location (re)start
docker compose -f orchestrator/dagster/compose.yaml up -d --build
docker compose -f orchestrator/dagster/compose.yaml ps
```

Then launch `nop` (plumbing only: one op that writes to stdout and stderr and succeeds) or
`orchestration_smoke` from the UI. `code-location.sh check` runs the gRPC health check. Operator
commands (creating, staging and submitting runs) are in [Dagster launching](../../docs/dagster/dagster-launching.md);
they all run on this host, with the code location's venv.

### Native Linux host

Docker Desktop (Windows, macOS) maps bind-mount ownership for you; a native Linux Docker engine does
not. `setup.py` therefore also appends `APPSEC_UID` / `APPSEC_GID` (the operator's uid/gid) to the
ignored `.env` on a POSIX host, and `compose.yaml` starts the runtime services as that user
(`user: "${APPSEC_UID:-0}:${APPSEC_GID:-0}"`; unset keeps root, the previous behaviour). Running as
root on native Linux used to break run data and git ownership when workers ran in a container.
Since ADR-0011 run data and targets are written and read by the host code location as the operator,
so this matters only for the services' own files: compute logs under the bind-mounted `.host/`
(which `setup.py` creates as the operator before `compose up` can create it as root).

Prerequisites: Docker Engine with the Compose v2 plugin (`docker compose version`; on Ubuntu the
package is `docker-compose-v2`), the operator in the `docker` group, and the review target checked
out on the host (for example under `targets/<name>`, ignored by git). Because workers now run on the
host (ADR-0011), the host also needs Python 3.12 with `venv` (`python3.12-venv`), `git`, and
`libfuzzy2` (`evidence_index` loads `libfuzzy.so.2`; `code-location.sh start` warns if it is
missing). These are no longer pinned by the image; qualification should record the host versions.

A stack first created as root may have left root-owned run directories and a root-owned `.host/`.
Fix them on the host, then re-run `setup.py` and `up -d`:

```text
sudo chown -R "$(id -u):$(id -g)" appsec-review-process/runs data/feeds/nvd orchestrator/dagster/.host
```

`nvd_reference_schedule` is on by default and calls the NVD API every two hours from the moment the
stack starts. On a development host add `APPSEC_NVD_SCHEDULE=stopped` to `.env` (the only other
accepted value is `running`); the job can still be launched by hand.

Workers read the repository in place, so suites resolve `docs/`, `data/reference/` and `schemas/`
at their normal relative locations. Run the unit suite where the workers run, on the host, with the
code location's venv:

```text
mkdir -p /tmp/p1 && PHASE1_TEST_DATA=/tmp/p1 APPSEC_DEFINITIONS_DIR=orchestrator/dagster \
  ~/.venvs/appsec-review-dagster/bin/python -B -m unittest discover -s appsec-review-process/tests -p "test_*.py"
```

To run a suite in exactly the jobs' environment (instance, run root, definitions), use
`orchestrator/dagster/code-location.sh run -B <script> [args]`; `qualify_phase1.py` does this for
its Linux test pass and its live-Dagster checks.

`compose.yaml`, `Dockerfile`, `definitions.py` and `dagster.yaml` are part of every job's runtime
fingerprint (`job_graph.py`), so a change to any of them makes previously accepted pointers
non-current.

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
engagement. This project only starts, stops and reports on its own Compose project (`appsec-review`); other
projects' containers on the same Docker engine are outside its scope and are never inspected. Port 3000 must be free for this stack's webserver.

Follow the [Phase 1 prompt](../../appsec-review-process/phase-1-implementation-prompt.md),
[run-data contract](../../docs/dagster/run-data-and-job-execution.md), and
[generated job graph](../../docs/design-parity/job-graph.mmd) for production job wiring.
Dagster [asset-check documentation](https://docs.dagster.io/guides/test/asset-checks) explains that
checks must be configured to block downstream execution; check visibility alone is not a gate.
The bootstrap uses explicit op dependencies and propagated exceptions.
