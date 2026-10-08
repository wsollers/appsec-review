# Dagster deployment

This deployment is a thin adapter around the application runtime. The code location discovers
semantic jobs from `JobRegistry`, reads names and schedules from `appsec-review.toml`, and sends
every Dagster launch through `JobRunner`. Dagster does not allocate application run ids, create
attempt directories, validate job output, or publish application status.

The Compose project contains PostgreSQL, a gRPC code location, the webserver, and the daemon. Only
the web console is published, on `127.0.0.1:3000`. The repository's `runs/` and `data/` directories
are mounted into the code-location container, and `targets/` is mounted read-only for review jobs;
PostgreSQL and Dagster compute logs use named volumes.
The code location alone receives the Docker socket and client needed to execute the pinned,
network-disabled cve-bin-tool database builder. Do not expose the code location to untrusted code.

## Build, start, verify, and stop

Run these commands from the repository root. Bootstrap creates an ignored `.env` once and preserves
its secret on later calls. On native Linux it also records the invoking operator's uid/gid so the
code location does not leave root-owned files in the bind-mounted `runs/` and `data/` trees.

```powershell
python deploy/dagster/bin/bootstrap.py
python deploy/dagster/bin/lifecycle.py build
python deploy/dagster/bin/lifecycle.py start
python deploy/dagster/bin/lifecycle.py status
python deploy/dagster/bin/verify.py
```

The console is then available at <http://localhost:3000>. The verification command checks the live
HTTP endpoint and GraphQL workspace, then compares the connected jobs and schedules with
`appsec-review.toml`, including cron, time zone, and enabled state.

Rebuild and reload only the code location after an application change, then prove that the
workspace reconnected:

```powershell
python deploy/dagster/bin/lifecycle.py build
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml up -d --no-deps --force-recreate --wait code-location
python deploy/dagster/bin/verify.py
```

Use the code-location CLI as a non-executing manual smoke check. It imports the same definitions
served to the webserver and prints the discovered semantic jobs:

```powershell
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml exec code-location dagster job list --module-name appsec_review.orchestration.dagster.definitions
```

Launch `third_party_data_sync` manually from the console only when a real external-data refresh is
intended; it performs network, filesystem, and isolated Docker work. The following command launches
through the live Dagster instance and retains the Dagster id for terminal verification:

```powershell
$dagsterRunId = [guid]::NewGuid().ToString()
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml exec -T webserver dagster job launch -w /opt/dagster/home/workspace.yaml -l appsec_review -j third_party_data_sync --run-id $dagsterRunId
python deploy/dagster/bin/verify.py --run-id $dagsterRunId --evidence deploy/dagster/verification/live-acceptance.json
```

Launch the deterministic review graph (intake, target catalog, and evidence collection) through the
same live instance. Its target mount is read-only, while application receipts and handoffs remain in
the ignored `runs/` mount. The retained Dagster job name is `wave1_review` for deployment continuity:

```powershell
$dagsterRunId = [guid]::NewGuid().ToString()
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml exec -T webserver dagster job launch -w /opt/dagster/home/workspace.yaml -l appsec_review -j wave1_review --run-id $dagsterRunId
python deploy/dagster/bin/verify.py --run-id $dagsterRunId --evidence deploy/dagster/verification/wave1-live-acceptance.json
```

The configured schedule and a manual launch enter the same generated dispatch op and `JobRunner`
path. Schedule cron, time zone, and enabled state come only from
`jobs.job_third_party_data_sync.schedule` in `appsec-review.toml`; the current declaration is
`0 0 * * *` in `UTC`, enabled.

Dagster and the application intentionally allocate different run ids. Dagster uses its UUID for
control-plane history. `JobRunner` allocates the date/serial application id used by immutable
receipts. On success the Dagster run receives `appsec/application_run_id` and
`appsec/application_attempt_id` tags plus structured output metadata for all unit statuses,
snapshots, counts, gaps, and receipt paths. The application `status.json` contains the reverse
`orchestration.system=dagster` and `orchestration.run_id=<Dagster UUID>` link. The verification
command validates both directions rather than inferring success from one system alone.

Dagster shows one execution op deliberately. The runtime does not yet expose a safe resumable API
for independently dispatched tasks, so drawing 12 Dagster ops would create false lifecycle
ownership. `JobRunner` executes and validates the real task graph; Dagster displays its 12 receipts
as structured metadata on the honest dispatch op.

Stop containers without deleting persistent state:

```powershell
python deploy/dagster/bin/lifecycle.py stop
```

For diagnostics:

```powershell
python deploy/dagster/bin/lifecycle.py logs
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml config
```

Do not use `down --volumes` during normal operation; that deletes the Dagster and PostgreSQL state.

## Tests

Run the full repository suite on the host. It skips only the optional Dagster tests when that
dependency is absent. Then run the deployment-specific suite in the pinned image:

```powershell
python -m pytest -q
docker build --file deploy/dagster/Dockerfile --target test --tag appsec-review-dagster-test .
docker run --rm appsec-review-dagster-test
```

The deployment tests cover TOML schedule generation, registry discovery, manual/scheduled dispatch
convergence, structured metadata mapping, and application-failure propagation. Live acceptance
evidence and its scope are described in `deploy/dagster/verification/README.md`.
