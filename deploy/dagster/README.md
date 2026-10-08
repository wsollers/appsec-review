# Dagster deployment

This deployment is a thin adapter around the application runtime. The code location discovers
semantic jobs from `JobRegistry`, reads names and schedules from `appsec-review.toml`, and sends
every Dagster launch through `JobRunner`. Dagster does not allocate application run ids, create
attempt directories, validate job output, or publish application status.

The Compose project contains PostgreSQL, a gRPC code location, the webserver, and the daemon. Only
the web console is published, on `127.0.0.1:3000`. The repository's `runs/` and `data/` directories
are mounted into the code-location container; PostgreSQL and Dagster compute logs use named volumes.

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
`appsec-review.toml`.

Use the code-location CLI as a non-executing manual smoke check. It imports the same definitions
served to the webserver and prints the discovered semantic jobs:

```powershell
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml exec code-location dagster job list --module-name appsec_review.orchestration.dagster.definitions
```

Launch `third_party_data_sync` manually from the console only when an NVD synchronization is
intended; it performs real network and filesystem work. Its configured schedule and a console
launch both enter the same generated dispatch op and `JobRunner` path. The schedule is enabled or
disabled only by `jobs.<job-id>.schedule.enabled` in `appsec-review.toml`.

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

The normal repository suite skips Dagster-specific tests when the optional dependency is absent.
The pinned image has the integration dependency and provides a test stage:

```powershell
docker build --file deploy/dagster/Dockerfile --target test --tag appsec-review-dagster-test .
docker run --rm appsec-review-dagster-test
```
