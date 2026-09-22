# Engagement flow bring-up on `hello-autotools` (working tracker)

Status: **living tracker**, updated as each step is run. We bring the engagement flow up in
process-flow order on the `hello-autotools` fixture, using the ADR-0011 split: Dagster
(webserver, daemon, postgres) in Docker Desktop, and the code location plus every operator command
as host processes in WSL (`Ubuntu-24.04`, clone at `~/projects/appsec-review`). The flow and
requirements themselves are in [engagement-start.md](engagement-start.md); the phase plan is in
`appsec-review-process/TODO.md` ("Step 4 plan").

## Flow and status

```mermaid
flowchart TD
  P0["P0 Stack up: compose + host code location<br/>nop job proven"]:::done
  P1["P1 fixtures/populate-targets.sh<br/>hello-autotools @ e3ad863"]:::done
  S1["S1 run_process.py --start<br/>creates run_id + run-owned dirs"]:::next
  S2["S2 stage_artifacts.py<br/>--target fixtures/targets/hello-autotools"]:::todo
  S3["S3 00-intake<br/>launch_job.py --job phase1_intake"]:::todo
  S4a["S4a 02-repository-partition-discovery<br/>no supplied map: expect actionable hand-off FAIL"]:::todo
  S4b["S4b author supplied partition map<br/>re-run: expect accepted"]:::todo
  S5["S5 02-dev-project-discovery (supplied)<br/>devops / sre: SKIPPED not-applicable"]:::todo
  S6["S6 02-build-configure"]:::blocked
  B13["Phase 3: B13 into service + B16 image registry"]:::blocked
  BE["Phase 4: C++ buildenv provisioning + lock"]:::blocked

  P0 --> P1 --> S1 --> S2 --> S3 --> S4a --> S4b --> S5 --> S6
  B13 -.-> S6
  BE -.-> S6

  classDef done fill:#d8f0d8,stroke:#2e7d32,color:#1b3d1b
  classDef next fill:#fff1c2,stroke:#b8860b,color:#4a3a00
  classDef todo fill:#eef1f5,stroke:#6b7a90,color:#2a3240
  classDef blocked fill:#f6dcdc,stroke:#b23b3b,color:#4a1515
```

Legend: green done, yellow next, grey to do, red blocked on another phase.

## Steps

All commands run in WSL from `~/projects/appsec-review` with the code location running
(`orchestrator/dagster/code-location.sh start`). `PY` is the code location's venv:
`PY=~/.venvs/appsec-review-dagster/bin/python`.

| Step | Who / what | Command | Expected result | Status |
|---|---|---|---|---|
| P0 | stack + host code location | `docker compose -f orchestrator/dagster/compose.yaml up -d`; `orchestrator/dagster/code-location.sh start` | `code-location.sh check` succeeds; `nop` runs | DONE 2026-09-22 (runs ac01458f, 3ea3b999) |
| P1 | fixture target | `fixtures/populate-targets.sh` | `hello-autotools` at `e3ad863` | DONE 2026-09-22 |
| S1 | security engineer: create the engagement | `$PY -B appsec-review-process/run_process.py --start` | JSON with `run_id`; `appsec-review-process/runs/<run_id>/` exists | NEXT |
| S2 | security engineer: stage inputs | `$PY -B appsec-review-process/stage_artifacts.py --run-id <run_id> --project hello-autotools --target fixtures/targets/hello-autotools --business-goal "..." --platform Linux --budget probe --execution-environment dagster-read-only-linux` | `inputs/artifact-manifest.json` validates; `executor_platform` = `posix` | |
| S3 | Dagster: `00-intake` | `$PY -B appsec-review-process/launch_job.py --run-id <run_id> --job phase1_intake --wait` | `SUCCESS`; `data/jobs/00-intake/whole/accepted.json` | |
| S4a | Dagster: partition discovery gate | `launch_job.py --run-id <run_id> --job repository_partition_discovery --wait` | fails with an actionable hand-off (no silent success) | |
| S4b | author supplied `repository-partition-map` | (to write: one component, one native family, autotools route) | gate accepts it | |
| S5 | dev-project discovery; devops/sre skip | (via `engagement_workflow` / `full_review` graph) | dev accepted; devops + sre `SKIPPED(not-applicable-no-matching-inputs)` with receipts | |
| S6 | `02-build-configure` | -- | needs B13 (Phase 3) and the C++ buildenv (Phase 4) | BLOCKED |

## Log

- 2026-09-22 -- P0/P1 done. Networking under WSL 2 NAT required the distro-IP mapping
  (ADR-0011 addendum). First operator script identified: `run_process.py --start` (S1), now a host
  command, no longer `docker compose exec code-server`.
