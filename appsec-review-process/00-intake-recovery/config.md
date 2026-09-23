# Config — Stateful intake and recovery

Phase 1 intake uses the shared `phase1.py` adapter. Normal submission selects the Dagster
`engagement_workflow`, which adds parallel preparation and a validated final join. The retained
`phase1_intake` job performs intake alone. See [job submission](../../docs/dagster/dagster-launching.md).
Acceptance is recorded separately in the run-scoped A01–A16 report; a successful intake alone
is not implementation acceptance.

Required inputs: target path, business goal, platforms, scope includes/excludes, budget,
execution environment and granted permissions. `read-source` permits only the trusted static
inventory worker. Target code, hooks, build scripts and network scanners are not executed.

Every intake records source revision, full dirty/untracked file fingerprints, unavailable
links/submodules, all discovered language/workspace/build/deployment families, a conditional
native compile/link-recipe plan, and specialist job routing. Choosing a primary native project
never excludes the rest of the scope. Non-native and IaC-only targets need no compile database.
Native build coverage remains blocked until separately collected; intake itself can pass.

Authoritative outputs live in `runs/<run_id>/data/jobs/00-intake/whole/attempts/<attempt_id>/`:
`evidence/source.json`, `outputs/intake.json`, `outputs/build-discovery.md`, validation results,
separate logs, and `status.json`. The atomic `accepted.json` pointer selects validated output.
Missing scanner artifacts are expected initially; supplied corrupt artifacts block intake.
Post-pregather completeness is checked separately. Prior plans require explicit hashed imports.

The `intake-coordinator` persona/role coordinates developer, DevOps and SRE review assignments.
`contract-validator` / `execution-validator` performs deterministic nonrecursive pre/post checks.
The machine graph is `job-graph.json`. Partition/specialist jobs are planned, not dispatched by
Phase 1. The next step is `02-repository-partition-discovery`, before characterization; it and
`02-dev-project-discovery` are supplied-result gates (`discovery_gate.py`, standalone jobs
`repository_partition_discovery` and `dev_project_discovery`).

Since ADR-0011 intake runs in the host code location, and runs are created and staged on the same
POSIX host (Linux, or WSL on Windows) with a host `--target` path; runs are no longer created inside
a code-server container. The execution-platform check is unchanged: the run records `posix`, and
Dagster refuses a run staged on another platform.

Workflow settings use `resources.workflow_settings.config` with `engagement_run_id` and `force`.
UI launches require a matching `engagement_run_id` tag; the host launcher supplies it. Workflow
state is under `data/workflows/engagement/`; intake state alone is not workflow acceptance.
