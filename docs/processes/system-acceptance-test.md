# System acceptance test (SAT)

One fixture, taken from a fresh clone of the system under test through the whole review cycle, to
SARIF and report generation, **in the order of the documented engagement flow**
([engagement-start.md](engagement-start.md)). The SAT is how the system is finished: stages are built
in flow order, and no stage is added until every earlier one runs and passes on the host.

Script: `scripts/system-acceptance-test.sh` (POSIX host); `scripts/system-acceptance-test.ps1` runs it
inside WSL from Windows. Contract engine: `scripts/sat_contract.py` (tested by
`appsec-review-process/tests/test_sat_contract.py`).

```bash
cd ~/projects/appsec-review
scripts/system-acceptance-test.sh --list                                # stages, and which are built
scripts/system-acceptance-test.sh --through <stage>                     # new SAT from the top
scripts/system-acceptance-test.sh --resume <sat_id> --through <stage>   # continue an earlier SAT
```

Start the code location first, in its own terminal (`orchestrator/dagster/code-location.sh start`).

## Contract enforcement: verify what you read, verify what you wrote

Every command the SAT runs goes through `run_step`, with a contract per command:

1. **Pre (inputs).** Every input the command reads is present and valid: parsed, validated against
   its schema in `schemas/` where one exists, otherwise against a structural contract (required
   fields and values). Inputs that must not exist yet (a supplied result before its hand-off check,
   an accepted intake before intake runs) are checked absent.
2. **Run.** The command's exit code must be the one the contract expects (0, or 1 where failure is
   the expected result).
3. **Post (writes).** The repository is snapshotted before and after (path, size, mtime; content
   hashes for the run folder and the checkout). Every added or modified file must match the
   command's declared write set, every declared required write must be present, and nothing may be
   deleted unless declared. Write sets are exact file shapes (`attempts/*/outputs/intake.json`), not
   whole folders.
4. **Post (outputs).** Every artifact the command wrote that the contract names is validated: schema
   where one exists, structural fields otherwise.

Then the stage checks the job's own success signal (Dagster `SUCCESS`, `LOADED`, an accepted pointer
from this very Dagster run) and the artifacts' meaning (semantic checks listed per stage below).

Ambient paths change without any SAT command and are reported, never counted: Dagster's own host
storage (`orchestrator/dagster/.host/`) and the scheduled NVD feed (`data/feeds/nvd/`).

Record: `appsec-review-process/logs/system-acceptance/<sat_id>/` (gitignored): `sat.json` (per stage:
status, evidence, and a summary of each step), `<stage>.log`, `contracts/<stage>.<step>.json` (the
contract as applied), `steps/<stage>.<step>.pre.json` and `.post.json` (inputs verified with their
hashes; every file added, modified, deleted; outputs validated). A failing stage stops the SAT; an
unbuilt stage stops it with `NOT_IMPLEMENTED` (exit 3).

## Stages

| # | Stage | Built |
|---|---|---|
| 1 | `sut-checkout` | yes |
| 2 | `services` | yes |
| 3 | `run-create` | yes |
| 4 | `stage-inputs` | yes |
| 5 | `engagement-workflow` (config, intake, 3 preparation branches, join) | yes |
| 6 | `partition-discovery` (gate) | yes |
| 7 | `dev-project-discovery` (gate) | yes |
| 8 | `devops-project-discovery` (gate; the fixture's Dockerfile) | |
| 9 | `sre-operations-topology` (gate) | |
| 10 | `build-discovery` | |
| 11 | `evidence` (legacy pipeline + hashed import; every tool ran or is a recorded gap) | |
| 12 | `ossf-scorecard` (needs a network permission grant) | |
| 13 | `evidence-index` | |
| 14 | `build-configure` (B13, C++ build environment, E01) | |
| 15 | `native-build` | |
| 16 | `review-lanes` | |
| 17 | `sarif` | |
| 18 | `report` | |

`build-configure` and `native-build` depend on Phase 3 (B13), Phase 4 (build environment) and E01.
A missing compile database blocks native lanes, not the engagement: stages 10 to 13 do not depend on
them.

### 1. `sut-checkout`

| Step | Reads (pre) | Writes (post) | Validates |
|---|---|---|---|
| `remove` (only if a checkout exists) | the checkout is a clean clone of the expected origin (git) | deletes only the checkout | checkout gone |
| `clone`: `fixtures/populate-targets.sh <fixture>` | the script; the checkout absent | only files inside the checkout; `configure.ac`, `Makefile.am`, `src/*` required | exactly the tracked-file count written |

Then: HEAD equals the pin (from `populate-targets.sh`, the single source), tree clean, origin right,
`docs/VULNERABILITIES.md` absent, no `VULN`/`CWE-` comments in `src/` (the answer key stays on the
fixture's `with-vulnerabilities-doc` branch).

### 2. `services`

| Step | Reads | Writes | Validates |
|---|---|---|---|
| `compose-up` | `compose.yaml`, `.env`, `workspace.yaml`, `dagster.yaml` | nothing in the repository | all three services `running/healthy` within 240 s |
| `reload`: `code-location.sh reload` | `definitions.py`, `dagster_workflow.py` | nothing | `LOADED` |

Before and around them: Docker answers (hang vs error reported), Docker Desktop is the only engine
(no native `docker.service`, ADR-0011 addendum 2026-09-23), `.env`'s code location address matches
this WSL boot, the webserver resolves `host.docker.internal` (IPv4) to it, gRPC health passes, the
SAT's jobs are loaded, every required Dagster daemon is healthy. The code location is checked, never
started.

### 3. `run-create`

| Step | Reads | Writes | Validates |
|---|---|---|---|
| `start`: `run_process.py --start` | `process-manifest.json` (`process_order`), the manifest template (unfilled) | exactly `run-status.json`, `run-status.md`, `events.jsonl`, `inputs/artifact-manifest.json`, all in the one new run | `run-status.json` schema id, `READY`, nothing completed |

Then: run id format; `resume_from` is the manifest's first lane; exactly one `RUN_CREATED` event; the
manifest is byte-identical to the template; `run-status.md` names the run.

### 4. `stage-inputs`

| Step | Reads | Writes | Validates |
|---|---|---|---|
| `stage`: `stage_artifacts.py` (fixed SAT engagement, `SAT_*` overrides) | `run-status.json` (this run, `READY`), the template manifest, the checkout | exactly the manifest, `run-status.json`, `run-status.md`, `processes/00-intake-recovery/status.json`, `data/publication.lock` | manifest: `orchestration_version` 1, run id, project, `executor_platform` posix, `read-source` only, no imports, no compile database, no supplied evidence, whole-tree scope |

Then: target, goal, platform, budget and execution environment as staged; run still `READY`.

### 5. `engagement-workflow`

| Step | Reads | Writes | Validates |
|---|---|---|---|
| `launch`: `launch_job.py --job engagement_workflow --wait` | manifest (posix-staged, this run); **no accepted intake yet**; **no published workflow yet**; `workflow-plan.json`; the checkout | intake attempt files (`inputs`, `status`, `evidence/source.json`, `logs/*`, `outputs/intake.json`, `outputs/build-discovery.md`, `validation/{pre,post}/*`), intake pointers; for each of the 3 branches: `inputs`, `output`, `pre`, `post`, `status`, `logs/*`, pointers; the workflow's `accepted`, `status`, `attempts/*/result.json`, `config.json`; manifest, run state views, `data/events.jsonl`, launch request, Dagster op records | `intake.json` against `schemas/intake.schema.json`; intake pointer `OK` (contract `intake`); workflow `OK`, `PLANNED_NOT_EXECUTED`; 3 branch outputs with no findings and no target execution |

Then: Dagster `SUCCESS`; `workflow.inspect_status` `OK`; intake **executed by this Dagster run**
(accepted pointer from it, `ACCEPTED` event, no `REUSE`), latest, every output file unchanged since
acceptance; `intake.json` has the pin, the staged values, exactly the clone's file count, no
findings, build `NOT_EXECUTED` with no commands attempted, partition and developer discovery
`required`; the manifest records the pointer and the revision; the workflow joined exactly the three
branches on this intake; discovery hand-offs `PLANNED_NOT_EXECUTED`; checkout unchanged.

### 6. `partition-discovery` and 7. `dev-project-discovery` (supplied-result gates)

Three steps each: `handoff`, `supply`, `accept`.

| Step | Reads | Writes | Validates |
|---|---|---|---|
| `handoff`: the gate with nothing supplied, **exit 1** | accepted intake (`OK`); the supplied result **absent** | `handoff.md`, `handoff.json`, `handoff/latest-handoff.json`, `handoff/handoffs/*.json`, `job.lock`; for the partition gate also a `BLOCKED` attempt (`inputs`, `result`, `status`) and its pointers; launch request | `handoff.json` names the job, the expected schema, the path; hand-off record has identity, composition, inputs, fingerprint, claim class; partition's `result.json` against `worker-result-envelope.schema.json` |
| `supply`: `fixtures/supply_record.py` | the fixture record against its schema, at the pin; the staged manifest's target; the supplied result absent | exactly `supplied/result.json` | against its schema; byte-identical to the record |
| `accept`: the gate again | the supplied result against its schema, at the pin; the upstream acceptance (intake for partition, the partition map for developer discovery) | partition: attempt `inputs`, `repository-partition-map.json`, `repository-partition-summary.md`, `result.json`, `status.json`, `supplied/result.json` and refreshed pointers/hand-off; developer: exactly `accepted`, `latest`, attempt `inputs`, `output`, `status` | outputs against their schemas (`repository-partition-map`, `project-discovery`, the worker envelope with `execution_status` `OK`) |

Then: Dagster `FAILURE` for `handoff` with nothing accepted, `SUCCESS` for `accept`;
`discovery_gate.validate` accepts; accepted by the launched Dagster run; every source-file citation's
SHA-256 recomputed from the checkout; partition: records' partitions, `docs` deferred; developer:
accepted output = supplied file = fixture record, same revision as the accepted partition map, every
command-plan entry has argv, purpose and authorization.

## Gaps the contracts have exposed

| Gap | Where | Status |
|---|---|---|
| No schema for the run manifest, run status, workflow and branch outputs, accepted pointers, or the job hand-off record | `schemas/` | Structural contracts in the SAT meanwhile |
| The developer-discovery gate records no output hashes in its accepted record | `discovery_gate._legacy_run` | SAT compares output, supplied file and record |
| DevOps and SRE discovery required by intake (Dockerfile) but have no gate or Dagster job | job graph, `dagster_workflow.py` | Stages 8 and 9 |
| No LLM or agent produces the discovery records; they are supplied fixture records | persona dispatch not wired into the gates | Open |
| Dagster-launched steps may write under `data/orchestration/dagster/*`, which a sandbox run without Dagster cannot observe | contracts | Confirmed only on the host run |
