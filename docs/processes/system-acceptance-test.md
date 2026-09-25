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
scripts/system-acceptance-test.sh --dispatch --through <stage>          # new SAT: stages 6 and 7
                                                                        # dispatch a real persona
                                                                        # invocation (D01, D02) instead
                                                                        # of installing the fixture's
                                                                        # supplied records
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
| 6 | `partition-discovery` (gate; `--dispatch`: D01 live automatic persona dispatch instead) | yes |
| 7 | `dev-project-discovery` (gate; `--dispatch`: D02 live automatic persona dispatch instead) | yes |
| 8 | `devops-project-discovery` (gate; the fixture's Dockerfile) | yes |
| 9 | `sre-operations-topology` (gate; chains after devops discovery) | yes |
| 10 | `build-index` (deterministic, cited build signals) | |
| 11 | `build-plan` (LLM build plan from the index; compared with the fixture answer key) | |
| 12 | `build-resolution` (image + trial build via B13, `build_resolution_attempts`; `image_build_<id>` catalogued) | |
| 13 | `build-configure` (E01: replay the lock) | |
| 14 | `native-build` (E02: compile database, binaries) | |
| 15 | `evidence` (legacy pipeline + hashed import; every tool ran or is a recorded gap) | |
| 16 | `ossf-scorecard` (needs a network permission grant) | |
| 17 | `evidence-index` | |
| 18 | `review-lanes` | |
| 19 | `sarif` | |
| 20 | `report` | |

Stages 10 to 14 are how the system learns to build a target it has never seen and then builds it:
[build-resolution.md](build-resolution.md) (ADR-0012). They come before evidence collection
because native evidence depends on a build. A `FAILED(BUILD_UNRESOLVED)` blocks native jobs, not
the engagement; the SAT fixture must resolve. The fixture's supplied discovery records are answer
keys: the build stages' pre-contracts check they are not in the run or the model's inputs, and
`build-plan` compares the plan with them afterwards. A second SAT with `build_image_reuse=auto`
must reuse the catalogued image; one with `rebuild` must infer again.

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

### 6. `partition-discovery`, 7. `dev-project-discovery`, 8. `devops-project-discovery`, 9. `sre-operations-topology` (supplied-result gates)

Three steps each: `handoff`, `supply`, `accept`. Stage 8 is the same gate shape as stage 7 --
`02-devops-project-discovery` reuses the `project-discovery` contract and schema, reading the
devops-persona partitions of the same accepted partition map (the fixture's Dockerfile as the
build/release route, not a second native build to resolve). Stage 9 (`02-sre-operations-topology`)
chains after stage 8's accepted record instead of the partition map directly (William, 2026-09-24:
operations topology is read off the containers/services devops discovery already found), using its
own `operations-topology` schema: one `hello-autotools` `cli-batch` service, no ports or
dependencies, citing the Dockerfile's final stage and `ENTRYPOINT`.

| Step | Reads | Writes | Validates |
|---|---|---|---|
| `handoff`: the gate with nothing supplied, **exit 1** | accepted intake (`OK`); the supplied result **absent** | `handoff.md`, `handoff.json`, `handoff/latest-handoff.json`, `handoff/handoffs/*.json`, `job.lock`; for the partition gate also a `BLOCKED` attempt (`inputs`, `result`, `status`) and its pointers; launch request | `handoff.json` names the job, the expected schema, the path; hand-off record has identity, composition, inputs, fingerprint, claim class; partition's `result.json` against `worker-result-envelope.schema.json` |
| `supply`: `fixtures/supply_record.py` | the fixture record against its schema, at the pin; the staged manifest's target; the supplied result absent | exactly `supplied/result.json` | against its schema; byte-identical to the record |
| `accept`: the gate again | the supplied result against its schema, at the pin; the upstream acceptance (intake for partition, the partition map for developer/devops discovery, the accepted devops record for SRE topology) | partition: attempt `inputs`, `repository-partition-map.json`, `repository-partition-summary.md`, `result.json`, `status.json`, `supplied/result.json` and refreshed pointers/hand-off; developer/devops/sre: exactly `accepted`, `latest`, attempt `inputs`, `output`, `status` | outputs against their schemas (`repository-partition-map`, `project-discovery`, `operations-topology`, the worker envelope with `execution_status` `OK`) |

Then: Dagster `FAILURE` for `handoff` with nothing accepted, `SUCCESS` for `accept`;
`discovery_gate.validate` accepts; accepted by the launched Dagster run; every source-file citation's
SHA-256 recomputed from the checkout; partition: records' partitions, `docs` deferred; developer/
devops: accepted output = supplied file = fixture record, same revision as the accepted partition
map, every command-plan entry has argv, purpose and authorization; sre: accepted output = supplied
file = fixture record, same revision as the accepted devops record, every service id unique, every
dependency target resolves to a known service id, coverage gaps recorded.

### 6. `partition-discovery` with `--dispatch` (D01: live automatic persona dispatch)

Run with `scripts/system-acceptance-test.sh --dispatch --through <stage>` (a new SAT only; a
`--resume` reads its own SAT's recorded choice, `--dispatch` is ignored). Stages 6 and 7 change
shape (stage 7: see the next subsection); stages 8-9 are unaffected and stay on supplied records
(they do not yet have a dispatch mode -- D03-D04, tracked separately).

Two steps instead of three: `dispatch-mode`, `accept`. There is no `handoff`/`supply` -- with
`dispatch-mode.json` set to `"automatic"` for `02-repository-partition-discovery` before the one
launch, `discovery_gate.run()` never takes the supplied/hand-off path at all
(`discovery_gate.py`'s own internal choice, Phase 5b item 5; `dagster_workflow.py`'s call into
`run()` is unchanged).

| Step | Reads | Writes | Validates |
|---|---|---|---|
| `dispatch-mode`: opt this run into automatic dispatch | the supplied result **absent** | `data/dispatch-mode.json` | `{"02-repository-partition-discovery": "automatic"}` |
| `accept`: the automatic-dispatch gate, a **real `claude` CLI call** | accepted intake (`OK`); `dispatch-mode.json` says automatic; the supplied result still absent | attempt `inputs`, `repository-partition-map.json`, `repository-partition-summary.md`, `result.json`, `status.json`, the persona invocation's own `outputs/persona/*` and `logs/persona/*`, the run's pinned `model-versions.json` and per-alias `*.jsonl` transcripts (`model_version_registry.resolve_run_model_versions` queries every configured alias once per run, not only the one this job uses), refreshed pointers | outputs against their schemas; the worker envelope `execution_status: OK`, `worker_kind: persona` |

Then: Dagster `SUCCESS`; `discovery_gate.validate` accepts; accepted by the launched Dagster run;
`status.json` records `dispatch_mode: "automatic"`; every source-file citation's SHA-256 recomputed
from the live checkout (unchanged check, `citations_fresh`); at least one partition, each with a
known `primary_persona_id` and at least one evidence citation; `coverage.category_checks`
non-empty with a valid `result` on each entry (the routing table is structurally complete). **What
changed from the supplied-result gate above, deliberately (per the original D01 spec): acceptance
no longer byte-compares the result against the fixture's answer key** -- a real model call has no
reason to reproduce a human's exact partition IDs, names or wording. A diff against the fixture
record is still computed and printed (`diff_note` in the stage summary) when the two disagree, but
it is informational only, never a pass/fail gate.

### 7. `dev-project-discovery` with `--dispatch` (D02: live automatic persona dispatch)

Same flag, same two steps (`dispatch-mode`, `accept`), for `02-dev-project-discovery`. This is the
first job in the pipeline where a model, not a human, decides **how the system under test wants to
be built**: languages and tooling, a candidate buildenv image per project, and the ordered,
authorization-labeled (`read-only` / `network-required` / `script-execution-required`)
`safe_command_plan` -- proposed, never executed. The persona reads the target checkout plus the
run's accepted `repository-partition-map.json`, handed over as a second, separately labeled readable
root (`upstream-artifacts`): scope, not citable evidence. If the accepted partition map changes, the
input fingerprint changes and the job re-dispatches instead of reusing.

`discovery_gate.py` keeps this job's existing accepted-record shape (`accepted.json`,
`attempts/<id>/output.json`, `inputs.json`, `status.json`) -- 02-dev-project-discovery was never on
the common worker envelope, and its consumers read exactly that shape; only the source of the value
changed. Extra artifacts the `accept` contract now allows: `attempts/*/project-discovery-summary.md`,
`persona-attempts/*/{outputs,logs}/persona/*` (the persona invocation's own request/record/result
triple, kept for review, never the published attempt), `upstream/*/repository-partition-map.json`
(the content-addressed copy the persona reads), `job.lock`, and the transcript tunable's
`llm-transcripts/d02-devproject/*`.

Then: Dagster `SUCCESS`; `discovery_gate.validate` accepts; accepted by the launched Dagster run;
`accepted.json` and `status.json` record `dispatch_mode: "automatic"`; the persona invocation record
exists; every citation's SHA-256 recomputed from the live checkout; same `source_revision` and
`target` as the accepted partition map; at least one project, each with evidence, at least one
command and a candidate buildenv image; a non-empty command plan in which every entry has argv,
purpose, a valid authorization, evidence, and a `project_id` that resolves. As for stage 6,
byte-equality with the fixture answer key is not a gate; a differing command plan is reported as
`diff_note`, informational only.

## Gaps the contracts have exposed

| Gap | Where | Status |
|---|---|---|
| No schema for the run manifest, run status, workflow and branch outputs, accepted pointers, or the job hand-off record | `schemas/` | Structural contracts in the SAT meanwhile |
| The developer-discovery gate records no output hashes in its accepted record | `discovery_gate._legacy_run` | SAT compares output, supplied file and record |
| SRE discovery required by intake (Dockerfile) but has no gate or Dagster job | job graph, `dagster_workflow.py` | Done 2026-09-24 (stage 8 devops, stage 9 sre topology both gated and passing live) |
| No LLM or agent produces the discovery records; they are supplied fixture records | persona dispatch not wired into the gates | Stage 6 (`02-repository-partition-discovery`, D01): closed, `--dispatch`. Stage 7 (`02-dev-project-discovery`, D02): closed, `--dispatch`, live PASS 2026-09-25 (first attempt; see flow-bringup.md log for the scope finding). Stages 8-9 (D03-D04) and the build part (stages 10-12, build-resolution.md): still open |
| The system cannot discover how to build an unknown target (CMake-only collector, no model call, no build image) | `build_discovery.py`, Phase 4 | Designed: build-resolution.md, ADR-0012 |
| Dagster-launched steps may write under `data/orchestration/dagster/*`, which a sandbox run without Dagster cannot observe | contracts | Confirmed only on the host run |
