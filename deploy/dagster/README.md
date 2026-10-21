# Dagster deployment

This deployment turns the application runtime's typed execution plan into a real Dagster DAG. The
code location discovers semantic jobs from `JobRegistry`, reads schedules and executor/concurrency
settings from `appsec-review.toml`, and maps each application unit to a Dagster node. Dagster owns
dependencies, multiprocess scheduling, node selection, and visibility. Application lifecycle
methods still allocate application attempts, validate unit receipts and artifacts, and publish
accepted handoffs and manifests.

The Compose project contains PostgreSQL, a gRPC code location, the webserver, and the daemon. Only
the web console is published, on `127.0.0.1:3000`. The repository's `runs/` and `data/` directories
are mounted into the Dagster containers, and `targets/` and `rules/` (the checked-in rule packs) are
mounted read-only; PostgreSQL and Dagster compute logs use named volumes.
The code location alone receives the host Docker socket. Every containerized step uses it: scanner
and tool images, project-image probes and builds, language builds, CodeQL, and the network-disabled
cve-bin-tool database builder. Socket access is equivalent to host root, so do not expose the code
location to untrusted code.

## Windows host WSL memory limit

On the current Windows Docker Desktop host, the global WSL 2 configuration is stored at
`C:\Users\wsoll\.wslconfig` (`%UserProfile%\.wslconfig`). It limits the shared WSL 2 virtual
machine to 16 GB of memory, provides 8 GB of swap, and enables immediate cache reclamation:

```ini
[wsl2]
memory=16GB
swap=8GB

[experimental]
autoMemoryReclaim=dropCache
```

The 16 GB limit is shared by Docker Desktop and every running WSL 2 distribution; it is not a
per-container or per-distribution allowance. After changing the file, save active WSL work, run
`wsl --shutdown`, and restart Docker Desktop. The shutdown stops all WSL distributions and running
containers.

## Build, start, verify, and stop

Run these commands from a native checkout on each host: `~/projects/appsec-review` in WSL or a
Windows drive checkout in PowerShell. Do not run the WSL deployment from `/mnt/c` or `/mnt/f`.
Each checkout has its own ignored `.env`, `runs/`, `data/`, target files, Claude login, Compose
project, image, PostgreSQL volume, and Dagster storage volume. The stacks share Docker Desktop's
engine, so stop one before starting the other. The lifecycle and live smoke commands enforce this.
Bootstrap preserves the existing database secret while refreshing host-specific paths and removing
Linux-only settings from the Windows environment. On Linux and WSL it records the operator uid/gid so the
code location does not leave root-owned files in the bind-mounted `runs/` and `data/` trees. It
records the Docker socket group id and adds that supplemental group to the code location so tool
containers remain usable.
Bootstrap also refreshes the resolved local Claude CLI binary, `~/.claude` directory, and
`~/.claude.json` state file whenever all three exist, regardless of the configured provider.
On Linux and WSL, `compose.claude.yaml` requires `APPSEC_CLAUDE_BINARY`,
`APPSEC_CLAUDE_CONFIG_DIR`, and `APPSEC_CLAUDE_STATE_FILE`; install and sign in to `claude` before
bootstrap or set them by hand. It mounts those paths read-only into the code location. On native
Windows, `compose.windows.yaml` installs the pinned Linux Claude CLI in the code-location image
and persists its login in the `claude-home` Docker volume. After starting, sign in with:

```powershell
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml -f deploy/dagster/compose.windows.yaml exec code-location claude auth login
```

Choose the Claude subscription login. The Windows host's Claude login is separate from this
container login; neither is copied into the image or repository.
For a bounded acceptance target already beneath the read-only `targets/` mount, set
`APPSEC_REVIEW_TARGET` to its container path for the lifecycle and launch commands; otherwise the
deployment defaults to `/opt/app/targets/appsec-multi-vuln`.

```bash
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

```bash
python deploy/dagster/bin/lifecycle.py build
python deploy/dagster/bin/lifecycle.py reload
python deploy/dagster/bin/verify.py
```

Use the code-location CLI as a non-executing manual smoke check. It imports the same definitions
served to the webserver and prints the discovered semantic jobs:

```bash
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml exec code-location dagster job list --module-name appsec_review.orchestration.dagster.definitions
```

Launch `third_party_data_sync` manually from the console only when a real external-data refresh is
intended; it performs network, filesystem, and isolated Docker work. The following command launches
through the live Dagster instance and retains the Dagster id for terminal verification:

```bash
dagsterRunId=$(python3 -c 'import uuid; print(uuid.uuid4())')
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml exec -T webserver dagster job launch -w /opt/dagster/home/workspace.yaml -l appsec_review -j third_party_data_sync --run-id $dagsterRunId
# Wait for this run to finish in the Dagster console before verifying it.
python deploy/dagster/bin/verify.py --run-id $dagsterRunId --evidence "runs/metadata/dagster-verification/$dagsterRunId.json"
```

Launch the deterministic review graph through the same live instance. After target planning, static
evidence collection runs independently from project-image resolution, buildability probes, generic
language-build execution (including its WebAssembly output-family lane), C++ compiled analysis, and post-build security assessment. The branches join before OWASP assessment, so a
slow or failed compiled tool cannot erase completed static evidence. Build-command provenance,
binary inspection, deterministic checks, and immutable `build_security` shards remain covered by
the retained `wave1_review` job. Its target mount is read-only, while application receipts and
handoffs remain in the ignored `runs/` mount:

```bash
dagsterRunId=$(python3 -c 'import uuid; print(uuid.uuid4())')
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml exec -T webserver dagster job launch -w /opt/dagster/home/workspace.yaml -l appsec_review -j wave1_review --run-id $dagsterRunId
python deploy/dagster/bin/review_run.py watch --run-id $dagsterRunId
python deploy/dagster/bin/verify.py --run-id $dagsterRunId --evidence "runs/metadata/dagster-verification/$dagsterRunId.json"
```

For an operator launch from WSL, `review_run.py` generates and prints the Dagster UUID, launches
`wave1_review`, and queries its live status. Keep the UUID for `status` or `watch`:

```bash
python3 deploy/dagster/bin/review_run.py submit
python3 deploy/dagster/bin/review_run.py watch --run-id DAGSTER_UUID
```

Dagster's running failure and cancellation sensors launch `wave1_error_state` when the whole
`wave1_review` run reaches either terminal state. That job queries up to five recent failure events
through the Dagster instance API and writes
`runs/metadata/dagster-error-state/<dagster-uuid>.log`. Its first line gives the Dagster and
application run ids and terminal status; the following lines name the failed steps and messages.
Use `python3 deploy/dagster/bin/review_run.py status --run-id DAGSTER_UUID` to query the live
Dagster status and show the last lines of that file. The file can appear shortly after Dagster
marks the source run terminal because the daemon launches the error-state job asynchronously.

For a `wave1_review` run, repeat `--required-family <family>` (for example `native` or `dotnet`)
to require zero-gap `SUCCEEDED` language-build receipts for that family and resolve their
retained capture artifacts; the verifier fails if any such receipt is missing, failed, or gapped.

With the current registry, the cross-job dependencies are:

```text
model_connectivity -> image_pin_verification -> review_intake -> target_catalog -> ci_configuration_analysis
  -> target_analysis_plan
target_catalog -> source_history_analysis -> target_analysis_plan
target_analysis_plan -> tree_sitter_ast -> change_context_analysis
target_analysis_plan -> project_build -> language_build -> artifact_indexing
artifact_indexing -> test_coverage
artifact_indexing -> profile_data
artifact_indexing -> artifact_security_analysis
language_build -> cpp_compiled_analysis -> clang_static_analysis
cpp_compiled_analysis -> post_build_security_assessment
cpp_compiled_analysis -> cpp_symbol_index
cpp_compiled_analysis -> cpg_analysis  # only when jobs.job_cpg_analysis.settings.enabled = true
target_analysis_plan -> evidence_collection
target_catalog + language_build + artifact_indexing + evidence_collection + cpp_compiled_analysis
  -> dependency_intelligence
language_build + artifact_indexing + artifact_security_analysis + cpp_compiled_analysis
  + clang_static_analysis + cpp_symbol_index + cpg_analysis
  + post_build_security_assessment + evidence_collection
  + tree_sitter_ast + change_context_analysis -> codeql_analysis
post_build_security_assessment + evidence_collection + artifact_security_analysis
  + tree_sitter_ast + codeql_analysis -> owasp_control_assessment
codeql_analysis + owasp_control_assessment -> review_prioritization
codeql_analysis + cpp_compiled_analysis + clang_static_analysis + cpp_symbol_index
  + tree_sitter_ast + review_prioritization -> code_graph_index
codeql_analysis + owasp_control_assessment + review_prioritization + code_graph_index
  -> security_tagging
test_coverage + profile_data + dependency_intelligence + security_tagging
  -> review_data_indexing -> review_package_assembly -> document_issue_analysis
  -> inference_security_review -> final_publication_gate -> final_report_publication
```

`wave1_review` contains every registered job except the standalone
`third_party_data_sync` job, and `final_report_publication` is its single terminal job.

This is the Dagster-only composed topology. The direct CLI has a smaller linear graph documented in
[`docs/operations/wave1-review.md`](../../docs/operations/wave1-review.md).

The code location also defines:

- one Dagster job per registered semantic job, named from that job's `name` in
  `appsec-review.toml` (for example `target_catalog` or `codeql_analysis`), with its nodes
  namespaced `standalone__`; a standalone launch joins the application run named by its
  `appsec/application_run_id` tag, and its input validators require that run's accepted upstream
  handoffs;
- `ci_configuration_review`: `model_connectivity -> image_pin_verification -> review_intake -> target_catalog ->
  ci_configuration_analysis`;
- `project_build_review`: `model_connectivity -> image_pin_verification -> review_intake -> target_catalog ->
  target_analysis_plan -> project_build -> language_build -> artifact_indexing -> artifact_security_analysis`.

The configured schedule and a manual launch enter the same generated semantic DAG. Schedule cron,
time zone, and enabled state come only from
`jobs.job_third_party_data_sync.schedule` in `appsec-review.toml`; the current declaration is
`0 0 * * *` in `UTC`, enabled.

Dagster and the application intentionally allocate different run ids. Dagster uses its UUID for
control-plane history. `JobRunner` allocates the date/serial application id used by immutable
receipts. When each job attempt is claimed, the Dagster run receives `appsec/application_run_id`
and `appsec/trigger` tags; when each job finalizes, it receives `appsec/<job_id>/attempt` and
`appsec/<job_id>/status` tags. The application attempt id also appears in node output metadata
(`application_attempt_id`), alongside structured metadata for unit statuses, snapshots, counts,
gaps, and receipt paths. The application `status.json` contains the reverse
`orchestration.system=dagster` and `orchestration.run_id=<Dagster UUID>` link. The verification
command validates both directions rather than inferring success from one system alone.

`wave1_review` shows intake and catalog units followed by the configured analysis jobs. Static evidence
collection and project-build processing both start from the accepted target-analysis plan. Generic
language-build execution waits for accepted project-build probes while its source and WebAssembly
lanes remain independent. Coverage and profile ingestion branch from accepted artifact indexing;
C++ analysis waits for native receipts, Clang static analysis waits for accepted compiled scopes,
and dependency intelligence joins accepted catalog, build, artifact, and evidence handoffs while
also waiting for the compiled C/C++ branch when present. Cross-language CodeQL consumes its
declared catalog, language-build, artifact, C++,
post-build, static-evidence, tree-sitter, and change-context publications. The code-graph job then
normalizes accepted CodeQL exports and cross-check inputs. OWASP, review prioritization, and
security tagging publish their own branches; `review_data_indexing` waits for every enabled leaf
and audits the composed accepted view. Each evidence
branch has scan, normalize, and producer-owned index nodes. Its cheap manifest barrier waits for a
truthful terminal disposition from every static branch, verifies every immutable shard, and then
publication moves the accepted pointer. OWASP assessment waits for both the static-evidence and
post-build branches. The configured multiprocess executor allows unrelated branches to overlap;
Grype alone waits for Syft.

A producer failure is not a clean scan and not a framework failure. It becomes a durable `FAILED`,
`BLOCKED`, `PARTIAL`, or `NOT_APPLICABLE` disposition, with bounded receipts and gaps, and can yield
`COMPLETED_WITH_GAPS`. Hash, path, configuration, receipt, handoff, manifest, and index-integrity
failures still fail the Dagster run.

### Inspect published review packages

After `wave1_review` succeeds, use the **application run id** in its Dagster tags (or the
verification receipt). The package node `review_package_assembly__publication__publish_packages`
records `package_directory`, `accepted_manifest_sha256`, counts, and `coverage_gap_count` in its
application result under `runs/<application-run-id>/data/jobs/job_review_package_assembly/attempts/`.
The directory is `runs/<application-run-id>/data/review-packages/<content-sha256>/`. Open its
`manifest.json` for package IDs, hashes, counts, and run-wide gaps; open a listed package JSON for
safe build command facts, function and build-action binding, source-local tags, Clang references,
evidence provenance, and lead-specific gaps. These are review leads, not adjudicated findings.
The terminal `document_issue_analysis__analysis__map_and_adjudicate` node records a private
candidate ledger under `data/document-issues/<content-sha256>/ledger.json`. A source mapping is
a navigation result; its empty finding and scoring lists do not mean the target is clean.

To validate a package directory against the current accepted manifest before use, run from the
repository root in the same environment as the run:

```bash
python -c "from pathlib import Path; from appsec_review.retrieval import RetrievalCore; from appsec_review.review_packages import verify_review_packages; run='APPLICATION_RUN_ID'; core=RetrievalCore(Path('runs'),run); print(verify_review_packages(core,Path('runs')/run/'data'/'review-packages'/'CONTENT_SHA256')['counts'])"
```

Use `appsec-review plan-resume --run-id <application-run-id> --target targets/appsec-multi-vuln`
before a direct resume. For Dagster, launch `wave1_review` with
`--tags '{"appsec/application_run_id":"<application-run-id>"}'` as described above. The package
job reruns when its configuration, implementation, accepted indexing handoff, or source snapshot
changes. Old content-addressed directories remain immutable. A new accepted manifest invalidates
their current-use validation; inspect the newest accepted package attempt. An absent package
directory or a failed package node is incomplete coverage, while the manifest's `coverage_gaps`
enumerate producer and lead-context limits in an accepted package set.

Stop containers without deleting persistent state:

```bash
python deploy/dagster/bin/lifecycle.py stop
```

For diagnostics:

```bash
python deploy/dagster/bin/lifecycle.py logs
python deploy/dagster/bin/run_report.py --stale-seconds 3600
python deploy/dagster/bin/lifecycle.py config
```

## Stepwise acceptance of wave1_review

`stepwise.py` runs every `wave1_review` job as its own single-job Dagster job, one at a time,
against one application run. Each launch goes through the webserver into the packaged code location,
so a job runs with the same uid/gid, mounts and Docker socket as in `wave1_review`. The job order
and each job's upstream handoffs come from the packaged code location
(`python -m appsec_review.orchestration.topology`), so the code-location image must contain that
module. The launcher names the accepted upstream handoffs in the `appsec/upstream_handoffs` run tag.
The job's begin op checks each one against the run's `latest.json` pointer, so a standalone job binds
the same handoffs it would receive inside the graph.

```bash
python3 deploy/dagster/bin/stepwise.py init --target /opt/app/targets/appsec-multi-vuln
python3 deploy/dagster/bin/stepwise.py accept --job model_connectivity --tag TAG
python3 deploy/dagster/bin/stepwise.py next           # launch, wait, check the next job
python3 deploy/dagster/bin/stepwise.py check --job JOB  # re-check without relaunching
python3 deploy/dagster/bin/stepwise.py accept --job JOB --tag TAG
# ...repeat next/accept for every job, then run a full wave1_review (review_run.py submit)...
python3 deploy/dagster/bin/stepwise.py compare --app-run FULL_RUN_ID --tag TAG
```

- `init` launches the first job without a run id, so the job allocates the application run the
  same way Dagster does. `--target` must equal the code location's `APPSEC_REVIEW_TARGET`. The walk
  state is stored at `runs/metadata/stepwise/<app-run>/state.json`.
- `check` prints the Dagster status with each failed step's root cause, the job's terminal status,
  its deduplicated gaps with counts, and any PARTIAL or FAILED units. It then audits everything the
  job wrote under `runs/<app-run>/`, `runs/metadata/` and `data/`. The audit flags owners that differ
  from `APPSEC_UID:APPSEC_GID`, root-owned entries, entries the operator cannot read, world-writable
  entries, dangling or escaping symlinks, scratch or temporary leftovers, an attempt still marked
  RUNNING after Dagster finished, and missing or mismatched receipts, handoffs and artifacts. The
  check fails on a Dagster failure or on any audit finding. Gaps are reported but never fail it. The
  full report is written under `runs/metadata/stepwise/<app-run>/checks/`.
- `accept` re-runs the check and refuses if it fails. It also refuses unless the target checkout's
  `HEAD` is the commit `TAG` names. It writes the normalized output to
  `test/acceptance/<TAG>/<job>.json`, with a `<job>.provenance.json` sidecar that records the corpus
  tag, target commit, repository commit, application run and Dagster run. It then records a seed of
  the run (below). Jobs are accepted strictly in graph order.
- `compare` normalizes each job of a full run and diffs it against the accepted files. Each
  difference is classed as `job-status`, `gap-added`, `gap-removed`, `finding-added`,
  `finding-removed`, `coverage` or `volatile`. The command exits non-zero on anything other than
  `volatile`.

**Seeds.** Each `accept` freezes the run as it stands after that job: the whole of `runs/<app-run>/`,
plus the shared inputs a job can read, which are `runs/metadata/` (without the stepwise, error-state
and recovery records) and `data/`. The per-entry manifest is committed as
`test/acceptance/<TAG>/seeds/after-<job>.manifest.json`. It lists each entry's path, type, sha256,
size, mode, and owner role (`deployment` means `APPSEC_UID:APPSEC_GID`). Each manifest is a delta
against the previous seed and is pinned to that seed's full digest. The bytes are kept out of git in
a content-addressed store, `data/acceptance-seeds/blobs/` (ignored). Successive seeds share every
unchanged file. Shared files over 1 MiB are recorded by digest only.

```bash
python3 deploy/dagster/bin/stepwise.py seed --tag TAG --after JOB [--replace]
python3 deploy/dagster/bin/stepwise.py next           # runs the job after JOB on the seeded run
python3 deploy/dagster/bin/stepwise.py verify-job --tag TAG --job JOB [--replace]
```

`seed` restores the run under its original run id, byte for byte, then checks every hash, mode
and owner. The id cannot be rewritten: the retrieval manifests that handoffs hash carry `run_id`, so
a new id would change every downstream handoff identity. A different `runtime.runs_dir` also changes
the resolved configuration the run is bound to. As a result, only one copy of a given seed run can be
live at a time. `--replace` moves the existing tree and walk state to
`runs/metadata/stepwise/displaced/`. If shared inputs have drifted from the seed, the restore fails
unless you pass `--restore-shared` (write the stored bytes back) or `--allow-shared-drift`.
`verify-job` seeds the job's graph-order predecessor, which contains every upstream the job reads.
It then runs the job, checks it, and diffs its normalized output against the accepted file. This is
the known-good regression check for a single job.

**Parity.** `parity` proves that the local launcher (`appsec-review run`) and Dagster produce the
same output for one job from the same starting state
([`docs/processes/local-dagster-parity.md`](../../docs/processes/local-dagster-parity.md)).

```bash
# deploy/dagster/.env: APPSEC_REVIEW_TARGET=/opt/app/targets/cpp-multivuln and
# APPSEC_REVIEW_MODEL_RECORDING=record, then recreate the stack.
python3 deploy/dagster/bin/stepwise.py parity --tag cpp-multivuln-v1 --job model_connectivity \
  --target /opt/app/targets/cpp-multivuln
python3 deploy/dagster/bin/stepwise.py accept --job model_connectivity --tag cpp-multivuln-v1
python3 deploy/dagster/bin/stepwise.py parity --tag cpp-multivuln-v1 --job JOB [--replace]
```

For each job, `parity` does the following, one step at a time:

1. Restores the seed of the job's predecessor. The first job instead starts a new run, and its
   local side gets an empty run bound to the same configuration.
2. Runs the job through Dagster, which records every model response.
3. Moves the Dagster run tree, its walk state and every shared path it added aside. Shared files
   it changed are restored from the seed store.
4. Restores the same seed again and runs `appsec-review run JOB --upstream-from-run` with model
   replay.
5. Audits and normalizes the local output, then puts the Dagster side back for `accept`.

The verdict is one of these:

- `PARITY OK` (exit 0): both sides succeeded and no difference is outside the masked volatile
  fields.
- `DIFFERENT` (exit 3): the outputs differ.
- `INVALID COMPARISON` (exit 3): the two handoffs disagree on implementation, configuration,
  validation, source fingerprint, input or upstream identity, such as when the code-location
  image was built from another commit.
- `RUN FAILED` (exit 1): either side failed, or the local write audit found something.

The report, both normalized outputs, the local log and the recordings are kept under
`runs/metadata/stepwise/parity/<app-run>/<job>/<time>/`, beside both parked trees.

## Serial smoke tests

Run each platform on that actual host: `windows` from native PowerShell, `wsl` from a WSL shell,
and `linux` from a native Linux shell. A Windows machine running WSL can exercise two cases; it
cannot claim native Linux coverage. Run one case at a time against the shared Compose project.

```text
python deploy/dagster/bin/smoke.py --platform windows --mode config
python deploy/dagster/bin/smoke.py --platform windows --mode live
python deploy/dagster/bin/smoke.py --platform windows --mode feeds
```

Replace `windows` with `wsl` or `linux` on the corresponding host. `config` validates resolved
Compose services, mounts, and Claude CLI placement without changing the deployment. `live` builds
and starts the stack, checks CLI version and subscription authentication, and verifies the connected
Dagster workspace. `feeds` does the same, then launches **one** `third_party_data_sync` Dagster run,
waits for it to finish, and verifies all six published branches (NVD, OSV, MITRE, KEV, EPSS, and
cve-bin-tool) against the run receipts and current pointers. It writes a verifier report under
`runs/metadata/dagster-smoke/<platform>/<Dagster UUID>.json`.

Live modes hold a shared lock under `runs/metadata/` and refuse to start while Dagster has any
non-terminal run. Do not schedule the three platform cases or feed cases concurrently. If a smoke
process dies, inspect its Dagster run and the lock owner before removing the stale lock. Live feed
mode makes real network requests and may take hours on a first NVD bootstrap.

To close specifically enumerated non-terminal records during an authorized recovery, use the
supported Dagster GraphQL termination API and retain the default host-level recovery receipt under
`runs/metadata/dagster-recovery/`:

```bash
python deploy/dagster/bin/recover_runs.py --reason "authorized deployment recovery" --run-id <enumerated-id>
```

Repeat `--run-id` for each exact ID from the immediately preceding report. The command refuses
missing or already-terminal targets so it cannot catch a run launched after enumeration.
Use `--policy MARK_AS_CANCELED_IMMEDIATELY` only for a stale/orphaned record whose original worker
can no longer acknowledge safe termination; the receipt records that policy.

Do not use `down --volumes` during normal operation; that deletes the Dagster and PostgreSQL state.

## Executor and pools

`[orchestration.dagster]` in `appsec-review.toml` sets `executor` (only `multiprocess` is
accepted) and `max_concurrent` (1 to 64, default 8) for every generated job.
`[orchestration.dagster.pools]` sets a per-pool limit (1 to 64), applied as a tag concurrency
limit on `appsec/pool`. The adapter assigns each node a pool from its unit id:

| Pool | Nodes |
| --- | --- |
| `lifecycle` | Per-job begin and finalize nodes, and `__`-prefixed units. |
| `owasp_validator` | `validation.*` units. |
| `owasp_verification` | `verification.*` and `join.*` units. |
| `cpp_build` | `prepare`, `configure`, `compile`, `catalog`, `image`, `probe`, and `execute` steps. |
| `cpp_analysis` | `compiled`, `ast`, `ir`, `codeql`, `joern`, `binary`, `provenance`, `inspection`, `deterministic`, and `inference` steps. |
| `ci_linter` | `*_scan` tasks under `ci_analysis`. |
| `scanner` | Other `*_scan` tasks. |
| `index` | `*_index` tasks. |
| `application` | Everything else. |

Two jobs route by job before these step-name heuristics (`_JOB_STEP_POOLS` and
`_JOB_DEFAULT_POOLS` in `orchestration/dagster/adapter.py`): every non-lifecycle unit of
`job_code_graph_index` runs in `index`, and `job_inference_security_review` runs `lead_review`
and `hunt_review` in `inference_teams` (limit 2), `scoring` in `inference_score` (limit 4),
`publication` in `lifecycle` and everything else in `application`. `job_final_publication_gate` and
`job_final_report_publication` have no routing of their own and use the default `application` pool.

The checked-in configuration limits every pool except `application`, which has no configured
limit and is bounded only by `max_concurrent`.

## Environment variables

`deploy/dagster/.env` (from bootstrap; see `.env.example`) supplies Compose interpolation:
`DAGSTER_POSTGRES_PASSWORD`, `APPSEC_UID`/`APPSEC_GID`, `APPSEC_REVIEW_TARGET`, the three
`APPSEC_CLAUDE_*` bind paths for Linux/WSL, and optionally `ANTHROPIC_API_KEY`. Compose passes
`ANTHROPIC_API_KEY` (empty by default) only to the code location; it is used only by models
configured with `provider = "anthropic-api"`, and the `claude-cli` transport removes it from the
CLI's environment. `APPSEC_REVIEW_CONFIG` is fixed to `/opt/app/appsec-review.toml` by
`compose.yaml` and the image; the adapter loads that file to build the definitions. On Windows,
the subscription CLI login persists in a named Docker volume and must be completed once after the
first start.

## Tests

Run the full repository suite on the host. It skips only the optional Dagster tests when that
dependency is absent. Then run the deployment-specific suite in the pinned image:

```bash
python -m pytest -q
docker build --file deploy/dagster/Dockerfile --target test --tag appsec-review-dagster-test .
docker run --rm appsec-review-dagster-test
```

The deployment tests cover TOML schedule generation, registry discovery, repository-wide node-name
uniqueness, manual/scheduled graph convergence, structured metadata mapping, multiprocess branch
overlap and barrier ordering, and application-failure propagation. Live acceptance
evidence and its scope are described in `deploy/dagster/verification/README.md`.
