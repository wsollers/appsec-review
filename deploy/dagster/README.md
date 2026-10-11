# Dagster deployment

This deployment turns the application runtime's typed execution plan into a real Dagster DAG. The
code location discovers semantic jobs from `JobRegistry`, reads schedules and executor/concurrency
settings from `appsec-review.toml`, and maps each application unit to a Dagster node. Dagster owns
dependencies, multiprocess scheduling, node selection, and visibility. Application lifecycle
methods still allocate application attempts, validate unit receipts and artifacts, and publish
accepted handoffs and manifests.

The Compose project contains PostgreSQL, a gRPC code location, the webserver, and the daemon. Only
the web console is published, on `127.0.0.1:3000`. The repository's `runs/` and `data/` directories
are mounted into the code-location container, and `targets/` is mounted read-only for review jobs;
PostgreSQL and Dagster compute logs use named volumes.
The code location alone receives the Docker socket and client needed to execute the pinned,
network-disabled cve-bin-tool database builder. Do not expose the code location to untrusted code.

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

Run these commands from the repository root. Bootstrap creates an ignored `.env` once and preserves
its secret on later calls. On native Linux it also records the invoking operator's uid/gid so the
code location does not leave root-owned files in the bind-mounted `runs/` and `data/` trees. It
records the Docker socket group id and adds that supplemental group to the code location so tool
containers remain usable.
When central configuration selects `claude-cli`, bootstrap also records the resolved local CLI,
configuration-directory, and state-file paths. Compose mounts those three paths read-only only into
the code-location container and sets an isolated container home; subscription credentials are not
copied into the image, repository, or `.env`.
For a bounded acceptance target already beneath the read-only `targets/` mount, set
`APPSEC_REVIEW_TARGET` to its container path for the lifecycle and launch commands; otherwise the
deployment defaults to `/opt/app/targets/appsec-multi-vuln`.

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

Launch the deterministic review graph through the same live instance. After target planning, static
evidence collection runs independently from project-image resolution, buildability probes, generic
language-build execution (including its WebAssembly output-family lane), C++ compiled analysis, and post-build security assessment. The branches join before OWASP assessment, so a
slow or failed compiled tool cannot erase completed static evidence. Build-command provenance,
binary inspection, deterministic checks, and immutable `build_security` shards remain covered by
the retained `wave1_review` job. Its target mount is read-only, while application receipts and
handoffs remain in the ignored `runs/` mount:

```powershell
$dagsterRunId = [guid]::NewGuid().ToString()
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml exec -T webserver dagster job launch -w /opt/dagster/home/workspace.yaml -l appsec_review -j wave1_review --run-id $dagsterRunId
python deploy/dagster/bin/verify.py --run-id $dagsterRunId --evidence deploy/dagster/verification/wave1-live-acceptance.json
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

With the current registry, the cross-job dependencies are:

```text
review_intake -> target_catalog -> ci_configuration_analysis -> target_analysis_plan
target_catalog -> source_history_analysis -> target_analysis_plan
target_analysis_plan -> tree_sitter_ast -> change_context_analysis
target_analysis_plan -> project_build -> language_build -> artifact_indexing -> artifact_security_analysis
language_build -> cpp_compiled_analysis -> post_build_security_assessment
target_analysis_plan -> evidence_collection
language_build + artifact_indexing + artifact_security_analysis + cpp_compiled_analysis
  + post_build_security_assessment + evidence_collection + tree_sitter_ast
  + change_context_analysis -> codeql_analysis
post_build_security_assessment + evidence_collection + artifact_security_analysis
  + tree_sitter_ast + codeql_analysis -> owasp_control_assessment
codeql_analysis + owasp_control_assessment -> review_prioritization
codeql_analysis + owasp_control_assessment + review_prioritization -> security_tagging
security_tagging -> review_data_indexing -> review_package_assembly
```

This is the Dagster-only composed topology. The direct CLI has a smaller linear graph documented in
[`docs/operations/wave1-review.md`](../../docs/operations/wave1-review.md).

The configured schedule and a manual launch enter the same generated semantic DAG. Schedule cron,
time zone, and enabled state come only from
`jobs.job_third_party_data_sync.schedule` in `appsec-review.toml`; the current declaration is
`0 0 * * *` in `UTC`, enabled.

Dagster and the application intentionally allocate different run ids. Dagster uses its UUID for
control-plane history. `JobRunner` allocates the date/serial application id used by immutable
receipts. On success the Dagster run receives `appsec/application_run_id` and
`appsec/application_attempt_id` tags plus structured output metadata for all unit statuses,
snapshots, counts, gaps, and receipt paths. The application `status.json` contains the reverse
`orchestration.system=dagster` and `orchestration.run_id=<Dagster UUID>` link. The verification
command validates both directions rather than inferring success from one system alone.

`wave1_review` shows intake and catalog units followed by the planned analysis jobs. Static evidence
collection and project-build processing both start from the accepted target-analysis plan. Generic
language-build execution waits for accepted project-build probes while its source and WebAssembly
lanes remain independent; C++ analysis waits for its native receipts; and post-build security waits
for the accepted C++ analysis handoff. Cross-language CodeQL then consumes the accepted catalog,
language-build, artifact, C++, post-build, static-evidence, and tree-sitter publications so its
manifest is the final composed retrieval view before OWASP. Each evidence
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
verification receipt). The terminal node `review_package_assembly__publication__publish_packages`
records `package_directory`, `accepted_manifest_sha256`, counts, and `coverage_gap_count` in its
application result under `runs/<application-run-id>/data/jobs/job_review_package_assembly/attempts/`.
The directory is `runs/<application-run-id>/data/review-packages/<content-sha256>/`. Open its
`manifest.json` for package IDs, hashes, counts, and run-wide gaps; open a listed package JSON for
safe build command facts, function and build-action binding, source-local tags, Clang references,
evidence provenance, and lead-specific gaps. These are review leads, not adjudicated findings.

To validate a package directory against the current accepted manifest before use, run from the
repository root in the same environment as the run:

```powershell
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

```powershell
python deploy/dagster/bin/lifecycle.py stop
```

For diagnostics:

```powershell
python deploy/dagster/bin/lifecycle.py logs
python deploy/dagster/bin/run_report.py --stale-seconds 3600
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml config
```

To close specifically enumerated non-terminal records during an authorized recovery, use the
supported Dagster GraphQL termination API and retain the default host-level recovery receipt under
`runs/metadata/dagster-recovery/`:

```powershell
python deploy/dagster/bin/recover_runs.py --reason "authorized deployment recovery" --run-id <enumerated-id>
```

Repeat `--run-id` for each exact ID from the immediately preceding report. The command refuses
missing or already-terminal targets so it cannot catch a run launched after enumeration.
Use `--policy MARK_AS_CANCELED_IMMEDIATELY` only for a stale/orphaned record whose original worker
can no longer acknowledge safe termination; the receipt records that policy.

Do not use `down --volumes` during normal operation; that deletes the Dagster and PostgreSQL state.

## Tests

Run the full repository suite on the host. It skips only the optional Dagster tests when that
dependency is absent. Then run the deployment-specific suite in the pinned image:

```powershell
python -m pytest -q
docker build --file deploy/dagster/Dockerfile --target test --tag appsec-review-dagster-test .
docker run --rm appsec-review-dagster-test
```

The deployment tests cover TOML schedule generation, registry discovery, repository-wide node-name
uniqueness, manual/scheduled graph convergence, structured metadata mapping, multiprocess branch
overlap and barrier ordering, and application-failure propagation. Live acceptance
evidence and its scope are described in `deploy/dagster/verification/README.md`.
