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
code location does not leave root-owned files in the bind-mounted `runs/` and `data/` trees.
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

With the current registry, the cross-job dependencies are:

```text
review_intake -> target_catalog -> ci_configuration_analysis -> target_analysis_plan
target_analysis_plan -> tree_sitter_ast
target_analysis_plan -> project_build -> language_build -> artifact_indexing -> artifact_security_analysis
language_build -> cpp_compiled_analysis -> post_build_security_assessment
target_analysis_plan -> evidence_collection
language_build + artifact_indexing + artifact_security_analysis + cpp_compiled_analysis
  + post_build_security_assessment + evidence_collection + tree_sitter_ast -> codeql_analysis
post_build_security_assessment + evidence_collection + artifact_security_analysis
  + tree_sitter_ast + codeql_analysis -> owasp_control_assessment
codeql_analysis + owasp_control_assessment -> security_tagging
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
