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
model_connectivity -> review_intake -> target_catalog -> ci_configuration_analysis -> target_analysis_plan
target_catalog -> source_history_analysis -> target_analysis_plan
target_analysis_plan -> tree_sitter_ast -> change_context_analysis
target_analysis_plan -> project_build -> language_build -> artifact_indexing -> artifact_security_analysis
language_build -> cpp_compiled_analysis -> post_build_security_assessment
cpp_compiled_analysis -> cpp_symbol_index
cpp_compiled_analysis -> cpg_analysis  # only when jobs.job_cpg_analysis.settings.enabled = true
target_analysis_plan -> evidence_collection
language_build + artifact_indexing + artifact_security_analysis + cpp_compiled_analysis
  + cpp_symbol_index + cpg_analysis + post_build_security_assessment + evidence_collection
  + tree_sitter_ast + change_context_analysis -> codeql_analysis
post_build_security_assessment + evidence_collection + artifact_security_analysis
  + tree_sitter_ast + codeql_analysis -> owasp_control_assessment
codeql_analysis + owasp_control_assessment -> review_prioritization
codeql_analysis + owasp_control_assessment + review_prioritization -> security_tagging
security_tagging -> review_data_indexing -> review_package_assembly -> document_issue_analysis
```

`wave1_review` contains every registered job except the standalone
`third_party_data_sync` and `inference_security_review` jobs, and
`document_issue_analysis` is its single terminal job.

This is the Dagster-only composed topology. The direct CLI has a smaller linear graph documented in
[`docs/operations/wave1-review.md`](../../docs/operations/wave1-review.md).

The code location also defines:

- one Dagster job per registered semantic job, named from that job's `name` in
  `appsec-review.toml` (for example `target_catalog` or `codeql_analysis`), with its nodes
  namespaced `standalone__`; a standalone launch joins the application run named by its
  `appsec/application_run_id` tag, and its input validators require that run's accepted upstream
  handoffs;
- `ci_configuration_review`: `model_connectivity -> review_intake -> target_catalog -> ci_configuration_analysis`;
- `project_build_review`: `model_connectivity -> review_intake -> target_catalog -> target_analysis_plan ->
  project_build -> language_build -> artifact_indexing -> artifact_security_analysis`.

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

`wave1_review` shows intake and catalog units followed by the planned analysis jobs. Static evidence
collection and project-build processing both start from the accepted target-analysis plan. Generic
language-build execution waits for accepted project-build probes while its source and WebAssembly
lanes remain independent; C++ analysis waits for its native receipts; and post-build security waits
for the accepted C++ analysis handoff. Cross-language CodeQL then consumes the accepted catalog,
language-build, artifact, C++ (including the clangd and Joern indexes), post-build,
static-evidence, tree-sitter, and change-context publications. Its manifest is the composed
retrieval view consumed by OWASP; review prioritization and security tagging publish further
shards after it, and `review_data_indexing` audits the final accepted view. Each evidence
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
