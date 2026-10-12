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

Run these commands from the repository root. Bootstrap creates an ignored `.env` once and preserves
its secret on later calls. On native Linux it also records the invoking operator's uid/gid so the
code location does not leave root-owned files in the bind-mounted `runs/` and `data/` trees.
Bootstrap also records the resolved local Claude CLI binary, `~/.claude` directory, and
`~/.claude.json` state file whenever all three exist, regardless of the configured provider.
`compose.yaml` requires `APPSEC_CLAUDE_BINARY`, `APPSEC_CLAUDE_CONFIG_DIR`, and
`APPSEC_CLAUDE_STATE_FILE` unconditionally, so install and sign in to `claude` before bootstrap or
set them by hand. Compose mounts those three paths read-only only into the code-location container
and sets an isolated container home; subscription credentials are not copied into the image,
repository, or `.env`.
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

For a `wave1_review` run, repeat `--required-family <family>` (for example `native` or `dotnet`)
to require zero-gap `SUCCEEDED` language-build receipts for that family and resolve their
retained capture artifacts; the verifier fails if any such receipt is missing, failed, or gapped.

With the current registry, the cross-job dependencies are:

```text
review_intake -> target_catalog -> ci_configuration_analysis -> target_analysis_plan
target_catalog -> source_history_analysis -> target_analysis_plan
target_analysis_plan -> tree_sitter_ast -> change_context_analysis
target_analysis_plan -> project_build -> language_build -> artifact_indexing -> artifact_security_analysis
language_build -> cpp_compiled_analysis -> post_build_security_assessment
cpp_compiled_analysis -> cpp_symbol_index
cpp_compiled_analysis -> cpg_analysis
target_analysis_plan -> evidence_collection
language_build + artifact_indexing + artifact_security_analysis + cpp_compiled_analysis
  + cpp_symbol_index + cpg_analysis + post_build_security_assessment + evidence_collection
  + tree_sitter_ast + change_context_analysis -> codeql_analysis
post_build_security_assessment + evidence_collection + artifact_security_analysis
  + tree_sitter_ast + codeql_analysis -> owasp_control_assessment
codeql_analysis + owasp_control_assessment -> review_prioritization
codeql_analysis + owasp_control_assessment + review_prioritization -> security_tagging
security_tagging -> review_data_indexing
```

`wave1_review` contains every registered job except `third_party_data_sync`, and
`review_data_indexing` is its single terminal job.

This is the Dagster-only composed topology. The direct CLI has a smaller linear graph documented in
[`docs/operations/wave1-review.md`](../../docs/operations/wave1-review.md).

The code location also defines:

- one Dagster job per registered semantic job, named from that job's `name` in
  `appsec-review.toml` (for example `target_catalog` or `codeql_analysis`), with its nodes
  namespaced `standalone__`; a standalone launch joins the application run named by its
  `appsec/application_run_id` tag, and its input validators require that run's accepted upstream
  handoffs;
- `ci_configuration_review`: `review_intake -> target_catalog -> ci_configuration_analysis`;
- `project_build_review`: `review_intake -> target_catalog -> target_analysis_plan ->
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
`APPSEC_CLAUDE_*` bind paths, and optionally `ANTHROPIC_API_KEY`. Compose passes
`ANTHROPIC_API_KEY` (empty by default) only to the code location; it is used only by models
configured with `provider = "anthropic-api"`, and the `claude-cli` transport removes it from the
CLI's environment. `APPSEC_REVIEW_CONFIG` is fixed to `/opt/app/appsec-review.toml` by
`compose.yaml` and the image; the adapter loads that file to build the definitions.

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
