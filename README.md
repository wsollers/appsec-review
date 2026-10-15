# appsec-review

Evidence-backed application-security review orchestration. A review runs a deterministic graph of
semantic jobs (intake, catalog, analysis planning, builds, static and compiled analysis, CodeQL,
evidence collection) against a local target checkout. Every job writes immutable receipts under
`runs/<run-id>/`. Missing, skipped, or failed coverage is recorded as a named gap, never as a clean
result.

The repository is mid-rebuild. Repository-agent rules live in [`AGENTS.md`](AGENTS.md); navigation
for the rest of the documentation is in [`docs/agent-reader.md`](docs/agent-reader.md), and the
architecture index is [`docs/architecture/README.md`](docs/architecture/README.md).

## Contents

- [What you need](#what-you-need)
- [Platform choice](#platform-choice)
- [Setup on Linux](#setup-on-linux)
- [Setup on Windows through WSL 2](#setup-on-windows-through-wsl-2)
- [Setup on native Windows](#setup-on-native-windows)
- [Download the acceptance target](#download-the-acceptance-target)
- [Build the tool container images](#build-the-tool-container-images)
- [Sync third-party metadata](#sync-third-party-metadata)
- [Run a review](#run-a-review)
- [Run the Dagster deployment](#run-the-dagster-deployment)
- [Run the tests](#run-the-tests)
- [Where things live](#where-things-live)

## What you need

| Requirement | Why |
| --- | --- |
| Git | Clone this repository and the review target. |
| Python 3.11 or newer (3.12 matches the deployment image) | The `appsec-review` package and its CLI. |
| Docker Engine with the Compose v2 plugin, or Docker Desktop | Tool images, isolated builds, the cve-bin-tool database builder, and the Dagster stack. |
| Claude Code CLI (`claude`), signed in | Model calls in `appsec-review.toml` use `provider = "claude-cli"`. An unavailable model blocks a review at intake. |
| Disk space | Feed data, tool images, and CodeQL databases are large. The cve-bin-tool database alone is about 530 MB for the full NVD. |
| `NVD_API_KEY` (optional) | Uses the authenticated NVD rate during metadata sync. |

All runtime settings (models, timeouts, worker counts, schedules, feed sources) live in
[`appsec-review.toml`](appsec-review.toml). Change them there rather than in prompts or scripts.

## Platform choice

| Platform | Direct CLI review | Tool image builds | Dagster deployment |
| --- | --- | --- | --- |
| Linux | Supported | Supported | Supported |
| Windows through WSL 2 | Supported | Supported | Supported (recommended on Windows) |
| Native Windows (PowerShell) | Supported | Supported | Supported with container Claude sign-in |

The pipeline is a Linux x86-64 execution vertical: builds, scanners, and CodeQL all run in Linux
containers. On a Windows machine, WSL 2 is the most direct route.

## Setup on Linux

Install the prerequisites (Debian/Ubuntu shown; use your distribution's equivalents elsewhere):

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip
```

Install Docker Engine and the Compose plugin by following
<https://docs.docker.com/engine/install/>, then let your user talk to the daemon:

```bash
sudo usermod -aG docker "$USER"
newgrp docker
docker version
docker compose version
```

Install and sign in to the Claude Code CLI (see <https://code.claude.com/docs>), then confirm it is
on `PATH`:

```bash
claude --version
```

Clone the repository and create a virtual environment:

```bash
git clone https://github.com/wsollers/appsec-review.git
cd appsec-review
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install pytest
```

Install the optional Dagster extras only if you want to run the Dagster tests on the host:

```bash
python -m pip install -e ".[dagster]"
```

Install the `rulepacks` extra (PyYAML) to validate or evaluate the SEI CERT rule pack under
`rules/sei-cert/`; without it the SEI CERT rule-pack tests are skipped:

```bash
python -m pip install -e ".[rulepacks]"
```

Confirm the CLI loads the central configuration:

```bash
appsec-review schedules
```

Continue with [Download the acceptance target](#download-the-acceptance-target).

## Setup on Windows through WSL 2

From an elevated PowerShell, install WSL 2 with Ubuntu and reboot if asked:

```powershell
wsl --install -d Ubuntu
```

Install Docker Desktop for Windows, then in **Settings → General** enable *Use the WSL 2 based
engine* and in **Settings → Resources → WSL integration** enable integration for your Ubuntu
distribution.

Docker Desktop and every WSL distribution share one WSL 2 virtual machine. Builds and CodeQL are
memory-heavy, so give that machine an explicit limit in `%UserProfile%\.wslconfig`:

```ini
[wsl2]
memory=16GB
swap=8GB

[experimental]
autoMemoryReclaim=dropCache
```

Apply the change (this stops all WSL distributions and running containers), then restart Docker
Desktop:

```powershell
wsl --shutdown
```

Open the Ubuntu shell. Keep the clone on the Linux filesystem (for example under `~`), not under
`/mnt/c/...`; bind mounts and file scans are far slower across the Windows boundary, and Linux file
ownership for `runs/` and `data/` only works on the Linux side.

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip
docker version
docker compose version
```

Install and sign in to the Claude Code CLI inside the WSL distribution (the Windows install is not
visible to Linux processes or to the Dagster containers):

```bash
claude --version
```

Then follow the same clone and virtual-environment steps as Linux:

```bash
cd ~
git clone https://github.com/wsollers/appsec-review.git
cd appsec-review
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install pytest
appsec-review schedules
```

From here on, run every command in this README from the WSL shell using the Linux (bash) form.

## Setup on native Windows

Install Git for Windows, Python 3.12 from <https://www.python.org/downloads/windows/> (tick *Add
python.exe to PATH*), and Docker Desktop (WSL 2 engine). Apply the `.wslconfig` memory limit shown
in the WSL section; Docker Desktop uses the same virtual machine.

Avoid CRLF conversion in shell scripts and fixtures before cloning:

```powershell
git config --global core.autocrlf input
```

Clone the repository and create a virtual environment in PowerShell:

```powershell
git clone https://github.com/wsollers/appsec-review.git
cd appsec-review
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install pytest
appsec-review schedules
```

If PowerShell refuses to run the activation script, allow local scripts for your user first:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Native Windows limitations:

- Native Windows Dagster uses a Linux Claude CLI installed inside its code-location image. Sign in
  once inside that container; its Claude home persists in a Docker volume. The Windows host Claude
  login is separate.
- The direct CLI and `containers/build-all.ps1` work from PowerShell, with Docker Desktop running
  the Linux containers.
- Windows-native target analysis is design work only; see
  [`docs/windows-native-analysis-todo.md`](docs/windows-native-analysis-todo.md).

## Download the acceptance target

`targets/` holds local target checkouts. It is ignored by Git (everything except its own
`.gitignore`), so a target never enters this repository. The acceptance target is
[`wsollers/appsec-multi-vuln`](https://github.com/wsollers/appsec-multi-vuln), a deliberately
vulnerable multi-language repository. Several tests and the Dagster deployment default expect it at
`targets/appsec-multi-vuln`.

Linux or WSL:

```bash
git clone https://github.com/wsollers/appsec-multi-vuln.git targets/appsec-multi-vuln
```

Native Windows:

```powershell
git clone https://github.com/wsollers/appsec-multi-vuln.git targets\appsec-multi-vuln
```

To reproduce the recorded acceptance evidence, check out the commit pinned in
[`docs/reviews/native-evaluator-guide.lock.json`](docs/reviews/native-evaluator-guide.lock.json):

```bash
git -C targets/appsec-multi-vuln checkout 29943842cc0c6a8ed5171417b0bccf5c6769f4ef
```

Do **not** clone the evaluator guide (`appsec-multi-vuln-guide`) under `targets/` or anywhere a
review can see it. It holds the ground truth, and `tests/test_blind_target_isolation.py` verifies
that reviews stay blind to it. If you need it for evaluation, keep it outside this repository and
point `APPSEC_EVALUATOR_GUIDE` at it.

Any other target works the same way: clone it beneath `targets/` and pass its path with `--target`
(direct CLI) or `APPSEC_REVIEW_TARGET` (Dagster).

## Build the tool container images

[`containers/catalog.toml`](containers/catalog.toml) is the inventory of scanner and runtime base
images. The Bash and PowerShell launchers call the same engine,
[`containers/build.py`](containers/build.py). Pinned downloads are checked against
`assets.lock.json` before each build, and Docker build steps run without network access. Results go
to `runs/container-builds/<run-id>/`. See [`containers/README.md`](containers/README.md) for details.

Linux or WSL:

```bash
containers/build-all.sh --list
containers/build-all.sh --validate-only
containers/build-all.sh build --all --jobs 4 --continue-on-error
containers/build-all.sh smoke --all
```

Native Windows:

```powershell
containers/build-all.ps1 --list
containers/build-all.ps1 --validate-only
containers/build-all.ps1 build --all --jobs 4 --continue-on-error
containers/build-all.ps1 smoke --all
```

To build only a few images:

```bash
containers/build-all.sh build tool-gitleaks tool-semgrep tool-infer
```

The CodeQL image needs a licensed base image that you supply. No proprietary CodeQL payload is
committed; see [`containers/tools/codeql/LICENSE.md`](containers/tools/codeql/LICENSE.md) and
[`docs/operations/codeql-analysis.md`](docs/operations/codeql-analysis.md). Without it, CodeQL scopes
are recorded as coverage gaps.

## Sync third-party metadata

Vulnerability and threat-reference data is fetched by `job_third_party_data_sync`. It refreshes
six branches:

| Branch | Publishes to | Contents |
| --- | --- | --- |
| `nvd_sync` | `data/feeds/nvd/` | NVD CVE 2.0 yearly feeds, then incremental last-modified windows. |
| `osv_sync` | `data/feeds/osv/` | Configured OSV ecosystem archives plus a SQLite lookup index. |
| `mitre_sync` | `data/feeds/mitre/` | Enterprise ATT&CK, CAPEC, and CWE (all three mandatory); Mobile and ICS ATT&CK are optional selections. |
| `cve_bin_tool_db_build` | `data/feeds/cve-bin-tool/` | cve-bin-tool database built offline in Docker from the NVD snapshot above. |
| `kev_sync` | `data/feeds/kev/` | CISA Known Exploited Vulnerabilities catalog and SQLite lookup index. |
| `epss_sync` | `data/feeds/epss/` | FIRST daily EPSS scores and SQLite lookup index. |

Each publication is an immutable, hash-manifested snapshot, and `current.json` moves only after
validation. A failed refresh keeps the previous last-known-good snapshot. Host-level status
pointers are written to `runs/metadata/`. Feed data and run receipts are local state and are never
committed. Full details are in
[`docs/operations/third-party-data-sync.md`](docs/operations/third-party-data-sync.md).

Run the sync once before your first review, and again whenever you want fresher data. Docker must be
running.

Linux or WSL:

```bash
export NVD_API_KEY=<your-nvd-api-key>   # optional
appsec-review run job_third_party_data_sync --trigger manual
```

Native Windows:

```powershell
$env:NVD_API_KEY = "<your-nvd-api-key>"   # optional
appsec-review run job_third_party_data_sync --trigger manual
```

The first NVD bootstrap downloads every yearly feed and takes a while. Without `NVD_API_KEY` the
configured unauthenticated delay applies. A nonzero exit means at least one branch failed; check
the unit receipts under
`runs/<run-id>/data/jobs/job_third_party_data_sync/attempts/<attempt-id>/` rather than assuming
the data is current.

When the Dagster stack is running, the same job runs nightly at `00:00 UTC` (configured under
`jobs.job_third_party_data_sync.schedule` in `appsec-review.toml`). To launch it by hand there, see
[Run the Dagster deployment](#run-the-dagster-deployment).

### Optional: Grype database

Grype is disabled by default (`[tools].disable_grype = true`), and its unit is recorded as a
`CONFIGURED_DISABLED` gap. To enable it, set that value to `false`, build `tool-grype`, import a
Grype v6 database into a staging directory, and publish it as an immutable snapshot:

```bash
python tools/publish_grype_snapshot.py --staging <grype-staging-dir>
```

The staging directory must contain `latest.json`, `vulnerability-db.tar.zst`, and the imported
`6/vulnerability.db` and `6/import.json`; the archive must match the listing's SHA-256 and the
listing must be `active`. The snapshot is written under `--destination` (default
`data/feeds/grype`). `--image` names the Grype tool image recorded in the manifest (default
`appsec-review/tool-grype:0.119.0`); it must already exist locally, because the script reads its
immutable image id with `docker image inspect`. Every snapshot manifest carries a fixed
`acquisition_gaps` entry stating that the container updater's TLS verification failed and that the
host fetched the official listing and archive and verified the published SHA-256.

## Run a review

The direct CLI runs this linear graph:

```text
model_connectivity -> tool_image_rebuild -> review_intake -> target_catalog -> source_history_analysis
  -> target_analysis_plan
  -> tree_sitter_ast -> project_build -> language_build
  -> artifact_indexing -> test_coverage -> profile_data -> artifact_security_analysis
  -> cpp_compiled_analysis -> clang_static_analysis -> cpp_symbol_index
  -> cpg_analysis (deprecated; only when enabled) -> evidence_collection -> dependency_intelligence
  -> change_context_analysis -> codeql_analysis -> review_prioritization
  -> code_graph_index -> review_data_indexing -> review_package_assembly
  -> document_issue_analysis
```

Start a review from the repository root with the virtual environment active:

```bash
appsec-review start --target targets/appsec-multi-vuln
```

The command prints a JSON summary that includes the `run_id` (for example `2026-10-08-0001`). Use
it to inspect or resume the run:

```bash
appsec-review logs --run-id <run-id>
appsec-review logs --run-id <run-id> --follow
appsec-review logs --run-id <run-id> --job job_target_catalog --level ERROR --raw
appsec-review plan-tools --run-id <run-id>
appsec-review metrics --run-id <run-id>
```

Explain and then perform a resume. `plan-resume` is read-only apart from its audit event:

```bash
appsec-review plan-resume --run-id <run-id> --target targets/appsec-multi-vuln
appsec-review resume --run-id <run-id> --target targets/appsec-multi-vuln
appsec-review resume --run-id <run-id> --target targets/appsec-multi-vuln --force-from job_target_catalog
```

Other options: the global `--config <path-or-file-URI>` (before the subcommand) selects a
configuration other than `appsec-review.toml`; `logs` also filters by `--step`, `--task`, and
`--attempt`; `plan-resume` accepts the same `--force-from <job-id>` as `resume`; and
`appsec-review run <job-id> [--run-id <run-id>] [--trigger manual|schedule]` dispatches one job,
optionally into an existing run. Two further subcommands run outside a review graph:
`appsec-review binary-decompile` (pre-run Ghidra decompilation; see
[`docs/operations/binary-decompilation.md`](docs/operations/binary-decompilation.md)) and
`appsec-review update-image-pins --run-id <run-id> [--write]` (rewrites image-ID pins reported
stale by a run's tool-image rebuild; see
[`docs/operations/tool-image-rebuild.md`](docs/operations/tool-image-rebuild.md)).

Without installing the package, run the module from the source tree instead:

```bash
PYTHONPATH=src python -m appsec_review start --target targets/appsec-multi-vuln
```

```powershell
$env:PYTHONPATH = "src"
python -m appsec_review start --target targets/appsec-multi-vuln
```

The direct graph leaves out CI configuration analysis, post-build security assessment, OWASP
control assessment, and security tagging. Use Dagster's `wave1_review` job, which runs every
enabled registered review job except the standalone `third_party_data_sync` and
`inference_security_review` jobs, when you need those branches. The direct graph is linear, so its
order is an execution order rather than a claim that every adjacent job consumes its predecessor.
`third_party_data_sync` remains a separate scheduled metadata job.
See [`docs/operations/wave1-review.md`](docs/operations/wave1-review.md).

## Run the Dagster deployment

Use `~/projects/appsec-review` for WSL and a native drive checkout for Windows. Each has its own
Compose project, image, database, run data, targets, and Claude authentication. Stop the running
stack before switching hosts; the lifecycle script rejects a second active appsec stack.

On Linux or WSL 2, make sure `claude` is installed and signed in **before** bootstrap;
the Linux Compose overlay requires the Claude paths, and bootstrap records its binary, `~/.claude`, and
`~/.claude.json` paths in the ignored `deploy/dagster/.env`, together with your uid/gid so
containers do not leave root-owned files in `runs/` and `data/`. Running bootstrap again preserves
the existing secret and refreshes the host-specific keys.

```bash
python deploy/dagster/bin/bootstrap.py
python deploy/dagster/bin/lifecycle.py build
python deploy/dagster/bin/lifecycle.py start
python deploy/dagster/bin/lifecycle.py status
python deploy/dagster/bin/verify.py
```

On native Windows, run the same commands in PowerShell, then sign in to the container CLI with
`docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml -f deploy/dagster/compose.windows.yaml exec code-location claude auth login`.
The [serial smoke runner](deploy/dagster/README.md#serial-smoke-tests) verifies this login without
printing its credentials.

The console is at <http://localhost:3000> (bound to `127.0.0.1` only). `targets/` is mounted
read-only, and the default review target is `/opt/app/targets/appsec-multi-vuln`. To review a
different checkout under `targets/`, set `APPSEC_REVIEW_TARGET` in `deploy/dagster/.env` to its
container path, for example:

```bash
APPSEC_REVIEW_TARGET=/opt/app/targets/<your-target>
```

Sync metadata through Dagster:

```bash
python deploy/dagster/bin/smoke.py --platform linux --mode feeds
```

Use `--platform wsl` from WSL or `--platform windows` from native PowerShell. The smoke runner
checks for active runs and executes one live sync at a time.

Launch the full review graph:

```bash
dagsterRunId=$(python3 -c 'import uuid; print(uuid.uuid4())')
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml exec -T webserver dagster job launch -w /opt/dagster/home/workspace.yaml -l appsec_review -j wave1_review --run-id "$dagsterRunId"
python3 deploy/dagster/bin/review_run.py watch --run-id "$dagsterRunId"
python deploy/dagster/bin/verify.py --run-id "$dagsterRunId" --evidence "runs/metadata/dagster-verification/$dagsterRunId.json"
```

After you change application code, rebuild and reload only the code location:

```bash
python deploy/dagster/bin/lifecycle.py build
python deploy/dagster/bin/lifecycle.py reload
python deploy/dagster/bin/verify.py
```

Diagnose and stop:

```bash
python deploy/dagster/bin/lifecycle.py logs
python deploy/dagster/bin/run_report.py --stale-seconds 3600
python deploy/dagster/bin/lifecycle.py stop
```

`stop` keeps all state. Do not run `docker compose ... down --volumes` in normal operation; that
deletes the Dagster and PostgreSQL volumes. The full operator guide, including run recovery, is
[`deploy/dagster/README.md`](deploy/dagster/README.md).

## Run the tests

Pytest keeps its temporary and cache state under `test/tmp/` (configured in `pyproject.toml`).
Tests that need the acceptance target expect `targets/appsec-multi-vuln`, and the Dagster tests are
skipped when the `dagster` extra is not installed.

```bash
python -m pytest -q
```

Use a named base directory beneath `test/tmp/` for focused or concurrent sessions:

```bash
python -m pytest -q tests/test_static_adapters.py --basetemp=test/tmp/static-adapters
```

Run the deployment test suite in its pinned image:

```bash
docker build --file deploy/dagster/Dockerfile --target test --tag appsec-review-dagster-test .
docker run --rm appsec-review-dagster-test
```

## Where things live

| Path | Contents |
| --- | --- |
| `appsec-review.toml` | Central typed configuration: jobs, steps, tasks, models, schedules, limits. |
| `src/appsec_review/` | The package: CLI, runtime, jobs, retrieval, MCP server, Dagster adapter. |
| `containers/` | Tool and base image definitions, pinned asset locks, build launchers. |
| `deploy/dagster/` | Compose stack, bootstrap, lifecycle, and verification scripts. |
| `tools/` | cve-bin-tool database builder and the Grype snapshot publisher. |
| `rules/` | Checked-in rules: SEI CERT and Semgrep packs, C++ CERT CodeQL mappings, PMD, and the CodeQL graph-export query pack (`codeql-graph-export/`); mounted read-only in Dagster. |
| `pipeline/` | Review-worker guidance: governing rules, personas, stacks, roles, tasks, the guidance registry, and registered runtime skills (`pipeline/skills/`). |
| `.claude/skills/` | Canonical development skills for agents working on this repository; never loaded by jobs or shipped in runtime images. |
| `.agents/skills/` | One pointer skill that sends Codex, Gemini CLI, Copilot and Cursor to `.claude/skills/`. |
| `data/reference/` | Committed reference data (OWASP standards and the security-tag taxonomy). |
| `data/feeds/` | Synced feed snapshots (local, ignored). |
| `targets/` | Review target checkouts (local, ignored). |
| `runs/` | Run receipts, logs, resolved configuration, and `runs/metadata/` host pointers (local). |
| `docs/` | Architecture, operations, schemas, and reviews. Start at `docs/agent-reader.md`. |
| `tests/` | The pytest suite. |
| `test/tmp/` | Disposable pytest temporary and cache state (local). |

An MCP stdio server for retrieval is installed as `appsec-review-mcp`; see
[`docs/operations/retrieval-mcp.md`](docs/operations/retrieval-mcp.md).
