# appsec-review

Evidence-backed application-security review orchestration. A review runs a deterministic graph of
semantic jobs (intake, catalog, analysis planning, builds, static and compiled analysis, CodeQL,
evidence collection) against a local target checkout. Every job writes immutable receipts under
`runs/<run-id>/`. Missing, skipped, or failed coverage is recorded as a named gap, never as a clean
result.

The repository is mid-rebuild. Repository-agent rules live in [`AGENTS.md`](AGENTS.md); navigation
for the rest of the documentation is in [`docs/agent-reader.md`](docs/agent-reader.md).

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
| Native Windows (PowerShell) | Supported | Supported | Not supported out of the box (see below) |

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

- The Dagster Compose file mounts a **Linux** Claude CLI binary, configuration directory, and state
  file into the code-location container, and `deploy/dagster/bin/bootstrap.py` records those paths
  (and the operator uid/gid) only on a POSIX host. Use WSL 2 for the Dagster deployment.
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
git -C targets/appsec-multi-vuln checkout 437ec5141591b25e54dac44168a6bcf832609242
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
four branches:

| Branch | Publishes to | Contents |
| --- | --- | --- |
| `nvd_sync` | `data/feeds/nvd/` | NVD CVE 2.0 yearly feeds, then incremental last-modified windows. |
| `osv_sync` | `data/feeds/osv/` | Configured OSV ecosystem archives plus a SQLite lookup index. |
| `mitre_sync` | `data/feeds/mitre/` | Enterprise ATT&CK, CAPEC, and CWE (Mobile/ICS ATT&CK when selected). |
| `cve_bin_tool_db_build` | `data/feeds/cve-bin-tool/` | cve-bin-tool database built offline in Docker from the NVD snapshot above. |

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
`6/vulnerability.db` and `6/import.json`. The snapshot is written under `data/feeds/grype/`.

## Run a review

The direct CLI runs this linear graph:

```text
review_intake -> target_catalog -> target_analysis_plan -> project_build -> language_build
  -> artifact_indexing -> artifact_security_analysis -> cpp_compiled_analysis
  -> codeql_analysis -> evidence_collection
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

Without installing the package, run the module from the source tree instead:

```bash
PYTHONPATH=src python -m appsec_review start --target targets/appsec-multi-vuln
```

```powershell
$env:PYTHONPATH = "src"
python -m appsec_review start --target targets/appsec-multi-vuln
```

The direct graph leaves out CI configuration analysis, tree-sitter AST, post-build security
assessment, and OWASP control assessment. Use Dagster's `wave1_review` job when you need those.
See [`docs/operations/wave1-review.md`](docs/operations/wave1-review.md).

## Run the Dagster deployment

Run on Linux or inside WSL 2. Make sure `claude` is installed and signed in **before** bootstrap;
bootstrap records its binary, `~/.claude`, and `~/.claude.json` paths in the ignored
`deploy/dagster/.env`, together with your uid/gid so containers do not leave root-owned files in
`runs/` and `data/`. Running bootstrap again keeps the existing secret and fills in only missing
keys.

```bash
python deploy/dagster/bin/bootstrap.py
python deploy/dagster/bin/lifecycle.py build
python deploy/dagster/bin/lifecycle.py start
python deploy/dagster/bin/lifecycle.py status
python deploy/dagster/bin/verify.py
```

The console is at <http://localhost:3000> (bound to `127.0.0.1` only). `targets/` is mounted
read-only, and the default review target is `/opt/app/targets/appsec-multi-vuln`. To review a
different checkout under `targets/`, set `APPSEC_REVIEW_TARGET` in `deploy/dagster/.env` to its
container path, for example:

```bash
APPSEC_REVIEW_TARGET=/opt/app/targets/<your-target>
```

Sync metadata through Dagster:

```bash
dagsterRunId=$(python3 -c 'import uuid; print(uuid.uuid4())')
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml exec -T webserver dagster job launch -w /opt/dagster/home/workspace.yaml -l appsec_review -j third_party_data_sync --run-id "$dagsterRunId"
python deploy/dagster/bin/verify.py --run-id "$dagsterRunId" --evidence deploy/dagster/verification/live-acceptance.json
```

Launch the full review graph:

```bash
dagsterRunId=$(python3 -c 'import uuid; print(uuid.uuid4())')
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml exec -T webserver dagster job launch -w /opt/dagster/home/workspace.yaml -l appsec_review -j wave1_review --run-id "$dagsterRunId"
python deploy/dagster/bin/verify.py --run-id "$dagsterRunId" --evidence deploy/dagster/verification/wave1-live-acceptance.json
```

After you change application code, rebuild and reload only the code location:

```bash
python deploy/dagster/bin/lifecycle.py build
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml up -d --no-deps --force-recreate --wait code-location
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
| `data/reference/` | Committed reference fixtures (OWASP standards). |
| `data/feeds/` | Synced feed snapshots (local, ignored). |
| `targets/` | Review target checkouts (local, ignored). |
| `runs/` | Run receipts, logs, resolved configuration, and `runs/metadata/` host pointers (local). |
| `docs/` | Architecture, operations, schemas, and reviews. Start at `docs/agent-reader.md`. |

An MCP stdio server for retrieval is installed as `appsec-review-mcp`; see
[`docs/operations/retrieval-mcp.md`](docs/operations/retrieval-mcp.md).
