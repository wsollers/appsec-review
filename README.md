# appsec-review

Evidence-backed application-security review orchestration. A review runs a deterministic graph of
semantic jobs (intake, catalog, analysis planning, builds, static and compiled analysis, CodeQL,
evidence collection) against a local target checkout. Every job writes immutable receipts under
`runs/<run-id>/`. Missing, skipped, or failed coverage is recorded as a named gap, never as a clean
result.

The repository is mid-rebuild. Repository-agent rules live only in [`AGENTS.md`](AGENTS.md), which
governs. [`docs/agent-reader.md`](docs/agent-reader.md) is navigation for agents and adds no rules;
the architecture index is [`docs/architecture/README.md`](docs/architecture/README.md).

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
- [Model profiles: dev and prod](#model-profiles-dev-and-prod)
- [Prepare an end-to-end run](#prepare-an-end-to-end-run)
- [Run the Dagster deployment](#run-the-dagster-deployment)
- [Run the tests](#run-the-tests)
- [Working with other agent sessions](#working-with-other-agent-sessions)
- [Where things live](#where-things-live)

## What you need

| Requirement | Why |
| --- | --- |
| Git | Clone this repository and the review target. |
| Python 3.11 or newer (3.12 matches the deployment image) | The `appsec-review` package and its CLI. |
| Docker Engine with the Compose v2 plugin, or Docker Desktop | Tool images, isolated builds, the cve-bin-tool database builder, and the Dagster stack. |
| Claude Code CLI (`claude`), signed in; or the opt-in Copilot SDK setup | Default model calls use `claude-cli`; `copilot-dev` and `copilot-prod` use a separate Copilot subscription login. An unavailable model blocks intake. |
| Disk space | Feed data, tool images, and CodeQL databases are large. The cve-bin-tool database alone is about 530 MB for the full NVD. |
| `NVD_API_KEY` (optional) | Uses the authenticated NVD rate during metadata sync. |

All runtime settings (models, timeouts, worker counts, schedules, feed sources) live in
[`appsec-review.toml`](appsec-review.toml). Change them there rather than in prompts or scripts.

Customer evidence uses strict assurance by default. Reduced repeated verification is an explicit
operator opt-in for approved first-party projects. Both modes exclude supplied platform
software/images/tools from customer scanning and payload fingerprinting; customer deliverables,
dependencies, generated outputs and build-chain evidence remain in scope. See
[performance and assurance](docs/operations/performance-assurance.md) for immutable policy,
declared releases, resource admission, required builder readiness and rollout limitations.

### Software inventory

Everything below is declared in the file named in the last column; nothing else is required.

**Required to run**

| Requirement | Needed for | Where declared |
| --- | --- | --- |
| Python >= 3.11 and `jsonschema>=4.20` (`tzdata` on Windows), installed by `pip install -e .` | The package and the `appsec-review` and `appsec-review-mcp` commands | `pyproject.toml` (`requires-python`, `dependencies`) |
| Docker with `docker buildx` (`--load`, `--network none`) | Operator tool/build-environment provisioning and container execution; review-time derived images use the bounded builder below | `containers/build.py`, `src/appsec_review/container_runtime/` |
| Claude Code CLI `claude` on `PATH`, signed in | Model calls; `provider = "claude-cli"` | `appsec-review.toml`, `src/appsec_review/inference/claude_cli.py` |
| Tool images (below), built locally | Every analysis job that is not a coverage gap | `containers/catalog.toml` |

**Required to test (host virtual environment, `pip install -e ".[test]"`)**

| Requirement | Needed for | Where declared |
| --- | --- | --- |
| `pytest>=8`, `hypothesis==6.170.0`, `PyYAML==6.0.3` | The suite (`tests/review` uses Hypothesis; the SEI CERT rule-pack tests use PyYAML) | `pyproject.toml` (`test` extra) |
| `git` | Source-history, change-context, SAST-flow and nothing-to-find tests (skipped without it) | `tests/` (`shutil.which("git")`) |
| Target checkout `targets/appsec-multi-vuln` | Tests that read the acceptance target (skipped when absent) | `tests/conftest.py`; [Download the acceptance target](#download-the-acceptance-target) |

**Optional or opt-in**

| Requirement | Needed for | Where declared |
| --- | --- | --- |
| `dagster` extra (`dagster`, `dagster-postgres`, `dagster-webserver`, all pinned) | Dagster tests on the host; otherwise they are skipped. The deployment image installs its own pinned set | `pyproject.toml`, `deploy/dagster/requirements.txt` and `requirements.lock.txt` |
| `rulepacks` extra (`PyYAML==6.0.3`) | Validating or evaluating `rules/sei-cert/` without the full `test` extra | `pyproject.toml` |
| Docker Compose v2 plugin | The Dagster stack | `deploy/dagster/compose*.yaml` |
| Commissioned bounded-builder service, immutable local BuildKit image, Docker/Skopeo and verified native cgroup-v2 limits | Required dependency or CodeQL derived images when no eligible prepared image exists; package-network recipes also need isolated operator egress. Not provisioned or enabled by this repository change | `review_policy.image_builder`; [performance and assurance](docs/operations/performance-assurance.md#scheduling-and-limits) |
| Host `semgrep` or `opengrep` (or `APPSEC_REVIEW_SEMGREP` / `APPSEC_REVIEW_OPENGREP`) | Rule-pack engine tests (skipped without it; some use the pinned Semgrep image instead) | `src/appsec_review/rulepacks/sei_cert/engines.py`, `tests/test_semgrep_rules.py`, `tests/test_cpp_cert_rules.py` |
| `bash`, and `pwsh` | The launcher-parity test (skipped without both) | `tests/test_container_builds.py` |
| `java` and `APPSEC_GRADLE_HOME` | Gradle provenance test | `tests/test_gradle_provenance.py` |
| `APPSEC_LIVE_SEEDED_CLANG=1`, `clang++-18` for the compiler check, and the built `tool-native-cpp`, `tool-clang-static-analysis` and `tool-joern` images for the container check | `tests/live/test_seeded_clang_live.py` | that file |
| `APPSEC_RUN_LIVE_INFERENCE=1` and a signed-in `claude` | Live model recipe inference in `tests/test_live_build_toolchains.py` | that file |
| `APPSEC_MULTI_VULN_WORKSPACE`, `APPSEC_CPP_ACCEPTANCE_TARGET`, `APPSEC_REVIEW_BUILDENV_PINS=local` | Live code-graph, C++ acceptance and build-image tests | `tests/live/test_code_graph_live.py`, `tests/orchestration/dagster/test_post_build_security.py`, `tests/integration/test_family_project_builds.py` |
| Built tool, build-environment and CodeQL images | Live, integration and full-tier tests (skipped, naming the missing image) | `containers/catalog.toml` |
| `NVD_API_KEY` | Authenticated NVD rate during metadata sync | `docs/operations/third-party-data-sync.md` |

**Tool images.** `containers/catalog.toml` is the authoritative list (32 enabled tool images, four
runtime bases, ten build environments); [`containers/README.md`](containers/README.md) explains building
them, and each `containers/tools/<name>/tool.toml` or `Dockerfile` pins its inputs. By purpose:
C/C++ (`native-cpp` toolchain with Clang 18, `clang-static-analysis` with Clang-Tidy and the Static
Analyzer, `clangd-indexer`, `cppcheck`, `infer`, `svf`), code property graph and binaries (`joern`,
`ghidra`, `blint`, `tree-sitter`), SAST (`semgrep`, `opengrep`, `gosec`, `pmd`, `spotbugs`,
`phpstan`, `phpcs`, `psalm`, `mobsfscan`, `shellcheck`), secrets, IaC and CI (`gitleaks`, `checkov`,
`hadolint`, `actionlint`, `zizmor`), dependencies and SBOM (`trivy`, `grype`, `syft`,
`osv-scanner`), report rendering (`report-latex`), and support (`git`, `sqlite-fts`). The
`cve-bin-tool` image is deferred for redesign, and `sbomasm` and `microsoft-sbom-tool` are replaced by `syft`.
Clang 18 comes from those images, not from the host; the host needs `clang++-18` only for the
opt-in live test above.

**CodeQL** is not in the catalog. Its licensed payload (CLI, extractors, query packs) is not in this
repository: on any Linux Docker host (native Linux or WSL 2, not Windows PowerShell)
`containers/tools/codeql/build-source-image.sh` downloads the pinned CodeQL bundle and
`github/codeql-coding-standards@v2.62.0` packs, verifies their SHA-256, and builds
`audit-codeql:local` and `audit-codeql:custom-2.27.0` from this repository's Dockerfiles.
Its execution image ID and declared component releases are configured in `appsec-review.toml`;
customer review execution does not hash supplied assets or their lock file. See
[`containers/tools/codeql/README.md`](containers/tools/codeql/README.md),
[`LICENSE.md`](containers/tools/codeql/LICENSE.md) and
[`docs/operations/codeql-analysis.md`](docs/operations/codeql-analysis.md). Without it, CodeQL
scopes are recorded as coverage gaps.

Hash-pinned downloads for the images are fetched and checked by `containers/build.py` against each
`assets.lock.json`; `tool-native-cpp` and `tool-tree-sitter` need their inputs acquired first (see
[Build the tool container images](#build-the-tool-container-images)).

## Platform choice

| Platform | Direct CLI review | Tool image builds | Dagster deployment |
| --- | --- | --- | --- |
| Linux | Supported | Supported | Supported |
| Windows through WSL 2 | Supported | Supported | Supported (recommended on Windows) |
| Native Windows (PowerShell) | Supported | Supported | Supported with container Claude sign-in |

The pipeline is a Linux x86-64 execution vertical: builds, scanners, and CodeQL all run in Linux
containers. On a Windows machine, WSL 2 is the most direct route.

For repository development and tests, use Linux or WSL with the checkout on the Linux filesystem
(for example, `~/src/appsec-review`, not `/mnt/c/...`). Windows-mounted checkouts can fail POSIX
path-custody checks even when Python runs inside WSL. Repository agents need explicit user
permission to work on native Windows; see [AGENTS.md](AGENTS.md).

### Line endings and hashes

[.gitattributes](.gitattributes) controls line endings independently of a user's `core.autocrlf`.
Portable text, including Bash and PowerShell, uses LF on both platforms. `.bat` and `.cmd` files
use CRLF in the working tree and canonical LF in Git. Git blob identities therefore agree across
platforms, although a raw working-tree SHA-256 changes when line endings change.

Rule packs, reference data, test fixtures and acceptance seeds are marked `-text`: Git checks out
their exact committed bytes, including any upstream CRLF or mixed endings, without conversion.
Their raw hashes and byte offsets must stay identical everywhere; do not normalize them before
verification or refresh a lock merely to hide conversion. [.editorconfig](.editorconfig) supplies
matching editor defaults without changing those byte-pinned inputs.

Attributes do not rewrite an existing checkout. If it already has converted files, preserve any
local edits and use a fresh clone on the Linux filesystem. Do not blindly run
`git add --renormalize .`: changes to byte-pinned content require an intentional source update and
the corresponding provenance/lock procedure.

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
python -m pip install -e ".[test]"
```

Give every checkout its own `.venv`. An editable install points at the checkout it was installed
from, so a test run that borrows another checkout's environment tests that checkout's code. Confirm
the import path before trusting a run:

```bash
python -c "import appsec_review; print(appsec_review.__file__)"   # must be inside this checkout
```

Install the optional Dagster extras only if you want to run the Dagster tests on the host:

```bash
python -m pip install -e ".[dagster]"
```

The `test` extra already includes PyYAML. Install the smaller `rulepacks` extra instead only to
validate or evaluate the SEI CERT rule pack under `rules/sei-cert/` without the rest of the test
dependencies (the SEI CERT rule-pack tests are skipped when PyYAML is missing):

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
python -m pip install -e ".[test]"
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
python -m pip install -e ".[test]"
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

Reviews run against the target commit pinned in
[`docs/reviews/native-evaluator-guide.lock.json`](docs/reviews/native-evaluator-guide.lock.json),
which also pins the evaluator guide commit. Check it out before a review, and move the target only
between runs, never while a run or test suite reads it:

```bash
git -C targets/appsec-multi-vuln checkout 29943842cc0c6a8ed5171417b0bccf5c6769f4ef
```

The target is blind: it carries no answers, and `tests/test_blind_target_isolation.py` fails if
its paths or prose name a weakness. Do **not** clone the evaluator guide (`appsec-multi-vuln-guide`)
under `targets/` or anywhere a review can see it. It holds the answer key and a per-defect inventory
(`data/defect-inventory.json`, validated with its `scripts/defect_inventory.py`). If you need it for
evaluation, keep it outside this repository and point `APPSEC_EVALUATOR_GUIDE` at it.

Any other target works the same way: clone it beneath `targets/` and pass its path with `--target`
(direct CLI) or `APPSEC_REVIEW_TARGET` (Dagster).

To review a pinned **system** instead, configure it under `[[target_acquisition.systems]]`. A
system has one or more components, because one reviewed system may span several source-control
systems. Each component is a Git commit (the default kind) with its submodules checked out
recursively, a submitted Perforce changelist, or a GitLab, Gerrit, or Azure DevOps review revision.
Then run:

```bash
appsec-review start --system storefront
```

The `job_target_acquisition` gate acquires every component in parallel into
`targets/<system>/<component>/` before intake, and discovery then runs once over the composed
`targets/<system>/` root. `appsec-review acquire-target --system <id>` does the same outside a run.
Acquisition writes hash-pinned manifests, records failed components as named gaps, and never
touches an existing checkout. See
[`docs/operations/target-acquisition.md`](docs/operations/target-acquisition.md).

## Build the tool container images

[`containers/catalog.toml`](containers/catalog.toml) is the inventory of every image: tool images,
shared runtime bases, and the language build environments under `containers/buildenv/` (built on a
shared native toolchain image). The Bash and PowerShell launchers call the same engine,
[`containers/build.py`](containers/build.py). Downloads are checked against `assets.lock.json`
before each build, and Docker build steps run without network access. Results go to
`runs/container-builds/<run-id>/`. See [`containers/README.md`](containers/README.md) for details.

Two images need their inputs acquired before the first build:

```bash
containers/tools/native-cpp/acquire_assets.sh        # C/C++ package closure for tool-native-cpp
```

`tool-tree-sitter` takes its wheels and grammars from
[`containers/tools/tree-sitter/acquire_assets.py`](containers/tools/tree-sitter/README.md), run in
the acquisition container its README describes.

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

The CodeQL images build on any Linux Docker host (native Linux or WSL 2) with one command,
`containers/tools/codeql/build-source-image.sh`, which fetches the pinned, hash-verified CodeQL and builds `audit-codeql:local` and the pinned `audit-codeql:custom-2.27.0`.
No proprietary CodeQL payload is committed; see
[`containers/tools/codeql/LICENSE.md`](containers/tools/codeql/LICENSE.md) and
[`docs/operations/codeql-analysis.md`](docs/operations/codeql-analysis.md). Without it, CodeQL scopes
are recorded as coverage gaps.

Images move forward; they are not reproduced byte for byte. Upstream archives change, so a rebuild
or re-acquisition can produce new bytes and a new image ID. When that happens, rebuild, smoke the
image, and record the result: the new size and SHA-256 in its `assets.lock.json`, and the new image
ID in its pins (`image_id` in the catalog, the build profiles in `appsec-review.toml`, and CodeQL's
`source_image_id`). Pins are host-local and are never compared across machines. See
[Moving forward, not reproducing](containers/README.md#moving-forward-not-reproducing).

The pipeline never builds images. The operator rebuilds them on the host with `containers/build.py`
and re-pins them with `appsec-review update-image-pins --write`. Every review then verifies at its
start (`job_image_pin_verification`) that every enabled catalog image, build profile and CodeQL source
image resolves on the local daemon to exactly its pin, and fails before intake naming every missing
image or moved tag. See
[`docs/operations/image-pin-verification.md`](docs/operations/image-pin-verification.md).

## Sync third-party metadata

Vulnerability and threat-reference data is fetched by `job_third_party_data_sync`. It refreshes
six branches:

| Branch | Publishes to | Contents |
| --- | --- | --- |
| `nvd_sync` | `data/feeds/nvd/` | NVD CVE 2.0 yearly feeds, then incremental last-modified windows. |
| `osv_sync` | `data/feeds/osv/` | OSV archives for PyPI, crates.io, npm, Go, Maven, Packagist, NuGet and RubyGems (about 291,000 records, 573 MB uncompressed) plus a SQLite lookup index. |
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

For a full Dagster review, start with the
[review startup guide: required inputs, features and flags](docs/operations/review-startup.md).
It includes PowerShell/WSL and Linux launch sequences, all `review-start` options, and the
TOML-only feature gates. The direct CLI below runs a smaller graph.

The direct CLI runs this linear graph:

```text
model_connectivity -> image_pin_verification -> target_acquisition -> review_intake -> target_catalog
  -> ci_configuration_analysis -> source_history_analysis
  -> target_analysis_plan
  -> project_build -> language_build -> tree_sitter_ast -> change_context_analysis
  -> artifact_indexing -> test_coverage -> profile_data -> artifact_security_analysis
  -> evidence_collection -> cpp_compiled_analysis -> clang_static_analysis
  -> sanitizer_build -> cpp_symbol_index -> cpg_analysis (deprecated; only when enabled)
  -> svf_alias_analysis (opt-in; only when enabled) -> binary_evidence_indexing
  -> post_build_security_assessment -> dependency_intelligence
  -> codeql_analysis -> review_prioritization
  -> code_graph_index -> security_tagging
  -> owasp_control_assessment (enabled by default)
  -> review_data_indexing -> review_package_assembly
  -> document_issue_analysis -> inference_security_review (chains before seal)
  -> poc_generation -> remediation_planning -> remediation_validation -> dossier_publication
  -> final_publication_gate -> openvex_export (opt-in; only when enabled)
  -> final_report_publication
```

The completion producers above run before one certified gate when enabled. The direct driver
dispatches post-gate export and report sequentially, but they are independent graph peers:
the report consumes only the gate snapshot, never OpenVEX output.

Start a review from the repository root with the virtual environment active:

```bash
appsec-review start --target targets/appsec-multi-vuln
```

Or name a configured system; `target_acquisition` acquires or re-verifies its components before
intake and the rest of the graph reviews the composed `targets/<system>/` root:

```bash
appsec-review start --system storefront
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

Explain and then perform a resume (pass `--system <id>` instead of `--target` for a system run).
`plan-resume` is read-only apart from its audit event:

```bash
appsec-review plan-resume --run-id <run-id> --target targets/appsec-multi-vuln
appsec-review resume --run-id <run-id> --target targets/appsec-multi-vuln
appsec-review resume --run-id <run-id> --target targets/appsec-multi-vuln --force-from job_target_catalog
```

Other options: the global `--config <path-or-file-URI>` (before the subcommand) selects a
configuration other than `appsec-review.toml`; `logs` also filters by `--step`, `--task`, and
`--attempt`; `plan-resume` accepts the same `--force-from <job-id>` as `resume`; and
`appsec-review run <job-id> [--run-id <run-id>] [--trigger manual|schedule]` dispatches one job,
optionally into an existing run. Three further subcommands run outside a review graph:
`appsec-review acquire-target [--target <id>] [--verify-only]` (hash-pinned Git, Perforce or
review-export acquisition into `targets/`; see
[`docs/operations/target-acquisition.md`](docs/operations/target-acquisition.md)),
`appsec-review binary-decompile` (pre-run Ghidra decompilation; see
[`docs/operations/binary-decompilation.md`](docs/operations/binary-decompilation.md)) and
`appsec-review update-image-pins [--write]` (re-pins every configured image-ID pin to the image its
tag resolves to on the local daemon after a host rebuild; see
[`docs/operations/image-pin-verification.md`](docs/operations/image-pin-verification.md)).

Without installing the package, run the module from the source tree instead:

```bash
PYTHONPATH=src python -m appsec_review start --target targets/appsec-multi-vuln
```

```powershell
$env:PYTHONPATH = "src"
python -m appsec_review start --target targets/appsec-multi-vuln
```

The direct graph leaves out CI configuration analysis and post-build security assessment,
including when those jobs are enabled. Use Dagster's `wave1_review` job, which runs every
enabled registered review job except the standalone
`third_party_data_sync` job, when you need those branches. The direct graph is linear, so its
order is an execution order rather than a claim that every adjacent job consumes its predecessor.
`third_party_data_sync` remains a separate scheduled metadata job.

The [OWASP assessment](docs/architecture/owasp-control-workbench.md) is enabled by default
with `mode = "assessment"` in all shipped profiles. Set
`jobs.job_owasp_control_assessment.settings.enabled = false` to opt out before freezing a run.
In both direct and Dagster graphs the enabled chain is accepted source/component/
build/static information → prioritization/code graph → security tagging/tag cloud → OWASP →
review data indexing (`control_evidence`) → package assembly → hunt and red/blue/independent
verification. Tags and classifications route work, never prove controls. Full pinned catalogs
contain 345 ASVS controls, 24 MASVS controls, 292 MASTG supporting tests and two 10-record risk
catalogs; **only four narrow Python static procedures are implemented**, not full compliance
coverage. Configured assessment calls a worker and a fresh blinded reviewer. Qualification is an
explicit synthetic mode, not selected by input-file presence and never production-eligible.
Downstream OWASP interpretations remain provisional and indirect for every final predicate:
review roles must retrieve original evidence. See [settings, outputs and limits](docs/operations/owasp-control-assessment.md).
Direct `start`, `resume` and `plan-resume` select tagging and OWASP in this order when enabled.
`--force-from` can name either job in `resume`/`plan-resume`, but cannot bypass a disabled-job gate.
This shared ordering is not full graph parity: CI/post-build remain Dagster additions and
third-party metadata sync remains standalone.

`sanitizer_build` rebuilds the accepted native units with AddressSanitizer and UBSan in its own
workspace and never runs a produced binary; see
[`docs/operations/sanitizer-build.md`](docs/operations/sanitizer-build.md).
`final_publication_gate` and `final_report_publication` call no model: they re-verify the accepted
inference review and write `final-report.json` and a deterministic `final-report.md`; see
[`docs/operations/final-report.md`](docs/operations/final-report.md).
Enabled PoC generation, remediation planning/validation and dossier publication run **before**
the single final gate. PoC and remediation checks are compile-only, never runtime reproduction
or a verified fix. New-run defaults do not change frozen historical configurations; manual
disabled PoC output requires explicit gate admission. See
[`docs/operations/poc-generation.md`](docs/operations/poc-generation.md),
[remediation](docs/operations/remediation.md) and [dossiers](docs/operations/dossier-publication.md).

`job_openvex_export` produces deterministic, model-free
OpenVEX `affected` statements only for the accepted gate's publishable confirmed findings,
with a protected evidence/limitations companion. It is disabled by default,
including refusal of manual dispatch while disabled, and requires explicit immutable pre-run
issuer/action/repository settings. Products identify the reviewed source snapshot and full
configuration, not a released binary or version range; local export does not authorize public
disclosure. Empty exports retain explicit non-clean accounting without writing an invalid empty
OpenVEX document. The user-selected boundary is **standalone post-gate export with gate-only reporting**:
OpenVEX is not a report field, attachment or prerequisite. At source
`ede3c107`, strict gate `/2` contracts and topology are reconciled; exporter verifier/projector
adaptation is still in progress, not evidence of final `/2` execution validation.
See the [design](docs/architecture/openvex-export.md) and
[operator guide and diagrams](docs/operations/openvex-export.md).

See [`docs/operations/wave1-review.md`](docs/operations/wave1-review.md).

## Model profiles: dev and prod

**Selection:** set `APPSEC_REVIEW_PROFILE=prod`, or use `--profile prod` on the stack and review
scripts (`-Profile prod` in PowerShell). The default is `dev`; `copilot-dev` is an opt-in
Haiku development profile using a separate Copilot subscription login. Other values are errors. The
stack's profile is the container default; `review-start --profile` picks another profile of the same
provider family (Claude or Copilot) for one run, and a family switch needs a stack restart.

| Profile | Models | Limits |
| --- | --- | --- |
| `dev` (default) | Haiku 5.5, the checked-in `appsec-review.toml` | today's small limits, for testing |
| `prod` | Sonnet 5.5, with an Opus 5.5 independent verifier (`profiles/prod.toml`) | larger token limits and budgets for real reviews |
| `copilot-dev` | Haiku 5.5 through the Copilot SDK (`profiles/copilot-dev.toml`) | unchanged dev limits; Git and inference accounts stay separate |
| `copilot-prod` | Sonnet 5.5 through Copilot, with Opus 5.5 verifier and judge (`profiles/copilot-prod.toml`) | unchanged prod limits, reasoning and role bindings; opt-in only |

For Copilot installation, separate-account login, catalog verification and deployment commands, see
[Copilot with a separate GitHub identity](docs/operations/model-profiles.md#copilot-with-a-separate-github-identity).
The existing `dev` and `prod` profiles still use Claude; selecting either Copilot profile does not require a
Claude login.

```bash
scripts/stack-restart.sh --profile prod
scripts/review-start.sh --profile prod --target appsec-multi-vuln
APPSEC_REVIEW_PROFILE=prod appsec-review start --target targets/appsec-multi-vuln
```

```powershell
scripts/stack-restart.ps1 -Profile prod
scripts/review-start.ps1 -Profile prod -Target appsec-multi-vuln
$env:APPSEC_REVIEW_PROFILE = "prod"; appsec-review start --target targets/appsec-multi-vuln
```

The exact prod values, the allowlist, the effect on fingerprints and the model contract, and what to
do when a work account names a model differently are in
[`docs/operations/model-profiles.md`](docs/operations/model-profiles.md).

## Prepare an end-to-end run

A review host runs a new end-to-end review in this order. Record the commit of every result (`git
rev-parse HEAD` in this repository and in the target), and do not pull, reinstall or switch branches
in a checkout while a run or test suite uses it.

1. Update this checkout to `origin/main` and reinstall into its own `.venv`; confirm the import path
   as shown in the setup section.
2. Check out the target at the commit pinned in the evaluator lock
   ([Download the acceptance target](#download-the-acceptance-target)).
3. Build and smoke every enabled image, acquiring inputs first where needed
   ([Build the tool container images](#build-the-tool-container-images)). Record new image IDs in
   their pins on that host.
4. Sync third-party metadata if it is older than you want
   ([Sync third-party metadata](#sync-third-party-metadata)).
5. Run the nothing-to-find review on the pinned images
   ([End-to-end review of a target with nothing to find](#end-to-end-review-of-a-target-with-nothing-to-find)).
   It must pass: a finding on that target is a false positive to fix, and a failed job is a break to
   fix, before a real review is trusted.
6. Start the review ([Run a review](#run-a-review) or the Dagster `wave1_review` job) and leave the
   checkout and target alone until it finishes.

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
writable (acquisition creates checkouts there and builds write their outputs into the checkout),
and the default review target is `/opt/app/targets/appsec-multi-vuln`. To review a
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

Launch the full review graph through the guarded operator script. It prints a Dagster UUID and an
application run id; replace `DAGSTER_UUID` below with the printed UUID. See the
[startup feature and flag reference](docs/operations/review-startup.md) to choose the target,
profile, capacity overlay or first-error policy.

```bash
scripts/review-start.sh
scripts/review-watch.sh --run DAGSTER_UUID
python deploy/dagster/bin/verify.py --run-id DAGSTER_UUID --evidence runs/metadata/dagster-verification/DAGSTER_UUID.json
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

Install the host test dependencies first (`python -m pip install -e ".[test]"`; add `.[dagster]`
for the Dagster tests). Pytest keeps its temporary and cache state under `test/tmp/` (configured in
`pyproject.toml`). Tests that need the acceptance target expect `targets/appsec-multi-vuln`, the
Dagster tests are skipped when the `dagster` extra is not installed, and live or image-dependent
tests are skipped, naming what is missing, until the opt-in requirements in the
[Software inventory](#software-inventory) are met.

```bash
python -m pytest -q
```

Use a named base directory beneath `test/tmp/` for focused or concurrent sessions:

```bash
python -m pytest -q tests/test_static_adapters.py --basetemp=test/tmp/static-adapters
```

### End-to-end review of a target with nothing to find

`tests/integration/test_nothing_review.py` runs the review graph that `appsec-review start` runs
(the CLI graph filtered by each job's `settings.enabled`) through `GraphRunner` against a benign
repository it creates under its base directory: `README.md`, `greeter.py`, `src/add.c` and a
`CMakeLists.txt`, committed with a fixed author and date. No live model is called: a replay
transport stands in for the configured providers, reports every configured model available and
answers the planning request with the CMake recipe. The test's configuration copy disables
`job_image_pin_verification`; every other job is the registered job. Both tiers assert that every enabled
job has an accepted handoff (or, in the first tier, a named reason it could not run), that missing
coverage is a named gap and makes its job `COMPLETED_WITH_GAPS` rather than `SUCCEEDED`, that every
evidence tool has a disposition with a reason when it did not run, that the accepted index holds no
security observation, that the run-bound configuration, the hash-pinned guidance bundles and every
handoff artifact verify, and that the dataset publication audit has no violation.

- **No-Docker tier** (runs anywhere, about a minute). A `docker` stub that reports an unreachable
  daemon is first on `PATH`, so the tier behaves the same on a host with images. A job that needs a
  container image (or only the handoff of such a job) is recorded with the image it named, removed,
  and the same run is resumed.

  ```bash
  python -m pytest -p no:cacheprovider tests/integration/test_nothing_review.py \
    -k without_container_images --basetemp=test/tmp/nothing-review
  ```

- **Full tier** (any Linux or WSL 2 Docker host with the pinned images built from this repository). It uses the real Docker
  daemon, runs the whole graph in one pass, requires every job to finish, and asserts that every
  scanner that ran observed nothing. It skips, naming what is missing, when the daemon, an enabled
  catalog tool image or a build-profile image is unavailable.

  ```bash
  python -m pytest -p no:cacheprovider tests/integration/test_nothing_review.py \
    -k with_pinned_images --basetemp=test/tmp/nothing-review-full -rs
  ```

A security observation on this target is a false positive in the rule that raised it; report the
rule rather than changing the target.

Run long suites in a dedicated worktree with its own `.venv`
(`git worktree add ../appsec-review-<name> <commit>`) rather than in a checkout another session or
a review uses.

Run the deployment test suite in its pinned image:

```bash
docker build --file deploy/dagster/Dockerfile --target test --tag appsec-review-dagster-test .
docker run --rm appsec-review-dagster-test
```

## Working with other agent sessions

Several agent sessions (cloud sessions, sessions on review hosts, Codex) may change, build and test
this repository at once. GitHub is their shared record: claim work early with a draft pull request,
keep pull requests small, merge `origin/main` before pushing, and never rebase or force-push a
shared branch. Host-specific values have single owners: image pins belong to the session on the
review host that built and smoked those images, asset locks to the session that acquired them, and
target checkouts to the repository owner. The procedure is
[`.claude/skills/multi-session-coordination/SKILL.md`](.claude/skills/multi-session-coordination/SKILL.md).

After a batch of merged pull requests, reconcile the docs with the code delta recorded in
[`docs/docs-sync.json`](docs/docs-sync.json) using
[`.claude/skills/docs-sync/SKILL.md`](.claude/skills/docs-sync/SKILL.md).

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
[`docs/operations/retrieval-mcp.md`](docs/operations/retrieval-mcp.md). It serves external clients;
review cells reach the same tools in-process (see
[`docs/architecture/retrieval-surfaces.md`](docs/architecture/retrieval-surfaces.md)).
