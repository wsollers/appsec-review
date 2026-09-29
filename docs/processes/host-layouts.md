# Host layouts: zarathustra (Linux), hal5000 (Windows + WSL)

The same repository runs on two machines. Only the start paths and the Docker engine differ; nothing
inside a job may depend on the host (ADR-0011). `zarathustra` is the primary host for the ADR-0013
target runs.

| | zarathustra | hal5000, WSL side | hal5000, Windows side |
|---|---|---|---|
| OS | Ubuntu 24.04 LTS, native | Ubuntu-24.04 under WSL 2 (`nat` networking) | Windows |
| Role | Primary: stack, code location, all runs | Stack host for Windows: code location and operator commands | Docker Desktop, PowerShell launcher, Windows clone |
| Repo | `/mnt/projects-drive/projects/appsec-review` (`~/projects` is a symlink to `/mnt/projects-drive/projects`) | `~/projects/appsec-review` (distro filesystem) | `F:\repos\appsec-review` (`/mnt/f/repos/appsec-review` from WSL) |
| Docker | Docker Engine (`docker.service`), root `/var/lib/docker` | Docker Desktop through WSL integration; no native `docker.service` in the distro | Docker Desktop, the only engine |
| Code location | `orchestrator/dagster/code-location.sh start`, binds `0.0.0.0:4000` | `code-location.sh start`, binds the distro's `eth0` IP (rewritten into `.env` on every WSL restart) | `orchestrator\dagster\code-location.ps1` runs `code-location.sh` inside WSL |
| Python | `/usr/bin/python3.12`, venv `~/.venvs/appsec-review-dagster` | same layout inside the distro | not used for jobs (Dagster needs POSIX modules) |

## Common to every host

- **One Docker engine.** Compose project `appsec-review` (services `webserver`, `daemon`,
  `postgres`; volumes `appsec-review_dagster-storage`, `appsec-review_postgres-data`). Other projects'
  containers on the same engine (for example `lra-ingestion-harness`) are never touched.
- **Ports.** Webserver `127.0.0.1:3000`, PostgreSQL `127.0.0.1:55432`, code location gRPC `4000`
  (containers reach it as `host.docker.internal:4000`).
- **Host packages.** Python 3.12 with `python3.12-venv`, `git`, `libfuzzy2` (the evidence index loads
  `libfuzzy.so.2`), the operator in the `docker` group, the `claude` CLI logged in (persona jobs use
  its subscription login).
- **Host-local state, never in Git and never copied between hosts.** Rebuild or re-sync it on each
  host; `orchestrator/prepare-host.sh` does this.

  | Path | What | Recreated by |
  |---|---|---|
  | `images/.build-state/` | successful image builds (image ids differ per host) | `images/image_build.py build <id>` |
  | `appsec-review-process/registry/container-images/*.json` | B16 image records | generated at code-location start |
  | `appsec-review-process/offline/dependency-snapshots/` | Grype/OSV snapshot registry | `dependency_snapshot_sync.py` |
  | `appsec-review-process/runs/` | engagement runs and their evidence | `run_process.py --start` |
  | `appsec-review-process/data/build-images/` | per-target build images | `02-build-resolution` |
  | `fixtures/targets/` | target clones at pinned commits | `fixtures/populate-targets.sh` |
  | `orchestrator/dagster/.env`, `.host/` | instance password, uid/gid, DAGSTER_HOME, compute logs | `orchestrator/dagster/setup.py`, `code-location.sh prepare` |
  | `data/feeds/nvd/` mutable state | NVD feed snapshots | `nvd_reference_schedule` |
  | `data/feeds/osv/`, `data/feeds/mitre/` | OSV and MITRE ATT&CK/CAPEC feed snapshots ([mitre-feed](../mitre-feed.md)) | `nvd_reference_schedule`, `mitre_feed.py sync` |

- **Runs are not portable.** A run started on one host is resumed on the same host.

## zarathustra (native Linux)

- 16 cores, 30 GiB RAM. Repo drive `/mnt/projects-drive` (ext4, NVMe, ~790 GB free); Docker root on
  `/` (~650 GB free). Extra drives under `/media/wsollers/` (`extradrive1`, `extradrive12`).
- `.env` carries `APPSEC_UID` / `APPSEC_GID`, so the compose services run as the operator and
  bind-mounted files stay owned by `wsollers` (see `orchestrator/dagster/README.md`, "Native Linux
  host").
- The code location binds `0.0.0.0:4000`, which is reachable from the LAN (`192.168.1.228`); the
  webserver and PostgreSQL stay on `127.0.0.1`.
- `prepare-host.sh` starts the code location in the background with its log at
  `orchestrator/dagster/.host/code-location.log`; stop it with
  `pkill -f 'dagster code-server start'`.
- Also on this host: Codex worktrees under `~/.codex/worktrees/` and
  `/mnt/projects-drive/projects/appsec-review-*`, plus many prunable `/tmp/appsec-*` worktrees
  (`git worktree prune` clears the missing ones). They share the one Docker engine but not the
  stack; only the main clone runs the code location.
- `libfuzzy2` is not installed yet (2026-09-27): `sudo apt install libfuzzy2`.

## hal5000, WSL side

- Distro `Ubuntu-24.04`, WSL 2 `nat` networking. Docker Desktop's host gateway is the Windows host,
  which WSL does not forward port 4000 to, so `code-location.sh` binds the distro's own IP and keeps
  `APPSEC_CODE_LOCATION_HOST` in `.env` current; when it changes, recreate the containers with
  `docker compose -f orchestrator/dagster/compose.yaml up -d webserver daemon` (ADR-0011 addendum
  2026-09-22).
- Exactly one engine: `systemctl is-active docker` must print `inactive`, and
  `docker info --format '{{.OperatingSystem}}'` must print `Docker Desktop` (ADR-0011 addendum
  2026-09-23). A native `docker.service` left running in the distro wedged Docker Desktop three times.
- Recovery from a wedged Docker Desktop: Ctrl+C the code location, `wsl --shutdown` from Windows,
  restart Docker Desktop, `code-location.sh start`, `docker compose ... up -d`, `code-location.sh
  reload`.
- The Windows clone is also visible here as `/mnt/f/repos/appsec-review`; runs use the distro
  clone `~/projects/appsec-review` (the Windows filesystem is slow from WSL and has different
  ownership).
- `scripts/sync_wsl.sh [BRANCH]` (default `main`) resets that clone to `origin/BRANCH`. It
  stashes local changes first; `git stash pop` brings them back.

## hal5000, Windows side

- Docker Desktop, with Ubuntu enabled under Settings, Resources, WSL integration.
- `F:\repos\appsec-review` is the Windows clone. It is used for Windows-side editing and agents,
  not for running the stack. Untracked leftovers there (`Claude outputs/`,
  `scripts/scancode-toolkit-src/`) are not part of the repo.
- `.\orchestrator\dagster\code-location.ps1 [-Command start|prepare|check] [-Distro Ubuntu-24.04]`
  runs the code location inside WSL; keep that window open while the stack runs.
- A Windows-native build of DOOM-3-BFG (MSVC / clang-cl, ADR-0003) is outside the current flow; on
  both hosts its build runs in Linux containers and is expected to produce build gaps.
