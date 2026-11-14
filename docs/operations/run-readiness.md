---
title: "Run readiness: preparing a host for review runs"
kind: "operations"
subsystem: "images and deployment"
status: "current"
jobs: ["job_codeql_analysis", "job_image_pin_verification", "job_model_connectivity"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Run readiness: preparing a host for review runs

The operator preparation of a review host, after which a routine source-only repair reloads the
measured application sources instead of rebuilding an unchanged tooling image. It is Phase 0 of
T-057 (`docs/TODO.md`). These host procedures are not executed by review jobs and require explicit
operator authorization; this page does not authorize an agent to provision or launch anything.
Each step names the document that owns its details.

## Decisions this runbook fixes

- **A review host is a WSL (Ubuntu) distribution with one Docker daemon, chosen once per machine
  and never switched.** Images live in a daemon's store, not in a shell: an image built against the
  in-WSL engine (`default` context) is invisible to Docker Desktop's engine (`desktop-linux`) and the
  reverse. Which daemon is a per-machine fact — HAL5000 and WSOLLERS1 both use the engine inside the
  distro (`default`, `/var/run/docker.sock`); WSOLLERS1 also has Docker Desktop installed, which is
  where the traps below come from — declared to `run-readiness` with `--docker-context`, which
  refuses to run against any other. Build, pin, sign and run against that
  one daemon, and check `docker context show` after every reboot: the active context has changed
  silently before. Each machine builds and keeps its own full image set (no image transfer between
  hosts); T-051 stores its bindings in ignored `deploy/dagster/host-pins.toml`. Windows is the
  editor; the Windows stack (`appsec-review-dagster-windows`, `docs/operations/signing.md`,
  "Windows hosts") is not used for review runs.
- **The checkout the stack mounts lives on WSL ext4**, never under `/mnt/c` or `/mnt/f`
  (`docs/architecture/deployment-image-and-source-mount.md`, "Host requirements"): the application
  image mounts `src`, `scripts`, `containers`, configuration, rules and schemas read-only from it,
  and the Windows file bridge is far too slow for a mounted package. Keep it a clone that tracks
  `main`; `F:\repos\appsec-review` stays the editing checkout.
- **Image enforcement stays `disabled` for the first runs.** Module signing of the mounted sources is
  on by default and needs the key at `start`/`reload`. A later change to
  `[signing] image_enforcement = "required"` is a separate operator policy decision, not an
  automatic consequence of a working loop. Explicit lifecycle/image verification still checks
  signatures while general launch enforcement is disabled.

### Docker Desktop on the same machine: three traps (WSOLLERS1, 2026-11-08)

`docker context ls` is the first diagnostic when `docker info` fails with `Failed to initialize:
protocol not available` inside WSL:

- **A context with a `npipe:////./pipe/…` endpoint** is Docker Desktop's context for the *Windows*
  CLI, leaked into the distro's `~/.docker/contexts`. A Linux client has no such protocol, so every
  command fails until `docker context use default`; `docker context rm desktop-linux` keeps it from
  being re-selected. The in-distro daemon is the `default` unix socket (`/var/run/docker.sock`,
  `root:docker`; `id -nG` must list `docker`, else `sudo usermod -aG docker $USER` and `wsl --shutdown`).
- **Resource Saver** (Settings → Resources → Advanced) pauses Desktop's VM after N seconds with no
  running container. An image build is many short BuildKit steps with idle gaps, so a 30-second timer
  pauses the daemon mid-session and the CLI fails intermittently. Turn it off on a review host.
- **Container mode**: the tray menu entry "Switch to Linux containers…" means Desktop is in Windows
  mode and every Linux image is offline. The Windows-container family (T-041+) will have to design
  around this: one Desktop install cannot serve both families at once.

## What triggers a rebuild afterwards

| Change | Action | Rebuild? |
| --- | --- | --- |
| Compatible source-only change in the release closure | `lifecycle.py reload`, then `plan-repair` / `admit-repair` / `resume` | no |
| Configuration, host pins, or schema/contract change | reload and start a fresh authorized run; preserve the old run | no |
| `deploy/dagster/requirements*.txt`, a provider CLI pin, `src/appsec_review/signing/*` (the verifier) | `scripts/stack-rebuild` | application image only |
| A tool image recipe: its `Dockerfile`, `tool.toml`, `assets.lock.json`, catalog tag | `containers/build-all.sh build <id>`, `smoke <id>`, re-pin, re-sign | that tool image only |
| A CodeQL image or any graph-export QL | the above, then `scripts/compile-codeql-queries.sh` | that image; recompile the cache |

The loop (`docs/operations/recovery-repair.md`) therefore contains no `docker build`.

## Steps

Steps 1–5 are scripted: `scripts/run-readiness.sh` (`.ps1` on Windows runs it in WSL) runs them in
order, idempotently, logging each to `runs/run-readiness/<timestamp>/`, and stops at the first step that
fails; `--from STEP` resumes, `--dry-run` prints every command
([`operator-scripts.md`](operator-scripts.md#run-readiness)). The steps below are what it does and
why; steps 6–8 are run by hand.

1. **Host and checkout.** In WSL: `docker context show` names this machine's chosen daemon and
   `docker info` answers from it (an engine that is installed but not running fails here: `sudo
   systemctl start docker`, or `sudo service docker start` without systemd); the checkout is on
   ext4 (`df -T .` shows `ext4`, not `9p`/`drvfs`); `core.autocrlf` is off so signed bytes match
   (`.gitattributes` pins LF). The readiness implementation requires Python 3.11 or newer and this
   checkout's own installed `.venv`; the documented deployment/quality baseline is 3.12, with
   the advertised-minimum renderer gap tracked by [T-160](../TODO.md). OpenSSL must be available
   for the configured signing procedure.
2. **Key and anchor** (`docs/operations/signing.md`, "Operator runbook" step 1). Once per operator:

   ```bash
   appsec-review signing keygen
   appsec-review signing export-trust-anchor --into deploy/dagster/trusted-keys   # commit the .pem
   sudo appsec-review signing install-trust-anchors
   ```

3. **Build and smoke every enabled image** (`containers/README.md`, "Build and validation"). Assets
   are fetched over HTTPS and checked against the locks; the builds themselves run with networking
   off. Hours of wall time; run it in parallel with code work, and never during a review run.

   ```bash
   containers/build-all.sh --validate-only
   containers/build-all.sh build --all --jobs 4 --continue-on-error
   containers/build-all.sh smoke --all
   python3 containers/build.py report      # per-image timings, cached/executed steps, critical path
   ```

   Keep the first build's `runs/container-builds/<run-id>/summary.json`: its `metrics.critical_path`
   and `slowest` are the evidence for any later catalog change meant to shorten builds (shared
   build-tool layers, cache export), and the second build's report is the measurement of it.

   Three images (`tool-native-cpp`, `tool-report-latex`, `tool-tree-sitter`) carry host-local assets
   that a catalog `acquire` helper produces on first build (`containers/README.md`, "Assets"); the
   first build on a fresh host therefore runs those helpers, which take minutes and use the network.
   An image that fails for a reason unrelated to the run (a moved asset URL, say) is **disabled in
   configuration for the first run and recorded in the task doc**, not fixed now; T-050 is where
   catalog work lives. Readiness means a host that can start a run, not a complete catalog.
4. **Bind local images and sign** (`docs/operations/image-pin-verification.md`, "Host procedure").
   T-051 keeps recipe tags and asset hashes committed; observed IDs and CodeQL preinstalled runtime
   declarations are host-owned. A missing host file is bootstrapped by the updater, not by copying
   another machine's pins.

   ```bash
   appsec-review update-image-pins            # plan
   appsec-review update-image-pins --write    # atomically write ignored host-pins.toml; no commit
   appsec-review signing sign-image --all-pinned --private-key ~/.config/appsec-review/signing/private/operator.pem
   ```

   The updater validates the full effective configuration before publication. It never rewrites
   recipe files or an existing run. A changed binding requires a fresh run; source-only repair
   admission does not waive frozen-configuration identity. `run-readiness pin` makes no Git commit.
5. **Compile the CodeQL query packs** into the shared cache the runs mount
   (`docs/operations/codeql-analysis.md`, "Compiling CodeQL queries"); a first run without it stalls
   cold in `job_codeql_analysis` with no error to read.

   ```bash
   scripts/compile-codeql-queries.sh
   ```

6. **Target.** `targets/appsec-multi-vuln-c094`, a clone of <https://github.com/wsollers/appsec-multi-vuln>
   checked out **at the tag `appsec-multi-vuln-c094-v1`** (`bd69bfe83fec…`;
   `docs/operations/test-targets.md`). Its key is `test/acceptance/appsec-multi-vuln-c094-v1/expectations.toml`
   (seven defects, seven paired negative controls), verified on 2026-11-08 at the tag and at `main`'s tip
   (`42284599…`), whose `projects/native/case-094` tree is byte-identical to the tag's; the checkout is
   still the tag, because `stepwise.py accept` requires the target's `HEAD` to equal the tag's commit.
   The first runs use this target only. CASTLE waits for a working loop.

   ```bash
   git clone https://github.com/wsollers/appsec-multi-vuln targets/appsec-multi-vuln-c094
   git -C targets/appsec-multi-vuln-c094 checkout appsec-multi-vuln-c094-v1
   ```

   `cpp-multivuln-v1` is not an option: its corpus was a separate local repository that never reached
   GitHub (`test-targets.md`); its tag exists nowhere `appsec-multi-vuln` can see. A host that ran it
   in the past still has a stopped `code-location` container whose settings name it (next step).
7. **Stack** (`docs/operations/operator-scripts.md`). Bootstrap first on a host whose `deploy/dagster/.env`
   is missing or predates a variable the Compose files now require (HAL5000, 2026-11-10: `lifecycle start`
   refused with `APPSEC_RESULT_CACHE_PASSWORD is missing a value: Run deploy/dagster/bin/bootstrap.py
   first`); it is idempotent and keeps every existing value. On Linux/WSL, `claude` must be installed and
   signed in before it (README, "Linux or WSL 2"). Then `stack-rebuild` once (builds the tooling-only
   application image) and `stack-start` **with the target named on the command line**: the stack
   scripts carry the previous `code-location` container's `APPSEC_REVIEW_TARGET`, overlay and recording
   settings forward (even from a stopped container, so a `--target` choice is never silently reverted),
   and those override `.env`. Name the target, drop the overlay, choose the recording mode once; later
   restarts carry them.

   ```bash
   .venv/bin/python deploy/dagster/bin/bootstrap.py
   scripts/stack-rebuild.sh
   scripts/stack-start.sh --target appsec-multi-vuln-c094 --overlay none --recording record
   ```

   `stack-start` checks health, the overlay and model connectivity. From here on,
   `scripts/stack-restart.sh --code-location-only` is the reload. `--recording record` keeps the model
   exchanges of the first runs for replay; `off` is the default when nothing is carried. Ubuntu has no
   `python` command: use `.venv/bin/python` (or `python3`) for every script here.
8. **Gate run.**

   ```bash
   .venv/bin/python deploy/dagster/bin/stepwise.py init --target /opt/app/targets/appsec-multi-vuln-c094
   .venv/bin/python deploy/dagster/bin/stepwise.py next     # job_model_connectivity
   .venv/bin/python deploy/dagster/bin/stepwise.py next     # job_image_pin_verification
   ```

   These two jobs have been through the job pass (`docs/tasks/2026-11-08-job-pass-01-…`, `…-02-…`) and
   are the two whose verdict on the host can be trusted. **Readiness is done when both accept.**

## Out of scope

Windows build containers (MSVC image, compile capture, the Windows native host: T-041, T-042, T-043,
T-049) are not needed for a Linux target and are not part of readiness. The first runs are
Linux-only; the Windows family follows once the loop works on Linux.
