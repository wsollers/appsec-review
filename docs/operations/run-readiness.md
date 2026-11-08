# Run readiness: preparing a host for review runs

The one-time preparation of a review host, after which the fix–test–restart loop never rebuilds an
image. It is Phase 0 of T-057 (`docs/TODO.md`). Everything here is operator-run on the host; nothing
in it is executed by jobs or agents. Each step names the document that owns its details.

## Decisions this runbook fixes

- **The review host is WSL (Ubuntu) on HAL5000, and the Docker daemon is the in-WSL engine
  (`default` context), the standard already decided for this host.** Images live in a daemon's store,
  not in a shell: an image built against the `default` engine is invisible to Docker Desktop's
  (`desktop-linux`) and the reverse, so a Windows-side `docker images` will not list them — that is
  expected. Build, pin, sign and run against the one daemon, and check `docker context show` and
  `docker images` after every reboot: the active context has changed silently before. Windows is the
  editor; the Windows stack (`appsec-review-dagster-windows`, `docs/operations/signing.md`, "Windows
  hosts") is not used for review runs.
- **The checkout the stack mounts lives on WSL ext4**, never under `/mnt/c` or `/mnt/f`
  (`docs/architecture/deployment-image-and-source-mount.md`, "Host requirements"): the application
  image mounts `src`, `scripts`, `containers`, configuration, rules and schemas read-only from it,
  and the Windows file bridge is far too slow for a mounted package. Keep it a clone that tracks
  `main`; `F:\repos\appsec-review` stays the editing checkout.
- **Image enforcement stays `disabled` for the first runs.** Module signing of the mounted sources is
  on by default and needs the key at `start`/`reload`; container-image verification
  (`[signing] image_enforcement = "required"`) is turned on once the loop works, so a signing
  refusal is never mistaken for a run break. Sign the images anyway (step 4) so the switch is one
  configuration line later.

## What triggers a rebuild afterwards

| Change | Action | Rebuild? |
| --- | --- | --- |
| Any file in the release closure: `src`, `appsec-review.toml`, `profiles`, `rules`, `pipeline`, `docs/schemas`, `scripts`, `containers/*.toml` | `lifecycle.py reload` (seconds), then `plan-repair` / `admit-repair` / `resume` | no |
| `deploy/dagster/requirements*.txt`, a provider CLI pin, `src/appsec_review/signing/*` (the verifier) | `scripts/stack-rebuild` | application image only |
| A tool image recipe: its `Dockerfile`, `tool.toml`, `assets.lock.json`, catalog tag | `containers/build-all.sh build <id>`, `smoke <id>`, re-pin, re-sign | that tool image only |
| A CodeQL image or any graph-export QL | the above, then `scripts/compile-codeql-queries.sh` | that image; recompile the cache |

The loop (`docs/operations/recovery-repair.md`) therefore contains no `docker build`.

## Steps

1. **Host and checkout.** In WSL: `docker context show` names the chosen daemon; the checkout is on
   ext4 (`df -T .` shows `ext4`, not `9p`/`drvfs`); `core.autocrlf` is off so signed bytes match
   (`.gitattributes` pins LF). Python 3.13 with this checkout's dependencies in `.venv`; OpenSSL 3 at
   `/usr/bin/openssl`.
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

   An image that fails for a reason unrelated to the run (a moved asset URL, say) is **disabled in
   configuration for the first run and recorded in the task doc**, not fixed now; T-050 is where
   catalog work lives. Readiness means a host that can start a run, not a complete catalog.
4. **Re-pin and sign** (`docs/operations/image-pin-verification.md`, "Host procedure"). Pins are
   host-local (T-051): the committed IDs name whichever host last pinned.

   ```bash
   appsec-review update-image-pins            # plan
   appsec-review update-image-pins --write    # apply; commit as its own "host re-pin" commit
   appsec-review signing sign-image --all-pinned --private-key ~/.config/appsec-review/signing/private/operator.pem
   ```

   The re-pin commit carries no code change, so the loop can tell a pin move from a fix.
5. **Compile the CodeQL query packs** into the shared cache the runs mount
   (`docs/operations/codeql-analysis.md`, "Compiling CodeQL queries"); a first run without it stalls
   cold in `job_codeql_analysis` with no error to read.

   ```bash
   scripts/compile-codeql-queries.sh
   ```

6. **Target — and its identity, which is currently inconsistent.** `targets/appsec-multi-vuln`
   (`docs/operations/test-targets.md`), `APPSEC_REVIEW_TARGET=/opt/app/targets/appsec-multi-vuln`
   in `deploy/dagster/.env`. The first runs use this target only — it is the smallest with an
   expectations key. CASTLE waits for a working loop.

   Three records disagree about which commit that is, and `stepwise.py accept --tag` refuses unless
   the target's `HEAD` equals the tag's commit: `test-targets.md` and the evaluator lock pin
   `29943842cc0c…`; `test/acceptance/cpp-multivuln-v1/expectations.toml` says the corpus is at
   `9acaa34035af…`; and on 2026-11-08 the remote carried **no tag `cpp-multivuln-v1` at all** (only
   `appsec-multi-vuln-c094-v1`). Reconcile in the target repository before the stack starts, in this
   order: confirm which commit holds the seven seeded defects the key describes
   (`git -C targets/appsec-multi-vuln merge-base --is-ancestor 9acaa340 29943842`, and read the key's
   paths at each); tag that commit `cpp-multivuln-v1` and push the tag; make `expectations.toml`
   `commit`, `test-targets.md` and the lock agree with it in one commit here. Never substitute one
   identity for another silently — the acceptance provenance records the tag and commit.
7. **Stack** (`docs/operations/operator-scripts.md`). `scripts/stack-rebuild.sh` once (builds the
   tooling-only application image), then `scripts/stack-start.sh`, which checks health, the overlay
   and model connectivity. From here on, `scripts/stack-restart.sh --code-location-only` is the
   reload.
8. **Gate run.** `python deploy/dagster/bin/stepwise.py init --target /opt/app/targets/appsec-multi-vuln`
   and `stepwise.py next` through `job_model_connectivity` and `job_image_pin_verification`. These two
   jobs have been through the job pass (`docs/tasks/2026-11-08-job-pass-01-…`, `…-02-…`) and are the
   two whose verdict on the host can be trusted. **Readiness is done when both accept.**

## Out of scope

Windows build containers (MSVC image, compile capture, the Windows native host: T-041, T-042, T-043,
T-049) are not needed for a Linux target and are not part of readiness. The first runs are
Linux-only; the Windows family follows once the loop works on Linux.
