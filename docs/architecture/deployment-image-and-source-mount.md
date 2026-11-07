# Deployment image and source mount

**Status:** Implemented in the Dagster deployment (`deploy/dagster/`) as of 2026-11-07; the direct
(non-Dagster) CLI and the native review host are unchanged.

## Decision

The Dagster application image is **tooling only**. It contains the Python interpreter, the pinned
third-party dependencies (`deploy/dagster/requirements.lock.txt`), the Docker client and BuildKit
plugin, the provider CLIs (Claude, Copilot) and the signing verifier (`sitecustomize` plus the five
root-owned bootstrap modules). It contains **no application sources, configuration, schemas, guidance,
rules, scripts or tool assets**, and the build fails if `appsec_review` is importable inside it.

Everything the application needs from the repository is **bind-mounted read-only from the host
checkout** at `/opt/app`, exactly the release closure that `release-dependencies.json` declares:

| Mount (read-only) | Purpose |
|---|---|
| `src` → `/opt/app/src` | the Python package; `PYTHONPATH=/opt/app/src`, `APPSEC_REVIEW_MODULE_ROOT=/opt/app/src/appsec_review` |
| `pyproject.toml`, `appsec-review.toml`, `release-dependencies.json` | package metadata, typed configuration, release closure |
| `profiles`, `docs/schemas`, `pipeline`, `rules` | model profiles, JSON Schemas, runtime guidance, rule packs |
| `containers`, `scripts`, `tools/cve-bin-tool`, `deploy/dagster/Dockerfile`, `deploy/dagster/requirements*.txt` | tool catalog and runners, operator scripts, declared release inputs |
| `deploy/dagster/signing` → `/opt/appsec-review/signing` | the module envelope signed at launch |

`runs`, `data` and `targets` stay writable mounts as before. The `test` image stage is the one stage
that copies sources, because it runs without Compose mounts.

## Why

The previous image baked `src` in with `pip install .` and ran the release builder at image build.
Every code change — including the one-line fixes a failing review produces — therefore required
`docker build`, re-signing the image, redeploying and re-admitting the repair, a many-minute cycle on
WSL2 Docker. The repository's own working lifecycle ("launch, observe breakage, fix its root cause,
restart; minimize the fix-test-restart interval", `AGENTS.md`) is impossible at that cadence.

The constraint that pushed sources into the image was signed-module enforcement, which was taken
to imply "the bytes must live in an image layer". That is a false dependency: the import hook
verifies *bytes* against a signed envelope and never cares how the bytes arrived. Mounting them
keeps the guarantee and removes the build.

## How identity and trust work now

Two identities are recorded in every attempt's `deployment_identity` (`runtime/repair.py`) and they
change independently:

- **Image identity** (`APPSEC_REVIEW_IMAGE_ID`, set by Compose to the launched
  `APPSEC_REVIEW_DAGSTER_IMAGE`): the tooling image. Changes when dependencies, tools or the verifier
  change. Verified by `lifecycle.py` on the host and by the in-container self-check.
- **Source identity** (`implementation-release.json`, `runtime/release.py`): measured from the
  mounted checkout **at launch**, not at image build. The code-location's start command is
  `container_self_check -- python -m appsec_review.runtime.release --root /opt/app --verify-assets
  --exec dagster code-server start ...`: after the image gate passes, the launch step verifies the
  mounted runtime assets and catalogs, writes the manifest to `/var/dagster/release/` (the
  `dagster-storage` volume; `APPSEC_REVIEW_RELEASE_MANIFEST` points every service and every
  `docker compose exec` CLI command at it) and execs the code server. Changes when any file in the
  release closure changes.

Signed-module enforcement over the mount:

- **Enforced (default).** `lifecycle.py start`/`reload` sign the checkout's `src/appsec_review` into
  `deploy/dagster/signing/python-modules.json` and verify it against the trust anchors *before*
  launching; a signing failure refuses the launch (exit 3). Compose mounts the directory read-only;
  the final image stages set `APPSEC_REVIEW_REQUIRE_SIGNED_MODULES=1` and
  `APPSEC_REVIEW_MODULE_SIGNATURE=/opt/appsec-review/signing/python-modules.json`. Every Python
  process verifies the mounted package against the envelope through `sitecustomize` (exit 78 on
  failure). A module edited after launch therefore **fails closed** in every new process until the
  next `reload`, which is the "keep mounted code fixed for an active review" rule enforced by the
  verifier rather than by an image layer.
- **Development (`APPSEC_UNSIGNED_MODULES=1` in `deploy/dagster/.env` or the shell).**
  `lifecycle.py` skips module signing, prints a warning and launches with
  `APPSEC_REVIEW_REQUIRE_SIGNED_MODULES=0` and an empty signature. The image is still verified and
  launched by exact ID. The operator owns the consequence: after editing sources, run `reload` so
  the measured manifest matches the running code; the repair-admission check
  (`bind_release`) still refuses to restart a run whose recorded release differs from the current
  measurement.

Attempt immutability is unchanged. `bind_release` copies the launch's manifest into
`data/recovery/releases/<sha>.json` and pins it in `data/recovery/current.json`; a later `reload`
writes a new manifest but never rewrites the copy an attempt recorded. Restarting a run under a
changed source identity requires `plan-repair` and `admit-repair`, exactly as before.

## The repair cycle this enables

```text
review faults
  -> appsec-review failure-replay ...            (bounded evidence, no execution)
  -> edit the checkout on the host
  -> run the focused unit tests on the host
  -> lifecycle.py reload                         (re-sign sources, recreate image services: seconds)
  -> appsec-review plan-repair / admit-repair    (new source identity, same image identity)
  -> appsec-review resume
```

No `docker build` appears in the loop. `scripts/stack-rebuild` is needed only when
`requirements*.txt`, a provider CLI pin, or `src/appsec_review/signing/*` (the verifier) change.

## Host requirements

- The mounted checkout must live on a Linux filesystem (WSL ext4 or native Linux). A checkout under
  `/mnt/c` or `/mnt/f` is mounted through the Windows file bridge and is far too slow for a
  mounted package (`AGENTS.md`, Workspace hygiene).
- `deploy/dagster/signing/` is created by `lifecycle.py` and is ignored by git; it must exist for the
  read-only mount to succeed, which `lifecycle.py` guarantees for signed and unsigned launches alike.
- The host signing environment (`APPSEC_SIGNING_PRIVATE_KEY`, trust anchors, OpenSSL, a Python with
  this checkout's dependencies) is now needed at `start`/`reload`, not only at `build`.

## What did not change

- `job_poc_generation`, `job_sanitizer_build` and every other job keep their no-execution rules.
- Tool images (`containers/tools/*`) are unaffected; they were always tooling only.
- The direct CLI (`appsec-review start`/`resume` from a checkout) still reads
  `implementation-release.json` beside the sources; run `python -m appsec_review.runtime.release`
  before a direct run as the operations docs already say.
- The native Windows review host and its signed release layout (`docs/operations/signing.md`,
  Native release) are separate and unchanged.

## Tests

`tests/test_dagster_signing.py` asserts the Dockerfile is tooling only (no `COPY src`, no package
install, no build-time release, `PYTHONPATH` and module root on the mount, `appsec_review` not
importable), that every image service mounts the same read-only closure and the envelope
directory, that `build` signs no sources while `start`/`reload` sign them, that an unsignable
checkout refuses the launch, and that the development flag turns enforcement off with a warning.
`tests/test_release_manifest_location.py` covers `APPSEC_REVIEW_RELEASE_MANIFEST`, the launch
step's measure-then-exec behaviour and its fail-closed cases. The in-container behaviour (a real
build, a real launch, a real reload after an edit) is manual validation through
`deploy/dagster/bin/smoke.py` and an authorized stack start.
