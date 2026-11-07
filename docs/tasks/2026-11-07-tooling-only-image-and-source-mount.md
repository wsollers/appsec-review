# TASK - TOOLING-ONLY DAGSTER IMAGE WITH A MOUNTED SOURCE CHECKOUT

User direction, quoted: "The inner loop is too slow ... Docker images should have tooling only
they should mount the src build and my python." Goal stated by the user: "start a review and if it
faults fix the broken piece and resume from there", with the fix-test-restart interval measured in
seconds, not an image build.

This supersedes the deployment-coupling constraint written into
`docs/tasks/2026-11-06-recovery-repair-admission.md` ("current application code is baked into
images ... Do not claim hot reload exists"). That constraint was an implementation package's
conservative default, not a product decision; the user has now decided the opposite. It also
supersedes the `AGENTS.md` sentence that limited mounts to job/task scripts.

## Problem

At `42dee4d3` the Dagster image did `COPY src ... && pip install --no-deps . && python -m
appsec_review.runtime.release` at build time, and signed-module enforcement pointed
`APPSEC_REVIEW_MODULE_ROOT` at `site-packages`. Every application-code change required
`lifecycle.py build` (sign modules, `docker build`, sign image, verify image), `reload`,
`plan-repair`, `admit-repair`, `resume`. On WSL2 Docker that is a many-minute cycle per fault; a
first run against a polyglot monorepo produces dozens of faults. The repository's own lifecycle
rule ("minimize the fix-test-restart interval", `AGENTS.md`) was unachievable.

Root cause of the coupling: the module-signing design assumed verified bytes must live in an image
layer. The import hook verifies bytes against an envelope and does not care where they come from.

## Required outcome (acceptance criteria)

1. The Dagster image is tooling only: interpreter, pinned dependencies, Docker client, provider
   CLIs, signing verifier. `appsec_review` is not importable inside the bare image; the build fails
   if it is.
2. Compose mounts the checkout's release closure (`release-dependencies.json`) read-only at
   `/opt/app`; `PYTHONPATH=/opt/app/src`; `APPSEC_REVIEW_MODULE_ROOT=/opt/app/src/appsec_review`.
3. `implementation-release.json` is measured at launch from the mounted tree by the code-location
   start command and written to `/var/dagster/release/`; every service and `docker compose exec`
   CLI reads it through `APPSEC_REVIEW_RELEASE_MANIFEST`. Attempts still pin their own copy.
4. Signed-module enforcement is preserved: `lifecycle.py start`/`reload` sign the checkout into
   `deploy/dagster/signing/python-modules.json` and verify it before launching; the directory is
   mounted read-only; the final stages keep `APPSEC_REVIEW_REQUIRE_SIGNED_MODULES=1`.
5. A development host can opt out per launch with `APPSEC_UNSIGNED_MODULES=1` (warning printed;
   image still verified). Never the default.
6. Image identity (`APPSEC_REVIEW_IMAGE_ID`) and source identity are recorded separately in
   `deployment_identity`; a code edit changes only the latter.
7. The repair cycle is: edit → focused unit tests → `lifecycle.py reload` → `plan-repair` →
   `admit-repair` → `resume`, with **no `docker build`**. Rebuild is required only for
   `requirements*.txt`, provider CLI pins, or `src/appsec_review/signing/*`.
8. Docs state the above truthfully: `recovery-repair.md`, `quality-and-retention.md`,
   `signing.md`, `deploy/dagster/README.md`, `README.md`, `AGENTS.md`, and the new
   `docs/architecture/deployment-image-and-source-mount.md`.

## Implementation record (this task, worktree `feature/tooling-only-image`, base `42dee4d3`)

Changed:

- `deploy/dagster/Dockerfile`: `runtime-base` no longer copies sources, installs the package or
  builds the release; sets `PYTHONPATH`, `APPSEC_REVIEW_RELEASE_MANIFEST`, module root on the
  mount; creates mount points; asserts `appsec_review` is not importable. Final stages set the
  signature path and `REQUIRE=1` without copying an envelope. `test` stage copies sources (it runs
  without mounts) and measures its own manifest with `--verify-assets`.
- `deploy/dagster/compose.yaml`: read-only mounts of the release closure and
  `deploy/dagster/signing` on the service anchor and, because YAML merge keys do not merge lists,
  repeated on `code-location`; `APPSEC_REVIEW_RELEASE_MANIFEST`, `APPSEC_REVIEW_IMAGE_ID`,
  `APPSEC_REVIEW_REQUIRE_SIGNED_MODULES=${APPSEC_SIGNED_MODULES:-1}` and
  `APPSEC_REVIEW_MODULE_SIGNATURE=${APPSEC_MODULE_SIGNATURE-...}` in the environment anchor;
  code-location command gains the launch step between the self-check gate and `dagster code-server`.
- `deploy/dagster/bin/lifecycle.py`: `build` no longer signs modules; `start`/`reload` sign and
  verify the checkout (or skip with a warning under `APPSEC_UNSIGNED_MODULES=1`), create the
  envelope directory, and pass `APPSEC_SIGNED_MODULES`/`APPSEC_MODULE_SIGNATURE` to Compose; a
  signing failure is `REFUSED` (exit 3).
- `deploy/dagster/bin/host.py`: `LAUNCH_COMMAND`. `deploy/dagster/bin/smoke.py`: the config check
  requires the launch step after the gate.
- `src/appsec_review/runtime/release.py`: `MANIFEST_ENV`, `manifest_path()`, `load_release` reads
  the configured location; `main` gains `--verify-assets` and `--exec COMMAND...` (measure, then
  `execvp`); `verify_deployment_assets()` carries the former image-build checks.
- `.gitignore`: `/deploy/dagster/signing/` (directory). `deploy/dagster/.env.example`:
  `APPSEC_UNSIGNED_MODULES`.
- Docs listed in criterion 8.
- Tests: `tests/test_dagster_signing.py` rewritten for the new contract (tooling-only Dockerfile,
  mounted closure on every image service, build signs no sources, launch signs, unsignable
  checkout refuses, unsigned development launch); new `tests/test_release_manifest_location.py`.

Verification (Linux, Python 3.13 venv with `.[test]`, `--basetemp=test/tmp/mount-*`):

- `tests/test_dagster_signing.py tests/test_repair_admission.py tests/test_wave1_resume.py
  tests/test_job_runtime.py tests/test_handoff_interchange.py tests/signing
  tests/test_release_manifest_location.py`: 584 passed, 2 skipped, 39 s.
- Pre-existing, unrelated failure on unmodified `main` in this environment:
  `tests/test_wave1_resume.py::test_catalog_path_index_accepts_structured_inventory_gaps`
  (deselected here; reproduces at `42dee4d3` without these changes).

Not run (manual, operator-authorized): `docker build --target runtime`, `lifecycle.py start`, an
edit + `reload` + `plan-repair` + `resume` cycle on a real stack, `deploy/dagster/bin/smoke.py`,
`tests/integration/signing/*`, `tests/integration/test_repair_workflow.py`. The first stack start
on HAL5000 after this change needs: a WSL-ext4 checkout (not `/mnt/f`), the signing key available
at `start` time (or `APPSEC_UNSIGNED_MODULES=1` while iterating), and one `lifecycle.py build` to
produce the tooling image.

## Follow-ups

- `tests/integration/signing/test_module_signing_container.py` builds its own fixture image that
  still mirrors the old `site-packages` layout; it tests the hook and remains valid, but a variant
  that mounts the package would mirror production.
- `scripts/stack-rebuild*` help text still describes rebuilding for code changes; update when the
  scripts are next touched.
