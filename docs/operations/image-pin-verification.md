# Image-pin verification and the host image procedure

The review pipeline never builds a container image. The operator builds images on the review host
and pins them; every review then verifies, before any target work starts, that the local Docker
daemon still holds exactly the pinned images. This document is the one place that describes both.

## The gate: `job_image_pin_verification`

`job_image_pin_verification` (Dagster name `image_pin_verification`) runs directly after
`job_model_connectivity` and before `job_review_intake` in the direct CLI graph and in every
composite Dagster graph (`wave1_review`, `ci_configuration_review`, `project_build_review`).

```text
model_connectivity -> image_pin_verification -> review_intake -> ...
```

Like the model gate, the job executes on every graph dispatch, including a resume, and its handoff
orders downstream jobs without entering their semantic identity.

### What it checks

The job reads `containers/catalog.toml` and the run's frozen configuration
(`runs/<run-id>/data/configuration/appsec-review.toml`), both present in the packaged Dagster image.
It needs no builder, Dockerfile or build context, and it runs only
`docker image inspect <tag> --format {{.Id}}`, once per distinct tag, through the injectable command
runner. The checked pins are:

- every `enabled` image in `containers/catalog.toml`: its tag must resolve to its `image_id` when the
  entry has one, and must at least be present when it has none. An entry marked `manual = true` is built
  and run by hand (today `tool-report-latex`), no pipeline job depends on it, and the check skips it;
- every enabled job's `tag`/`image_id` pair, which today means each
  `[jobs.job_project_build.settings.profiles.<family>]` build profile;
- every enabled job's `source_image_tag`/`source_image_id` pair, which today means CodeQL's
  `[jobs.job_codeql_analysis.settings]` source image.

A disabled job's pins are not checked, because the job will not run.

| Unit | Responsibility |
| --- | --- |
| `selection.resolve_pins` | Collect the pins and record `image-pin-plan.json` with the catalog and frozen-configuration hashes. |
| `verification.inspect_images` | Inspect every tag, classify every pin, and record `image-pin-verification.json`. |
| `publication.publish_handoff` | Publish `image-pin-verification-handoff.json` with every pin, its pinned ID, its resolved ID and status. |

Each pin is recorded as `matched`, `present` (an unpinned catalog image exists), `mismatched` (the tag
moved to another image), `missing` (Docker reports no such image) or `inspect_failed` (Docker could not
be asked, or timed out after 60 seconds).

### Any mismatch fails the run

A missing or moved tool image is never a recorded gap. When any pin is `mismatched`, `missing` or
`inspect_failed`, the unit raises, the job fails, and no later job can start. The error message, the
run log event `IMAGE_PIN_VERIFICATION_FAILED` (level `ERROR`) and the verification record name every
failing pin on its own line:

```text
containers/catalog.toml images.tool-semgrep.image_id: tag appsec-review/tool-semgrep:1.178.0 pinned <unpinned> resolved missing
jobs.job_project_build.settings.profiles.native.image_id: tag audit-buildenv-cpp:local pinned sha256:f685... resolved sha256:0b1c...
jobs.job_codeql_analysis.settings.source_image_id: tag audit-codeql:custom-2.27.0 pinned sha256:3344... resolved missing
```

To recover, follow the host procedure below, then resume the run. Resume reruns the gate and reuses
accepted downstream work.

### Configuration

`[jobs.job_image_pin_verification.settings]` has one typed key, `enabled`. `false` makes the job
transparent: intake then depends directly on `model_connectivity`. Any other key fails configuration
loading. Unit tests inject a fake runner and never call Docker.

## Host procedure: rebuild, re-pin, reload

Run these steps on the review host, from the repository checkout, never during a running review: a
rebuild moves tags on the shared daemon that a live run may be using.

1. **Rebuild the images** with the deterministic builder. It validates the catalog, builds base
   images before the images that use them, and writes per-image logs and `summary.json` under
   `runs/container-builds/<builder-run-id>/`:

   ```bash
   python3 containers/build.py build <image-id> [<image-id> ...] [--jobs N] [--continue-on-error]
   python3 containers/build.py build --all     # every enabled catalog image
   ```

   Smoke the rebuilt images (`python3 containers/build.py smoke <image-id>`) before pinning them.

   After rebuilding a CodeQL image, fully compile its query packs to prove they plan in the new
   image. This fills the shared compile cache review runs mount (keyed by the declared CodeQL
   release and runtime user), so no review run compiles cold afterwards:

   ```bash
   python3 containers/build.py query-packs --warm
   ```

2. **Re-pin** every configured pin to the image its tag now resolves to on the local daemon:

   ```bash
   appsec-review update-image-pins          # print the planned edits only
   appsec-review update-image-pins --write  # apply them
   ```

   The command collects the same pins as the gate, inspects each tag, and for each pinned tag that
   moved replaces the one quoted image ID on the line that owns the pin in `containers/catalog.toml`
   or `appsec-review.toml`. Formatting, comments and line endings are untouched, and the edited file is
   re-parsed to prove that only the planned values changed. A pinned tag that is missing or cannot be
   inspected is `unresolved`, a pin whose line cannot be located unambiguously is `manual`, and an
   enabled unpinned catalog image that is missing is listed under `unpinned_missing`. The command
   exits non-zero in any of those cases. It never adds a pin to an unpinned catalog entry; that is a
   reviewed edit. Review the diff and commit it. Only the session on the review host that built the
   images changes these pins (see `.claude/skills/multi-session-coordination/SKILL.md`).

3. **Rebuild and reload the Dagster code location**, so the packaged image carries the new pins and
   the gate checks against them, then prove the workspace reconnected:

   ```bash
   python deploy/dagster/bin/lifecycle.py build
   python deploy/dagster/bin/lifecycle.py reload
   python deploy/dagster/bin/verify.py
   ```

Images move forward rather than reproduce bit for bit, so a rebuild normally yields new image IDs and
therefore a re-pin (see [`containers/README.md`](../../containers/README.md#moving-forward-not-reproducing)).
