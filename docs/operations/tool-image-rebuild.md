# Tool image rebuild

`job_tool_image_rebuild` (Dagster name `tool_image_rebuild`) rebuilds the container images the
review uses as tools before any target work starts. It runs directly after
`job_model_connectivity` and before `job_review_intake` in the direct CLI graph and in every
composite Dagster graph (`wave1_review`, `ci_configuration_review`, `project_build_review`).

```text
model_connectivity -> tool_image_rebuild -> review_intake -> ...
```

Like the model gate, the job executes on every graph dispatch, including a resume, and its handoff
orders downstream jobs without entering their semantic identity. Docker's layer cache keeps an
unchanged rebuild cheap.

## What it runs

The job drives the deterministic builder `containers/build.py` and never calls Docker itself:

```text
<python> containers/build.py build <image ids...> --jobs <parallelism> \
  --timeout-seconds <image_timeout_seconds> [--continue-on-error]
```

The builder validates `containers/catalog.toml`, builds dependencies (base images) before the images
that use them, and writes its own per-image fetch and build logs plus `summary.json` under
`runs/container-builds/<builder-run-id>/`.

| Unit | Responsibility |
| --- | --- |
| `selection.resolve_images` | Read the catalog, resolve the configured selection and its dependencies in catalog dependency order, and record `tool-image-plan.json` with the catalog and builder hashes. |
| `build.build_images` | Run the builder once with the whole selection, keep its stdout/stderr, copy its summary, and record one receipt per image. |
| `publication.publish_handoff` | Publish `tool-image-rebuild-handoff.json` naming every rebuilt image and its digest. |

On success, `build_images` writes under its unit root
(`runs/<run-id>/data/jobs/job_tool_image_rebuild/attempts/<attempt>/steps/build/tasks/build_images/`):

- `receipts/<image-id>.json`: image id, tag, kind, dependency order, resulting image ID
  (`docker image inspect` digest), build duration, build/fetch log paths, Dockerfile and assets-lock
  hashes, and base identity;
- `tool-image-rebuild.json`: the command, exit status, duration, and every receipt;
- `builder-summary.json`, `builder-stdout.log`, `builder-stderr.log`.

## Failure fails the run

A missing tool image is never a recorded gap. The unit raises, the job fails, and no later job in
the review can start when any of these holds:

- an image's builder result is not `passed` (failed, blocked by a failed dependency, or skipped),
  or it has no resolved image ID;
- the builder exits non-zero, exceeds `total_timeout_seconds`, or cannot be started;
- the builder reports no summary, or its results do not match the catalog dependency order;
- a configured image id is unknown or not `enabled` in the catalog.
- with `pin_mismatch = "fail"` (not the default), a rebuilt image ID differs from a configured pin (see below).

The error message, the run log event `TOOL_IMAGE_REBUILD_FAILED` (level `ERROR`), and
`tool-image-rebuild-failure.json` in the unit root name the failed image ids, the builder command,
the exit status, a bounded tail of builder stderr and stdout, the path of each failed image's build
log and of the builder summary, and the tail of each failed image's build log. Read the full log at
the named `runs/container-builds/<builder-run-id>/logs/<image-id>.build.log`.

## Image-ID pins

Some consumers pin an image tag to an exact image ID: catalog entries with `image_id`, the
project-build profiles (`jobs.job_project_build.settings.profiles.<family>.tag`/`image_id`), and
`source_image_tag`/`source_image_id` settings such as CodeQL's. A rebuild that is not bit-for-bit
reproducible yields a new image ID, which those consumers' own pin checks would reject later.

`selection.resolve_images` collects every pin, from the catalog and from enabled jobs' settings in the
run's frozen configuration, whose tag this run rebuilds. After a successful build, each pin is
recorded on its image receipt as `matched` or `mismatched`. With `pin_mismatch = "report"` (default)
the mismatch is recorded in the receipts and handoff and logged as `TOOL_IMAGE_PIN_MISMATCH`, and the
consuming job's own pin check decides. With `"fail"` a mismatch fails the run before intake, naming
each stale pin, its pinned ID, and the rebuilt ID. Pins whose tag is not rebuilt (for example a
profile naming a deferred catalog image) are not checked here.

### Updating pins

`update-image-pins` turns one run's mismatched pins into exact edits of `containers/catalog.toml`
and `appsec-review.toml`:

```bash
appsec-review update-image-pins --run-id <run-id>          # print the planned edits only
appsec-review update-image-pins --run-id <run-id> --write  # apply them
```

It reads the rebuild record of the run's latest attempt, and for each mismatched pin replaces the one
quoted image ID on the line that owns that pin. Formatting and comments are untouched, and the edited
file is re-parsed to prove that only the planned values changed. By default each tag's local image
must already be the rebuilt image (`docker image inspect`); a pin whose local image differs is
`refused`. `--no-image-check` skips that check. A pin whose line cannot be located unambiguously is
reported as `manual`. The command exits non-zero when any pin is refused or manual. Review the diff
and commit it; the next run then records the pins as `matched`.

To recover, fix the image (or the Docker host) and rebuild it directly with
`python3 containers/build.py build <image-id>`, then resume the run. Resume reruns the rebuild gate
and reuses accepted downstream work.

## Configuration

`[jobs.job_tool_image_rebuild.settings]` in `appsec-review.toml` is typed and validated at load;
unknown keys and out-of-range or wrongly typed values fail configuration loading.

| Setting | Meaning |
| --- | --- |
| `enabled` | `false` makes the job transparent: intake then depends directly on `model_connectivity`. |
| `images` | Catalog image ids to rebuild. Empty (the shipped value) selects every `enabled` catalog image, including the deprecated `tool-joern`. Dependencies are always built first. |
| `parallelism` | Concurrent docker builds, passed as `--jobs` (1..8). |
| `image_timeout_seconds` | Per-image docker build bound, passed as `--timeout-seconds` (60..14400). |
| `total_timeout_seconds` | Bound on the whole builder run; must be at least `image_timeout_seconds`. |
| `continue_on_error` | Keep building independent images after a failure so one run names every failing image. The job still fails. |
| `pin_mismatch` | `report` (the shipped value) or `fail` (emits `TOOL_IMAGE_PIN_CHECK_FAILED`); see [Image-ID pins](#image-id-pins). All eight keys are required; the loader supplies no defaults. |
| `log_tail_bytes` | Bytes of builder output and of each failed build log kept in the failure report (256..65536). |

The job needs a working Docker host, like the builder. Unit tests inject a fake builder runner and
never call Docker.
