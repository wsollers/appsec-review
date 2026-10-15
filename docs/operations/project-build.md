# Project-build operations

`job_project_build` consumes only the accepted, hash-verified target analysis plan and turns its
build recipes into project images, buildability probes, and dispatches for downstream jobs. The
planning-side narrative is in [`target-analysis-planning.md`](target-analysis-planning.md); the
consumer is [`language-build.md`](language-build.md). Capture semantics are in
[`../architecture/build-environments-and-execution-capture.md`](../architecture/build-environments-and-execution-capture.md).

## Steps

The configured topology must be exactly `plan`, `image`, `static_dispatch`, `probe`,
`build_dispatch`, `acceptance`; a mismatch fails configuration validation.

| Step | Tasks | Purpose |
| --- | --- | --- |
| `plan` | `load_recipes` | load the accepted plan and validated recipes |
| `image` | one per family | resolve or build the derived project image |
| `static_dispatch` | `global` plus one per family | publish `lang_jobflow_static` dispatches; depends only on `plan` |
| `probe` | one per family | run the accepted recipe under capture against the image |
| `build_dispatch` | one per family | publish `lang_jobflow_build` dispatches for successful probes |
| `acceptance` | `publish_handoff` | write `accepted-project-build-dispatch.json` (`appsec-review/project-build-dispatch/2`) |

Families are `native`, `rust`, `go`, `java`, `node`, `dotnet`, `python`, `php`, and `wasm`; each
needs a `settings.profiles.<family>` entry with a pinned `tag`, `image_id`, and non-root `user`.

## Settings

`[jobs.job_project_build.settings]` (shipped values):

| Key | Default | Meaning |
| --- | --- | --- |
| `command_timeout_seconds` | 600 | per probe command |
| `image_build_timeout_seconds` | 1800 | per project-image build |
| `output_bytes` | 8388608 | in-memory stream preview; complete streams are retained |
| `artifact_count_limit` | 10000 | cataloged probe artifacts |
| `force_buildability_probe` | false | Boolean; bypass the cross-run probe cache |
| `repair_attempts` | 3 | integer 3-10; image-repair attempts after a failed default probe |
| `build_capture.event_count_limit` | 250000 | job override of the global `[build_capture]` limit |
| `build_capture.retain_raw_traces` | true | keep secret-scanned, hashed raw strace files under `raw-traces/` (debug period; see language-build.md) |
| `build_capture.raw_trace_bytes_limit` | 67108864 | retained raw-trace bytes per command; truncation is flagged in `record.json` |

`settings.model` must define exactly `enabled`, `provider`, `model`, `reasoning`,
`max_input_tokens`, `max_output_tokens`, and `timeout_seconds` (positive integers for the limits).
It configures only image repair.

## Recipe validation

Every recipe, including a repaired one, passes `validate_build_recipe` in
`src/appsec_review/jobs/build_discovery.py`. `image_profile` must equal the deterministic
`required_image_profile` supplied to inference. This normally equals the language family; an
accepted `com.android.application` Gradle unit remains in the Java family but requires the Android
profile. `source_dir` must equal the build-unit root, and outputs stay beneath it. Commands are argv arrays
(at most 16 per list, 128 arguments each) without shell operators, and `argv[0]` must be a bare
name in that profile's `_PROFILE_COMMANDS` allowlist (for example `go` only for Go, `dotnet` and
`msbuild` for .NET). Test, run, and install subcommands, non-build Maven goals or Gradle tasks, and
secret-like environment names are rejected.

## Default-image-first probing and repair

Each unseen recipe is probed against the default family image first. If it fails and the model is
enabled, the job copies the exact generated Dockerfile and bounded diagnostics into
`repair-NNN/` under the probe task, sends an `appsec-review/build-image-repair-request/1` summary
with the runtime skill `pipeline/skills/build-image-repair/SKILL.md` guidance, and accepts only an
`appsec-review/build-image-repair/1` proposal: a new, unique apt package set (1-64 packages) and a
reason. Commands, paths, environment, dependency files, outputs, base image, and container policy
cannot change. Each attempt rebuilds the image, re-probes it, and is recorded with its outcome;
invalid output, failed installation, timeout, and compiler failure each consume one attempt.

Probe preparation is family-local and remains inside the run-owned workspace. For Maven units with
a bounded legacy `src/*.java` source set and no conventional `src/main/java` tree, project-build
materializes a duplicate conventional tree in that workspace before running the accepted Maven
recipe; the target is not changed and the adaptation is recorded on the probe receipt. For a
networked Node recipe whose configure phase already runs `npm ci`/`npm install`, `pnpm install`, or
`yarn install`, the probe does not expose the immutable image-owned `node_modules` tree. The
package manager restores into the writable workspace and uses bounded `/tmp` caches. Node recipes
without an explicit restore continue to receive the image-owned dependency view. The language
build applies the same rule, so a recipe's own installer never meets the read-only image tree.

Recipe normalization marks a Node recipe `network_required` whenever the unit's own `package.json`
declares `dependencies`, `devDependencies`, or `optionalDependencies`, even without a lockfile. The
derived image then runs the script-disabled lockless restore (`npm install --ignore-scripts`), so a
TypeScript build resolves the declared `typescript` and `@types/*` packages instead of failing with
TS2688. The Node build image is defined in `containers/buildenv/typescript/`.

Concurrent image-repair telemetry identifies `family`, `root`, `build_system`, `build_unit_id`, and
`repair_number`. Operators must use those correlation fields rather than adjacent log order when
multiple family lanes repair simultaneously.

A repaired image that passes is accepted in
`runs/metadata/project-build-repairs/<base-recipe-identity>/accepted.json`
(`appsec-review/build-image-repair-cache/1`). A later run with the same base recipe identity
revalidates that recipe and Dockerfile identity and reuses the image; a changed image ID repeats
the probe sequence. Accepted probes are cached under `runs/metadata/project-probes/`.

## Outputs and recovery

Probe workspaces and captures live under `runs/<run-id>/data/build/probes/<build-unit-id>/`; the
dispatch document is under the attempt's `artifacts/project-build/`. A failed probe, a disabled or
unavailable repair model, or exhausted repairs is a named gap and publishes no build dispatch for
that unit; static dispatch and sibling units continue. Resume the same run: accepted probes are
reused only when the recipe identity and resolved image ID still match. An invalid repair cache
or a changed accepted repair identity fails the task instead of being silently rebuilt.
