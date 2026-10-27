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
| `command_timeout_seconds` | 1800 | per probe command |
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
`appsec-review/build-image-repair/2` proposal
([schema](../schemas/build-image-repair.schema.json)). The request carries `repair_options`, the
closed vocabulary for that unit. A proposal is typed data in four parts, each the complete set for
the next attempt, and must differ from the current repair set:

| Part | Bound | Applied as |
| --- | --- | --- |
| `system_packages` | 0-64 apt package specifiers | exec-form `apt-get install` in the derived image |
| `environment` | 0-16 names from the family allowlist, each value matching that name's pattern | `ENV` before every restore, and merged into the recipe environment the probe and language build pass |
| `package_manager` | `null`, or a manager the family image pins (Node: npm, pnpm 9.15.9, Yarn 1.22.22) | the lockless Node restore; refused when a lockfile fixes the manager or the recipe runs another manager |
| `dependency_restores` | 0-8 accepted dependency files | a restore by the family's own manager, built by code, run in the manifest's directory while the image builds |

The environment allowlist (`REPAIR_ENVIRONMENT` in `src/appsec_review/jobs/job_project_build/repair.py`)
comes from the failures real builds hit: `PIP_BREAK_SYSTEM_PACKAGES`, `PIP_NO_BUILD_ISOLATION`,
`PIP_PREFER_BINARY`, and `SETUPTOOLS_SCM_PRETEND_VERSION` for Python; npm peer/engine/fund settings,
`YARN_IGNORE_ENGINES`, and a bounded `NODE_OPTIONS=--max-old-space-size=N` for Node; Cargo git
fetch, retry, multiplexing, and job settings; `MAVEN_ARGS` limited to plugin `*.skip=true`, test
skips, compiler source/target/release levels, and wagon retries; MSBuild warning, analyzer,
end-of-life, and locked-restore properties for .NET; `GOFLAGS` limited to `-mod=` and
`-buildvcs=false`, and `CGO_ENABLED` for Go; Composer platform-requirement, no-dev, and timeout
settings for PHP. Names that pick URLs, registries, credentials, toolchain downloads, or checksum
databases are absent, and a repair cannot overwrite a variable the accepted recipe already sets.

Restorable manifests are those whose dependencies land where the later build reads them: any
accepted `requirements*.txt` (pip into `/opt/project-deps`), `Cargo.toml`, `go.mod`/`go.work`,
`pom.xml`, Gradle build or settings file, and .NET project or solution; for Node only the
manifest or lockfile at the dependency root; for Composer only the unit's own `composer.json`. Node
restores keep `--ignore-scripts`, Composer keeps `--no-scripts --no-plugins`, and Maven keeps
`-DskipTests`. There is no free-form command, path, URL, or Dockerfile text in a proposal.

The applied repair is recorded on the recipe as `image_repairs` (environment, package manager, and
normalized restores with their manager), so it is part of the recipe identity, the Dockerfile,
every attempt record, the build dispatch, and the repair cache. `validate_build_recipe` re-checks
it whenever the recipe is reused. Commands, paths, dependency files, outputs, base image, and
container policy cannot change. Each attempt rebuilds the image, re-probes it, and is recorded with
its outcome; invalid output, failed installation, timeout, and compiler failure each consume one
attempt.

Probe preparation is family-local and remains inside the run-owned workspace. For Maven units with
a bounded legacy `src/*.java` source set, no conventional `src/main/java` tree, and no
`<build><sourceDirectory>` in the pom, project-build materializes a duplicate conventional tree in that workspace before running the accepted Maven
recipe; the target is not changed and the adaptation is recorded on the probe receipt. A pom that
names its source directory already finds its sources, and a second copy would compile each class
twice, so it is left as is. For a
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

Derived image manifests use `appsec-review/project-build-image/2` and live under a run-private
namespace in `runs/metadata/project-images/`. Reuse requires operator-declared `platform` and
`build_toolchain` releases. Target dependency and effective recipe changes invalidate the image;
unrelated query declarations do not. Supplied generator/Dockerfile payloads are not fingerprinted:
`dockerfile_sha256` remains null, and the owner must update the relevant release declaration when
the generator or build environment changes. Missing declarations disable image reuse.
Under review admission, creation of an unavailable derived image is a named
`derived_image_preparation_unavailable` gap until the operator supplies a resource-bounded
builder with confirmed cancellation. No such builder contract is currently approved. This does
not silently substitute the baseline image when the recipe requires dependency preparation.
Eligible declared prepared images remain usable; platform image preparation is separate work.

A repaired image that passes is accepted in
`runs/metadata/project-build-repairs/<run-scoped-identity>/accepted.json`
(`appsec-review/build-image-repair-cache/1`). Same-run reuse requires declared `platform`,
`build_toolchain` and `validation` releases, an unchanged target snapshot and base recipe, and
matching capture/limit settings. It revalidates the target recipe and resolves the image; a changed
image ID repeats the probe sequence. Accepted probes use equivalent run-scoped identities under
`runs/metadata/project-probes/`. Missing releases emit `CHECKPOINT_MISSED` rather than allowing
an early hit. Another application run does not inherit these probe or repair checkpoints.

## Outputs and recovery

Probe workspaces and captures live under `runs/<run-id>/data/build/probes/<build-unit-id>/`; the
dispatch document is under the attempt's `artifacts/project-build/`. A probe receipt lists each
changed output with a role `kind` from the typed `ArtifactKind` vocabulary and its container
`format` (`elf`, `ar`, `pe`, `macho`, `wasm`, `zip`, ...) separately, and counts CMake and Cargo
build bookkeeping under `excluded_bookkeeping` instead of listing it (see
[`language-build.md`](language-build.md)). A failed probe, a disabled or
unavailable repair model, or exhausted repairs is a named gap and publishes no build dispatch for
that unit; static dispatch and sibling units continue. Resume the same run: accepted probes are
reused only when the release, target and run bindings, recipe identity and resolved image ID still
match. An invalid repair cache
or a changed accepted repair identity fails the task instead of being silently rebuilt.
