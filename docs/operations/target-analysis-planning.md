# Target analysis planning operations

The planner runs automatically after `job_target_catalog` and before evidence collection in the
`wave1_review` Dagster graph. Its accepted artifact is:

`runs/<run-id>/data/jobs/job_target_analysis_plan/attempts/<attempt-id>/artifacts/analysis-plan/accepted-analysis-plan.json`

Inspect `scanner_selections`, `scanner_non_selections`, `build_topology`, `contradictions`, and
`coverage_gaps` together. A skipped or unavailable family is not evidence that the target is clean.
Mandatory baseline scanners remain selected whenever they have applicable catalog inputs;
otherwise their non-selection is explicit.

Model settings and worker count are centralized under `[jobs.job_target_analysis_plan.settings.model]`
in `appsec-review.toml`. Build-recipe inference is partitioned by language family and build system,
then executed through the configured bounded worker pool. Every request composes the DevOps Engineer
persona with a language-specialized Build Engineer role and only the build units in that partition.
The shipped configuration uses the bounded Anthropic Messages adapter and requires
`ANTHROPIC_API_KEY` at execution time. The runtime stores exact guidance and model identity beneath
`runs/<run-id>/data/guidance/<sha256>/`, and logs only hashes, identity, counts, duration, retries,
status, and token counts in the central log. Bounded raw provider responses—including rejected
responses—are retained as run-owned diagnostic artifacts beside the inference task so malformed
model output can be debugged; credentials are never written there. Repair calls receive only the
rejected textual output and validation errors, not the provider envelope or hidden metadata.

On provider failure or proposal rejection, the job completes with gaps and publishes its
deterministic safe plan. A framework integrity failure—changed catalog bytes, escaped paths,
corrupt manifests, invalid baseline suppression, or an unverified index—fails the job and stops
downstream publication. Resume the same run after correcting the integrity problem; immutable
catalog and plan identities allow unaffected jobs and shards to be reused.

The accepted plan is directly retrievable from the `analysis` index through the bounded MCP tools.
No new glob, regex, SQL, shell, or filesystem endpoint is needed.

## Isolated project builds

`job_project_build` consumes only the accepted, hash-verified plan. Each language family has four
explicit phases: resolve or build its project image, publish its static-analysis dispatch, probe
buildability, and publish its downstream language-build dispatch. Static dispatch depends only on
the accepted plan, so it can proceed while project images and probes are still running. In the
composed Dagster graph the concrete evidence-collection job likewise branches immediately after
planning; it does not wait for compiled analysis.

A project image is derived from the hash-pinned language baseline. Its identity covers the recipe,
baseline image, generator contract, and dependency-file hashes. Supported dependency restoration
occurs only while building that image; the actual probe has no network, uses direct argv, a read-only
container root, a non-root user, dropped capabilities, and bounded resources. Images are reused only
when both their manifest and runtime image identity still match. Language-specific dependency cache
locations are embedded in the derived image so a no-network probe consumes the restored Cargo, Go,
Maven/Gradle, NuGet, npm, Composer, or Python dependencies. Project images use a digest-pinned
Buildx/BuildKit client and load the result into the local engine. Docker image mutation is narrowly
serialized as an additional engine-safety boundary; the language DAG and static dispatch remain
parallel.

The identity uses the recipe's operational fields; changing only the model's explanatory `reason`
does not rebuild an identical image or invalidate its accepted probe.

The probe answers only whether the accepted recipe can build. A successful probe or a verified
cross-run reuse receipt publishes `lang_jobflow_build`, carrying the recipe, exact project image,
root, family, and requested capabilities. A failed probe publishes a coverage gap and no build
dispatch, but it does not remove that project's static-analysis dispatch or successful sibling
projects. Set `force_buildability_probe = true` in the central project-build settings to bypass the
cross-run probe cache.

Resume is per build unit. An accepted probe is reused only when the enriched recipe identity and
resolved image ID still match. Missing dependencies, unsupported restoration, and build failures
are explicit coverage gaps; they do not erase successful siblings and are never reported as clean
coverage. Accepted dispatches and probe artifacts are stored beneath the run's `data/build/` tree;
shared image/probe acceptance metadata is stored beneath `runs/metadata/`.
