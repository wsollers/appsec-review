# Target analysis planning operations

The planner runs automatically after `job_target_catalog` and before evidence collection in the
`wave1_review` Dagster graph. Its accepted artifact is:

`runs/<run-id>/data/jobs/job_target_analysis_plan/attempts/<attempt-id>/artifacts/analysis-plan/accepted-analysis-plan.json`

Inspect `scanner_selections`, `scanner_non_selections`, `build_topology`, `contradictions`, and
`coverage_gaps` together. A skipped or unavailable family is not evidence that the target is clean.
Mandatory baseline scanners remain selected whenever they have applicable catalog inputs;
otherwise their non-selection is explicit.

Model settings are centralized under `[jobs.job_target_analysis_plan.settings.model]` in
`appsec-review.toml`. The shipped configuration uses the bounded Anthropic Messages adapter and
requires `ANTHROPIC_API_KEY` at execution time. The runtime stores exact guidance and model identity beneath
`runs/<run-id>/data/guidance/<sha256>/`, and logs only hashes, identity, counts, duration, retries,
status, and token counts. It does not log prompts, source content, or model output.

On provider failure or proposal rejection, the job completes with gaps and publishes its
deterministic safe plan. A framework integrity failure—changed catalog bytes, escaped paths,
corrupt manifests, invalid baseline suppression, or an unverified index—fails the job and stops
downstream publication. Resume the same run after correcting the integrity problem; immutable
catalog and plan identities allow unaffected jobs and shards to be reused.

The accepted plan is directly retrievable from the `analysis` index through the bounded MCP tools.
No new glob, regex, SQL, shell, or filesystem endpoint is needed.

## Isolated project builds

`job_project_build` consumes only the accepted, hash-verified plan. Each language family is an
independent Dagster branch, so a slow or failed family does not block retained artifacts from the
others. Every recipe runs as direct argv in its pinned build image with no network, a read-only
container root, a non-root user, dropped capabilities, and bounded resources. The accepted handoff
and build artifacts are stored beneath the run's `data/build/` tree.

Resume is per build unit. A checkpoint is reused only when the target snapshot, validated recipe,
pinned image, executor contract, and artifact hashes still match. Missing dependencies, build
failures, and recipes that require network are explicit coverage gaps; they do not erase successful
siblings and are never reported as clean coverage.
