# Operating CI configuration analysis

Run this job after `job_target_catalog`; the standard Dagster review graph enforces that order. Configuration lives under `[jobs.job_ci_configuration_analysis]` in `appsec-review.toml`, including provider routing, worker counts, bounds, correlation identity, and reviewed ruleset identity.

Before a live run, build the enabled pinned images for Zizmor, Checkov, and actionlint using the repository container process. Missing images do not trigger downloads: the affected branch records an unavailable-tool gap and the other provider/tool branches continue. All commands in the target definitions are inert data.

Accepted outputs include:

- a deterministic CI definition and provider catalog;
- raw and normalized per-tool artifacts;
- conservative hierarchy data;
- immutable `observations/ci_*` shards;
- an immutable `evidence/ci_findings` shard;
- exact-only canonical findings;
- a coverage join naming every missing or partial provider/tool branch.

Use the MCP `query_ci_configuration` tool to filter accepted shards by provider, pipeline, workflow, stage, job, step, tool, rule, category, canonical finding, or shard. Source excerpts remain hash-verified through the ordinary retrieval API.

For benchmark evaluation, complete the review first. Then start a separate evaluator with the accepted run mounted read-only and the guide repository mounted separately. Never expose the guide checkout to review workers, tool containers, retrieval indexing, MCP, or prompts. Any guide path or answer prose appearing in a run artifact is an oracle-leak failure.
