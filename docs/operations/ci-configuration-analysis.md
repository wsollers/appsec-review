---
title: "Operating CI configuration analysis"
kind: "operations"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_ci_configuration_analysis", "job_target_catalog"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
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
- a coverage join naming every missing or partial provider/tool branch, plus a separately
  counted `not_applicable_inputs` summary.

External linters receive only definitions their declared input support accepts
(`appsec_review.tool_inputs`): actionlint and Checkov's `github_actions` framework read workflow
files under `.github/workflows/`, while Zizmor also reads `.github/actions/**/action.yml`
definitions. A definition outside a linter's support is `SKIPPED_NA` for that linter and never
launched; when none remain the branch is `NOT_APPLICABLE` without a gap. A supported definition on
which a linter fails stays a gap.

Gaps are `producer-gap/1` records declared by the unit that found them (`strict_gaps`): a pinned image
missing from the local daemon is `producer_blocked` (retryable) on the scan unit; a linter exception
or an exit code outside its accepted set is `producer_failed` scoped to the definition; an
over-`max_file_bytes` definition and a cataloged definition with no enabled linter are
`producer_reported_gap` scoped to the definition; unreadable/invalid UTF-8 static or hierarchy
input, malformed native linter output and invalid source mappings are `parser_error`; the
`max_files` and `max_observations_per_tool` bounds are `truncated`. Normalization, indexing, coverage
and publication declare no gaps of their own — they carry the scan records as payload
(`scan_gap_records`, `gap_records`) so the handoff counts each gap once — and the published handoff
keeps the human reasons under `gaps` with `gap_count` and `coverage_status`. Empty-result shape is
adapter-specific: native Zizmor requires an array, so `[]` is empty while `{}` is a parser error;
generic object adapters do not manufacture an observation from `{}`. Non-retryable failure
records are not advisory. See the [canonical process and acceptance checks](job_ci_configuration_analysis.md).
The job's events are `CI_DEFINITIONS_DISCOVERED`,
one `CI_TOOL_SCANNED` per provider/tool branch, and `CI_ANALYSIS_PUBLISHED`.

Use the MCP `query_ci_configuration` tool to filter accepted shards by provider, pipeline, workflow, stage, job, step, tool, rule, category, canonical finding, or shard. Source excerpts remain hash-verified through the ordinary retrieval API.

For benchmark evaluation, complete the review first. Then start a separate evaluator with the accepted run mounted read-only and the guide repository mounted separately. Never expose the guide checkout to review workers, tool containers, retrieval indexing, MCP, or prompts. Any guide path or answer prose appearing in a run artifact is an oracle-leak failure.
