---
title: "Operating CI configuration analysis"
kind: "operations"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_ci_configuration_analysis", "job_target_catalog"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# Operating CI configuration analysis

`job_ci_configuration_analysis` is a source-only review lane running after `job_target_catalog`
(enforced by the standard Dagster review graph). It accepts the immutable target catalog, discovers
a fixed set of native CI definition paths, classifies providers, fans out provider/tool tasks,
normalizes observations, attaches conservative pipeline/workflow/stage/job/step context, publishes
one immutable observation shard per tool branch, performs exact-only correlation, and joins
coverage deterministically. Configuration lives under `[jobs.job_ci_configuration_analysis]` in
`appsec-review.toml`, including provider routing, worker counts, bounds, correlation identity, and
reviewed ruleset identity.

Provider `tools` lists select only the already-declared branches; an empty list disables that
provider's scans. Omitted provider settings retain the central adapter defaults. Disabled branches
keep their task and shard declarations, report `CONFIGURED_DISABLED`, and carry
`disabled_by_configuration` through raw output, indexing and coverage. They never resolve images,
read scan inputs, or launch linters. Coverage describes the configured work, not execution of disabled
tools. The discovery-only `other` provider uses the configured tool name
`supported_discovery_without_linter`. Unknown settings, providers or tools, duplicate tool names,
non-integer bounds, and unsupported framework/ruleset/correlation identities are rejected at job
admission. Frameworks must match their provider's wired Checkov adapter; the supported identities
remain `ci-static-reviewed-rules/1` and `exact-only/1`. Changing an identity does not select a new
implementation.

The lane never contacts a CI controller or provider API. It never executes YAML, Groovy, or Kotlin
DSL, never loads Jenkins or TeamCity plugins, never expands generators, never starts a build, and
never executes commands found in a pipeline; all commands in target definitions are inert data.
Before a live run, build the enabled pinned images for Zizmor, Checkov, and actionlint using the
repository container process. External linters run only through the pinned container executor with
no network, a read-only target, non-root identity, dropped capabilities, bounded resources, and an
explicit cataloged file argument. Missing images do not trigger downloads: the affected branch
records an unavailable-tool gap and the other provider/tool branches continue. Structured failure
fallbacks do not override an active execution-safety stop, and publication's own success does not
erase the scan-unit gaps carried in verified outcomes.

GitHub Actions routes to pinned Zizmor offline mode, Checkov's `github_actions` framework, pinned
actionlint, and bounded structural rules. Azure Pipelines, GitLab CI, CircleCI, and Bitbucket
Pipelines route to their explicit Checkov frameworks plus bounded structural validation. Jenkins
and TeamCity Kotlin use source-backed structural parsing and reviewed rules; controller, plugin,
generator, extension, and dynamic scripted semantics remain named gaps. Other recognized CI
definitions are classified as `supported_discovery_without_linter`.

Accepted outputs include:

- a deterministic CI definition and provider catalog;
- raw and normalized per-tool artifacts;
- conservative hierarchy data;
- immutable `observations/ci_*` shards;
- an immutable `evidence/ci_findings` shard;
- exact-only canonical findings;
- the canonical `lead_candidate` subset as handoff `security_findings`, consumed by review
  prioritization as leads rather than final adjudicated vulnerabilities;
- a coverage join naming every missing or partial provider/tool branch, plus a separately
  counted `not_applicable_inputs` summary.

Raw output remains hash-bound run-owned evidence; bounded normalized observations are the retrieval
surface, not arbitrary raw-payload access. Canonical records merge only identical provider, path,
source span, category and normalized-message keys. All source mappings, precise or ambiguous, must
also match their byte ranges, provenance, method, confidence and ambiguity; similar or merely
co-located observations are not merged. Canonical records retain contributor byte spans and mapping
identity rather than reconstructing exact matches as whole-line excerpts. Native actionlint columns
survive normalization and deduplication, but do not by themselves establish byte offsets or a column
encoding. Without byte offsets, indexed locations are explicitly ambiguous line ranges and retain
native coordinates in `producer_location`. Invalid explicit byte spans fail instead of being clipped
and mislabeled exact.
Observation fingerprints bind snapshot, normalized artifact and hierarchy, provider/tool/framework,
ruleset, settings and parser/normalizer/mapping identities. Canonical evidence fingerprints bind the
exact correlation document.

For GitHub workflow block mappings, structural context uses actual job IDs directly beneath `jobs`
and step sequence items beneath each job's `steps`, not those container names as invented jobs.
Job/step ranges contain observations only within their lexical boundaries, including named steps
and block-scalar commands; another job's last step cannot leak into subsequent observations.
Block-scalar command text is inert, not hierarchy syntax. Other providers retain conservative
latest-preceding structural context. This is not alias expansion or dynamic CI semantics.

External linters receive only definitions their declared input support accepts
(`appsec_review.tool_inputs`): actionlint and Checkov's `github_actions` framework read workflow
files under `.github/workflows/`, while Zizmor also reads `.github/actions/**/action.yml`
definitions. A definition outside a linter's support is `SKIPPED_NA` for that linter and never
launched; when none remain the branch is `NOT_APPLICABLE` without a gap. A supported definition on
which a linter fails stays a gap. Before image resolution or external execution, source bytes are
admitted against `max_file_bytes`. Static scanning, hierarchy and indexed source-location reads use
the same bounded read (at most the limit plus one overflow-detection byte), including when a file
grows after its size check. Indexed source hashes use those same bytes. An input over the bound is
not scanned; a later over-bound source-location read fails rather than publishing an invented span.

Gaps are `producer-gap/1` records declared by the unit that found them (`strict_gaps`): a pinned image
missing from the local daemon is `producer_blocked` (retryable) on the scan unit; a linter exception
or an exit code outside its accepted set is `producer_failed` scoped to the definition; an
over-`max_file_bytes` definition and a cataloged definition with no enabled linter are
`producer_reported_gap` scoped to the definition; unreadable/invalid UTF-8 static or hierarchy
input, malformed native linter output and invalid source mappings are `parser_error`; the
`max_files` and `max_observations_per_tool` bounds are `truncated`. Executor stdout/stderr truncation
flags and report files exceeding the wired tool's `output_bytes` limit also produce `truncated`;
report files are bounded before parsing, independently of executor capture. Normalization, indexing, coverage
and publication declare no gaps of their own — they carry the scan records as payload
(`scan_gap_records`, `gap_records`) so the handoff counts each gap once — and the published handoff
keeps the human reasons under `gaps` with `gap_count` and `coverage_status`. Native reports are parsed
atomically: invalid UTF-8/JSON, malformed records, Checkov parsing-error reports, and error-shaped
objects cannot become complete zero-finding scans. actionlint's JSONL must have no malformed lines.
Empty-result shape is adapter-specific: native Zizmor requires an array, so `[]` is empty while `{}`
is a parser error; actionlint and Checkov retain silent output, `{}` and `[]` compatibility on exit 0.
Checkov result envelopes must contain a `failed_checks` array. A missing report or actionlint/Checkov
exit 1 without findings is a parser gap, not an empty success. Non-retryable failure
records are not advisory. See the [canonical process and acceptance checks](job_ci_configuration_analysis.md).
The job's events are `CI_DEFINITIONS_DISCOVERED`,
one `CI_TOOL_SCANNED` per provider/tool branch, and `CI_ANALYSIS_PUBLISHED`.

Use the MCP `query_ci_configuration` tool to filter accepted shards by provider, pipeline, workflow, stage, job, step, tool, rule, category, canonical finding, or shard. Source excerpts remain hash-verified through the ordinary retrieval API.

The public target repository is blind: target-specific expected findings, vulnerable locations,
remediation, and scoring material belong only to the separate evaluator guide and must never be
mounted into or indexed by a review run. For benchmark evaluation, complete the review first. Then
start a separate evaluator with the accepted run mounted read-only and the guide repository mounted
separately. Never expose the guide checkout to review workers, tool containers, retrieval indexing,
MCP, or prompts. Any guide path or answer prose appearing in a run artifact is an oracle-leak failure.
