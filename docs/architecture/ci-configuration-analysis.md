---
title: "Static CI configuration analysis"
kind: "architecture"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_ci_configuration_analysis"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Static CI configuration analysis

`job_ci_configuration_analysis` is a source-only review lane. It accepts the immutable target catalog, discovers a fixed set of native CI definition paths, classifies providers, fans out provider/tool tasks, normalizes observations, attaches conservative pipeline/workflow/stage/job/step context, publishes one immutable observation shard per tool branch, performs exact-only correlation, and joins coverage deterministically.

The lane never contacts a CI controller or provider API. It never evaluates YAML, Groovy, or Kotlin DSL, never loads Jenkins or TeamCity plugins, never expands generators, never starts a build, and never executes commands found in a pipeline. External linters run only through the pinned container executor with no network, a read-only target, non-root identity, dropped capabilities, bounded resources, and an explicit cataloged file argument. A failed or unavailable tool emits a coverage gap while sibling branches continue.

GitHub Actions routes to pinned Zizmor offline mode, Checkov's `github_actions` framework, pinned actionlint, and bounded structural rules. Azure Pipelines, GitLab CI, CircleCI, and Bitbucket Pipelines route to their explicit Checkov frameworks plus bounded structural validation. Jenkins and TeamCity Kotlin use source-backed structural parsing and reviewed rules; controller, plugin, generator, extension, and dynamic scripted semantics remain named gaps. Other recognized CI definitions are classified as `supported_discovery_without_linter`.

Raw output remains hash-bound run-owned evidence; bounded normalized observations are the retrieval
surface, not arbitrary raw-payload access. Canonical records merge only identical provider, path,
source span, category and normalized-message keys. Ambiguous source mappings must also match
their byte ranges and mapping provenance; similar or merely co-located observations are not merged.
Observation fingerprints bind snapshot, normalized artifact and hierarchy, provider/tool/framework,
ruleset, settings and parser/normalizer/mapping identities. Canonical evidence fingerprints bind the
exact correlation document. The [canonical job page](../operations/job_ci_configuration_analysis.md)
records the current native Zizmor/Checkov mapping and strict originating-unit gap contract.

Structured failure fallbacks do not override an active execution-safety stop. Publication's own
success also does not erase the scan-unit gaps carried in the verified outcomes.

The public target repository is blind. Target-specific expected findings, vulnerable locations, remediation, and scoring material belong only to the separate evaluator guide and must never be mounted into or indexed by a review run.
