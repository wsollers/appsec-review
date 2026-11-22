---
title: "Task plan T-170: Preserve Semgrep codeFlows deduplicate scanner leads and verify SCA reachability"
kind: "task"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_artifact_indexing", "job_artifact_security_analysis", "job_ci_configuration_analysis", "job_clang_static_analysis", "job_code_graph_index", "job_cpp_compiled_analysis", "job_debug_symbol_indexing", "job_dependency_intelligence", "job_evidence_collection", "job_inference_security_review"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# Task plan T-170: Preserve Semgrep codeFlows deduplicate scanner leads and verify SCA reachability

This plan implements **T-170** (`docs/TODO.md`): upgrading static scanner normalization,
cross-scanner deduplication, supply-chain OSV indexing, FFI/import vulnerable-symbol reachability,
and CI/CD + artifact finding promotion so every scanner produces high-signal, non-redundant,
indexed evidence for downstream review.

## Problem and motivation

- `job_evidence_collection` currently flattens Semgrep and OpenGrep SARIF results to their sink
  location, discarding `codeFlows` / `threadFlows` source-to-sink taint steps that Semgrep already
  computed.
- Per-scanner observation caps truncate distinct vulnerability locations when overlapping rules
  fire repeatedly on the same sink line across Semgrep, OpenGrep, Bandit, Gosec, Brakeman,
  cppcheck, Clang-Tidy, CSA, and Infer.
- `job_dependency_intelligence` defaults to `osv_version_matching = "scan"` (sequentially walking
  snapshot files) rather than indexed lookup, and reports vendored/third-party CVEs with identical
  weight whether or not first-party code imports or calls the affected library symbol (`T-166`).
- `job_ci_configuration_analysis` and `job_artifact_security_analysis` detect high-impact supply-chain
  flaws (such as `pull_request_target` with untrusted PR checkout or privileged container configs)
  without promoting exploitable classes into structured leads.

## Technical design and dataflow changes

1. **Preserve SARIF `codeFlows` and cross-scanner deduplication (`job_evidence_collection`,
   `job_clang_static_analysis`, `job_cpp_compiled_analysis`):**
   - Retain bounded `code_flows` (`source_span`, intermediate propagation steps, `sink_span`) and
     rule `metadata.category` / CWE mappings on normalized scanner observations.
   - Cluster and deduplicate observations across scanners by `(source_id, sink_line_band, cwe_family)`
     **before** applying observation caps, preserving `corroborating_scanners` and boosting
     multi-tool agreement confidence.
   - Add first-party review-signal sink/dangerous-API rules for Rust (`unsafe` pointer/transmute/command
     sinks), Ruby, PHP, and C# so all nine smoke languages receive sink nominations.
2. **Indexed OSV matching & vulnerable-symbol reachability (`job_dependency_intelligence`):**
   - Switch default `osv_version_matching` to `"index"` in `appsec-review.toml` and settings, with
     graceful fallback to `"scan"` only if an older snapshot lacks the SQLite/JSON index.
   - Join accepted shards from `job_code_graph_index`, `job_tree_sitter_ast`, `job_artifact_indexing`,
     and `job_debug_symbol_indexing` to classify each dependency advisory's reachability from
     first-party code as `used` (with resolving first-party import/call/FFI source spans),
     `not_used` (with consulted index receipts), or `unknown` (named `producer-gap/1` when an index
     is unavailable).
3. **Exploitable CI/CD and artifact lead promotion (`job_ci_configuration_analysis`,
   `job_artifact_security_analysis`):**
   - Tag exploitable workflow script injection, `pull_request_target` untrusted code execution,
     unpinned privileged third-party actions, and root/privileged container or secret-bearing
     artifact defects for admission into Lane A verification and executive supply-chain reporting.

## Schema and telemetry specification

```text
New / updated versioned schemas:
- appsec-review/scanner-observation/2      (adds bounded code_flows[], rule_category, corroborating_scanners[])
- appsec-review/dependency-reachability/1  (status: used | not_used | unknown, citing_spans[], indexes_consulted[])

Telemetry & metrics recorded per attempt:
- scanners.raw_observations_by_tool, scanners.dedup_clusters_formed,
  scanners.observations_with_code_flows, scanners.stylistic_filtered_count
- sca.osv_lookup_mode, sca.osv_lookup_duration_ms,
  sca.advisories_by_reachability (used / not_used / unknown), ci.promoted_leads_count
```

## Seven-point acceptance criteria

1. **Documentation & dataflow updates:** Update [`../architecture/scanners-and-evidence-collection.md`](../architecture/scanners-and-evidence-collection.md),
   [`../operations/job_evidence_collection.md`](../operations/job_evidence_collection.md),
   [`../operations/dependency-intelligence.md`](../operations/dependency-intelligence.md),
   [`../operations/ci-configuration-analysis.md`](../operations/ci-configuration-analysis.md),
   [`../operations/artifact-security-analysis.md`](../operations/artifact-security-analysis.md),
   `docs/docs-ledger.json`, and run `scripts/generate-docs.py`.
2. **Full indexing for downstream inference:** Index `code_flows`, corroborating scanner clusters,
   SCA reachability verdicts, and CI/artifact observations in `RetrievalCore`
   (`query_observations`, `query_ci_configuration`, `query_precomputed`).
3. **Fast, isolated unit tests (`<10s`):** Add code-level unit tests under
   `tests/unit/job_evidence_collection/`, `tests/unit/job_dependency_intelligence/`, and
   `tests/unit/job_ci_configuration_analysis/` testing SARIF `codeFlows` extraction, pre-cap
   clustering, indexed OSV lookup, `used`/`not_used`/`unknown` FFI/import reachability, and CI
   workflow lead promotion—zero container launches or network calls, `<10s` per test.
4. **Common querying & indexing skills doc alignment:** Document `query_observations` `code_flows`
   fields and SCA reachability querying in
   [`../architecture/querying-and-indexing-skills.md`](../architecture/querying-and-indexing-skills.md).
5. **Frontier prompting, roles & skills alignment:** Ensure `evidence-and-graph-querying` directs
   Lane A cells to verify intermediate `code_flows` hops and SCA `citing_spans` directly with
   `read_excerpt` rather than re-discovering paths from scratch.
6. **Metrics & telemetry:** Record raw-vs-deduplicated scanner counts, `code_flows` retention
   rates, OSV index lookup latency, and SCA reachability distributions.
7. **Proper schema versioning:** Validate `scanner-observation` v2 and `dependency-reachability` v1
   on write while keeping v1 observation readers compatible for historical run replay.
