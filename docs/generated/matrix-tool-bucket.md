---
title: "Tool-to-intelligence-bucket matrix"
kind: "generated"
subsystem: "runtime interchange"
status: "current"
jobs: []
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---

<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py, docs/intelligence-buckets.json, src/appsec_review/tool_inputs.py, src/appsec_review/jobs/cataloging.py, src/appsec_review/review/capability.py by scripts/generate-docs.py; do not edit -->
# Tool-to-intelligence-bucket matrix

[Full matrix](matrix-tool-bucket.json) | [Authored bucket map](../intelligence-buckets.json)

Only canonical catalog entries with `kind = tool` are rows here; non-tool entries are listed separately in JSON. Configured CodeQL tooling is not invented as a catalog tool ID.
Bindings are source declarations, not observed launches. Input compatibility is not rule coverage; the JSON retains input selectors, global tool policy and unresolved language metadata.

| Tool | Bucket | Bound jobs / tasks | Declared input languages | Catalog state | Gap |
| --- | --- | --- | --- | --- | --- |
| `tool-actionlint` | `scanner_observations` | `job_ci_configuration_analysis`<br>`job_ci_configuration_analysis.ci_analysis.github_actionlint_scan` | Undeclared; see gap | enabled | [T-157](../TODO.md) |
| `tool-blint` | `artifacts_and_binary` | `job_evidence_collection`<br>`job_evidence_collection.binary_hardening.blint_scan` | Undeclared; see gap | enabled | [T-157](../TODO.md) |
| `tool-checkov` | `scanner_observations` | `job_ci_configuration_analysis`, `job_evidence_collection`<br>`job_ci_configuration_analysis.ci_analysis.azure_checkov_scan`, `job_ci_configuration_analysis.ci_analysis.bitbucket_checkov_scan`, `job_ci_configuration_analysis.ci_analysis.circleci_checkov_scan` (+3 in JSON) | Undeclared; see gap | enabled | [T-157](../TODO.md) |
| `tool-clang-static-analysis` | `scanner_observations` | Undeclared; see gap<br>Undeclared; see gap | Undeclared; see gap | enabled | [T-147](../TODO.md), [T-157](../TODO.md) |
| `tool-clangd-indexer` | `symbols_and_calls` | Undeclared; see gap<br>Undeclared; see gap | Undeclared; see gap | enabled | [T-147](../TODO.md), [T-157](../TODO.md) |
| `tool-cppcheck` | `scanner_observations` | `job_evidence_collection`<br>`job_evidence_collection.source_sast.cppcheck_scan` | `C`, `C++`, `C/C++` | enabled | None |
| `tool-ghidra` | `artifacts_and_binary` | Undeclared; see gap<br>Undeclared; see gap | Undeclared; see gap | enabled | [T-147](../TODO.md), [T-157](../TODO.md) |
| `tool-git` | `history` | Undeclared; see gap<br>Undeclared; see gap | Undeclared; see gap | enabled | [T-147](../TODO.md), [T-157](../TODO.md) |
| `tool-gitleaks` | `scanner_observations` | `job_evidence_collection`<br>`job_evidence_collection.secrets.gitleaks_scan` | Not applicable (source-backed) | enabled | None |
| `tool-gosec` | `scanner_observations` | `job_evidence_collection`<br>`job_evidence_collection.source_sast.gosec_scan` | `Go` | enabled | None |
| `tool-grype` | `dependencies_and_advisories` | `job_evidence_collection`<br>`job_evidence_collection.vulnerability_matching.grype_scan` | Not applicable (source-backed) | enabled | None |
| `tool-hadolint` | `scanner_observations` | `job_evidence_collection`<br>`job_evidence_collection.configuration.hadolint_scan` | Undeclared; see gap | enabled | [T-157](../TODO.md) |
| `tool-infer` | `scanner_observations` | Undeclared; see gap<br>Undeclared; see gap | Undeclared; see gap | enabled | [T-147](../TODO.md), [T-157](../TODO.md) |
| `tool-joern` | `dataflow` | Undeclared; see gap<br>Undeclared; see gap | Undeclared; see gap | enabled | [T-147](../TODO.md), [T-157](../TODO.md) |
| `tool-mobsfscan` | `scanner_observations` | `job_evidence_collection`<br>`job_evidence_collection.source_sast.mobsfscan_scan` | `Java`, `Kotlin`, `Swift` | enabled | None |
| `tool-native-cpp` | `build_and_deployment` | Undeclared; see gap<br>Undeclared; see gap | Undeclared; see gap | enabled | [T-147](../TODO.md), [T-157](../TODO.md) |
| `tool-opengrep` | `scanner_observations` | `job_evidence_collection`<br>`job_evidence_collection.source_sast.opengrep_scan` | `C`, `C++`, `C/C++` (+1 in JSON) | enabled | None |
| `tool-osv-scanner` | `dependencies_and_advisories` | `job_evidence_collection`<br>`job_evidence_collection.vulnerability_matching.osv_scanner_scan` | Undeclared; see gap | enabled | [T-157](../TODO.md) |
| `tool-phpcs` | `scanner_observations` | `job_evidence_collection`<br>`job_evidence_collection.source_sast.phpcs_scan` | `PHP` | enabled | None |
| `tool-phpstan` | `scanner_observations` | `job_evidence_collection`<br>`job_evidence_collection.source_sast.phpstan_scan` | `PHP` | enabled | None |
| `tool-pmd` | `scanner_observations` | `job_evidence_collection`<br>`job_evidence_collection.source_sast.pmd_scan` | `Java` | enabled | None |
| `tool-psalm` | `scanner_observations` | `job_evidence_collection`<br>`job_evidence_collection.source_sast.psalm_scan` | `PHP` | enabled | None |
| `tool-report-latex` | `review_products` | Undeclared; see gap<br>Undeclared; see gap | Undeclared; see gap | enabled | [T-147](../TODO.md), [T-157](../TODO.md) |
| `tool-semgrep` | `scanner_observations` | `job_evidence_collection`<br>`job_evidence_collection.source_sast.semgrep_scan` | `C`, `C#`, `C++` (+12 in JSON); incomplete declarations | enabled | [T-157](../TODO.md) |
| `tool-shellcheck` | `scanner_observations` | `job_evidence_collection`<br>`job_evidence_collection.source_sast.shellcheck_scan` | `Shell` | enabled | None |
| `tool-spotbugs` | `scanner_observations` | `job_evidence_collection`<br>`job_evidence_collection.source_sast.spotbugs_scan` | Undeclared; see gap | enabled | [T-157](../TODO.md) |
| `tool-sqlite-fts` | `documents_and_retrieval` | Undeclared; see gap<br>Undeclared; see gap | Undeclared; see gap | enabled | [T-147](../TODO.md), [T-157](../TODO.md) |
| `tool-svf` | `dataflow` | Undeclared; see gap<br>Undeclared; see gap | Undeclared; see gap | enabled | [T-147](../TODO.md), [T-157](../TODO.md) |
| `tool-syft` | `dependencies_and_advisories` | `job_evidence_collection`<br>`job_evidence_collection.software_inventory.syft_scan` | Not applicable (source-backed) | enabled | None |
| `tool-tree-sitter` | `syntax` | Undeclared; see gap<br>Undeclared; see gap | Undeclared; see gap | enabled | [T-147](../TODO.md), [T-157](../TODO.md) |
| `tool-trivy` | `scanner_observations` | `job_evidence_collection`<br>`job_evidence_collection.configuration.trivy_scan` | Undeclared; see gap | enabled | [T-157](../TODO.md) |
| `tool-zizmor` | `scanner_observations` | `job_ci_configuration_analysis`, `job_evidence_collection`<br>`job_ci_configuration_analysis.ci_analysis.github_zizmor_scan`, `job_evidence_collection.configuration.zizmor_scan` | Undeclared; see gap | enabled | [T-157](../TODO.md) |

Not applicable means an explicit source-backed selector (for example arbitrary input or artifact format), not universal language coverage. Image state and job enablement are separate facts; neither proves a tool ran.
