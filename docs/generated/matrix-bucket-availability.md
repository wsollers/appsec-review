---
title: "Bucket-to-availability matrix"
kind: "generated"
subsystem: "runtime interchange"
status: "current"
jobs: []
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py, docs/intelligence-buckets.json, src/appsec_review/tool_inputs.py, src/appsec_review/jobs/cataloging.py, src/appsec_review/review/capability.py by scripts/generate-docs.py; do not edit -->
# Bucket-to-availability matrix

[Full per-language matrix and dataset rows](matrix-bucket-availability.json) | [Authored bucket map](../intelligence-buckets.json)

This is a summary of declarations, not a run-coverage report. The JSON includes every bucket/language pair, configured candidates, unbound producers and each producer/dataset row.
The language universe comes from catalog census labels and configured producer selectors, not inferred external-engine support.
A producer's configured language selectors do not prove that every dataset is published for those languages. Target-independent jobs are identified separately.
Eligible roles are the registry allowlist intersected with in-process tool/index compatibility; an actual run/package-scoped capability is still required. Protected and artifact-only routes expose sanitized metadata, not payloads. Bucket grouping never changes evidence authority.

| Bucket | Producer language selectors | Producers / datasets | Declared stages | Index / MCP | Eligible roles | Gap |
| --- | --- | --- | --- | --- | --- | --- |
| `artifacts_and_binary` | Undeclared; see gap | 4 producers / 9 dataset IDs | `artifact_only`, `indexed` | `artifacts`, `binary`<br>`coverage`, `find`, `query_artifacts` (+4 in JSON) | `adjudication_judge`, `attack_chain_analyst`, `blue_team_refuter` (+6 in JSON) | [T-157](../TODO.md) |
| `build_and_deployment` | Undeclared; see gap | 10 producers / 24 dataset IDs | `artifact_only`, `indexed`, `protected` | `analysis`, `build`, `build_security`<br>`coverage`, `find`, `query_build_security` (+4 in JSON) | `adjudication_judge`, `attack_chain_analyst`, `blue_team_refuter` (+5 in JSON) | [T-157](../TODO.md) |
| `dataflow` | `C`, `C#`, `C++` (+10 in JSON); incomplete declarations | 4 producers / 13 dataset IDs | `artifact_only`, `indexed`, `protected` | `analysis`, `graph`, `observations`<br>`coverage`, `find`, `list_codeql_databases` (+4 in JSON) | `adjudication_judge`, `attack_chain_analyst`, `blue_team_refuter` (+5 in JSON) | [T-157](../TODO.md) |
| `dependencies_and_advisories` | Undeclared; see gap | 2 producers / 9 dataset IDs | `artifact_only`, `indexed`, `protected` | `inventory`<br>`coverage`, `find`, `query_dataset_inventory` (+2 in JSON) | `adjudication_judge`, `attack_chain_analyst`, `blue_team_refuter` (+5 in JSON) | [T-157](../TODO.md) |
| `documents_and_retrieval` | Undeclared; see gap | 2 producers / 9 dataset IDs | `artifact_only`, `indexed` | `documents`, `inventory`, `links` (+1 in JSON)<br>`coverage`, `find`, `query_dataset_inventory` (+5 in JSON) | `adjudication_judge`, `attack_chain_analyst`, `blue_team_refuter` (+6 in JSON) | [T-157](../TODO.md) |
| `history` | Undeclared; see gap | 2 producers / 8 dataset IDs | `artifact_only`, `indexed`, `protected` | `history`<br>`coverage`, `find`, `query_change_context` (+4 in JSON) | `adjudication_judge`, `attack_chain_analyst`, `blue_team_refuter` (+5 in JSON); incomplete declarations | [T-157](../TODO.md) |
| `metrics` | Undeclared; see gap | 5 producers / 8 dataset IDs | `artifact_only`, `indexed` | `analysis`<br>`coverage`, `query_dataset_inventory`, `query_precomputed` | `completeness_reviewer`; incomplete declarations | [T-157](../TODO.md) |
| `review_products` | Undeclared; see gap | 14 producers / 33 dataset IDs | `artifact_only`, `indexed`, `protected` | `applicability`, `component-classification`, `control-result` (+5 in JSON)<br>`coverage`, `find`, `query_dataset_inventory` (+5 in JSON) | `adjudication_judge`, `attack_chain_analyst`, `blue_team_refuter` (+5 in JSON); incomplete declarations | [T-157](../TODO.md) |
| `scanner_observations` | `C`, `C#`, `C++` (+10 in JSON); incomplete declarations | 6 producers / 19 dataset IDs | `artifact_only`, `indexed`, `protected` | `evidence`, `observations`<br>`coverage`, `find`, `query_artifacts` (+6 in JSON) | `adjudication_judge`, `attack_chain_analyst`, `blue_team_refuter` (+6 in JSON) | [T-157](../TODO.md) |
| `source_snapshot` | Undeclared; see gap | 3 producers / 5 dataset IDs | `artifact_only`, `indexed` | `components`, `source`<br>`coverage`, `find`, `query_dataset_inventory` (+2 in JSON) | `adjudication_judge`, `attack_chain_analyst`, `blue_team_refuter` (+6 in JSON) | [T-157](../TODO.md) |
| `symbols_and_calls` | Undeclared; see gap | 4 producers / 13 dataset IDs | `artifact_only`, `indexed`, `protected` | `analysis`, `compiled`, `debug_symbols`<br>`coverage`, `find`, `query_dataset_inventory` (+4 in JSON) | `adjudication_judge`, `attack_chain_analyst`, `blue_team_refuter` (+5 in JSON); incomplete declarations | [T-157](../TODO.md) |
| `syntax` | Undeclared; see gap | 2 producers / 6 dataset IDs | `artifact_only`, `indexed`, `protected` | `analysis`<br>`coverage`, `find`, `query_dataset_inventory` (+3 in JSON) | `adjudication_judge`, `attack_chain_analyst`, `blue_team_refuter` (+5 in JSON) | [T-157](../TODO.md) |

Every missing or partially declared cell names a TODO gap. Source-backed not-applicable states preserve intentional boundaries, such as a protected payload having no index; they do not request wider access.
Code-graph-specific follow-ups remain in [T-115](../TODO.md) through [T-126](../TODO.md); their scope is not duplicated here.
