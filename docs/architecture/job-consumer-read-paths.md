---
title: "Job consumer read-path inventory"
kind: "architecture"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_artifact_indexing", "job_artifact_security_analysis", "job_binary_evidence_indexing", "job_build_environment_analysis", "job_build_iteration", "job_change_context_analysis", "job_ci_configuration_analysis", "job_clang_static_analysis", "job_code_graph_index", "job_codeql_analysis", "job_cpg_analysis", "job_cpp_compiled_analysis", "job_cpp_symbol_index", "job_debug_symbol_indexing", "job_dependency_intelligence", "job_document_issue_analysis", "job_dossier_publication", "job_evidence_collection", "job_final_publication_gate", "job_final_report_publication", "job_image_pin_verification", "job_inference_security_review", "job_language_build", "job_model_connectivity", "job_openvex_export", "job_owasp_control_assessment", "job_poc_generation", "job_post_build_security_assessment", "job_profile_data", "job_project_build", "job_remediation_planning", "job_remediation_validation", "job_review_data_indexing", "job_review_intake", "job_review_package_assembly", "job_review_prioritization", "job_sanitizer_build", "job_security_tagging", "job_source_history_analysis", "job_svf_alias_analysis", "job_target_acquisition", "job_target_analysis_plan", "job_target_catalog", "job_test_coverage", "job_third_party_data_sync", "job_threat_model_generation", "job_tree_sitter_ast"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Job consumer read-path inventory

This is a navigation/checking inventory of principal read families, not another runtime registry.
`Job.contract`, its exact dataset requirements, and the admitted reader checks remain authoritative.
The [generated inventory](../generated/inventory.json) and [canonical job pages](../operations/README.md)
own the complete current declarations.
The inventory names the principal input access families; it is **not** exhaustive certification
of every private reader, enabled-job combination, race or live tool path.

| Job | Principal input/read boundary |
|---|---|
| `job_third_party_data_sync` | Frozen feed configuration, feed source transport and snapshot provenance; standalone fresh maintenance, not a required review handoff. |
| `job_model_connectivity` | Frozen enabled model profiles; operational readiness, no target or upstream data grant. |
| `job_image_pin_verification` | Frozen image catalog/pins; operational readiness, no target or upstream data grant. |
| `job_target_acquisition` | Approved component acquisition configuration and acquisition records; no semantic graph handoff dependency. |
| `job_review_intake` | Target/configuration plus immutable selected acquisition and binary-publication identities. |
| `job_target_catalog` | Intake admission and target inventory; publishes original source, declaration and document shards. |
| `job_build_environment_analysis` | Accepted catalog and bounded environment declarations. |
| `job_source_history_analysis` | Accepted intake/catalog plus bounded Git/review metadata identity. |
| `job_ci_configuration_analysis` | Accepted catalog/source context; static CI definitions. |
| `job_target_analysis_plan` | Accepted catalog, history and environment; CI scheduling does not itself grant consumption. |
| `job_project_build` | Accepted plan/catalog/environment and configured build profiles. |
| `job_language_build` | Accepted project/plan/catalog/intake, the plan-bound environment publication, and exact build/workspace references. |
| `job_build_iteration` | Immutable controller request and selected build inputs; internal transaction, never an unconditional review publisher. |
| `job_tree_sitter_ast` | Accepted intake/catalog/language-build context and source/generated-source identity. |
| `job_change_context_analysis` | Catalog/history/Tree-sitter handoffs and original shards. |
| `job_artifact_indexing` | Accepted language build/catalog and exact artifact references. |
| `job_debug_symbol_indexing` | Accepted artifact/language-build publications and symbol artifacts. |
| `job_test_coverage` | Accepted catalog/build/artifacts; imported coverage, not test execution. |
| `job_profile_data` | Accepted catalog/build/artifacts; imported workload observations. |
| `job_artifact_security_analysis` | Accepted language build/artifact catalog and exact scanner inputs. |
| `job_evidence_collection` | Catalog/intake/plan, the plan-bound environment publication, plus selected immutable local feed snapshots. |
| `job_cpp_compiled_analysis` | Accepted native language build, catalog, plan and scanner seed context. |
| `job_clang_static_analysis` | Accepted C++ scopes and original catalog/scanner seeds. |
| `job_svf_alias_analysis` | Accepted C++ bitcode/scopes and original seed context; disabled selection stays explicit. |
| `job_cpp_symbol_index` | Accepted C++ scopes and original catalog/scanner seed context. |
| `job_cpg_analysis` | Accepted C++ scopes/seed context; deprecated/disabled coverage is not clean evidence. |
| `job_sanitizer_build` | Accepted native language-build recipe/workspace; compilation only. |
| `job_binary_evidence_indexing` | Intake-frozen binary publication references; the accepted catalog envelope for its retrieval manifest only. |
| `job_post_build_security_assessment` | Accepted compiled/build/plan/catalog/environment properties. |
| `job_dependency_intelligence` | Catalog/build/artifact/scanner/compiled inputs and selected feed snapshots. |
| `job_codeql_analysis` | Accepted plan/build/catalog plus explicitly declared scanner, compiled, symbol and source context. |
| `job_review_prioritization` | Original intake/catalog/syntax/history/scanner/CodeQL publications. |
| `job_code_graph_index` | Accepted CodeQL exports and original catalog/AST/IR/clangd/SVF/analyzer/prioritization shards. |
| `job_security_tagging` | Accepted original producer shards; tags remain routing context, not control proof. |
| `job_owasp_control_assessment` | Declared original source/build/scanner/tag/graph context and selected reference inputs. |
| `job_threat_model_generation` | Accepted catalog, artifact, build, graph, syntax and prioritization shards through bounded index queries; no checkout. Default disabled; when admitted, its output can supply bounded review-behavior routing context, not predicate proof. |
| `job_review_data_indexing` | Accepted original handoffs/shards, exact file ownership, feed pins and bound OWASP publication. |
| `job_review_package_assembly` | Accepted inventory/indexing publication plus original source/evidence shards; a manifest does not re-own them. |
| `job_document_issue_analysis` | Accepted packages and original declared document/source context. |
| `job_inference_security_review` | Accepted packages/original retrieval scope; run-pinned reference inputs bind to the accepted indexing summary. |
| `job_poc_generation` | Accepted review/build plus the explicit downstream source-context dataset view for real package briefs. |
| `job_remediation_planning` | Accepted review/build plus the explicit source-context view; `SourceReader.resolve` runs before model dispatch. |
| `job_remediation_validation` | Accepted review/plans and exact baseline/patch/build references; it does not call the index-backed `SourceReader`. |
| `job_dossier_publication` | Accepted review/engineering outcomes plus the source-context view for cited excerpts. |
| `job_final_publication_gate` | Accepted review and enabled completion artifacts; optional language-build envelope is read only when an admitted PoC binds its hash. |
| `job_final_report_publication` | Certified gate snapshot only; no rediscovery of original source/engineering heads. |
| `job_openvex_export` | Certified gate and accepted review identities; no arbitrary source-index rescan. |

## Downstream source-context view

`jobs.bound_artifacts.source_context_datasets` selects explicit original output kinds for
catalog source/declarations/documents, syntax/compiled/symbol facts, scanner observations,
graph facts, dependency context, tags/priorities and derived links/precomputed facts.
It is a finite semantic selection, not the scheduling closure or every output of those jobs.
`source_context_inputs` builds the three consumers' typed requirements from those same declarations.

`source_context_core` verifies the original full manifest and preserves its hash, then restricts
database queries to the selected original shard claims. It does not write a re-export or change
producer identities. Operational inventory, history-only context, working artifacts and unrelated
owners are not implicitly queried. Cursors/session identities include the selected shard view.

Source-view selection, admitted dataset availability and observed reads share
`runtime.datasets.shard_owner`: a shard belongs to the unique most-specific matching declaration
in its producer's **complete pinned output contract**, not any matching selected declaration.
Within typed execution, source-view metadata uses the exact supplied handoff even if the producer's
current pointer advances. Ambiguous or unclaimed shards fail; caught reader failures remain terminal.

The view explicitly includes `tree_sitter_coverage`, `clangd_coverage`,
`clang_static_scope_coverage`, `cpg_scope_coverage`, `svf_alias_scope_coverage` and
`cpp_blocked_branches`. Their unavailable/partial scopes and gap text remain queryable. A
coverage-only shard does not establish that the broader AST, symbol or observation dataset exists.
Other output kinds are not implicitly admitted merely because they share an index or producer.

Provenance-unknown historical source views stay unknown and remain readable outside typed execution.
Inside `JobRunner`, the unchanged observer still refuses a shard without an admitted original owner.
Removing a required owner from the consumer contract remains a terminal read-contract violation;
the view is not an observer bypass.

## Executed revision checks

`tests/test_downstream_input_contracts.py` uses synthetic scanner/model inputs with real review
adjudication/acceptance, exact producer-owned nonempty source/analysis/graph/link shards, real
accepted-build readers, and real consumer units under `JobRunner`. Only model transport is scripted;
no build, model provider, Docker or target execution is performed. It covers remediation before
model dispatch, PoC `plan.briefs`, dossier excerpts, unrelated-history exclusion, undeclared/
unknown-owner refusal, and the bound-PoC gate with no-binding/disabled controls.

Fixtures pin complete real producer declarations, including required catalog/inventory outputs.
`tests/test_shard_ownership.py` covers each coverage-only sibling, exact availability versus read
accounting, ambiguous/unclaimed rejection at admission and both reader boundaries, sticky failures,
and supplied-versus-current historical ownership. Combined six-producer cases execute the real
`load.verify_inputs` and `assess.propose`, `plan.briefs` or `dossiers.create` units through the runner
and inspect their actual result/observation receipts. They do not claim a partially executed fixture
attempt is a published job. Separate full downstream cases retain publication coverage (including
the Tree-sitter-only remediation regression) without duplicating unrelated publication work in each
combined coverage-reader check.

`tests/test_standalone_input_contracts.py` executes the actual Dagster begin op on an existing
fixture run. Untagged single-job supply remains unspecified (`None`) so the same enabled-contract
selection as direct `JobRunner` applies. Tagged `{}` and composite supply remain explicitly empty.
These are offline unit checks, not permission to execute a live Dagster review.
