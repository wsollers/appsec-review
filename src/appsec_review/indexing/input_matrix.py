"""Machine-readable input-source matrix from ``docs/architecture/indexing-and-query-reuse.md``.

Reconciliation compares this matrix with the resolved registry/configuration and the run's actual
inventory rows. The matrix is a review check, not an allowlist: the dataset audit still enforces
every configured step. ``runtime`` names a non-job producer (the runtime itself or a future
inference/publication lane); ``planned:<job>`` names a producer that is not built or not yet
registered. Once ``<job>`` is registered, reconciliation treats it as that job, so a planned
producer needs no matrix change when it lands.

Code-graph facts are not precomputed query sets: the retired graph set names never appear in the
query-set column. The ``graph`` index is accounted by the ``code_graph`` lane of the language and
build-unit matrices instead.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping


# (source, producers, design state, precomputed query sets, MCP endpoints)
INPUT_SOURCES: tuple[tuple[str, tuple[str, ...], str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("resolved_configuration", ("job_model_connectivity", "job_image_pin_verification", "job_review_intake"), "extend",
     ("review_package",), ("query_datasets", "coverage")),
    # Pinned source identity of every acquired component; intake binds the composed tree fingerprint.
    ("target_acquisition", ("job_target_acquisition",), "artifact_only", (), ("coverage",)),
    ("source_snapshot", ("job_target_catalog",), "current", ("symbol_links", "hotspot_context"), ("core",)),
    ("repository_partitions", ("job_target_catalog",), "current", ("artifact_inventory", "review_package"), ("core",)),
    ("build_recipes", ("job_target_catalog", "job_target_analysis_plan"), "extend",
     ("build_provenance", "artifact_inventory"), ("core", "query_artifacts")),
    ("analysis_plan", ("job_target_analysis_plan",), "current", ("review_package",), ("coverage", "core")),
    ("git_history", ("job_source_history_analysis",), "current", ("history_context", "hotspot_context"),
     ("query_hotspots", "query_change_context", "query_precomputed")),
    ("github_review_metadata", ("job_source_history_analysis",), "current", ("history_context",),
     ("query_change_context", "coverage")),
    ("change_context", ("job_change_context_analysis",), "current", ("history_context", "ci_trust"),
     ("query_change_context", "query_precomputed")),
    ("tree_sitter_syntax", ("job_tree_sitter_ast",), "current", ("symbol_links", "hotspot_context"),
     ("core", "query_precomputed")),
    ("prioritization_metrics", ("job_review_prioritization",), "current", ("hotspot_context", "review_package"),
     ("query_hotspots", "query_precomputed")),
    ("project_build_probes", ("job_project_build",), "extend", ("build_provenance",),
     ("query_build_security", "coverage")),
    ("captured_build_actions", ("job_language_build",), "extend", ("build_provenance", "ci_trust", "review_package"),
     ("query_build_security", "query_precomputed")),
    ("package_manager_metadata", ("job_language_build", "job_artifact_indexing"), "current",
     ("artifact_inventory", "dependency_advisories"), ("query_artifacts", "query_precomputed")),
    ("produced_artifacts", ("job_artifact_indexing",), "current", ("artifact_inventory", "build_provenance"),
     ("query_artifacts", "query_precomputed")),
    ("test_coverage", ("job_test_coverage",), "current", ("hotspot_context", "review_package"),
     ("query_precomputed", "coverage")),
    ("execution_profiles", ("job_profile_data",), "current", ("hotspot_context", "review_package"),
     ("query_precomputed", "coverage")),
    ("artifact_security_scans", ("job_artifact_security_analysis",), "current",
     ("scanner_correlation", "dependency_advisories"), ("query_artifacts", "query_observations", "query_precomputed")),
    # Clang AST, LLVM IR and clangd are C/C++ cross-check inputs of the graph index, not graph producers.
    ("clang_ast", ("job_cpp_compiled_analysis",), "current", ("symbol_links",), ("core", "query_precomputed")),
    ("llvm_ir_binary_infer", ("job_cpp_compiled_analysis",), "current", ("scanner_correlation",),
     ("core", "query_build_security", "query_precomputed")),
    ("clang_static_analysis", ("job_clang_static_analysis",), "current",
     ("scanner_correlation", "review_package", "hotspot_context"),
     ("query_observations", "query_precomputed", "coverage")),
    ("clangd_symbols", ("job_cpp_symbol_index",), "current", ("symbol_links",), ("core", "query_precomputed")),
    # Ghidra pseudo-C, call neighbourhoods, imports and strings of configured third-party binaries.
    ("binary_decompilation", ("job_binary_evidence_indexing",), "current", (), ("core", "coverage")),
    # SVF points-to sets and indirect-call targets are a C/C++ cross-check input of the graph index.
    ("svf_points_to", ("job_svf_alias_analysis",), "current", (), ("core", "query_code_graph")),
    # Instrumented native builds are protected, artifact-only evidence for a later execution stage.
    ("sanitizer_builds", ("job_sanitizer_build",), "artifact_only", (), ("coverage",)),
    # Not a graph producer; see code-graph-precomputation.md.
    ("joern_cpg", ("job_cpg_analysis",), "artifact_only", (), ("coverage",)),
    # CodeQL is the primary graph producer: its export is normalized into the graph index by
    # job_code_graph_index and read through query_code_graph.
    ("codeql_sarif", ("job_codeql_analysis", "job_code_graph_index"), "current", ("scanner_correlation",),
     ("query_codeql", "query_code_graph", "query_observations", "query_precomputed")),
    ("post_build_assessment", ("job_post_build_security_assessment",), "current",
     ("build_provenance", "review_package"), ("query_build_security",)),
    ("ci_definitions", ("job_ci_configuration_analysis",), "current", ("ci_trust", "scanner_correlation"),
     ("query_ci_configuration", "query_precomputed")),
    ("secret_leads", ("job_evidence_collection",), "current", ("redacted_secret_exposure", "scanner_correlation"),
     ("query_observations", "query_precomputed")),
    ("source_sast", ("job_evidence_collection",), "current", ("scanner_correlation", "review_package", "hotspot_context"),
     ("query_observations", "query_precomputed")),
    ("syft_inventory", ("job_evidence_collection",), "current", ("artifact_inventory", "dependency_advisories"),
     ("query_artifacts", "query_observations", "query_precomputed")),
    ("dependency_vulnerability_matches", ("job_evidence_collection",), "current",
     ("dependency_advisories", "scanner_correlation"), ("query_observations", "query_artifacts", "query_precomputed")),
    ("dependency_scorecards", ("job_dependency_intelligence",), "current",
     ("review_package", "hotspot_context"), ("query_artifacts", "query_precomputed", "coverage")),
    ("configuration_scans", ("job_evidence_collection",), "current",
     ("scanner_correlation", "ci_trust", "deployment_exposure"), ("query_observations", "query_precomputed")),
    ("binary_scan", ("job_evidence_collection",), "current", ("scanner_correlation", "artifact_inventory"),
     ("query_artifacts", "query_observations")),
    ("owasp_controls", ("job_owasp_control_assessment",), "current", ("control_evidence", "review_package"),
     ("query_owasp_workbench", "query_precomputed")),
    ("security_tags", ("job_security_tagging",), "current", ("scanner_correlation", "hotspot_context"),
     ("core", "query_precomputed")),
    ("nvd_feed", ("job_third_party_data_sync",), "global_unpinned", ("reference_intelligence", "dependency_advisories"),
     ("query_precomputed",)),
    ("kev_feed", ("job_third_party_data_sync",), "global_unpinned", ("dependency_advisories",),
     ("query_precomputed",)),
    ("epss_feed", ("job_third_party_data_sync",), "global_unpinned", ("dependency_advisories",),
     ("query_precomputed",)),
    ("osv_feed", ("job_third_party_data_sync",), "global_unpinned", ("reference_intelligence", "dependency_advisories"),
     ("query_precomputed",)),
    ("mitre_feed", ("job_third_party_data_sync",), "global_unpinned", ("reference_intelligence", "control_evidence"),
     ("query_precomputed",)),
    ("cve_bin_tool_database", ("job_third_party_data_sync",), "global_unpinned",
     ("reference_intelligence", "dependency_advisories"), ("query_precomputed",)),
    ("interface_contracts", ("job_target_catalog",), "extend", ("contract_enforcement",),
     ("search", "find", "read_excerpt")),
    ("deployment_topology", ("planned:job_deployment_topology",), "planned", ("deployment_exposure", "ci_trust"), ()),
    ("tests_and_fixtures", ("job_target_catalog", "job_review_data_indexing"), "extend",
     ("document_context", "review_package"), ("search", "find", "read_excerpt", "query_precomputed")),
    ("docs_and_threat_models", ("job_target_catalog", "job_review_data_indexing"), "extend",
     ("document_context", "review_package"), ("search", "find", "read_excerpt", "query_precomputed")),
    ("target_agent_guidance", ("planned:job_test_and_doc_indexing",), "planned", (), ()),
    ("sanitized_fts_streams", ("job_review_data_indexing",), "current", (), ("search", "find", "read_excerpt")),
    ("dynamic_traces", ("planned:future_dynamic_producer",), "planned", ("review_package",), ()),
    ("protected_runtime_material", ("runtime",), "protected", (), ("query_datasets", "coverage")),
    ("review_decisions", ("job_inference_security_review",), "extend", ("review_package",), ("coverage",)),
    ("attack_chains", ("job_inference_security_review",), "artifact_only", (), ("coverage",)),
    ("remediation_plans", ("job_remediation_planning",), "artifact_only", (), ("coverage",)),
    ("remediation_validations", ("job_remediation_validation",), "artifact_only", (), ("coverage",)),
    ("dossiers", ("job_dossier_publication",), "protected", (), ("coverage",)),
    ("publication_gate_decisions", ("job_final_publication_gate",), "artifact_only", (), ("coverage",)),
    ("openvex_exports", ("job_openvex_export",), "protected", (), ("coverage",)),
    ("final_report_publications", ("job_final_report_publication",), "artifact_only", (), ("coverage",)),
    # Proof-of-concept unit-test functions for the claims the judge agreed with: developer-facing files, hash-bound
    # by the handoff and shown by the final report; compile-checked, never linked or run.
    ("poc_generation", ("job_poc_generation",), "artifact_only", (), ("coverage",)),
)

# Downstream accepted-handoff consumers, in publication order.
PLANNED_CONSUMERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("job_poc_generation", ("job_inference_security_review", "job_language_build")),
    ("job_remediation_planning", ("job_inference_security_review", "job_poc_generation")),
    ("job_remediation_validation", ("job_inference_security_review", "job_remediation_planning")),
    ("job_dossier_publication", ("job_inference_security_review", "job_poc_generation",
                                "job_remediation_planning", "job_remediation_validation")),
    ("job_final_publication_gate", ("job_inference_security_review", "job_poc_generation",
                                  "job_remediation_planning", "job_remediation_validation",
                                  "job_dossier_publication")),
    ("job_openvex_export", ("job_final_publication_gate", "job_inference_security_review")),
    ("job_final_report_publication", ("job_final_publication_gate",)),
)


def resolve_producer(producer: str, registered: Iterable[str]) -> str:
    """A ``planned:<job>`` producer whose job is now registered is evaluated as that job."""
    job = producer.removeprefix("planned:")
    return job if producer.startswith("planned:job_") and job in set(registered) else producer


def reconcile(registry_jobs: Iterable[str], jobs: Iterable[Mapping[str, Any]], rows: Iterable[Mapping[str, Any]],
              products: Mapping[str, Mapping[str, Any]], self_job: str, *,
              disabled_jobs: Iterable[str] = ()) -> tuple[list[dict[str, Any]], list[str]]:
    """Return one reconciled row per input source plus discrepancies between matrix and registry."""
    registered = set(registry_jobs)
    disabled = set(disabled_jobs)
    status = {item["job_id"]: item["status"] for item in jobs}
    by_job: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        by_job.setdefault(str(row["job_id"]), []).append(row)
    discrepancies: list[str] = []
    named = {resolve_producer(producer, registered) for _source, producers, *_ in INPUT_SOURCES
             for producer in producers if producer.removeprefix("planned:") not in disabled}
    downstream_jobs = {"job_review_package_assembly", "job_document_issue_analysis"}
    for job_id in sorted(registered - named - {self_job} - downstream_jobs):
        discrepancies.append(f"registered job {job_id} is absent from the input-source matrix")
    reconciled = []
    for source, producers, state, query_sets, endpoints in INPUT_SOURCES:
        producers = tuple(producer for producer in producers
                          if producer.removeprefix("planned:") not in disabled)
        if not producers:
            continue
        producer_states = []
        for producer in (resolve_producer(item, registered) for item in producers):
            if producer.startswith("planned:") or producer == "runtime":
                producer_states.append({"producer": producer, "status": "planned" if producer != "runtime" else "runtime"})
                continue
            if producer not in registered:
                discrepancies.append(f"matrix source {source} names unregistered producer {producer}")
                producer_states.append({"producer": producer, "status": "unregistered"})
                continue
            datasets = by_job.get(producer, [])
            producer_states.append({
                "producer": producer, "status": status.get(producer, "not_executed"),
                "indexed_datasets": sum(1 for item in datasets if item["disposition"] == "indexed"),
                "unavailable_datasets": sum(1 for item in datasets if item["disposition"] == "unavailable"),
            })
        available = [item for item in producer_states if item["status"] in {"accepted", "self"}]
        runtime = ("unavailable" if not available else
                   "partial" if any(item.get("unavailable_datasets") for item in available) else "available")
        reconciled.append({
            "source": source, "producers": list(producers), "design_state": state,
            "runtime_state": runtime, "producer_states": producer_states, "query_sets": list(query_sets),
            "query_set_status": {name: products.get(name, {}).get("status", "pending_follow_up")
                                 for name in query_sets},
            "mcp_endpoints": list(endpoints),
        })
    return reconciled, discrepancies
