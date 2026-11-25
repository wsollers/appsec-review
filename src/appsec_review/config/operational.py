"""Explicit settings that may change without discarding accepted computations."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import math
import re
from typing import Any


@dataclass(frozen=True, slots=True)
class OperationalSetting:
    job_id: str | None
    path: tuple[str, ...]
    category: str = "execution"
    value_type: str = "positive_integer"

    @property
    def resolved_path(self) -> tuple[str, ...]:
        return ("jobs", self.job_id, *self.path) if self.job_id is not None else self.path


OPERATIONAL_SETTINGS = (
    OperationalSetting("job_openvex_export", ("settings", "timeout_seconds")),
    OperationalSetting("job_model_connectivity", ("settings", "timeout_seconds")),
    OperationalSetting("job_review_intake", ("settings", "model_preflight", "timeout_seconds")),
    OperationalSetting("job_source_history_analysis", ("settings", "github", "timeout_seconds")),
    OperationalSetting("job_review_prioritization", ("settings", "syntax_metrics_reservation", "cpu")),
    OperationalSetting("job_review_prioritization", ("settings", "syntax_metrics_reservation", "memory_mb")),
    OperationalSetting("job_review_prioritization",
                       ("settings", "syntax_metrics_reservation", "admission_timeout_seconds")),
    OperationalSetting("job_threat_model_generation", ("settings", "reservation", "cpu")),
    OperationalSetting("job_threat_model_generation", ("settings", "reservation", "memory_mb")),
    OperationalSetting("job_threat_model_generation", ("settings", "reservation", "admission_timeout_seconds")),
    OperationalSetting("job_sanitizer_build", ("settings", "workers")),
    OperationalSetting("job_sanitizer_build", ("settings", "command_timeout_seconds")),
    OperationalSetting("job_debug_symbol_indexing", ("settings", "reader", "timeout_seconds"),
                       value_type="positive_number"),
    OperationalSetting("job_dossier_publication", ("settings", "render_timeout_seconds")),
    OperationalSetting("job_build_environment_analysis", ("settings", "deadline_seconds"), category="coverage"),
    OperationalSetting('job_clang_static_analysis', ('settings', 'workers'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_cpp_symbol_index', ('settings', 'workers'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_cpg_analysis', ('settings', 'workers'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_code_graph_index', ('settings', 'workers'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_tree_sitter_ast', ('settings', 'workers'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_codeql_analysis', ('settings', 'concurrency'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_codeql_analysis', ('settings', 'threads'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_codeql_analysis', ('settings', 'ram_mb'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_codeql_analysis', ('settings', 'inventory_timeout_seconds'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_codeql_analysis', ('settings', 'database_timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_codeql_analysis', ('settings', 'query_timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_codeql_analysis', ('settings', 'export_queries', 'compile_threads'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_codeql_analysis', ('settings', 'export_queries', 'compile_ram_mb'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_codeql_analysis', ('settings', 'export_queries', 'compile_timeout_seconds'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_codeql_analysis', ('settings', 'export_queries', 'timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_project_build', ('settings', 'command_timeout_seconds'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_language_build', ('settings', 'command_timeout_seconds'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_project_build', ('settings', 'image_build_timeout_seconds'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_review_prioritization', ('settings', 'syntax_metrics_reservation', 'io_slots'), category='execution', value_type='nonnegative_integer'),
    OperationalSetting('job_threat_model_generation', ('settings', 'reservation', 'io_slots'), category='execution', value_type='nonnegative_integer'),
    OperationalSetting(None, ('runtime', 'operation_progress_interval_seconds'), category='execution', value_type='nonnegative_number'),
    OperationalSetting(None, ('runtime', 'operation_sample_interval_seconds'), category='execution', value_type='nonnegative_number'),
    OperationalSetting(None, ('orchestration', 'dagster', 'max_concurrent'), category='execution', value_type='positive_integer'),
    OperationalSetting(None, ('orchestration', 'dagster', 'pools', 'scanner'), category='execution', value_type='positive_integer'),
    OperationalSetting(None, ('orchestration', 'dagster', 'pools', 'index'), category='execution', value_type='positive_integer'),
    OperationalSetting(None, ('orchestration', 'dagster', 'pools', 'lifecycle'), category='execution', value_type='positive_integer'),
    OperationalSetting(None, ('orchestration', 'dagster', 'pools', 'cpp_build'), category='execution', value_type='positive_integer'),
    OperationalSetting(None, ('orchestration', 'dagster', 'pools', 'cpp_analysis'), category='execution', value_type='positive_integer'),
    OperationalSetting(None, ('orchestration', 'dagster', 'pools', 'owasp_validator'), category='execution', value_type='positive_integer'),
    OperationalSetting(None, ('orchestration', 'dagster', 'pools', 'owasp_verification'), category='execution', value_type='positive_integer'),
    OperationalSetting(None, ('orchestration', 'dagster', 'pools', 'ci_linter'), category='execution', value_type='positive_integer'),
    OperationalSetting(None, ('orchestration', 'dagster', 'pools', 'inference_teams'), category='execution', value_type='positive_integer'),
    OperationalSetting(None, ('orchestration', 'dagster', 'pools', 'inference_score'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'command_timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'max_functions'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'max_goto_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'max_instructions'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'max_output_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'max_properties'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'max_property_summaries'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'max_scopes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'max_seeds_per_scope'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'max_source_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'max_source_files'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'max_trace_steps'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'max_trace_value_chars'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'max_translation_units'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cbmc_analysis', ('settings', 'total_timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_clang_static_analysis', ('settings', 'max_diagnostics_per_scope'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_clang_static_analysis', ('settings', 'max_output_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_clang_static_analysis', ('settings', 'seeded_bounds', 'include_scan_files'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_clang_static_analysis', ('settings', 'seeded_bounds', 'unit_limit'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cpg_analysis', ('settings', 'max_cpg_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cpg_analysis', ('settings', 'seeded_bounds', 'include_scan_files'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cpg_analysis', ('settings', 'seeded_bounds', 'unit_limit'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cpp_compiled_analysis', ('settings', 'seeded_bounds', 'block_limit'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cpp_compiled_analysis', ('settings', 'seeded_bounds', 'function_limit'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cpp_compiled_analysis', ('settings', 'seeded_bounds', 'include_scan_files'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cpp_compiled_analysis', ('settings', 'seeded_bounds', 'unit_limit'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cpp_symbol_index', ('settings', 'locations_per_relation'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cpp_symbol_index', ('settings', 'max_documents_per_scope'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cpp_symbol_index', ('settings', 'max_relations_per_scope'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_cpp_symbol_index', ('settings', 'max_symbols_per_scope'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_debug_symbol_indexing', ('settings', 'max_artifacts'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_debug_symbol_indexing', ('settings', 'reader', 'max_depth'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_debug_symbol_indexing', ('settings', 'reader', 'max_input_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_debug_symbol_indexing', ('settings', 'reader', 'max_output_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_debug_symbol_indexing', ('settings', 'reader', 'max_records'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'attack_chains', 'max_candidates_per_composition'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'attack_chains', 'max_challenge_cells'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'attack_chains', 'max_evidence_per_obligation'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'attack_chains', 'max_expansions'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'attack_chains', 'max_links'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'attack_chains', 'max_queries'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'attack_chains', 'max_result_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'attack_chains', 'max_turns'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'budgets', 'budget_team_packages'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'budgets', 'max_input_tokens'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'budgets', 'max_model_turns'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'budgets', 'max_output_tokens'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'budgets', 'max_retrieval_queries'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'budgets', 'timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'decision_audit', 'max_input_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'decision_audit', 'max_page_size'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'decision_audit', 'max_records'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'decision_audit', 'page_size'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'decision_audit', 'shard_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'decision_audit', 'shard_records'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'hunting', 'agents'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'hunting', 'brief_bounds', 'max_files'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'hunting', 'brief_bounds', 'max_functions'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'hunting', 'brief_bounds', 'max_leads'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'hunting', 'max_areas'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'lanes', 'hunt_max_claims_per_package'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'lanes', 'hunt_max_units'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'lanes', 'lead_max_claims_per_package'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'default', 'max_input_tokens'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'default', 'max_output_tokens'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'default', 'max_queries'), category='coverage', value_type='nonnegative_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'default', 'max_turns'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'default', 'timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'planner', 'max_input_tokens'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'planner', 'max_output_tokens'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'planner', 'max_queries'), category='coverage', value_type='nonnegative_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'planner', 'max_turns'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'planner', 'timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'triage', 'max_input_tokens'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'triage', 'max_output_tokens'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'triage', 'max_queries'), category='coverage', value_type='nonnegative_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'triage', 'max_turns'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'triage', 'timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'verifier', 'max_input_tokens'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'verifier', 'max_output_tokens'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'verifier', 'max_queries'), category='coverage', value_type='nonnegative_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'verifier', 'max_turns'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'models', 'verifier', 'timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'caller_depth'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'max_behavior_artifact_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'max_callers'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'max_context_entries'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'max_depth'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'max_memory_context_entries'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'max_operation_records'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'max_package_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'max_page_size'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'max_pages'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'max_slice_lines'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'max_slice_lines_per_function'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'max_view_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'max_view_source_lines'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'max_view_type_declarations'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'packages', 'unit_max_files'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'red_output', 'max_chain_seeds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'red_output', 'max_chain_steps'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'red_output', 'max_evidence_refs'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'red_output', 'max_evidence_requests'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'red_output', 'max_gaps'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'red_output', 'max_obligations'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'red_output', 'max_path_nodes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'red_output', 'max_proposals'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'red_output', 'max_result_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'red_output', 'max_taint_paths'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'red_output', 'max_text_chars'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'result_cache', 'connect_timeout_seconds'), category='execution', value_type='positive_number'),
    OperationalSetting('job_inference_security_review', ('settings', 'retry', 'backoff_seconds'), category='coverage', value_type='backoff'),
    OperationalSetting('job_inference_security_review', ('settings', 'retry', 'max_attempts'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'retry', 'retry_on_timeout'), category='coverage', value_type='boolean'),
    OperationalSetting('job_inference_security_review', ('settings', 'roles', 'adjudication_judge', 'max_cited_row_chars'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'roles', 'adjudication_judge', 'max_cited_rows_per_side'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'roles', 'adjudication_judge', 'max_why_chars'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'roles', 'adjudication_judge', 'workers'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'roles', 'independent_verifier', 'workers'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'rounds', 'max_active_claims'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'rounds', 'max_attack_chains'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'rounds', 'max_rounds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'triage', 'batch_size'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'triage', 'max_excerpt_lines'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'triage', 'max_leads'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ('settings', 'triage', 'max_reason_chars'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_language_build', ('settings', 'artifact_count_limit'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_language_build', ('settings', 'go', 'diagnostic_tail_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_language_build', ('settings', 'jvm', 'diagnostic_tail_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_language_build', ('settings', 'jvm', 'provenance_count_limit'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_language_build', ('settings', 'jvm', 'trace_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_language_build', ('settings', 'node', 'diagnostic_tail_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_language_build', ('settings', 'output_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_language_build', ('settings', 'php', 'diagnostic_tail_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_language_build', ('settings', 'python', 'diagnostic_tail_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_language_build', ('settings', 'rust', 'diagnostic_tail_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_language_build', ('settings', 'wasm', 'workspace_file_limit'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_post_build_security_assessment', ('settings', 'model', 'max_input_tokens'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_post_build_security_assessment', ('settings', 'model', 'max_output_tokens'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_post_build_security_assessment', ('settings', 'model', 'retries'), category='coverage', value_type='nonnegative_integer'),
    OperationalSetting('job_post_build_security_assessment', ('settings', 'model', 'timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_project_build', ('settings', 'artifact_count_limit'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_project_build', ('settings', 'model', 'max_input_tokens'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_project_build', ('settings', 'model', 'max_output_tokens'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_project_build', ('settings', 'model', 'timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_project_build', ('settings', 'output_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_project_build', ('settings', 'repair_attempts'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'andersen_time_limit_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'compile_timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'link_timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'max_accessors_per_object'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'max_indirect_calls'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'max_module_bitcode_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'max_module_output_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'max_modules_per_scope'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'max_objects_per_module'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'max_output_bytes'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'max_pts_size'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'max_sites'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'max_targets_per_call'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'max_unmodeled_names'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'module_timeout_seconds'), category='coverage', value_type='positive_integer'),
    OperationalSetting('job_svf_alias_analysis', ('settings', 'workers'), category='execution', value_type='positive_integer'),
    OperationalSetting(None, ('review_policy', 'resources', 'cpu'), category='execution', value_type='positive_integer'),
    OperationalSetting(None, ('review_policy', 'resources', 'io_slots'), category='execution', value_type='positive_integer'),
    OperationalSetting(None, ('review_policy', 'resources', 'memory_mb'), category='execution', value_type='positive_integer'),
    OperationalSetting(None, ('review_policy', 'resources', 'staging_memory_mb'), category='execution', value_type='positive_integer'),
    OperationalSetting('job_inference_security_review', ("settings", "retry", 'retry_on_provider_error'), category="coverage", value_type="boolean"),
    OperationalSetting('job_inference_security_review', ("settings", "retry", 'retry_on_invalid_output'), category="coverage", value_type="boolean"),
)


class MaterialConfigurationChange(ValueError):
    """A configuration change needs more than operational-setting admission."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def operational_changes(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return exact admitted deltas, rejecting every other changed field."""
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        raise ValueError("resolved configuration must be an object")
    declarations = {setting.resolved_path: setting for setting in OPERATIONAL_SETTINGS}
    changes: list[dict[str, Any]] = []
    material: list[str] = []

    def compare(left: Any, right: Any, path: tuple[str, ...]) -> None:
        if _canonical(left) == _canonical(right):
            return
        if path in (("configuration_profile",), ("configuration_overlay",)):
            if not isinstance(left, Mapping) or not isinstance(right, Mapping):
                material.append(".".join(path))
                return
            identity_keys = set(left) | set(right)
            identity_keys -= {"sha256", "document", "keys", "name", "path", "layer"}
            if any(_canonical(left.get(key)) != _canonical(right.get(key)) for key in identity_keys):
                material.append(".".join(path))
                return
            def flattened(value: Mapping[str, Any], prefix: tuple[str, ...] = ()) -> dict[tuple[str, ...], Any]:
                result = {}
                for key, child in value.items():
                    if isinstance(child, Mapping):
                        result.update(flattened(child, (*prefix, key)))
                    else:
                        result[(*prefix, key)] = child
                return result
            first = flattened(left.get("document", {}))
            second = flattened(right.get("document", {}))
            for key in sorted(set(first) | set(second)):
                if key in first and key in second and _canonical(first[key]) == _canonical(second[key]):
                    continue
                if key not in declarations:
                    material.append(".".join((*path, "document", *key)))
            # Source-layer digests are provenance, not authority. Effective leaf values are
            # validated below and the immutable layer bytes are verified by configuration_snapshot.
            for value in (left, right):
                digest = value.get("sha256")
                if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                    material.append(".".join((*path, "sha256")))
            changes.append({"job_id": None, "path": list(path), "category": "provenance",
                            "before": left, "after": right})
            return
        setting = declarations.get(path)
        if setting is not None:
            def valid(value: Any) -> bool:
                if setting.value_type == "memory":
                    return isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*[mg]", value) is not None
                if setting.value_type == "boolean":
                    return type(value) is bool
                if setting.value_type == "backoff":
                    return (isinstance(value, (list, tuple)) and len(value) <= 16 and
                            all(type(item) is int and 0 <= item <= 3600 for item in value) and
                            list(value) == sorted(value))
                integral = setting.value_type.endswith("integer")
                numeric = type(value) is int if integral else type(value) in (int, float)
                return numeric and (type(value) is int or math.isfinite(value)) and (
                    value >= 0 if setting.value_type.startswith("nonnegative") else value > 0)

            if not valid(left) or not valid(right):
                raise MaterialConfigurationChange(
                    "operational setting must retain " + setting.value_type + ": " + ".".join(path))
            changes.append({"job_id": setting.job_id, "path": list(setting.path),
                            "category": setting.category, "before": left, "after": right})
            return
        if isinstance(left, Mapping) and isinstance(right, Mapping):
            for key in sorted(set(left) | set(right)):
                if key not in left or key not in right:
                    if not path and key in ("configuration_profile", "configuration_overlay"):
                        compare(left.get(key, {}), right.get(key, {}), (key,))
                    else:
                        material.append(".".join((*path, key)))
                else:
                    compare(left[key], right[key], (*path, key))
            return
        material.append(".".join(path))

    compare(before, after, ())
    if material:
        raise MaterialConfigurationChange(
            "non-operational configuration changed: " + ", ".join(material))
    return changes


def configuration_compatible(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
    try:
        operational_changes(before, after)
    except MaterialConfigurationChange:
        return False
    return True
