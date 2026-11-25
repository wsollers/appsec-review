"""Explicit settings that may change without discarding accepted computations."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import math
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
        setting = declarations.get(path)
        if setting is not None:
            def valid(value: Any) -> bool:
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
