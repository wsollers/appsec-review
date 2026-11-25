"""Explicit settings that may change without discarding accepted computations."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
from typing import Any


@dataclass(frozen=True, slots=True)
class OperationalSetting:
    job_id: str
    path: tuple[str, ...]
    category: str = "execution"

    @property
    def resolved_path(self) -> tuple[str, ...]:
        return ("jobs", self.job_id, *self.path)


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
    OperationalSetting("job_debug_symbol_indexing", ("settings", "reader", "timeout_seconds")),
    OperationalSetting("job_dossier_publication", ("settings", "render_timeout_seconds")),
    OperationalSetting("job_build_environment_analysis", ("settings", "deadline_seconds"), category="coverage"),
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
            if type(left) is not int or type(right) is not int or left < 1 or right < 1:
                raise MaterialConfigurationChange(
                    "operational setting must retain a positive integer: " + ".".join(path))
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
