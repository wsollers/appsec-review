"""Run-bound code-graph settings and pins (docs/architecture/code-graph-precomputation.md, C9).

A run binds its resolved configuration under ``runs/<run-id>/data/configuration/``. Retrieval and
the graph job read the code-graph bounds and the graph catalog pin from the attempt/handoff's
hash-verified configuration snapshot (or the admitted operational revision), falling back to the
run-bound base configuration only when called standalone without a claim or revision identity.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from appsec_review.graph.contract import GraphSettings
from appsec_review.storage import file_sha256

GRAPH_JOB = "job_code_graph_index"
CODEQL_JOB = "job_codeql_analysis"


class RunConfigurationError(ValueError):
    """The run-bound resolved configuration exists but fails its hash check or shape."""


def _active_config_sha256(run_root: Path, expected_sha256: str | None = None) -> str | None:
    if isinstance(expected_sha256, str) and expected_sha256:
        return expected_sha256
    root = Path(run_root).resolve()
    from appsec_review.storage.shared import current as current_publication
    owner = current_publication()
    if owner is not None and owner.run_root == root:
        claim_path = owner.attempt_root / "claim.json"
        if claim_path.is_file():
            claim = json.loads(claim_path.read_bytes())
            sha = claim.get("resolved_config_sha256")
            if isinstance(sha, str) and sha:
                return sha
    from appsec_review.runtime.repair import current_binding
    from appsec_review.runtime.configuration import admitted_configuration_sha256
    binding = current_binding(root)
    if binding is not None and binding.get("repair") is not None:
        return admitted_configuration_sha256(root, binding)
    return None


def run_configuration(run_root: Path, expected_sha256: str | None = None) -> Mapping[str, Any] | None:
    """The hash-verified resolved configuration for the active attempt/revision, or ``None`` when unbound."""
    destination = Path(run_root) / "data" / "configuration"
    manifest_path = destination / "manifest.json"
    if not manifest_path.is_file():
        if expected_sha256 is not None:
            raise RunConfigurationError("run-bound resolved configuration is unavailable")
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        resolved = destination / "resolved.json"
        base_sha = manifest.get("resolved_sha256")
        if file_sha256(resolved) != base_sha:
            raise RunConfigurationError("run-bound resolved configuration hash mismatch")
        target_sha = _active_config_sha256(run_root, expected_sha256)
        if target_sha is not None and target_sha != base_sha:
            from appsec_review.runtime.configuration import configuration_snapshot
            document: Any = configuration_snapshot(Path(run_root), target_sha).document
        else:
            document = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        if isinstance(error, RunConfigurationError):
            raise
        raise RunConfigurationError(f"run-bound resolved configuration is unreadable: {error}") from error
    if not isinstance(document, Mapping):
        raise RunConfigurationError("run-bound resolved configuration is not an object")
    return document


def _job_settings(document: Mapping[str, Any], job_id: str) -> Mapping[str, Any] | None:
    for table in ("jobs", "pending_jobs"):
        job = (document.get(table) or {}).get(job_id)
        if isinstance(job, Mapping):
            settings = job.get("settings")
            return settings if isinstance(settings, Mapping) else {}
    return None


def run_graph_settings(run_root: Path, expected_sha256: str | None = None) -> GraphSettings:
    """``jobs.job_code_graph_index.settings.graph`` of the run/revision; contract defaults when unconfigured."""
    document = (
        run_configuration(run_root)
        if expected_sha256 is None
        else run_configuration(run_root, expected_sha256)
    )
    settings = _job_settings(document, GRAPH_JOB) if document is not None else None
    return GraphSettings.from_mapping((settings or {}).get("graph"))


def catalog_pins(document: Mapping[str, Any]) -> dict[str, frozenset[str]]:
    """Per CodeQL language, the graph catalog SHA-256 values its configured export packs pin."""
    settings = _job_settings(document, CODEQL_JOB) or {}
    pins: dict[str, frozenset[str]] = {}
    for language, value in dict(settings.get("languages") or {}).items():
        exports = value.get("export_queries") if isinstance(value, Mapping) else None
        values = {str(item["catalog_sha256"]) for item in exports or ()
                  if isinstance(item, Mapping) and item.get("catalog_sha256")}
        if values:
            pins[str(language)] = frozenset(values)
    return pins


__all__ = ["RunConfigurationError", "catalog_pins", "run_configuration", "run_graph_settings"]
