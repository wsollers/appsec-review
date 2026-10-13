"""Run-bound code-graph settings and pins (docs/architecture/code-graph-precomputation.md, C9).

A run binds its resolved configuration under ``runs/<run-id>/data/configuration/``. Retrieval and
the graph job read the code-graph bounds and the graph catalog pin from that hash-verified copy, so
the caps a review cell or MCP session sees, and the catalog a graph shard was built with, follow the
configuration the run was started with rather than library defaults or the current checkout.
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


def run_configuration(run_root: Path) -> Mapping[str, Any] | None:
    """The hash-verified resolved configuration bound to the run, or ``None`` when none is bound."""
    destination = Path(run_root) / "data" / "configuration"
    manifest_path = destination / "manifest.json"
    if not manifest_path.is_file():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        resolved = destination / "resolved.json"
        if file_sha256(resolved) != manifest.get("resolved_sha256"):
            raise RunConfigurationError("run-bound resolved configuration hash mismatch")
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


def run_graph_settings(run_root: Path) -> GraphSettings:
    """``jobs.job_code_graph_index.settings.graph`` of the run; contract defaults when unconfigured."""
    document = run_configuration(run_root)
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
