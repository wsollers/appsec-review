"""Resolve repository-owned runtime assets in source and installed deployments."""

from __future__ import annotations

import os
from pathlib import Path


def application_root(required_path: str | Path) -> Path:
    """Return the configured application root containing ``required_path``.

    The Dagster image installs Python modules into ``site-packages`` while keeping configuration,
    rules, prompts, and tool assets under ``/opt/app``. ``APPSEC_REVIEW_CONFIG`` is therefore the
    authoritative installed-layout anchor; the module-relative candidate is for source checkouts.
    """
    relative = Path(required_path)
    if relative.anchor or ".." in relative.parts:
        raise ValueError("application asset path must be relative and contained")
    candidates: list[Path] = []
    configured = os.environ.get("APPSEC_REVIEW_CONFIG")
    if configured:
        candidates.append(Path(configured).resolve().parent)
    candidates.append(Path(__file__).resolve().parents[2])
    for root in candidates:
        candidate = root / relative
        if candidate.is_file() and not candidate.is_symlink():
            return root
    raise FileNotFoundError(f"application file is unavailable: {relative.as_posix()}")


def application_asset(required_path: str | Path) -> Path:
    """Return one verified repository-owned runtime asset."""
    relative = Path(required_path)
    return application_root(relative) / relative


def verify_runtime_assets() -> None:
    """Fail an image build when required non-package assets are absent or misresolved."""
    for relative in (
        "containers/catalog.toml",
        "docs/schemas/document-issue-ledger.schema.json",
        "pipeline/guidance/registry.json",
        "pipeline/prompt-fragments/personas/devops-engineer.md",
        "rules/codeql-graph-export/catalog.json",
        "rules/codeql-graph-export/catalog.schema.json",
        "rules/codeql-graph-export/columns.json",
        "rules/sei-cert/pack.lock.json",
    ):
        application_asset(relative)


__all__ = ["application_asset", "application_root", "verify_runtime_assets"]
