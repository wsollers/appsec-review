"""Run-completion hook for target-grouped finding archival, RoR reporting, and smoke scoring."""

from __future__ import annotations

import logging
from pathlib import Path
from collections.abc import Callable
from typing import Any

from appsec_review.config.efficacy_report import EfficacyReportSettings
from appsec_review.container_runtime.executor import ContainerExecutor
from appsec_review.observability.findings.target_identity import resolve_target_identity
from appsec_review.reporting.smoke_effectiveness import REPOSITORY_ROOT
from appsec_review.reporting.run_over_run_report import (
    archive_target_run,
    build_run_over_run_report,
    has_accepted_publication_gate,
    write_run_over_run_outputs,
)
from appsec_review.reporting.smoke_effectiveness import (
    ExecutorFactory,
    build_smoke_effectiveness,
    discover_matching_smoke_key,
    write_smoke_effectiveness_outputs,
)
from appsec_review.reporting.smoke_score import load_answer_key, render_summary, score_run, write_outputs
from appsec_review.reporting.smoke_scorecard import render_scorecard

_LOG = logging.getLogger(__name__)


def _resolve_dir(raw: str, repo_root: Path) -> Path:
    candidate = Path(raw)
    if candidate.is_absolute():
        return candidate.resolve()
    return (repo_root / candidate).resolve()


def run_efficacy_finalization(
    run_root: Path,
    settings: EfficacyReportSettings,
    *,
    runs_dir: Path | None = None,
    repository_root: Path | None = None,
    executor_factory: ExecutorFactory = ContainerExecutor,
    out_dir: Path | None = None,
    render_pdf_override: bool | None = None,
) -> dict[str, Any]:
    """Execute archival, Run-over-Run report generation, and optional auto smoke scoring."""
    run = Path(run_root).resolve()
    repo_root = Path(repository_root or REPOSITORY_ROOT).resolve()
    effective_runs_dir = Path(runs_dir).resolve() if runs_dir is not None else run.parent
    history_root = _resolve_dir(settings.history_dir, repo_root)
    smoke_guide_root = _resolve_dir(settings.smoke_guide_dir, repo_root)
    render_pdf = settings.render_pdf if render_pdf_override is None else render_pdf_override

    if not has_accepted_publication_gate(run):
        return {
            "status": "skipped_incomplete_run",
            "run_id": run.name,
        }

    identity = resolve_target_identity(run, repository_root=repo_root)
    matched_key: Path | None = None
    eff_payload: dict[str, Any] | None = None
    smoke_scorecard_receipt: dict[str, Any] | None = None
    smoke_eff_receipt: dict[str, Any] | None = None

    if settings.auto_smoke_score:
        matched_key = discover_matching_smoke_key(
            smoke_guide_root,
            repository=identity.repository,
            target_id=identity.target_id,
            snapshot_commit=identity.snapshot_commit,
        )
        key_doc = load_answer_key(matched_key) if matched_key is not None else None
        score_doc = score_run(run, key_doc)
        write_outputs(run, score_doc, render_summary(score_doc))

        eff_payload = build_smoke_effectiveness(run, key_path=matched_key)
        smoke_eff_receipt = write_smoke_effectiveness_outputs(
            run,
            eff_payload,
            render_tex_and_pdf=(matched_key is not None),
            render_pdf=render_pdf,
            timeout_seconds=settings.timeout_seconds,
            max_tex_bytes=settings.max_tex_bytes,
            max_pdf_bytes=settings.max_pdf_bytes,
            repository_root=repo_root,
            executor_factory=executor_factory,
        )
        if matched_key is not None:
            smoke_scorecard_receipt = render_scorecard(
                run,
                score_doc,
                repository_root=repo_root,
                executor_factory=executor_factory,
                render_pdf=render_pdf,
            )

    archive_res = archive_target_run(
        run,
        history_root=history_root,
        repository_root=repo_root,
        smoke_key_path=matched_key,
    )
    ror_payload = build_run_over_run_report(
        target_id=identity.target_id,
        history_root=history_root,
        runs_dir=effective_runs_dir,
        current_run_id=run.name,
        current_identity=identity,
        current_effectiveness=eff_payload,
    )
    ror_receipt = write_run_over_run_outputs(
        run,
        history_root=history_root,
        ror_payload=ror_payload,
        scorecard_payload=archive_res.get("scorecard"),
        render_pdf=render_pdf,
        timeout_seconds=settings.timeout_seconds,
        max_tex_bytes=settings.max_tex_bytes,
        max_pdf_bytes=settings.max_pdf_bytes,
        repository_root=repo_root,
        executor_factory=executor_factory,
        out_dir=out_dir,
    )

    return {
        "status": ror_receipt["status"],
        "run_id": run.name,
        "target_id": identity.target_id,
        "archive_status": archive_res["status"],
        "cohort_size": ror_payload["cohort_size"],
        "matched_smoke_target": matched_key is not None,
        "receipt": ror_receipt,
        "smoke_effectiveness_receipt": smoke_eff_receipt,
        "smoke_scorecard_receipt": smoke_scorecard_receipt,
        "ror_payload": ror_payload,
        "smoke_effectiveness": eff_payload,
    }


def finalize_efficacy_report(
    run_root: Path,
    settings: EfficacyReportSettings,
    *,
    runs_dir: Path | None = None,
    repository_root: Path | None = None,
    renderer: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Best-effort completion hook; never raises out of orchestration completion."""
    if not settings.enabled:
        return None
    run = Path(run_root)
    if not (run / "data").is_dir():
        return None
    if not has_accepted_publication_gate(run):
        return None
    try:
        return (renderer or run_efficacy_finalization)(
            run,
            settings,
            runs_dir=runs_dir,
            repository_root=repository_root,
        )
    except Exception as exc:
        _LOG.warning("efficacy report for run %s was not produced: %s", run.name, type(exc).__name__)
        return None


__all__ = ["finalize_efficacy_report", "run_efficacy_finalization"]
