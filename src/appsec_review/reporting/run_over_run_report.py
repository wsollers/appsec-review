"""Target-grouped finding archival and Run-over-Run (RoR) efficacy reporting."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import json
from pathlib import Path
from typing import Any

from appsec_review.observability.findings import (
    contracts,
    coverage_adapter,
    history,
    lead_adapter,
    lifecycle,
    run_adapter,
    scorecard,
    stability,
)
from appsec_review.observability.findings.contracts import is_actionable, is_published
from appsec_review.observability.findings.target_identity import (
    ResolvedTargetIdentity,
    normalize_target_id,
    resolve_target_identity,
)
import hashlib

from appsec_review.reporting.digest import field, table
from appsec_review.reporting.model import (
    Bar,
    BarChart,
    Box,
    Document,
    Fields,
    Heading,
    Note,
    Para,
    Stat,
    Stats,
)
from appsec_review.reporting.smoke_effectiveness import (
    REPOSITORY_ROOT,
    ExecutorFactory,
    build_smoke_effectiveness,
    render_latex_pdf_with_receipt,
)
from appsec_review.reporting.text import clean
from appsec_review.reporting.tokens import BoxKind, Limits
from appsec_review.storage import atomic_bytes, canonical_json

LIMITS = Limits(text_chars=1200, value_chars=220, rows=96, ids=32)
from appsec_review.container_runtime.executor import ContainerExecutor

SCHEMA = "appsec-review/run-over-run-efficacy-report/1"
RECEIPT_SCHEMA = "appsec-review/run-over-run-efficacy-receipt/1"
RENDERER = "appsec_review.reporting.run_over_run_report/1"
OUTPUT_DIRECTORY = Path("data") / "efficacy"

JSON_NAME = "run-over-run-report.json"
MD_NAME = "run-over-run-report.md"
TEX_NAME = "run-over-run-report.tex"
PDF_NAME = "run-over-run-report.pdf"
LOG_NAME = "run-over-run-report.latex.log"
PDFINFO_NAME = "run-over-run-report.pdfinfo.txt"
RECEIPT_NAME = "receipt.json"
SCORECARD_NAME = "scorecard.json"

LATEST_JSON_NAME = "latest-run-over-run.json"
LATEST_MD_NAME = "latest-run-over-run.md"

_ACCEPTED_TERMINAL_STATUSES = frozenset({"succeeded", "completed_with_gaps", "skipped_not_applicable"})
_VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_MAX_JSON_BYTES = 16_777_216


def _read_bounded_json(path: Path) -> Any | None:
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > _MAX_JSON_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def has_accepted_publication_gate(run_root: Path) -> bool:
    """Return True iff ``job_final_publication_gate`` has an accepted committed handoff."""
    run = Path(run_root)
    latest = _read_bounded_json(run / "data" / "jobs" / "job_final_publication_gate" / "latest.json")
    if not isinstance(latest, Mapping):
        return False
    rel_handoff = latest.get("handoff_path")
    if not isinstance(rel_handoff, str) or not rel_handoff.strip():
        return False
    try:
        handoff_path = (run / rel_handoff).resolve()
        handoff_path.relative_to(run.resolve())
    except (OSError, ValueError):
        return False
    handoff = _read_bounded_json(handoff_path)
    if not isinstance(handoff, Mapping):
        return False
    term = handoff.get("terminal_status")
    if isinstance(term, str) and term in _ACCEPTED_TERMINAL_STATUSES:
        return True
    status_doc = _read_bounded_json(handoff_path.parent / "status.json")
    if isinstance(status_doc, Mapping) and status_doc.get("terminal_status") in _ACCEPTED_TERMINAL_STATUSES:
        return True
    return term is None


def _fallback_snapshot_from_run(
    run_root: Path,
    *,
    target_id: str,
    source_revision: str,
    reviewed_units: Mapping[str, str | None] | None,
    unreviewed_units: Mapping[str, str] | None,
    extra_gaps: Sequence[str] = (),
) -> dict[str, Any]:
    """Construct a schema-valid ``finding-snapshot/1`` when ``job_final_report_publication`` is absent."""
    eff = build_smoke_effectiveness(run_root, key_path=None)
    identities = run_adapter.run_identities(run_root)
    normalized_findings: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for rec in eff.get("adjudicated_findings", ()):
        if not isinstance(rec, Mapping):
            continue
        status = str(rec.get("status") or "")
        if status == "refuted":
            continue
        fid = str(rec.get("finding_id") or rec.get("claim_id") or "")
        if not fid or fid in seen_ids:
            continue
        seen_ids.add(fid)

        path = str(rec.get("path") or "unresolved/unknown")
        start_line = rec.get("start_line") if isinstance(rec.get("start_line"), int) and rec["start_line"] >= 1 else 1
        end_line = rec.get("end_line") if isinstance(rec.get("end_line"), int) and rec["end_line"] >= start_line else start_line

        pkg_kind = str(rec.get("package_kind") or "")
        lane = "lead" if pkg_kind == "finding_lead" else ("hunt" if pkg_kind == "hunt" else None)
        sev = str(rec.get("severity") or "").lower()
        severity = sev if sev in _VALID_SEVERITIES else None

        raw_bucket = str(rec.get("bucket") or "")
        if raw_bucket in ("findings", "verification_backlog", "withheld"):
            bucket = raw_bucket
        elif status == "confirmed":
            bucket = "findings"
        else:
            bucket = "verification_backlog"

        cwe = contracts.normalize_cwe(rec.get("cwe")) if rec.get("cwe") else None
        claim_id = str(rec["claim_id"]) if isinstance(rec.get("claim_id"), str) and rec["claim_id"] else None
        scanners = rec.get("scanners") if isinstance(rec.get("scanners"), list) else []

        finding_obj: dict[str, Any] = {
            "finding_id": fid,
            "state": "confirmed" if status == "confirmed" else "supported",
            "weakness_cwe": cwe,
            "locations": [{"path": path, "start_line": start_line, "end_line": end_line}],
            "lead_families": [],
            "scanner_backed": bool(scanners) or lane == "lead",
            "duplicates_collapsed": 0,
            "lane": lane,
            "bucket": bucket,
            "severity": severity,
            "ship_block_status": (
                "ship_blocking"
                if status == "confirmed" and severity in ("critical", "high")
                else ("not_ship_blocking" if status == "confirmed" else "needs_verification")
            ),
            "claim_id": claim_id,
            "security_predicate": str(rec.get("title") or "")[:120] or None,
        }
        normalized_findings.append(finding_obj)

    return contracts.build_snapshot(
        run_id=run_root.name,
        target_id=target_id,
        source_revision=source_revision,
        findings=normalized_findings,
        fingerprint=run_adapter.fingerprint,
        stage="published",
        reviewed_units=reviewed_units,
        unreviewed_units=unreviewed_units,
        gaps=sorted(set(extra_gaps)),
        configuration_sha256=identities.get("configuration_sha256"),
        guidance_sha256=identities.get("guidance_sha256"),
        model_sha256=identities.get("model_sha256"),
    )


def _extract_snapshot_for_run(
    run_root: Path,
    identity: ResolvedTargetIdentity,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Extract ``(snapshot, coverage_info)`` from ``run_root``."""
    try:
        cov = coverage_adapter.coverage_from_run(run_root)
    except Exception:
        cov = {
            "reviewed": None,
            "unreviewed": None,
            "unit_gaps": ["coverage_unavailable"],
            "entry_points": None,
            "entry_gaps": [],
        }

    try:
        snap = run_adapter.snapshot_from_run(
            run_root,
            target_id=identity.target_id,
            source_revision=identity.source_revision,
            reviewed_units=cov.get("reviewed"),
            unreviewed_units=cov.get("unreviewed"),
            unit_gaps=cov.get("unit_gaps") or (),
        )
        return snap, cov
    except Exception:
        snap = _fallback_snapshot_from_run(
            run_root,
            target_id=identity.target_id,
            source_revision=identity.source_revision,
            reviewed_units=cov.get("reviewed"),
            unreviewed_units=cov.get("unreviewed"),
            extra_gaps=[*(cov.get("unit_gaps") or ()), "snapshot_from_gate_fallback"],
        )
        return snap, cov


def archive_target_run(
    run_root: Path,
    *,
    history_root: Path,
    repository_root: Path | None = None,
    smoke_key_path: Path | None = None,
) -> dict[str, Any]:
    """Idempotently archive ``run_root`` under ``history_root/<target_id>/`` and compute scorecard + lifecycle."""
    from appsec_review.storage.validation import validation_scope

    _ = smoke_key_path
    run = Path(run_root).resolve()
    hist_root = Path(history_root).resolve()
    identity = resolve_target_identity(run, repository_root=repository_root)

    if not has_accepted_publication_gate(run):
        return {
            "status": "skipped_incomplete_run",
            "run_id": run.name,
            "target_identity": identity.to_dict(),
            "snapshot": None,
            "snapshot_receipt": None,
            "lifecycle": None,
            "lifecycle_receipt": None,
            "scorecard": None,
        }

    loaded = history.load_history(hist_root, identity.target_id)
    existing_row = next(
        (
            row
            for row in loaded["snapshots"]
            if row["run_id"] == run.name and row["stage"] == "published"
        ),
        None,
    )

    with validation_scope(run):
        cov_info: dict[str, Any]
        leads_payload: list[dict[str, Any]] | None = None
        input_gaps: list[str] = []

        if existing_row is not None:
            snapshot = history.read_snapshot(hist_root, identity.target_id, existing_row["sha256"])
            snapshot_receipt = {
                "status": "already_archived",
                "sha256": existing_row["sha256"],
                "path": str(hist_root / identity.target_id / "snapshots" / f"{existing_row['sha256']}.json"),
            }
            cached_scorecard = _read_bounded_json(
                hist_root / identity.target_id / "scorecards" / f"{existing_row['sha256']}.json"
            )
            prior_sha = history.latest_prior(loaded, stage="published", before_run_id=run.name)
            classified: dict[str, Any] | None = None
            lifecycle_receipt: dict[str, str] | None = None
            if prior_sha is not None:
                prior_snapshot = history.read_snapshot(hist_root, identity.target_id, prior_sha)
                classified = lifecycle.classify(
                    prior_snapshot,
                    snapshot,
                    previously_fixed=history.previously_fixed(loaded),
                )
                lifecycle_receipt = dict(history.publish_lifecycle(hist_root, identity.target_id, classified))
                loaded = history.load_history(hist_root, identity.target_id)
            if isinstance(cached_scorecard, Mapping) and cached_scorecard.get("schema") == scorecard.METRICS_SCHEMA:
                return {
                    "status": "already_archived",
                    "run_id": run.name,
                    "target_identity": identity.to_dict(),
                    "snapshot": snapshot,
                    "snapshot_receipt": snapshot_receipt,
                    "lifecycle": classified,
                    "lifecycle_receipt": lifecycle_receipt,
                    "scorecard": dict(cached_scorecard),
                }
            try:
                cov_info = coverage_adapter.coverage_from_run(run)
            except Exception:
                cov_info = {"entry_points": None, "entry_gaps": []}
        else:
            snapshot, cov_info = _extract_snapshot_for_run(run, identity)
            pub_res = history.publish_snapshot(hist_root, snapshot)
            snapshot_receipt = dict(pub_res)
            loaded = history.load_history(hist_root, identity.target_id)
            prior_sha = history.latest_prior(loaded, stage="published", before_run_id=run.name)
            classified = None
            lifecycle_receipt = None
            if prior_sha is not None:
                prior_snapshot = history.read_snapshot(hist_root, identity.target_id, prior_sha)
                classified = lifecycle.classify(
                    prior_snapshot,
                    snapshot,
                    previously_fixed=history.previously_fixed(loaded),
                )
                lifecycle_receipt = dict(history.publish_lifecycle(hist_root, identity.target_id, classified))
                loaded = history.load_history(hist_root, identity.target_id)

        input_gaps.extend(cov_info.get("entry_gaps") or ())
        try:
            leads_res = lead_adapter.leads_from_run(run)
            if isinstance(leads_res, Mapping):
                leads_payload = leads_res.get("leads") if isinstance(leads_res.get("leads"), list) else None
                input_gaps.extend(leads_res.get("gaps") or ())
        except Exception:
            input_gaps.append("leads_unavailable")

    telemetry_summary = _read_bounded_json(run / "data" / "telemetry" / "summary.json")
    triage_reduction = (
        telemetry_summary.get("triage_reduction")
        if isinstance(telemetry_summary, Mapping) and isinstance(telemetry_summary.get("triage_reduction"), Mapping)
        else None
    )

    published_snapshots = [
        history.read_snapshot(hist_root, identity.target_id, row["sha256"])
        for row in loaded["snapshots"]
        if row["stage"] == "published"
    ]
    stab = stability.series(published_snapshots, subset="published") if len(published_snapshots) >= 2 else None
    flap = stability.flapping(published_snapshots) if len(published_snapshots) >= 3 else None

    sc_inputs = scorecard.Inputs(
        triage_reduction=triage_reduction,
        leads=leads_payload,
        lifecycle=classified if classified is not None else None,
        ages=history.ages(loaded, stage="published") if classified is not None else None,
        entry_points=cov_info.get("entry_points"),
        stability=stab,
        flapping=flap,
        input_gaps=tuple(sorted(set(input_gaps))),
    )
    scorecard_doc = scorecard.build(snapshot, sc_inputs)
    snap_sha = snapshot_receipt.get("sha256")
    if isinstance(snap_sha, str) and len(snap_sha) == 64:
        sc_cache_dir = hist_root / identity.target_id / "scorecards"
        sc_cache_dir.mkdir(parents=True, exist_ok=True)
        atomic_bytes(sc_cache_dir / f"{snap_sha}.json", canonical_json(scorecard_doc))

    return {
        "status": snapshot_receipt.get("status", "published"),
        "run_id": run.name,
        "target_identity": identity.to_dict(),
        "snapshot": snapshot,
        "snapshot_receipt": snapshot_receipt,
        "lifecycle": classified,
        "lifecycle_receipt": lifecycle_receipt,
        "scorecard": scorecard_doc,
    }


def _extract_run_enrichment(
    archived_run_root: Path | None,
    snapshot: Mapping[str, Any],
    *,
    in_memory_effectiveness: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Gather funnel, SAST-vs-Hunter, PoC/Remediation, token/cost efficiency, and smoke metrics for one run."""
    findings = [f for f in snapshot.get("findings", ()) if isinstance(f, Mapping)]
    published = [f for f in findings if is_published(f)]
    confirmed = [f for f in published if f.get("state") == "confirmed"]
    if not confirmed and published:
        confirmed = published

    sast_from_snap = sum(1 for f in confirmed if f.get("lane") == "lead")
    hunt_from_snap = sum(1 for f in confirmed if f.get("lane") == "hunt")

    eff_doc: Mapping[str, Any] | None = in_memory_effectiveness
    if eff_doc is None and archived_run_root is not None and archived_run_root.is_dir():
        saved_eff = _read_bounded_json(archived_run_root / "data" / "verification" / "smoke-effectiveness.json")
        if isinstance(saved_eff, Mapping):
            eff_doc = saved_eff
        elif (archived_run_root / "data").is_dir():
            try:
                eff_doc = build_smoke_effectiveness(archived_run_root, key_path=None)
            except Exception:
                eff_doc = None

    funnel = {
        "leads": None,
        "packages": None,
        "claims": len(findings),
        "confirmed": len(confirmed),
    }
    lane_attr = {
        "sast_confirmed": sast_from_snap,
        "hunter_confirmed": hunt_from_snap,
        "sast_only": sast_from_snap,
        "hunter_only": hunt_from_snap,
        "both_lanes": 0,
    }
    qualification = {
        "poc_generated": 0,
        "poc_verified": 0,
        "remediation_build_checked": 0,
        "remediation_rejected": 0,
    }
    smoke_gt: dict[str, Any] | None = None

    if isinstance(eff_doc, Mapping):
        ef_f = eff_doc.get("funnel")
        if isinstance(ef_f, Mapping):
            funnel = {
                "leads": ef_f.get("scanner_leads"),
                "packages": ef_f.get("packages_total"),
                "claims": ef_f.get("claims_total", len(findings)),
                "confirmed": ef_f.get("confirmed_total", len(confirmed)),
            }
        ef_l = eff_doc.get("lane_attribution")
        if isinstance(ef_l, Mapping):
            lane_attr = {
                "sast_confirmed": ef_l.get("confirmed_from_sast_lane", sast_from_snap),
                "hunter_confirmed": ef_l.get("confirmed_from_hunter_lane", hunt_from_snap),
                "sast_only": ef_l.get("sast_only_count", sast_from_snap),
                "hunter_only": ef_l.get("hunter_only_count", hunt_from_snap),
                "both_lanes": ef_l.get("both_lanes_count", 0),
            }
        adj = [r for r in eff_doc.get("adjudicated_findings", ()) if isinstance(r, Mapping) and r.get("status") == "confirmed"]
        qualification = {
            "poc_generated": sum(
                1 for r in adj if str(r.get("poc_status") or "none") not in ("none", "not_generated", "skipped", "failed", "missing")
            ),
            "poc_verified": sum(
                1 for r in adj if str(r.get("poc_status") or "") in ("verified", "passed", "reproduced", "compile_checked")
            ),
            "remediation_build_checked": sum(
                1 for r in adj if str(r.get("remediation_validation_status") or "") in ("build_checked", "validated", "verified")
            ),
            "remediation_rejected": sum(
                1 for r in adj if str(r.get("remediation_validation_status") or "") in ("rejected", "failed")
            ),
        }
        keyed = eff_doc.get("keyed")
        if isinstance(keyed, Mapping) and isinstance(keyed.get("headline_metrics"), Mapping):
            hm = keyed["headline_metrics"]
            smoke_gt = {
                "code_tp_recall": hm.get("code_tp_recall"),
                "sast_only_code_recall": hm.get("sast_only_code_recall"),
                "hunter_only_code_recall": hm.get("hunter_only_code_recall"),
                "combined_sast_hunter_recall": hm.get("combined_sast_hunter_recall"),
                "vendored_cve_recall": hm.get("vendored_cve_recall"),
                "planted_fp_trap_rejection_rate": hm.get("planted_fp_trap_rejection_rate"),
                "precision": hm.get("precision"),
            }

    total_tokens: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    known_cost_usd: float | None = None
    wall_time_ms: int | None = None

    if archived_run_root is not None and archived_run_root.is_dir():
        summary = _read_bounded_json(archived_run_root / "data" / "telemetry" / "summary.json")
        if isinstance(summary, Mapping):
            mt = summary.get("model_tokens")
            if isinstance(mt, Mapping):
                in_t = mt.get("input_tokens")
                out_t = mt.get("output_tokens")
                if isinstance(in_t, int) and isinstance(out_t, int):
                    input_tokens = in_t
                    output_tokens = out_t
                    total_tokens = in_t + out_t
            wt = summary.get("wall_time_ms")
            if isinstance(wt, int):
                wall_time_ms = wt
            cp = summary.get("cost_provenance")
            if isinstance(cp, Mapping) and isinstance(cp.get("run"), Mapping):
                ka = cp["run"].get("known_amounts")
                if isinstance(ka, Mapping) and isinstance(ka.get("USD"), (int, float)):
                    known_cost_usd = round(float(ka["USD"]), 6)

    confirmed_n = len(confirmed)
    efficiency = {
        "total_tokens": total_tokens,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "known_cost_usd": known_cost_usd,
        "tokens_per_confirmed_finding": (
            round(total_tokens / confirmed_n, 1) if total_tokens is not None and confirmed_n > 0 else None
        ),
        "cost_per_confirmed_finding": (
            round(known_cost_usd / confirmed_n, 6) if known_cost_usd is not None and confirmed_n > 0 else None
        ),
        "wall_time_ms": wall_time_ms,
    }

    return {
        "funnel": funnel,
        "lane_attribution": lane_attr,
        "qualification": qualification,
        "efficiency": efficiency,
        "smoke_ground_truth": smoke_gt,
    }


def _jaccard_overlap(prior_snap: Mapping[str, Any], current_snap: Mapping[str, Any]) -> float:
    prior_fps = {
        str(f["fingerprint"]["relocated"])
        for f in prior_snap.get("findings", ())
        if isinstance(f, Mapping) and is_published(f) and isinstance(f.get("fingerprint"), Mapping)
    }
    curr_fps = {
        str(f["fingerprint"]["relocated"])
        for f in current_snap.get("findings", ())
        if isinstance(f, Mapping) and is_published(f) and isinstance(f.get("fingerprint"), Mapping)
    }
    union = prior_fps | curr_fps
    if not union:
        return 1.0
    return round(len(prior_fps & curr_fps) / len(union), 4)


def build_run_over_run_report(
    *,
    target_id: str,
    history_root: Path,
    runs_dir: Path | None = None,
    current_run_id: str | None = None,
    current_identity: ResolvedTargetIdentity | None = None,
    current_effectiveness: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build ``appsec-review/run-over-run-efficacy-report/1`` strictly for ``target_id``."""
    norm_tid = normalize_target_id(target_id)
    hist_root = Path(history_root).resolve()
    loaded = history.load_history(hist_root, norm_tid)

    pub_rows = [row for row in loaded["snapshots"] if row["stage"] == "published"]
    pub_rows.sort(key=lambda r: (r["run_id"], r["sha256"]))
    snapshots = [history.read_snapshot(hist_root, norm_tid, row["sha256"]) for row in pub_rows]

    series_rows: list[dict[str, Any]] = []
    ever_seen_fps: set[str] = set()
    ever_disappeared_fps: set[str] = set()
    persisted_fixed = set(history.previously_fixed(loaded))
    jaccards: list[float] = []

    for idx, (row_meta, snap) in enumerate(zip(pub_rows, snapshots, strict=True)):
        rid = snap["run_id"]
        findings = [f for f in snap.get("findings", ()) if isinstance(f, Mapping)]
        published = [f for f in findings if is_published(f)]
        confirmed = [f for f in published if f.get("state") == "confirmed"]
        if not confirmed and published:
            confirmed = published
        backlog = [
            f for f in findings if f.get("bucket") == "verification_backlog" or f.get("state") == "supported"
        ]

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in confirmed:
            s = str(f.get("severity") or "").lower()
            if s in sev_counts:
                sev_counts[s] += 1

        ship_blockers = sum(
            1
            for f in confirmed
            if f.get("ship_block_status") in ("ship_blocking", "ship_blocking_pending_distinct_verification")
        )

        curr_fps = {
            str(f["fingerprint"]["exact"])
            for f in published
            if isinstance(f.get("fingerprint"), Mapping)
        } | {
            str(f["fingerprint"]["relocated"])
            for f in published
            if isinstance(f.get("fingerprint"), Mapping)
        }

        if idx == 0:
            lc_summary = {
                "new": len(published),
                "persisting": 0,
                "fixed": 0,
                "regressed": 0,
                "reclassified": 0,
                "fix_candidate": 0,
                "not_redetected": 0,
                "not_covered": 0,
            }
            jaccard: float | None = None
        else:
            prior_snap = snapshots[idx - 1]
            jaccard = _jaccard_overlap(prior_snap, snap)
            jaccards.append(jaccard)
            classified = lifecycle.classify(
                prior_snap,
                snap,
                previously_fixed=frozenset(persisted_fixed | ever_disappeared_fps),
            )
            matches = lifecycle.match_findings(prior_snap["findings"], snap["findings"])
            prior_by_id = {f["finding_id"]: f for f in prior_snap["findings"]}
            curr_by_id = {f["finding_id"]: f for f in snap["findings"]}
            reclassified_count = 0
            for pid, (cid, _tier) in matches.items():
                pf = prior_by_id.get(pid, {})
                cf = curr_by_id.get(cid, {})
                if (
                    pf.get("severity") != cf.get("severity")
                    or pf.get("state") != cf.get("state")
                    or pf.get("bucket") != cf.get("bucket")
                ):
                    reclassified_count += 1

            prior_states = [r["state"] for r in classified["prior"]]
            curr_states = [r["state"] for r in classified["current"]]
            fix_cand = sum(1 for s in prior_states if s == "fix_candidate")
            not_redet = sum(1 for s in prior_states if s == "not_redetected")
            not_cov = sum(1 for s in prior_states if s == "not_covered")
            strict_fixed = sum(1 for s in prior_states if s == "fixed")
            effective_fixed = strict_fixed + fix_cand + not_redet

            for pr in classified["prior"]:
                if pr["state"] in ("fixed", "fix_candidate", "not_redetected"):
                    ever_disappeared_fps.add(pr["fingerprint_exact"])
                    pf_full = prior_by_id.get(pr["finding_id"])
                    if isinstance(pf_full, Mapping) and isinstance(pf_full.get("fingerprint"), Mapping):
                        ever_disappeared_fps.add(str(pf_full["fingerprint"]["relocated"]))

            lc_summary = {
                "new": sum(1 for s in curr_states if s == "new"),
                "persisting": sum(1 for s in curr_states if s == "persisting"),
                "fixed": effective_fixed,
                "regressed": sum(1 for s in curr_states if s == "regressed"),
                "reclassified": reclassified_count,
                "fix_candidate": fix_cand,
                "not_redetected": not_redet,
                "not_covered": not_cov,
            }

        ever_seen_fps |= curr_fps

        archived_dir = (Path(runs_dir) / rid) if runs_dir is not None else None
        in_mem_eff = current_effectiveness if (current_run_id and rid == current_run_id) else None
        enrichment = _extract_run_enrichment(archived_dir, snap, in_memory_effectiveness=in_mem_eff)

        series_rows.append(
            {
                "run_id": rid,
                "source_revision": snap["source_revision"],
                "snapshot_sha256": row_meta["sha256"],
                "confirmed_total": len(confirmed),
                "critical": sev_counts["critical"],
                "high": sev_counts["high"],
                "medium": sev_counts["medium"],
                "low": sev_counts["low"],
                "ship_blockers": ship_blockers,
                "backlog_supported": len(backlog),
                "lifecycle": lc_summary,
                "jaccard_stability_vs_prior": jaccard,
                "funnel": enrichment["funnel"],
                "lane_attribution": enrichment["lane_attribution"],
                "qualification": enrichment["qualification"],
                "efficiency": enrichment["efficiency"],
                "smoke_ground_truth": enrichment["smoke_ground_truth"],
            }
        )

    latest_row = series_rows[-1] if series_rows else None
    ident_dict = (
        current_identity.to_dict()
        if current_identity is not None
        else {
            "target_id": norm_tid,
            "source_revision": latest_row["source_revision"] if latest_row else "unknown-revision",
            "repository": None,
            "snapshot_commit": None,
            "source_fingerprint": None,
            "resolution_source": "history_store",
        }
    )

    stab_series = stability.series(snapshots, subset="published") if len(snapshots) >= 2 else None
    stability_summary = {
        "consecutive_pairs": len(jaccards),
        "mean_jaccard": round(sum(jaccards) / len(jaccards), 4) if jaccards else None,
        "min_jaccard": min(jaccards) if jaccards else None,
        "latest_jaccard": jaccards[-1] if jaccards else None,
        "controlled_series_status": stab_series.get("status") if isinstance(stab_series, Mapping) else "single_run",
    }

    return {
        "schema": SCHEMA,
        "target_id": norm_tid,
        "target_identity": ident_dict,
        "current_run_id": current_run_id or (latest_row["run_id"] if latest_row else None),
        "cohort_size": len(series_rows),
        "stability_summary": stability_summary,
        "per_run_series": series_rows,
    }


def _fmt_pct(val: float | None) -> str:
    return "n/a" if val is None else f"{val * 100.0:.1f}%"


def _fmt_num(val: int | float | None) -> str:
    if val is None:
        return "n/a"
    if isinstance(val, float):
        return f"{val:,.2f}"
    return f"{val:,}"


def render_run_over_run_markdown(payload: Mapping[str, Any]) -> str:
    """Render an executive-readable Markdown Run-over-Run efficacy report."""
    tid = str(payload.get("target_id") or "unknown-target")
    ident = payload.get("target_identity") if isinstance(payload.get("target_identity"), Mapping) else {}
    cohort = int(payload.get("cohort_size") or 0)
    curr_run = str(payload.get("current_run_id") or "n/a")
    stab = payload.get("stability_summary") if isinstance(payload.get("stability_summary"), Mapping) else {}
    rows = [r for r in payload.get("per_run_series", ()) if isinstance(r, Mapping)]
    latest = rows[-1] if rows else {}

    lines = [
        f"# Run-over-Run Efficacy Report ? `{tid}`",
        "",
        "## 1. KPI Summary",
        "",
        f"- **Target ID:** `{tid}`",
        f"- **Repository:** `{ident.get('repository') or 'n/a'}`",
        f"- **Latest Run ID:** `{curr_run}` (`{str(latest.get('source_revision') or 'n/a')[:16]}`)",
        f"- **Archived Target Cohort Size:** `{cohort}` run(s)",
        f"- **Latest Confirmed Findings:** `{latest.get('confirmed_total', 0)}` "
        f"(Critical `{latest.get('critical', 0)}`, High `{latest.get('high', 0)}`, "
        f"Medium `{latest.get('medium', 0)}`, Low `{latest.get('low', 0)}`)",
        f"- **Mean Consecutive Jaccard Stability:** `{_fmt_pct(stab.get('mean_jaccard'))}` "
        f"(Latest: `{_fmt_pct(stab.get('latest_jaccard'))}`)",
        "",
        "## 2. Target Run-over-Run Progression Table",
        "",
        "| Run ID | Revision | Confirmed | Crit / High / Med / Low | Ship Blockers | Backlog Supported |",
        "| --- | --- | ---: | --- | ---: | ---: |",
    ]
    for r in rows:
        rev = str(r.get("source_revision") or "")[:12]
        chml = f"{r.get('critical', 0)} / {r.get('high', 0)} / {r.get('medium', 0)} / {r.get('low', 0)}"
        lines.append(
            f"| `{r['run_id']}` | `{rev}` | {r.get('confirmed_total', 0)} | {chml} | "
            f"{r.get('ship_blockers', 0)} | {r.get('backlog_supported', 0)} |"
        )

    lines.extend(
        [
            "",
            "## 3. Lifecycle Churn & Stability Analysis",
            "",
            "| Run ID | New | Persisting | Fixed | Regressed | Reclassified | Jaccard vs Prior |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for r in rows:
        lc = r.get("lifecycle") if isinstance(r.get("lifecycle"), Mapping) else {}
        lines.append(
            f"| `{r['run_id']}` | {lc.get('new', 0)} | {lc.get('persisting', 0)} | "
            f"{lc.get('fixed', 0)} | {lc.get('regressed', 0)} | {lc.get('reclassified', 0)} | "
            f"{_fmt_pct(r.get('jaccard_stability_vs_prior'))} |"
        )

    lines.extend(
        [
            "",
            "## 4. Funnel & SAST-vs-Hunter Attribution",
            "",
            "| Run ID | Scanner Leads | Packages | Claims | Confirmed | SAST Confirmed | Hunter Confirmed | SAST-Only | Hunter-Only | Both Lanes |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for r in rows:
        fn = r.get("funnel") if isinstance(r.get("funnel"), Mapping) else {}
        la = r.get("lane_attribution") if isinstance(r.get("lane_attribution"), Mapping) else {}
        lines.append(
            f"| `{r['run_id']}` | {_fmt_num(fn.get('leads'))} | {_fmt_num(fn.get('packages'))} | "
            f"{_fmt_num(fn.get('claims'))} | {fn.get('confirmed', 0)} | "
            f"{la.get('sast_confirmed', 0)} | {la.get('hunter_confirmed', 0)} | "
            f"{la.get('sast_only', 0)} | {la.get('hunter_only', 0)} | {la.get('both_lanes', 0)} |"
        )

    lines.extend(
        [
            "",
            "## 5. Qualification Velocity (PoC + Build-Checked Fixes)",
            "",
            "| Run ID | Confirmed | PoC Generated | PoC Verified | Build-Checked Fixes | Rejected Fixes |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for r in rows:
        q = r.get("qualification") if isinstance(r.get("qualification"), Mapping) else {}
        lines.append(
            f"| `{r['run_id']}` | {r.get('confirmed_total', 0)} | {q.get('poc_generated', 0)} | "
            f"{q.get('poc_verified', 0)} | {q.get('remediation_build_checked', 0)} | "
            f"{q.get('remediation_rejected', 0)} |"
        )

    lines.extend(
        [
            "",
            "## 6. Model Cost & Token Efficiency Trend",
            "",
            "| Run ID | Total Tokens | Tokens / Confirmed | Known Cost (USD) | Cost / Confirmed | Wall Time (s) |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for r in rows:
        ef = r.get("efficiency") if isinstance(r.get("efficiency"), Mapping) else {}
        wt = ef.get("wall_time_ms")
        wt_str = f"{wt / 1000.0:.1f}" if isinstance(wt, int) else "n/a"
        cost = ef.get("known_cost_usd")
        cost_str = f"${cost:.4f}" if isinstance(cost, (int, float)) else "n/a"
        cpc = ef.get("cost_per_confirmed_finding")
        cpc_str = f"${cpc:.4f}" if isinstance(cpc, (int, float)) else "n/a"
        lines.append(
            f"| `{r['run_id']}` | {_fmt_num(ef.get('total_tokens'))} | "
            f"{_fmt_num(ef.get('tokens_per_confirmed_finding'))} | {cost_str} | {cpc_str} | {wt_str} |"
        )

    gt_rows = [r for r in rows if isinstance(r.get("smoke_ground_truth"), Mapping)]
    if gt_rows:
        lines.extend(
            [
                "",
                "## 7. Known-Smoke Ground-Truth Efficacy",
                "",
                "| Run ID | Code TP Recall | SAST-Only Recall | Hunter-Only Recall | Combined Recall | Vendored CVE Recall | FP Trap Rejection | Precision |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for r in gt_rows:
            gt = r["smoke_ground_truth"]
            lines.append(
                f"| `{r['run_id']}` | {_fmt_pct(gt.get('code_tp_recall'))} | "
                f"{_fmt_pct(gt.get('sast_only_code_recall'))} | {_fmt_pct(gt.get('hunter_only_code_recall'))} | "
                f"{_fmt_pct(gt.get('combined_sast_hunter_recall'))} | {_fmt_pct(gt.get('vendored_cve_recall'))} | "
                f"{_fmt_pct(gt.get('planted_fp_trap_rejection_rate'))} | {_fmt_pct(gt.get('precision'))} |"
            )

    lines.append("")
    return "\n".join(lines)


def build_run_over_run_document(
    payload: Mapping[str, Any],
    *,
    source_date_epoch: int = 0,
) -> Document:
    """Build a ``reporting.model.Document`` for ``run-over-run-report.tex`` / ``.pdf``."""
    tid = clean(str(payload.get("target_id") or "unknown-target"))
    curr_run = clean(str(payload.get("current_run_id") or "latest"))
    cohort = int(payload.get("cohort_size") or 0)
    stab = payload.get("stability_summary") if isinstance(payload.get("stability_summary"), Mapping) else {}
    rows = [r for r in payload.get("per_run_series", ()) if isinstance(r, Mapping)]
    latest = rows[-1] if rows else {}
    latest_la = latest.get("lane_attribution") if isinstance(latest.get("lane_attribution"), Mapping) else {}
    latest_q = latest.get("qualification") if isinstance(latest.get("qualification"), Mapping) else {}

    stats_block = Stats(
        (
            Stat("Archived Runs", str(cohort), "supported"),
            Stat("Latest Confirmed", str(latest.get("confirmed_total", 0)), "confirmed" if latest.get("confirmed_total", 0) else "neutral"),
            Stat("Latest Jaccard", _fmt_pct(stab.get("latest_jaccard")), "neutral"),
            Stat("Hunter Rescues", str(latest_la.get("hunter_only", 0)), "confirmed" if latest_la.get("hunter_only", 0) else "neutral"),
            Stat("Build-Checked Fixes", str(latest_q.get("remediation_build_checked", 0)), "confirmed" if latest_q.get("remediation_build_checked", 0) else "neutral"),
        )
    )

    blocks: list[Any] = [
        stats_block,
        Note(
            f"Target {tid} has {cohort} archived run(s). "
            "Snapshots and lifecycles are strictly partitioned by canonical target identity."
        ),
    ]

    if rows:
        blocks.extend(
            [
                Heading(1, "Run-over-run progression and lifecycle churn", "progression"),
                BarChart(
                    title="Confirmed findings per archived run of this target",
                    unit="findings",
                    bars=tuple(
                        Bar(
                            clean(str(r["run_id"])[:24]),
                            float(r.get("confirmed_total") or 0),
                            str(r.get("confirmed_total") or 0),
                            "confirmed",
                        )
                        for r in rows[-12:]
                    ),
                    caption="Chronological progression across archived snapshots of this target.",
                ),
                Box(
                    BoxKind.RESULT,
                    "Lifecycle transitions and Jaccard stability",
                    items=(
                        table(
                            ("Run ID", "Revision", "Confirmed", "New", "Persist", "Fixed", "Regress", "Jaccard"),
                            [
                                (
                                    str(r["run_id"]),
                                    str(r.get("source_revision") or "")[:10],
                                    str(r.get("confirmed_total", 0)),
                                    str((r.get("lifecycle") or {}).get("new", 0)),
                                    str((r.get("lifecycle") or {}).get("persisting", 0)),
                                    str((r.get("lifecycle") or {}).get("fixed", 0)),
                                    str((r.get("lifecycle") or {}).get("regressed", 0)),
                                    _fmt_pct(r.get("jaccard_stability_vs_prior")),
                                )
                                for r in rows
                            ],
                            LIMITS,
                            widths=(0.20, 0.14, 0.11, 0.10, 0.11, 0.10, 0.11, 0.13),
                        ),
                    ),
                ),
                Heading(1, "Funnel, lane attribution and qualification", "funnel"),
                Box(
                    BoxKind.EVIDENCE,
                    "SAST vs Hunter confirmation and build-checked remediations",
                    items=(
                        table(
                            ("Run ID", "Leads", "Packages", "Confirmed", "SAST", "Hunter", "Both", "PoC", "Fixes"),
                            [
                                (
                                    str(r["run_id"]),
                                    _fmt_num((r.get("funnel") or {}).get("leads")),
                                    _fmt_num((r.get("funnel") or {}).get("packages")),
                                    str(r.get("confirmed_total", 0)),
                                    str((r.get("lane_attribution") or {}).get("sast_only", 0)),
                                    str((r.get("lane_attribution") or {}).get("hunter_only", 0)),
                                    str((r.get("lane_attribution") or {}).get("both_lanes", 0)),
                                    str((r.get("qualification") or {}).get("poc_generated", 0)),
                                    str((r.get("qualification") or {}).get("remediation_build_checked", 0)),
                                )
                                for r in rows
                            ],
                            LIMITS,
                            widths=(0.19, 0.10, 0.10, 0.11, 0.10, 0.10, 0.10, 0.10, 0.10),
                        ),
                    ),
                ),
            ]
        )

    gt_rows = [r for r in rows if isinstance(r.get("smoke_ground_truth"), Mapping)]
    if gt_rows:
        blocks.extend(
            [
                Heading(1, "Known-smoke ground-truth efficacy", "ground-truth"),
                Box(
                    BoxKind.VERIFICATION,
                    "Planted vulnerability recall and false-positive trap rejection",
                    items=(
                        table(
                            ("Run ID", "Code Recall", "SAST", "Hunter", "CVE Recall", "FP Reject", "Precision"),
                            [
                                (
                                    str(r["run_id"]),
                                    _fmt_pct(r["smoke_ground_truth"].get("code_tp_recall")),
                                    _fmt_pct(r["smoke_ground_truth"].get("sast_only_code_recall")),
                                    _fmt_pct(r["smoke_ground_truth"].get("hunter_only_code_recall")),
                                    _fmt_pct(r["smoke_ground_truth"].get("vendored_cve_recall")),
                                    _fmt_pct(r["smoke_ground_truth"].get("planted_fp_trap_rejection_rate")),
                                    _fmt_pct(r["smoke_ground_truth"].get("precision")),
                                )
                                for r in gt_rows
                            ],
                            LIMITS,
                            widths=(0.20, 0.14, 0.13, 0.13, 0.14, 0.13, 0.13),
                        ),
                    ),
                ),
            ]
        )

    blocks.extend(
        [
            Heading(1, "Provenance", "provenance"),
            Box(
                BoxKind.PROVENANCE,
                "Run-over-run report provenance",
                items=(
                    Fields(
                        (
                            field("Schema", SCHEMA, LIMITS, mono=True),
                            field("Target ID", tid, LIMITS, mono=True),
                            field("Cohort size", str(cohort), LIMITS, mono=True),
                            field("Renderer", RENDERER, LIMITS, mono=True),
                        )
                    ),
                ),
            ),
        ]
    )

    head_sha = hashlib.sha256(canonical_json(payload)).hexdigest()
    return Document(
        title="Run-over-Run Efficacy",
        run_id=curr_run,
        subtitle=f"Target {tid} ({cohort} archived run(s))",
        status_badge="TRACKED",
        status_tone="confirmed",
        source_date_epoch=source_date_epoch,
        ledger_head=head_sha,
        blocks=tuple(blocks),
        renderer=RENDERER,
        head_label="efficacy sha256",
    )


def write_run_over_run_outputs(
    run_root: Path,
    *,
    history_root: Path,
    ror_payload: Mapping[str, Any],
    scorecard_payload: Mapping[str, Any] | None = None,
    render_pdf: bool = True,
    timeout_seconds: int = 600,
    max_tex_bytes: int = 8_388_608,
    max_pdf_bytes: int = 16_777_216,
    repository_root: Path | None = None,
    executor_factory: ExecutorFactory = ContainerExecutor,
    out_dir: Path | None = None,
    source_date_epoch: int = 0,
) -> dict[str, Any]:
    """Write run-owned ``data/efficacy/*`` artifacts and target-indexed ``latest-run-over-run.{json,md}``."""
    run = Path(run_root).resolve()
    out = run / OUTPUT_DIRECTORY
    out.mkdir(parents=True, exist_ok=True)

    json_bytes = canonical_json(ror_payload)
    md_bytes = render_run_over_run_markdown(ror_payload).encode("utf-8")

    atomic_bytes(out / JSON_NAME, json_bytes)
    atomic_bytes(out / MD_NAME, md_bytes)
    if scorecard_payload is not None:
        atomic_bytes(out / SCORECARD_NAME, canonical_json(scorecard_payload))

    tid = normalize_target_id(str(ror_payload.get("target_id") or "unknown-target"))
    target_hist_dir = Path(history_root).resolve() / tid
    target_hist_dir.mkdir(parents=True, exist_ok=True)
    atomic_bytes(target_hist_dir / LATEST_JSON_NAME, json_bytes)
    atomic_bytes(target_hist_dir / LATEST_MD_NAME, md_bytes)

    doc = build_run_over_run_document(ror_payload, source_date_epoch=source_date_epoch)
    receipt = render_latex_pdf_with_receipt(
        run_root=run,
        out_dir=out,
        document=doc,
        tex_name=TEX_NAME,
        pdf_name=PDF_NAME,
        log_name=LOG_NAME,
        pdfinfo_name=PDFINFO_NAME,
        receipt_name=RECEIPT_NAME,
        receipt_schema=RECEIPT_SCHEMA,
        renderer_id=RENDERER,
        render_pdf=render_pdf,
        timeout_seconds=timeout_seconds,
        max_tex_bytes=max_tex_bytes,
        max_pdf_bytes=max_pdf_bytes,
        repository_root=repository_root,
        executor_factory=executor_factory,
        source_date_epoch=source_date_epoch,
    )
    if out_dir is not None:
        mirror = Path(out_dir).resolve()
        if mirror != out.resolve():
            import shutil as _shutil
            mirror.mkdir(parents=True, exist_ok=True)
            for fname in (JSON_NAME, MD_NAME, SCORECARD_NAME, TEX_NAME, PDF_NAME, RECEIPT_NAME):
                src_file = out / fname
                if src_file.is_file():
                    _shutil.copyfile(src_file, mirror / fname)
    return receipt


__all__ = [
    "JSON_NAME",
    "LATEST_JSON_NAME",
    "LATEST_MD_NAME",
    "MD_NAME",
    "OUTPUT_DIRECTORY",
    "PDF_NAME",
    "RECEIPT_NAME",
    "RECEIPT_SCHEMA",
    "RENDERER",
    "SCHEMA",
    "SCORECARD_NAME",
    "TEX_NAME",
    "archive_target_run",
    "build_run_over_run_document",
    "build_run_over_run_report",
    "has_accepted_publication_gate",
    "render_run_over_run_markdown",
    "write_run_over_run_outputs",
]
