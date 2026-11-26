"""Read-only nested dossier-style live HTML report and stdlib web server for a review run.

Reads run telemetry, frozen dependency graphs, accepted job handoffs, published dossiers, final
reports, accepted inference review packages, or mid-flight claim ledgers strictly read-only. Never
writes to or mutates ``runs/<run-id>/``.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qs, urlparse

from appsec_review.jobs.completion_contracts import DOSSIER_SCHEMA
from appsec_review.observability.monitor import poll_run
from appsec_review.observability.monitor_inputs import read_json
from appsec_review.runtime.consume import accepted_upstream

from .dossiers import dossier_document
from .html import _badge, _block, css as dossier_base_css
from .sources import RunReader
from .telemetry import format as fmt
from .telemetry.inputs import EVENTS_PATH, STATUS_TONE, event_timestamp
from .text import bound, clean, esc, esc_line, sha256_value, token
from .tokens import STYLE_BY_KIND, BoxKind, VERDICT_COLOR

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_TOP_N = 10
DEFAULT_REFRESH_SECONDS = 300
MAX_TOP_N = 200
MAX_REFRESH_SECONDS = 86_400
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024

SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "moderate": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
    "none": 0,
}
STATE_RANK = {"confirmed": 3, "supported": 2, "qualified_supported": 2}
BUCKET_RANK = {"publishable": 3, "withheld": 2, "verification_backlog": 1, "unfinalized": 0}
SHIP_BLOCK_RANK = {
    "ship_blocking": 4,
    "ship_blocking_pending_distinct_verification": 3,
    "decision_pending": 2,
    "non_blocking": 1,
    "not_applicable": 0,
}
CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}
TERMINAL_RUN_STATUSES = frozenset({"SUCCEEDED", "COMPLETED_WITH_GAPS", "FAILED", "CANCELLED", "TIMED_OUT"})


@dataclass(frozen=True, slots=True)
class LiveFinding:
    """Normalized read-only finding projection for ranked nested dossier display."""

    identifier: str
    finding_package_id: str | None
    claim_id: str | None
    dossier_id: str | None
    title: str
    state: str
    bucket: str
    technical_severity: str | None
    ship_block_status: str | None
    exploitability_confidence: str | None
    cwe: str | None
    owasp: tuple[str, ...]
    security_predicate: str | None
    lane: str | None
    primary_location: str | None
    statement: str
    independent_verification: str
    preconditions: tuple[str, ...]
    evidence_rows: tuple[dict[str, str], ...]
    excerpts: tuple[dict[str, str], ...]
    score_rows: tuple[tuple[str, str], ...]
    poc_summary: str | None
    remediation_rows: tuple[str, ...]
    attack_chains: tuple[str, ...]
    limitations: tuple[str, ...]
    dossier: Mapping[str, Any] | None = None

    def sort_key(self) -> tuple[Any, ...]:
        sev = SEVERITY_RANK.get((self.technical_severity or "").lower(), -1)
        state = STATE_RANK.get(self.state.lower(), 0)
        bucket = BUCKET_RANK.get(self.bucket.lower(), 0)
        ship = SHIP_BLOCK_RANK.get((self.ship_block_status or "").lower(), 0)
        conf = CONFIDENCE_RANK.get((self.exploitability_confidence or "").lower(), 0)
        return (
            -state,
            -bucket,
            -ship,
            -sev,
            -conf,
            -len(self.evidence_rows),
            self.finding_package_id or self.claim_id or self.identifier,
            self.title,
        )


@dataclass(frozen=True, slots=True)
class JobRow:
    job_id: str
    wave: int
    status: str
    attempt_id: str | None
    duration_ms: int | None
    in_current_epoch: bool
    accepted_across_run: bool
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class LiveReportData:
    run_id: str
    run_dir: Path
    observed_at: str
    run_started_at: str | None
    last_event_at: str | None
    wall_ms: int | None
    run_status: str
    terminal_confirmed: bool
    profile: str | None
    dagster_run_id: str | None
    source_sha256: str | None
    configuration_sha256: str | None
    configured_enabled_jobs: int | None
    epoch_jobs: Mapping[str, Any]
    all_epoch_attempts: Mapping[str, Any]
    accepted_job_count: int
    known_graph_job_count: int
    active_jobs: tuple[Mapping[str, Any], ...]
    active_steps: tuple[Mapping[str, Any], ...]
    waves: tuple[tuple[int, tuple[JobRow, ...]], ...]
    models: Mapping[str, Any]
    coverage: Mapping[str, Any]
    telemetry_gaps: tuple[str, ...]
    findings_source: str
    findings_stage_note: str
    total_findings: int
    confirmed_findings: int
    supported_findings: int
    top_n: int
    findings: tuple[LiveFinding, ...]
    omitted_findings_sha256: str | None = None


def resolve_run_dir(run: str | Path, runs_root: str | Path | None = None) -> Path:
    """Resolve an application run directory without creating or modifying anything."""
    raw = str(run).strip()
    if not raw:
        raise ValueError("--run-id is required")
    candidate = Path(raw)
    if runs_root is not None and not candidate.is_absolute() and "/" not in raw and "\\" not in raw:
        if raw in {".", ".."} or ".." in raw:
            raise ValueError(f"invalid run identifier: {raw!r}")
        base = Path(runs_root).resolve()
        target = (base / raw).resolve()
        if base not in target.parents:
            raise ValueError(f"run path escapes runs root: {raw!r}")
        if not target.is_dir():
            raise FileNotFoundError(f"run directory not found: {target}")
        return target
    if candidate.is_dir():
        return candidate.resolve()
    if runs_root is not None:
        fallback = (Path(runs_root) / candidate).resolve()
        if fallback.is_dir():
            return fallback
    raise FileNotFoundError(f"run directory not found: {raw}")


def _safe_json(run_root: Path, rel_path: str, *, limit: int = MAX_ARTIFACT_BYTES) -> Any | None:
    try:
        doc, _ = read_json(run_root, rel_path, limit=limit)
        return doc
    except (OSError, ValueError, TypeError):
        return None


def _first_event_timestamp(run_dir: Path) -> datetime | None:
    log_path = run_dir / EVENTS_PATH
    if not log_path.is_file() or log_path.is_symlink():
        return None
    try:
        with log_path.open("rb") as handle:
            for _ in range(16):
                line = handle.readline(262_144)
                if not line or not line.endswith(b"\n"):
                    break
                record = json.loads(line.decode("utf-8"))
                if isinstance(record, Mapping):
                    stamp = event_timestamp(record.get("timestamp"))
                    if stamp is not None:
                        return stamp
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    return None


def _load_graphs(run_dir: Path, current_graph_sha: str | None) -> tuple[dict[str, list[str]], set[str]]:
    """Return merged dependency graph across epochs and the current epoch's job set."""
    graphs_dir = run_dir / "data" / "configuration" / "graphs"
    merged: dict[str, list[str]] = {}
    current_jobs: set[str] = set()
    if not graphs_dir.is_dir() or graphs_dir.is_symlink():
        return merged, current_jobs
    candidates: list[tuple[int, str, Mapping[str, Any]]] = []
    try:
        entries = sorted(graphs_dir.glob("*.json"))
    except OSError:
        return merged, current_jobs
    for entry in entries:
        rel = entry.relative_to(run_dir).as_posix()
        doc = _safe_json(run_dir, rel)
        if not isinstance(doc, Mapping) or not isinstance(doc.get("jobs"), Mapping):
            continue
        jobs = doc["jobs"]
        sha = entry.stem
        if current_graph_sha and sha == current_graph_sha:
            current_jobs = {str(k) for k in jobs}
        candidates.append((len(jobs), sha, jobs))
    for _, _, jobs in sorted(candidates, key=lambda item: (-item[0], item[1])):
        for job_id, parents in jobs.items():
            name = str(job_id)
            deps = [str(p) for p in parents] if isinstance(parents, list) else []
            if name not in merged or len(deps) > len(merged[name]):
                merged[name] = deps
    return merged, current_jobs


def _compute_waves(dependencies: Mapping[str, Sequence[str]], extra_jobs: Sequence[str]) -> dict[str, int]:
    all_jobs = dict.fromkeys([*dependencies.keys(), *extra_jobs])
    memo: dict[str, int] = {}
    visiting: set[str] = set()

    def depth(job_id: str) -> int:
        if job_id in memo:
            return memo[job_id]
        if job_id in visiting:
            return 1
        visiting.add(job_id)
        parents = [p for p in dependencies.get(job_id, ()) if p in all_jobs and p != job_id]
        value = 1 + max((depth(p) for p in parents), default=0)
        visiting.remove(job_id)
        memo[job_id] = value
        return value

    for job_id in all_jobs:
        depth(job_id)
    return memo


def _accepted_jobs(run_dir: Path) -> dict[str, dict[str, Any]]:
    """Verify and read accepted per-job handoff metadata read-only."""
    jobs_dir = run_dir / "data" / "jobs"
    accepted: dict[str, dict[str, Any]] = {}
    if not jobs_dir.is_dir() or jobs_dir.is_symlink():
        return accepted
    try:
        entries = sorted(jobs_dir.iterdir(), key=lambda p: p.name)
    except OSError:
        return accepted
    for entry in entries:
        if not entry.is_dir() or entry.is_symlink() or not (entry / "latest.json").is_file():
            continue
        job_id = entry.name
        try:
            record = accepted_upstream(run_dir, job_id, required=False)
        except ValueError:
            continue
        if record is None:
            continue
        handoff = record.handoff
        started = event_timestamp(handoff.get("started_at"))
        completed = event_timestamp(handoff.get("completed_at"))
        duration_ms = None
        if started is not None and completed is not None and completed >= started:
            duration_ms = int((completed - started).total_seconds() * 1000)
        status = str(handoff.get("completion_status") or "SUCCEEDED")
        accepted[job_id] = {
            "attempt_id": str(handoff.get("attempt_id") or "-"),
            "status": status,
            "duration_ms": duration_ms,
            "handoff": handoff,
        }
    return accepted


def _build_wave_rows(
    run_dir: Path,
    monitor_report: Mapping[str, Any],
    accepted: Mapping[str, Mapping[str, Any]],
) -> tuple[tuple[tuple[int, tuple[JobRow, ...]], ...], int]:
    deps, current_epoch_jobs = _load_graphs(run_dir, monitor_report.get("graph_sha256"))
    state = monitor_report.get("state") or {}
    running_by_job = {
        str(row["job"]): row
        for row in (state.get("current") or ())
        if isinstance(row, Mapping) and row.get("job")
    }
    step_by_job = {
        str(row["job"]): row
        for row in (state.get("current_steps") or ())
        if isinstance(row, Mapping) and row.get("job")
    }
    blocked_by_job = {
        str(row["job"]): row
        for row in (state.get("blocked") or ())
        if isinstance(row, Mapping) and row.get("job")
    }
    extra_jobs = sorted(set(accepted) | set(running_by_job) | set(blocked_by_job) | current_epoch_jobs)
    wave_map = _compute_waves(deps, extra_jobs)
    by_wave: dict[int, list[JobRow]] = {}
    for job_id in sorted(wave_map, key=lambda j: (wave_map[j], j)):
        in_epoch = job_id in current_epoch_jobs if current_epoch_jobs else True
        acc = accepted.get(job_id)
        if job_id in running_by_job:
            cur = running_by_job[job_id]
            elapsed_s = cur.get("elapsed_seconds")
            dur = int(float(elapsed_s) * 1000) if isinstance(elapsed_s, (int, float)) else None
            step = step_by_job.get(job_id)
            detail = None
            if step:
                detail = ".".join(str(x) for x in (step.get("step"), step.get("task")) if x and x != "-")
            row = JobRow(
                job_id=job_id,
                wave=wave_map[job_id],
                status="RUNNING",
                attempt_id=str(cur.get("attempt") or "-"),
                duration_ms=dur,
                in_current_epoch=in_epoch,
                accepted_across_run=acc is not None,
                detail=detail,
            )
        elif job_id in blocked_by_job:
            blk = blocked_by_job[job_id]
            row = JobRow(
                job_id=job_id,
                wave=wave_map[job_id],
                status=str(blk.get("status") or "FAILED"),
                attempt_id=str(blk.get("attempt") or "-"),
                duration_ms=None,
                in_current_epoch=in_epoch,
                accepted_across_run=acc is not None,
                detail=clean(blk.get("reason") or blk.get("error_code") or "") or None,
            )
        elif acc is not None:
            row = JobRow(
                job_id=job_id,
                wave=wave_map[job_id],
                status=str(acc["status"]),
                attempt_id=str(acc["attempt_id"]),
                duration_ms=acc["duration_ms"],
                in_current_epoch=in_epoch,
                accepted_across_run=True,
                detail="prior epoch accepted" if current_epoch_jobs and not in_epoch else None,
            )
        else:
            row = JobRow(
                job_id=job_id,
                wave=wave_map[job_id],
                status="REMAINING" if in_epoch else "NOT_SCHEDULED",
                attempt_id=None,
                duration_ms=None,
                in_current_epoch=in_epoch,
                accepted_across_run=False,
            )
        by_wave.setdefault(row.wave, []).append(row)
    waves = tuple((w, tuple(rows)) for w, rows in sorted(by_wave.items()))
    return waves, len(wave_map)


# --- Read-only findings discovery -------------------------------------------------------------

def _load_published_dossiers(run_dir: Path, accepted: Mapping[str, Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    """Map finding_package_id and claim_id to published dossier JSON documents if available."""
    by_key: dict[str, Mapping[str, Any]] = {}
    pub = accepted.get("job_dossier_publication")
    if pub is not None:
        outputs = (pub["handoff"].get("outputs") or {}).get("acceptance.publish_handoff") or {}
        ref = outputs.get("artifact")
        if isinstance(ref, Mapping) and isinstance(ref.get("path"), str):
            manifest = _safe_json(run_dir, ref["path"])
            if isinstance(manifest, Mapping):
                for item in manifest.get("items") or ():
                    if not isinstance(item, Mapping):
                        continue
                    json_ref = (item.get("files") or {}).get("json")
                    if not isinstance(json_ref, Mapping) or not isinstance(json_ref.get("path"), str):
                        continue
                    doc = _safe_json(run_dir, json_ref["path"])
                    if isinstance(doc, Mapping) and doc.get("schema") == DOSSIER_SCHEMA:
                        if doc.get("finding_package_id"):
                            by_key[str(doc["finding_package_id"])] = doc
                        if doc.get("claim_id"):
                            by_key[str(doc["claim_id"])] = doc
    return by_key


def _extract_scores(scores: Sequence[Mapping[str, Any]]) -> tuple[tuple[tuple[str, str], ...], str | None]:
    rows: list[tuple[str, str]] = []
    confidence: str | None = None
    for pkg in scores:
        if not isinstance(pkg, Mapping):
            continue
        for dim in ("technical_severity", "exploitability_confidence", "environmental_business_impact", "remediation_priority"):
            val = pkg.get(dim)
            if isinstance(val, Mapping) and val.get("rating"):
                rating = clean(val["rating"])
                if dim == "exploitability_confidence" and confidence is None:
                    confidence = rating
                extra = f" ({clean(val['value'])})" if val.get("value") is not None else ""
                rows.append((dim.replace("_", " "), f"{rating}{extra}"))
        if pkg.get("missing_factors"):
            rows.append(("missing factors", ", ".join(clean(x) for x in pkg["missing_factors"])))
    return tuple(rows), confidence


def _finding_from_dossier(dossier: Mapping[str, Any], *, pkg_override: Mapping[str, Any] | None = None) -> LiveFinding:
    pkg = pkg_override or {}
    cls = dossier.get("classification") if isinstance(dossier.get("classification"), Mapping) else {}
    ship = (pkg.get("ship_block") if isinstance(pkg.get("ship_block"), Mapping) else None) or (
        dossier.get("ship_block") if isinstance(dossier.get("ship_block"), Mapping) else {}
    )
    scores_raw = pkg.get("scores") or dossier.get("scores") or ()
    score_rows, confidence = _extract_scores(scores_raw if isinstance(scores_raw, list) else ())
    sev_raw = ship.get("technical_severity")
    if isinstance(sev_raw, Mapping):
        sev = clean(sev_raw.get("rating") or "") or None
    else:
        sev = clean(sev_raw or "") or None
    if not sev and isinstance(ship.get("inputs"), Mapping):
        ts_in = ship["inputs"].get("technical_severity")
        if isinstance(ts_in, Mapping) and ts_in.get("rating"):
            sev = clean(ts_in["rating"])
    state = clean(pkg.get("state") or dossier.get("state") or "supported")
    bucket = clean(pkg.get("bucket") or ("publishable" if state == "confirmed" else "verification_backlog"))
    owasp_list = tuple(clean(x) for x in (cls.get("owasp") or ()) if x)
    cwe = clean(cls.get("cwe") or dossier.get("weakness_cwe") or "") or None

    ev_rows: list[dict[str, str]] = []
    primary_loc: str | None = None
    for rel in dossier.get("evidence") or ():
        if not isinstance(rel, Mapping):
            continue
        loc = clean(rel.get("locator") or "")
        if loc and primary_loc is None:
            primary_loc = loc
        ev_rows.append({
            "predicate": clean(rel.get("predicate") or "-").replace("_", " "),
            "kind": clean(rel.get("kind") or "-"),
            "admissibility": clean(rel.get("admissibility") or "-"),
            "locator": loc or clean(rel.get("entity_id") or "-"),
        })

    excerpts: list[dict[str, str]] = []
    for src in dossier.get("sources") or ():
        if not isinstance(src, Mapping):
            continue
        loc_info = src.get("location") if isinstance(src.get("location"), Mapping) else {}
        path = clean(loc_info.get("path") or src.get("path") or "source")
        lines = (
            f":{loc_info['start_line']}-{loc_info['end_line']}"
            if loc_info.get("start_line") is not None and loc_info.get("end_line") is not None
            else ""
        )
        header = f"{path}{lines}"
        if primary_loc is None and path != "source":
            primary_loc = header
        if src.get("excerpt"):
            text, _ = bound(src["excerpt"], 1600)
            excerpts.append({"caption": header, "text": text})

    poc = dossier.get("poc") if isinstance(dossier.get("poc"), Mapping) else pkg.get("poc")
    poc_summary = None
    if isinstance(poc, Mapping) and poc.get("status"):
        poc_summary = f"{clean(poc['status'])} (compile-only policy; never executed)"

    remediation_rows: list[str] = []
    for rem in dossier.get("remediation") or ():
        if isinstance(rem, Mapping):
            stage = clean(rem.get("stage") or "Remediation")
            st = clean(rem.get("status") or "recorded")
            inv = clean(rem.get("corrected_invariant") or rem.get("reason") or "")
            remediation_rows.append(f"{stage}: {st}" + (f" ? {inv}" if inv else ""))

    chains: list[str] = []
    for ch in dossier.get("attack_chains") or ():
        if isinstance(ch, Mapping):
            chains.append(f"{clean(ch.get('chain_id'))} ({clean(ch.get('status'))})"
                          + (f": {clean(ch.get('objective'))}" if ch.get("objective") else ""))
        elif isinstance(ch, str):
            chains.append(clean(ch))

    indep = (pkg.get("independence") if isinstance(pkg.get("independence"), Mapping) else None) or (
        dossier.get("independence") if isinstance(dossier.get("independence"), Mapping) else {}
    )
    if indep.get("independent") is True:
        indep_text = "Yes (independent verifier model)"
    elif indep.get("independent") is False:
        indep_text = "No (same model / non-distinct verifier)"
    else:
        indep_text = "Unknown / pending"

    limits = tuple(
        clean(x)
        for x in [*(pkg.get("missing_predicates") or ()), *(dossier.get("missing_predicates") or ()), *(dossier.get("gaps") or ())]
        if x
    )
    limits = tuple(dict.fromkeys(limits))

    f_id = clean(pkg.get("finding_package_id") or dossier.get("finding_package_id") or "") or None
    c_id = clean(pkg.get("claim_id") or dossier.get("claim_id") or "") or None
    d_id = clean(dossier.get("dossier_id") or "") or None
    return LiveFinding(
        identifier=f_id or c_id or d_id or "finding",
        finding_package_id=f_id,
        claim_id=c_id,
        dossier_id=d_id,
        title=clean(pkg.get("title") or dossier.get("title") or cwe or f_id or c_id or "Finding"),
        state=state,
        bucket=bucket,
        technical_severity=sev,
        ship_block_status=clean(ship.get("status") or "") or None,
        exploitability_confidence=confidence,
        cwe=cwe,
        owasp=owasp_list,
        security_predicate=clean(dossier.get("security_predicate") or "") or None,
        lane=clean(pkg.get("lane") or dossier.get("lane") or "") or None,
        primary_location=primary_loc,
        statement=clean(dossier.get("statement") or "Narrative statement not available in this artifact."),
        independent_verification=indep_text,
        preconditions=tuple(clean(x) for x in (dossier.get("preconditions") or ()) if x),
        evidence_rows=tuple(ev_rows),
        excerpts=tuple(excerpts),
        score_rows=score_rows,
        poc_summary=poc_summary,
        remediation_rows=tuple(remediation_rows),
        attack_chains=tuple(chains),
        limitations=limits,
        dossier=dossier,
    )


def _finding_from_package(
    pkg: Mapping[str, Any],
    *,
    claim: Mapping[str, Any] | None = None,
    relations: Sequence[Mapping[str, Any]] = (),
    bucket_default: str | None = None,
) -> LiveFinding:
    claim = claim or {}
    ship = pkg.get("ship_block") if isinstance(pkg.get("ship_block"), Mapping) else {}
    sev_raw = ship.get("technical_severity")
    if isinstance(sev_raw, Mapping):
        sev = clean(sev_raw.get("rating") or "") or None
    else:
        sev = clean(sev_raw or "") or None
    if not sev and isinstance(ship.get("inputs"), Mapping):
        ts_in = ship["inputs"].get("technical_severity")
        if isinstance(ts_in, Mapping) and ts_in.get("rating"):
            sev = clean(ts_in["rating"])

    scores_raw = pkg.get("scores") if isinstance(pkg.get("scores"), list) else ()
    score_rows, confidence = _extract_scores([s for s in scores_raw if isinstance(s, Mapping)])
    state = clean(pkg.get("state") or claim.get("state") or "supported")
    bucket = clean(pkg.get("bucket") or bucket_default or ("publishable" if state == "confirmed" else "verification_backlog"))

    cited_ids = set(pkg.get("direct_evidence") or ()) | set(pkg.get("analyst_assessed_evidence") or ())
    ev_rows: list[dict[str, str]] = []
    primary_loc: str | None = None
    for rel in relations:
        if not isinstance(rel, Mapping):
            continue
        if cited_ids and rel.get("relation_id") not in cited_ids and rel.get("claim_id") != pkg.get("claim_id"):
            continue
        loc = clean(rel.get("locator") or "")
        if loc and primary_loc is None:
            primary_loc = loc
        ev_rows.append({
            "predicate": clean(rel.get("predicate") or "-").replace("_", " "),
            "kind": clean(rel.get("kind") or "-"),
            "admissibility": clean(rel.get("admissibility") or "-"),
            "locator": loc or clean(rel.get("entity_id") or "-"),
        })
    if not ev_rows:
        for eid in pkg.get("direct_evidence") or ():
            ev_rows.append({"predicate": "direct citation", "kind": "supports", "admissibility": "direct", "locator": clean(eid)})

    indep = pkg.get("independence") if isinstance(pkg.get("independence"), Mapping) else {}
    if indep.get("independent") is True:
        indep_text = "Yes (independent verifier model)"
    elif indep.get("independent") is False:
        indep_text = "No (same model / non-distinct verifier)"
    else:
        indep_text = "Unknown / pending"

    poc = pkg.get("poc") if isinstance(pkg.get("poc"), Mapping) else None
    poc_summary = f"{clean(poc['status'])} (compile-only policy; never executed)" if poc and poc.get("status") else None
    f_id = clean(pkg.get("finding_package_id") or "") or None
    c_id = clean(pkg.get("claim_id") or claim.get("claim_id") or "") or None
    cwe = clean(claim.get("weakness_cwe") or "") or None
    statement = clean(claim.get("statement") or pkg.get("title") or "Accepted finding package; protected dossier narrative not loaded.")
    limits = tuple(dict.fromkeys(clean(x) for x in [*(pkg.get("missing_predicates") or ()), *(pkg.get("withheld_reasons") or ())] if x))
    return LiveFinding(
        identifier=f_id or c_id or "finding",
        finding_package_id=f_id,
        claim_id=c_id,
        dossier_id=None,
        title=clean(pkg.get("title") or cwe or f_id or c_id or "Finding"),
        state=state,
        bucket=bucket,
        technical_severity=sev,
        ship_block_status=clean(ship.get("status") or "") or None,
        exploitability_confidence=confidence,
        cwe=cwe,
        owasp=(),
        security_predicate=clean(claim.get("security_predicate") or "") or None,
        lane=clean(pkg.get("lane") or claim.get("lane") or "") or None,
        primary_location=primary_loc,
        statement=statement,
        independent_verification=indep_text,
        preconditions=tuple(clean(x) for x in (claim.get("preconditions") or ()) if x),
        evidence_rows=tuple(ev_rows),
        excerpts=(),
        score_rows=score_rows,
        poc_summary=poc_summary,
        remediation_rows=(),
        attack_chains=tuple(clean(x) for x in (pkg.get("attack_chains") or ()) if x),
        limitations=limits,
        dossier=None,
    )


def _discover_findings(
    run_dir: Path,
    accepted: Mapping[str, Mapping[str, Any]],
    *,
    run_status: str,
    active_jobs: Sequence[Mapping[str, Any]],
) -> tuple[str, str, list[LiveFinding]]:
    """Discover findings read-only in descending order of publication authority."""
    dossiers = _load_published_dossiers(run_dir, accepted)
    reader = RunReader(run_dir)

    # 1. Published final-report.json (enriched with published dossier or claim ledger if present)
    found_final = reader.final_report()
    if found_final is not None:
        _, final_report = found_final
        ledger = reader.ledger() if not dossiers else None
        items: list[LiveFinding] = []
        for bucket_key, bucket_name in (("findings", "publishable"), ("verification_backlog", "verification_backlog"), ("withheld", "withheld")):
            for row in final_report.get(bucket_key) or ():
                if not isinstance(row, Mapping):
                    continue
                fid = str(row.get("finding_package_id") or "")
                cid = str(row.get("claim_id") or "")
                dossier = dossiers.get(fid) or dossiers.get(cid)
                if dossier is not None:
                    items.append(_finding_from_dossier(dossier, pkg_override={**row, "bucket": bucket_name}))
                else:
                    claim_map = dict(ledger.claims[cid]) if ledger is not None and cid in ledger.claims else {}
                    rel_maps = list(ledger.relations.get(cid, ())) if ledger is not None else []
                    items.append(_finding_from_package(row, claim=claim_map, relations=rel_maps, bucket_default=bucket_name))
        pub_status = clean((final_report.get("status") or {}).get("publication") or "published")
        note = (
            f"Source: published final report ({pub_status}). Confirmed publishable findings rank ahead of "
            "unconfirmed supported verification-backlog items."
        )
        return "final_report", note, items

    # 2. Published dossiers (before final-report completes)
    if dossiers:
        seen_ids: set[str] = set()
        items = []
        for doc in dossiers.values():
            if doc.get("kind") not in (None, "finding"):
                continue
            key = str(doc.get("dossier_id") or doc.get("finding_package_id") or doc.get("claim_id"))
            if key in seen_ids:
                continue
            seen_ids.add(key)
            items.append(_finding_from_dossier(doc))
        return (
            "dossier_publication",
            "Source: accepted developer dossiers (final executive report publication has not completed yet).",
            items,
        )

    # 3. Accepted job_inference_security_review finding packages
    rev_acc = accepted.get("job_inference_security_review")
    if rev_acc is not None:
        outputs = rev_acc["handoff"].get("outputs") or {}
        rev_ref = (outputs.get("publication.publish_handoff") or {}).get("artifact")
        ledger_ref = (outputs.get("publication.publish_claim_ledger") or {}).get("artifact")
        claims_by_id: dict[str, Mapping[str, Any]] = {}
        rels_by_claim: dict[str, list[Mapping[str, Any]]] = {}
        if isinstance(ledger_ref, Mapping) and isinstance(ledger_ref.get("path"), str):
            proj_path = str(Path(ledger_ref["path"]).parent / "projection.json")
            proj = _safe_json(run_dir, proj_path)
            if isinstance(proj, Mapping):
                for cl in proj.get("claims") or ():
                    if isinstance(cl, Mapping) and cl.get("claim_id"):
                        claims_by_id[str(cl["claim_id"])] = cl
                for rel in proj.get("evidence_relations") or ():
                    if isinstance(rel, Mapping) and rel.get("claim_id"):
                        rels_by_claim.setdefault(str(rel["claim_id"]), []).append(rel)
        if isinstance(rev_ref, Mapping) and isinstance(rev_ref.get("path"), str):
            rev_doc = _safe_json(run_dir, rev_ref["path"])
            if isinstance(rev_doc, Mapping):
                items = []
                for pkg_entry in rev_doc.get("packages") or ():
                    ref = pkg_entry.get("finding_package") if isinstance(pkg_entry, Mapping) and "finding_package" in pkg_entry else pkg_entry
                    if not isinstance(ref, Mapping) or not isinstance(ref.get("path"), str):
                        continue
                    pkg_doc = _safe_json(run_dir, ref["path"])
                    if not isinstance(pkg_doc, Mapping):
                        continue
                    score_docs: list[Mapping[str, Any]] = []
                    for s_ref in pkg_doc.get("scores") or ():
                        if isinstance(s_ref, Mapping) and isinstance(s_ref.get("path"), str):
                            sd = _safe_json(run_dir, s_ref["path"])
                            if isinstance(sd, Mapping):
                                score_docs.append(sd)
                    cid = str(pkg_doc.get("claim_id") or "")
                    enriched = {**pkg_doc, "scores": score_docs}
                    items.append(_finding_from_package(
                        enriched,
                        claim=claims_by_id.get(cid),
                        relations=rels_by_claim.get(cid, ()),
                    ))
                return (
                    "inference_security_review",
                    "Source: accepted inference security review packages (downstream dossier/report jobs still pending).",
                    items,
                )

    # 4. Mid-flight claim ledger shards (if job_inference_security_review is running/partial)
    ledger = reader.ledger()
    if ledger.claims:
        items = []
        for claim_id in ledger.claim_order:
            claim = ledger.claims.get(claim_id) or {}
            state = ledger.claim_state(claim_id)
            if state not in {"confirmed", "supported"}:
                continue
            rels = [
                {
                    "predicate": clean(r.get("predicate") or "-").replace("_", " "),
                    "kind": clean(r.get("kind") or "-"),
                    "admissibility": clean(r.get("admissibility") or "-"),
                    "locator": clean(r.get("locator") or r.get("entity_id") or "-"),
                }
                for r in ledger.relations.get(claim_id, ())
                if isinstance(r, Mapping)
            ]
            primary_loc = next((r["locator"] for r in rels if ":" in r["locator"]), None)
            cwe = clean(claim.get("weakness_cwe") or "") or None
            pred = clean(claim.get("security_predicate") or "") or None
            items.append(LiveFinding(
                identifier=claim_id,
                finding_package_id=None,
                claim_id=claim_id,
                dossier_id=None,
                title=clean(f"{cwe or 'Claim'}: {pred or claim_id}"),
                state=state,
                bucket="unfinalized",
                technical_severity=None,
                ship_block_status="decision_pending",
                exploitability_confidence=None,
                cwe=cwe,
                owasp=(),
                security_predicate=pred,
                lane=clean(claim.get("lane") or "") or None,
                primary_location=primary_loc,
                statement=clean(claim.get("statement") or "Unfinalized ledger claim."),
                independent_verification="Unfinalized mid-run claim ledger",
                preconditions=tuple(clean(x) for x in (claim.get("preconditions") or ()) if x),
                evidence_rows=tuple(rels),
                excerpts=(),
                score_rows=(),
                poc_summary=None,
                remediation_rows=(),
                attack_chains=(),
                limitations=("Mid-run ledger projection; final adjudication and scoring have not completed.",),
                dossier=None,
            ))
        if items:
            return (
                "in_progress_ledger",
                "Source: mid-run claim ledger projection (unfinalized; final publication gate has not run yet).",
                items,
            )

    # 5. No findings recorded (yet or after completion)
    if run_status not in TERMINAL_RUN_STATUSES:
        active_names = ", ".join(clean(j.get("job")) for j in active_jobs if j.get("job")) or "dispatching"
        note = (
            f"No findings published yet ? review run is still active (current stage: {active_names}). "
            "Absence of findings mid-run is never evidence that the target is clean."
        )
    else:
        note = (
            "0 findings recorded for this run. Absence of findings is bounded by recorded review coverage "
            "and named gaps, never standalone proof that a target is clean."
        )
    return "none", note, []


def collect_live_report_data(
    run_dir: Path,
    *,
    top_n: int = DEFAULT_TOP_N,
    now: datetime | None = None,
) -> LiveReportData:
    """Collect a read-only snapshot of run status, performance metrics, and top-N findings."""
    if top_n < 1:
        raise ValueError("top_n must be >= 1")
    run_dir = Path(run_dir).resolve()
    now = now or datetime.now(timezone.utc)
    report = poll_run(run_dir, save=False, pages=100, max_rows=30, now=now)
    accepted = _accepted_jobs(run_dir)
    waves, known_graph_jobs = _build_wave_rows(run_dir, report, accepted)

    state = report.get("state") or {}
    run_status = str(state.get("status") or "UNKNOWN")
    active_jobs = tuple(state.get("current") or ())
    active_steps = tuple(state.get("current_steps") or ())

    first_stamp = _first_event_timestamp(run_dir)
    last_event_raw = (report.get("coverage") or {}).get("last_event_at")
    last_stamp = event_timestamp(last_event_raw)
    wall_ms: int | None = None
    if first_stamp is not None:
        if run_status in TERMINAL_RUN_STATUSES and last_stamp is not None:
            end_ref = last_stamp
        else:
            end_ref = max(last_stamp, now) if last_stamp is not None else now
        if end_ref >= first_stamp:
            wall_ms = int((end_ref - first_stamp).total_seconds() * 1000)

    source, stage_note, all_findings = _discover_findings(
        run_dir,
        accepted,
        run_status=run_status,
        active_jobs=active_jobs,
    )
    ranked = sorted(all_findings, key=lambda item: item.sort_key())
    confirmed_count = sum(1 for item in ranked if item.state == "confirmed")
    supported_count = sum(1 for item in ranked if item.state != "confirmed")
    omitted_sha = (
        sha256_value([f.identifier for f in ranked[top_n:]])
        if len(ranked) > top_n
        else None
    )

    state_gaps = state.get("gaps") or {}
    gap_items: list[str] = [clean(g) for g in (report.get("gaps") or ())]
    if isinstance(state_gaps, Mapping):
        gap_items.extend(f"{clean(k)} ({v})" for k, v in sorted(state_gaps.items()) if v)
    for sig in report.get("signals") or ():
        gap_items.append(clean(sig))

    return LiveReportData(
        run_id=str(report.get("run_id") or run_dir.name),
        run_dir=run_dir,
        observed_at=str(report.get("observed_at") or now.isoformat()),
        run_started_at=first_stamp.isoformat() if first_stamp else None,
        last_event_at=str(last_event_raw) if last_event_raw else None,
        wall_ms=wall_ms,
        run_status=run_status,
        terminal_confirmed=bool(state.get("terminal_confirmed")),
        profile=report.get("profile"),
        dagster_run_id=report.get("dagster_run_id") or report.get("observed_dispatch_id"),
        source_sha256=report.get("source_sha256"),
        configuration_sha256=report.get("configuration_sha256"),
        configured_enabled_jobs=report.get("configured_enabled_jobs"),
        epoch_jobs=state.get("jobs") or {},
        all_epoch_attempts=state.get("attempts") or {},
        accepted_job_count=len(accepted),
        known_graph_job_count=known_graph_jobs,
        active_jobs=active_jobs,
        active_steps=active_steps,
        waves=waves,
        models=report.get("models") or {},
        coverage=report.get("coverage") or {},
        telemetry_gaps=tuple(gap_items),
        findings_source=source,
        findings_stage_note=stage_note,
        total_findings=len(ranked),
        confirmed_findings=confirmed_count,
        supported_findings=supported_count,
        top_n=top_n,
        findings=tuple(ranked[:top_n]),
        omitted_findings_sha256=omitted_sha,
    )


# --- HTML / CSS rendering ---------------------------------------------------------------------

def _live_css() -> str:
    return dossier_base_css() + """
.live-banner{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:.6rem;margin-bottom:.6rem}
.refresh-pill{display:inline-flex;align-items:center;gap:.4rem;font-size:.76rem;background:var(--panel);
  border:1px solid var(--rule);border-radius:999px;padding:.2rem .65rem;color:var(--muted);font-family:var(--mono)}
.refresh-pill a{color:var(--brand);text-decoration:none;font-weight:600}
.refresh-pill a:hover{text-decoration:underline}
.stat .sub{font-size:.73rem;color:var(--muted);margin-top:.16rem}
.progress-track{display:flex;height:10px;border-radius:999px;overflow:hidden;background:var(--panel);
  border:1px solid var(--rule);margin:.45rem 0 .75rem}
.progress-seg{height:100%}
.progress-seg[data-tone=pending]{background:var(--rule)}
.wave-grid{display:grid;gap:.45rem;margin:.5rem 0}
.job-pills{display:flex;flex-wrap:wrap;gap:.38rem;padding:.25rem 0}
.job-pill{display:inline-flex;align-items:center;gap:.35rem;font-size:.78rem;border:1px solid var(--rule);
  border-radius:5px;padding:.18rem .48rem;background:var(--panel)}
.job-pill code{font-size:.76rem}
.meta-chip{display:inline-block;background:var(--panel);color:var(--muted);border:1px solid var(--rule);
  font-size:.68rem;font-weight:600;padding:.12rem .45rem;border-radius:3px;line-height:1.3;font-family:var(--mono)}
.findings-empty-panel{position:relative;min-height:260px;display:flex;flex-direction:column;
  align-items:center;justify-content:center;border:1.5px dashed var(--rule);border-radius:8px;
  background:repeating-linear-gradient(-28deg,var(--panel),var(--panel) 14px,transparent 14px,transparent 28px);
  padding:2rem 1.5rem;margin:.75rem 0 1rem;overflow:hidden;text-align: center}
.na-watermark-svg{width:min(520px,92%);height:auto;max-height:220px;color:var(--brand);user-select:none;pointer-events:none}
.findings-empty-caption{position:relative;z-index:1;max-width:44rem;margin-top:.55rem;font-size:.86rem;
  color:var(--muted);background:var(--panel);padding:.4rem .8rem;border-radius:4px;border:1px solid var(--rule)}
.section-head{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;
  gap:.5rem;border-bottom:1px solid var(--rule);padding-bottom:.35rem;margin:2.2rem 0 .8rem}
.section-head h2{margin:0;padding:0;border:0;font-size:1.35rem}
"""


def _status_tone_key(status: str) -> str:
    norm = status.upper()
    if norm in {"SUCCEEDED", "COMPLETE", "CONFIRMED"}:
        return "confirmed"
    if norm in {"COMPLETED_WITH_GAPS", "SUPPORTED", "QUALIFIED_SUPPORTED", "ACTIVE_UNCONFIRMED"}:
        return "insufficient_evidence"
    if norm in {"FAILED", "TIMED_OUT", "CRITICAL", "HIGH", "SHIP_BLOCKING"}:
        return "contradicted"
    if norm in {"RUNNING", "QUEUED", "MEDIUM"}:
        return "proposed"
    return STATUS_TONE.get(norm, "unresolved")


def _status_badge(status: str) -> str:
    tone = _status_tone_key(status)
    return _badge(tone, status.replace("_", " ").lower())


def _severity_badge(severity: str | None) -> str:
    if not severity:
        return _badge("unresolved", "unrated")
    low = severity.lower()
    if low in {"critical", "high"}:
        return _badge("contradicted", low)
    if low in {"medium", "moderate"}:
        return _badge("insufficient_evidence", low)
    if low in {"low", "informational", "info"}:
        return _badge("proposed", low)
    return _badge("unresolved", low)


def _usage_text(usage_entry: Mapping[str, Any] | None) -> str:
    if not isinstance(usage_entry, Mapping):
        return fmt.UNAVAILABLE
    known = usage_entry.get("known_sum")
    if known is None:
        return fmt.UNAVAILABLE
    suffix = "+" if usage_entry.get("lower_bound") else ""
    return f"{fmt.compact(known)}{suffix}"


def _token_pair_stat(models: Mapping[str, Any]) -> tuple[str, str]:
    usage = ((models.get("totals") or {}).get("usage")) if isinstance(models.get("totals"), Mapping) else {}
    if not isinstance(usage, Mapping):
        return fmt.UNAVAILABLE, "telemetry unavailable"
    inp = usage.get("input_tokens") if isinstance(usage.get("input_tokens"), Mapping) else {}
    out = usage.get("output_tokens") if isinstance(usage.get("output_tokens"), Mapping) else {}
    in_k, out_k = inp.get("known_sum"), out.get("known_sum")
    if in_k is None and out_k is None:
        return fmt.UNAVAILABLE, "no measured token usage yet"
    total = int(in_k or 0) + int(out_k or 0)
    plus = "+" if (inp.get("lower_bound") or out.get("lower_bound") or in_k is None or out_k is None) else ""
    sub = f"in {_usage_text(inp)} ? out {_usage_text(out)}"
    return f"{fmt.compact(total)}{plus}", sub


def _latency_stat(models: Mapping[str, Any]) -> tuple[str, str]:
    totals = models.get("totals") if isinstance(models.get("totals"), Mapping) else {}
    lat = totals.get("call_latency") if isinstance(totals.get("call_latency"), Mapping) else {}
    p50, p95, mx = lat.get("p50_ms"), lat.get("p95_ms"), lat.get("max_ms")
    if p50 is None and p95 is None:
        return fmt.UNAVAILABLE, "no completed model calls"
    return f"{fmt.duration(p50)} / {fmt.duration(p95)}", f"p50 / p95 ? max {fmt.duration(mx)}"


def _short_sha(value: str | None) -> str:
    if not value:
        return fmt.UNAVAILABLE
    return f"{value[:12]}?" if len(value) > 16 else value


def _render_na_watermark(caption: str) -> str:
    """Render a large slanted diagonal N/A watermark SVG visual for zero-findings runs."""
    return (
        '<div class="findings-empty-panel" data-empty-findings="true">'
        '<svg class="na-watermark-svg" viewBox="0 0 600 240" role="img" '
        'aria-label="N/A ? No findings recorded">'
        '<g transform="translate(300,120) rotate(-22)">'
        '<rect x="-220" y="-74" width="440" height="148" rx="14" ry="14" '
        'fill="none" stroke="currentColor" stroke-opacity="0.16" stroke-width="5"/>'
        '<rect x="-210" y="-64" width="420" height="128" rx="10" ry="10" '
        'fill="none" stroke="currentColor" stroke-opacity="0.11" stroke-width="2" stroke-dasharray="10 6"/>'
        '<text x="0" y="26" text-anchor="middle" '
        'font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" '
        'font-size="108" font-weight="800" letter-spacing="12" '
        'fill="currentColor" fill-opacity="0.15">N/A</text>'
        '<text x="0" y="54" text-anchor="middle" '
        'font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" '
        'font-size="14" font-weight="700" letter-spacing="5" '
        'fill="currentColor" fill-opacity="0.22">NO FINDINGS RECORDED</text>'
        "</g></svg>"
        f'<p class="findings-empty-caption">{esc(caption)}</p>'
        "</div>"
    )


def _render_progress_bar(waves: Sequence[tuple[int, Sequence[JobRow]]]) -> str:
    counts = Counter(row.status for _, rows in waves for row in rows)
    total = sum(counts.values())
    if total <= 0:
        return ""
    palette = (
        ("SUCCEEDED", "confirmed"),
        ("NOT_APPLICABLE", "confirmed"),
        ("COMPLETED_WITH_GAPS", "insufficient_evidence"),
        ("RUNNING", "proposed"),
        ("FAILED", "contradicted"),
        ("TIMED_OUT", "contradicted"),
        ("REMAINING", "pending"),
        ("NOT_SCHEDULED", "pending"),
    )
    segs: list[str] = []
    for key, tone in palette:
        n = counts.get(key, 0)
        if n > 0:
            pct = (n / total) * 100.0
            if tone in VERDICT_COLOR:
                style_attr = f'width:{pct:.2f}%;background:#{VERDICT_COLOR[tone]}'
                tone_attr = ""
            else:
                style_attr = f"width:{pct:.2f}%"
                tone_attr = ' data-tone="pending"'
            segs.append(
                f'<span class="progress-seg"{tone_attr} style="{style_attr}" '
                f'title="{esc_line(f"{key}: {n}/{total}")}"></span>'
            )
    return f'<div class="progress-track" aria-label="Job completion progress">{"".join(segs)}</div>'


def _render_status_section(data: LiveReportData) -> str:
    style = STYLE_BY_KIND[BoxKind.PROVENANCE]
    ej = data.epoch_jobs
    e_total = ej.get("total")
    e_comp = ej.get("completed", 0)
    e_run = ej.get("running", 0)
    e_rem = ej.get("remaining", 0)
    epoch_badge = (
        f"epoch {e_comp}/{e_total} done"
        if isinstance(e_total, int)
        else f"{data.accepted_job_count} accepted"
    )
    head = (
        '<div class="bh">'
        f'<span class="chip" data-kind="{BoxKind.PROVENANCE.value}">{esc_line(style.chip)}</span>'
        "<h4>Run status, wave progress &amp; performance telemetry</h4>"
        f"{_status_badge(data.run_status)}"
        f'<span class="meta-chip">{esc_line(epoch_badge)}</span>'
        f'<span class="meta-chip">{esc_line(f"accepted jobs: {data.accepted_job_count}/{data.known_graph_job_count or data.accepted_job_count}")}</span>'
        "</div>"
    )

    inner: list[str] = [_render_progress_bar(data.waves)]

    if data.active_jobs or data.active_steps:
        rows_html: list[str] = []
        step_lookup = {str(s.get("job")): s for s in data.active_steps if isinstance(s, Mapping)}
        for cur in data.active_jobs:
            job_name = clean(cur.get("job") or "-")
            st = step_lookup.get(job_name) or {}
            unit_label = ".".join(str(x) for x in (st.get("step"), st.get("task")) if x and x != "-") or "(job level)"
            elapsed_ms = int(float(cur["elapsed_seconds"]) * 1000) if isinstance(cur.get("elapsed_seconds"), (int, float)) else None
            age_ms = int(float(cur["progress_age_seconds"]) * 1000) if isinstance(cur.get("progress_age_seconds"), (int, float)) else None
            rows_html.append(
                "<tr>"
                f"<td><code>{esc_line(job_name)}</code></td>"
                f"<td><code>{esc_line(str(cur.get('attempt') or '-'))}</code></td>"
                f"<td><code>{esc_line(unit_label)}</code></td>"
                f"<td>{esc_line(fmt.duration(elapsed_ms))}</td>"
                f"<td>{esc_line(fmt.duration(age_ms))} ago</td>"
                "</tr>"
            )
        inner.append(
            '<details class="inner" open><summary>Active execution units '
            f"({len(data.active_jobs)} running)</summary>"
            '<div class="tw"><table><thead><tr><th>Job</th><th>Attempt</th><th>Current step.task</th>'
            "<th>Elapsed</th><th>Last event</th></tr></thead>"
            f"<tbody>{''.join(rows_html)}</tbody></table></div></details>"
        )

    if data.waves:
        wave_blocks: list[str] = []
        for wave_num, rows in data.waves:
            running_here = any(r.status == "RUNNING" for r in rows)
            failed_here = any(r.status in {"FAILED", "TIMED_OUT"} for r in rows)
            done_here = sum(1 for r in rows if r.status in {"SUCCEEDED", "COMPLETED_WITH_GAPS", "NOT_APPLICABLE"})
            open_attr = " open" if (running_here or failed_here) else ""
            pills = []
            for r in rows:
                dur = f" ? {fmt.duration(r.duration_ms)}" if r.duration_ms is not None else ""
                det = f" ({r.detail})" if r.detail else ""
                pills.append(
                    f'<span class="job-pill">{_status_badge(r.status)} '
                    f"<code>{esc_line(r.job_id)}</code>"
                    f'<span class="muted">{esc_line(dur + det)}</span></span>'
                )
            wave_blocks.append(
                f'<details class="inner"{open_attr}><summary>'
                f"Wave {wave_num} ? {done_here}/{len(rows)} completed"
                + (f" ({sum(1 for r in rows if r.status == 'RUNNING')} running)" if running_here else "")
                + f'</summary><div class="job-pills">{"".join(pills)}</div></details>'
            )
        open_waves = " open" if len(data.waves) <= 6 or data.active_jobs else ""
        inner.append(
            f'<details class="inner"{open_waves}><summary>Nested wave &amp; job topology '
            f"({len(data.waves)} waves, {sum(len(r) for _, r in data.waves)} jobs)</summary>"
            f'<div class="wave-grid">{"".join(wave_blocks)}</div></details>'
        )

    totals = (data.models.get("totals") or {}) if isinstance(data.models, Mapping) else {}
    by_role = (data.models.get("by_job_role") or ()) if isinstance(data.models, Mapping) else ()
    usage = totals.get("usage") if isinstance(totals.get("usage"), Mapping) else {}
    perf_fields = [
        ("Epoch job counts", f"total={e_total if e_total is not None else 'unavailable'}, completed={e_comp}, running={e_run}, remaining={e_rem}"),
        ("All-epoch attempts", f"observed={data.all_epoch_attempts.get('total_observed', 0)}, retries={data.all_epoch_attempts.get('retry_attempts', 0)}, reused={data.all_epoch_attempts.get('reused', 0)}"),
        ("Model calls", f"fresh={totals.get('fresh_calls', 0)}, retries={totals.get('retry_calls', 0)}, reused={totals.get('reused_calls', 0)}"),
        ("Concurrent model wall", fmt.duration(totals.get("concurrent_dispatch_wall_ms"))),
        ("Token breakdown", f"in={_usage_text(usage.get('input_tokens'))}, out={_usage_text(usage.get('output_tokens'))}, cache={_usage_text(usage.get('cache_tokens'))}, reasoning={_usage_text(usage.get('reasoning_tokens'))}"),
        ("Event log coverage", f"{clean(data.coverage.get('status') or 'unknown')} (seq {data.coverage.get('sequence', 0)}, {data.coverage.get('observed_event_count', 0)} events)"),
    ]
    dl_rows = "".join(
        f"<dt>{esc_line(k)}</dt><dd><code>{esc_line(v)}</code></dd>"
        for k, v in perf_fields
    )
    role_table = ""
    if by_role:
        r_rows = []
        for entry in by_role[:20]:
            if not isinstance(entry, Mapping):
                continue
            clat = entry.get("call_latency") or {}
            eu = entry.get("usage") or {}
            r_rows.append(
                "<tr>"
                f"<td><code>{esc_line(clean(entry.get('job') or '-'))}</code></td>"
                f"<td><code>{esc_line(clean(entry.get('role') or '-'))}</code></td>"
                f"<td>{esc_line(fmt.count(entry.get('fresh_calls', 0)))}</td>"
                f"<td>{esc_line(fmt.count(entry.get('retry_calls', 0)))}</td>"
                f"<td>{esc_line(fmt.duration(clat.get('p50_ms')))}</td>"
                f"<td>{esc_line(fmt.duration(clat.get('p95_ms')))}</td>"
                f"<td>{esc_line(_usage_text(eu.get('input_tokens')))}</td>"
                f"<td>{esc_line(_usage_text(eu.get('output_tokens')))}</td>"
                "</tr>"
            )
        role_table = (
            '<div class="tw"><table><thead><tr><th>Job</th><th>Role</th><th>Calls</th><th>Retries</th>'
            "<th>p50</th><th>p95</th><th>In tokens</th><th>Out tokens</th></tr></thead>"
            f"<tbody>{''.join(r_rows)}</tbody></table></div>"
        )
    inner.append(
        '<details class="inner"><summary>Performance &amp; model telemetry breakdown</summary>'
        f'<dl class="kv">{dl_rows}</dl>{role_table}</details>'
    )

    if data.telemetry_gaps:
        bullets = "".join(f"<li>{esc_line(g)}</li>" for g in data.telemetry_gaps)
        inner.append(
            f'<details class="inner"><summary>Lifecycle &amp; telemetry gaps ({len(data.telemetry_gaps)})</summary>'
            f'<ul class="bl">{bullets}</ul></details>'
        )

    inner.append(
        '<p class="para muted">Lifecycle progress and model spend describe execution state only; they are '
        "not security findings or assurance that the target is clean.</p>"
    )

    return (
        f'<details class="box" data-kind="{BoxKind.PROVENANCE.value}" open>'
        f"<summary>{head}</summary>"
        f'<div class="bb">{"".join(inner)}</div></details>'
    )


def _render_finding_dossier(rank: int, finding: LiveFinding) -> str:
    kind = BoxKind.CLAIM if finding.state == "confirmed" else BoxKind.GAP
    style = STYLE_BY_KIND[kind]
    open_attr = " open" if rank == 1 else ""

    badges = [
        _severity_badge(finding.technical_severity),
        _status_badge(finding.state),
    ]
    if finding.cwe:
        badges.append(f'<span class="meta-chip">{esc_line(finding.cwe)}</span>')
    if finding.primary_location:
        loc_short, cut = bound(finding.primary_location, 48)
        badges.append(f'<span class="meta-chip">{esc_line(loc_short + ("?" if cut else ""))}</span>')

    title_text, cut = bound(finding.title, 140)
    if cut:
        title_text += "?"
    head = (
        '<div class="bh">'
        f'<span class="chip" data-kind="{kind.value}">{esc_line(style.chip)}</span>'
        f"<h4>#{rank} ? {esc_line(title_text)}</h4>"
        f'{"".join(badges)}'
        "</div>"
    )

    field_pairs = [
        ("Rank", f"#{rank}"),
        ("Identifier", finding.finding_package_id or finding.claim_id or finding.identifier),
        ("Accepted state", f"{finding.state} ({finding.bucket.replace('_', ' ')})"),
        ("Technical severity", finding.technical_severity or "unrated / pending"),
        ("Ship-block status", (finding.ship_block_status or "not recorded").replace("_", " ")),
        ("CWE / OWASP", ", ".join([*([finding.cwe] if finding.cwe else []), *finding.owasp]) or "not classified"),
        ("Security predicate", (finding.security_predicate or "unavailable").replace("_", " ")),
        ("Primary location", finding.primary_location or "not resolved to single line"),
        ("Independent verification", finding.independent_verification),
    ]
    fields_html = "".join(
        f"<dt>{esc_line(label)}</dt><dd><code>{esc_line(val)}</code></dd>"
        for label, val in field_pairs
    )

    body: list[str] = [
        f'<dl class="kv">{fields_html}</dl>',
        f'<p class="para">{esc(finding.statement)}</p>',
    ]

    ev_parts: list[str] = []
    if finding.preconditions:
        ev_parts.append(
            '<div class="sub-label">Preconditions (claim assumptions)</div><ul class="bl">'
            + "".join(f"<li>{esc_line(p)}</li>" for p in finding.preconditions)
            + "</ul>"
        )
    if finding.evidence_rows:
        trs = "".join(
            "<tr>"
            f"<td>{esc_line(r['predicate'])}</td>"
            f"<td>{esc_line(r['kind'])}</td>"
            f"<td>{esc_line(r['admissibility'])}</td>"
            f"<td><code>{esc_line(r['locator'])}</code></td>"
            "</tr>"
            for r in finding.evidence_rows[:20]
        )
        ev_parts.append(
            '<div class="tw"><table><thead><tr><th>Predicate</th><th>Relation</th><th>Admissibility</th><th>Locator / Entity</th></tr></thead>'
            f"<tbody>{trs}</tbody></table></div>"
        )
    for ex in finding.excerpts[:4]:
        ev_parts.append(
            f'<details class="inner"><summary>Source excerpt ? {esc_line(ex["caption"])}</summary>'
            f'<pre class="code">{esc(ex["text"])}</pre></details>'
        )
    if ev_parts:
        body.append(
            f'<details class="inner"{" open" if rank == 1 else ""}>'
            f"<summary>Evidence citations &amp; source context ({len(finding.evidence_rows)} citations)</summary>"
            f'{"".join(ev_parts)}</details>'
        )

    detail_parts: list[str] = []
    if finding.score_rows:
        s_dl = "".join(
            f"<dt>{esc_line(k)}</dt><dd><code>{esc_line(v)}</code></dd>"
            for k, v in finding.score_rows
        )
        detail_parts.append(f'<dl class="kv">{s_dl}</dl>')
    if finding.poc_summary:
        detail_parts.append(f'<p class="para"><strong>PoC status:</strong> {esc(finding.poc_summary)}</p>')
    if finding.attack_chains:
        detail_parts.append(
            '<div class="sub-label">Attack chains</div><ul class="bl">'
            + "".join(f"<li>{esc_line(c)}</li>" for c in finding.attack_chains)
            + "</ul>"
        )
    if finding.remediation_rows:
        detail_parts.append(
            '<div class="sub-label">Remediation</div><ul class="bl">'
            + "".join(f"<li>{esc_line(r)}</li>" for r in finding.remediation_rows)
            + "</ul>"
        )
    if finding.limitations:
        detail_parts.append(
            '<div class="sub-label">Recorded limitations &amp; missing predicates</div><ul class="bl">'
            + "".join(f"<li>{esc_line(lim)}</li>" for lim in finding.limitations)
            + "</ul>"
        )
    if detail_parts:
        body.append(
            '<details class="inner">'
            "<summary>Risk dimensions, PoC, remediation &amp; limitations</summary>"
            f'{"".join(detail_parts)}</details>'
        )

    if finding.dossier is not None and finding.dossier.get("schema") == DOSSIER_SCHEMA:
        try:
            doc = dossier_document(finding.dossier)
            rendered_blocks = "".join(_block(b) for b in doc.blocks)
            body.append(
                '<details class="inner">'
                f"<summary>Full developer dossier ({esc_line(finding.dossier_id or 'dossier/1')})</summary>"
                f"{rendered_blocks}</details>"
            )
        except Exception:  # noqa: BLE001
            pass

    return (
        f'<details class="box finding-dossier" id="finding-{rank}" data-kind="{kind.value}"{open_attr}>'
        f"<summary>{head}</summary>"
        f'<div class="bb">{"".join(body)}</div></details>'
    )


def _stat_border_attr(tone: str | None) -> str:
    safe = token(tone or "")
    if safe in VERDICT_COLOR:
        return f' style="border-left-color:#{VERDICT_COLOR[safe]}"'
    return ""


def render_live_report_html(
    data: LiveReportData,
    *,
    refresh_seconds: int = DEFAULT_REFRESH_SECONDS,
) -> str:
    """Render a deterministic, self-contained HTML page with optional auto-refresh."""
    if refresh_seconds < 0:
        raise ValueError("refresh_seconds must be >= 0")

    refresh_meta = (
        f'<meta http-equiv="refresh" content="{int(refresh_seconds)}">'
        if refresh_seconds > 0
        else ""
    )
    refresh_label = (
        f"Auto-refresh: every {refresh_seconds // 60}m ({refresh_seconds}s)"
        if refresh_seconds > 0 and refresh_seconds % 60 == 0
        else (f"Auto-refresh: every {refresh_seconds}s" if refresh_seconds > 0 else "Auto-refresh: off")
    )

    tokens_val, tokens_sub = _token_pair_stat(data.models)
    lat_val, lat_sub = _latency_stat(data.models)
    totals = (data.models.get("totals") or {}) if isinstance(data.models, Mapping) else {}
    fresh_calls = totals.get("fresh_calls")
    retry_calls = totals.get("retry_calls", 0)
    ej = data.epoch_jobs
    if isinstance(ej.get("total"), int):
        jobs_val = f"{ej.get('completed', 0)} / {ej['total']}"
        jobs_sub = f"epoch ({data.accepted_job_count} accepted across run)"
    else:
        denom = data.known_graph_job_count or data.configured_enabled_jobs
        jobs_val = f"{data.accepted_job_count}" + (f" / {denom}" if denom else "")
        jobs_sub = "accepted job handoffs"

    if data.total_findings == 0:
        findings_sub = "none recorded yet" if data.run_status not in TERMINAL_RUN_STATUSES else "0 published"
        findings_tone = "unresolved"
    else:
        findings_sub = f"{data.confirmed_findings} confirmed ? {data.supported_findings} supported"
        findings_tone = "contradicted" if data.confirmed_findings else "insufficient_evidence"

    stat_cards = [
        ("# Findings", fmt.count(data.total_findings), findings_sub, findings_tone),
        ("Run status", data.run_status.replace("_", " ").lower(), "terminal confirmed" if data.terminal_confirmed else "live / unfinalized", _status_tone_key(data.run_status)),
        ("Wall / elapsed", fmt.duration(data.wall_ms), "from first pipeline event", None),
        ("Jobs progress", jobs_val, jobs_sub, None),
        ("Model calls", fmt.count(fresh_calls) if isinstance(fresh_calls, int) else fmt.UNAVAILABLE, f"{fmt.count(retry_calls)} retries", None),
        ("Tokens (in + out)", tokens_val, tokens_sub, None),
        ("Model latency", lat_val, lat_sub, None),
        ("Telemetry gaps", fmt.count(len(data.telemetry_gaps)), "explicit named gaps", "coverage_gap" if data.telemetry_gaps else None),
    ]
    stats_html = "".join(
        f'<div class="stat" data-stat="{esc_line(label.lower())}"{_stat_border_attr(tone)}>'
        f'<div class="k">{esc_line(label)}</div>'
        f'<div class="v">{esc_line(val)}</div>'
        f'<div class="sub">{esc_line(sub)}</div></div>'
        for label, val, sub, tone in stat_cards
    )

    meta_items = [
        ("Run ID", f"<code>{esc_line(data.run_id)}</code>"),
        ("Profile", f"<code>{esc_line(data.profile or fmt.UNAVAILABLE)}</code>"),
        ("Dagster dispatch", f"<code>{esc_line(data.dagster_run_id or fmt.UNAVAILABLE)}</code>"),
        ("Started (UTC)", esc_line(data.run_started_at or fmt.UNAVAILABLE)),
        ("Last event (UTC)", esc_line(data.last_event_at or fmt.UNAVAILABLE)),
        ("Observed (UTC)", esc_line(data.observed_at)),
        ("Source SHA-256", f"<code>{esc_line(_short_sha(data.source_sha256))}</code>"),
        ("Findings source", esc_line(data.findings_source.replace("_", " "))),
    ]
    meta_html = "".join(f"<dt>{esc_line(k)}</dt><dd>{v}</dd>" for k, v in meta_items)

    if data.total_findings == 0:
        findings_header_right = '<span class="meta-chip">0 findings</span>'
        findings_body = _render_na_watermark(data.findings_stage_note)
    else:
        shown = len(data.findings)
        findings_header_right = (
            f'<span class="meta-chip">Showing top {shown} of {data.total_findings} (top-n={data.top_n})</span>'
        )
        dossiers_html = "".join(
            _render_finding_dossier(idx, item)
            for idx, item in enumerate(data.findings, start=1)
        )
        omitted_note = ""
        if data.total_findings > shown:
            omitted_count = data.total_findings - shown
            sha_text = f", sha256 <code>{esc_line(data.omitted_findings_sha256[:16])}?</code>" if data.omitted_findings_sha256 else ""
            omitted_note = (
                f'<p class="cut">Bounded to top {shown} of {data.total_findings} ranked findings '
                f"({omitted_count} omitted; increase --top-n or ?top_n= to view more){sha_text}</p>"
            )
        findings_body = f'<p class="note">{esc(data.findings_stage_note)}</p>{dossiers_html}{omitted_note}'

    subtitle_active = ""
    if data.active_jobs:
        names = ", ".join(clean(j.get("job")) for j in data.active_jobs if j.get("job"))
        subtitle_active = f" ? Active: {names}"

    return "\n".join([
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        refresh_meta,
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">",
        f"<title>{esc_line(f'Live Run Dossier ? {data.run_id}')}</title>",
        f"<style>{_live_css()}</style></head><body><div class=\"page\">",
        '<header class="cover">',
        '<div class="live-banner">',
        '<div class="eyebrow">appsec-review ? Read-only live dossier</div>',
        f'<div class="refresh-pill"><span>{esc_line(refresh_label)}</span> ? <a href="">Refresh now</a></div>',
        "</div>",
        f"<h1>Run {esc_line(data.run_id)} {_status_badge(data.run_status)}</h1>",
        f'<div class="sub">Status: {esc_line(data.run_status.replace("_", " ").lower())}{esc_line(subtitle_active)}</div>',
        f'<dl class="meta-grid">{meta_html}</dl>',
        "</header><main>",
        '<div class="section-head"><h2>Summary &amp; performance metrics</h2></div>',
        f'<div class="stats">{stats_html}</div>',
        '<div class="section-head"><h2>Run dispatch &amp; nested job progress</h2></div>',
        _render_status_section(data),
        f'<div class="section-head"><h2>Top {data.top_n} findings</h2>{findings_header_right}</div>',
        f'<section id="findings-section">{findings_body}</section>',
        "</main></div></body></html>",
    ]) + "\n"


# --- Stdlib read-only HTTP server -------------------------------------------------------------

class LiveReportHTTPServer(ThreadingHTTPServer):
    """Threaded stdlib HTTP server carrying immutable configuration for one read-only run."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        run_dir: Path,
        top_n: int = DEFAULT_TOP_N,
        refresh_seconds: int = DEFAULT_REFRESH_SECONDS,
        quiet: bool = False,
    ) -> None:
        self.run_dir = Path(run_dir).resolve()
        self.top_n = top_n
        self.refresh_seconds = refresh_seconds
        self.quiet = quiet
        super().__init__(server_address, _LiveReportHandler)


class _LiveReportHandler(BaseHTTPRequestHandler):
    server: LiveReportHTTPServer

    def do_GET(self) -> None:  # noqa: N802
        self._serve(send_body=True)

    def do_HEAD(self) -> None:  # noqa: N802
        self._serve(send_body=False)

    def _parse_int_query(self, params: Mapping[str, list[str]], key: str, default: int, minimum: int, maximum: int) -> int:
        if key not in params or not params[key]:
            return default
        raw = params[key][0].strip()
        value = int(raw)
        if not minimum <= value <= maximum:
            raise ValueError(f"{key} must be between {minimum} and {maximum}")
        return value

    def _serve(self, *, send_body: bool) -> None:
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query, keep_blank_values=False)

        if route == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if route == "/healthz":
            data = collect_live_report_data(self.server.run_dir, top_n=self.server.top_n)
            payload = json.dumps({
                "ok": True,
                "run_id": data.run_id,
                "status": data.run_status,
                "findings_count": data.total_findings,
                "observed_at": data.observed_at,
                "refresh_seconds": self.server.refresh_seconds,
            }, sort_keys=True).encode("utf-8") + b"\n"
            self._write_response(HTTPStatus.OK, "application/json; charset=utf-8", payload, send_body=send_body)
            return

        valid_routes = {"/", "/index.html", f"/runs/{self.server.run_dir.name}"}
        if route not in valid_routes:
            body = b"Not found\n"
            self._write_response(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", body, send_body=send_body)
            return

        try:
            top_n = self._parse_int_query(params, "top_n", self.server.top_n, 1, MAX_TOP_N)
            refresh = self._parse_int_query(params, "refresh", self.server.refresh_seconds, 0, MAX_REFRESH_SECONDS)
        except ValueError as exc:
            body = f"Invalid query parameter: {clean(exc)}\n".encode("utf-8")
            self._write_response(HTTPStatus.BAD_REQUEST, "text/plain; charset=utf-8", body, send_body=send_body)
            return

        data = collect_live_report_data(self.server.run_dir, top_n=top_n)
        html_bytes = render_live_report_html(data, refresh_seconds=refresh).encode("utf-8")
        self._write_response(HTTPStatus.OK, "text/html; charset=utf-8", html_bytes, send_body=send_body)

    def _write_response(self, status: HTTPStatus, content_type: str, payload: bytes, *, send_body: bool) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if send_body:
            self.wfile.write(payload)

    def log_message(self, format_str: str, *args: Any) -> None:  # noqa: A002
        if not self.server.quiet:
            super().log_message(format_str, *args)


def create_live_report_server(
    run_dir: Path,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    top_n: int = DEFAULT_TOP_N,
    refresh_seconds: int = DEFAULT_REFRESH_SECONDS,
    quiet: bool = False,
) -> LiveReportHTTPServer:
    if top_n < 1 or top_n > MAX_TOP_N:
        raise ValueError(f"--top-n must be between 1 and {MAX_TOP_N}")
    if refresh_seconds < 0 or refresh_seconds > MAX_REFRESH_SECONDS:
        raise ValueError(f"--refresh-seconds must be between 0 and {MAX_REFRESH_SECONDS}")
    return LiveReportHTTPServer(
        (host, port),
        run_dir=run_dir,
        top_n=top_n,
        refresh_seconds=refresh_seconds,
        quiet=quiet,
    )


# --- CLI --------------------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    default_runs = Path(__file__).resolve().parents[3] / "runs"
    parser = argparse.ArgumentParser(
        prog="live-run-report",
        description=(
            "Serve or export a read-only nested dossier-style HTML live status and top-N findings "
            "report for one application security review run (auto-refreshes every 5 minutes by default)."
        ),
    )
    parser.add_argument(
        "--run-id", "--run",
        dest="run_id",
        required=True,
        help="Application run ID under --runs-root (e.g. 2026-11-25-0003) or path to a run directory.",
    )
    parser.add_argument(
        "--runs-root", "--runs-dir",
        dest="runs_root",
        type=Path,
        default=default_runs,
        help=f"Runs root directory when --run-id is an ID (default: {default_runs}).",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=DEFAULT_TOP_N,
        help=f"Maximum number of ranked findings to display (default: {DEFAULT_TOP_N}).",
    )
    parser.add_argument(
        "--refresh-seconds",
        type=int,
        default=DEFAULT_REFRESH_SECONDS,
        help=f"Browser auto-refresh interval in seconds; 0 disables refresh (default: {DEFAULT_REFRESH_SECONDS}).",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Bind address for the HTTP server (default: {DEFAULT_HOST}).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Bind port for the HTTP server; 0 picks an ephemeral port (default: {DEFAULT_PORT}).",
    )
    parser.add_argument(
        "--export-html",
        type=Path,
        default=None,
        help="Optional output path ('-' for stdout) to render HTML once and exit without serving.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-request HTTP access logs.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.top_n <= MAX_TOP_N:
        print(f"error: --top-n must be between 1 and {MAX_TOP_N}", file=sys.stderr)
        return 2
    if not 0 <= args.refresh_seconds <= MAX_REFRESH_SECONDS:
        print(f"error: --refresh-seconds must be between 0 and {MAX_REFRESH_SECONDS}", file=sys.stderr)
        return 2
    if not 0 <= args.port <= 65535:
        print("error: --port must be between 0 and 65535", file=sys.stderr)
        return 2
    try:
        run_dir = resolve_run_dir(args.run_id, args.runs_root)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.export_html is not None:
        data = collect_live_report_data(run_dir, top_n=args.top_n)
        rendered = render_live_report_html(data, refresh_seconds=args.refresh_seconds)
        if str(args.export_html) == "-":
            sys.stdout.write(rendered)
        else:
            out_path = args.export_html.resolve()
            if out_path == run_dir or run_dir in out_path.parents:
                print("error: refusing to write inside run directory; choose an external --export-html path", file=sys.stderr)
                return 2
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
            print(out_path)
        return 0

    server = create_live_report_server(
        run_dir,
        host=args.host,
        port=args.port,
        top_n=args.top_n,
        refresh_seconds=args.refresh_seconds,
        quiet=args.quiet,
    )
    bound_host, bound_port = server.server_address[:2]
    url_host = f"[{bound_host}]" if ":" in str(bound_host) else str(bound_host)
    print(
        f"Serving read-only live run dossier for {run_dir.name} at http://{url_host}:{bound_port}/ "
        f"(top_n={args.top_n}, refresh={args.refresh_seconds}s)",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
