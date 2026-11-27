"""Known-smoke-target auto-detection and SAST-vs-Hunter effectiveness analysis.

Operator-side effectiveness analysis built over run outputs and optional smoke answer keys.
Never writes raw host paths of an answer-key repository into run directories; only sanitized
identifiers (``repository_slug`` and ``answer_key_sha256``) are recorded.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
import shutil
from types import MappingProxyType
from typing import Any
import uuid

from appsec_review.container_runtime.catalog import load_catalog
from appsec_review.container_runtime.executor import ContainerExecutor, ExecutionRequest, Mount
from appsec_review.observability.findings.target_identity import normalize_target_id
from appsec_review.review.secret_redaction import redact_message
from appsec_review.signing.core import SignatureVerificationError
from appsec_review.storage import atomic_bytes, canonical_json, platform_file_sha256

from .digest import bullets, field, table
from .dossier_render import TOOL_ID, template_identity
from .latex import render_latex
from .model import (
    Bar,
    BarChart,
    Box,
    Document,
    Fields,
    Heading,
    Para,
    RadarAxis,
    RadarChart,
    RadarLegendRow,
    Stat,
    Stats,
)
from .smoke_score import (
    AXIS_KEY,
    AXIS_LABEL,
    LOW_CONFIDENCE_PLANTED,
    OUTPUT_DIRECTORY,
    RunData,
    SmokeScoreError,
    load_answer_key,
    primary_sites,
    score_run,
)
from .smoke_scorecard import SCALE_NOTE, SERIES, radar_axes, radar_series
from .text import clean
from .tokens import BoxKind, Limits

SCHEMA = "appsec-review/smoke-effectiveness/1"
RENDERER = "appsec-review/smoke-effectiveness-report/1"
RECEIPT_SCHEMA = "appsec-review/smoke-effectiveness-receipt/1"
JSON_NAME = "smoke-effectiveness.json"
MD_NAME = "smoke-effectiveness.md"
TEX_NAME = "smoke-effectiveness.tex"
PDF_NAME = "smoke-effectiveness.pdf"
RECEIPT_NAME = "smoke-effectiveness-receipt.json"
LOG_NAME = "smoke-effectiveness.log"
PDFINFO_NAME = "smoke-effectiveness.pdfinfo.txt"
LIMITS = Limits(text_chars=1200, value_chars=220, rows=96, ids=32)
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ExecutorFactory = Callable[..., ContainerExecutor]

_CWE_RE = re.compile(r"CWE-0*(\d+)", re.IGNORECASE)
_PAGES_RE = re.compile(r"^Pages:\s+(\d+)", re.MULTILINE)
_SCA_FAMILIES = frozenset({"dependency_sca", "sca", "sbom", "advisory", "osv", "vendored_sca"})
_SCA_SCANNERS = frozenset(
    {
        "tool-osv-scanner",
        "osv-scanner",
        "osv",
        "tool-trivy",
        "trivy",
        "tool-grype",
        "grype",
        "tool-cve-bin-tool",
        "cve-bin-tool",
        "tool-syft",
        "syft",
    }
)
_REFUTED_STATES = frozenset({"contradicted", "refuted", "not_exploitable", "not_reachable", "rejected", "false_positive"})
_SUPPORTED_STATES = frozenset({"supported", "insufficient_evidence", "proposed", "open", "unverified"})
_LINE_WINDOW_SLACK = 5


def _norm_cwe(value: Any) -> str | None:
    if isinstance(value, int) and value > 0:
        return f"CWE-{value}"
    if isinstance(value, str):
        match = _CWE_RE.search(value)
        if match:
            return f"CWE-{int(match.group(1))}"
    return None


def _norm_status(raw_state: str | None) -> str:
    state = (raw_state or "").strip().lower()
    if state == "confirmed":
        return "confirmed"
    if state in _REFUTED_STATES:
        return "refuted"
    if state in _SUPPORTED_STATES:
        return "supported"
    return "supported" if state else "refuted"


def _commits_compatible(commit_a: str | None, commit_b: str | None) -> bool:
    if not commit_a or not commit_b:
        return False
    a = commit_a.strip().lower()
    b = commit_b.strip().lower()
    if not a or not b:
        return False
    return a == b or a.startswith(b) or b.startswith(a)


def discover_matching_smoke_key(
    smoke_guide_root: Path,
    *,
    repository: str | None,
    target_id: str,
    snapshot_commit: str | None,
) -> Path | None:
    """Locate a matching ``answer-key.json`` under ``smoke_guide_root``, or ``None`` for non-smoke targets."""
    guide_root = Path(smoke_guide_root)
    if not guide_root.is_dir():
        return None

    candidates: list[Path] = []
    direct = guide_root / "answer-key.json"
    if direct.is_file():
        candidates.append(direct)
    try:
        candidates.extend(sorted(p for p in guide_root.glob("*/answer-key.json") if p.is_file()))
    except OSError:
        return None

    norm_target = normalize_target_id(target_id)
    norm_repo = normalize_target_id(repository) if repository else None
    snap = snapshot_commit.strip().lower() if isinstance(snapshot_commit, str) and snapshot_commit.strip() else None

    commit_exact_match: Path | None = None
    slug_match: Path | None = None

    for candidate in candidates:
        try:
            key = load_answer_key(candidate)
        except (OSError, ValueError, SmokeScoreError):
            continue
        key_commit_raw = key.get("commit")
        key_commit = key_commit_raw.strip().lower() if isinstance(key_commit_raw, str) and key_commit_raw.strip() else None
        key_repo_raw = key.get("repository")
        key_slug = normalize_target_id(key_repo_raw) if isinstance(key_repo_raw, str) else "unknown-target"

        commit_matches = _commits_compatible(snap, key_commit)
        if snap and key_commit and not commit_matches:
            continue

        repo_matches = key_slug != "unknown-target" and (
            key_slug == norm_target or (norm_repo is not None and key_slug == norm_repo)
        )
        if commit_matches:
            commit_exact_match = candidate
            break
        if repo_matches and slug_match is None:
            slug_match = candidate

    return commit_exact_match or slug_match


def _read_optional_job_json(run_root: Path, job_id: str, suffixes: Sequence[str]) -> Any:
    job_dir = run_root / "data" / "jobs" / job_id
    if not job_dir.is_dir():
        return None
    latest_path = job_dir / "latest.json"
    if latest_path.is_file():
        try:
            latest = json.loads(latest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            latest = None
        if isinstance(latest, Mapping) and isinstance(latest.get("handoff_path"), str):
            hp = run_root / latest["handoff_path"]
            if hp.is_file():
                try:
                    handoff = json.loads(hp.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    handoff = None
                if isinstance(handoff, Mapping):
                    for art in handoff.get("artifacts", ()) if isinstance(handoff.get("artifacts"), list) else ():
                        if isinstance(art, Mapping) and isinstance(art.get("path"), str):
                            rel = art["path"]
                            if any(rel.endswith(sfx) for sfx in suffixes):
                                target_file = run_root / rel
                                if target_file.is_file():
                                    try:
                                        return json.loads(target_file.read_text(encoding="utf-8"))
                                    except (OSError, ValueError):
                                        pass
                    for sfx in suffixes:
                        cand = hp.parent / sfx.lstrip("/")
                        if cand.is_file():
                            try:
                                return json.loads(cand.read_text(encoding="utf-8"))
                            except (OSError, ValueError):
                                pass
    for sfx in suffixes:
        name = sfx.lstrip("/")
        for candidate in (job_dir / name, *sorted(job_dir.glob(f"attempt_*/{name}")), *sorted(job_dir.glob(f"attempt_*/artifacts/{name}"))):
            if candidate.is_file():
                try:
                    return json.loads(candidate.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
    return None


def _format_location(path: str | None, start_line: int | None, end_line: int | None) -> str:
    if not path:
        return "unlocated"
    if isinstance(start_line, int) and start_line > 0:
        if isinstance(end_line, int) and end_line > start_line:
            return f"{path}:{start_line}-{end_line}"
        return f"{path}:{start_line}"
    return path


def _extract_poc_by_claim(run_root: Path, final_report: Mapping[str, Any] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    if isinstance(final_report, Mapping):
        poc_section = final_report.get("poc_outcomes") or final_report.get("poc")
        items = poc_section.get("items", ()) if isinstance(poc_section, Mapping) else ()
        for item in items:
            if not isinstance(item, Mapping):
                continue
            finding = item.get("finding") if isinstance(item.get("finding"), Mapping) else {}
            cid = finding.get("claim_id") or item.get("claim_id")
            status = item.get("status") or item.get("outcome")
            if isinstance(cid, str) and isinstance(status, str):
                result[cid] = status
    poc_doc = _read_optional_job_json(run_root, "job_poc_generation", ("poc-generation.json", "poc.json"))
    if isinstance(poc_doc, Mapping):
        for cand in poc_doc.get("candidates", ()) if isinstance(poc_doc.get("candidates"), list) else ():
            if not isinstance(cand, Mapping) or not isinstance(cand.get("claim_id"), str):
                continue
            cid = cand["claim_id"]
            if cid in result:
                continue
            execution = cand.get("execution")
            if isinstance(execution, Mapping) and execution.get("verified") is True:
                result[cid] = "verified"
            elif cand.get("files") or cand.get("description"):
                result[cid] = "candidate_generated"
    return result


def _extract_remediation_by_claim(run_root: Path, final_report: Mapping[str, Any] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for doc in (
        final_report.get("remediation_validation") if isinstance(final_report, Mapping) else None,
        _read_optional_job_json(run_root, "job_remediation_validation", ("remediation-validations.json",)),
    ):
        if not isinstance(doc, Mapping):
            continue
        for item in doc.get("items", ()) if isinstance(doc.get("items"), list) else ():
            if not isinstance(item, Mapping):
                continue
            finding = item.get("finding") if isinstance(item.get("finding"), Mapping) else {}
            cid = finding.get("claim_id") or item.get("claim_id")
            status = item.get("status")
            if isinstance(cid, str) and isinstance(status, str) and cid not in result:
                result[cid] = status
    return result


def _is_sca_lead(lead: Mapping[str, Any]) -> bool:
    family = str(lead.get("family") or "").strip().lower()
    scanner = str(lead.get("scanner") or lead.get("tool") or "").strip().lower()
    return family in _SCA_FAMILIES or scanner in _SCA_SCANNERS


def _extract_adjudicated_records(run_root: Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    run = RunData(run_root)
    assembly = run.assembly()
    observations_list = run.observations() or []
    obs_by_id: dict[str, dict[str, Any]] = {}
    for obs in observations_list:
        obs_by_id[obs.identity] = {
            "lead_id": obs.identity,
            "scanner": obs.scanner,
            "family": obs.family,
            "rule_id": obs.rule_id,
            "path": obs.location.path if obs.location else None,
            "start_line": obs.location.start_line if obs.location else None,
            "end_line": obs.location.end_line if obs.location else None,
            "reported_severity": obs.reported_severity,
        }

    pkg_by_id: dict[str, dict[str, Any]] = {}
    if isinstance(assembly, Mapping) and isinstance(assembly.get("packages"), list):
        for pkg in assembly["packages"]:
            if isinstance(pkg, Mapping) and isinstance(pkg.get("package_id"), str):
                pkg_by_id[pkg["package_id"]] = dict(pkg)
    else:
        fallback_pkgs = _read_optional_job_json(run_root, "job_inference_security_review", ("packages.json", "package-manifest.json"))
        pkg_rows = fallback_pkgs.get("packages", ()) if isinstance(fallback_pkgs, Mapping) else (fallback_pkgs if isinstance(fallback_pkgs, list) else ())
        for pkg in pkg_rows:
            if isinstance(pkg, Mapping) and isinstance(pkg.get("package_id"), str):
                pkg_by_id[pkg["package_id"]] = dict(pkg)

    projection = run.projection()
    if projection is None:
        fallback_claims = _read_optional_job_json(run_root, "job_inference_security_review", ("claims.json", "projection.json"))
        if isinstance(fallback_claims, Mapping):
            projection = fallback_claims
        elif isinstance(fallback_claims, list):
            projection = {"claims": fallback_claims, "relations": {}}
        else:
            projection = {"claims": [], "relations": {}}

    merge_doc = run.merge_document() or _read_optional_job_json(run_root, "job_inference_security_review", ("merge.json",)) or {}
    proposal_packages: Mapping[str, Any] = (
        merge_doc.get("proposal_packages") if isinstance(merge_doc, Mapping) and isinstance(merge_doc.get("proposal_packages"), Mapping) else {}
    )

    finding_pkgs = list(run.finding_packages())
    if not finding_pkgs:
        fb_findings = _read_optional_job_json(run_root, "job_inference_security_review", ("findings.json",))
        rows = fb_findings.get("findings", ()) if isinstance(fb_findings, Mapping) else (fb_findings if isinstance(fb_findings, list) else ())
        finding_pkgs = [dict(r) for r in rows if isinstance(r, Mapping)]

    gate_doc = run.gate_document() or _read_optional_job_json(
        run_root, "job_final_publication_gate", ("final-publication-gate.json", "gate.json")
    )
    gate_by_finding: dict[str, dict[str, Any]] = {}
    if isinstance(gate_doc, Mapping):
        for entry in gate_doc.get("packages", ()) if isinstance(gate_doc.get("packages"), list) else ():
            if isinstance(entry, Mapping):
                fid = entry.get("finding_package_id") or entry.get("finding_id")
                if isinstance(fid, str):
                    gate_by_finding[fid] = dict(entry)

    final_report = run.final_report() or _read_optional_job_json(
        run_root, "job_final_report_publication", ("final-report.json",)
    )
    dossiers_by_claim = dict(run.dossiers_by_claim())
    if not dossiers_by_claim:
        fb_dossiers = _read_optional_job_json(run_root, "job_dossier_publication", ("dossiers.json",))
        d_rows = fb_dossiers.get("dossiers", ()) if isinstance(fb_dossiers, Mapping) else (fb_dossiers if isinstance(fb_dossiers, list) else ())
        for d in d_rows:
            if isinstance(d, Mapping) and isinstance(d.get("claim_id"), str):
                dossiers_by_claim[d["claim_id"]] = dict(d)

    poc_by_claim = _extract_poc_by_claim(run_root, final_report if isinstance(final_report, Mapping) else None)
    rem_by_claim = _extract_remediation_by_claim(run_root, final_report if isinstance(final_report, Mapping) else None)

    claims_by_id: dict[str, dict[str, Any]] = {}
    for c in projection.get("claims", ()) if isinstance(projection.get("claims"), list) else ():
        if isinstance(c, Mapping) and isinstance(c.get("claim_id"), str):
            claims_by_id[c["claim_id"]] = dict(c)

    relations_map: dict[str, list[dict[str, Any]]] = {}
    raw_rels = projection.get("relations")
    if isinstance(raw_rels, Mapping):
        for rk, rv in raw_rels.items():
            if isinstance(rv, list):
                relations_map[str(rk)] = [dict(x) for x in rv if isinstance(x, Mapping)]
    elif isinstance(raw_rels, list):
        missing_loc_ids = [
            str(r.get("entity_id"))
            for r in raw_rels
            if isinstance(r, Mapping) and isinstance(r.get("entity_id"), str) and not r.get("locator")
        ]
        located_entities = run.locate(missing_loc_ids) if missing_loc_ids else {}
        for r in raw_rels:
            if not isinstance(r, Mapping) or not isinstance(r.get("claim_id"), str):
                continue
            row = dict(r)
            if not row.get("locator") and isinstance(row.get("entity_id"), str):
                locs = located_entities.get(row["entity_id"], [])
                if locs:
                    row["locator"] = f"{locs[0].path}:{locs[0].start_line}-{locs[0].end_line}"
                    if not row.get("entity_kind") and locs[0].kind:
                        row["entity_kind"] = locs[0].kind
            relations_map.setdefault(r["claim_id"], []).append(row)

    titles_by_claim: dict[str, list[str]] = {}
    for fp in finding_pkgs:
        cid = fp.get("claim_id")
        if isinstance(cid, str) and isinstance(fp.get("title"), str):
            titles_by_claim.setdefault(cid, []).append(fp["title"])

    def _resolve_claim_location(claim: Mapping[str, Any], fp: Mapping[str, Any] | None) -> tuple[str | None, int | None, int | None]:
        for src in (fp or {}, claim, dossiers_by_claim.get(str(claim.get("claim_id") or ""), {})):
            if isinstance(src.get("path"), str) and src["path"]:
                sl = src.get("start_line") if isinstance(src.get("start_line"), int) else (src.get("line") if isinstance(src.get("line"), int) else None)
                el = src.get("end_line") if isinstance(src.get("end_line"), int) else sl
                return src["path"], sl, el
            locs = src.get("locations")
            if isinstance(locs, list) and locs and isinstance(locs[0], Mapping) and isinstance(locs[0].get("path"), str):
                loc0 = locs[0]
                sl = loc0.get("start_line") if isinstance(loc0.get("start_line"), int) else None
                el = loc0.get("end_line") if isinstance(loc0.get("end_line"), int) else sl
                return loc0["path"], sl, el
        cid = str(claim.get("claim_id") or "")
        dossier = dossiers_by_claim.get(cid)
        claim_titles = list(titles_by_claim.get(cid, ()))
        if isinstance(claim.get("title"), str):
            claim_titles.append(claim["title"])
        if isinstance(dossier, Mapping) and isinstance(dossier.get("title"), str):
            claim_titles.append(dossier["title"])
        try:
            sites, _source = primary_sites(claim, relations_map, dossier, claim_titles)
        except Exception:
            sites = []
        if sites:
            s0 = sites[0]
            return s0.path, s0.start_line, s0.end_line
        return None, None, None

    def _package_provenance(claim: Mapping[str, Any], fp: Mapping[str, Any] | None) -> tuple[list[str], str, list[dict[str, Any]]]:
        cid = str(claim.get("claim_id") or "")
        pkg_ids: list[str] = []
        for pid in proposal_packages.get(cid, ()) if isinstance(proposal_packages.get(cid), list) else ():
            if isinstance(pid, str) and pid not in pkg_ids:
                pkg_ids.append(pid)
        for src in (fp or {}, claim):
            pid = src.get("package_id")
            if isinstance(pid, str) and pid not in pkg_ids:
                pkg_ids.append(pid)
            for p_extra in src.get("package_ids", ()) if isinstance(src.get("package_ids"), list) else ():
                if isinstance(p_extra, str) and p_extra not in pkg_ids:
                    pkg_ids.append(p_extra)

        kinds: set[str] = set()
        seed_leads: list[dict[str, Any]] = []
        seen_leads: set[str] = set()

        for pid in pkg_ids:
            pkg = pkg_by_id.get(pid, {})
            k = str(pkg.get("kind") or pkg.get("package_kind") or "").strip()
            lane_val = str(pkg.get("lane") or "").strip()
            if k in {"finding_lead", "hunt"}:
                kinds.add(k)
            elif lane_val == "lead" or pid.startswith("finding_lead"):
                kinds.add("finding_lead")
            elif lane_val == "hunt" or pid.startswith("hunt"):
                kinds.add("hunt")

            raw_leads = pkg.get("seed_leads") if isinstance(pkg.get("seed_leads"), list) else pkg.get("lead_ids", ())
            if isinstance(raw_leads, list):
                for entry in raw_leads:
                    if isinstance(entry, str):
                        if entry in seen_leads:
                            continue
                        seen_leads.add(entry)
                        obs = obs_by_id.get(entry)
                        if obs is not None:
                            seed_leads.append(obs)
                        else:
                            seed_leads.append({"lead_id": entry, "scanner": "scanner", "family": "source_sast", "rule_id": None})
                    elif isinstance(entry, Mapping):
                        lid = str(entry.get("lead_id") or entry.get("id") or f"lead-{len(seed_leads)}")
                        if lid in seen_leads:
                            continue
                        seen_leads.add(lid)
                        seed_leads.append(
                            {
                                "lead_id": lid,
                                "scanner": entry.get("scanner") or entry.get("tool") or "scanner",
                                "family": entry.get("family") or "source_sast",
                                "rule_id": entry.get("rule_id"),
                            }
                        )

        for src in (fp or {}, claim):
            if isinstance(src.get("seed_leads"), list):
                for entry in src["seed_leads"]:
                    if isinstance(entry, Mapping):
                        lid = str(entry.get("lead_id") or entry.get("id") or f"lead-{len(seed_leads)}")
                        if lid not in seen_leads:
                            seen_leads.add(lid)
                            seed_leads.append(
                                {
                                    "lead_id": lid,
                                    "scanner": entry.get("scanner") or entry.get("tool") or "scanner",
                                    "family": entry.get("family") or "source_sast",
                                    "rule_id": entry.get("rule_id"),
                                }
                            )
            k_direct = str(src.get("package_kind") or "").strip()
            lane_direct = str(src.get("lane") or "").strip()
            if k_direct in {"finding_lead", "hunt"}:
                kinds.add(k_direct)
            elif lane_direct == "lead":
                kinds.add("finding_lead")
            elif lane_direct == "hunt":
                kinds.add("hunt")

        if "finding_lead" in kinds and "hunt" in kinds:
            pkg_kind = "both"
        elif "hunt" in kinds:
            pkg_kind = "hunt"
        else:
            pkg_kind = "finding_lead"
        return pkg_ids, pkg_kind, seed_leads

    records: list[dict[str, Any]] = []
    covered_claims: set[str] = set()

    for fp in finding_pkgs:
        fid = str(fp.get("finding_package_id") or fp.get("finding_id") or "")
        cid = str(fp.get("claim_id") or fid)
        covered_claims.add(cid)
        claim = claims_by_id.get(cid, {})
        if claim.get("state") == "duplicate":
            continue
        gate_entry = gate_by_finding.get(fid, {})
        raw_state = str(fp.get("state") or claim.get("state") or gate_entry.get("state") or "supported")
        status = _norm_status(raw_state)
        bucket = str(gate_entry.get("bucket") or fp.get("bucket") or ("publishable" if status == "confirmed" else "verification_backlog"))
        ship_block = fp.get("ship_block") if isinstance(fp.get("ship_block"), Mapping) else {}
        inputs = ship_block.get("inputs") if isinstance(ship_block.get("inputs"), Mapping) else {}
        tech_sev = inputs.get("technical_severity") if isinstance(inputs.get("technical_severity"), Mapping) else {}
        severity = (
            fp.get("severity")
            or tech_sev.get("rating")
            or ship_block.get("technical_severity")
            or gate_entry.get("technical_severity")
            or (dossiers_by_claim.get(cid, {}).get("severity") if cid in dossiers_by_claim else None)
            or claim.get("severity")
        )
        cwe = _norm_cwe(
            fp.get("cwe")
            or fp.get("weakness_cwe")
            or claim.get("weakness_cwe")
            or claim.get("cwe")
            or (dossiers_by_claim.get(cid, {}).get("cwe") if cid in dossiers_by_claim else None)
        )
        path, start_line, end_line = _resolve_claim_location(claim, fp)
        pkg_ids, pkg_kind, seed_leads = _package_provenance(claim, fp)

        poc_field = fp.get("poc")
        poc_status = poc_by_claim.get(cid)
        if not poc_status:
            if isinstance(poc_field, Mapping) and poc_field.get("status"):
                poc_status = str(poc_field["status"])
            elif isinstance(fp.get("poc_status"), str):
                poc_status = fp["poc_status"]
            else:
                poc_status = "none"

        rem_status = rem_by_claim.get(cid) or (str(fp["remediation_validation_status"]) if isinstance(fp.get("remediation_validation_status"), str) else "none")
        predicate = str(claim.get("security_predicate") or fp.get("security_predicate") or "")
        is_dep = bool(
            fp.get("is_dependency")
            or predicate in {"vulnerable_dependency", "known_vulnerability_component"}
            or (seed_leads and all(_is_sca_lead(l) for l in seed_leads))
        )
        lane_label = (
            "Both SAST + Hunter"
            if pkg_kind == "both"
            else ("Autonomous Hunter Lane" if pkg_kind == "hunt" else "SAST-Seeded Lane")
        )
        records.append(
            {
                "finding_id": fid or cid,
                "claim_id": cid,
                "title": fp.get("title") or claim.get("statement") or cid,
                "package_ids": pkg_ids,
                "package_kind": pkg_kind,
                "lane": lane_label,
                "seed_leads": seed_leads,
                "scanners": sorted({str(l.get("scanner")) for l in seed_leads if l.get("scanner")}),
                "rules": sorted({str(l.get("rule_id")) for l in seed_leads if l.get("rule_id")}),
                "path": path,
                "start_line": start_line,
                "end_line": end_line,
                "location": _format_location(path, start_line, end_line),
                "cwe": cwe,
                "cve": fp.get("cve") or claim.get("cve"),
                "package_name": fp.get("package") or claim.get("package"),
                "severity": str(severity).lower() if isinstance(severity, str) and severity else None,
                "status": status,
                "raw_state": raw_state,
                "bucket": bucket,
                "published": bucket in {"publishable", "findings"} and status == "confirmed",
                "poc_status": poc_status,
                "remediation_validation_status": rem_status,
                "is_dependency": is_dep,
            }
        )

    for cid, claim in sorted(claims_by_id.items()):
        if cid in covered_claims or claim.get("state") == "duplicate":
            continue
        raw_state = str(claim.get("state") or "supported")
        status = _norm_status(raw_state)
        path, start_line, end_line = _resolve_claim_location(claim, None)
        pkg_ids, pkg_kind, seed_leads = _package_provenance(claim, None)
        cwe = _norm_cwe(claim.get("weakness_cwe") or claim.get("cwe"))
        predicate = str(claim.get("security_predicate") or "")
        is_dep = bool(
            claim.get("is_dependency")
            or predicate in {"vulnerable_dependency", "known_vulnerability_component"}
            or (seed_leads and all(_is_sca_lead(l) for l in seed_leads))
        )
        lane_label = (
            "Both SAST + Hunter"
            if pkg_kind == "both"
            else ("Autonomous Hunter Lane" if pkg_kind == "hunt" else "SAST-Seeded Lane")
        )
        records.append(
            {
                "finding_id": cid,
                "claim_id": cid,
                "title": titles_by_claim.get(cid) or claim.get("statement") or cid,
                "package_ids": pkg_ids,
                "package_kind": pkg_kind,
                "lane": lane_label,
                "seed_leads": seed_leads,
                "scanners": sorted({str(l.get("scanner")) for l in seed_leads if l.get("scanner")}),
                "rules": sorted({str(l.get("rule_id")) for l in seed_leads if l.get("rule_id")}),
                "path": path,
                "start_line": start_line,
                "end_line": end_line,
                "location": _format_location(path, start_line, end_line),
                "cwe": cwe,
                "cve": claim.get("cve"),
                "package_name": claim.get("package"),
                "severity": str(claim["severity"]).lower() if isinstance(claim.get("severity"), str) else None,
                "status": status,
                "raw_state": raw_state,
                "bucket": "unbucketed",
                "published": False,
                "poc_status": poc_by_claim.get(cid, "none"),
                "remediation_validation_status": rem_by_claim.get(cid, "none"),
                "is_dependency": is_dep,
            }
        )

    funnel_counts = {
        "scanner_leads": len(observations_list),
        "packages_total": len(pkg_by_id),
        "sast_packages": sum(1 for p in pkg_by_id.values() if (p.get("kind") or p.get("package_kind")) == "finding_lead" or p.get("lane") == "lead"),
        "hunter_packages": sum(1 for p in pkg_by_id.values() if (p.get("kind") or p.get("package_kind")) == "hunt" or p.get("lane") == "hunt"),
        "claims_total": sum(1 for c in claims_by_id.values() if c.get("state") != "duplicate"),
        "confirmed_total": sum(1 for r in records if r["status"] == "confirmed"),
        "supported_total": sum(1 for r in records if r["status"] == "supported"),
        "refuted_total": sum(1 for r in records if r["status"] == "refuted"),
    }
    return sorted(records, key=lambda r: (r["status"] != "confirmed", r["location"], r["finding_id"])), funnel_counts


def _compute_lane_attribution(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    confirmed = [r for r in records if r["status"] == "confirmed"]
    confirmed_sast_records = [r for r in confirmed if r["package_kind"] in {"finding_lead", "both"}]
    confirmed_hunt_records = [r for r in confirmed if r["package_kind"] in {"hunt", "both"}]

    clusters: list[dict[str, Any]] = []
    for rec in confirmed:
        path = rec.get("path")
        sl = rec.get("start_line")
        el = rec.get("end_line") if isinstance(rec.get("end_line"), int) else sl
        cwe = rec.get("cwe")
        matched_cluster: dict[str, Any] | None = None
        if isinstance(path, str) and path and isinstance(sl, int):
            assert isinstance(el, int)
            for cluster in clusters:
                if cluster["path"] != path:
                    continue
                if cwe and cluster["cwe"] and cwe != cluster["cwe"]:
                    continue
                if sl <= cluster["end_line"] + _LINE_WINDOW_SLACK and el >= cluster["start_line"] - _LINE_WINDOW_SLACK:
                    matched_cluster = cluster
                    break
        if matched_cluster is None:
            matched_cluster = {
                "path": path,
                "start_line": sl if isinstance(sl, int) else 0,
                "end_line": el if isinstance(el, int) else 0,
                "cwe": cwe,
                "is_dependency": bool(rec.get("is_dependency")),
                "finding_ids": [],
                "kinds": set(),
            }
            clusters.append(matched_cluster)
        else:
            if isinstance(sl, int) and sl < matched_cluster["start_line"]:
                matched_cluster["start_line"] = sl
            if isinstance(el, int) and el > matched_cluster["end_line"]:
                matched_cluster["end_line"] = el
            if cwe and not matched_cluster["cwe"]:
                matched_cluster["cwe"] = cwe
        matched_cluster["finding_ids"].append(rec["finding_id"])
        if rec["package_kind"] == "both":
            matched_cluster["kinds"].update(("finding_lead", "hunt"))
        else:
            matched_cluster["kinds"].add(rec["package_kind"])

    sast_only_clusters: list[dict[str, Any]] = []
    hunter_only_clusters: list[dict[str, Any]] = []
    both_lanes_clusters: list[dict[str, Any]] = []
    dependency_clusters: list[dict[str, Any]] = []

    for cl in clusters:
        summary = {
            "location": _format_location(cl["path"], cl["start_line"] or None, cl["end_line"] or None),
            "cwe": cl["cwe"],
            "finding_ids": sorted(set(cl["finding_ids"])),
        }
        kinds = cl["kinds"]
        if cl["is_dependency"] and "hunt" not in kinds:
            dependency_clusters.append(summary)
        elif "finding_lead" in kinds and "hunt" in kinds:
            both_lanes_clusters.append(summary)
        elif "hunt" in kinds:
            hunter_only_clusters.append(summary)
        else:
            sast_only_clusters.append(summary)

    return {
        "confirmed_findings_total": len(confirmed),
        "confirmed_from_sast_lane": len(confirmed_sast_records),
        "confirmed_from_hunter_lane": len(confirmed_hunt_records),
        "distinct_confirmed_issues": len(clusters),
        "sast_only_count": len(sast_only_clusters),
        "hunter_only_count": len(hunter_only_clusters),
        "both_lanes_count": len(both_lanes_clusters),
        "dependency_scanner_count": len(dependency_clusters),
        "sast_only_issues": sast_only_clusters,
        "hunter_only_rescues": hunter_only_clusters,
        "both_lanes_issues": both_lanes_clusters,
        "dependency_scanner_issues": dependency_clusters,
    }


def _match_record_to_planted_item(rec: Mapping[str, Any], item: Mapping[str, Any]) -> bool:
    klass = str(item.get("class") or "")
    if "dependency" in klass:
        item_cve = str(item.get("cve") or item.get("osv") or "").strip().upper()
        rec_cve = str(rec.get("cve") or "").strip().upper()
        if item_cve and rec_cve and item_cve == rec_cve:
            return True
        pkg = str(item.get("package") or "").strip().lower()
        rec_pkg = str(rec.get("package_name") or "").strip().lower()
        if pkg and rec_pkg and pkg == rec_pkg:
            return True
        loc_prefix = str(item.get("location") or "").strip()
        if loc_prefix and isinstance(rec.get("path"), str) and rec["path"].startswith(loc_prefix):
            return True
        return False

    item_file = item.get("file")
    rec_path = rec.get("path")
    if not isinstance(item_file, str) or not isinstance(rec_path, str) or rec_path != item_file:
        return False
    span = item.get("span") if isinstance(item.get("span"), Mapping) else item.get("introduced_span")
    sink = item.get("sink") if isinstance(item.get("sink"), Mapping) else {}
    s_start = span.get("start_line") if isinstance(span, Mapping) and isinstance(span.get("start_line"), int) else sink.get("line")
    s_end = span.get("end_line") if isinstance(span, Mapping) and isinstance(span.get("end_line"), int) else s_start
    r_start = rec.get("start_line")
    r_end = rec.get("end_line") if isinstance(rec.get("end_line"), int) else r_start
    if isinstance(s_start, int) and isinstance(s_end, int) and isinstance(r_start, int) and isinstance(r_end, int):
        if not (r_start <= s_end + _LINE_WINDOW_SLACK and r_end >= s_start - _LINE_WINDOW_SLACK):
            return False
    item_cwe = _norm_cwe(item.get("cwe"))
    rec_cwe = _norm_cwe(rec.get("cwe"))
    if item_cwe and rec_cwe and item_cwe != rec_cwe and klass.startswith("true_positive"):
        return False
    return True


def _reconcile_keyed(
    key: Mapping[str, Any],
    score: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    keyed = score.get("keyed") if isinstance(score.get("keyed"), Mapping) else {}
    scored_by_id = {
        str(row["id"]): row
        for row in (keyed.get("items") or ())
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    by_claim_records: dict[str, list[Mapping[str, Any]]] = {}
    by_finding_records: dict[str, Mapping[str, Any]] = {}
    for rec in records:
        by_claim_records.setdefault(rec["claim_id"], []).append(rec)
        by_finding_records[rec["finding_id"]] = rec

    planted_items = [item for item in (key.get("planted") or ()) if isinstance(item, Mapping)]
    positives_out: list[dict[str, Any]] = []
    negatives_out: list[dict[str, Any]] = []
    matched_positive_finding_ids: set[str] = set()
    matched_negative_finding_ids: set[str] = set()

    for item in planted_items:
        item_id = str(item.get("id") or "")
        klass = str(item.get("class") or "")
        scored = scored_by_id.get(item_id, {})

        matched_recs: list[Mapping[str, Any]] = []
        seen_fids: set[str] = set()
        for fp_ref in scored.get("finding_packages", ()) if isinstance(scored.get("finding_packages"), list) else ():
            if isinstance(fp_ref, Mapping) and isinstance(fp_ref.get("finding_package_id"), str):
                fid = fp_ref["finding_package_id"]
                if fid in by_finding_records and fid not in seen_fids:
                    seen_fids.add(fid)
                    matched_recs.append(by_finding_records[fid])
        for cl_ref in scored.get("claims", ()) if isinstance(scored.get("claims"), list) else ():
            if isinstance(cl_ref, Mapping) and isinstance(cl_ref.get("claim_id"), str):
                for rec in by_claim_records.get(cl_ref["claim_id"], ()):
                    if rec["finding_id"] not in seen_fids:
                        seen_fids.add(rec["finding_id"])
                        matched_recs.append(rec)
        for rec in records:
            if rec["finding_id"] not in seen_fids and _match_record_to_planted_item(rec, item):
                seen_fids.add(rec["finding_id"])
                matched_recs.append(rec)

        confirmed_recs = [r for r in matched_recs if r["status"] == "confirmed"]
        span = item.get("span") if isinstance(item.get("span"), Mapping) else item.get("introduced_span")
        start_line = span.get("start_line") if isinstance(span, Mapping) and isinstance(span.get("start_line"), int) else None
        end_line = span.get("end_line") if isinstance(span, Mapping) and isinstance(span.get("end_line"), int) else start_line
        loc_display = (
            _format_location(item.get("file"), start_line, end_line)
            if isinstance(item.get("file"), str)
            else f"{item.get('package') or 'dependency'}@{item.get('version') or item.get('fixed_version') or 'unknown'}"
        )

        if klass.startswith("true_positive"):
            for r in confirmed_recs:
                matched_positive_finding_ids.add(r["finding_id"])
            is_hit = bool(confirmed_recs) or scored.get("outcome") == "hit"
            if not is_hit:
                attr_lane = "missed"
                supported_recs = [r for r in matched_recs if r["status"] == "supported"]
                if supported_recs:
                    lanes_seen = sorted({"Hunter" if r["package_kind"] == "hunt" else ("Both" if r["package_kind"] == "both" else "SAST") for r in supported_recs})
                    attr_display = f"Backlog supported ({', '.join(lanes_seen)})"
                elif klass == "true_positive_dependency" and scored.get("leads"):
                    attr_display = "SCA lead packaged (VEX under_investigation; 0 claims)"
                else:
                    attr_display = "MISSED"
            elif klass == "true_positive_dependency" or (confirmed_recs and all(r.get("is_dependency") for r in confirmed_recs)):
                attr_lane = "dependency_scanner"
                attr_display = "Dependency Scanner (OSV/Trivy)"
            else:
                kinds: set[str] = set()
                for r in confirmed_recs:
                    if r["package_kind"] == "both":
                        kinds.update(("finding_lead", "hunt"))
                    else:
                        kinds.add(r["package_kind"])
                for cl_ref in scored.get("claims", ()) if isinstance(scored.get("claims"), list) else ():
                    if isinstance(cl_ref, Mapping) and cl_ref.get("state") == "confirmed":
                        kinds.add("hunt" if cl_ref.get("lane") == "hunt" else "finding_lead")
                if "finding_lead" in kinds and "hunt" in kinds:
                    attr_lane = "both_lanes"
                    attr_display = "Both SAST + Hunter"
                elif "hunt" in kinds:
                    attr_lane = "hunter_only"
                    attr_display = "Hunter only"
                else:
                    attr_lane = "sast_only"
                    attr_display = "SAST only"

            matched_ids = sorted({r["finding_id"] for r in confirmed_recs})
            if not matched_ids and is_hit:
                matched_ids = sorted(
                    {
                        str(fp["finding_package_id"])
                        for fp in (scored.get("finding_packages") or ())
                        if isinstance(fp, Mapping) and isinstance(fp.get("finding_package_id"), str)
                    }
                )
            resolved_loc = confirmed_recs[0]["location"] if confirmed_recs and confirmed_recs[0]["location"] != "unlocated" else loc_display
            positives_out.append(
                {
                    "id": item_id,
                    "class": klass,
                    "title": item.get("title") or item.get("cve") or item.get("osv") or item_id,
                    "cwe": _norm_cwe(item.get("cwe")),
                    "cve": item.get("cve") or item.get("osv"),
                    "planted_location": loc_display,
                    "resolved_location": resolved_loc,
                    "reconciliation": "MATCHED" if is_hit else "MISSED",
                    "matched_finding_ids": matched_ids,
                    "attribution_lane": attr_lane,
                    "attribution_display": attr_display,
                    "stage": scored.get("stage") or ("confirmed" if is_hit else "not_observed"),
                }
            )
        else:
            unclaimed_confirmed = [
                r for r in confirmed_recs if r["finding_id"] not in matched_positive_finding_ids and r.get("bucket") != "withheld"
            ]
            for r in unclaimed_confirmed:
                matched_negative_finding_ids.add(r["finding_id"])
            leads = list(scored.get("leads") or ()) if isinstance(scored.get("leads"), list) else []
            if not leads:
                for r in matched_recs:
                    leads.extend(r.get("seed_leads") or ())
            raw_sast_hit = bool(leads) or bool(item.get("flagged_by"))
            admitted_leads = [l for l in leads if isinstance(l, Mapping) and l.get("admission") == "admitted"]
            false_alarm = bool(unclaimed_confirmed)
            if false_alarm:
                suppression = "falsely_reported"
            elif any(r["status"] == "refuted" for r in matched_recs):
                suppression = "verifier_or_judge_refuted"
            elif any(r.get("bucket") == "withheld" for r in matched_recs):
                suppression = "gate_withheld"
            elif admitted_leads or scored.get("packages"):
                suppression = "review_or_judge_suppressed"
            elif leads:
                suppression = "admission_filtered"
            else:
                suppression = "no_raw_scanner_hit"

            negatives_out.append(
                {
                    "id": item_id,
                    "class": klass,
                    "title": item.get("title") or item_id,
                    "planted_location": loc_display,
                    "reconciliation": "FALSE_ALARM" if false_alarm else "CLEANLY_REJECTED",
                    "raw_sast_hit": raw_sast_hit,
                    "raw_sast_lead_count": len(leads),
                    "admitted_sast_lead_count": len(admitted_leads),
                    "scanners": sorted({str(l.get("scanner")) for l in leads if isinstance(l, Mapping) and l.get("scanner")}),
                    "suppression_mechanism": suppression,
                    "false_alarm_finding_ids": sorted({r["finding_id"] for r in unclaimed_confirmed}),
                    "stage": scored.get("stage") or ("false_report" if false_alarm else "correctly_passed"),
                }
            )

    all_planted_fids = matched_positive_finding_ids | matched_negative_finding_ids
    unplanted_code: list[dict[str, Any]] = []
    unplanted_sca: list[dict[str, Any]] = []
    for rec in records:
        if rec["status"] != "confirmed" or rec.get("bucket") == "withheld":
            continue
        if rec["finding_id"] in all_planted_fids:
            continue
        entry = {
            "finding_id": rec["finding_id"],
            "claim_id": rec["claim_id"],
            "title": rec["title"],
            "location": rec["location"],
            "cwe": rec["cwe"],
            "cve": rec.get("cve"),
            "severity": rec["severity"],
            "package_kind": rec["package_kind"],
            "lane": "Dependency Scanner" if rec.get("is_dependency") else ("Hunter" if rec["package_kind"] == "hunt" else ("Both SAST + Hunter" if rec["package_kind"] == "both" else "SAST")),
        }
        if rec.get("is_dependency"):
            unplanted_sca.append(entry)
        else:
            unplanted_code.append(entry)

    code_tps = [p for p in positives_out if p["class"] == "true_positive_code"]
    dep_tps = [p for p in positives_out if p["class"] == "true_positive_dependency"]
    code_total = len(code_tps)
    code_matched = sum(1 for p in code_tps if p["reconciliation"] == "MATCHED")
    code_sast_only = sum(1 for p in code_tps if p["attribution_lane"] == "sast_only")
    code_hunter_only = sum(1 for p in code_tps if p["attribution_lane"] == "hunter_only")
    code_both = sum(1 for p in code_tps if p["attribution_lane"] == "both_lanes")
    dep_total = len(dep_tps)
    dep_matched = sum(1 for p in dep_tps if p["reconciliation"] == "MATCHED")

    fp_traps = [n for n in negatives_out if n["class"] == "false_positive"]
    neg_total = len(negatives_out)
    false_alarms = sum(1 for n in negatives_out if n["reconciliation"] == "FALSE_ALARM")
    fp_trap_false_alarms = sum(1 for n in fp_traps if n["reconciliation"] == "FALSE_ALARM")
    matched_total = code_matched + dep_matched

    def _rate(num: int, den: int) -> float | None:
        return round(num / den, 4) if den > 0 else None

    headline = {
        "code_tp_total": code_total,
        "code_tp_matched": code_matched,
        "code_tp_recall": _rate(code_matched, code_total),
        "sast_only_code_matched": code_sast_only,
        "hunter_only_code_matched": code_hunter_only,
        "both_lanes_code_matched": code_both,
        "sast_only_code_recall": _rate(code_sast_only + code_both, code_total),
        "sast_exclusive_code_recall": _rate(code_sast_only, code_total),
        "hunter_only_code_recall": _rate(code_hunter_only + code_both, code_total),
        "hunter_rescue_code_recall": _rate(code_hunter_only, code_total),
        "combined_sast_hunter_recall": _rate(code_matched, code_total),
        "vendored_cve_total": dep_total,
        "vendored_cve_matched": dep_matched,
        "vendored_cve_recall": _rate(dep_matched, dep_total),
        "planted_negatives_total": neg_total,
        "planted_fp_traps_total": len(fp_traps),
        "false_alarms": false_alarms,
        "fp_trap_false_alarms": fp_trap_false_alarms,
        "planted_fp_trap_rejection_rate": _rate(neg_total - false_alarms, neg_total),
        "strict_fp_trap_rejection_rate": _rate(len(fp_traps) - fp_trap_false_alarms, len(fp_traps)),
        "precision": _rate(matched_total, matched_total + false_alarms),
        "unplanted_code_findings_count": len(unplanted_code),
        "unplanted_sca_findings_count": len(unplanted_sca),
    }

    return {
        "headline_metrics": headline,
        "planted_positives": positives_out,
        "planted_negatives": negatives_out,
        "unplanted_code_findings": unplanted_code,
        "unplanted_sca_findings": unplanted_sca,
        "by_axis": list(keyed.get("by_axis") or ()),
    }


def build_smoke_effectiveness(
    run_root: Path,
    *,
    key_path: Path | None = None,
) -> dict[str, Any]:
    """Build ``appsec-review/smoke-effectiveness/1`` payload for ``run_root``."""
    run_root = Path(run_root)
    key: dict[str, Any] | None = None
    answer_key_meta: dict[str, Any] | None = None
    if key_path is not None:
        key_bytes = Path(key_path).read_bytes()
        key_sha256 = hashlib.sha256(key_bytes).hexdigest()
        key = load_answer_key(Path(key_path))
        repo_slug = normalize_target_id(key.get("repository") if isinstance(key.get("repository"), str) else None)
        answer_key_meta = {
            "answer_key_id": f"{repo_slug}:{key_sha256[:16]}",
            "repository_slug": repo_slug,
            "answer_key_sha256": key_sha256,
            "language": key.get("language"),
            "tag": key.get("tag"),
            "commit": key.get("commit"),
            "planted_count": len(key.get("planted") or ()),
        }

    score = score_run(run_root, key)
    records, funnel = _extract_adjudicated_records(run_root)
    attribution = _compute_lane_attribution(records)
    keyed_reconciliation = _reconcile_keyed(key, score, records) if key is not None else None

    return {
        "schema": SCHEMA,
        "run_id": score["run_id"],
        "keyed_smoke_target": key is not None,
        "answer_key": answer_key_meta,
        "funnel": funnel,
        "lane_attribution": attribution,
        "adjudicated_findings": records,
        "keyed": keyed_reconciliation,
        "smoke_score_summary": {
            "schema": score["schema"],
            "check_counts": score.get("check_counts"),
            "gaps": score.get("gaps", []),
        },
    }


def _pct(val: float | None) -> str:
    return "n/a" if val is None else f"{val * 100:.1f}%"


def render_smoke_effectiveness_markdown(payload: Mapping[str, Any]) -> str:
    """Render crisp Markdown summary of ``appsec-review/smoke-effectiveness/1``."""
    lines: list[str] = [
        f"# Smoke & Lane Effectiveness Report — `{payload['run_id']}`",
        "",
    ]
    ak = payload.get("answer_key")
    if isinstance(ak, Mapping):
        lines.append(
            f"- **Known Smoke Corpus**: `{ak['answer_key_id']}` (language `{ak.get('language')}`, tag `{ak.get('tag')}`, commit `{str(ak.get('commit') or '')[:12]}`)"
        )
    else:
        lines.append("- **Corpus Mode**: Unkeyed target review (SAST vs Autonomous Hunter lane attribution only)")
    attr = payload["lane_attribution"]
    lines.extend(
        [
            f"- **Distinct Confirmed Issues**: `{attr['distinct_confirmed_issues']}` "
            f"(SAST-only `{attr['sast_only_count']}`, Hunter-only rescues `{attr['hunter_only_count']}`, "
            f"Both SAST + Hunter `{attr['both_lanes_count']}`, Dependency Scanner `{attr['dependency_scanner_count']}`)",
            "",
            "## SAST vs Autonomous Hunter Attribution",
            "",
            "| Attribution Bucket | Distinct Confirmed Issues | Locations |",
            "| --- | ---: | --- |",
            f"| SAST-Only Discoveries (`finding_lead`) | {attr['sast_only_count']} | "
            + (", ".join(f"`{i['location']}`" for i in attr["sast_only_issues"]) or "none")
            + " |",
            f"| Hunter-Only Rescues (`hunt`) | {attr['hunter_only_count']} | "
            + (", ".join(f"`{i['location']}`" for i in attr["hunter_only_rescues"]) or "none")
            + " |",
            f"| Both SAST + Hunter Overlap | {attr['both_lanes_count']} | "
            + (", ".join(f"`{i['location']}`" for i in attr["both_lanes_issues"]) or "none")
            + " |",
            f"| Dependency Scanner (`OSV`/`Trivy`) | {attr['dependency_scanner_count']} | "
            + (", ".join(f"`{i['location']}`" for i in attr["dependency_scanner_issues"]) or "none")
            + " |",
            "",
        ]
    )

    keyed = payload.get("keyed")
    if isinstance(keyed, Mapping):
        hm = keyed["headline_metrics"]
        lines.extend(
            [
                "## Headline Ground-Truth Efficacy Metrics",
                "",
                "| Metric | Value | Detail |",
                "| --- | ---: | --- |",
                f"| Code TP Recall (Combined SAST + Hunter) | {_pct(hm['code_tp_recall'])} | `{hm['code_tp_matched']}/{hm['code_tp_total']}` planted code TPs |",
                f"| SAST-Only Code Recall | {_pct(hm['sast_only_code_recall'])} | `{hm['sast_only_code_matched'] + hm['both_lanes_code_matched']}/{hm['code_tp_total']}` (`{hm['sast_only_code_matched']}` SAST-exclusive) |",
                f"| Hunter-Only Code Recall | {_pct(hm['hunter_only_code_recall'])} | `{hm['hunter_only_code_matched'] + hm['both_lanes_code_matched']}/{hm['code_tp_total']}` (`{hm['hunter_only_code_matched']}` Hunter rescues) |",
                f"| Vendored CVE Recall | {_pct(hm['vendored_cve_recall'])} | `{hm['vendored_cve_matched']}/{hm['vendored_cve_total']}` planted dependency CVEs |",
                f"| Planted FP Trap Rejection Rate | {_pct(hm['planted_fp_trap_rejection_rate'])} | `{hm['planted_negatives_total'] - hm['false_alarms']}/{hm['planted_negatives_total']}` negatives cleanly rejected |",
                f"| Precision (Planted Corpus) | {_pct(hm['precision'])} | `{hm['false_alarms']}` false alarms across planted negatives |",
                "",
                "## Planted Positives Reconciliation",
                "",
                "| Item | Class | CWE / CVE | Location | Status | Lane Attribution | Matched Findings |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for p in keyed["planted_positives"]:
            cwe_or_cve = p.get("cwe") or p.get("cve") or "n/a"
            fids = ", ".join(f"`{fid[:20]}`" for fid in p["matched_finding_ids"]) or "none"
            lines.append(
                f"| `{p['id']}` | `{p['class']}` | `{cwe_or_cve}` | `{p['resolved_location']}` | **{p['reconciliation']}** | {p['attribution_display']} | {fids} |"
            )
        lines.extend(
            [
                "",
                "## Planted Negatives & False-Positive Traps",
                "",
                "| Item | Class | Location | Status | Raw SAST Hits | Suppression / Outcome |",
                "| --- | --- | --- | --- | ---: | --- |",
            ]
        )
        for n in keyed["planted_negatives"]:
            lines.append(
                f"| `{n['id']}` | `{n['class']}` | `{n['planted_location']}` | **{n['reconciliation']}** | {n['raw_sast_lead_count']} | `{n['suppression_mechanism']}` |"
            )
        lines.extend(
            [
                "",
                "## Unplanted Additional Findings (Bonus Discoveries)",
                "",
            ]
        )
        bonus = [*keyed["unplanted_code_findings"], *keyed["unplanted_sca_findings"]]
        if not bonus:
            lines.append("No unplanted additional confirmed findings reported.")
        else:
            lines.extend(
                [
                    "| Finding ID | Location | CWE / CVE | Severity | Lane |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            for b in bonus:
                lines.append(
                    f"| `{b['finding_id'][:24]}` | `{b['location']}` | `{b.get('cwe') or b.get('cve') or 'n/a'}` | `{b.get('severity') or 'unrated'}` | {b['lane']} |"
                )
        lines.append("")

    lines.extend(
        [
            "## Adjudicated Claims & Findings Ledger",
            "",
            "| Finding / Claim | Lane | Location | CWE | Severity | Status | PoC | Remediation |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for rec in payload["adjudicated_findings"]:
        lines.append(
            f"| `{rec['finding_id'][:24]}` | {rec['lane']} | `{rec['location']}` | `{rec.get('cwe') or 'n/a'}` | "
            f"`{rec.get('severity') or 'unrated'}` | `{rec['status']}` | `{rec['poc_status']}` | `{rec['remediation_validation_status']}` |"
        )
    lines.append("")
    return "\n".join(lines)


def build_smoke_effectiveness_document(
    payload: Mapping[str, Any],
    *,
    source_date_epoch: int = 0,
) -> Document:
    """Build ``reporting.model.Document`` for ``smoke-effectiveness.tex`` / ``.pdf``."""
    run_id = clean(payload["run_id"])
    attr = payload["lane_attribution"]
    keyed = payload.get("keyed") if isinstance(payload.get("keyed"), Mapping) else None
    ak = payload.get("answer_key") if isinstance(payload.get("answer_key"), Mapping) else {}

    if keyed is not None:
        hm = keyed["headline_metrics"]
        stats_block = Stats(
            (
                Stat("Code TP Recall", _pct(hm["code_tp_recall"]), "confirmed" if (hm["code_tp_recall"] or 0) >= 0.8 else "neutral"),
                Stat("Hunter Rescues", str(hm["hunter_only_code_matched"]), "confirmed" if hm["hunter_only_code_matched"] else "neutral"),
                Stat("SAST-Only Recall", _pct(hm["sast_only_code_recall"]), "neutral"),
                Stat("FP Trap Rejection", _pct(hm["planted_fp_trap_rejection_rate"]), "confirmed" if hm["false_alarms"] == 0 else "contradicted"),
                Stat("Precision", _pct(hm["precision"]), "confirmed" if (hm["precision"] or 0) >= 0.9 else "neutral"),
            )
        )
    else:
        stats_block = Stats(
            (
                Stat("Confirmed Issues", str(attr["distinct_confirmed_issues"]), "confirmed" if attr["distinct_confirmed_issues"] else "neutral"),
                Stat("SAST-Only", str(attr["sast_only_count"]), "neutral"),
                Stat("Hunter Rescues", str(attr["hunter_only_count"]), "confirmed" if attr["hunter_only_count"] else "neutral"),
                Stat("Both Lanes", str(attr["both_lanes_count"]), "supported" if attr["both_lanes_count"] else "neutral"),
                Stat("SCA Confirmed", str(attr["dependency_scanner_count"]), "neutral"),
            )
        )

    bars = BarChart(
        title="Confirmed issue attribution across SAST and Autonomous Hunter lanes",
        unit="issues",
        bars=(
            Bar("SAST-only (finding_lead)", float(attr["sast_only_count"]), str(attr["sast_only_count"]), "supported"),
            Bar("Hunter-only rescues (hunt)", float(attr["hunter_only_count"]), str(attr["hunter_only_count"]), "confirmed"),
            Bar("Both SAST + Hunter overlap", float(attr["both_lanes_count"]), str(attr["both_lanes_count"]), "proposed"),
            Bar("Dependency Scanner (SCA)", float(attr["dependency_scanner_count"]), str(attr["dependency_scanner_count"]), "neutral"),
        ),
        caption="Distinct confirmed issues clustered by source file, line window and CWE.",
    )

    blocks: list[Any] = [
        stats_block,
        Heading(1, "SAST vs Autonomous Hunter attribution", "attribution"),
        bars,
    ]

    if keyed is not None:
        axis_rows = keyed.get("by_axis") or ()
        if axis_rows:
            axes = radar_axes(axis_rows)
            by_axis = {str(r["axis"]): r for r in axis_rows}
            legend = [RadarLegendRow("series", label, label, meaning) for label, _t, _m, meaning in SERIES]
            legend.extend(
                RadarLegendRow(
                    "axis",
                    AXIS_KEY[a],
                    AXIS_LABEL[a],
                    f"planted {by_axis[a]['planted']}, confirmed {by_axis[a]['confirmed']}"
                    if a in by_axis
                    else "not in corpus",
                )
                for a in axes
            )
            blocks.append(
                RadarChart(
                    "Recall, precision and coverage across security axes",
                    tuple(RadarAxis(AXIS_LABEL[a], AXIS_KEY[a]) for a in axes),
                    tuple(radar_series(axis_rows, axes)),
                    scale_note=SCALE_NOTE,
                    legend=tuple(legend),
                )
            )

        pos_rows = [
            (
                p["id"],
                p["class"],
                p.get("cwe") or p.get("cve") or "n/a",
                p["resolved_location"],
                p["reconciliation"],
                p["attribution_display"],
                ", ".join(fid[:14] for fid in p["matched_finding_ids"]) or "none",
            )
            for p in keyed["planted_positives"]
        ]
        neg_rows = [
            (
                n["id"],
                n["class"],
                n["planted_location"],
                n["reconciliation"],
                str(n["raw_sast_lead_count"]),
                n["suppression_mechanism"],
            )
            for n in keyed["planted_negatives"]
        ]
        blocks.extend(
            [
                Heading(1, "Planted positives reconciliation", "positives"),
                Box(
                    BoxKind.RESULT,
                    "Planted vulnerabilities vs SAST and Hunter confirmation",
                    items=(
                        table(
                            ("ID", "Class", "CWE/CVE", "Location", "Status", "Attribution", "Findings"),
                            pos_rows,
                            LIMITS,
                            widths=(0.08, 0.16, 0.11, 0.20, 0.10, 0.17, 0.18),
                        ),
                    ),
                ),
                Heading(1, "Planted negatives and false-positive traps", "negatives"),
                Box(
                    BoxKind.VERIFICATION,
                    "Scanner trap suppression and fixed-code verification",
                    items=(
                        table(
                            ("ID", "Class", "Location", "Status", "Raw SAST", "Suppression"),
                            neg_rows,
                            LIMITS,
                            widths=(0.09, 0.16, 0.24, 0.16, 0.10, 0.25),
                        ),
                    ),
                ),
            ]
        )
        bonus = [*keyed["unplanted_code_findings"], *keyed["unplanted_sca_findings"]]
        if bonus:
            bonus_rows = [
                (b["finding_id"][:18], b["location"], b.get("cwe") or b.get("cve") or "n/a", b.get("severity") or "unrated", b["lane"])
                for b in bonus
            ]
            blocks.append(
                Box(
                    BoxKind.EVIDENCE,
                    "Unplanted additional confirmed findings",
                    items=(
                        table(("Finding", "Location", "CWE/CVE", "Severity", "Lane"), bonus_rows, LIMITS, widths=(0.22, 0.30, 0.14, 0.14, 0.20)),
                    ),
                )
            )

    ledger_rows = [
        (
            r["finding_id"][:16],
            r["lane"],
            r["location"],
            r.get("cwe") or "n/a",
            r.get("severity") or "unrated",
            r["status"],
            r["poc_status"],
            r["remediation_validation_status"],
        )
        for r in payload["adjudicated_findings"]
    ]
    if ledger_rows:
        blocks.extend(
            [
                Heading(1, "Adjudicated findings and claims", "ledger"),
                Box(
                    BoxKind.EVIDENCE,
                    "Per-finding lane provenance, PoC and build-checked remediation",
                    items=(
                        table(
                            ("Finding", "Lane", "Location", "CWE", "Severity", "Status", "PoC", "Remediation"),
                            ledger_rows,
                            LIMITS,
                            widths=(0.15, 0.16, 0.20, 0.08, 0.09, 0.10, 0.10, 0.12),
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
                "Effectiveness report inputs",
                items=(
                    Fields(
                        (
                            field("Schema", SCHEMA, LIMITS, mono=True),
                            field("Answer key id", ak.get("answer_key_id") or "unkeyed", LIMITS, mono=True),
                            field("Answer key sha256", ak.get("answer_key_sha256") or "none", LIMITS, mono=True),
                            field("Renderer", RENDERER, LIMITS, mono=True),
                        )
                    ),
                    bullets(
                        [
                            "Answer-key reconciliation runs strictly outside review jobs; no worker or prompt receives answer-key metadata.",
                            f"Axes with fewer than {LOW_CONFIDENCE_PLANTED} planted items are low-confidence indicators.",
                        ],
                        LIMITS,
                        chars=400,
                    ),
                ),
            ),
        ]
    )

    head_sha = clean(ak.get("answer_key_sha256") or hashlib.sha256(canonical_json(payload)).hexdigest())
    return Document(
        title="Smoke & Lane Effectiveness",
        run_id=run_id,
        subtitle=f"SAST vs Hunter effectiveness for run {run_id}",
        status_badge="KEYED" if keyed is not None else "ATTRIBUTED",
        status_tone="confirmed" if keyed is not None else "supported",
        source_date_epoch=source_date_epoch,
        ledger_head=head_sha,
        blocks=tuple(blocks),
        renderer=RENDERER,
        head_label="effectiveness sha256",
    )


def render_latex_pdf_with_receipt(
    *,
    run_root: Path,
    out_dir: Path,
    document: Document,
    tex_name: str,
    pdf_name: str,
    log_name: str,
    pdfinfo_name: str,
    receipt_name: str,
    receipt_schema: str,
    renderer_id: str,
    render_pdf: bool,
    timeout_seconds: int = 600,
    max_tex_bytes: int = 8_388_608,
    max_pdf_bytes: int = 16_777_216,
    repository_root: Path | None = None,
    executor_factory: ExecutorFactory = ContainerExecutor,
    source_date_epoch: int = 0,
) -> dict[str, Any]:
    """Shared receipted LaTeX -> PDF renderer using the pinned offline ``tool-report-latex`` container."""
    run = Path(run_root).resolve()
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    repo_root = Path(repository_root or REPOSITORY_ROOT).resolve()
    template = repo_root / "containers" / "report" / "latex" / "template"
    identity = template_identity(template)
    tex_bytes = render_latex(document, template).encode("utf-8")

    for stale in (tex_name, pdf_name, log_name, pdfinfo_name, receipt_name):
        (out / stale).unlink(missing_ok=True)

    tool_identity: dict[str, Any] = {"id": TOOL_ID}
    gaps: list[str] = []
    execution: dict[str, Any] | None = None
    pages: int | None = None
    overfull_boxes: int | None = None
    pdf_bytes: bytes | None = None
    tex_sha256: str | None = None

    if len(tex_bytes) > max_tex_bytes:
        status = "render_failed"
        gaps.append("tex_exceeds_max_bytes")
    else:
        atomic_bytes(out / tex_name, tex_bytes)
        tex_sha256 = hashlib.sha256(tex_bytes).hexdigest()
        if not render_pdf:
            status = "latex_only"
            gaps.append("pdf_not_requested")
        else:
            staging = out / f".latex-staging-{uuid.uuid4().hex}"
            inputs = staging / "input"
            scratch = staging / "scratch"
            scratch.mkdir(parents=True, exist_ok=True)
            inputs.mkdir(parents=True, exist_ok=True)
            atomic_bytes(inputs / "report.tex", tex_bytes)
            atomic_bytes(inputs / "source-date-epoch", f"{source_date_epoch}\n".encode("utf-8"))
            try:
                catalog = load_catalog(repo_root)
                tool = replace(catalog.tool(TOOL_ID), timeout_seconds=timeout_seconds)
                catalog = replace(catalog, tools=MappingProxyType({**catalog.tools, TOOL_ID: tool}))
                tool_identity.update(
                    image_tag=tool.tag,
                    version=tool.version,
                    manifest_sha256=platform_file_sha256(tool.manifest_path),
                )
                result = executor_factory(catalog, run).execute(
                    ExecutionRequest(
                        tool_id=TOOL_ID,
                        argv=(tool.executable,),
                        target_root=inputs,
                        scratch_root=scratch,
                        extra_mounts=(Mount(template, "/template"), Mount(inputs, "/input")),
                        environment={"SOURCE_DATE_EPOCH": str(source_date_epoch)},
                        working_directory="/scratch",
                        file_size_limit_bytes=max_pdf_bytes,
                    )
                )
                for src_name, dst_name in (("report.log", log_name), ("report.pdfinfo.txt", pdfinfo_name)):
                    src_file = scratch / src_name
                    if src_file.is_file() and not src_file.is_symlink() and src_file.stat().st_size <= max_pdf_bytes:
                        raw = src_file.read_bytes()
                        atomic_bytes(out / dst_name, raw)
                        if src_name == "report.log":
                            overfull_boxes = raw.count(b"Overfull")
                        elif src_name == "report.pdfinfo.txt":
                            found = _PAGES_RE.search(raw.decode("utf-8", "replace"))
                            pages = int(found.group(1)) if found else None
                execution = {
                    "terminal_status": result.terminal_status,
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                    "oom_killed": result.oom_killed,
                    "file_size_limit_reached": result.file_size_limit_reached,
                    "image_id": result.image_id,
                }
                pdf_file = scratch / "report.pdf"
                if result.timed_out:
                    gaps.append("latex_render_timeout")
                elif (
                    result.exit_code != 0
                    or result.oom_killed
                    or result.file_size_limit_reached
                    or not pdf_file.is_file()
                    or pdf_file.is_symlink()
                ):
                    gaps.append("latex_render_failed")
                else:
                    candidate = pdf_file.read_bytes() if pdf_file.stat().st_size <= max_pdf_bytes else b""
                    if len(candidate) <= 32 or not candidate.startswith(b"%PDF-") or not candidate.rstrip().endswith(b"%%EOF"):
                        gaps.append("latex_pdf_invalid")
                    else:
                        pdf_bytes = candidate
                        atomic_bytes(out / pdf_name, pdf_bytes)
            except (OSError, RuntimeError, ValueError, SignatureVerificationError) as exc:
                detail = redact_message(f"{type(exc).__name__}: {exc}", bound=240) or type(exc).__name__
                gaps.append("latex_renderer_unavailable")
                execution = {"error": detail}
            finally:
                shutil.rmtree(staging, ignore_errors=True)
            status = "rendered" if pdf_bytes is not None else "render_failed"

    receipt = {
        "schema": receipt_schema,
        "run_id": document.run_id,
        "status": status,
        "tex_sha256": tex_sha256,
        "pdf_sha256": hashlib.sha256(pdf_bytes).hexdigest() if pdf_bytes is not None else None,
        "pages": pages,
        "overfull_boxes": overfull_boxes,
        "files": sorted(name for name in (tex_name, pdf_name, log_name, pdfinfo_name) if (out / name).is_file()) + [receipt_name],
        "template": identity,
        "tool": tool_identity,
        "renderer": renderer_id,
        "source_date_epoch": source_date_epoch,
        "execution": execution,
        "named_gaps": sorted(set(gaps)),
        "policy": {
            "network": "none",
            "shell_escape": False,
            "input_read_only": True,
            "template_read_only": True,
            "run_evidence": "read_only",
        },
    }
    atomic_bytes(out / receipt_name, canonical_json(receipt))
    return receipt


def write_smoke_effectiveness_outputs(
    run_root: Path,
    payload: Mapping[str, Any],
    *,
    render_tex_and_pdf: bool = False,
    render_pdf: bool = True,
    timeout_seconds: int = 600,
    max_tex_bytes: int = 8_388_608,
    max_pdf_bytes: int = 16_777_216,
    repository_root: Path | None = None,
    executor_factory: ExecutorFactory = ContainerExecutor,
    source_date_epoch: int = 0,
) -> dict[str, Any] | None:
    """Write ``smoke-effectiveness.{json,md}`` (and optional ``.tex``/``.pdf``) under ``data/verification/``."""
    out = Path(run_root) / OUTPUT_DIRECTORY
    out.mkdir(parents=True, exist_ok=True)
    atomic_bytes(out / JSON_NAME, canonical_json(payload))
    md_text = render_smoke_effectiveness_markdown(payload)
    atomic_bytes(out / MD_NAME, md_text.encode("utf-8"))
    if not render_tex_and_pdf:
        return None
    doc = build_smoke_effectiveness_document(payload, source_date_epoch=source_date_epoch)
    return render_latex_pdf_with_receipt(
        run_root=run_root,
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


__all__ = [
    "JSON_NAME",
    "MD_NAME",
    "PDF_NAME",
    "RECEIPT_NAME",
    "RECEIPT_SCHEMA",
    "RENDERER",
    "SCHEMA",
    "TEX_NAME",
    "build_smoke_effectiveness",
    "build_smoke_effectiveness_document",
    "discover_matching_smoke_key",
    "render_latex_pdf_with_receipt",
    "render_smoke_effectiveness_markdown",
    "write_smoke_effectiveness_outputs",
]
