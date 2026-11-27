"""Streamlined visual Executive Report layouts (Candidate A, Candidate B, Candidate C).

Each candidate projects the gate-certified ``final-report.json`` document (optionally
enriched with certified location, CWE, invariant, and hop metadata from bound dossiers)
into a concise, deterministic :class:`ReportDocument` without raw source code excerpts
or multi-page evidence/gap identifier dumps.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from appsec_review.review.models import IntegrityError
from appsec_review.review.secret_redaction import redact_prose_secrets

from .code_flow import to_mermaid
from .html import render_html
from .latex import default_template_dir, render_latex
from .model import (
    Bar,
    BarChart,
    Box,
    Bullets,
    Cell,
    Document,
    Field,
    Fields,
    FlowDiagram,
    FlowEdge,
    FlowNode,
    FlowNodeRole,
    Heading,
    Note,
    Para,
    RadarAxis,
    RadarChart,
    RadarLegendRow,
    RadarSeries,
    Stat,
    Stats,
    Table,
)
from .tokens import STATUS_TONES, BoxKind

ReportDocument = Document

CANDIDATE_IDS: tuple[str, str, str] = ("a", "b", "c")
CANDIDATE_LABELS: Mapping[str, str] = MappingProxyType({
    "a": "Candidate A",
    "b": "Candidate B",
    "c": "Candidate C",
})
CANDIDATE_TITLES: Mapping[str, str] = MappingProxyType({
    "a": "Executive Security Review \u2014 Candidate A",
    "b": "Executive Security Review \u2014 Candidate B",
    "c": "Executive Security Review \u2014 Candidate C",
})
CANDIDATE_SUBTITLES: Mapping[str, str] = MappingProxyType({
    "a": "Compact Posture and Priority Action Brief",
    "b": "Visual Triage and Remediation Matrix",
    "c": "Assurance Funnel and Coverage Summary",
})
CANDIDATE_RENDERER = "appsec-review/executive-candidate/1"

_REDACTED_MARKER_RE = re.compile(r"<redacted:\d+\s*chars>", re.IGNORECASE)
_PREFIXED_SHA_RE = re.compile(r"\b([a-z][a-z0-9_]*)-([0-9a-f]{64})\b")
_BARE_SHA_RE = re.compile(r"\b([0-9a-f]{64})\b")

_SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "unrated")
_SEVERITY_RANK: Mapping[str, int] = {name: idx for idx, name in enumerate(_SEVERITY_ORDER)}
_SEVERITY_TONE: Mapping[str, str] = {
    "critical": "contradicted",
    "high": "contradicted",
    "medium": "insufficient_evidence",
    "low": "not_exploitable_in_observed_configuration",
    "unrated": "unresolved",
}
_SHIP_BLOCK_RANK: Mapping[str, int] = {
    "ship_blocking": 0,
    "ship_blocking_pending_distinct_verification": 1,
    "decision_pending": 2,
    "needs_verification": 3,
    "not_ship_blocking": 4,
}
_FIX_LABELS: Mapping[str, str] = {
    "build_checked": "Build-Checked",
    "static_checked": "Static-Checked",
    "in_memory_patch_and_syntax_verified": "Syntax-Checked",
    "proposal_generated": "Patch Proposed",
    "proposal_only": "Patch Proposed",
    "rejected": "Rejected",
    "inconclusive": "Inconclusive",
    "manual_validation_required": "Manual Validation",
    "manual_design_required": "Manual Design",
    "insufficient_evidence": "Insufficient Evidence",
    "capped": "Capped",
    "not_launched": "Not Launched",
    "pending": "Pending",
}
_POC_COMPILED_STATES = frozenset({"compiled", "compile_verified", "compile_only_verified", "build_succeeded", "succeeded", "verified", "generated"})


def normalize_candidate_id(candidate_id: str) -> str:
    """Normalize a candidate identifier to ``'a'``, ``'b'``, or ``'c'``."""
    if not isinstance(candidate_id, str):
        raise ValueError(f"candidate_id must be a string, got {type(candidate_id).__name__}")
    cleaned = candidate_id.strip().lower()
    for prefix in ("executive-report-candidate-", "candidate-", "candidate_", "candidate "):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):].strip()
    if cleaned not in CANDIDATE_IDS:
        raise ValueError(f"unsupported executive candidate {candidate_id!r}; expected one of {CANDIDATE_IDS}")
    return cleaned


def _scrub_text(value: Any, *, max_len: int = 160) -> str:
    if value is None:
        return ""
    raw = " ".join(str(value).replace("\x00", " ").split())
    if not raw:
        return ""
    redacted = redact_prose_secrets(raw, secret_context=False)
    scrubbed = _REDACTED_MARKER_RE.sub("[redacted]", redacted)
    scrubbed = _PREFIXED_SHA_RE.sub(lambda m: f"{m.group(1)}-{m.group(2)[:8]}", scrubbed)
    scrubbed = _BARE_SHA_RE.sub(lambda m: f"{m.group(1)[:12]}", scrubbed)
    scrubbed = " ".join(scrubbed.split())
    if len(scrubbed) > max_len:
        if max_len <= 3:
            return scrubbed[:max_len]
        return scrubbed[: max_len - 3].rstrip() + "..."
    return scrubbed


def _short_id(value: Any, *, fallback: str = "unassigned") -> str:
    if not isinstance(value, str) or not value.strip():
        return fallback
    text = value.strip()
    matched = _PREFIXED_SHA_RE.fullmatch(text)
    if matched:
        return f"{matched.group(1)}-{matched.group(2)[:8]}"
    if _BARE_SHA_RE.fullmatch(text):
        return text[:12]
    return _scrub_text(text, max_len=36) or fallback


def _short_digest(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "unavailable"
    text = value.strip()
    return text[:12] if len(text) >= 12 else text


def assert_candidate_output_clean(text: str, *, label: str = "executive candidate output") -> None:
    """Fail closed if a redaction-marker token or NUL byte survives into rendered output."""
    if "\x00" in text:
        raise IntegrityError(f"{label} contains NUL byte")
    if _REDACTED_MARKER_RE.search(text):
        raise IntegrityError(f"{label} leaked raw redaction marker")


@dataclass(frozen=True, slots=True)
class _SanitizedHop:
    role: FlowNodeRole
    label: str
    location: str
    detail: str


@dataclass(frozen=True, slots=True)
class _SanitizedDossierMeta:
    finding_package_id: str
    claim_id: str
    kind: str
    cwe: str
    security_predicate: str
    locations: tuple[tuple[str, int], ...]
    hops: tuple[_SanitizedHop, ...]


@dataclass(frozen=True, slots=True)
class _FindingRow:
    rank: int
    finding_package_id: str
    short_id: str
    claim_id: str
    claim_short_id: str
    title: str
    severity: str
    ship_block_status: str
    lane: str
    cwe: str
    domain: str
    primary_location: str
    files: tuple[str, ...]
    fix_bucket: str
    fix_label: str
    poc_status: str
    poc_compiled: bool
    violated_invariant: str
    qualification_summary: str
    chain_elevated: bool
    hops: tuple[_SanitizedHop, ...]


def _normalize_hop_role(raw_role: Any, index: int, total: int) -> FlowNodeRole:
    token = str(raw_role or "").strip().lower()
    if token in ("entry", "source", "hop", "guard", "sink", "callee"):
        return token  # type: ignore[return-value]
    if token in ("sanitizer", "validator", "check", "barrier"):
        return "guard"
    if index == 0:
        return "source"
    if index == total - 1:
        return "sink"
    return "hop"


def _extract_sanitized_dossiers(dossiers: Sequence[Any]) -> dict[str, _SanitizedDossierMeta]:
    """Project ONLY non-excerpt location, CWE, invariant, and hop metadata from bound dossiers."""
    by_key: dict[str, _SanitizedDossierMeta] = {}
    for entry in dossiers:
        doc: Mapping[str, Any] | None = None
        kind = "confirmed_finding"
        binding: Mapping[str, Any] = {}
        if hasattr(entry, "document") and isinstance(getattr(entry, "document"), Mapping):
            doc = getattr(entry, "document")
            kind = str(getattr(entry, "kind", "confirmed_finding") or "confirmed_finding")
            raw_finding = getattr(entry, "finding", None)
            if isinstance(raw_finding, Mapping):
                binding = raw_finding
        elif isinstance(entry, Mapping):
            if isinstance(entry.get("document"), Mapping):
                doc = entry["document"]
                kind = str(entry.get("kind", "confirmed_finding") or "confirmed_finding")
                if isinstance(entry.get("finding"), Mapping):
                    binding = entry["finding"]
            else:
                doc = entry
                kind = str(entry.get("kind", "confirmed_finding") or "confirmed_finding")
        if not isinstance(doc, Mapping):
            continue
        doc_finding = doc.get("finding") if isinstance(doc.get("finding"), Mapping) else {}
        f_id = str(binding.get("finding_package_id") or doc_finding.get("finding_package_id") or "")
        c_id = str(binding.get("claim_id") or doc_finding.get("claim_id") or "")
        if not f_id and not c_id:
            continue

        cwe = _scrub_text(doc_finding.get("weakness_cwe") or doc.get("weakness_cwe") or "", max_len=32)
        predicate = _scrub_text(doc_finding.get("security_predicate") or doc.get("security_predicate") or "", max_len=120)

        # Explicitly ignore "excerpt", "code", "snippet", and "locator" fields on dossier sources/evidence.
        locs: list[tuple[str, int]] = []
        raw_sources = doc.get("sources")
        if isinstance(raw_sources, Sequence) and not isinstance(raw_sources, (str, bytes)):
            for src in raw_sources:
                if not isinstance(src, Mapping):
                    continue
                src_path = _scrub_text(src.get("path") or src.get("file_path") or "", max_len=96)
                if not src_path:
                    continue
                line_val = src.get("start_line", src.get("line", 0))
                line_num = int(line_val) if isinstance(line_val, int) and not isinstance(line_val, bool) and line_val > 0 else 0
                pair = (src_path, line_num)
                if pair not in locs:
                    locs.append(pair)

        hops: list[_SanitizedHop] = []
        raw_hops = doc.get("finding_path_rows")
        if isinstance(raw_hops, Sequence) and not isinstance(raw_hops, (str, bytes)):
            valid_rows = [r for r in raw_hops if isinstance(r, Mapping)][:5]
            total = len(valid_rows)
            for idx, hop in enumerate(valid_rows):
                raw_stage = str(hop.get("stage") or "")
                stage_role = raw_stage.split(".", 1)[-1].strip() if "." in raw_stage else raw_stage
                role = _normalize_hop_role(hop.get("role") or hop.get("kind") or hop.get("step_kind") or stage_role, idx, total)
                assessment = str(hop.get("assessment") or "")
                fn_from_assess = ""
                loc_from_assess = ""
                if " at " in assessment:
                    head_part, tail_part = assessment.split(" at ", 1)
                    fn_from_assess = head_part.strip()
                    loc_from_assess = tail_part.split(";", 1)[0].strip()
                fn_name = _scrub_text(hop.get("function") or hop.get("symbol") or hop.get("label") or fn_from_assess or "", max_len=48)
                hop_path = _scrub_text(hop.get("file_path") or hop.get("path") or loc_from_assess or "", max_len=72)
                hop_line_raw = hop.get("line", hop.get("start_line", 0))
                hop_line = int(hop_line_raw) if isinstance(hop_line_raw, int) and not isinstance(hop_line_raw, bool) and hop_line_raw > 0 else 0
                loc_str = f"{hop_path}:{hop_line}" if hop_path and hop_line and ":" not in hop_path else (hop_path or "bound-step")
                label = fn_name or f"{role.capitalize()} Step {idx + 1}"
                detail = _scrub_text(hop.get("references") or f"Certified {role} step", max_len=56)
                hops.append(_SanitizedHop(role=role, label=label, location=loc_str, detail=detail))

        meta = _SanitizedDossierMeta(
            finding_package_id=f_id,
            claim_id=c_id,
            kind=kind,
            cwe=cwe,
            security_predicate=predicate,
            locations=tuple(locs),
            hops=tuple(hops),
        )
        for key in (f_id, c_id):
            if not key:
                continue
            existing = by_key.get(key)
            if existing is None or (existing.kind != "confirmed_finding" and kind == "confirmed_finding"):
                by_key[key] = meta
    return by_key


def _normalize_severity(raw: Any) -> str:
    if isinstance(raw, str):
        lowered = raw.strip().lower()
        if lowered in _SEVERITY_RANK:
            return lowered
    return "unrated"


def _classify_fix(validation_status: str, planning_status: str, inline_status: str) -> tuple[str, str]:
    chosen = validation_status or inline_status or planning_status or "pending"
    lowered = chosen.strip().lower()
    if lowered == "build_checked":
        return "build_checked", _FIX_LABELS["build_checked"]
    if lowered in ("static_checked", "in_memory_patch_and_syntax_verified"):
        return "static_checked", _FIX_LABELS[lowered]
    if lowered in ("proposal_generated", "proposal_only"):
        return "proposed", _FIX_LABELS[lowered]
    if lowered in ("rejected", "inconclusive"):
        return "rejected_or_unchecked", _FIX_LABELS.get(lowered, lowered.replace("_", " ").title())
    label = _FIX_LABELS.get(lowered, _scrub_text(lowered.replace("_", " ").title(), max_len=28) or "Pending")
    return "pending", label


def _format_location(path: str, line: int) -> str:
    return f"{path}:{line}" if line > 0 else path


def _extract_finding_locations(
    finding: Mapping[str, Any],
    dossier_meta: _SanitizedDossierMeta | None,
) -> tuple[str, tuple[str, ...]]:
    files: list[str] = []
    primary = ""

    raw_primary = finding.get("primary_location")
    if isinstance(raw_primary, str) and raw_primary.strip():
        primary = _scrub_text(raw_primary, max_len=84)
        file_part = primary.split(":", 1)[0].strip()
        if file_part:
            files.append(file_part)
    elif isinstance(raw_primary, Mapping):
        p_path = _scrub_text(raw_primary.get("path") or raw_primary.get("file") or "", max_len=76)
        p_line = raw_primary.get("line", raw_primary.get("start_line", 0))
        line_no = int(p_line) if isinstance(p_line, int) and not isinstance(p_line, bool) and p_line > 0 else 0
        if p_path:
            primary = _format_location(p_path, line_no)
            files.append(p_path)

    raw_locs = finding.get("locations")
    if isinstance(raw_locs, Sequence) and not isinstance(raw_locs, (str, bytes)):
        for loc in raw_locs:
            if isinstance(loc, str) and loc.strip():
                cleaned = _scrub_text(loc, max_len=84)
                if not primary:
                    primary = cleaned
                f_part = cleaned.split(":", 1)[0].strip()
                if f_part and f_part not in files:
                    files.append(f_part)
            elif isinstance(loc, Mapping):
                l_path = _scrub_text(loc.get("path") or loc.get("file") or "", max_len=76)
                l_line = loc.get("line", loc.get("start_line", 0))
                line_no = int(l_line) if isinstance(l_line, int) and not isinstance(l_line, bool) and l_line > 0 else 0
                if l_path:
                    formatted = _format_location(l_path, line_no)
                    if not primary:
                        primary = formatted
                    if l_path not in files:
                        files.append(l_path)

    if dossier_meta is not None:
        for d_path, d_line in dossier_meta.locations:
            if not primary:
                primary = _format_location(d_path, d_line)
            if d_path not in files:
                files.append(d_path)

    if not primary:
        primary = "gate-certified-package"
    return primary, tuple(files)


def _extract_findings(
    final_report: Mapping[str, Any],
    dossiers: Sequence[Any],
) -> tuple[_FindingRow, ...]:
    dossier_map = _extract_sanitized_dossiers(dossiers)

    planning_by_key: dict[str, str] = {}
    for row in (final_report.get("remediation_planning") or {}).get("items") or ():
        if isinstance(row, Mapping):
            binding = row.get("finding") if isinstance(row.get("finding"), Mapping) else {}
            status = str(row.get("status") or "")
            for k in (binding.get("finding_package_id"), binding.get("claim_id")):
                if isinstance(k, str) and k:
                    planning_by_key[k] = status

    validation_by_key: dict[str, str] = {}
    for row in (final_report.get("remediation_validation") or {}).get("items") or ():
        if isinstance(row, Mapping):
            binding = row.get("finding") if isinstance(row.get("finding"), Mapping) else {}
            status = str(row.get("status") or "")
            for k in (binding.get("finding_package_id"), binding.get("claim_id")):
                if isinstance(k, str) and k:
                    validation_by_key[k] = status

    roadmap_by_key: dict[str, Mapping[str, Any]] = {}
    for row in final_report.get("remediation_roadmap") or ():
        if isinstance(row, Mapping):
            for k in (row.get("finding_package_id"), row.get("claim_id")):
                if isinstance(k, str) and k:
                    roadmap_by_key[k] = row

    poc_by_key: dict[str, str] = {}
    for row in (final_report.get("poc_outcomes") or {}).get("items") or ():
        if isinstance(row, Mapping):
            binding = row.get("finding") if isinstance(row.get("finding"), Mapping) else row
            status = str(row.get("status") or "")
            for k in (binding.get("finding_package_id"), binding.get("claim_id")):
                if isinstance(k, str) and k and status:
                    poc_by_key[k] = status

    domain_by_key: dict[str, str] = {}
    chain_elevated_keys: set[str] = set()
    for card in final_report.get("attack_chain_cards") or ():
        if not isinstance(card, Mapping):
            continue
        for step in card.get("steps") or ():
            if not isinstance(step, Mapping):
                continue
            dom = _scrub_text(step.get("domain_id") or "", max_len=36)
            for k in (step.get("finding_package_id"), step.get("claim_id")):
                if isinstance(k, str) and k:
                    chain_elevated_keys.add(k)
                    if dom and k not in domain_by_key:
                        domain_by_key[k] = dom

    raw_findings = [f for f in (final_report.get("findings") or ()) if isinstance(f, Mapping)]

    def _sort_key(item: Mapping[str, Any]) -> tuple[int, int, str, str]:
        ship_block = item.get("ship_block") if isinstance(item.get("ship_block"), Mapping) else {}
        sev = _normalize_severity(ship_block.get("technical_severity") or item.get("technical_severity") or item.get("severity"))
        sb_status = str(ship_block.get("status") or "not_ship_blocking")
        return (
            _SEVERITY_RANK.get(sev, 99),
            _SHIP_BLOCK_RANK.get(sb_status, 99),
            str(item.get("finding_package_id") or ""),
            str(item.get("claim_id") or ""),
        )

    ordered = sorted(raw_findings, key=_sort_key)
    rows: list[_FindingRow] = []
    for idx, item in enumerate(ordered, start=1):
        f_id = str(item.get("finding_package_id") or f"finding-{idx:04d}")
        c_id = str(item.get("claim_id") or f"claim-{idx:04d}")
        d_meta = dossier_map.get(f_id) or dossier_map.get(c_id)
        roadmap = roadmap_by_key.get(f_id) or roadmap_by_key.get(c_id) or {}

        ship_block = item.get("ship_block") if isinstance(item.get("ship_block"), Mapping) else {}
        sev = _normalize_severity(
            ship_block.get("technical_severity")
            or roadmap.get("technical_severity")
            or item.get("technical_severity")
            or item.get("severity")
        )
        sb_status = _scrub_text(ship_block.get("status") or roadmap.get("ship_block_status") or "not_ship_blocking", max_len=44)
        lane = _scrub_text(item.get("lane") or "lead", max_len=16)

        cwe_raw = item.get("cwe") or item.get("weakness_cwe") or (d_meta.cwe if d_meta else "")
        cwe = _scrub_text(cwe_raw, max_len=28) or "CWE-unmapped"

        domain_raw = (
            item.get("domain_id")
            or item.get("domain")
            or roadmap.get("domain_id")
            or domain_by_key.get(f_id)
            or domain_by_key.get(c_id)
            or ""
        )
        domain = _scrub_text(domain_raw, max_len=36) or "general"

        primary_loc, file_list = _extract_finding_locations(item, d_meta)

        val_status = validation_by_key.get(f_id) or validation_by_key.get(c_id) or str(roadmap.get("validation_status") or "")
        plan_status = planning_by_key.get(f_id) or planning_by_key.get(c_id) or str(roadmap.get("planning_status") or "")
        inline_rem = ""
        if isinstance(item.get("remediation"), Mapping):
            inline_rem = str(item["remediation"].get("status") or "")
        elif isinstance(item.get("remediation_status"), str):
            inline_rem = item["remediation_status"]
        fix_bucket, fix_label = _classify_fix(val_status, plan_status, inline_rem)

        poc_field = item.get("poc")
        poc_raw = ""
        if isinstance(poc_field, Mapping):
            poc_raw = str(poc_field.get("status") or "")
        elif isinstance(poc_field, str):
            poc_raw = poc_field
        roadmap_poc = roadmap.get("poc_posture") if isinstance(roadmap.get("poc_posture"), Mapping) else {}
        if not poc_raw:
            poc_raw = (
                poc_by_key.get(f_id)
                or poc_by_key.get(c_id)
                or str(roadmap_poc.get("status") or roadmap.get("poc_status") or "not_run")
            )
        poc_clean = _scrub_text(poc_raw.replace("_", " "), max_len=28) or "not run"
        poc_compiled = poc_raw.strip().lower() in _POC_COMPILED_STATES

        inv_raw = item.get("violated_invariant") or (d_meta.security_predicate if d_meta else "")
        if inv_raw:
            violated_invariant = _scrub_text(inv_raw, max_len=104)
        else:
            missing_preds = [str(p) for p in (item.get("missing_predicates") or ()) if p]
            if missing_preds:
                violated_invariant = _scrub_text(
                    f"Confirmed {lane}-lane defect; unresolved predicates: {', '.join(missing_preds[:2])}",
                    max_len=104,
                )
            else:
                violated_invariant = _scrub_text(
                    f"Confirmed {lane}-lane defect ({cwe}); all required security predicates satisfied",
                    max_len=104,
                )

        direct_cnt = len(item.get("direct_evidence") or ())
        assessed_cnt = len(item.get("analyst_assessed_evidence") or ())
        indep = item.get("independence") if isinstance(item.get("independence"), Mapping) else {}
        indep_tag = "distinct-verifier" if indep.get("verifier_model_distinct") else (
            "independent" if indep.get("independent") else "single-lane"
        )
        qual_summary = f"{direct_cnt} direct, {assessed_cnt} assessed ({indep_tag})"

        chain_flag = bool(item.get("attack_chains")) or (f_id in chain_elevated_keys) or (c_id in chain_elevated_keys)
        hops = d_meta.hops if d_meta is not None else ()

        rows.append(_FindingRow(
            rank=idx,
            finding_package_id=f_id,
            short_id=_short_id(f_id),
            claim_id=c_id,
            claim_short_id=_short_id(c_id),
            title=_scrub_text(item.get("title") or f"Confirmed Defect {idx}", max_len=88),
            severity=sev,
            ship_block_status=sb_status,
            lane=lane,
            cwe=cwe,
            domain=domain,
            primary_location=primary_loc,
            files=file_list,
            fix_bucket=fix_bucket,
            fix_label=fix_label,
            poc_status=poc_clean,
            poc_compiled=poc_compiled,
            violated_invariant=violated_invariant,
            qualification_summary=qual_summary,
            chain_elevated=chain_flag,
            hops=hops,
        ))
    return tuple(rows)


def _build_finding_flow_diagram(row: _FindingRow, *, index_prefix: str) -> FlowDiagram:
    """Build a concise 4-node linear FlowDiagram from certified hops or finding metadata."""
    if len(row.hops) >= 2:
        nodes_list: list[FlowNode] = []
        edges_list: list[FlowEdge] = []
        for idx, hop in enumerate(row.hops[:5], start=1):
            node_id = f"{index_prefix}_n{idx}"
            nodes_list.append(FlowNode(
                node_id=node_id,
                label=hop.label,
                role=hop.role,
                location=hop.location,
                detail=hop.detail,
            ))
            if idx > 1:
                edges_list.append(FlowEdge(
                    source=f"{index_prefix}_n{idx - 1}",
                    target=node_id,
                    label=f"hop {idx - 1}",
                ))
        return FlowDiagram(
            nodes=tuple(nodes_list),
            edges=tuple(edges_list),
            lane_badge=f"{row.lane.upper()} | {row.severity.upper()}",
            caption=f"{row.short_id}: {row.title} ({row.cwe}) -> {row.fix_label}",
            orientation="LR",
        )

    n1 = f"{index_prefix}_n1"
    n2 = f"{index_prefix}_n2"
    n3 = f"{index_prefix}_n3"
    n4 = f"{index_prefix}_n4"
    nodes = (
        FlowNode(
            node_id=n1,
            label="Primary Defect Site",
            role="source",
            location=row.primary_location,
            detail=f"Confirmed {row.lane}-lane locus",
        ),
        FlowNode(
            node_id=n2,
            label=row.cwe,
            role="hop",
            location=row.short_id,
            detail=_scrub_text(row.title, max_len=64),
        ),
        FlowNode(
            node_id=n3,
            label="Violated Invariant",
            role="sink",
            location=row.severity.upper(),
            detail=_scrub_text(row.violated_invariant, max_len=68),
        ),
        FlowNode(
            node_id=n4,
            label=f"Remedy: {row.fix_label}",
            role="guard",
            location=f"PoC: {row.poc_status}",
            detail=row.ship_block_status.replace("_", " "),
        ),
    )
    edges = (
        FlowEdge(source=n1, target=n2, label="exhibits"),
        FlowEdge(source=n2, target=n3, label="violates"),
        FlowEdge(source=n3, target=n4, label="mitigation"),
    )
    return FlowDiagram(
        nodes=nodes,
        edges=edges,
        lane_badge=f"{row.lane.upper()} | {row.severity.upper()}",
        caption=f"{row.short_id} ({row.severity.upper()}): {row.title}",
        orientation="LR",
    )


def _severity_bar_chart(rows: Sequence[_FindingRow], *, title: str) -> BarChart:
    counts = Counter(r.severity for r in rows)
    bars: list[Bar] = []
    for sev in _SEVERITY_ORDER:
        cnt = counts.get(sev, 0)
        if cnt == 0 and sev == "unrated":
            continue
        bars.append(Bar(
            label=sev.capitalize(),
            value=float(cnt),
            display=f"{cnt} finding{'s' if cnt != 1 else ''}",
            tone=_SEVERITY_TONE.get(sev, "neutral"),
        ))
    if not bars:
        bars.append(Bar(label="Confirmed", value=0.0, display="0 findings", tone="supported"))
    return BarChart(
        title=title,
        unit="confirmed findings",
        bars=tuple(bars),
        caption="Gate-certified confirmed findings grouped by technical severity.",
    )


def _domain_posture_chart(
    final_report: Mapping[str, Any],
    rows: Sequence[_FindingRow],
) -> RadarChart | BarChart:
    """Build a RadarChart when >=3 security domains have scores, else a compact HorizontalBar."""
    raw_domains = final_report.get("domain_posture") or final_report.get("security_domains")
    parsed_axes: list[RadarAxis] = []
    parsed_vals: list[float | None] = []
    parsed_disp: list[str] = []
    legend_rows: list[RadarLegendRow] = []

    radar_tracker = final_report.get("radar_tracker")
    if isinstance(radar_tracker, Mapping) and not raw_domains:
        rt_axes = radar_tracker.get("axes")
        if isinstance(rt_axes, Sequence) and not isinstance(rt_axes, (str, bytes)):
            seen_rt: set[str] = set()
            for idx, entry in enumerate(rt_axes):
                if not isinstance(entry, Mapping) or len(parsed_axes) >= 12:
                    continue
                label = _scrub_text(entry.get("label") or entry.get("domain_id") or f"Domain {idx + 1}", max_len=24)
                key = re.sub(r"[^a-zA-Z0-9_]+", "_", str(entry.get("key") or entry.get("domain_id") or label)).strip("_") or f"d{idx}"
                if key in seen_rt:
                    key = f"{key}_{idx}"
                seen_rt.add(key)
                series_map = entry.get("series") if isinstance(entry.get("series"), Mapping) else {}
                vc = series_map.get("verified_coverage") if isinstance(series_map.get("verified_coverage"), Mapping) else {}
                raw_score = vc.get("score")
                if raw_score is None:
                    for flat_key in ("posture_score", "score", "verified_coverage"):
                        cand_val = entry.get(flat_key)
                        if isinstance(cand_val, (int, float)) and not isinstance(cand_val, bool):
                            raw_score = cand_val
                            break
                if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool):
                    norm = float(raw_score) / 100.0 if float(raw_score) > 1.0 else float(raw_score)
                    clamped = max(0.0, min(1.0, norm))
                    parsed_vals.append(clamped)
                    parsed_disp.append(f"{round(clamped * 100)}%")
                else:
                    parsed_vals.append(None)
                    parsed_disp.append("N/A")
                parsed_axes.append(RadarAxis(label=label, key=key))
                legend_rows.append(RadarLegendRow(
                    kind="axis",
                    key=key,
                    label=label,
                    meaning=_scrub_text(entry.get("coverage_status") or f"Verified coverage for {label}", max_len=64),
                ))

    if isinstance(raw_domains, Sequence) and not isinstance(raw_domains, (str, bytes)):
        seen_keys: set[str] = set()
        for idx, entry in enumerate(raw_domains):
            if not isinstance(entry, Mapping) or len(parsed_axes) >= 8:
                continue
            label = _scrub_text(entry.get("label") or entry.get("domain_id") or f"Domain {idx + 1}", max_len=24)
            key = re.sub(r"[^a-z0-9_]+", "_", str(entry.get("domain_id") or label).lower()).strip("_") or f"d{idx}"
            if key in seen_keys:
                key = f"{key}_{idx}"
            seen_keys.add(key)
            raw_score = entry.get("score")
            if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool):
                clamped = max(0.0, min(1.0, float(raw_score)))
                parsed_vals.append(clamped)
                parsed_disp.append(f"{round(clamped * 100)}%")
            else:
                parsed_vals.append(None)
                parsed_disp.append("N/A")
            parsed_axes.append(RadarAxis(label=label, key=key))
            legend_rows.append(RadarLegendRow(
                kind="axis",
                key=key,
                label=label,
                meaning=_scrub_text(entry.get("summary") or f"Observed posture for {label}", max_len=64),
            ))

    if len(parsed_axes) >= 3 and any(v is not None for v in parsed_vals):
        return RadarChart(
            title="Security Domain Posture",
            axes=tuple(parsed_axes),
            series=(
                RadarSeries(
                    label="Observed Posture",
                    tone="supported",
                    values=tuple(parsed_vals),
                    displays=tuple(parsed_disp),
                ),
            ),
            scale_note="Normalized [0.0, 1.0] domain posture; unmeasured axes remain N/A.",
            caption="Domain-level posture derived from gate-certified review signals.",
            legend=tuple(legend_rows[:6]),
        )

    bucket_counts: Counter[str] = Counter()
    for r in rows:
        key_label = r.domain if r.domain != "general" else r.cwe
        bucket_counts[key_label] += 1

    if len(bucket_counts) >= 3:
        top_domains = sorted(bucket_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:6]
        max_cnt = max(cnt for _, cnt in top_domains) or 1
        axes: list[RadarAxis] = []
        vals: list[float | None] = []
        disps: list[str] = []
        for idx, (dom_label, cnt) in enumerate(top_domains):
            clean_lbl = _scrub_text(dom_label, max_len=22)
            axis_key = f"dom_{idx + 1}"
            axes.append(RadarAxis(label=clean_lbl, key=axis_key))
            ratio = round(max(0.0, min(1.0, 1.0 - (cnt / (max_cnt + 1)))), 2)
            vals.append(ratio)
            disps.append(f"{cnt} defect{'s' if cnt != 1 else ''}")
        return RadarChart(
            title="Weakness Domain Posture Index",
            axes=tuple(axes),
            series=(
                RadarSeries(
                    label="Relative Assurance",
                    tone="insufficient_evidence",
                    values=tuple(vals),
                    displays=tuple(disps),
                ),
            ),
            scale_note="Higher values indicate lower confirmed defect concentration on [0.0, 1.0].",
            caption="Relative domain posture across the top weakness categories in this run.",
        )

    bars = tuple(
        Bar(
            label=_scrub_text(lbl, max_len=28),
            value=float(cnt),
            display=f"{cnt} finding{'s' if cnt != 1 else ''}",
            tone="contradicted" if cnt > 1 else "insufficient_evidence",
        )
        for lbl, cnt in sorted(bucket_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:6]
    ) or (
        Bar(label="No Confirmed Weaknesses", value=0.0, display="0 findings", tone="supported"),
    )
    return BarChart(
        title="Weakness Category Breakdown",
        unit="confirmed findings",
        bars=bars,
        caption="Confirmed defect concentration by weakness category.",
    )


@dataclass(frozen=True, slots=True)
class _ReportMeta:
    run_id: str
    snapshot_head: str
    gate_verdict: str
    confirmed_cnt: int
    backlog_cnt: int
    withheld_cnt: int
    total_packages: int
    backlog_items: tuple[Mapping[str, Any], ...]


def _extract_report_meta(
    final_report: Mapping[str, Any],
    rows: Sequence[_FindingRow],
    *,
    ledger_head: str | None = None,
) -> _ReportMeta:
    run_id = _scrub_text(
        final_report.get("run_id") or final_report.get("application_run_id") or "unknown-run",
        max_len=64,
    ) or "unknown-run"
    prov = final_report.get("provenance") if isinstance(final_report.get("provenance"), Mapping) else {}
    snapshot_head = _short_digest(
        ledger_head or prov.get("ledger_head_sha256") or final_report.get("target_snapshot_sha256") or "unavailable"
    )
    status_map = final_report.get("status") if isinstance(final_report.get("status"), Mapping) else {}
    gate_verdict = _scrub_text(
        status_map.get("publication") or final_report.get("gate_terminal_status") or "COMPLETED",
        max_len=36,
    ) or "COMPLETED"
    raw_backlog_seq = (
        final_report.get("verification_backlog")
        if final_report.get("verification_backlog") is not None
        else (final_report.get("backlog") or ())
    )
    backlog_items = tuple(b for b in raw_backlog_seq if isinstance(b, Mapping))
    summary = final_report.get("summary") if isinstance(final_report.get("summary"), Mapping) else {}
    pkg_counts = summary.get("package_counts") if isinstance(summary.get("package_counts"), Mapping) else {}

    if "publishable" in pkg_counts:
        confirmed_cnt = int(pkg_counts.get("publishable") or 0)
    else:
        confirmed_cnt = int(summary.get("confirmed_finding_count", len(rows)) or 0)
    if "verification_backlog" in pkg_counts:
        backlog_cnt = int(pkg_counts.get("verification_backlog") or 0)
    else:
        backlog_cnt = int(summary.get("supported_backlog_count", len(backlog_items)) or 0)
    if "withheld" in pkg_counts:
        withheld_cnt = int(pkg_counts.get("withheld") or 0)
    else:
        withheld_cnt = int(summary.get("withheld_count", len(final_report.get("withheld") or ())) or 0)
    if "total" in pkg_counts:
        total_packages = int(pkg_counts.get("total") or 0)
    else:
        total_packages = int(summary.get("total_finding_packages", confirmed_cnt + backlog_cnt + withheld_cnt) or 0)

    return _ReportMeta(
        run_id=run_id,
        snapshot_head=snapshot_head,
        gate_verdict=gate_verdict,
        confirmed_cnt=confirmed_cnt,
        backlog_cnt=backlog_cnt,
        withheld_cnt=withheld_cnt,
        total_packages=total_packages,
        backlog_items=backlog_items,
    )


def _summarize_gaps(final_report: Mapping[str, Any]) -> tuple[int, tuple[tuple[str, str, int, str], ...]]:
    """Group named gaps by (source, category) so 100+ raw gap records become a compact summary."""
    raw_gaps = [g for g in (final_report.get("named_coverage_gaps") or ()) if isinstance(g, Mapping)]
    grouped: dict[tuple[str, str], tuple[int, str]] = {}
    if raw_gaps:
        for gap in raw_gaps:
            src = _scrub_text(gap.get("source") or gap.get("affected_scope") or "pipeline", max_len=36) or "pipeline"
            raw_cat = str(gap.get("category") or "")
            raw_text = str(gap.get("gap") or gap.get("statement") or raw_cat or "unspecified_gap")
            head = raw_cat or raw_text.split(":", 1)[0].strip()
            category = _scrub_text(head or "coverage_gap", max_len=44) or "coverage_gap"
            sample = _scrub_text(raw_text, max_len=84)
            key = (src, category)
            prev_cnt, prev_sample = grouped.get(key, (0, sample))
            grouped[key] = (prev_cnt + 1, prev_sample)
        total_count = len(raw_gaps)
    else:
        lims = [
            row for row in (final_report.get("limitations") or ())
            if isinstance(row, Mapping) and row.get("kind") in ("gap", "not_run")
        ]
        total_count = 0
        for row in lims:
            src = _scrub_text(row.get("source") or "pipeline", max_len=36) or "pipeline"
            cat = _scrub_text(row.get("limitation_id") or row.get("kind") or "coverage_gap", max_len=44) or "coverage_gap"
            cnt = max(int(row.get("count", 1) or 1), 1)
            sample = _scrub_text(row.get("statement") or cat, max_len=84)
            total_count += cnt
            key = (src, cat)
            prev_cnt, prev_sample = grouped.get(key, (0, sample))
            grouped[key] = (prev_cnt + cnt, prev_sample)

    ordered = sorted(grouped.items(), key=lambda kv: (-kv[1][0], kv[0][0], kv[0][1]))
    summary_rows = tuple(
        (src, cat, cnt, sample)
        for (src, cat), (cnt, sample) in ordered[:10]
    )
    return total_count, summary_rows


def _gate_status_badge_and_tone(final_report: Mapping[str, Any], confirmed_count: int) -> tuple[str, str]:
    status_map = final_report.get("status") if isinstance(final_report.get("status"), Mapping) else {}
    gate_status = str(status_map.get("review") or status_map.get("publication") or final_report.get("gate_terminal_status") or "")
    total_gaps, _ = _summarize_gaps(final_report)
    if confirmed_count > 0:
        badge = "CONFIRMED FINDINGS"
        tone = "confirmed"
    elif gate_status in ("COMPLETED_WITH_GAPS", "DEGRADED") or total_gaps > 0:
        badge = "COMPLETED WITH GAPS"
        tone = "coverage_gap"
    else:
        badge = "GATE CERTIFIED"
        tone = "supported"
    if tone not in STATUS_TONES:
        tone = "neutral"
    return badge, tone


def _count_fix_states(final_report: Mapping[str, Any], rows: Sequence[_FindingRow]) -> tuple[int, int, int]:
    val_summary = (final_report.get("remediation_validation") or {}).get("summary") or {}
    if isinstance(val_summary, Mapping) and val_summary:
        build_checked = int(val_summary.get("build_checked", 0) or 0)
        static_checked = int(val_summary.get("static_checked", 0) or 0)
        rejected_unchecked = (
            int(val_summary.get("rejected", 0) or 0)
            + int(val_summary.get("inconclusive", 0) or 0)
            + int(val_summary.get("manual_validation_required", 0) or 0)
            + int(val_summary.get("capped", 0) or 0)
            + int(val_summary.get("not_launched", 0) or 0)
        )
        return build_checked, static_checked, rejected_unchecked
    bc = sum(1 for r in rows if r.fix_bucket == "build_checked")
    sc = sum(1 for r in rows if r.fix_bucket == "static_checked")
    ru = sum(1 for r in rows if r.fix_bucket != "build_checked")
    return bc, sc, ru


def _count_pocs(final_report: Mapping[str, Any], rows: Sequence[_FindingRow]) -> int:
    poc_items = (final_report.get("poc_outcomes") or {}).get("items")
    if isinstance(poc_items, Sequence) and not isinstance(poc_items, (str, bytes)) and poc_items:
        return sum(
            1
            for item in poc_items
            if isinstance(item, Mapping)
            and str(item.get("status") or "").strip().lower() in _POC_COMPILED_STATES
        )
    return sum(1 for r in rows if r.poc_compiled)


def _build_candidate_a_blocks(
    final_report: Mapping[str, Any],
    rows: Sequence[_FindingRow],
) -> tuple[Any, ...]:
    """Candidate A: Compact Posture & Priority Action Brief (~4-6 pages)."""
    meta = _extract_report_meta(final_report, rows)
    confirmed_cnt = meta.confirmed_cnt
    high_crit_cnt = sum(1 for r in rows if r.severity in ("critical", "high"))
    build_checked, _static_checked, _unchecked = _count_fix_states(final_report, rows)
    poc_cnt = _count_pocs(final_report, rows)
    total_gaps, gap_groups = _summarize_gaps(final_report)
    gate_verdict = meta.gate_verdict
    backlog_cnt = meta.backlog_cnt

    posture_summary = (
        f"Publication gate completed with status {gate_verdict}: {confirmed_cnt} confirmed "
        f"publishable finding(s) ({high_crit_cnt} high/critical), {build_checked} build-checked "
        f"remediation patch(es), {poc_cnt} compiled PoC artifact(s), and {total_gaps} named coverage gap(s)."
    )

    blocks: list[Any] = [
        Heading(
            level=1,
            text="1. Posture Overview and Key Metrics",
            anchor="cand-a-posture",
            subtitle="Gate-certified posture snapshot and priority remediation indicators",
        ),
        Box(
            kind=BoxKind.VERIFICATION,
            title="Publication Posture Summary",
            chip="POSTURE",
            items=(
                Para(_scrub_text(posture_summary, max_len=320)),
                Fields(rows=(
                    Field("Target Snapshot", meta.snapshot_head),
                    Field("Gate Verdict", gate_verdict),
                    Field("Supported Backlog", str(backlog_cnt)),
                )),
            ),
        ),
        Stats(items=(
            Stat("Publication Verdict", gate_verdict.replace("_", " "), tone="coverage_gap" if total_gaps else "supported"),
            Stat("Confirmed Findings", str(confirmed_cnt), tone="confirmed" if confirmed_cnt else "supported"),
            Stat("High / Critical", str(high_crit_cnt), tone="contradicted" if high_crit_cnt else "supported"),
            Stat("Build-Checked Fixes", str(build_checked), tone="supported" if build_checked else "neutral"),
            Stat("PoC Artifacts", str(poc_cnt), tone="confirmed" if poc_cnt else "neutral"),
            Stat("Open Coverage Gaps", str(total_gaps), tone="coverage_gap" if total_gaps else "supported"),
        )),
        Heading(
            level=1,
            text="2. Severity and Security Domain Distribution",
            anchor="cand-a-charts",
            subtitle="Confirmed severity distribution paired with domain posture",
        ),
        _severity_bar_chart(rows, title="Confirmed Findings by Technical Severity"),
        _domain_posture_chart(final_report, rows),
        Heading(
            level=1,
            text="3. Priority Remediation Action Table",
            anchor="cand-a-actions",
            subtitle="Ordered by technical severity and ship-block disposition",
        ),
    ]

    if rows:
        action_rows = tuple(
            (
                Cell(str(r.rank), mono=True),
                Cell(r.short_id, mono=True),
                Cell(r.title),
                Cell("", badge=_SEVERITY_TONE.get(r.severity), badge_label=r.severity.upper()),
                Cell(r.cwe, mono=True),
                Cell(r.primary_location, mono=True),
                Cell(r.fix_label),
                Cell(r.ship_block_status.replace("_", " ")),
            )
            for r in rows[:25]
        )
        blocks.append(Box(
            kind=BoxKind.RESULT,
            title=f"Priority Action Queue ({len(rows)} Confirmed)",
            chip="ACTIONS",
            items=(
                Table(
                    headers=("Rank", "Finding ID", "Title", "Severity", "CWE", "Primary Location", "Fix Status", "Disposition"),
                    rows=action_rows,
                    widths=(0.06, 0.13, 0.22, 0.09, 0.10, 0.18, 0.11, 0.11),
                ),
            ),
        ))
    else:
        blocks.append(Note(
            "No confirmed publishable findings were certified in this run. "
            "Missing or skipped producer coverage remains recorded below and does not prove absence of defects."
        ))

    blocks.append(Heading(
        level=1,
        text="4. Representative Defect Flow Snapshot",
        anchor="cand-a-flow",
        subtitle="Top-ranked defect mechanism and remediation boundary",
    ))
    if rows:
        blocks.append(_build_finding_flow_diagram(rows[0], index_prefix="ca_f1"))
    else:
        blocks.append(Note("No confirmed defect flow is present in this gate snapshot."))

    blocks.append(Heading(
        level=1,
        text="5. Coverage and Qualification Summary",
        anchor="cand-a-coverage",
        subtitle="Grouped producer coverage gaps and non-confirmed qualification counts",
    ))
    if gap_groups:
        gap_table_rows = tuple(
            (
                Cell(src, mono=True),
                Cell(cat, mono=True),
                Cell(str(cnt), mono=True, badge="coverage_gap", badge_label="gap"),
                Cell(sample),
            )
            for src, cat, cnt, sample in gap_groups
        )
        blocks.append(Box(
            kind=BoxKind.GAP,
            title=f"Coverage Gap Summary ({total_gaps} Total Across {len(gap_groups)} Group(s))",
            chip="COVERAGE",
            items=(
                Table(
                    headers=("Producer / Source", "Gap Category", "Count", "Representative Condition"),
                    rows=gap_table_rows,
                    widths=(0.24, 0.24, 0.10, 0.42),
                ),
            ),
        ))
    else:
        blocks.append(Box(
            kind=BoxKind.VERIFICATION,
            title="Coverage Status",
            chip="COVERAGE",
            items=(Para("Zero named producer coverage gaps were recorded in the gate-certified report."),),
        ))

    return tuple(blocks)


def _build_candidate_b_blocks(
    final_report: Mapping[str, Any],
    rows: Sequence[_FindingRow],
) -> tuple[Any, ...]:
    """Candidate B: Visual Triage & Remediation Matrix (~6-9 pages)."""
    meta = _extract_report_meta(final_report, rows)
    confirmed_cnt = meta.confirmed_cnt
    backlog_cnt = meta.backlog_cnt
    build_checked, static_checked, unchecked_cnt = _count_fix_states(final_report, rows)
    poc_cnt = _count_pocs(final_report, rows)

    file_counter: Counter[str] = Counter()
    file_severities: dict[str, Counter[str]] = {}
    file_fixes: dict[str, int] = {}
    for r in rows:
        targets = r.files if r.files else (r.primary_location.split(":", 1)[0],)
        for path in targets:
            if not path:
                continue
            file_counter[path] += 1
            file_severities.setdefault(path, Counter())[r.severity] += 1
            if r.fix_bucket == "build_checked":
                file_fixes[path] = file_fixes.get(path, 0) + 1

    affected_file_cnt = len(file_counter)

    fix_bars: list[Bar] = []
    for sev in _SEVERITY_ORDER:
        sev_rows = [r for r in rows if r.severity == sev]
        if not sev_rows and sev == "unrated":
            continue
        bc = sum(1 for r in sev_rows if r.fix_bucket == "build_checked")
        sc = sum(1 for r in sev_rows if r.fix_bucket == "static_checked")
        other = len(sev_rows) - bc - sc
        fix_bars.append(Bar(
            label=f"{sev.capitalize()} ({len(sev_rows)})",
            value=float(len(sev_rows)),
            display=f"{bc} build-checked | {sc} static | {other} pending",
            tone="supported" if (sev_rows and bc == len(sev_rows)) else _SEVERITY_TONE.get(sev, "neutral"),
        ))
    if not fix_bars:
        fix_bars.append(Bar(label="All Severities (0)", value=0.0, display="0 findings", tone="supported"))

    hotspot_items = sorted(file_counter.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
    hotspot_bars = tuple(
        Bar(
            label=_scrub_text(path, max_len=42),
            value=float(cnt),
            display=f"{cnt} defect{'s' if cnt != 1 else ''} ({file_fixes.get(path, 0)} build-checked)",
            tone="contradicted" if cnt >= 2 else "insufficient_evidence",
        )
        for path, cnt in hotspot_items
    ) or (
        Bar(label="No Affected Source Paths", value=0.0, display="0 defects", tone="supported"),
    )

    blocks: list[Any] = [
        Heading(
            level=1,
            text="1. Triage Overview and Remediation Readiness",
            anchor="cand-b-overview",
            subtitle="Patch validation readiness, affected file concentration, and backlog scope",
        ),
        Box(
            kind=BoxKind.CLAIM,
            title="Remediation Triage Summary",
            chip="TRIAGE",
            items=(
                Para(_scrub_text(
                    f"Triage matrix covers {confirmed_cnt} confirmed defect(s) across {affected_file_cnt} "
                    f"source path(s): {build_checked} build-checked patch(es), {static_checked} static-checked, "
                    f"{unchecked_cnt} unchecked/rejected/manual, and {backlog_cnt} supported backlog lead(s).",
                    max_len=320,
                )),
            ),
        ),
        Stats(items=(
            Stat("Confirmed", str(confirmed_cnt), tone="confirmed" if confirmed_cnt else "supported"),
            Stat("Build-Checked Fixes", str(build_checked), tone="supported" if build_checked else "neutral"),
            Stat("Unchecked / Rejected", str(unchecked_cnt), tone="insufficient_evidence" if unchecked_cnt else "supported"),
            Stat("Affected Files", str(affected_file_cnt), tone="neutral"),
            Stat("PoC Artifacts", str(poc_cnt), tone="confirmed" if poc_cnt else "neutral"),
            Stat("Backlog Supported", str(backlog_cnt), tone="proposed" if backlog_cnt else "neutral"),
        )),
        Heading(
            level=1,
            text="2. Fix Readiness by Severity and Hotspot Concentration",
            anchor="cand-b-charts",
            subtitle="Remediation verification breakdown paired with top affected paths",
        ),
        BarChart(
            title="Fix Readiness Breakdown by Severity",
            unit="confirmed findings",
            bars=tuple(fix_bars),
            caption="Each severity bar reports build-checked, static-checked, and pending/rejected counts.",
        ),
        BarChart(
            title="Hotspot File Concentration",
            unit="defects per path",
            bars=hotspot_bars,
            caption="Top source paths ranked by confirmed defect count.",
        ),
        Heading(
            level=1,
            text="3. Component Hotspots and Confirmed Defect Matrix",
            anchor="cand-b-matrix",
            subtitle="Hotspot concentration table followed by the complete defect and patch matrix",
        ),
    ]

    if hotspot_items:
        hotspot_table_rows = tuple(
            (
                Cell(_scrub_text(path, max_len=56), mono=True),
                Cell(str(cnt), mono=True),
                Cell(str(file_severities[path].get("critical", 0) + file_severities[path].get("high", 0))),
                Cell(str(file_fixes.get(path, 0))),
            )
            for path, cnt in hotspot_items
        )
        blocks.append(Box(
            kind=BoxKind.EVIDENCE,
            title="File and Component Hotspot Summary",
            chip="HOTSPOTS",
            items=(
                Table(
                    headers=("Source Path", "Confirmed Defects", "High / Critical", "Build-Checked Fixes"),
                    rows=hotspot_table_rows,
                    widths=(0.48, 0.18, 0.17, 0.17),
                ),
            ),
        ))

    if rows:
        matrix_rows = tuple(
            (
                Cell(r.short_id, mono=True, badge=_SEVERITY_TONE.get(r.severity), badge_label=r.severity.upper()),
                Cell(r.primary_location, mono=True),
                Cell(f"{r.cwe} / {r.domain}", mono=True),
                Cell(_scrub_text(r.violated_invariant, max_len=84)),
                Cell(r.fix_label),
                Cell(r.poc_status),
            )
            for r in rows[:30]
        )
        blocks.append(Box(
            kind=BoxKind.RESULT,
            title=f"Complete Confirmed Defect and Patch Matrix ({len(rows)} Item(s))",
            chip="MATRIX",
            items=(
                Table(
                    headers=("Finding (Sev)", "Primary Location", "CWE / Domain", "Violated Invariant Summary", "Remediation", "PoC"),
                    rows=matrix_rows,
                    widths=(0.15, 0.19, 0.14, 0.30, 0.12, 0.10),
                ),
            ),
        ))
    else:
        blocks.append(Note("Zero confirmed findings to tabulate in the defect and patch matrix."))

    blocks.append(Heading(
        level=1,
        text="4. Top Defect Code-Flow Visuals",
        anchor="cand-b-flows",
        subtitle="Up to three highest-severity confirmed defect chains",
    ))
    if rows:
        for idx, r in enumerate(rows[:3], start=1):
            blocks.append(_build_finding_flow_diagram(r, index_prefix=f"cb_f{idx}"))
    else:
        blocks.append(Note("No confirmed defect code flows were produced in this run."))

    blocks.append(Heading(
        level=1,
        text="5. Supported Backlog and Residual Qualification",
        anchor="cand-b-backlog",
        subtitle="Non-confirmed leads retained for follow-up verification",
    ))
    raw_backlog = list(meta.backlog_items)
    if raw_backlog:
        backlog_rows = tuple(
            (
                Cell(_short_id(b.get("finding_package_id") or b.get("claim_id")), mono=True),
                Cell(_scrub_text(b.get("title") or "Supported Lead", max_len=68)),
                Cell(_scrub_text(b.get("lane") or "lead", max_len=16), mono=True),
                Cell(_scrub_text(", ".join(str(p) for p in (b.get("missing_predicates") or ())[:3]) or "verification_pending", max_len=64)),
            )
            for b in raw_backlog[:15]
        )
        blocks.append(Box(
            kind=BoxKind.FEEDBACK,
            title=f"Supported Backlog Summary ({len(raw_backlog)} Total)",
            chip="BACKLOG",
            items=(
                Table(
                    headers=("Lead ID", "Title", "Lane", "Remaining Verification Predicate(s)"),
                    rows=backlog_rows,
                    widths=(0.16, 0.38, 0.12, 0.34),
                ),
            ),
        ))
    else:
        blocks.append(Box(
            kind=BoxKind.FEEDBACK,
            title="Supported Backlog Summary",
            chip="BACKLOG",
            items=(Para("Zero supported backlog leads remain outside the confirmed set."),),
        ))

    return tuple(blocks)



def _build_candidate_c_blocks(
    final_report: Mapping[str, Any],
    rows: Sequence[_FindingRow],
) -> tuple[Any, ...]:
    """Candidate C: Assurance Funnel & Coverage Summary (~6-9 pages)."""
    meta = _extract_report_meta(final_report, rows)
    confirmed_cnt = meta.confirmed_cnt
    backlog_cnt = meta.backlog_cnt
    withheld_cnt = meta.withheld_cnt
    total_packages = meta.total_packages
    build_checked, static_checked, _unchecked = _count_fix_states(final_report, rows)
    verified_remedies = build_checked + static_checked
    poc_cnt = _count_pocs(final_report, rows)
    total_gaps, gap_groups = _summarize_gaps(final_report)
    gate_verdict = meta.gate_verdict

    funnel_bars = (
        Bar("Total Gate Packages", float(total_packages), f"{total_packages} package(s)", tone="neutral"),
        Bar("Confirmed Publishable", float(confirmed_cnt), f"{confirmed_cnt} confirmed", tone="confirmed" if confirmed_cnt else "supported"),
        Bar("Build-Checked Fix", float(build_checked), f"{build_checked} patch(es)", tone="supported" if build_checked else "neutral"),
        Bar("Generated PoC", float(poc_cnt), f"{poc_cnt} artifact(s)", tone="confirmed" if poc_cnt else "neutral"),
        Bar("Supported Backlog", float(backlog_cnt), f"{backlog_cnt} lead(s)", tone="proposed" if backlog_cnt else "neutral"),
    )

    boundary_rows = (
        (
            Cell("Confirmed Findings"),
            Cell(str(confirmed_cnt), mono=True),
            Cell("", badge="confirmed" if confirmed_cnt else "supported", badge_label="Publishable"),
            Cell("Gate-certified defects with qualifying evidence and verification metadata."),
        ),
        (
            Cell("Supported Backlog"),
            Cell(str(backlog_cnt), mono=True),
            Cell("", badge="proposed" if backlog_cnt else "neutral", badge_label="Retained Lead"),
            Cell("Credible leads awaiting distinct-verifier or predicate completion."),
        ),
        (
            Cell("Withheld Packages"),
            Cell(str(withheld_cnt), mono=True),
            Cell("", badge="not_reachable" if withheld_cnt else "neutral", badge_label="Excluded"),
            Cell("Contradicted, duplicate, out-of-scope, or unverified packages held at gate."),
        ),
        (
            Cell("Named Coverage Gaps"),
            Cell(str(total_gaps), mono=True),
            Cell("", badge="coverage_gap" if total_gaps else "supported", badge_label="Coverage Gap" if total_gaps else "Clean"),
            Cell("Producer skips, timeouts, or bounded omissions; never treated as clean coverage."),
        ),
    )

    blocks: list[Any] = [
        Heading(
            level=1,
            text="1. Gate Certification and Assurance Indicators",
            anchor="cand-c-gate",
            subtitle="Publication gate boundary, verification funnel totals, and coverage accounting",
        ),
        Box(
            kind=BoxKind.PROVENANCE,
            title="Publication Gate Certification",
            chip="ASSURANCE",
            items=(
                Para(_scrub_text(
                    f"Gate evaluated {total_packages} finding package(s) under verdict {gate_verdict}: "
                    f"{confirmed_cnt} confirmed publishable, {backlog_cnt} supported backlog, "
                    f"{withheld_cnt} withheld, {verified_remedies} verified remedy artifact(s), "
                    f"and {total_gaps} named coverage gap(s).",
                    max_len=320,
                )),
                Fields(rows=(
                    Field("Schema", _scrub_text(final_report.get("schema") or "appsec-review/final-report/4", max_len=44)),
                    Field("Target Snapshot", meta.snapshot_head),
                    Field("Gate Status", gate_verdict),
                )),
            ),
        ),
        Stats(items=(
            Stat("Gate Status", gate_verdict.replace("_", " "), tone="coverage_gap" if total_gaps else "supported"),
            Stat("Confirmed Publishable", str(confirmed_cnt), tone="confirmed" if confirmed_cnt else "supported"),
            Stat("Backlog Supported", str(backlog_cnt), tone="proposed" if backlog_cnt else "neutral"),
            Stat("Withheld", str(withheld_cnt), tone="neutral"),
            Stat("Verified Remedies", str(verified_remedies), tone="supported" if verified_remedies else "neutral"),
            Stat("Coverage Gaps", str(total_gaps), tone="coverage_gap" if total_gaps else "supported"),
        )),
        Heading(
            level=1,
            text="2. Review Qualification Funnel and Severity Profile",
            anchor="cand-c-funnel",
            subtitle="Progression from candidate gate packages to verified remedies and PoCs",
        ),
        BarChart(
            title="Review Qualification Funnel",
            unit="finding packages",
            bars=funnel_bars,
            caption="Gate qualification progression across total packages, confirmed defects, remedies, PoCs, and backlog.",
        ),
        _severity_bar_chart(rows, title="Confirmed Defect Severity Distribution"),
        Heading(
            level=1,
            text="3. Qualification Boundary and Confirmed Defect Ledger",
            anchor="cand-c-ledger",
            subtitle="Gate disposition classes paired with evidence-qualification ledger",
        ),
        Box(
            kind=BoxKind.VERIFICATION,
            title="Publication Gate and Qualification Boundary Summary",
            chip="BOUNDARY",
            items=(
                Table(
                    headers=("Disposition Class", "Count", "Gate Treatment", "Qualification Rule"),
                    rows=boundary_rows,
                    widths=(0.23, 0.09, 0.20, 0.48),
                ),
            ),
        ),
    ]

    if rows:
        ledger_rows = tuple(
            (
                Cell("", badge=_SEVERITY_TONE.get(r.severity), badge_label=r.severity.upper()),
                Cell(f"{r.short_id}: {r.title}"),
                Cell(r.primary_location, mono=True),
                Cell(r.qualification_summary),
                Cell(f"{r.fix_label} | PoC: {r.poc_status}"),
            )
            for r in rows[:25]
        )
        blocks.append(Box(
            kind=BoxKind.RESULT,
            title=f"Confirmed Defect Qualification Ledger ({len(rows)} Confirmed)",
            chip="LEDGER",
            items=(
                Table(
                    headers=("Severity", "Finding", "Primary Location", "Evidence Qualification", "Remediation & PoC"),
                    rows=ledger_rows,
                    widths=(0.11, 0.27, 0.20, 0.22, 0.20),
                ),
            ),
        ))
    else:
        blocks.append(Note("No confirmed defects appear in the qualification ledger for this run."))

    blocks.append(Heading(
        level=1,
        text="4. Representative High-Impact Code-Flow Diagram",
        anchor="cand-c-flow",
        subtitle="Highest-impact defect chain and verification boundary",
    ))
    if rows:
        chosen = next((r for r in rows if r.chain_elevated), rows[0])
        blocks.append(_build_finding_flow_diagram(chosen, index_prefix="cc_f1"))
    else:
        blocks.append(Note("No high-impact confirmed defect flow is present in this gate snapshot."))

    blocks.append(Heading(
        level=1,
        text="5. Producer Coverage and Gap Category Breakdown",
        anchor="cand-c-coverage",
        subtitle="Bounded accounting of producer skips, omissions, and coverage limits",
    ))
    if gap_groups:
        gap_bars = tuple(
            Bar(
                label=f"{src} / {cat}"[:42],
                value=float(cnt),
                display=f"{cnt} gap{'s' if cnt != 1 else ''}",
                tone="coverage_gap",
            )
            for src, cat, cnt, _sample in gap_groups[:8]
        )
        blocks.append(BarChart(
            title="Coverage Gaps by Producer and Category",
            unit="named gaps",
            bars=gap_bars,
            caption="Aggregated producer coverage gaps; missing coverage is never treated as proof of cleanliness.",
        ))
        gap_rows = tuple(
            (
                Cell(src, mono=True),
                Cell(cat, mono=True),
                Cell(str(cnt), mono=True, badge="coverage_gap", badge_label="gap"),
                Cell(sample),
            )
            for src, cat, cnt, sample in gap_groups
        )
        blocks.append(Box(
            kind=BoxKind.GAP,
            title="Producer Coverage Gap Ledger",
            chip="GAPS",
            items=(
                Table(
                    headers=("Producer", "Gap Category", "Count", "Representative Summary"),
                    rows=gap_rows,
                    widths=(0.24, 0.24, 0.10, 0.42),
                ),
            ),
        ))
    else:
        blocks.append(Box(
            kind=BoxKind.VERIFICATION,
            title="Producer Coverage Accounting",
            chip="COVERAGE",
            items=(Para("All upstream producers completed without named coverage gaps."),),
        ))

    return tuple(blocks)


def build_executive_candidate_document(
    candidate_id: str,
    final_report: Mapping[str, Any],
    *,
    dossiers: Sequence[Any] = (),
    source_date_epoch: int = 0,
    ledger_head: str | None = None,
) -> ReportDocument:
    """Build a deterministic :class:`ReportDocument` for Candidate A, B, or C."""
    cid = normalize_candidate_id(candidate_id)
    if not isinstance(final_report, Mapping):
        raise ValueError("final_report must be a mapping")

    rows = _extract_findings(final_report, dossiers)
    meta = _extract_report_meta(final_report, rows, ledger_head=ledger_head)
    run_id = meta.run_id
    snapshot_head = meta.snapshot_head
    confirmed_cnt = meta.confirmed_cnt
    badge, tone = _gate_status_badge_and_tone(final_report, confirmed_cnt)

    if cid == "a":
        blocks = _build_candidate_a_blocks(final_report, rows)
    elif cid == "b":
        blocks = _build_candidate_b_blocks(final_report, rows)
    else:
        blocks = _build_candidate_c_blocks(final_report, rows)

    total_gaps, gap_groups = _summarize_gaps(final_report)
    concise_gaps = tuple(
        f"{src} ({cat}): {cnt} occurrence(s) \u2014 {sample}"
        for src, cat, cnt, sample in gap_groups[:6]
    )
    if total_gaps > sum(cnt for _s, _c, cnt, _sm in gap_groups[:6]):
        rem = total_gaps - sum(cnt for _s, _c, cnt, _sm in gap_groups[:6])
        concise_gaps = (*concise_gaps, f"additional grouped coverage gaps: {rem} occurrence(s)")

    return Document(
        title=CANDIDATE_TITLES[cid],
        run_id=run_id,
        subtitle=CANDIDATE_SUBTITLES[cid],
        status_badge=badge,
        status_tone=tone,
        source_date_epoch=int(source_date_epoch),
        ledger_head=snapshot_head,
        blocks=blocks,
        named_gaps=concise_gaps,
        renderer=CANDIDATE_RENDERER,
        head_label="target snapshot",
    )


def _md_escape_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _render_candidate_markdown_item(item: Any) -> list[str]:
    lines: list[str] = []
    if isinstance(item, Para):
        lines.append(item.text)
        lines.append("")
    elif isinstance(item, Note):
        lines.append(f"> **NOTE:** {item.text}")
        lines.append("")
    elif isinstance(item, Fields):
        for f in item.rows:
            val = f"`{f.value}`" if f.mono else f.value
            lines.append(f"- **{f.label}:** {val}")
        lines.append("")
    elif isinstance(item, Bullets):
        for b in item.items:
            lines.append(f"- {b}")
        lines.append("")
    elif isinstance(item, Table):
        headers = " | ".join(_md_escape_cell(h) for h in item.headers)
        sep = " | ".join("---" for _ in item.headers)
        lines.append(f"| {headers} |")
        lines.append(f"| {sep} |")
        for row in item.rows:
            cells = []
            for c in row:
                txt = _md_escape_cell(c.text)
                if c.mono and txt:
                    txt = f"`{txt}`"
                if c.badge:
                    b_lbl = _md_escape_cell(c.badge_label or c.badge)
                    txt = f"{txt} [{b_lbl}]".strip() if txt else f"**{b_lbl}**"
                cells.append(txt)
            lines.append(f"| {' | '.join(cells)} |")
        lines.append("")
    return lines


def render_executive_candidate_markdown(doc: ReportDocument) -> str:
    """Render a candidate :class:`ReportDocument` to deterministic UTF-8 Markdown."""
    lines: list[str] = [
        f"# {doc.title}",
        "",
        f"*{doc.subtitle}*",
        "",
        f"- **Run ID:** `{doc.run_id}`",
        f"- **Status:** `{doc.status_badge}`",
        f"- **{doc.head_label.title()}:** `{doc.ledger_head}`",
        "",
    ]

    for block in doc.blocks:
        if isinstance(block, Heading):
            prefix = "#" * min(max(block.level + 1, 2), 4)
            lines.append(f"{prefix} {block.text}")
            if block.subtitle:
                lines.append(f"*{block.subtitle}*")
            lines.append("")
        elif isinstance(block, Stats):
            lines.append("| Metric | Value |")
            lines.append("| --- | --- |")
            for st in block.items:
                lines.append(f"| {_md_escape_cell(st.label)} | **{_md_escape_cell(st.value)}** |")
            lines.append("")
        elif isinstance(block, BarChart):
            lines.append(f"### {block.title} ({block.unit})")
            lines.append("")
            lines.append("| Category | Metric | Value |")
            lines.append("| --- | --- | --- |")
            for bar in block.bars:
                lines.append(f"| {_md_escape_cell(bar.label)} | {_md_escape_cell(bar.display)} | {bar.value:g} |")
            if block.caption:
                lines.append("")
                lines.append(f"*{block.caption}*")
            lines.append("")
        elif isinstance(block, RadarChart):
            lines.append(f"### {block.title}")
            lines.append("")
            lines.append("| Axis | Score | Summary |")
            lines.append("| --- | --- | --- |")
            series = block.series[0] if block.series else None
            for idx, axis in enumerate(block.axes):
                val = series.values[idx] if series and idx < len(series.values) else None
                disp = series.displays[idx] if series and series.displays and idx < len(series.displays) else (
                    f"{val:.2f}" if val is not None else "N/A"
                )
                score_str = f"{val:.2f}" if val is not None else "N/A"
                lines.append(f"| {_md_escape_cell(axis.label)} | {score_str} | {_md_escape_cell(disp)} |")
            if block.scale_note:
                lines.append("")
                lines.append(f"*{block.scale_note}*")
            lines.append("")
        elif isinstance(block, FlowDiagram):
            if block.caption:
                lines.append(f"**{block.caption}**")
                lines.append("")
            lines.append("```mermaid")
            lines.append(to_mermaid(block).rstrip())
            lines.append("```")
            lines.append("")
        elif isinstance(block, Box):
            chip = block.chip or block.kind.value.upper()
            lines.append(f"### [{chip}] {block.title}")
            lines.append("")
            for item in block.items:
                lines.extend(_render_candidate_markdown_item(item))
        elif isinstance(block, (Para, Note)):
            lines.extend(_render_candidate_markdown_item(block))

    rendered = "\n".join(lines).rstrip() + "\n"
    assert_candidate_output_clean(rendered, label=f"{doc.title} markdown")
    return rendered


def render_executive_candidate_html(doc: ReportDocument) -> str:
    """Render a candidate :class:`ReportDocument` to deterministic self-contained HTML."""
    rendered = render_html(doc)
    assert_candidate_output_clean(rendered, label=f"{doc.title} html")
    return rendered


def render_executive_candidate_latex(
    doc: ReportDocument,
    *,
    template_dir: Path | None = None,
) -> str:
    """Render a candidate :class:`ReportDocument` to deterministic XeLaTeX."""
    rendered = render_latex(doc, template_dir=template_dir or default_template_dir())
    assert_candidate_output_clean(rendered, label=f"{doc.title} latex")
    return rendered


@dataclass(frozen=True, slots=True)
class RenderedExecutiveCandidate:
    candidate_id: str
    label: str
    document: ReportDocument
    markdown: str
    html: str
    latex: str


def render_executive_candidates(
    final_report: Mapping[str, Any],
    *,
    dossiers: Sequence[Any] = (),
    candidate_ids: Sequence[str] = CANDIDATE_IDS,
    source_date_epoch: int = 0,
    template_dir: Path | None = None,
) -> dict[str, RenderedExecutiveCandidate]:
    """Build and render the requested executive report candidates (defaults to A, B, C)."""
    out: dict[str, RenderedExecutiveCandidate] = {}
    for raw_id in candidate_ids:
        cid = normalize_candidate_id(raw_id)
        doc = build_executive_candidate_document(
            cid,
            final_report,
            dossiers=dossiers,
            source_date_epoch=source_date_epoch,
        )
        out[cid] = RenderedExecutiveCandidate(
            candidate_id=cid,
            label=CANDIDATE_LABELS[cid],
            document=doc,
            markdown=render_executive_candidate_markdown(doc),
            html=render_executive_candidate_html(doc),
            latex=render_executive_candidate_latex(doc, template_dir=template_dir),
        )
    return out


__all__ = [
    "CANDIDATE_IDS",
    "CANDIDATE_LABELS",
    "CANDIDATE_RENDERER",
    "CANDIDATE_SUBTITLES",
    "CANDIDATE_TITLES",
    "RenderedExecutiveCandidate",
    "ReportDocument",
    "assert_candidate_output_clean",
    "build_executive_candidate_document",
    "normalize_candidate_id",
    "render_executive_candidate_html",
    "render_executive_candidate_latex",
    "render_executive_candidate_markdown",
    "render_executive_candidates",
]
