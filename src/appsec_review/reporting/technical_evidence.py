"""Conservative display adapters for the existing, gate-bound dossier contract.

Only producer-verified finding path rows carry order. Unordered citations, excerpt order,
legacy timelines and free-text locators cannot establish an edge or an advisory score.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping

from .text import clean

_SHA256 = re.compile(r"[0-9a-f]{64}")
_CWE = re.compile(r"CWE-[1-9][0-9]*")


@dataclass(frozen=True)
class Citation:
    label: str
    relation_id: str
    predicate: str
    attribution: str
    source: str
    content_sha256: str
    receipt_sha256: str


@dataclass(frozen=True)
class PathRow:
    stage: str
    assessment: str
    references: str


def source_location(source: Mapping[str, Any]) -> str:
    """A resolving span retains snapshot and file identity; incomplete mappings remain unknown."""
    start, end = source.get("start_line"), source.get("end_line")
    path = clean(source.get("path"))
    resolved = (
        path and clean(source.get("source_id")) and clean(source.get("target_snapshot"))
        and _SHA256.fullmatch(clean(source.get("file_sha256")))
        and type(start) is int and type(end) is int and 0 < start <= end
        and source.get("mapping_ambiguous") is False
        and source.get("mapping_method") not in (None, "", "not recorded")
    )
    if not resolved:
        return "Source span not established in accepted evidence (missing or ambiguous mapping)."
    span = f"line {start}" if start == end else f"lines {start}-{end}"
    return (f"{path}, {span}; snapshot {clean(source['target_snapshot'])}; "
            f"source {clean(source['source_id'])}; file SHA-256 {source['file_sha256']}; "
            f"mapping {clean(source['mapping_method'])}"
            + ("; accepted excerpt truncated" if source.get("upstream_truncated") else ""))


def citations(dossier: Mapping[str, Any]) -> tuple[Citation, ...]:
    sources: dict[str, list[Mapping[str, Any]]] = {}
    for source in dossier.get("sources") or ():
        sources.setdefault(clean(source.get("entity_id")), []).append(source)
    result = []
    for index, row in enumerate(sorted(dossier.get("evidence") or (),
                                       key=lambda row: clean(row.get("relation_id"))), 1):
        strength = row.get("strength")
        attribution = ("Cited, counted direct" if strength == "counted_direct" else
                       "Analyst-assessed, not counted" if strength == "analyst_assessed_not_counted" else
                       "Unknown attribution")
        attribution += (f"; {clean(row.get('kind')) or 'relation kind unavailable'}; "
                        f"{clean(row.get('admissibility')) or 'admissibility unavailable'}; "
                        f"complete: {'yes' if row.get('complete') is True else 'not established'}")
        mapped = sources.get(clean(row.get("entity_id")), ())
        source = " | ".join(source_location(item) for item in mapped)
        result.append(Citation(
            f"E{index}", clean(row.get("relation_id")), clean(row.get("predicate")), attribution,
            source or "Source span not established in accepted evidence.",
            clean(row.get("content_sha256")) or "unavailable",
            clean(row.get("retrieval_receipt_sha256")) or "unavailable",
        ))
    return tuple(result)


def cited_path_rows(path: Mapping[str, Any]) -> tuple[PathRow, ...]:
    """Display one producer-checked graph path; never connect different path identities."""
    pin = path["citation"]
    cite = pin["relation_id"]
    rows = [PathRow("Cited static path", f"{path['status'].replace('_', ' ')}; not a runtime observation.", cite),
            PathRow("Producer evidence", pin["entity_id"], pin["content_sha256"]),
            PathRow("Accepted shard", pin["shard_id"], path["shard_sha256"] or "[unverified link]"),
            PathRow("Retrieval receipt", pin["relation_id"], pin["retrieval_receipt_sha256"] or "[unverified link]"),
            PathRow("Snapshot / manifest", path["target_snapshot"], path["manifest_sha256"])]
    for step in path["steps"]:
        if step["gap_before"]:
            rows.append(PathRow("Missing transition", "[unverified link]", cite))
        span = step["span"]
        symbol = step["symbol"] or step["symbol_id"] or "[unverified link]"
        where = f"{span['path']}:{span['start_line']}-{span['end_line']}" if span else "[unverified link]"
        detail = f"{symbol} at {where}"
        ref = f"{cite} / step {step['ordinal']}"
        edge = step.get("incoming_edge")
        if edge:
            detail += f"; incoming {edge['kind']} ({edge['tier']})"
            ref += f"; edge {edge['id']}"
            if site := edge.get("site"):
                detail += f" at {site['path']}:{site['start_line']}"
                ref += f"; site file {site['file_sha256']}"
        rows.append(PathRow(f"{step['ordinal'] + 1}. {step['role']}", detail,
                            f"{ref}; file {span['file_sha256']}" if span else ref))
    rows.extend(PathRow("Path control", control["description"], control["reference"]) for control in path["controls"])
    rows.extend(PathRow("Counterevidence", "Recorded against reachability", ref) for ref in path["counter_relations"])
    rows.extend(PathRow("Qualification", "[unverified link] " + reason, cite) for reason in path["limitations"])
    return tuple(rows)


def attack_path(dossier: Mapping[str, Any], refs: tuple[Citation, ...]) -> tuple[PathRow, ...]:
    if dossier.get("finding_path_rows"):
        return tuple(PathRow(**row) for row in dossier["finding_path_rows"])

    def refs_for(*predicates: str) -> str:
        return ", ".join(row.label for row in refs if row.predicate in predicates) or "No admitted citation"

    # Citations support predicates, not a sequence. Even counted reachability evidence need not
    # contain a call path, and bounded model-checker witnesses do not prove external reachability.
    return (
        PathRow("Attacker input / entry",
                "[unverified link] Entry identity and input-to-function transition not established in accepted evidence.",
                refs_for("attacker_input_control", "configuration_enables")),
        PathRow("Relevant functions / calls",
                "[unverified link] Function names and ordered calls not established in accepted evidence. "
                "Cited affected-source spans are listed in the evidence register, not joined into a path.",
                refs_for("affected_construct", "source_to_sink_reachability")),
        PathRow("Trust boundary / guard",
                "[unverified link] Specific boundary crossing and guard disposition not established in accepted evidence.",
                refs_for("missing_or_ineffective_guard", "configuration_enables")),
        PathRow("Vulnerable sink / effect",
                "[unverified link] Sink function and entry-to-sink chain not established in accepted evidence. "
                "The accepted mechanism and impact classification are described above.",
                refs_for("affected_construct", "security_impact")),
    )


def standards(dossier: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    cwe = clean(dossier.get("weakness_cwe"))
    cwe_text = (f"{cwe} (accepted mechanism mapping; taxonomy name not supplied)"
                if _CWE.fullmatch(cwe) else "N/A — no accepted CWE identifier.")
    return (
        ("CWE", cwe_text),
        ("CVE", "N/A — no verified affected-version/advisory linkage in the accepted report inputs."),
        ("CVSS", "N/A — no accepted supported version, vector and provenance. "
         "Provider ratings below are not recalculated or relabelled as CVSS."),
        ("EPSS", "N/A — no verified CVE linkage and no run-admitted date-pinned FIRST record. "
         "Unavailable is not zero."),
    )


def provider_scores(dossier: Mapping[str, Any]) -> tuple[str, ...]:
    result = []
    for row in dossier.get("scores") or ():
        dimensions = []
        for key in ("technical_severity", "exploitability_confidence",
                    "environmental_business_impact", "remediation_priority"):
            value = row.get(key)
            dimensions.append(f"{key.replace('_', ' ')}: " + (
                "; ".join(f"{name} {clean(value.get(name)) or 'unavailable'}"
                          for name in ("scale", "rating", "value"))
                if value is not None else "unavailable"))
        result.append(
            f"Provider {clean(row.get('provider')) or 'unavailable'}; "
            f"score {clean(row.get('score_id')) or 'unavailable'}; SHA-256 "
            f"{clean(row.get('sha256')) or 'unavailable'}. " + ". ".join(dimensions)
            + ". Missing factors: "
            + (", ".join(clean(item) for item in row.get("missing_factors") or ()) or "none recorded")
            + ". Separately attributed provider assessment, not a validated CVSS vector or FIRST EPSS.")
    return tuple(result)
