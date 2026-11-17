"""CVE/OSV + PURL dependency-reachability OpenVEX v0.2.0 projection.

Enforces strict coverage honesty: ``not_affected`` with justification
``vulnerable_code_not_in_execute_path`` is emitted ONLY when symbol/package
reachability is deterministically ``unreachable_in_target`` under complete
target coverage with zero coverage gaps. Missing or degraded coverage always
yields ``under_investigation`` (unless reachability is already proven
``symbol_reachable`` -> ``affected``).
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
from typing import Any
from urllib.parse import quote

from appsec_review.interchange import GapCode, producer_gap

from . import contracts as c
from .validation import schema_validator

CVE_OPENVEX_SUMMARY_SCHEMA = "appsec-review/openvex-cve-reachability/1"
NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_ADVISORY_PREFIXES = ("GHSA-", "OSV-", "PYSEC-", "RUSTSEC-", "GO-", "DSA-", "USN-")
_REACHABLE_STATES = frozenset({
    "symbol_reachable",
    "reachable",
    "confirmed_reachable",
    "call_path_reachable",
})
_UNREACHABLE_STATES = frozenset({
    "unreachable_in_target",
})
_DEGRADED_TIERS = frozenset({
    "syntactic_fallback",
    "unverified",
    "partial",
    "missing",
    "unknown",
    "none",
})
_COMPLETE_COVERAGE_STATES = frozenset({
    "complete",
    "verified_complete",
    "full",
})


@dataclass(frozen=True)
class CveReachabilityDecision:
    vulnerability_name: str
    vulnerability_iri: str
    aliases: tuple[str, ...]
    purl: str | None
    cpe23: str | None
    package_label: str
    status: str
    justification: str | None
    impact_statement: str | None
    action_statement: str | None
    status_notes: str
    has_coverage_gap: bool
    gap_reasons: tuple[str, ...]


@dataclass(frozen=True)
class CveOpenVexBundle:
    document: dict[str, Any] | None
    document_bytes: bytes | None
    decisions: tuple[CveReachabilityDecision, ...]
    statements_by_status: dict[str, int]
    telemetry: dict[str, Any]
    gaps: tuple[dict[str, Any], ...]


def _clean_str(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _normalize_vuln_token(token: str) -> str:
    cleaned = token.strip()
    if _CVE_RE.match(cleaned):
        return cleaned.upper()
    upper = cleaned.upper()
    for prefix in _ADVISORY_PREFIXES:
        if upper.startswith(prefix):
            if prefix == "GHSA-":
                # Preserve lowercase hex/alnum after GHSA- per GitHub canonical form when mixed,
                # or normalize prefix to uppercase GHSA-.
                return "GHSA-" + cleaned[5:]
            return upper if prefix in {"CVE-", "PYSEC-", "RUSTSEC-", "GO-"} else cleaned
    return cleaned


def extract_vulnerability_identity(record: Mapping[str, Any]) -> tuple[str, str, tuple[str, ...], str]:
    """Return ``(primary_name, iri, aliases, description)`` with CVE preferred as primary."""
    candidates: list[str] = []
    for key in ("cve_id", "vulnerability_id", "advisory_id", "osv_id", "ghsa_id", "id", "name"):
        val = _clean_str(record.get(key))
        if val:
            candidates.append(_normalize_vuln_token(val))
    vuln_obj = record.get("vulnerability")
    if isinstance(vuln_obj, Mapping):
        for key in ("name", "cve_id", "id"):
            val = _clean_str(vuln_obj.get(key))
            if val:
                candidates.append(_normalize_vuln_token(val))
        raw_aliases = vuln_obj.get("aliases")
        if isinstance(raw_aliases, Sequence) and not isinstance(raw_aliases, (str, bytes)):
            for item in raw_aliases:
                val = _clean_str(item)
                if val:
                    candidates.append(_normalize_vuln_token(val))
    for list_key in ("cve_ids", "aliases", "advisory_aliases", "osv_ids", "ghsa_ids"):
        seq = record.get(list_key)
        if isinstance(seq, Sequence) and not isinstance(seq, (str, bytes)):
            for item in seq:
                val = _clean_str(item)
                if val:
                    candidates.append(_normalize_vuln_token(val))

    deduped: list[str] = []
    seen: set[str] = set()
    for token in candidates:
        if token and token not in seen:
            seen.add(token)
            deduped.append(token)
    if not deduped:
        raise ValueError("dependency advisory record has no CVE/OSV vulnerability identifier")

    cves = sorted(tok for tok in deduped if _CVE_RE.match(tok))
    primary = cves[0] if cves else deduped[0]
    aliases = tuple(sorted(tok for tok in deduped if tok != primary))

    explicit_iri = _clean_str(record.get("vulnerability_iri"))
    if not explicit_iri and isinstance(vuln_obj, Mapping):
        explicit_iri = _clean_str(vuln_obj.get("@id"))
    if explicit_iri:
        c.validate_repository_iri(explicit_iri)
        iri = explicit_iri
    elif _CVE_RE.match(primary):
        iri = f"https://nvd.nist.gov/vuln/detail/{quote(primary, safe='-')}"
    else:
        iri = f"https://osv.dev/vulnerability/{quote(primary, safe='-')}"

    description = (
        _clean_str(record.get("description"))
        or _clean_str(record.get("summary"))
        or (_clean_str(vuln_obj.get("description")) if isinstance(vuln_obj, Mapping) else "")
    )
    return primary, iri, aliases, description


def construct_purl(record: Mapping[str, Any]) -> str | None:
    """Extract or deterministically construct a Package URL (PURL) from package metadata."""
    explicit = _clean_str(record.get("purl"))
    if not explicit and isinstance(record.get("identifiers"), Mapping):
        explicit = _clean_str(record["identifiers"].get("purl"))
    if explicit.startswith("pkg:"):
        return explicit

    ecosystem = _clean_str(record.get("ecosystem") or record.get("package_ecosystem")).lower()
    name = _clean_str(record.get("package_name") or record.get("component_name") or record.get("package"))
    version = _clean_str(record.get("package_version") or record.get("version"))
    if not ecosystem or not name:
        return None
    eco_map = {
        "python": "pypi",
        "pip": "pypi",
        "pypi": "pypi",
        "node": "npm",
        "nodejs": "npm",
        "npm": "npm",
        "javascript": "npm",
        "typescript": "npm",
        "rust": "cargo",
        "cargo": "cargo",
        "crates": "cargo",
        "go": "golang",
        "golang": "golang",
        "maven": "maven",
        "java": "maven",
        "nuget": "nuget",
        "dotnet": "nuget",
        "c": "generic",
        "cpp": "generic",
        "c++": "generic",
        "conan": "conan",
        "vcpkg": "generic",
    }
    purl_type = eco_map.get(ecosystem, quote(ecosystem, safe="+-._"))
    if purl_type == "npm" and name.startswith("@") and "/" in name:
        ns, pkg = name.split("/", 1)
        encoded_name = f"{quote(ns, safe='')}/{quote(pkg, safe='-._')}"
    elif "/" in name:
        parts = [quote(part, safe="-._") for part in name.split("/") if part]
        encoded_name = "/".join(parts)
    else:
        encoded_name = quote(name, safe="-._")
    base = f"pkg:{purl_type}/{encoded_name}"
    return f"{base}@{quote(version, safe='+-._')}" if version else base


def _extract_gap_reasons(record: Mapping[str, Any], *, run_has_coverage_gaps: bool) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if run_has_coverage_gaps:
        reasons.append("run_level_coverage_gap")
    if record.get("has_coverage_gaps") is True:
        reasons.append("advisory_coverage_gap")
    if record.get("coverage_complete") is False:
        reasons.append("coverage_incomplete")
    cov_status = _clean_str(record.get("coverage_status")).lower()
    if cov_status and cov_status not in _COMPLETE_COVERAGE_STATES:
        reasons.append(f"coverage_status:{cov_status}")
    tier = _clean_str(record.get("resolution_tier")).lower()
    if tier in _DEGRADED_TIERS:
        reasons.append(f"degraded_resolution_tier:{tier}")
    for key in ("gaps", "coverage_gaps"):
        raw = record.get(key)
        if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
            for item in raw:
                if isinstance(item, str) and item.strip():
                    reasons.append(item.strip())
                elif isinstance(item, Mapping):
                    gid = _clean_str(item.get("gap_id") or item.get("reason") or item.get("cause"))
                    reasons.append(gid or "producer_gap")

    full_coverage_declared = (
        record.get("coverage_complete") is True
        or cov_status in _COMPLETE_COVERAGE_STATES
    )
    deduped = tuple(dict.fromkeys(reasons))
    return (bool(deduped) or not full_coverage_declared), deduped


def classify_cve_reachability(
    record: Mapping[str, Any],
    *,
    default_action_statement: str = "Upgrade to a patched dependency release or apply vendor mitigations.",
    run_has_coverage_gaps: bool = False,
) -> CveReachabilityDecision:
    """Classify one dependency advisory into OpenVEX status with strict coverage honesty."""
    vuln_name, vuln_iri, aliases, _ = extract_vulnerability_identity(record)
    purl = construct_purl(record)
    cpe23 = _clean_str(record.get("cpe23") or record.get("cpe"))
    if not cpe23 and isinstance(record.get("identifiers"), Mapping):
        cpe23 = _clean_str(record["identifiers"].get("cpe23"))
    cpe23_val = cpe23 or None
    if purl is None and cpe23_val is None:
        raise ValueError(f"advisory {vuln_name} requires a PURL or CPE23 component identifier")

    pkg_label = (
        purl
        or cpe23_val
        or _clean_str(record.get("package_name") or record.get("component_name"))
        or vuln_name
    )
    reachability = _clean_str(
        record.get("reachability")
        or record.get("reachability_status")
        or record.get("symbol_reachability")
    ).lower()
    has_gap, gap_reasons = _extract_gap_reasons(record, run_has_coverage_gaps=run_has_coverage_gaps)
    fixed_ver = _clean_str(record.get("fixed_version") or record.get("patched_version"))
    explicit_action = _clean_str(record.get("action_statement"))

    if reachability in _REACHABLE_STATES:
        if explicit_action:
            action = explicit_action
        elif fixed_ver:
            action = f"Upgrade {pkg_label} to {fixed_ver} or later; reachable execution path verified in target."
        else:
            action = default_action_statement
        symbols = record.get("reachable_symbols") or record.get("call_path") or ()
        sym_note = ""
        if isinstance(symbols, Sequence) and not isinstance(symbols, (str, bytes)) and symbols:
            sym_note = f" Reachable symbols/path: {', '.join(str(s) for s in list(symbols)[:5])}."
        notes = f"Confirmed symbol reachability ({reachability}) for {pkg_label}.{sym_note}"
        if gap_reasons:
            notes += f" Additional coverage notes: {', '.join(gap_reasons)}."
        return CveReachabilityDecision(
            vulnerability_name=vuln_name,
            vulnerability_iri=vuln_iri,
            aliases=aliases,
            purl=purl,
            cpe23=cpe23_val,
            package_label=pkg_label,
            status="affected",
            justification=None,
            impact_statement=None,
            action_statement=action,
            status_notes=notes,
            has_coverage_gap=bool(gap_reasons),
            gap_reasons=gap_reasons,
        )

    if reachability in _UNREACHABLE_STATES and not has_gap:
        impact = (
            _clean_str(record.get("impact_statement"))
            or f"Deterministic symbol and call-graph analysis with complete target coverage verified "
               f"that vulnerable code in {pkg_label} is not in any executable path."
        )
        return CveReachabilityDecision(
            vulnerability_name=vuln_name,
            vulnerability_iri=vuln_iri,
            aliases=aliases,
            purl=purl,
            cpe23=cpe23_val,
            package_label=pkg_label,
            status="not_affected",
            justification=NOT_IN_EXECUTE_PATH,
            impact_statement=impact,
            action_statement=None,
            status_notes=f"Deterministically unreachable_in_target under full coverage for {pkg_label}.",
            has_coverage_gap=False,
            gap_reasons=(),
        )

    reason_text = ", ".join(gap_reasons) if gap_reasons else (reachability or "coverage_unverified")
    notes = (
        f"Reachability for {pkg_label} remains under_investigation ({reason_text}); "
        "missing or partial coverage is never treated as not_affected."
    )
    normalized_reasons = gap_reasons if gap_reasons else ((reachability or "coverage_unverified"),)
    return CveReachabilityDecision(
        vulnerability_name=vuln_name,
        vulnerability_iri=vuln_iri,
        aliases=aliases,
        purl=purl,
        cpe23=cpe23_val,
        package_label=pkg_label,
        status="under_investigation",
        justification=None,
        impact_statement=None,
        action_statement=None,
        status_notes=notes,
        has_coverage_gap=True,
        gap_reasons=normalized_reasons,
    )


def _component_identifiers(decision: CveReachabilityDecision) -> dict[str, str]:
    ids: dict[str, str] = {}
    if decision.purl:
        ids["purl"] = decision.purl
    if decision.cpe23:
        ids["cpe23"] = decision.cpe23
    return ids


def validate_cve_openvex_document(
    document: Mapping[str, Any], *, repository_root: Any = None,
) -> None:
    """Validate an OpenVEX v0.2.0 document offline against the pinned upstream schema."""
    validator = schema_validator("upstream/openvex-v0.2.0.schema.json", repository_root=repository_root)
    errors = sorted(validator.iter_errors(dict(document)), key=lambda err: [str(p) for p in err.absolute_path])
    if errors:
        first = errors[0]
        where = "/".join(str(p) for p in first.absolute_path) or "<root>"
        raise ValueError(f"CVE OpenVEX document failed OpenVEX v0.2.0 validation at {where}: {first.message}")


def project_dependency_advisories_to_openvex(
    advisories: Sequence[Mapping[str, Any]],
    *,
    author: str = "appsec-review",
    role: str = "Automated Application Security Review",
    timestamp: str = "2026-01-01T00:00:00Z",
    product_id: str | None = None,
    exporter_release: str = "1",
    default_action_statement: str = "Upgrade to a patched dependency release or apply vendor mitigations.",
    run_has_coverage_gaps: bool = False,
) -> CveOpenVexBundle:
    """Deterministically project dependency-intelligence reachability records to OpenVEX v0.2.0."""
    norm_ts = c.normalize_timestamp(timestamp)
    tooling = c.exporter_tooling(exporter_release)
    if product_id is not None:
        c.validate_repository_iri(product_id)

    decisions_with_desc: list[tuple[CveReachabilityDecision, str]] = []
    for record in advisories:
        _, _, _, description = extract_vulnerability_identity(record)
        decision = classify_cve_reachability(
            record,
            default_action_statement=default_action_statement,
            run_has_coverage_gaps=run_has_coverage_gaps,
        )
        decisions_with_desc.append((decision, description))

    decisions_with_desc.sort(
        key=lambda pair: (
            pair[0].vulnerability_name,
            pair[0].purl or "",
            pair[0].cpe23 or "",
            pair[0].status,
        )
    )

    counts = {"affected": 0, "not_affected": 0, "under_investigation": 0}
    statements: list[dict[str, Any]] = []
    gap_records: list[dict[str, Any]] = []
    ordered_decisions: list[CveReachabilityDecision] = []

    for decision, description in decisions_with_desc:
        ordered_decisions.append(decision)
        counts[decision.status] = counts.get(decision.status, 0) + 1
        vuln_struct: dict[str, Any] = {
            "@id": decision.vulnerability_iri,
            "name": decision.vulnerability_name,
        }
        if description:
            vuln_struct["description"] = description
        if decision.aliases:
            vuln_struct["aliases"] = list(decision.aliases)

        comp_ids = _component_identifiers(decision)
        if product_id:
            products = [{
                "@id": product_id,
                "subcomponents": [{"identifiers": comp_ids}],
            }]
        else:
            products = [{"identifiers": comp_ids}]

        stmt_body: dict[str, Any] = {
            "version": 1,
            "vulnerability": vuln_struct,
            "timestamp": norm_ts,
            "products": products,
            "status": decision.status,
            "status_notes": decision.status_notes,
        }
        if decision.justification is not None:
            stmt_body["justification"] = decision.justification
        if decision.impact_statement is not None:
            stmt_body["impact_statement"] = decision.impact_statement
        if decision.action_statement is not None:
            stmt_body["action_statement"] = decision.action_statement

        stmt_id = c.statement_id(author, stmt_body)
        statements.append({"@id": stmt_id, **stmt_body})

        if decision.has_coverage_gap and decision.status == "under_investigation":
            gap_records.append(
                producer_gap(
                    GapCode.PRODUCER_REPORTED_GAP,
                    (
                        f"OpenVEX advisory {decision.vulnerability_name} ({decision.package_label}) "
                        f"kept under_investigation due to coverage gaps: {', '.join(decision.gap_reasons)}"
                    ),
                    scope_id=decision.package_label,
                )
            )

    document: dict[str, Any] | None = None
    document_bytes: bytes | None = None
    if statements:
        raw_doc: dict[str, Any] = {
            "@context": c.OPENVEX_CONTEXT,
            "author": author,
            "timestamp": norm_ts,
            "version": 1,
            "tooling": tooling,
            "statements": statements,
        }
        if role:
            raw_doc["role"] = role
        document = {"@id": c.document_id(raw_doc), **raw_doc}
        validate_cve_openvex_document(document)
        document_bytes = c.canonical_bytes(document)

    telemetry = {
        "openvex.cve_statements_by_status": dict(counts),
        "openvex.cve_total_statements": len(statements),
        "openvex.cve_coverage_gap_statements": sum(
            1 for d in ordered_decisions if d.status == "under_investigation" and d.has_coverage_gap
        ),
    }
    return CveOpenVexBundle(
        document=document,
        document_bytes=document_bytes,
        decisions=tuple(ordered_decisions),
        statements_by_status=counts,
        telemetry=telemetry,
        gaps=tuple(gap_records),
    )
