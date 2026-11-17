"""Expanded 12-axis security domain model and 4-series verification funnel tracker.

Every member of ``SecurityPredicate`` except ``"other"`` belongs to exactly one domain's
``predicates`` tuple. Explicit domain metadata (``domain_id`` / ``radar_domain``, CI/CD
workflow paths or classes, container/binary hardening classes, and mapped CWE identifiers)
also routes findings to ``ci_cd_build_integrity`` and ``container_deployment_hardening``
without guessing on unclassified titles. Missing, partial, or unbound coverage is always
surfaced as ``unverified_gap`` or ``partial_coverage_gap``, never as a clean domain.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping, Sequence

from appsec_review.review.models import SecurityPredicate
from .text import clean

SECURITY_RADAR_TRACKER_SCHEMA = "appsec-review/security-radar-tracker/1"
RADAR_SERIES_IDS: tuple[str, ...] = (
    "surface_exposure",
    "verified_coverage",
    "corroborated_leads",
    "confirmed_high_critical",
)
RADAR_SERIES_ORDER = RADAR_SERIES_IDS


@dataclass(frozen=True, slots=True)
class Dimension:
    key: str
    label: str
    predicates: tuple[str, ...]
    counts: str
    domain_id: str = ""
    cwes: tuple[str, ...] = ()
    owasp_2025: str = ""


DIMENSIONS: tuple[Dimension, ...] = (
    Dimension(
        "Auth",
        "AuthN & Session",
        ("authn_bypass",),
        "authentication bypass, session lifecycle, token binding, credential verification",
        domain_id="authentication_session",
        cwes=("CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-306", "CWE-307", "CWE-384", "CWE-613", "CWE-798"),
        owasp_2025="A07:2025",
    ),
    Dimension(
        "AzZ",
        "AuthZ & Tenant Isolation",
        ("authz_bypass", "info_disclosure"),
        "authorization bypass, privilege boundaries, tenant isolation, disclosure of private data",
        domain_id="authorization_access_control",
        cwes=("CWE-200", "CWE-209", "CWE-269", "CWE-284", "CWE-285", "CWE-532", "CWE-639", "CWE-862", "CWE-863"),
        owasp_2025="A01:2025",
    ),
    Dimension(
        "Inj",
        "Injection & Command/SQL/Template",
        ("injection", "command_injection", "sql_injection", "code_injection"),
        "command, SQL, code, XSS, LDAP/XPath, format-string and template interpreter injection",
        domain_id="injection_interpreters",
        cwes=(
            "CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-90",
            "CWE-91", "CWE-94", "CWE-95", "CWE-96", "CWE-134", "CWE-643", "CWE-917", "CWE-1336",
        ),
        owasp_2025="A05:2025",
    ),
    Dimension(
        "Mem",
        "Memory & Native Safety",
        ("memory_corruption", "out_of_bounds_read", "use_after_free", "integer_error"),
        "buffer overflows and memory corruption, out-of-bounds reads, use after free, integer errors",
        domain_id="memory_safety_native",
        cwes=(
            "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-131",
            "CWE-190", "CWE-191", "CWE-415", "CWE-416", "CWE-476", "CWE-681", "CWE-787", "CWE-843",
        ),
        owasp_2025="A06:2025",
    ),
    Dimension(
        "Pars",
        "Parsing & Deserialization",
        ("deserialization",),
        "unsafe deserialization of untrusted data, XXE, schema and object parsing",
        domain_id="parsing_deserialization",
        cwes=("CWE-20", "CWE-502", "CWE-611", "CWE-776", "CWE-829", "CWE-915", "CWE-1286", "CWE-1321"),
        owasp_2025="A08:2025",
    ),
    Dimension(
        "Cryp",
        "Cryptography & Secrets",
        ("crypto_weakness",),
        "weak or misused cryptography, TLS/certificate verification, key custody, randomness, secrets",
        domain_id="cryptography_secrets",
        cwes=(
            "CWE-295", "CWE-310", "CWE-311", "CWE-312", "CWE-319", "CWE-321",
            "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338", "CWE-347",
        ),
        owasp_2025="A04:2025",
    ),
    Dimension(
        "API",
        "API, SSRF & Boundary Drift",
        ("ssrf",),
        "server-side request forgery, outbound RPC/HTTP egress, CSRF/CORS, API boundary drift",
        domain_id="network_api_surface",
        cwes=("CWE-352", "CWE-444", "CWE-601", "CWE-918", "CWE-942", "CWE-1275"),
        owasp_2025="A01:2025",
    ),
    Dimension(
        "Path",
        "Filesystem, Path & Resource Safety",
        ("path_traversal", "resource_exhaustion"),
        "path traversal, symlink/file handling, upload controls, uncontrolled resource exhaustion",
        domain_id="filesystem_path_resources",
        cwes=(
            "CWE-22", "CWE-23", "CWE-36", "CWE-59", "CWE-73", "CWE-377",
            "CWE-400", "CWE-401", "CWE-404", "CWE-434", "CWE-770", "CWE-772",
        ),
        owasp_2025="A01:2025",
    ),
    Dimension(
        "Logi",
        "Business Logic, Concurrency & State",
        ("race_condition",),
        "workflow invariants, state-machine bypass, TOCTOU, race conditions and unsafe interleavings",
        domain_id="business_logic_state",
        cwes=("CWE-362", "CWE-367", "CWE-472", "CWE-667", "CWE-820", "CWE-833", "CWE-840", "CWE-841"),
        owasp_2025="A06:2025",
    ),
    Dimension(
        "Deps",
        "SCA & Native Dependency Reachability",
        ("supply_chain_compromise",),
        "compromised or vulnerable third-party dependencies, native CPE/PURL reachability",
        domain_id="supply_chain_dependencies",
        cwes=("CWE-494", "CWE-830", "CWE-1104", "CWE-1357", "CWE-1395"),
        owasp_2025="A03:2025",
    ),
    Dimension(
        "CICD",
        "CI/CD & Build Pipeline Integrity",
        (),
        "CI/CD workflow triggers, unpinned third-party actions, build script injection, provenance",
        domain_id="ci_cd_build_integrity",
        cwes=("CWE-506",),
        owasp_2025="A08:2025",
    ),
    Dimension(
        "Hard",
        "Artifact, Binary & Runtime Hardening",
        ("insecure_configuration",),
        "insecure deployment settings, container privileges, binary hardening (PIE/RELRO/NX/canary)",
        domain_id="container_deployment_hardening",
        cwes=("CWE-16", "CWE-250", "CWE-276", "CWE-732", "CWE-1004", "CWE-1220"),
        owasp_2025="A02:2025",
    ),
)

DOMAIN_IDS: tuple[str, ...] = tuple(dim.domain_id for dim in DIMENSIONS)
DIMENSION_BY_KEY: dict[str, Dimension] = {dim.key: dim for dim in DIMENSIONS}
DIMENSION_BY_DOMAIN: dict[str, Dimension] = {dim.domain_id: dim for dim in DIMENSIONS}
DIMENSION_OF_PREDICATE: dict[str, str] = {
    predicate: dim.key for dim in DIMENSIONS for predicate in dim.predicates
}
DOMAIN_OF_PREDICATE: dict[str, str] = {
    predicate: dim.domain_id for dim in DIMENSIONS for predicate in dim.predicates
}
KEY_OF_CWE: dict[str, str] = {
    cwe: dim.key for dim in DIMENSIONS for cwe in dim.cwes
}
DOMAIN_OF_CWE: dict[str, str] = {
    cwe: dim.domain_id for dim in DIMENSIONS for cwe in dim.cwes
}

assert set(DIMENSION_OF_PREDICATE) == {item.value for item in SecurityPredicate} - {"other"}
assert len(DIMENSIONS) == 12 and len(DIMENSION_BY_KEY) == 12 and len(DIMENSION_BY_DOMAIN) == 12

_CWE_RE = re.compile(r"\b(CWE-\d+)\b", re.IGNORECASE)
_CICD_PATH_RE = re.compile(
    r"(?:^|/)(?:\.github/workflows/|\.gitlab-ci\.ya?ml$|Jenkinsfile$|azure-pipelines\.ya?ml$|\.circleci/)",
    re.IGNORECASE,
)
_HARDENING_PATH_RE = re.compile(
    r"(?:^|/)(?:Dockerfile(?:\.[^/]+)?|docker-compose[^/]*\.ya?ml|helm/|k8s/|kubernetes/)",
    re.IGNORECASE,
)
_CICD_CLASSES = frozenset({"ci_cd", "ci_cd_workflow", "workflow_security", "build_integrity", "github_actions"})
_HARDENING_CLASSES = frozenset({"binary_hardening", "container_security", "deployment_hardening", "artifact_hardening"})
_HIGH_CRITICAL = frozenset({"critical", "high"})


@dataclass(frozen=True, slots=True)
class DimensionCounts:
    key: str
    label: str
    findings: int
    claims: int
    domain_id: str = ""
    owasp_2025: str = ""
    high_critical_findings: int = 0
    corroborated_leads: int = 0
    surface_exposure_raw: int = 0
    verified_coverage_pct: float = 0.0
    coverage_status: str = "unverified_gap"


DimensionRow = DimensionCounts


def predicate_of(item: Mapping[str, Any], dossier: Mapping[str, Any] | None = None) -> str | None:
    """Return the package's closed ``SecurityPredicate`` string when bound, else ``None``."""
    candidates = [
        clean((dossier or {}).get("security_predicate")),
        clean(item.get("security_predicate")),
        clean(item.get("title")).split(" (", 1)[0].strip(),
    ]
    return next((candidate for candidate in candidates if candidate in DIMENSION_OF_PREDICATE), None)


def _explicit_domain_key(record: Mapping[str, Any] | None) -> str | None:
    if not isinstance(record, Mapping):
        return None
    for field in ("radar_domain", "domain_id", "security_domain"):
        raw = record.get(field)
        if isinstance(raw, str):
            token = raw.strip()
            if token in DIMENSION_BY_DOMAIN:
                return DIMENSION_BY_DOMAIN[token].key
            if token in DIMENSION_BY_KEY:
                return token
    obs_class = str(record.get("observation_class") or record.get("lane") or "").strip().lower()
    if obs_class in _CICD_CLASSES:
        return "CICD"
    if obs_class in _HARDENING_CLASSES:
        return "Hard"
    sources = record.get("sources")
    if isinstance(sources, Sequence) and not isinstance(sources, (str, bytes)):
        paths = [str(entry.get("path") or "") for entry in sources if isinstance(entry, Mapping) and entry.get("path")]
        if paths and all(_CICD_PATH_RE.search(p) for p in paths):
            return "CICD"
        if paths and all(_HARDENING_PATH_RE.search(p) for p in paths):
            return "Hard"
    return None


def _cwe_key(value: Any) -> str | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return KEY_OF_CWE.get(f"CWE-{value}")
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            found = _cwe_key(item)
            if found is not None:
                return found
        return None
    if not isinstance(value, str) or not value.strip():
        return None
    stripped = value.strip()
    if stripped.isdigit():
        return KEY_OF_CWE.get(f"CWE-{int(stripped)}")
    match = _CWE_RE.search(stripped)
    if match is None:
        return None
    return KEY_OF_CWE.get(match.group(1).upper())


def dimension_of_package(package: Mapping[str, Any], dossier: Mapping[str, Any] | None = None) -> str | None:
    """Return the 12-axis dimension key for an accepted package, or ``None`` if unclassified."""
    for candidate in (dossier, package):
        explicit = _explicit_domain_key(candidate)
        if explicit is not None:
            return explicit
    predicate = predicate_of(package, dossier)
    if predicate is not None:
        return DIMENSION_OF_PREDICATE[predicate]
    head = clean(package.get("title")).split(" (", 1)[0].strip()
    if head in DIMENSION_BY_DOMAIN:
        return DIMENSION_BY_DOMAIN[head].key
    for candidate in (dossier, package):
        if isinstance(candidate, Mapping):
            for cwe_field in ("weakness_cwe", "cwe", "cwe_id", "cwes"):
                mapped = _cwe_key(candidate.get(cwe_field))
                if mapped is not None:
                    return mapped
    return _cwe_key(package.get("title"))


def domain_id_of_package(package: Mapping[str, Any], dossier: Mapping[str, Any] | None = None) -> str | None:
    key = dimension_of_package(package, dossier)
    return None if key is None else DIMENSION_BY_KEY[key].domain_id


def owasp_of_cwe_or_domain(weakness_cwe: str | int | None, domain_id: str | None = None) -> str | None:
    if isinstance(domain_id, str) and domain_id in DIMENSION_BY_DOMAIN:
        return DIMENSION_BY_DOMAIN[domain_id].owasp_2025 or None
    key = _cwe_key(weakness_cwe)
    if key is not None:
        return DIMENSION_BY_KEY[key].owasp_2025 or None
    return None


def _lookup_dossier(
    package: Mapping[str, Any],
    dossiers_map: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    claim_id = package.get("claim_id")
    if isinstance(claim_id, str) and claim_id in dossiers_map:
        return dossiers_map[claim_id]
    pkg_id = package.get("finding_package_id")
    if isinstance(pkg_id, str) and pkg_id in dossiers_map:
        return dossiers_map[pkg_id]
    return None


def _technical_severity(package: Mapping[str, Any], dossier: Mapping[str, Any] | None = None) -> str | None:
    ship = package.get("ship_block")
    if isinstance(ship, Mapping) and isinstance(ship.get("technical_severity"), str):
        return ship["technical_severity"].lower()
    if isinstance(dossier, Mapping):
        d_ship = dossier.get("ship_block")
        if isinstance(d_ship, Mapping) and isinstance(d_ship.get("technical_severity"), str):
            return d_ship["technical_severity"].lower()
    for score in package.get("scores") or ():
        if isinstance(score, Mapping):
            tech = score.get("technical_severity")
            if isinstance(tech, Mapping) and isinstance(tech.get("rating"), str):
                return tech["rating"].lower()
    return None


def _chain_claim_ids(report: Mapping[str, Any]) -> set[str]:
    chains = report.get("attack_chains")
    if not isinstance(chains, Mapping):
        return set()
    admitted: set[str] = set()
    for item in chains.get("items") or ():
        if not isinstance(item, Mapping):
            continue
        status = str(item.get("status") or "")
        if status in {"confirmed", "qualified_supported", "admitted", "supported"}:
            for cid in item.get("claim_ids") or ():
                if isinstance(cid, str):
                    admitted.add(cid)
    return admitted


def build_radar_tracker(
    report: Mapping[str, Any],
    dossiers_by_claim: Mapping[str, Mapping[str, Any]] | None = None,
    *,
    domain_telemetry: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compute the deterministic 12-axis, 4-series Security Radar Tracker projection."""
    dossiers = dossiers_by_claim or {}
    telemetry = domain_telemetry or {}
    status_obj = report.get("status") if isinstance(report.get("status"), Mapping) else {}
    review_incomplete = bool(status_obj.get("review_incomplete", False))
    review_status = str(status_obj.get("review") or "UNKNOWN")
    global_gaps = [
        str(item.get("limitation_id"))
        for item in (report.get("limitations") or ())
        if isinstance(item, Mapping) and item.get("kind") == "gap" and item.get("limitation_id")
    ]
    chain_claims = _chain_claim_ids(report)

    findings_by_key = {dim.key: 0 for dim in DIMENSIONS}
    hc_by_key = {dim.key: 0 for dim in DIMENSIONS}
    chain_by_key = {dim.key: 0 for dim in DIMENSIONS}
    claims_by_key = {dim.key: 0 for dim in DIMENSIONS}
    backlog_by_key = {dim.key: 0 for dim in DIMENSIONS}
    unclassified = 0

    for section in ("findings", "verification_backlog", "withheld"):
        for package in report.get(section) or ():
            if not isinstance(package, Mapping):
                continue
            dossier = _lookup_dossier(package, dossiers)
            key = dimension_of_package(package, dossier)
            if key is None:
                unclassified += 1
                continue
            claims_by_key[key] += 1
            if section == "findings":
                findings_by_key[key] += 1
                sev = _technical_severity(package, dossier)
                in_chain = str(package.get("claim_id") or "") in chain_claims or bool(
                    isinstance(dossier, Mapping) and dossier.get("chains")
                )
                if in_chain:
                    chain_by_key[key] += 1
                if sev in _HIGH_CRITICAL or in_chain:
                    hc_by_key[key] += 1
            elif section == "verification_backlog":
                backlog_by_key[key] += 1

    raw_surface: dict[str, int] = {}
    raw_leads: dict[str, int] = {}
    raw_cov_count: dict[str, int] = {}
    cov_pct: dict[str, float] = {}
    cov_status: dict[str, str] = {}
    cov_gaps: dict[str, list[str]] = {}

    for dim in DIMENSIONS:
        dom = telemetry.get(dim.domain_id) if isinstance(telemetry.get(dim.domain_id), Mapping) else {}
        leads_raw = int(dom.get("corroborated_leads", claims_by_key[dim.key]))
        exposed_raw = int(dom.get("surface_exposure", dom.get("exposed_units", leads_raw)))
        exposed_raw = max(exposed_raw, leads_raw)
        raw_leads[dim.key] = max(0, leads_raw)
        raw_surface[dim.key] = max(0, exposed_raw)

        axis_gap_reasons: list[str] = []
        for extra_gap in dom.get("coverage_gaps") or ():
            if isinstance(extra_gap, str) and extra_gap:
                axis_gap_reasons.append(extra_gap)
        if dom.get("syntactic_fallback_only"):
            axis_gap_reasons.append("syntactic_fallback_only")

        if "inspected_units" in dom and exposed_raw > 0:
            inspected = max(0, min(int(dom["inspected_units"]), exposed_raw))
            raw_cov_count[dim.key] = inspected
            pct = round(100.0 * inspected / exposed_raw, 1)
            if inspected < exposed_raw:
                axis_gap_reasons.append("uninspected_exposed_units")
        elif exposed_raw > 0:
            adjudicated = max(0, claims_by_key[dim.key] - backlog_by_key[dim.key])
            inspected = claims_by_key[dim.key]
            raw_cov_count[dim.key] = inspected
            if backlog_by_key[dim.key] > 0:
                pct = round(100.0 * (adjudicated + 0.5 * backlog_by_key[dim.key]) / exposed_raw, 1)
                axis_gap_reasons.append("verification_backlog_unconfirmed")
            else:
                pct = round(100.0 * min(inspected, exposed_raw) / exposed_raw, 1)
        else:
            raw_cov_count[dim.key] = 0
            pct = 0.0
            axis_gap_reasons.append("no_domain_coverage_bound")

        if review_incomplete:
            axis_gap_reasons.append("review_incomplete")
        elif review_status == "DEGRADED" and exposed_raw > 0:
            axis_gap_reasons.append("review_degraded")

        dedup_reasons = list(dict.fromkeys(axis_gap_reasons))
        cov_gaps[dim.key] = dedup_reasons
        cov_pct[dim.key] = max(0.0, min(100.0, pct))
        if pct <= 0.0 or "no_domain_coverage_bound" in dedup_reasons:
            cov_status[dim.key] = "unverified_gap"
        elif dedup_reasons:
            cov_status[dim.key] = "partial_coverage_gap"
        elif findings_by_key[dim.key] > 0:
            cov_status[dim.key] = "verified_findings"
        else:
            cov_status[dim.key] = "verified_no_findings"

    max_surface = max(raw_surface.values(), default=0)
    max_leads = max(raw_leads.values(), default=0)
    max_hc = max(hc_by_key.values(), default=0)
    max_confirmed_any = max(findings_by_key.values(), default=0)

    axes_out: list[dict[str, Any]] = []
    verified_axes = 0
    gap_axes = 0
    for dim in DIMENSIONS:
        k = dim.key
        is_gap = cov_status[k] in {"unverified_gap", "partial_coverage_gap"}
        if is_gap:
            gap_axes += 1
        else:
            verified_axes += 1

        surf_unit = round(raw_surface[k] / max_surface, 4) if max_surface > 0 else 0.0
        cov_unit = round(cov_pct[k] / 100.0, 4)
        leads_unit = round(raw_leads[k] / max_leads, 4) if max_leads > 0 else 0.0
        if max_hc > 0:
            hc_unit = round(hc_by_key[k] / max_hc, 4)
        elif max_confirmed_any > 0 and findings_by_key[k] > 0:
            hc_unit = round(0.5 * findings_by_key[k] / max_confirmed_any, 4)
        else:
            hc_unit = 0.0

        axes_out.append({
            "domain_id": dim.domain_id,
            "key": dim.key,
            "label": dim.label,
            "owasp_2025": dim.owasp_2025,
            "predicates": list(dim.predicates),
            "coverage_status": cov_status[k],
            "gap_reasons": cov_gaps[k],
            "series": {
                "surface_exposure": {
                    "raw_count": raw_surface[k],
                    "score": round(surf_unit * 100.0, 1),
                    "unit": surf_unit,
                },
                "verified_coverage": {
                    "raw_count": raw_cov_count[k],
                    "score": cov_pct[k],
                    "unit": cov_unit,
                    "is_gap": is_gap,
                },
                "corroborated_leads": {
                    "raw_count": raw_leads[k],
                    "score": round(leads_unit * 100.0, 1),
                    "unit": leads_unit,
                },
                "confirmed_high_critical": {
                    "raw_count": hc_by_key[k],
                    "all_confirmed_count": findings_by_key[k],
                    "chain_elevated_count": chain_by_key[k],
                    "score": round(hc_unit * 100.0, 1),
                    "unit": hc_unit,
                },
            },
        })

    mean_cov = sum(cov_pct.values()) / len(DIMENSIONS) if DIMENSIONS else 0.0
    confidence_score = int(round(mean_cov * (0.6 if review_incomplete else 1.0)))
    gap_summary = (
        f"{gap_axes} of {len(DIMENSIONS)} security domains have unverified or partial coverage gaps; "
        "missing coverage is never treated as clean."
        if gap_axes
        else f"All {len(DIMENSIONS)} security domains met bounded verification coverage."
    )
    return {
        "schema": SECURITY_RADAR_TRACKER_SCHEMA,
        "axis_count": len(DIMENSIONS),
        "series_ids": list(RADAR_SERIES_IDS),
        "unclassified_packages": unclassified,
        "coverage_confidence": {
            "verified_axes": verified_axes,
            "gap_axes": gap_axes,
            "confidence_score": max(0, min(100, confidence_score)),
            "review_complete": bool(status_obj.get("review_complete", False)),
            "global_gap_ids": global_gaps,
            "summary_statement": gap_summary,
        },
        "axes": axes_out,
    }


def dimension_counts(
    report: Mapping[str, Any],
    dossiers_by_claim: Mapping[str, Mapping[str, Any]] | None = None,
    *,
    domain_telemetry: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[tuple[DimensionCounts, ...], int]:
    """Per-axis counts over the report's three package buckets, and the number of unclassified packages."""
    tracker = build_radar_tracker(report, dossiers_by_claim, domain_telemetry=domain_telemetry)
    by_key = {axis["key"]: axis for axis in tracker["axes"]}
    return (
        tuple(
            DimensionCounts(
                key=dim.key,
                label=dim.label,
                findings=by_key[dim.key]["series"]["confirmed_high_critical"]["all_confirmed_count"],
                claims=by_key[dim.key]["series"]["corroborated_leads"]["raw_count"],
                domain_id=dim.domain_id,
                owasp_2025=dim.owasp_2025,
                high_critical_findings=by_key[dim.key]["series"]["confirmed_high_critical"]["raw_count"],
                corroborated_leads=by_key[dim.key]["series"]["corroborated_leads"]["raw_count"],
                surface_exposure_raw=by_key[dim.key]["series"]["surface_exposure"]["raw_count"],
                verified_coverage_pct=by_key[dim.key]["series"]["verified_coverage"]["score"],
                coverage_status=by_key[dim.key]["coverage_status"],
            )
            for dim in DIMENSIONS
        ),
        int(tracker["unclassified_packages"]),
    )


__all__ = [
    "DIMENSIONS",
    "DIMENSION_BY_DOMAIN",
    "DIMENSION_BY_KEY",
    "DIMENSION_OF_PREDICATE",
    "DOMAIN_IDS",
    "DOMAIN_OF_CWE",
    "DOMAIN_OF_PREDICATE",
    "KEY_OF_CWE",
    "RADAR_SERIES_IDS",
    "SECURITY_RADAR_TRACKER_SCHEMA",
    "Dimension",
    "DimensionCounts",
    "DimensionRow",
    "build_radar_tracker",
    "dimension_counts",
    "dimension_of_package",
    "domain_id_of_package",
    "owasp_of_cwe_or_domain",
    "predicate_of",
]


def radar_telemetry(tracker: Mapping[str, Any]) -> dict[str, Any]:
    """Deterministic telemetry summary for a 12-axis security-radar-tracker/1 payload."""
    axes = tracker.get("axes") or ()
    by_axis: dict[str, dict[str, int]] = {}
    totals = {
        "surface_exposure": 0,
        "verified_coverage": 0,
        "corroborated_leads": 0,
        "confirmed_high_critical": 0,
    }
    for axis in axes:
        if not isinstance(axis, Mapping):
            continue
        did = str(axis.get("domain_id") or axis.get("key") or "unknown")
        series = axis.get("series") or {}
        row: dict[str, int] = {}
        for s_name in totals:
            entry = series.get(s_name) or {}
            raw = int(entry.get("raw_count", 0)) if isinstance(entry, Mapping) else 0
            row[s_name] = raw
            totals[s_name] += raw
        by_axis[did] = row

    def _rate(num: int, den: int) -> float:
        return round(num / den, 4) if den > 0 else 0.0

    return {
        "reporting.radar_counts_by_axis_and_series": by_axis,
        "reporting.funnel_conversion_rates": {
            "exposure_to_coverage_rate": _rate(totals["verified_coverage"], totals["surface_exposure"]),
            "exposure_to_leads_rate": _rate(totals["corroborated_leads"], max(totals["surface_exposure"], totals["corroborated_leads"])),
            "leads_to_confirmed_rate": _rate(totals["confirmed_high_critical"], totals["corroborated_leads"]),
        },
    }
