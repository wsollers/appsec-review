"""Advisory reference context for dependency and artifact-scanner leads (lane A and lane B).

The accepted ``dependency_advisories`` product joins each scanner-reported package/advisory match
to the run-pinned OSV, NVD, KEV and EPSS snapshots. This module maps a lead (its observation
identity) to those facts and projects a bounded, deterministic ``advisory_context`` for its
finding-lead package, a compact ``advisory_summary`` for hunt menus, the NVD CVSS band used as
reported severity when the scanner gave no CVSS, and the KEV/EPSS signals used for admission and
lane B ranking.

Everything here is reference context. It orders and informs review work; it never satisfies a
proof obligation (``review.evidence`` classifies advisories and precomputed facts INDIRECT), and a
missing feed is a named gap and an ``unknown`` value, never ``False`` or zero.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from appsec_review.indexing.products import preferred_cvss

CONTEXT_RULE = "appsec-review/advisory-context/1"
MAX_ADVISORIES = 3
MAX_CVES = 4
MAX_GAPS = 12
FEEDS = ("osv", "nvd", "kev", "epss")


def _text(value: Any, bound: int) -> str | None:
    return value[:bound] if isinstance(value, str) and value else None


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def advisory_facts(scope: Any) -> dict[str, list[dict[str, Any]]]:
    """Observation identity -> accepted ``dependency_advisories`` facts that cite it, by fact id."""
    found: dict[str, list[dict[str, Any]]] = defaultdict(list)
    coverage = scope.producer("dependency_advisories")
    for row in scope.store.entities(coverage.shards, kinds=("precomputed_fact",)):
        payload = row["payload"]
        result = payload.get("result") or {}
        if payload.get("query_set") != "dependency_advisories" or not isinstance(result.get("advisory"), str):
            continue
        record = {"fact_id": row["identity"], "result": result, "gaps": list(payload.get("gaps") or ())}
        for observation in result.get("observations") or ():
            if isinstance(observation, str):
                found[observation].append(record)
    return {key: sorted(values, key=lambda item: (str(item["result"]["advisory"]), item["fact_id"]))
            for key, values in found.items()}


def _feed(reference: Any) -> dict[str, Any]:
    reference = reference if isinstance(reference, Mapping) else {}
    return {"status": _text(reference.get("status"), 32) or "unavailable",
            "snapshot_id": _text(reference.get("snapshot_id"), 80), "stale": bool(reference.get("stale"))}


def _advisory(record: Mapping[str, Any]) -> dict[str, Any]:
    result = record["result"]
    intelligence = result.get("intelligence") or {}
    feeds = result.get("feeds") or {"osv": intelligence.get("feed")}
    osv = None
    if intelligence.get("advisory_known") is not None:
        osv = {"known": bool(intelligence.get("advisory_known")),
               "summary": _text(intelligence.get("summary"), 512),
               "withdrawn": _text(intelligence.get("withdrawn"), 64),
               "fixed_versions": [str(item)[:64] for item in intelligence.get("fixed_versions") or ()][:5],
               "aliases": [str(item)[:64] for item in intelligence.get("aliases") or ()][:10]}
    nvd = [{"cve_id": item.get("cve_id"), "status": _text(item.get("status"), 64),
            "published": _text(item.get("published"), 64), "last_modified": _text(item.get("last_modified"), 64),
            "description": _text(item.get("description"), 512),
            "cwes": [str(cwe)[:16] for cwe in item.get("cwes") or ()][:8],
            "cvss": [{"family": _text(metric.get("family"), 64), "version": _text(metric.get("version"), 16),
                      "vector": _text(metric.get("vector"), 256), "base_score": _number(metric.get("base_score")),
                      "base_severity": _text(metric.get("base_severity"), 32)}
                     for metric in item.get("cvss") or () if isinstance(metric, Mapping)][:6]}
           for item in result.get("nvd") or () if isinstance(item, Mapping)][:MAX_CVES]
    kev = [{"cve_id": item.get("cve_id"), "listed": bool(item.get("listed")),
            "date_added": _text(item.get("date_added"), 32), "due_date": _text(item.get("due_date"), 32),
            "known_ransomware_use": _text(item.get("known_ransomware_use"), 32),
            "vulnerability_name": _text(item.get("vulnerability_name"), 256)}
           for item in result.get("kev") or () if isinstance(item, Mapping)][:MAX_CVES]
    epss = [{"cve_id": item.get("cve_id"), "epss": _number(item.get("epss")),
             "percentile": _number(item.get("percentile")), "score_date": _text(item.get("score_date"), 32)}
            for item in result.get("epss") or () if isinstance(item, Mapping)][:MAX_CVES]
    status = result.get("join_status") or {}
    return {"fact_id": record["fact_id"], "advisory_id": str(result["advisory"])[:128],
            "package": _text(result.get("package"), 256), "version": _text(result.get("version"), 128),
            "cve_ids": [str(item)[:32] for item in result.get("cve_ids") or ()][:MAX_CVES],
            "osv": osv, "nvd": nvd, "kev": kev, "epss": epss,
            "joins": {feed: _text(status.get(feed), 32) or "unavailable" for feed in ("nvd", "kev", "epss")},
            "feeds": {feed: _feed(feeds.get(feed)) for feed in FEEDS},
            "gaps": [str(item)[:300] for item in record["gaps"]][:MAX_GAPS]}


def _kev(advisories: Iterable[Mapping[str, Any]]) -> bool | None:
    listed: list[bool] = []
    unknown = False
    for item in advisories:
        if item["kev"]:
            listed.extend(entry["listed"] for entry in item["kev"])
        elif item["cve_ids"] or item["joins"]["kev"] == "unavailable":
            unknown = True
    if any(listed):
        return True
    return None if unknown or not listed else False


def context_for(records: Iterable[Mapping[str, Any]] | None) -> dict[str, Any] | None:
    """The bounded ``advisory_context`` of one lead, or ``None`` when no accepted fact cites it."""
    records = list(records or ())
    if not records:
        return None
    advisories = [_advisory(record) for record in records]
    shown = advisories[:MAX_ADVISORIES]
    metrics = [metric for item in advisories for entry in item["nvd"] for metric in entry["cvss"]]
    percentiles = [entry["percentile"] for item in advisories for entry in item["epss"]
                   if entry["percentile"] is not None]
    preferred = preferred_cvss(metrics)
    return {"rule": CONTEXT_RULE, "advisories": shown, "omitted_advisories": len(advisories) - len(shown),
            "summary": {"cve_ids": sorted({cve for item in advisories for cve in item["cve_ids"]})[:MAX_CVES],
                        "kev_listed": _kev(advisories),
                        "epss_percentile": max(percentiles) if percentiles else None,
                        "max_cvss": max((metric["base_score"] for metric in metrics
                                         if metric["base_score"] is not None), default=None),
                        "preferred_cvss": dict(preferred) if preferred else None},
            "statement": "reference context from pinned feeds; it never satisfies a proof obligation"}


def summary_of(context: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """The compact hunt-menu form: CVE ids, KEV flag, EPSS percentile and max CVSS."""
    if not context:
        return None
    summary = context["summary"]
    return {key: summary[key] for key in ("cve_ids", "kev_listed", "epss_percentile", "max_cvss")}


def nvd_severity(context: Mapping[str, Any] | None) -> tuple[float, str] | None:
    """``(base_score, native label)`` of the preferred NVD metric (v4.0, v3.1, v3.0, then v2)."""
    preferred = (context or {}).get("summary", {}).get("preferred_cvss") if context else None
    if not preferred or preferred.get("base_score") is None:
        return None
    return float(preferred["base_score"]), f"NVD CVSS {preferred.get('version')} {preferred['base_score']}"


def kev_listed(context: Mapping[str, Any] | None) -> bool | None:
    return None if not context else context["summary"]["kev_listed"]


def epss_percentile(context: Mapping[str, Any] | None) -> float | None:
    return None if not context else context["summary"]["epss_percentile"]


def nvd_cwes(context: Mapping[str, Any] | None) -> tuple[str, ...]:
    if not context:
        return ()
    return tuple(sorted({cwe for item in context["advisories"] for entry in item["nvd"] for cwe in entry["cwes"]
                         if cwe.startswith("CWE-") and cwe[4:].isdigit()}, key=lambda value: int(value[4:])))


def reference_inputs(context: Mapping[str, Any] | None) -> dict[str, Any]:
    """Labelled reference scoring inputs: NVD CVSS vectors, the KEV flag and EPSS."""
    if not context:
        return {"reference_cvss": [], "kev_listed": None, "epss": None}
    metrics = sorted({(entry["cve_id"], metric["version"], metric["vector"], metric["base_score"])
                      for item in context["advisories"] for entry in item["nvd"] for metric in entry["cvss"]
                      if metric["vector"]}, key=lambda value: tuple(str(part) for part in value))[:8]
    epss = sorted(((entry["cve_id"], entry["epss"], entry["percentile"], entry["score_date"])
                   for item in context["advisories"] for entry in item["epss"]),
                  key=lambda value: (-(value[2] or 0.0), str(value[0])))
    return {"reference_cvss": [{"cve_id": cve, "version": version, "vector": vector, "base_score": score}
                               for cve, version, vector, score in metrics],
            "kev_listed": kev_listed(context),
            "epss": ({"cve_id": epss[0][0], "epss": epss[0][1], "percentile": epss[0][2], "score_date": epss[0][3]}
                     if epss else None)}
