"""Complete, traceable scanner-lead menus over accepted observation shards.

Every accepted source-SAST observation becomes one ``lead`` fact. High/Critical leads, including
suppressed and duplicate leads, are listed in a per-component ``menu`` partition; unknown native
severity has its own menu. The membership audit fails the job if an accepted High/Critical
observation is missing from its menu, so deduplication, suppression or a partition bound can never
make a lead disappear. Scanner severity orders attention only; it is never adjudicated severity.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping

from appsec_review.retrieval.observations import (
    SEVERITY_ORDER, SEVERITY_RULE, classify, normalize_reported_severity, rule_of, scanner_of,
)

from appsec_review.indexing.products_base import AcceptedShards, Fact, Product


RULE_VERSION = "appsec-review/scanner-correlation/1"
SUPPRESSION_RULE = "appsec-review/inline-suppression-match/1"
DUPLICATE_RULE = "appsec-review/same-location-lead-correlation/1"
MENU_KINDS = ("high_critical", "unknown")
# Suppression directives name tools; map them to the observation scanners they silence.
_SUPPRESSION_TOOLS = {
    "semgrep": {"tool-semgrep", "tool-opengrep"}, "gosec": {"tool-gosec"}, "codeql": {"codeql"},
    "flawfinder": {"tool-flawfinder"}, "cppcheck": {"tool-cppcheck"}, "phpcs": {"tool-phpcs"},
    "psalm": {"tool-psalm"}, "phpstan": {"tool-phpstan"}, "sonar": set(),
    "clang-tidy": {"tool-clang-tidy", "tool-clang-static-analysis"},
}


class LeadAuditError(ValueError):
    """An accepted High/Critical observation is not accounted for in a lead menu."""


def _suppressed_lines(suppression: Mapping[str, Any]) -> tuple[int, int] | None:
    start = int(suppression.get("start_line") or 0)
    scope = suppression.get("scope")
    if start < 1:
        return None
    if scope == "line":
        return start, start
    if scope == "next_line":
        return start + 1, start + 1
    if scope == "file":
        return 1, 1 << 30
    return None


def _match_suppressions(lead: Mapping[str, Any], by_path: Mapping[str, list[Mapping[str, Any]]]) -> tuple[str, list[str]]:
    path = lead["location"].get("source_path")
    if path is None:
        return "unknown", []
    matched = []
    possible = False
    for item in by_path.get(path, ()):
        scanners = _SUPPRESSION_TOOLS.get(str(item.get("tool")))
        if not scanners or lead["scanner"] not in scanners:
            continue
        lines = _suppressed_lines(item)
        if lines is None:
            possible = True
            continue
        if lines[0] <= int(lead["location"]["start_line"]) <= lines[1]:
            matched.append(str(item.get("signal_id")))
    if matched:
        return "suppressed", sorted(matched)
    return ("possibly_suppressed" if possible else "not_suppressed"), []


def build_scanner_correlation(shards: AcceptedShards, syntax: Mapping[str, Any] | None,
                              dispositions: list[Mapping[str, Any]], settings: Mapping[str, Any],
                              rule_version: str = RULE_VERSION) -> Product:
    product = Product("scanner_correlation", rule_version, complete_or_fail=True)
    observation_shards = shards.select("observations")
    product.use(observation_shards)
    priority_shards = shards.select("priority")
    product.use(priority_shards)
    if not observation_shards:
        return product.unavailable("no accepted observation shard: scanner leads are unavailable, not clean")
    for item in shards.coverage(observation_shards):
        if item["status"] != "complete":
            product.partial(f"observations/{item['shard_id']}: {item['area']}: {item['status']}: {item['gap']}")
    for item in dispositions:
        if item.get("terminal_status") not in {"SUCCEEDED", None}:
            product.partial(f"scanner {item.get('tool_id')}: {item.get('terminal_status')}")
    files = (syntax or {}).get("files", {})
    if syntax is None:
        product.partial("inline suppression state unknown: accepted prioritization syntax facts are unavailable")
    suppressions: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for path, record in files.items():
        suppressions[path].extend(record.get("suppressions", ()))
        if int(record.get("suppression_count", 0)) > len(record.get("suppressions", ())):
            product.partial(f"suppression list truncated for {path}")
    flows: dict[tuple[str, str, int], list[str]] = defaultdict(list)
    for row in shards.entities(priority_shards, ("review_signal",)):
        if row.payload.get("category") == "semantic_path" and isinstance(row.payload.get("sink"), Mapping):
            sink = row.payload["sink"]
            flows[(str(row.payload.get("rule_id")), str(sink.get("path")), int(sink.get("start_line", 0)))].append(
                row.identity)

    leads: list[dict[str, Any]] = []
    other_counts: dict[str, int] = defaultdict(int)
    for row in shards.entities(observation_shards, ("tool_observation",)):
        payload = row.payload
        observation_class = classify(payload)
        if observation_class != "source_sast":
            other_counts[observation_class] += 1
            continue
        severity = normalize_reported_severity(payload)
        location: dict[str, Any] = {"exact": False, "mapping_method": "unresolved"}
        if row.location is not None:
            location = {"exact": not bool(row.location["ambiguous"]),
                        "mapping_method": str(row.location["mapping_method"]),
                        "source_path": row.location["path"], "file_sha256": row.location["file_sha256"],
                        "start_line": int(row.location["start_line"]), "end_line": int(row.location["end_line"])}
        mapping = payload.get("rule_mapping") if isinstance(payload.get("rule_mapping"), Mapping) else {}
        cwes = sorted({str(value) for key, value in mapping.items() if "cwe" in key.lower() and isinstance(value, str)} |
                      {str(entry) for key, value in mapping.items() if "cwe" in key.lower() and isinstance(value, list)
                       for entry in value})
        path = location.get("source_path")
        component = payload.get("component") or (files.get(path, {}).get("component_id") if path else None)
        lead = {
            "observation_id": row.identity, "scanner": scanner_of(payload), "rule_id": rule_of(payload),
            "category": str(payload.get("category") or "source_sast"), "native_severity": severity["native"],
            "producer_normalized_severity": payload.get("severity"),
            "normalized_reported_severity": severity["value"], "severity_rule": SEVERITY_RULE,
            "severity_basis": severity["basis"], "cwe": cwes, "flow_ids": [], "location": location,
            "component_id": str(component or "unassigned"), "shard_id": row.shard_id,
            "shard_sha256": row.shard_sha256, "language": payload.get("language") or (
                files.get(path, {}).get("language") if path else None),
        }
        if path is not None:
            lead["flow_ids"] = sorted(flows.get((lead["rule_id"], path, int(location["start_line"])), ()))
        status, matched = (_match_suppressions(lead, suppressions) if syntax is not None else ("unknown", []))
        lead["suppression_status"] = status
        lead["suppressed"] = status == "suppressed"
        lead["suppression_ids"] = matched
        lead["suppression_rule"] = SUPPRESSION_RULE
        lead["_row"] = row
        leads.append(lead)

    # Duplicate correlation keeps every member; only the canonical lead lacks ``duplicate_of``.
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for lead in leads:
        location = lead["location"]
        if "source_path" not in location:
            continue
        if lead["cwe"]:
            groups[("cwe", location["source_path"], location["start_line"], tuple(lead["cwe"]))].append(lead)
        else:
            groups[("rule", location["source_path"], location["start_line"], lead["scanner"], lead["rule_id"])].append(lead)
    for key, members in sorted(groups.items(), key=lambda pair: repr(pair[0])):
        ordered = sorted(members, key=lambda item: (SEVERITY_ORDER[item["normalized_reported_severity"]],
                                                    item["observation_id"]))
        canonical = ordered[0]
        canonical["duplicate_of"] = None
        for member in ordered[1:]:
            member["duplicate_of"] = canonical["observation_id"]
            member["duplicate_method"] = "same-location-same-cwe" if key[0] == "cwe" else "same-location-same-rule"
        if len(members) > 1:
            product.facts.append(Fact(
                "correlation", canonical["observation_id"],
                {"canonical_observation_id": canonical["observation_id"],
                 "member_observation_ids": [item["observation_id"] for item in ordered],
                 "scanners": sorted({item["scanner"] for item in ordered}),
                 "method": "same-location-same-cwe" if key[0] == "cwe" else "same-location-same-rule",
                 "duplicate_rule": DUPLICATE_RULE},
                "independent observations at the same exact source line", canonical["observation_id"],
                canonical["location"].get("source_path"), tuple(item["observation_id"] for item in ordered)))
    for lead in leads:
        lead.setdefault("duplicate_of", None)

    for lead in leads:
        row = lead.pop("_row")
        product.facts.append(Fact(
            "lead", row.identity, lead, "accepted source-SAST observation; scanner severity orders review only",
            row.identity, lead["location"].get("source_path"), (row.identity,),
            "complete" if lead["location"]["exact"] else "partial", row.source_location(shards.snapshot),
            f"lead {lead['normalized_reported_severity']} {lead['scanner']} {lead['rule_id']} "
            f"{lead['suppression_status']} {'duplicate' if lead['duplicate_of'] else 'canonical'}"))

    partition_size = int(settings["menu_partition_size"])
    expected: dict[str, set[str]] = {kind: set() for kind in MENU_KINDS}
    by_menu: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for lead in leads:
        severity = lead["normalized_reported_severity"]
        kind = "high_critical" if severity in {"critical", "high"} else "unknown" if severity == "unknown" else None
        if kind is not None:
            expected[kind].add(lead["observation_id"])
            by_menu[(kind, lead["component_id"])].append(lead)
    listed: dict[str, set[str]] = {kind: set() for kind in MENU_KINDS}
    for (kind, component), members in sorted(by_menu.items()):
        ordered = sorted(members, key=lambda item: (SEVERITY_ORDER[item["normalized_reported_severity"]],
                                                    item["observation_id"]))
        partitions = [ordered[offset:offset + partition_size] for offset in range(0, len(ordered), partition_size)]
        for number, chunk in enumerate(partitions):
            listed[kind].update(item["observation_id"] for item in chunk)
            product.facts.append(Fact(
                "menu", f"{kind}:{component}:{number:05d}",
                {"menu": kind, "component_id": component, "partition": number, "partition_count": len(partitions),
                 "next_partition": f"{kind}:{component}:{number + 1:05d}" if number + 1 < len(partitions) else None,
                 "member_count": len(chunk), "menu_total": len(ordered),
                 "members": [{key: item[key] for key in (
                     "observation_id", "scanner", "rule_id", "normalized_reported_severity", "native_severity",
                     "suppressed", "suppression_status", "duplicate_of")} for item in chunk]},
                "complete per-component lead menu; partitioned, never truncated",
                None, None, tuple(item["observation_id"] for item in chunk)))
    missing = {kind: sorted(expected[kind] - listed[kind]) for kind in MENU_KINDS}
    accepted_sast = len(leads)
    counts = {"source_sast_observations": accepted_sast, "lead_facts": accepted_sast,
              "high_critical": len(expected["high_critical"]), "unknown_severity": len(expected["unknown"]),
              "high_critical_suppressed": sum(1 for lead in leads if lead["observation_id"] in expected["high_critical"]
                                              and lead["suppressed"]),
              "high_critical_duplicates": sum(1 for lead in leads if lead["observation_id"] in expected["high_critical"]
                                              and lead["duplicate_of"]),
              **{f"other_{name}": value for name, value in sorted(other_counts.items())}}
    for lead in leads:
        key = f"lead_language:{str(lead.get('language') or 'unknown').lower()}"
        counts[key] = counts.get(key, 0) + 1
    product.counts = counts
    product.facts.append(Fact(
        "audit", "lead-membership",
        {"counts": counts, "missing_from_menu": missing, "status": "passed" if not any(missing.values()) else "failed",
         "audit_rule": RULE_VERSION},
        "membership audit of accepted source-SAST observations against lead menus"))
    if any(missing.values()):
        raise LeadAuditError(f"accepted High/Critical or unknown-severity leads missing from menus: {missing}")
    return product
