"""Deterministic SARIF 2.1.0 rendering with codeFlows, fixes, CWE/OWASP taxa, and 12-axis radar tags.

Pure projection: no wall clock, locale, randomness, or network calls.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
import re
from typing import Any

from .dimensions import DIMENSIONS, Dimension, dimension_of_package, owasp_of_cwe_or_domain

SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

_CWE_NUM_RE = re.compile(r"\bCWE-([1-9]\d*)\b", re.IGNORECASE)
_HUNK_RE = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@")
_VALIDATED_TIERS = frozenset({
    "validated",
    "build_checked",
    "in_memory_patch_and_syntax_verified",
    "syntax_verified",
    "compile_verified",
    "accepted",
})
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
}
_SEVERITY_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "2.5",
    "info": "1.0",
    "informational": "1.0",
}
_DOMAIN_BY_KEY = {dim.key: dim for dim in DIMENSIONS}
_DOMAIN_BY_ID = {dim.domain_id: dim for dim in DIMENSIONS}
_UNCLASSIFIED = Dimension("unclassified", "Unclassified", (), "", domain_id="unclassified")


def _clean_str(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _normalize_uri(raw_path: Any) -> str:
    text = _clean_str(raw_path).replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    if (not text or text == "unknown" or text.startswith("/") or ":" in text
            or any(part in {"", ".."} for part in text.split("/"))):
        raise ValueError("SARIF source location requires an explicit repository-relative path")
    return text


def _pos_int(value: Any, default: int | None = None) -> int:
    if value is None and default is not None:
        return default
    if type(value) is int and value >= 1:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
        if parsed >= 1:
            return parsed
    raise ValueError("SARIF source location requires a positive line number")


def _normalize_cwes(finding: Mapping[str, Any]) -> list[str]:
    found: list[int] = []
    for key in ("cwe", "cwe_id", "cwes", "cwe_ids"):
        raw = finding.get(key)
        items = [raw] if isinstance(raw, (int, str)) else (
            list(raw) if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)) else []
        )
        for item in items:
            if isinstance(item, bool):
                continue
            if isinstance(item, str):
                for match in _CWE_NUM_RE.finditer(item):
                    num = int(match.group(1))
                    if num > 0:
                        found.append(num)
    return [f"CWE-{num}" for num in sorted(set(found))]


def _resolve_radar_domain(finding: Mapping[str, Any], cwes: Sequence[str]) -> Any:
    explicit = _clean_str(finding.get("radar_domain") or finding.get("domain_id") or finding.get("dimension"))
    if explicit in _DOMAIN_BY_ID:
        return _DOMAIN_BY_ID[explicit]
    if explicit in _DOMAIN_BY_KEY:
        return _DOMAIN_BY_KEY[explicit]
    probe = dict(finding)
    if cwes and "weakness_cwe" not in probe:
        probe["weakness_cwe"] = cwes[0]
    key = dimension_of_package(probe)
    return _DOMAIN_BY_KEY.get(key, _UNCLASSIFIED)


def _resolve_owasp_ids(finding: Mapping[str, Any], cwes: Sequence[str], domain_id: str) -> list[str]:
    owasp: set[str] = set()
    raw = finding.get("owasp_2025") or finding.get("owasp")
    if isinstance(raw, str) and raw.strip():
        owasp.add(raw.strip())
    elif isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        for item in raw:
            if isinstance(item, str) and item.strip():
                owasp.add(item.strip())
    for cwe in cwes:
        num = int(cwe.split("-", 1)[1])
        mapped = owasp_of_cwe_or_domain(num, domain_id)
        if mapped:
            owasp.add(mapped)
    if not owasp:
        fallback = owasp_of_cwe_or_domain(None, domain_id)
        if fallback:
            owasp.add(fallback)
    return sorted(owasp)


def _extract_trace_steps(finding: Mapping[str, Any]) -> list[dict[str, Any]]:
    for key in ("taint_path_timeline", "trace_steps", "path_steps", "call_path", "steps"):
        raw = finding.get(key)
        if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)) and raw:
            steps = [dict(item) for item in raw if isinstance(item, Mapping)]
            if steps:
                return steps
    dossier = finding.get("dossier")
    if isinstance(dossier, Mapping):
        raw = dossier.get("taint_path_timeline")
        if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
            return [dict(item) for item in raw if isinstance(item, Mapping)]
    return []


def _step_kinds(role: str, index: int, total: int) -> list[str]:
    lower = role.lower()
    if "source" in lower or "entry" in lower or (index == 0 and total > 1):
        return ["acquire"]
    if "guard" in lower or "branch" in lower or "sanitiz" in lower:
        return ["branch"]
    if "sink" in lower or index == total - 1:
        return ["danger"]
    return ["taint"]


def build_sarif_code_flows(finding_id: str, finding: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Build SARIF 2.1.0 ``codeFlows`` with ``threadFlows`` from source-to-sink path steps."""
    steps = _extract_trace_steps(finding)
    if not steps:
        return []
    tf_locations: list[dict[str, Any]] = []
    total = len(steps)
    for idx, step in enumerate(steps):
        raw_path = step.get("path") or step.get("file") or step.get("uri")
        loc_str = _clean_str(step.get("location"))
        line_val = step.get("line") or step.get("start_line")
        if not raw_path and ":" in loc_str:
            p_part, l_part = loc_str.rsplit(":", 1)
            raw_path = p_part
            if line_val is None and l_part.isdigit():
                line_val = int(l_part)
        uri = _normalize_uri(raw_path)
        start_line = _pos_int(line_val)
        end_line = _pos_int(step.get("end_line"), start_line)
        if end_line < start_line:
            raise ValueError("SARIF end line precedes start line")
        role = _clean_str(step.get("role") or step.get("kind") or ("source" if idx == 0 else ("sink" if idx == total - 1 else "hop")))
        symbol = _clean_str(step.get("symbol") or step.get("function"))
        transform = _clean_str(step.get("taint_transform") or step.get("transform") or step.get("detail") or step.get("summary"))
        guard_status = _clean_str(step.get("guard_status") or step.get("guard"))

        msg_parts = [f"[{role}]"]
        if symbol:
            msg_parts.append(symbol)
        if transform:
            msg_parts.append(f"- {transform}")
        if guard_status:
            msg_parts.append(f"(guard: {guard_status})")

        region: dict[str, Any] = {"startLine": start_line}
        if end_line > start_line:
            region["endLine"] = end_line
        loc_obj: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": region,
            },
            "message": {"text": " ".join(msg_parts)},
        }
        if symbol:
            loc_obj["logicalLocations"] = [{"name": symbol, "kind": "function"}]

        props: dict[str, Any] = {"step_role": role}
        if transform:
            props["taint_transform"] = transform
        if guard_status:
            props["guard_status"] = guard_status

        tf_locations.append({
            "location": loc_obj,
            "nestingLevel": int(step.get("nesting_level", 0)) if isinstance(step.get("nesting_level"), int) and step.get("nesting_level", 0) >= 0 else 0,
            "executionOrder": idx + 1,
            "kinds": _step_kinds(role, idx, total),
            "properties": props,
        })

    if not tf_locations:
        return []
    return [{
        "message": {"text": f"Source-to-sink taint and control-flow path ({len(tf_locations)} steps)"},
        "threadFlows": [{
            "id": f"{finding_id}-flow-1",
            "locations": tf_locations,
        }],
    }]


def parse_unified_diff_to_artifact_changes(
    diff_text: str, *, fallback_uri: str = "unknown",
) -> list[dict[str, Any]]:
    """Parse a unified diff into SARIF 2.1.0 ``artifactChange`` objects."""
    if not diff_text.strip():
        return []
    changes_by_uri: dict[str, list[dict[str, Any]]] = {}
    current_uri: str | None = None
    lines = diff_text.splitlines()
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if line.startswith("+++ "):
            target = line[4:].strip().split("\t", 1)[0]
            if target != "/dev/null":
                if target.startswith("b/"):
                    target = target[2:]
                current_uri = _normalize_uri(target)
            idx += 1
            continue
        if line.startswith("--- "):
            source = line[4:].strip().split("\t", 1)[0]
            if current_uri is None and source != "/dev/null":
                if source.startswith("a/"):
                    source = source[2:]
                current_uri = _normalize_uri(source)
            idx += 1
            continue
        hunk_match = _HUNK_RE.match(line)
        if hunk_match:
            old_start = max(1, int(hunk_match.group(1)))
            old_count = int(hunk_match.group(2)) if hunk_match.group(2) is not None else 1
            idx += 1
            replacement_lines: list[str] = []
            consumed_old = 0
            while idx < len(lines):
                hline = lines[idx]
                if hline.startswith(("diff ", "--- ", "+++ ", "@@ ")):
                    break
                if hline.startswith("\\"):
                    idx += 1
                    continue
                if hline.startswith("+"):
                    replacement_lines.append(hline[1:])
                elif hline.startswith("-"):
                    consumed_old += 1
                elif hline.startswith(" ") or hline == "":
                    replacement_lines.append(hline[1:] if hline.startswith(" ") else "")
                    consumed_old += 1
                else:
                    break
                idx += 1
            effective_old = old_count if old_count > 0 else consumed_old
            if effective_old > 0:
                deleted_region: dict[str, Any] = {
                    "startLine": old_start,
                    "endLine": old_start + effective_old - 1,
                }
            else:
                deleted_region = {"startLine": old_start, "startColumn": 1, "endColumn": 1}
            inserted_text = "\n".join(replacement_lines)
            if replacement_lines:
                inserted_text += "\n"
            uri = current_uri or _normalize_uri(fallback_uri)
            changes_by_uri.setdefault(uri, []).append({
                "deletedRegion": deleted_region,
                "insertedContent": {"text": inserted_text},
            })
            continue
        idx += 1

    return [
        {
            "artifactLocation": {"uri": uri},
            "replacements": replacements,
        }
        for uri, replacements in sorted(changes_by_uri.items())
        if replacements
    ]


def build_sarif_fixes(
    finding: Mapping[str, Any], *, primary_uri: str, primary_line: int,
) -> list[dict[str, Any]]:
    """Build SARIF 2.1.0 ``fixes`` when validated remediation diffs/replacements exist."""
    exact = finding.get("exact_remediation")
    if isinstance(exact, Mapping):
        return _exact_fixes(exact)
    rem_candidates: list[Mapping[str, Any]] = []
    for key in ("validated_remediation", "remediation", "remediation_guide"):
        val = finding.get(key)
        if isinstance(val, Mapping):
            rem_candidates.append(val)
    dossier = finding.get("dossier")
    if isinstance(dossier, Mapping) and isinstance(dossier.get("remediation_guide"), Mapping):
        rem_candidates.append(dossier["remediation_guide"])
    rem_candidates.append(finding)

    merged: dict[str, Any] = {}
    for src in reversed(rem_candidates):
        for k in (
            "validated",
            "validation_status",
            "validation_tier",
            "unified_diff",
            "proposed_patch",
            "patch",
            "replacement_text",
            "patched_code",
            "description",
            "summary",
            "fix_description",
            "target_path",
            "start_line",
            "end_line",
        ):
            if src.get(k) not in (None, ""):
                merged[k] = src[k]

    status = _clean_str(merged.get("validation_status") or merged.get("validation_tier")).lower()
    is_validated = merged.get("validated") is True or status in _VALIDATED_TIERS
    if not is_validated:
        return []

    diff_text = _clean_str(merged.get("unified_diff") or merged.get("proposed_patch") or merged.get("patch"))
    target_uri = _normalize_uri(merged.get("target_path") or primary_uri)
    artifact_changes: list[dict[str, Any]] = []
    if "@@" in diff_text:
        artifact_changes = parse_unified_diff_to_artifact_changes(diff_text, fallback_uri=target_uri)
    else:
        snippet = _clean_str(merged.get("replacement_text") or merged.get("patched_code"))
        if not snippet and diff_text and not diff_text.startswith(("diff ", "--- ")):
            snippet = diff_text
        if snippet and target_uri != "unknown":
            s_line = _pos_int(merged.get("start_line"), primary_line)
            e_line = max(s_line, _pos_int(merged.get("end_line"), s_line))
            artifact_changes = [{
                "artifactLocation": {"uri": target_uri},
                "replacements": [{
                    "deletedRegion": {"startLine": s_line, "endLine": e_line},
                    "insertedContent": {"text": snippet if snippet.endswith("\n") else snippet + "\n"},
                }],
            }]

    if not artifact_changes:
        return []

    desc = (
        _clean_str(merged.get("fix_description") or merged.get("description") or merged.get("summary"))
        or f"Validated remediation patch ({status or 'validated'})."
    )
    return [{
        "description": {"text": desc},
        "artifactChanges": artifact_changes,
    }]


def _exact_fixes(remediation: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Keep accepted UTF-8 byte coordinates; no source text or line mapping is inferred."""
    status = remediation.get("validation_status")
    if status not in {"static_checked", "build_checked"}:
        raise ValueError("SARIF exact remediation requires a qualified validation outcome")
    changes = []
    for file in sorted(remediation["files"], key=lambda row: row["path"]):
        replacements = []
        last_end = -1
        for edit in file["edits"]:
            start, end = edit["start"], edit["end"]
            if (type(start) is not int or type(end) is not int or start < 0 or end < start
                    or start < last_end or start == end == last_end
                    or not isinstance(edit["old"], str) or not isinstance(edit["new"], str)
                    or len(edit["old"].encode("utf-8")) != end - start):
                raise ValueError("SARIF exact remediation has invalid byte edits")
            replacements.append({
                "deletedRegion": {"byteOffset": start, "byteLength": end - start},
                "insertedContent": {"text": edit["new"]},
            })
            last_end = end
        if not replacements:
            raise ValueError("SARIF exact remediation has no edits")
        changes.append({
            "artifactLocation": {"uri": _normalize_uri(file["path"])},
            "replacements": replacements,
            "properties": {"before_sha256": file["before_sha256"], "absence_proof": file["absence_proof"]},
        })
    if not changes:
        raise ValueError("SARIF exact remediation has no files")
    return [{
        "description": {"text": f"Remediation proposal ({status}); not a resolved finding. "
                                "Runtime regression was not performed."},
        "artifactChanges": changes,
        "properties": {
            "validation_status": status,
            "patch": dict(remediation["patch"]),
            "validation": dict(remediation["validation"]),
            "checks": dict(remediation["checks"]),
            "runtime_regression": "not_performed_by_policy",
        },
    }]


def _primary_location(finding: Mapping[str, Any]) -> tuple[str, int, int, str]:
    raw_path = finding.get("path") or finding.get("file") or finding.get("primary_path") or finding.get("uri")
    line_val = finding.get("line") or finding.get("start_line")
    end_val = finding.get("end_line")
    symbol = _clean_str(finding.get("symbol") or finding.get("function"))
    loc_obj = finding.get("location") or finding.get("primary_location")
    if isinstance(loc_obj, Mapping):
        raw_path = raw_path or loc_obj.get("path") or loc_obj.get("file") or loc_obj.get("uri")
        line_val = line_val or loc_obj.get("line") or loc_obj.get("start_line")
        end_val = end_val or loc_obj.get("end_line")
        symbol = symbol or _clean_str(loc_obj.get("symbol"))
    elif isinstance(loc_obj, str) and ":" in loc_obj and not raw_path:
        p_part, l_part = loc_obj.rsplit(":", 1)
        raw_path = p_part
        if line_val is None and l_part.isdigit():
            line_val = int(l_part)
    if not raw_path:
        steps = _extract_trace_steps(finding)
        if steps:
            sink = steps[-1]
            raw_path = sink.get("path") or sink.get("file") or sink.get("uri")
            line_val = line_val or sink.get("line") or sink.get("start_line")
            symbol = symbol or _clean_str(sink.get("symbol"))
    uri = _normalize_uri(raw_path)
    start_line = _pos_int(line_val)
    end_line = _pos_int(end_val, start_line)
    if end_line < start_line:
        raise ValueError("SARIF end line precedes start line")
    return uri, start_line, end_line, symbol


def build_sarif_log(
    findings: Sequence[Mapping[str, Any]],
    *,
    exporter_release: str = "1",
    run_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a deterministic OASIS SARIF 2.1.0 log and companion telemetry counters."""
    all_cwes: set[str] = set()
    all_owasp: set[str] = set()
    prepared: list[dict[str, Any]] = []

    for idx, finding in enumerate(findings):
        finding_id = _clean_str(
            finding.get("finding_id") or finding.get("finding_package_id") or finding.get("claim_id")
        ) or f"finding-{idx + 1:04d}"
        cwes = _normalize_cwes(finding)
        domain = _resolve_radar_domain(finding, cwes)
        domain_id = str(domain.domain_id)
        owasp_ids = _resolve_owasp_ids(finding, cwes, domain_id)
        all_cwes.update(cwes)
        all_owasp.update(owasp_ids)

        severity = _clean_str(finding.get("severity")).lower()
        if severity not in _SEVERITY_TO_LEVEL:
            raise ValueError("SARIF finding requires an explicit supported severity")
        base_rule_id = _clean_str(finding.get("rule_id")) or "appsec-review"
        # A rule has one severity and taxonomy: neither may depend on the first result's ID.
        classification = "/".join((domain_id, "+".join(cwe.lower() for cwe in cwes) or "unmapped",
                                    "+".join(owasp_ids) or "unmapped"))
        rule_id = f"{base_rule_id}/{classification}/{severity}"
        level = _SEVERITY_TO_LEVEL[severity]
        uri, start_line, end_line, symbol = _primary_location(finding)
        title = _clean_str(finding.get("title") or finding.get("summary")) or f"{domain.label} finding"
        detail = _clean_str(finding.get("description") or finding.get("summary") or title)

        prepared.append({
            "finding_id": finding_id,
            "finding": finding,
            "rule_id": rule_id,
            "severity": severity,
            "level": level,
            "uri": uri,
            "start_line": start_line,
            "end_line": end_line,
            "symbol": symbol,
            "title": title,
            "detail": detail,
            "cwes": cwes,
            "owasp_ids": owasp_ids,
            "domain": domain,
        })

    prepared.sort(key=lambda item: (item["finding_id"], item["rule_id"], item["uri"], item["start_line"]))

    sorted_cwes = sorted(all_cwes, key=lambda c: int(c.split("-", 1)[1]))
    cwe_index = {cwe: i for i, cwe in enumerate(sorted_cwes)}
    sorted_owasp = sorted(all_owasp)
    owasp_index = {oid: i for i, oid in enumerate(sorted_owasp)}

    taxonomies: list[dict[str, Any]] = [
        {
            "name": "CWE",
            "version": "4.15",
            "informationUri": "https://cwe.mitre.org/",
            "taxa": [
                {"id": cwe, "name": cwe, "shortDescription": {"text": f"MITRE {cwe}"}}
                for cwe in sorted_cwes
            ],
        },
        {
            "name": "OWASP Top 10 2025",
            "version": "2025",
            "informationUri": "https://owasp.org/Top10/",
            "taxa": [
                {"id": oid, "name": oid, "shortDescription": {"text": f"OWASP {oid}"}}
                for oid in sorted_owasp
            ],
        },
    ]

    rules_by_id: dict[str, dict[str, Any]] = {}
    for item in prepared:
        rid = item["rule_id"]
        if rid in rules_by_id:
            continue
        domain = item["domain"]
        relationships: list[dict[str, Any]] = []
        for cwe in item["cwes"]:
            relationships.append({
                "target": {
                    "id": cwe,
                    "index": cwe_index[cwe],
                    "toolComponent": {"name": "CWE", "index": 0},
                },
                "kinds": ["superset"],
            })
        for oid in item["owasp_ids"]:
            relationships.append({
                "target": {
                    "id": oid,
                    "index": owasp_index[oid],
                    "toolComponent": {"name": "OWASP Top 10 2025", "index": 1},
                },
                "kinds": ["relevant"],
            })
        tags = sorted({
            "security",
            f"radar:{domain.domain_id}",
            *(f"external/cwe/{c.lower()}" for c in item["cwes"]),
            *(f"external/owasp/{o.lower()}" for o in item["owasp_ids"]),
        })
        rule_obj: dict[str, Any] = {
            "id": rid,
            "name": domain.domain_id,
            "shortDescription": {"text": str(domain.label)},
            "fullDescription": {"text": f"Verified security finding in radar domain {domain.label}."},
            "defaultConfiguration": {"level": item["level"]},
            "properties": {
                "tags": tags,
                "security-severity": _SEVERITY_SCORE[item["severity"]],
                "radar_domain": {
                    "domain_id": domain.domain_id,
                    "key": domain.key,
                    "label": domain.label,
                },
                "cwe": item["cwes"],
                "owasp_2025": item["owasp_ids"],
            },
        }
        if relationships:
            rule_obj["relationships"] = relationships
        rules_by_id[rid] = rule_obj

    sorted_rule_ids = sorted(rules_by_id)
    rule_index_map = {rid: idx for idx, rid in enumerate(sorted_rule_ids)}
    rules = [rules_by_id[rid] for rid in sorted_rule_ids]

    results: list[dict[str, Any]] = []
    codeflows_emitted = 0
    fixes_emitted = 0

    for item in prepared:
        finding = item["finding"]
        domain = item["domain"]
        region: dict[str, Any] = {"startLine": item["start_line"]}
        if item["end_line"] > item["start_line"]:
            region["endLine"] = item["end_line"]
        loc_entry: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": item["uri"]},
                "region": region,
            },
        }
        if item["symbol"]:
            loc_entry["logicalLocations"] = [{"name": item["symbol"], "kind": "function"}]

        taxa_refs: list[dict[str, Any]] = [
            {
                "id": cwe,
                "index": cwe_index[cwe],
                "toolComponent": {"name": "CWE", "index": 0},
            }
            for cwe in item["cwes"]
        ] + [
            {
                "id": oid,
                "index": owasp_index[oid],
                "toolComponent": {"name": "OWASP Top 10 2025", "index": 1},
            }
            for oid in item["owasp_ids"]
        ]

        code_flows = build_sarif_code_flows(item["finding_id"], finding)
        if code_flows:
            codeflows_emitted += len(code_flows)
        fixes = build_sarif_fixes(finding, primary_uri=item["uri"], primary_line=item["start_line"])
        if fixes:
            fixes_emitted += len(fixes)

        reachability = _clean_str(finding.get("reachability") or finding.get("reachability_status")) or "unknown"
        tags = sorted({
            "security",
            f"radar:{domain.domain_id}",
            *item["cwes"],
            *item["owasp_ids"],
        })
        props: dict[str, Any] = {
            "finding_id": item["finding_id"],
            "severity": item["severity"],
            "reachability": reachability,
            "radar_domain": {
                "domain_id": domain.domain_id,
                "key": domain.key,
                "label": domain.label,
            },
            "cwe": item["cwes"],
            "owasp_2025": item["owasp_ids"],
            "tags": tags,
            "poc_execution_policy": "not_performed_by_policy",
        }

        result_obj: dict[str, Any] = {
            "ruleId": item["rule_id"],
            "ruleIndex": rule_index_map[item["rule_id"]],
            "level": item["level"],
            "message": {"text": item["detail"]},
            "locations": [loc_entry],
            "partialFingerprints": {"primaryFindingId/v1": item["finding_id"]},
            "properties": props,
        }
        if taxa_refs:
            result_obj["taxa"] = taxa_refs
        if code_flows:
            result_obj["codeFlows"] = code_flows
        if fixes:
            result_obj["fixes"] = fixes
        results.append(result_obj)

    telemetry = {
        "reporting.sarif_results_total": len(results),
        "reporting.sarif_codeflows_emitted": codeflows_emitted,
        "reporting.sarif_fixes_emitted": fixes_emitted,
        "reporting.sarif_rules_total": len(rules),
    }

    run_props: dict[str, Any] = {"telemetry": telemetry}
    if run_id:
        run_props["run_id"] = run_id

    sarif_log: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "appsec-review",
                        "version": exporter_release,
                        "informationUri": "https://github.com/wsollers/appsec-review",
                        "rules": rules,
                    }
                },
                "taxonomies": taxonomies,
                "results": results,
                "columnKind": "utf16CodeUnits",
                "properties": run_props,
            }
        ],
    }
    return sarif_log, telemetry


def canonical_sarif_bytes(sarif_log: Mapping[str, Any]) -> bytes:
    """Serialize SARIF 2.1.0 deterministically with sorted keys and LF newline."""
    return (json.dumps(sarif_log, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
