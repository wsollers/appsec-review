from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any, Iterable, Mapping

from appsec_review.storage import atomic_json, canonical_json, file_sha256
from appsec_review.storage.shared import reference
from appsec_review.provenance import common_metadata, merge_native_references


SECRET_FIELDS = {"secret", "match", "password", "token", "apikey", "api_key", "private_key"}
NORMALIZER_IDENTITY = "static-evidence/4"
_ASSIGNMENT = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*([\"']?)([^\s,;\"']+)\2"
)
_CWE_NUMBER_RE = re.compile(r"(?i)\bcwe[-_:\s]*(\d+)\b")

_SEVERITY_RANK: Mapping[str, int] = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1,
}

_CWE_FAMILY_MAP: Mapping[int, str] = {
    **{n: "CWE-89" for n in (89, 564)},
    **{n: "CWE-78" for n in (77, 78, 88)},
    **{n: "CWE-79" for n in (79, 80, 83, 87)},
    **{n: "CWE-22" for n in (22, 23, 36, 73)},
    502: "CWE-502",
    918: "CWE-918",
    **{n: "CWE-611" for n in (611, 776)},
    **{n: "CWE-119" for n in (119, 120, 121, 122, 125, 787)},
    **{n: "CWE-416" for n in (415, 416)},
    **{n: "CWE-190" for n in (190, 191)},
    **{n: "CWE-327" for n in (326, 327, 328)},
    **{n: "CWE-338" for n in (330, 338)},
    **{n: "CWE-94" for n in (94, 95, 96)},
    **{n: "CWE-798" for n in (259, 321, 798)},
    476: "CWE-476",
}

_KNOWN_RULE_CWE: Mapping[str, int] = {
    "g201": 89, "g202": 89, "b608": 89, "sqlinjection": 89,
    "g204": 78, "b602": 78, "b605": 78, "b607": 78, "commandinjection": 78,
    "b301": 502, "b302": 502, "b506": 502,
    "g401": 327, "g501": 327, "b303": 327, "b324": 327,
    "g404": 338, "b311": 338,
    "deallocuse": 416, "doublefree": 415,
    "bufferaccessoutofbounds": 119, "arrayindexoutofbounds": 119,
    "nullpointer": 476,
}


@dataclass(frozen=True, slots=True)
class EvidenceBounds:
    max_records: int = 5_000
    max_field_bytes: int = 8_192
    max_total_bytes: int = 8 * 1024 * 1024


def _text(value: object, limit: int) -> tuple[str, bool]:
    rendered = "" if value is None else str(value)
    redacted = _ASSIGNMENT.sub(lambda match: f"{match.group(1)}=<redacted>", rendered)
    payload = redacted.encode("utf-8")
    if len(payload) <= limit:
        return redacted, False
    return payload[:limit].decode("utf-8", "ignore"), True


def redact_structure(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if str(key).lower() in SECRET_FIELDS and child not in (None, ""):
                digest = hashlib.sha256(str(child).encode()).hexdigest()
                result[str(key)] = {"redacted": True, "correlation_sha256": digest}
            else:
                result[str(key)] = redact_structure(child)
        return result
    if isinstance(value, list):
        return [redact_structure(child) for child in value]
    if isinstance(value, str):
        return _ASSIGNMENT.sub(lambda match: f"{match.group(1)}=<redacted>", value)
    return value


def severity(value: object) -> str:
    native = str(value or "UNKNOWN").upper()
    if native in {"CRITICAL", "HIGH", "ERROR"}:
        return "HIGH" if native == "ERROR" else native
    if native in {"MEDIUM", "MODERATE", "WARNING", "WARN"}:
        return "MEDIUM"
    if native in {"LOW", "INFO", "INFORMATIONAL", "STYLE"}:
        return "LOW"
    return "UNKNOWN"


def _rule_mapping(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    mapping: dict[str, Any] = {}
    for key, item in sorted(value.items()):
        if isinstance(item, str):
            mapping[str(key)] = item[:512]
        elif isinstance(item, list) and all(isinstance(entry, str) for entry in item):
            mapping[str(key)] = [entry[:128] for entry in item[:32]]
    return mapping or None


def safe_location(path: object, start_line: object, end_line: object, cataloged: set[str]) -> dict[str, Any] | None:
    if path is None:
        return None
    candidate = str(path).replace("\\", "/")
    for prefix in ("/target/", "target/"):
        if candidate.startswith(prefix):
            candidate = candidate[len(prefix):]
    pure = PurePosixPath(candidate)
    if pure.is_absolute() or ".." in pure.parts or candidate not in cataloged:
        return None
    if isinstance(start_line, str) and "-" in start_line:
        left, right = start_line.split("-", 1)
        if left.strip().isdigit() and right.strip().isdigit():
            first = max(1, int(left.strip()))
            parsed_end = max(first, int(right.strip()))
            try:
                explicit_end = int(end_line) if end_line not in (None, 1, "1") else parsed_end
            except (TypeError, ValueError):
                explicit_end = parsed_end
            return {"path": candidate, "start_line": first, "end_line": max(first, explicit_end)}
    try:
        first = max(1, int(start_line or 1))
        last = max(first, int(end_line or first))
    except (TypeError, ValueError):
        first = last = 1
    return {"path": candidate, "start_line": first, "end_line": last}


def _normalize_trace_node(node: object, cataloged: set[str], max_field_bytes: int, *, text_key: str) -> dict[str, Any] | None:
    if not isinstance(node, Mapping):
        return None
    raw_path = node.get("path")
    raw_start = node.get("start_line", 1)
    raw_end = node.get("end_line", raw_start)
    resolved = safe_location(raw_path, raw_start, raw_end, cataloged)
    if resolved is not None:
        norm_path: str | None = resolved["path"]
        start_line, end_line = resolved["start_line"], resolved["end_line"]
    else:
        norm_path = None
        try:
            start_line = max(1, int(raw_start or 1))
            end_line = max(start_line, int(raw_end or start_line))
        except (TypeError, ValueError):
            start_line = end_line = 1
    raw_text = node.get(text_key) or node.get("label") or node.get("symbol") or ""
    rendered, _ = _text(raw_text, min(max_field_bytes, 512))
    return {"path": norm_path, "start_line": start_line, "end_line": end_line, text_key: rendered}


def normalize_dataflow_trace(raw_trace: object, cataloged: set[str], max_field_bytes: int = 8_192) -> dict[str, Any] | None:
    if not isinstance(raw_trace, Mapping):
        return None
    source_loc = _normalize_trace_node(raw_trace.get("source_location"), cataloged, max_field_bytes, text_key="label")
    sink_loc = _normalize_trace_node(raw_trace.get("sink_location"), cataloged, max_field_bytes, text_key="label")
    intermediate_vars: list[dict[str, Any]] = []
    for item in (raw_trace.get("intermediate_vars") or [])[:30]:
        norm_var = _normalize_trace_node(item, cataloged, max_field_bytes, text_key="symbol")
        if norm_var is not None:
            intermediate_vars.append(norm_var)
    steps: list[dict[str, Any]] = []
    raw_steps = raw_trace.get("steps")
    if isinstance(raw_steps, list) and raw_steps:
        for idx, raw_step in enumerate(raw_steps[:32]):
            if not isinstance(raw_step, Mapping):
                continue
            norm_step = _normalize_trace_node(raw_step, cataloged, max_field_bytes, text_key="label")
            if norm_step is None:
                continue
            kind = str(raw_step.get("kind") or ("source" if idx == 0 else "step"))
            if kind not in {"source", "step", "sink"}:
                kind = "step"
            steps.append({
                "index": len(steps), "kind": kind, "path": norm_step["path"],
                "start_line": norm_step["start_line"], "end_line": norm_step["end_line"],
                "label": norm_step["label"],
            })
    else:
        if source_loc is not None:
            steps.append({
                "index": len(steps), "kind": "source", "path": source_loc["path"],
                "start_line": source_loc["start_line"], "end_line": source_loc["end_line"], "label": source_loc["label"],
            })
        for var in intermediate_vars:
            steps.append({
                "index": len(steps), "kind": "step", "path": var["path"],
                "start_line": var["start_line"], "end_line": var["end_line"], "label": var["symbol"],
            })
        if sink_loc is not None:
            steps.append({
                "index": len(steps), "kind": "sink", "path": sink_loc["path"],
                "start_line": sink_loc["start_line"], "end_line": sink_loc["end_line"], "label": sink_loc["label"],
            })
    if source_loc is None and sink_loc is None and not intermediate_vars and not steps:
        return None
    return {"source_location": source_loc, "intermediate_vars": intermediate_vars, "steps": steps, "sink_location": sink_loc}


def extract_cwe_family(record_or_obs: Mapping[str, Any]) -> str | None:
    explicit = record_or_obs.get("cwe_family")
    if isinstance(explicit, str) and explicit.strip():
        match = _CWE_NUMBER_RE.search(explicit)
        if match:
            num = int(match.group(1))
            return _CWE_FAMILY_MAP.get(num, f"CWE-{num}")
        return explicit.strip()
    candidates: list[str] = []
    rule_mapping = record_or_obs.get("rule_mapping")
    if isinstance(rule_mapping, Mapping):
        cwe_val = rule_mapping.get("cwe")
        if isinstance(cwe_val, str):
            candidates.append(cwe_val)
        elif isinstance(cwe_val, list):
            candidates.extend(str(item) for item in cwe_val if item is not None)
    raw_cwe = record_or_obs.get("cwe")
    if isinstance(raw_cwe, (str, int)):
        candidates.append(f"CWE-{raw_cwe}" if str(raw_cwe).isdigit() else str(raw_cwe))
    elif isinstance(raw_cwe, Mapping) and str(raw_cwe.get("id") or "").strip().isdigit():
        candidates.append(f"CWE-{int(str(raw_cwe['id']).strip())}")
    rule_id = str(record_or_obs.get("native_rule_id") or record_or_obs.get("rule_id") or "")
    if rule_id:
        candidates.append(rule_id)
    for text in candidates:
        match = _CWE_NUMBER_RE.search(text)
        if match:
            num = int(match.group(1))
            if num > 0:
                return _CWE_FAMILY_MAP.get(num, f"CWE-{num}")
    normalized_rule = rule_id.rsplit(".", 1)[-1].rsplit("/", 1)[-1].strip().lower()
    if normalized_rule in _KNOWN_RULE_CWE:
        num = _KNOWN_RULE_CWE[normalized_rule]
        return _CWE_FAMILY_MAP.get(num, f"CWE-{num}")
    return None


def line_bucket_for_location(location: Mapping[str, Any], *, bucket_size: int = 5) -> int:
    start_line = max(1, int(location.get("start_line") or 1))
    return (start_line - 1) // max(1, bucket_size)


def _spans_corroborate(loc_a: Mapping[str, Any], loc_b: Mapping[str, Any], *, bucket_size: int = 5) -> bool:
    if loc_a.get("path") != loc_b.get("path"):
        return False
    a_start, a_end = int(loc_a.get("start_line") or 1), int(loc_a.get("end_line") or 1)
    b_start, b_end = int(loc_b.get("start_line") or 1), int(loc_b.get("end_line") or 1)
    if line_bucket_for_location(loc_a, bucket_size=bucket_size) == line_bucket_for_location(loc_b, bucket_size=bucket_size):
        return True
    return a_start <= b_end + 2 and b_start <= a_end + 2


def _prefer_trace(existing: dict[str, Any] | None, incoming: dict[str, Any] | None) -> dict[str, Any] | None:
    if existing is None:
        return incoming
    if incoming is None:
        return existing
    return incoming if len(incoming.get("steps") or ()) > len(existing.get("steps") or ()) else existing


def build_envelope(
    *, tool: Mapping[str, Any], target_fingerprint: str, applicability: Mapping[str, Any],
    coverage_scope: Mapping[str, Any], gaps: Iterable[object], raw_artifacts: Iterable[Path],
    parser_identity: str, observations: Iterable[Mapping[str, Any]], cataloged_paths: Iterable[str],
    terminal_status: str, run_root: Path, bounds: EvidenceBounds = EvidenceBounds(),
    source_hashes: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    paths = set(cataloged_paths)
    default_tool_id = str(tool.get("id") or tool.get("name") or "unknown")
    bounded_gaps = [str(item) for item in gaps]
    clusters: list[dict[str, Any]] = []
    exact_by_id: dict[str, dict[str, Any]] = {}
    corroborable_by_path_cwe: dict[tuple[str, str], list[dict[str, Any]]] = {}
    raw_scanner_findings = 0

    for observation in observations:
        raw_scanner_findings += 1
        obs_tool_id = str(observation.get("tool_id") or observation.get("scanner_id") or default_tool_id)
        references = merge_native_references(observation.get("_native_refs", ()))
        if not references:
            bounded_gaps.append("provenance_unavailable: observation has no retained native result")
        native = redact_structure({key: value for key, value in observation.items()
                                   if key not in {"_native_refs", "_native_selector", "tool_id", "scanner_id"}})
        message, truncated = _text(native.get("message", ""), bounds.max_field_bytes)
        if truncated:
            bounded_gaps.append("one or more normalized fields were truncated")
        location = safe_location(native.get("path"), native.get("start_line"), native.get("end_line"), paths)
        if location is not None and source_hashes and source_hashes.get(location["path"]):
            location["source_sha256"] = source_hashes[location["path"]]
        record: dict[str, Any] = {
            "native_rule_id": _text(native.get("rule_id", "unknown"), bounds.max_field_bytes)[0],
            "native_severity": _text(native.get("severity", "UNKNOWN"), 128)[0],
            "severity": severity(native.get("severity")),
            "category": _text(native.get("category", "unspecified"), 256)[0],
            "message": message, "location": location,
            "component": native.get("component"), "package": native.get("package"),
            "advisory": native.get("advisory"), "language": native.get("language"),
        }
        for field in ("version", "purl", "repository_url", "raw_selector"):
            if native.get(field) is not None:
                rendered, field_truncated = _text(native[field], bounds.max_field_bytes)
                if field_truncated:
                    bounded_gaps.append(f"normalized {field} exceeded its field bound")
                else:
                    record[field] = rendered
        rule_mapping = _rule_mapping(native.get("rule_mapping"))
        if rule_mapping is not None:
            record["rule_mapping"] = rule_mapping
        trace = normalize_dataflow_trace(native.get("dataflow_trace"), paths, bounds.max_field_bytes)
        if trace is not None:
            record["dataflow_trace"] = trace
        if location is None:
            record["artifact_evidence"] = True
        location_gaps: tuple[str, ...] = ()
        if location is None and native.get("path"):
            bounded_gaps.append("location_unresolved: native source path is not in the accepted catalog")
            location_gaps = ("location_unresolved",)
        record["evidence_id"] = "evidence-" + hashlib.sha256(canonical_json(record)).hexdigest()[:24]

        rule_tag = f"{obs_tool_id}:{record['native_rule_id']}"
        cwe_family = extract_cwe_family(record) if record["category"] == "source_sast" else None

        if record["evidence_id"] in exact_by_id:
            entry = exact_by_id[record["evidence_id"]]
            entry["ref_batches"].append(references)
            entry["scanners"].add(obs_tool_id)
            entry["rule_ids"].add(rule_tag)
            merged_trace = _prefer_trace(entry["record"].get("dataflow_trace"), trace)
            if merged_trace is not None:
                entry["record"]["dataflow_trace"] = merged_trace
            continue

        matched_cluster: dict[str, Any] | None = None
        if location is not None and cwe_family is not None:
            for candidate in corroborable_by_path_cwe.get((location["path"], cwe_family), ()):
                if _spans_corroborate(candidate["record"]["location"], location):
                    matched_cluster = candidate
                    break

        if matched_cluster is not None:
            matched_cluster["ref_batches"].append(references)
            matched_cluster["scanners"].add(obs_tool_id)
            matched_cluster["rule_ids"].add(rule_tag)
            existing_rec = matched_cluster["record"]
            if _SEVERITY_RANK.get(record["severity"], 0) > _SEVERITY_RANK.get(existing_rec["severity"], 0):
                existing_rec["severity"] = record["severity"]
            merged_trace = _prefer_trace(existing_rec.get("dataflow_trace"), trace)
            if merged_trace is not None:
                existing_rec["dataflow_trace"] = merged_trace
            existing_loc = existing_rec["location"]
            existing_loc["start_line"] = min(int(existing_loc["start_line"]), int(location["start_line"]))
            existing_loc["end_line"] = max(int(existing_loc["end_line"]), int(location["end_line"]))
            continue

        entry = {
            "record": record, "ref_batches": [references], "scanners": {obs_tool_id},
            "rule_ids": {rule_tag}, "cwe_family": cwe_family, "location_gaps": location_gaps,
        }
        clusters.append(entry)
        exact_by_id[record["evidence_id"]] = entry
        if location is not None and cwe_family is not None:
            corroborable_by_path_cwe.setdefault((location["path"], cwe_family), []).append(entry)

    records: list[dict[str, Any]] = []
    total = 0
    corroborated_clusters = 0

    for entry in clusters:
        record = entry["record"]
        scanners_sorted = sorted(entry["scanners"])
        rules_sorted = sorted(entry["rule_ids"])
        if len(rules_sorted) > 1 or len(scanners_sorted) > 1:
            record["corroborating_scanners"] = scanners_sorted
            record["corroboration_count"] = len(scanners_sorted)
            record["scanner_rule_ids"] = rules_sorted
            if entry["cwe_family"] is not None:
                record["cwe_family"] = entry["cwe_family"]
            corroborated_clusters += 1
            record["evidence_id"] = "evidence-" + hashlib.sha256(canonical_json(record)).hexdigest()[:24]

        first_refs = entry["ref_batches"][0] if entry["ref_batches"] else []
        common = common_metadata(
            {"tool_id": default_tool_id, **record},
            evidence_refs=first_refs, payload_schema="appsec-review/static-tool-evidence/2",
            record_kind="observation" if record["category"] == "software_inventory" else "finding",
            gaps=entry["location_gaps"],
        )
        if len(records) >= bounds.max_records:
            bounded_gaps.append("normalized record count bound reached")
            continue
        record["common"] = common
        encoded = canonical_json(record)
        if total + len(encoded) > bounds.max_total_bytes:
            bounded_gaps.append("normalized total byte bound reached")
            continue
        total += len(encoded)
        for extra_refs in entry["ref_batches"][1:]:
            merged = merge_native_references(record["common"]["evidence_refs"], extra_refs)
            delta = len(canonical_json(merged)) - len(canonical_json(record["common"]["evidence_refs"]))
            if total + delta > bounds.max_total_bytes:
                bounded_gaps.append("normalized total byte bound reached")
                continue
            record["common"]["evidence_refs"] = merged
            total += delta
        records.append(record)

    taint_traces_preserved = sum(1 for item in records if item.get("dataflow_trace") is not None)
    artifacts = [reference(run_root, path) for path in raw_artifacts]
    return {
        "schema": "appsec-review/static-tool-evidence/2",
        "tool": dict(tool), "target_fingerprint": target_fingerprint,
        "applicability": dict(applicability), "coverage_scope": dict(coverage_scope),
        "exclusions_and_gaps": list(dict.fromkeys(bounded_gaps)),
        "raw_artifacts": artifacts, "parser_identity": parser_identity,
        "records": records, "record_count": len(records), "terminal_status": terminal_status,
        "security_findings": [],
        "telemetry": {
            "raw_scanner_findings": raw_scanner_findings,
            "corroborated_clusters": corroborated_clusters,
            "taint_traces_preserved": taint_traces_preserved,
            "post_dedupe_capped_count": len(records),
        },
    }


def corroborate_sast_records(
    tool_envelopes: Mapping[str, Mapping[str, Any]],
    *,
    target_fingerprint: str,
    max_findings_per_scope: int = 5_000,
) -> dict[str, Any]:
    if type(max_findings_per_scope) is not int or not 1 <= max_findings_per_scope <= 1_000_000:
        raise ValueError("max_findings_per_scope must be an integer in [1, 1000000]")
    clusters: list[dict[str, Any]] = []
    by_path_cwe: dict[tuple[str, str], list[dict[str, Any]]] = {}
    exact_fallback: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    raw_scanner_findings = 0

    for tool_id in sorted(tool_envelopes):
        envelope = tool_envelopes[tool_id]
        env_records = list(envelope.get("records") or ())
        env_telemetry = envelope.get("telemetry") if isinstance(envelope.get("telemetry"), Mapping) else {}
        raw_scanner_findings += max(len(env_records), int(env_telemetry.get("raw_scanner_findings", len(env_records))))
        for rec in env_records:
            if not isinstance(rec, Mapping) or rec.get("category") != "source_sast":
                continue
            loc = rec.get("location") if isinstance(rec.get("location"), Mapping) else None
            cwe_family = extract_cwe_family(rec)
            rule_id = str(rec.get("native_rule_id") or rec.get("rule_id") or "unknown")
            scanners = set(rec.get("corroborating_scanners") or [tool_id])
            scanners.add(tool_id)
            rule_ids = set(rec.get("scanner_rule_ids") or [f"{tool_id}:{rule_id}"])
            rule_ids.add(f"{tool_id}:{rule_id}")
            trace = rec.get("dataflow_trace") if isinstance(rec.get("dataflow_trace"), Mapping) else None
            refs = list((rec.get("common") or {}).get("evidence_refs") or ())

            if loc is not None and cwe_family is not None:
                path_str = str(loc.get("path") or "")
                matched = None
                for candidate in by_path_cwe.get((path_str, cwe_family), ()):
                    if _spans_corroborate(candidate["location"], loc):
                        matched = candidate
                        break
                if matched is not None:
                    matched["scanners"].update(scanners)
                    matched["rule_ids"].update(rule_ids)
                    if _SEVERITY_RANK.get(str(rec.get("severity")), 0) > _SEVERITY_RANK.get(matched["severity"], 0):
                        matched["severity"] = str(rec.get("severity"))
                    matched["dataflow_trace"] = _prefer_trace(matched["dataflow_trace"], dict(trace) if trace else None)
                    matched["location"]["start_line"] = min(int(matched["location"]["start_line"]), int(loc.get("start_line") or 1))
                    matched["location"]["end_line"] = max(int(matched["location"]["end_line"]), int(loc.get("end_line") or 1))
                    matched["evidence_refs"] = merge_native_references(matched["evidence_refs"], refs)
                    continue
                cluster = {
                    "cwe_family": cwe_family, "severity": str(rec.get("severity") or "UNKNOWN"),
                    "category": "source_sast", "message": str(rec.get("message") or ""),
                    "location": dict(loc), "language": rec.get("language"),
                    "rule_mapping": dict(rec["rule_mapping"]) if isinstance(rec.get("rule_mapping"), Mapping) else None,
                    "scanners": scanners, "rule_ids": rule_ids,
                    "dataflow_trace": dict(trace) if trace is not None else None,
                    "evidence_refs": merge_native_references(refs),
                }
                clusters.append(cluster)
                by_path_cwe.setdefault((path_str, cwe_family), []).append(cluster)
            else:
                path_str = str(loc.get("path") or "") if loc is not None else ""
                start_line = int(loc.get("start_line") or 1) if loc is not None else 0
                fb_key = (path_str, rule_id, start_line, str(rec.get("message") or ""))
                if fb_key in exact_fallback:
                    existing = exact_fallback[fb_key]
                    existing["scanners"].update(scanners)
                    existing["rule_ids"].update(rule_ids)
                    existing["dataflow_trace"] = _prefer_trace(existing["dataflow_trace"], dict(trace) if trace else None)
                    existing["evidence_refs"] = merge_native_references(existing["evidence_refs"], refs)
                    continue
                cluster = {
                    "cwe_family": cwe_family, "severity": str(rec.get("severity") or "UNKNOWN"),
                    "category": "source_sast", "message": str(rec.get("message") or ""),
                    "location": dict(loc) if loc is not None else None, "language": rec.get("language"),
                    "rule_mapping": dict(rec["rule_mapping"]) if isinstance(rec.get("rule_mapping"), Mapping) else None,
                    "scanners": scanners, "rule_ids": rule_ids,
                    "dataflow_trace": dict(trace) if trace is not None else None,
                    "evidence_refs": merge_native_references(refs),
                }
                clusters.append(cluster)
                exact_fallback[fb_key] = cluster

    by_scope: dict[str, list[dict[str, Any]]] = {}
    for cluster in clusters:
        loc = cluster["location"]
        if isinstance(loc, Mapping) and loc.get("path"):
            parts = PurePosixPath(str(loc["path"])).parts
            scope = parts[0] if len(parts) > 1 else "."
        else:
            scope = "."
        by_scope.setdefault(scope, []).append(cluster)

    emitted: list[dict[str, Any]] = []
    cap = max_findings_per_scope
    for scope in sorted(by_scope):
        ranked = sorted(
            by_scope[scope],
            key=lambda item: (
                -len(item["scanners"]),
                -(1 if item["dataflow_trace"] is not None else 0),
                -_SEVERITY_RANK.get(item["severity"], 0),
                str((item["location"] or {}).get("path") or ""),
                int((item["location"] or {}).get("start_line") or 0),
                sorted(item["rule_ids"])[0],
            ),
        )
        for item in ranked[:cap]:
            corroborating_scanners = sorted(item["scanners"])
            scanner_rule_ids = sorted(item["rule_ids"])
            cluster_payload: dict[str, Any] = {
                "cwe_family": item["cwe_family"], "severity": item["severity"],
                "category": item["category"], "message": item["message"],
                "location": item["location"],
                "corroborating_scanners": corroborating_scanners,
                "corroboration_count": len(corroborating_scanners),
                "scanner_rule_ids": scanner_rule_ids,
                "dataflow_trace": item["dataflow_trace"],
            }
            if item.get("language") is not None:
                cluster_payload["language"] = item["language"]
            if item.get("rule_mapping") is not None:
                cluster_payload["rule_mapping"] = item["rule_mapping"]
            if item.get("evidence_refs"):
                cluster_payload["evidence_refs"] = item["evidence_refs"]
            cluster_id = "sast-cluster-" + hashlib.sha256(canonical_json(cluster_payload)).hexdigest()[:24]
            emitted.append({"cluster_id": cluster_id, **cluster_payload})

    corroborated_clusters = sum(
        1 for item in emitted if item["corroboration_count"] > 1 or len(item["scanner_rule_ids"]) > 1
    )
    taint_traces_preserved = sum(1 for item in emitted if item.get("dataflow_trace") is not None)
    return {
        "schema": "appsec-review/corroborated-sast-evidence/1",
        "target_fingerprint": target_fingerprint,
        "max_findings_per_scope": cap,
        "cluster_count": len(emitted),
        "clusters": emitted,
        "telemetry": {
            "raw_scanner_findings": raw_scanner_findings,
            "corroborated_clusters": corroborated_clusters,
            "taint_traces_preserved": taint_traces_preserved,
            "post_dedupe_capped_count": len(emitted),
        },
    }


def write_envelope(path: Path, envelope: Mapping[str, Any]) -> dict[str, Any]:
    atomic_json(path, dict(envelope))
    return {"path": path.as_posix(), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}
