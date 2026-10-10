from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Iterable, Mapping

from appsec_review.storage import atomic_json, canonical_json, file_sha256


SECRET_FIELDS = {"secret", "match", "password", "token", "apikey", "api_key", "private_key"}
NORMALIZER_IDENTITY = "static-evidence/3"
_ASSIGNMENT = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*([\"']?)([^\s,;\"']+)\2"
)


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
    """Bounded rule-pack mapping metadata (for example the SEI CERT identifier) from the native rule."""
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
    try:
        first = max(1, int(start_line or 1))
        last = max(first, int(end_line or first))
    except (TypeError, ValueError):
        first = last = 1
    return {"path": candidate, "start_line": first, "end_line": last}


def build_envelope(
    *, tool: Mapping[str, Any], target_fingerprint: str, applicability: Mapping[str, Any],
    coverage_scope: Mapping[str, Any], gaps: Iterable[object], raw_artifacts: Iterable[Path],
    parser_identity: str, observations: Iterable[Mapping[str, Any]], cataloged_paths: Iterable[str],
    terminal_status: str, run_root: Path, bounds: EvidenceBounds = EvidenceBounds(),
    source_hashes: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    paths = set(cataloged_paths)
    records: list[dict[str, Any]] = []
    seen_evidence_ids: set[str] = set()
    bounded_gaps = [str(item) for item in gaps]
    total = 0
    for observation in observations:
        if len(records) >= bounds.max_records:
            bounded_gaps.append("normalized record count bound reached")
            break
        native = redact_structure(dict(observation))
        message, truncated = _text(native.get("message", ""), bounds.max_field_bytes)
        if truncated:
            bounded_gaps.append("one or more normalized fields were truncated")
        location = safe_location(native.get("path"), native.get("start_line"),
                                 native.get("end_line"), paths)
        if location is not None and source_hashes and source_hashes.get(location["path"]):
            location["source_sha256"] = source_hashes[location["path"]]
        record = {
            "native_rule_id": _text(native.get("rule_id", "unknown"), bounds.max_field_bytes)[0],
            "native_severity": _text(native.get("severity", "UNKNOWN"), 128)[0],
            "severity": severity(native.get("severity")),
            "category": _text(native.get("category", "unspecified"), 256)[0],
            "message": message,
            "location": location,
            "component": native.get("component"),
            "package": native.get("package"),
            "advisory": native.get("advisory"),
            "language": native.get("language"),
        }
        rule_mapping = _rule_mapping(native.get("rule_mapping"))
        if rule_mapping is not None:
            record["rule_mapping"] = rule_mapping
        if location is None:
            record["artifact_evidence"] = True
        record["evidence_id"] = "evidence-" + hashlib.sha256(canonical_json(record)).hexdigest()[:24]
        if record["evidence_id"] in seen_evidence_ids:
            continue
        seen_evidence_ids.add(record["evidence_id"])
        encoded = canonical_json(record)
        if total + len(encoded) > bounds.max_total_bytes:
            bounded_gaps.append("normalized total byte bound reached")
            break
        total += len(encoded)
        records.append(record)
    artifacts = []
    for path in raw_artifacts:
        resolved = path.resolve(strict=True)
        if run_root.resolve() not in resolved.parents:
            raise ValueError("raw tool artifact is not run-owned")
        artifacts.append({"path": resolved.relative_to(run_root).as_posix(),
                          "sha256": file_sha256(resolved), "size_bytes": resolved.stat().st_size})
    return {
        "schema": "appsec-review/static-tool-evidence/1",
        "tool": dict(tool), "target_fingerprint": target_fingerprint,
        "applicability": dict(applicability), "coverage_scope": dict(coverage_scope),
        "exclusions_and_gaps": list(dict.fromkeys(bounded_gaps)),
        "raw_artifacts": artifacts, "parser_identity": parser_identity,
        "records": records, "record_count": len(records), "terminal_status": terminal_status,
        "security_findings": [],
    }


def write_envelope(path: Path, envelope: Mapping[str, Any]) -> dict[str, Any]:
    atomic_json(path, dict(envelope))
    return {"path": path.as_posix(), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}
