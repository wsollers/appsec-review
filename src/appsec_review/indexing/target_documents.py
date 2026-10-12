"""Bounded extraction of target-owned contracts and intent artifacts.

This parser consumes a catalog-style, hash-pinned file inventory. Its output is
data for later indexing; it does not establish that a declared control is enforced.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from itertools import islice
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from appsec_review.retrieval.model import normalize_relative_path


KINDS = frozenset({"design", "threat_model", "dfd", "openapi", "postman", "unit_test"})
METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"})
_HEADING = re.compile(r"^#{1,6} +(.+?)\s*$")
_THREAT = re.compile(r"^\|\s*([STRIDE]\d+)\s*\|(.+?)\|\s*(TB\d+(?:/TB\d+)*)\s*\|(.+?)\|(.+?)\|\s*$")
_BOUNDARY = re.compile(r"^- \*\*(TB\d+)\s*[—-]\s*(.+?)\*\*:")
_TEST = re.compile(r"\b(?:it|test)\s*\(\s*(['\"`])(.+?)\1")
_ROUTE = re.compile(r"\.(get|post|put|patch|delete)\(\s*(['\"`])(/[^'\"`]+)\2")
_HEX = re.compile(r"^[0-9a-f]{64}$")


class InventoryIntegrityError(ValueError):
    """An accepted inventory cannot be resolved to the exact target bytes."""


@dataclass(frozen=True)
class DocumentResult:
    records: tuple[dict[str, Any], ...]
    links: tuple[dict[str, Any], ...]
    gaps: tuple[dict[str, str], ...]


def _route(value: str) -> str:
    path = urlsplit(value.replace("{{baseUrl}}", "http://fixture.invalid")).path
    path = re.sub(r"/\{\{[^}]+\}\}", "/{id}", path)
    return re.sub(r"/\d+(?=/|$)", "/{id}", path).rstrip("/") or "/"


def collect_target_documents(
    target_root: Path, target_snapshot: str, inventory: Iterable[Mapping[str, str]], *,
    max_files: int = 128, max_file_bytes: int = 256_000, max_records: int = 2_000,
) -> DocumentResult:
    """Extract bounded facts from an accepted inventory, without executing target code.

    Inventory entries require ``path``, ``sha256`` and ``kind``. The caller is
    responsible for selecting entries from the accepted target catalog.
    """
    if not target_snapshot:
        raise ValueError("target snapshot is required")
    if min(max_files, max_file_bytes, max_records) < 1:
        raise ValueError("collection bounds must be positive")
    root = target_root.resolve()
    records: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []
    entries = list(islice(inventory, max_files + 1))
    if len(entries) > max_files:
        gaps.append({"path": "", "reason": "file_limit", "detail": str(max_files)})

    def emit(path: str, sha: str, kind: str, subtype: str, line: int, text: str,
             fields: Mapping[str, Any] | None = None) -> None:
        if len(records) >= max_records:
            if not any(gap["reason"] == "record_limit" for gap in gaps):
                gaps.append({"path": path, "reason": "record_limit", "detail": str(max_records)})
            return
        record_id = hashlib.sha256(json.dumps([target_snapshot, path, sha, kind, subtype, line, text],
                                               ensure_ascii=False).encode()).hexdigest()
        records.append({"id": record_id, "target_snapshot": target_snapshot, "path": path,
                        "file_sha256": sha, "kind": kind, "subtype": subtype,
                        "authority": "declared" if kind == "openapi" else "intent",
                        "line": line, "text": text[:500], "fields": dict(fields or {})})

    for entry in entries[:max_files]:
        raw_path, sha, kind = entry.get("path", ""), entry.get("sha256", ""), entry.get("kind", "")
        try:
            path = normalize_relative_path(raw_path)
        except ValueError as exc:
            raise InventoryIntegrityError(f"invalid accepted target path: {raw_path}") from exc
        if kind not in KINDS or not _HEX.fullmatch(sha):
            raise InventoryIntegrityError(f"invalid accepted inventory entry: {path}")
        source = (root / path).resolve()
        if root not in source.parents or not source.is_file():
            raise InventoryIntegrityError(f"accepted target source missing or escaped: {path}")
        if source.stat().st_size > max_file_bytes:
            gaps.append({"path": path, "reason": "byte_limit", "detail": str(max_file_bytes)})
            continue
        raw = source.read_bytes()
        if len(raw) > max_file_bytes:
            gaps.append({"path": path, "reason": "byte_limit", "detail": str(max_file_bytes)})
            continue
        if hashlib.sha256(raw).hexdigest() != sha:
            raise InventoryIntegrityError(f"accepted target source hash mismatch: {path}")
        try:
            content = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            gaps.append({"path": path, "reason": "decode_error", "detail": "UTF-8 required"})
            continue
        lines = content.splitlines()

        if kind in {"design", "threat_model", "dfd"}:
            for number, line in enumerate(lines, 1):
                heading = _HEADING.match(line)
                if heading:
                    emit(path, sha, kind, "heading", number, heading.group(1))
                if kind == "threat_model":
                    threat = _THREAT.match(line)
                    if threat:
                        emit(path, sha, kind, "threat", number, line,
                             {"threat_id": threat.group(1), "boundaries": threat.group(3).split("/"),
                              "mitigation": threat.group(5).strip()})
                if kind == "dfd":
                    boundary = _BOUNDARY.match(line)
                    if boundary:
                        emit(path, sha, kind, "boundary", number, line,
                             {"boundary_id": boundary.group(1)})
                    if "-->" in line:
                        emit(path, sha, kind, "flow", number, line.strip())
        elif kind == "unit_test":
            for number, line in enumerate(lines, 1):
                match = _TEST.search(line)
                if match:
                    emit(path, sha, kind, "case", number, match.group(2))
                route = _ROUTE.search(line)
                if route:
                    emit(path, sha, kind, "request", number, line.strip(),
                         {"method": route.group(1).upper(), "route": _route(route.group(3))})
        elif kind == "openapi" and source.suffix.lower() != ".json":
            gaps.append({"path": path, "reason": "unsupported_format",
                         "detail": "OpenAPI source must be a materialized JSON document"})
        else:
            try:
                document = json.loads(content)
            except (ValueError, TypeError):
                gaps.append({"path": path, "reason": "parse_error", "detail": "invalid JSON"})
                continue
            if kind == "openapi":
                if not isinstance(document, dict) or not str(document.get("openapi", "")).startswith("3.") \
                        or not isinstance(document.get("paths"), dict):
                    gaps.append({"path": path, "reason": "parse_error", "detail": "invalid OpenAPI 3 document"})
                    continue
                for route, operations in document["paths"].items():
                    if not isinstance(operations, dict):
                        continue
                    route_line = next((i for i, value in enumerate(lines, 1)
                                       if value.lstrip().startswith(json.dumps(route) + ":")), None)
                    for method, operation in operations.items():
                        if method.upper() not in METHODS or not isinstance(operation, dict):
                            continue
                        method_line = None
                        if route_line is not None:
                            route_indent = len(lines[route_line - 1]) - len(lines[route_line - 1].lstrip())
                            for i in range(route_line, len(lines)):
                                value = lines[i]
                                indent = len(value) - len(value.lstrip())
                                if value.strip() and indent <= route_indent:
                                    break
                                if value.lstrip().startswith(json.dumps(method) + ":"):
                                    method_line = i + 1
                                    break
                        if method_line is None:
                            gaps.append({"path": path, "reason": "unresolved_span",
                                         "detail": f"{method.upper()} {route}"})
                            continue
                        emit(path, sha, kind, "operation", method_line, f"{method.upper()} {route}",
                             {"method": method.upper(), "route": route,
                              "parameters": operation.get("parameters", []),
                              "responses": sorted(operation.get("responses", {})),
                              "request_body": bool(operation.get("requestBody"))})
            else:
                if not isinstance(document, dict) or not isinstance(document.get("item"), list):
                    gaps.append({"path": path, "reason": "parse_error", "detail": "invalid Postman collection"})
                    continue
                url_occurrences: dict[str, int] = {}
                def walk(items: list[Any], depth: int = 0) -> None:
                    if depth > 12:
                        gaps.append({"path": path, "reason": "depth_limit", "detail": "Postman nesting"})
                        return
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        if isinstance(item.get("item"), list):
                            walk(item["item"], depth + 1)
                        request = item.get("request")
                        if not isinstance(request, dict):
                            continue
                        method = str(request.get("method", "")).upper()
                        url = request.get("url", "")
                        raw_url = url.get("raw", "") if isinstance(url, dict) else url
                        if method not in METHODS or not isinstance(raw_url, str):
                            continue
                        route = _route(raw_url)
                        key = "raw" if isinstance(url, dict) else "url"
                        marker = json.dumps(key) + ": " + json.dumps(raw_url)
                        matches = [i for i, value in enumerate(lines, 1) if value.lstrip().startswith(marker)]
                        occurrence = url_occurrences.get(marker, 0)
                        line = matches[occurrence] if occurrence < len(matches) else None
                        url_occurrences[marker] = occurrence + 1
                        if line is None:
                            gaps.append({"path": path, "reason": "unresolved_span", "detail": f"{method} {route}"})
                            continue
                        emit(path, sha, kind, "request", line, f"{method} {route}",
                             {"method": method, "route": route, "name": str(item.get("name", ""))[:200],
                              "assertions": sum(len(event.get("script", {}).get("exec", []))
                                                for event in item.get("event", []) if isinstance(event, dict))})
                walk(document["item"])

    operations = {(r["fields"].get("method"), r["fields"].get("route")): r for r in records
                  if r["kind"] == "openapi" and r["subtype"] == "operation"}
    boundaries = {r["fields"].get("boundary_id"): r for r in records
                  if r["kind"] == "dfd" and r["subtype"] == "boundary"}
    links = []
    for record in records:
        if record["kind"] in {"postman", "unit_test"} and record["subtype"] == "request":
            operation = operations.get((record["fields"]["method"], record["fields"]["route"]))
            if operation:
                links.append({"from": record["id"], "to": operation["id"], "relation": "mentions_route",
                              "authority": "intent", "exact": True})
        if record["kind"] == "threat_model" and record["subtype"] == "threat":
            for boundary_id in record["fields"]["boundaries"]:
                boundary = boundaries.get(boundary_id)
                if boundary:
                    links.append({"from": record["id"], "to": boundary["id"],
                                  "relation": "mentions_boundary", "authority": "intent", "exact": True})
    return DocumentResult(tuple(records), tuple(links), tuple(gaps))
