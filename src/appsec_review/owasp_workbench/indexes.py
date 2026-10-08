from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.storage import atomic_json, canonical_json, file_sha256


INDEX_SCHEMA = "appsec-review/owasp-index-shard/1"
MANIFEST_SCHEMA = "appsec-review/owasp-index-manifest/1"
FAMILIES = {
    "standards", "component-classification", "applicability", "validation-work",
    "control-result", "finding-package",
}


def _safe(value: str) -> str:
    if not value or len(value) > 128 or any(character not in
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for character in value):
        raise ValueError("index shard identity is invalid")
    return value


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def publish_shard(run_root: Path, *, family: str, shard_id: str,
                  records: Sequence[Mapping[str, Any]], fingerprint_inputs: Mapping[str, Any],
                  gaps: Sequence[str] = ()) -> dict[str, Any]:
    if family not in FAMILIES:
        raise ValueError(f"unknown OWASP index family: {family}")
    shard_id = _safe(shard_id)
    fingerprint = _fingerprint({"family": family, "shard_id": shard_id,
                                "inputs": fingerprint_inputs})
    document = {
        "schema": INDEX_SCHEMA, "family": family, "shard_id": shard_id,
        "fingerprint": fingerprint, "records": [dict(item) for item in records],
        "gaps": list(gaps),
    }
    document["records_sha256"] = _fingerprint(document["records"])
    relative = Path("data") / "indexes" / "owasp" / family / shard_id / f"{fingerprint}.json"
    path = Path(run_root) / relative
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing != document:
            raise ValueError("immutable OWASP index shard conflicts with existing bytes")
    else:
        atomic_json(path, document)
    return {"family": family, "shard_id": shard_id, "schema": INDEX_SCHEMA,
            "fingerprint": fingerprint, "sha256": file_sha256(path),
            "path": relative.as_posix(), "record_count": len(records), "gaps": list(gaps)}


def publish_manifest(run_root: Path, *, run_id: str, shards: Sequence[Mapping[str, Any]],
                     accepted_upstream_manifest: Mapping[str, Any],
                     configuration_sha256: str) -> dict[str, Any]:
    identities = sorted((dict(value) for value in shards),
                        key=lambda value: (value["family"], value["shard_id"]))
    if len({(item["family"], item["shard_id"]) for item in identities}) != len(identities):
        raise ValueError("OWASP index manifest contains duplicate shard identities")
    manifest = {"schema": MANIFEST_SCHEMA, "run_id": run_id, "shards": identities,
                "accepted_upstream_manifest": dict(accepted_upstream_manifest),
                "configuration_sha256": configuration_sha256}
    manifest["fingerprint"] = _fingerprint(manifest)
    relative = Path("data") / "indexes" / "owasp" / "manifests" / f"{manifest['fingerprint']}.json"
    path = Path(run_root) / relative
    atomic_json(path, manifest)
    pointer = Path(run_root) / "data" / "indexes" / "owasp" / "accepted.json"
    atomic_json(pointer, {"schema": "appsec-review/owasp-index-pointer/1",
                          "run_id": run_id, "manifest_path": relative.as_posix(),
                          "manifest_sha256": file_sha256(path),
                          "fingerprint": manifest["fingerprint"]})
    return {"path": relative.as_posix(), "sha256": file_sha256(path),
            "fingerprint": manifest["fingerprint"], "shard_count": len(identities)}


class WorkbenchIndex:
    """Bounded, run-isolated query over the accepted immutable OWASP shard manifest."""

    _FILTERS = {"standard", "version", "profile", "control", "component", "project",
                "evidence_mode", "validator", "batch", "disposition", "shard"}

    def __init__(self, runs_dir: Path, run_id: str):
        if not run_id or Path(run_id).name != run_id:
            raise ValueError("run id is invalid")
        self.runs_dir = Path(runs_dir).resolve()
        self.run_root = (self.runs_dir / run_id).resolve()
        if self.runs_dir not in self.run_root.parents or not self.run_root.is_dir():
            raise ValueError("run is unavailable")
        pointer = json.loads((self.run_root / "data" / "indexes" / "owasp" / "accepted.json").read_text(
            encoding="utf-8"))
        if pointer.get("run_id") != run_id:
            raise ValueError("accepted OWASP index belongs to another run")
        manifest_path = (self.run_root / str(pointer.get("manifest_path", ""))).resolve()
        if self.run_root not in manifest_path.parents or file_sha256(manifest_path) != pointer.get("manifest_sha256"):
            raise ValueError("accepted OWASP index manifest cannot be resolved")
        self.manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if self.manifest.get("schema") != MANIFEST_SCHEMA or self.manifest.get("run_id") != run_id:
            raise ValueError("accepted OWASP index manifest is invalid")
        self.run_id = run_id

    @staticmethod
    def _value(record: Mapping[str, Any], key: str) -> Any:
        aliases = {
            "control": ("control_identity", "control_id", "id"),
            "component": ("component_id",), "project": ("project_id",),
            "validator": ("validator", "role"), "batch": ("batch_id",),
            "disposition": ("outcome", "status", "control_status"),
            "standard": ("standard", "family"), "version": ("version",),
            "profile": ("profile",), "evidence_mode": ("evidence_mode",),
        }
        for field in aliases.get(key, (key,)):
            if field in record:
                return record[field]
            assignment = record.get("assignment")
            if isinstance(assignment, Mapping) and field in assignment:
                return assignment[field]
        return None

    def query(self, *, family: str | None = None, limit: int = 50, cursor: str | None = None,
              **filters: str | None) -> dict[str, Any]:
        if family is not None and family not in FAMILIES:
            raise ValueError("unknown OWASP index family")
        unknown = set(filters) - self._FILTERS
        if unknown:
            raise ValueError(f"unknown OWASP query filters: {sorted(unknown)}")
        active = {key: value for key, value in filters.items() if value is not None}
        if any(not isinstance(value, str) or not value or len(value) > 4096 for value in active.values()):
            raise ValueError("OWASP query filters must be bounded strings")
        if not 1 <= limit <= 100:
            raise ValueError("OWASP query result limit exceeds bound")
        request = {"run_id": self.run_id, "family": family, "filters": active, "limit": limit}
        request_hash = _fingerprint(request)
        offset = 0
        if cursor:
            try:
                decoded = json.loads(base64.urlsafe_b64decode(cursor.encode() + b"===").decode())
            except Exception as exc:
                raise ValueError("OWASP query cursor is invalid") from exc
            if decoded.get("request_hash") != request_hash or type(decoded.get("offset")) is not int:
                raise ValueError("OWASP query cursor does not match the request")
            offset = decoded["offset"]
        found = []
        gaps = []
        for identity in self.manifest["shards"]:
            if family is not None and identity["family"] != family:
                continue
            if "shard" in active and identity["shard_id"] != active["shard"]:
                continue
            path = (self.run_root / identity["path"]).resolve()
            if self.run_root not in path.parents or file_sha256(path) != identity["sha256"]:
                gaps.append(f"{identity['family']}/{identity['shard_id']}: shard resolution failed")
                continue
            document = json.loads(path.read_text(encoding="utf-8"))
            gaps.extend(f"{identity['family']}/{identity['shard_id']}: {gap}"
                        for gap in document.get("gaps", ()))
            for record in document["records"]:
                if all(str(self._value(record, key)) == expected for key, expected in active.items()
                       if key != "shard"):
                    found.append({"run_id": self.run_id, "index_family": identity["family"],
                                  "shard_id": identity["shard_id"],
                                  "index_sha256": identity["sha256"], "record": record})
        found.sort(key=lambda item: (item["index_family"], item["shard_id"], _fingerprint(item["record"])))
        page = found[offset:offset + limit]
        next_cursor = None
        if offset + limit < len(found):
            next_cursor = base64.urlsafe_b64encode(canonical_json(
                {"request_hash": request_hash, "offset": offset + limit})).decode().rstrip("=")
        return {"schema": "appsec-review/owasp-query-response/1", "run_id": self.run_id,
                "manifest_identity": {"fingerprint": self.manifest["fingerprint"]},
                "results": page, "pagination": {"limit": limit, "offset": offset,
                "next_cursor": next_cursor, "truncated": next_cursor is not None},
                "ambiguity": [], "coverage_gaps": sorted(set(gaps))}
