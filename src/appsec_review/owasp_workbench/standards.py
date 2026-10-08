from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from appsec_review.storage import canonical_json


CATALOG_SCHEMA = "appsec-review/owasp-catalog/1"
CONTROL_AUTHORITIES = {"ASVS", "MASVS"}
SUPPORTED_FAMILIES = {
    "ASVS": "control",
    "MASVS": "control",
    "MASTG": "supporting_test",
    "OWASP_API_TOP_10": "routing_context",
    "OWASP_TOP_10": "routing_context",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def file_sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


@dataclass(frozen=True, slots=True)
class StandardCatalog:
    family: str
    version: str
    authority: str
    records: tuple[Mapping[str, Any], ...]
    source: Mapping[str, Any]
    catalog_sha256: str
    fixture: bool

    @property
    def snapshot_id(self) -> str:
        return f"{self.family}:{self.version}:sha256-{self.catalog_sha256[:16]}"

    def identity(self, native_id: str) -> str:
        return f"{self.family}:{self.version}:{native_id}"


def load_catalog(repository_root: Path, family: str, settings: Mapping[str, Any]) -> StandardCatalog:
    if family not in SUPPORTED_FAMILIES:
        raise ValueError(f"unsupported OWASP family: {family}")
    relative = Path(str(settings.get("catalog_path", "")))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{family} catalog path must be repository-relative")
    path = (Path(repository_root).resolve() / relative).resolve()
    if Path(repository_root).resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError(f"{family} catalog is unavailable")
    document = json.loads(path.read_text(encoding="utf-8"))
    expected = str(settings.get("catalog_sha256", ""))
    actual = digest(document)
    if not SHA256.fullmatch(expected) or actual != expected:
        raise ValueError(f"{family} catalog hash mismatch")
    if document.get("schema") != CATALOG_SCHEMA:
        raise ValueError(f"{family} catalog schema is unsupported")
    if document.get("family") != family or document.get("authority") != SUPPORTED_FAMILIES[family]:
        raise ValueError(f"{family} catalog authority mismatch")
    version = str(settings.get("version", ""))
    if not version or document.get("version") != version:
        raise ValueError(f"{family} catalog version mismatch")
    upstream = document.get("upstream")
    required = {"repository", "ref", "commit", "license"}
    if not isinstance(upstream, Mapping) or not required <= set(upstream):
        raise ValueError(f"{family} upstream identity is incomplete")
    for field in required:
        if str(settings.get(field, "")) != str(upstream.get(field, "")):
            raise ValueError(f"{family} pinned {field} mismatch")
    if not re.fullmatch(r"[0-9a-f]{40}", str(upstream["commit"])):
        raise ValueError(f"{family} upstream commit is not immutable")
    records = document.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError(f"{family} catalog is empty")
    ids: set[str] = set()
    normalized = []
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise ValueError(f"{family} record {index} is not an object")
        native_id = str(record.get("id", ""))
        if not native_id or native_id in ids or not str(record.get("text", "")).strip():
            raise ValueError(f"{family} record identity/text is invalid or duplicated")
        ids.add(native_id)
        normalized.append(dict(record))
    return StandardCatalog(
        family=family,
        version=version,
        authority=SUPPORTED_FAMILIES[family],
        records=tuple(normalized),
        source={key: str(upstream[key]) for key in sorted(required)},
        catalog_sha256=actual,
        fixture=bool(document.get("fixture", False)),
    )


def load_catalogs(repository_root: Path, sources: Mapping[str, Any]) -> dict[str, StandardCatalog]:
    if set(sources) != set(SUPPORTED_FAMILIES):
        raise ValueError("OWASP source configuration must select every supported family exactly once")
    catalogs = {family: load_catalog(repository_root, family, sources[family])
                for family in sorted(sources)}
    masvs = {str(item["id"]) for item in catalogs["MASVS"].records}
    for test in catalogs["MASTG"].records:
        if any(str(control) not in masvs for control in test.get("supports", ())):
            raise ValueError("MASTG crosswalk references an unknown MASVS control")
    return catalogs


def standards_manifest(catalogs: Mapping[str, StandardCatalog]) -> dict[str, Any]:
    sources = []
    gaps = []
    for family in sorted(catalogs):
        catalog = catalogs[family]
        sources.append({
            "family": family,
            "version": catalog.version,
            "authority": catalog.authority,
            "snapshot_id": catalog.snapshot_id,
            "catalog_sha256": catalog.catalog_sha256,
            "record_count": len(catalog.records),
            "upstream": dict(catalog.source),
            "fixture": catalog.fixture,
        })
        if catalog.fixture:
            gaps.append(f"{family} uses a pinned abridged fixture; live upstream refresh is unverified")
    payload = {"schema": "appsec-review/owasp-standards-manifest/1", "sources": sources,
               "gaps": gaps}
    payload["fingerprint"] = digest(payload)
    return payload


def control_records(catalogs: Mapping[str, StandardCatalog], *, asvs_level: int,
                    masvs_profile: str) -> tuple[dict[str, Any], ...]:
    if asvs_level not in {1, 2, 3}:
        raise ValueError("ASVS level must be 1, 2, or 3")
    if masvs_profile not in {"L1", "L2"}:
        raise ValueError("MASVS profile must be L1 or L2")
    values = []
    for family in sorted(CONTROL_AUTHORITIES):
        catalog = catalogs[family]
        for raw in catalog.records:
            if family == "ASVS" and asvs_level not in raw.get("levels", ()):
                continue
            if family == "MASVS" and masvs_profile not in raw.get("profiles", ()):
                continue
            record = dict(raw)
            record.update({"family": family, "version": catalog.version,
                           "control_identity": catalog.identity(str(raw["id"])),
                           "catalog_sha256": catalog.catalog_sha256})
            if family == "MASVS":
                record["supporting_tests"] = sorted(
                    catalogs["MASTG"].identity(str(test["id"]))
                    for test in catalogs["MASTG"].records if raw["id"] in test.get("supports", ()))
            values.append(record)
    return tuple(sorted(values, key=lambda item: item["control_identity"]))
