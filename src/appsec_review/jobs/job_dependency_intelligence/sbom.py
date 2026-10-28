"""Deterministic SPDX 2.3 enrichment of accepted source and native inventories."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime
from functools import lru_cache
import hashlib
from importlib import resources
import json
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from jsonschema import Draft7Validator
from referencing import Registry
from referencing.exceptions import NoSuchResource

from appsec_review.storage import canonical_json

from .native_sbom_contracts import (
    ArtifactRef, CoverageGap, DISCOVERY_IDENTITY, DISCOVERY_SCHEMA, DiscoveryResult,
    MERGE_IDENTITY, NativeCandidate, NativeInputIntegrityError, PROVENANCE_SCHEMA,
    SBOM_COUNTERS, SPDX_VERSION, SbomBounds, SbomResult, SpdxBaseline, SpdxValidationError,
)


_SCHEMA_RESOURCE = "schemas/spdx-2.3.schema.json"
_SCHEMA_SHA256 = "239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b"
_ELEMENTS = ("packages", "files", "snippets", "relationships", "hasExtractedLicensingInfos")
_ID = re.compile(r"SPDXRef-[A-Za-z0-9.-]+\Z")
_DOC_ID = re.compile(r"DocumentRef-[A-Za-z0-9.-]+\Z")
_LICENSE_ID = re.compile(r"LicenseRef-[A-Za-z0-9.-]+\Z")
_LICENSE_TOKEN = re.compile(
    r"(?<![A-Za-z0-9.-])(?:(DocumentRef-[A-Za-z0-9.-]+):)?(LicenseRef-[A-Za-z0-9.-]+)"
)
_LICENSE_FIELDS = frozenset({
    "licenseConcluded", "licenseDeclared", "licenseInfoFromFiles", "licenseInfoInFiles",
    "licenseInfoInSnippets",
})
_REF_LISTS = frozenset({"documentDescribes", "hasFiles", "fileDependencies"})
_REF_FIELDS = frozenset({
    "spdxElementId", "relatedSpdxElement", "snippetFromFile", "reference",
})
_IDENTITY_COLLECTIONS = frozenset({"checksums", "externalRefs"})


def _digest(value: Any) -> str:
    return hashlib.sha256(_encode(value)).hexdigest()


def _encode(value: Any) -> bytes:
    try:
        json.dumps(value, allow_nan=False)
        return canonical_json(value)
    except (TypeError, ValueError, RecursionError) as error:
        raise SpdxValidationError(f"Not finite JSON: {error}") from error


def _sorted_unique(values: Sequence[Any]) -> list[Any]:
    records = {_encode(value): value for value in values}
    return [records[key] for key in sorted(records)]


def _ordered(value: Any) -> Any:
    """SPDX collection order carries no assertion or source-selector meaning."""
    if isinstance(value, Mapping):
        return {key: _ordered(item) for key, item in value.items()}
    if isinstance(value, list):
        return _sorted_unique([_ordered(item) for item in value])
    return value


def _utc(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", value
    ):
        raise SpdxValidationError("created must be an ISO 8601 UTC timestamp ending in Z")
    try:
        datetime.fromisoformat(value)
    except ValueError as error:
        raise SpdxValidationError(f"Invalid UTC created timestamp: {value}") from error


def _reject_retrieval(uri: str) -> Any:
    raise NoSuchResource(ref=uri)


@lru_cache(maxsize=1)
def _validator() -> Draft7Validator:
    data = resources.files(__package__).joinpath(*_SCHEMA_RESOURCE.split("/")).read_bytes()
    if hashlib.sha256(data).hexdigest() != _SCHEMA_SHA256:
        raise SpdxValidationError("Packaged official SPDX schema digest mismatch")
    schema = json.loads(data)
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema, registry=Registry(retrieve=_reject_retrieval))


def schema_sha256() -> str:
    """Return the digest of the verified, locally packaged official release schema."""
    _validator()
    return _SCHEMA_SHA256


def _payload_bounds(value: Any, *, limit: int, field_bytes: int) -> int:
    size = len(_encode(value))
    if size > limit:
        raise SpdxValidationError(f"JSON bytes {size} exceed bound {limit}")
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str) and len(item.encode("utf-8")) > field_bytes:
            raise SpdxValidationError(f"String field exceeds UTF-8 byte bound {field_bytes}")
        if isinstance(item, Mapping):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return size


def _document_bounds(document: Mapping[str, Any], bounds: SbomBounds, *, baseline: bool) -> int:
    count = sum(len(document.get(key, [])) for key in _ELEMENTS
                if isinstance(document.get(key, []), list))
    if count > bounds.element_limit:
        raise SpdxValidationError(f"SPDX elements {count} exceed bound {bounds.element_limit}")
    return _payload_bounds(
        document, limit=bounds.input_bytes if baseline else bounds.output_bytes,
        field_bytes=bounds.field_bytes,
    )


def _namespace(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return bool(parsed.scheme and not parsed.fragment and (
        parsed.netloc or parsed.scheme == "urn" and parsed.path
    ))


def validate_spdx(document: Mapping[str, Any], *, bounds: SbomBounds) -> None:
    """Validate the official schema, closed references, license bindings and bounds."""
    _validate(document, bounds=bounds, baseline=False)


def _validate(document: Mapping[str, Any], *, bounds: SbomBounds, baseline: bool) -> None:
    _document_bounds(document, bounds, baseline=baseline)
    errors = sorted(_validator().iter_errors(document), key=lambda error: (
        tuple(str(part) for part in error.absolute_path), error.message,
    ))
    if errors:
        error = errors[0]
        path = "/" + "/".join(str(part) for part in error.absolute_path)
        raise SpdxValidationError(f"Official SPDX 2.3 schema at {path}: {error.message}")
    if document["spdxVersion"] != SPDX_VERSION or document["dataLicense"] != "CC0-1.0":
        raise SpdxValidationError("Expected SPDX-2.3 with CC0-1.0 dataLicense")
    if document["SPDXID"] != "SPDXRef-DOCUMENT":
        raise SpdxValidationError("Document SPDXID must be SPDXRef-DOCUMENT")
    if not _namespace(document.get("documentNamespace", "")):
        raise SpdxValidationError("A valid absolute documentNamespace without fragment is required")
    _utc(document["creationInfo"]["created"])
    if not document["creationInfo"]["creators"]:
        raise SpdxValidationError("At least one SPDX creator is required")
    ids = {"SPDXRef-DOCUMENT": "document"}
    for key in ("packages", "files", "snippets"):
        for record in document.get(key, []):
            identifier = record["SPDXID"]
            if not _ID.fullmatch(identifier) or identifier in ids:
                raise SpdxValidationError(f"Invalid or duplicate SPDXID: {identifier}")
            ids[identifier] = key
    external: set[str] = set()
    for record in document.get("externalDocumentRefs", []):
        identifier = record["externalDocumentId"]
        if not _DOC_ID.fullmatch(identifier) or identifier in external:
            raise SpdxValidationError(f"Invalid or duplicate external document id: {identifier}")
        if not _namespace(record["spdxDocument"]):
            raise SpdxValidationError(f"Invalid external document namespace: {identifier}")
        external.add(identifier)
    licenses: set[str] = set()
    for record in document.get("hasExtractedLicensingInfos", []):
        identifier = record["licenseId"]
        if not _LICENSE_ID.fullmatch(identifier) or identifier in licenses:
            raise SpdxValidationError(f"Invalid or duplicate extracted license id: {identifier}")
        licenses.add(identifier)

    def reference(value: str, kind: str | None = None, *, sentinel: bool = False) -> None:
        if sentinel and value in {"NONE", "NOASSERTION"}:
            return
        if ":" in value:
            prefix, identifier = value.split(":", 1)
            if prefix not in external or not _ID.fullmatch(identifier):
                raise SpdxValidationError(f"Unbound external SPDX reference: {value}")
        elif value not in ids or kind is not None and ids[value] != kind:
            raise SpdxValidationError(f"Dangling or wrong-kind SPDX reference: {value}")

    for identifier in document.get("documentDescribes", []):
        reference(identifier)
        if identifier == "SPDXRef-DOCUMENT":
            raise SpdxValidationError("A document cannot documentDescribes itself")
    for record in document.get("relationships", []):
        reference(record["spdxElementId"])
        reference(record["relatedSpdxElement"], sentinel=True)
    for record in document.get("packages", []):
        for identifier in record.get("hasFiles", []):
            reference(identifier, "files")
        if record.get("filesAnalyzed") is False and "packageVerificationCode" in record:
            raise SpdxValidationError("filesAnalyzed false cannot assert a packageVerificationCode")
    for record in document.get("files", []):
        for identifier in record.get("fileDependencies", []):
            reference(identifier, "files")
    for record in document.get("snippets", []):
        reference(record["snippetFromFile"], "files")
        for span in record["ranges"]:
            for pointer in ("startPointer", "endPointer"):
                reference(span[pointer]["reference"], "files")
                if span[pointer]["reference"] != record["snippetFromFile"]:
                    raise SpdxValidationError("Snippet pointer must reference snippetFromFile")
            for coordinate in ("offset", "lineNumber"):
                start = span["startPointer"].get(coordinate)
                end = span["endPointer"].get(coordinate)
                minimum = 0 if coordinate == "offset" else 1
                if (start is not None and start < minimum
                        or end is not None and end < minimum
                        or start is not None and end is not None and end < start):
                    raise SpdxValidationError("Invalid snippet pointer range")
            for pointer in ("startPointer", "endPointer"):
                if not ({"offset", "lineNumber"} & span[pointer].keys()):
                    raise SpdxValidationError("Snippet pointer requires an offset or lineNumber")
    for record in [*document.get("packages", []), *document.get("files", []),
                   *document.get("snippets", [])]:
        for field in _LICENSE_FIELDS:
            values = record.get(field, [])
            if isinstance(values, str):
                values = [values]
            for expression in values:
                for token in re.findall(r"[^\s()]+", expression):
                    if "LicenseRef-" not in token:
                        continue
                    match = _LICENSE_TOKEN.fullmatch(token)
                    if match is None:
                        raise SpdxValidationError(f"Invalid LicenseRef token: {token}")
                    prefix, identifier = match.groups()
                    if prefix and prefix not in external or not prefix and identifier not in licenses:
                        raise SpdxValidationError(f"Missing LicenseRef binding: {prefix}:{identifier}")


def _rewrite(
    value: Any, ids: Mapping[str, str], licenses: Mapping[str, str],
    external: Mapping[str, str], *, field: str = "",
) -> Any:
    if isinstance(value, Mapping):
        return {key: _rewrite(item, ids, licenses, external, field=key)
                for key, item in value.items()}
    if isinstance(value, list):
        return [_rewrite(item, ids, licenses, external, field=field) for item in value]
    if not isinstance(value, str):
        return value
    if field in _LICENSE_FIELDS:
        def replace(match: re.Match[str]) -> str:
            prefix, identifier = match.groups()
            return (external.get(prefix, prefix) + ":" + identifier if prefix
                    else licenses.get(identifier, identifier))
        return _LICENSE_TOKEN.sub(replace, value)
    if field in _REF_FIELDS or field in _REF_LISTS:
        if ":" in value:
            prefix, identifier = value.split(":", 1)
            return external.get(prefix, prefix) + ":" + identifier
        return ids.get(value, value)
    if field == "SPDXID":
        return ids.get(value, value)
    if field == "licenseId":
        return licenses.get(value, value)
    if field == "externalDocumentId":
        return external.get(value, value)
    return value


def _declaration_maps(
    documents: Sequence[Mapping[str, Any]], collection: str, field: str, prefix: str,
) -> list[dict[str, str]]:
    declarations: dict[str, set[str]] = {}
    for document in documents:
        for record in document.get(collection, []):
            declarations.setdefault(record[field], set()).add(_digest(_ordered(record)))
    reserved = set(declarations)
    result = []
    for document in documents:
        mapping = {}
        for record in document.get(collection, []):
            identifier = record[field]
            replacement = identifier
            if len(declarations[identifier]) > 1:
                replacement = prefix + _digest(_ordered(record))
                while replacement in reserved:
                    replacement += "-remapped"
            mapping[identifier] = replacement
        result.append(mapping)
    return result


def _purls(package: Mapping[str, Any]) -> set[str]:
    return {ref["referenceLocator"] for ref in package.get("externalRefs", [])
            if ref["referenceCategory"] == "PACKAGE-MANAGER" and ref["referenceType"] == "purl"
            and _valid_purl(ref["referenceLocator"])}


def _valid_purl(value: Any) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"pkg:[a-z][a-z0-9.+-]*/\S+", value):
        return False
    if re.search(r"%(?![A-Fa-f0-9]{2})", value) or any(ord(char) < 33 for char in unquote(value)):
        return False
    parsed = urlsplit(value)
    path = parsed.path.split("/", 1)[1]
    if "@" in path:
        path, version = path.rsplit("@", 1)
        if not version or "@" in path or "/" in version:
            return False
    if not path or any(unquote(part) in {"", ".", ".."} for part in path.split("/")):
        return False
    try:
        qualifiers = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        return False
    return (len({key for key, _ in qualifiers}) == len(qualifiers)
            and all(re.fullmatch(r"[a-z][a-z0-9._-]*", key) and item for key, item in qualifiers)
            and all(part not in {".", ".."} for part in parsed.fragment.split("/")))


def _compatible_packages(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    a = {key: value for key, value in left.items() if key != "SPDXID"}
    b = {key: value for key, value in right.items() if key != "SPDXID"}
    if left["SPDXID"] == right["SPDXID"] and a == b:
        return True
    if not (_purls(left) & _purls(right)):
        return False
    return all(a[key] == b[key] or key not in _IDENTITY_COLLECTIONS
               and isinstance(a[key], list) and isinstance(b[key], list)
               for key in a.keys() & b.keys())


def _merge_baseline_packages(
    packages: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    groups: list[tuple[dict[str, Any], set[str]]] = []
    by_content: dict[str, set[int]] = {}
    by_purl: dict[str, set[int]] = {}

    def content_key(record: Mapping[str, Any]) -> str:
        return _digest({key: value for key, value in record.items()
                        if key != "SPDXID" or not _purls(record)})

    def index_group(index: int, package: Mapping[str, Any]) -> None:
        by_content.setdefault(content_key(package), set()).add(index)
        for purl in _purls(package):
            by_purl.setdefault(purl, set()).add(index)

    for record in sorted(packages, key=_encode):
        possible = set(by_content.get(content_key(record), ()))
        for purl in _purls(record):
            possible.update(by_purl.get(purl, ()))
        matches = [index for index in sorted(possible)
                   if _compatible_packages(groups[index][0], record)]
        if len(matches) == 1:
            index = matches[0]
            package, originals = groups[index]
            by_content[content_key(package)].discard(index)
            originals.add(record["SPDXID"])
            for key, value in record.items():
                if key != "SPDXID":
                    package[key] = (_sorted_unique([*package[key], *value])
                                    if key in package and isinstance(value, list) else deepcopy(value))
            index_group(index, package)
        else:
            groups.append((deepcopy(record), {record["SPDXID"]}))
            index_group(len(groups) - 1, record)
    remap = {}
    merged = []
    for package, originals in groups:
        identity = {key: value for key, value in package.items() if key != "SPDXID"}
        if not _purls(package):
            identity = {"record": identity, "baseline_element_ids": sorted(originals)}
        identifier = "SPDXRef-Baseline-" + _digest(identity)
        package["SPDXID"] = identifier
        for original in originals:
            remap[original] = identifier
        merged.append(package)
    return _sorted_unique(merged), remap


def _discovery(discovery: DiscoveryResult, source_fingerprint: str) -> dict[str, Any]:
    if discovery["schema"] != DISCOVERY_SCHEMA:
        raise NativeInputIntegrityError("Unsupported native discovery schema")
    result = deepcopy(dict(discovery))
    evidence: dict[str, Any] = {}
    for record in result["evidence"]:
        identifier = record["evidence_id"]
        if identifier in evidence and evidence[identifier] != record:
            raise NativeInputIntegrityError(f"Conflicting native evidence id: {identifier}")
        if record["source_fingerprint"] != source_fingerprint or not record["selector"]:
            raise NativeInputIntegrityError(f"Unbound native evidence: {identifier}")
        evidence[identifier] = record
    candidates: dict[str, Any] = {}
    for candidate in result["candidates"]:
        identifier = candidate["candidate_id"]
        for field in ("evidence_ids",):
            candidate[field] = sorted(set(candidate[field]))
        for field in ("identity", "release", "upstream"):
            claim = candidate[field]
            claim["evidence_ids"] = sorted(set(claim["evidence_ids"]))
            claim["alternatives"] = sorted(set(claim["alternatives"]))
            if claim["status"] not in {"unknown", "inferred", "corroborated", "conflicted"}:
                raise NativeInputIntegrityError(f"Unknown native claim status: {identifier}")
            if claim["status"] == "corroborated" and (
                not claim["value"] or not claim["evidence_ids"]
            ):
                raise NativeInputIntegrityError(f"Unsupported corroborated claim: {identifier}")
        referenced = {ref for field in ("identity", "release", "upstream")
                      for ref in candidate[field]["evidence_ids"]} | set(candidate["evidence_ids"])
        if not referenced <= evidence.keys():
            raise NativeInputIntegrityError(f"Unknown native evidence reference: {identifier}")
        candidate["observations"] = _sorted_unique(candidate["observations"])
        if identifier in candidates and candidates[identifier] != candidate:
            raise NativeInputIntegrityError(f"Conflicting native candidate id: {identifier}")
        candidates[identifier] = candidate
    for gap in result["gaps"]:
        gap["evidence_ids"] = sorted(set(gap["evidence_ids"]))
        if not set(gap["evidence_ids"]) <= evidence.keys():
            raise NativeInputIntegrityError("Discovery gap references unknown evidence")
    result["candidates"] = sorted(candidates.values(), key=lambda item: item["candidate_id"])
    result["evidence"] = sorted(evidence.values(), key=lambda item: item["evidence_id"])
    result["gaps"] = _sorted_unique(result["gaps"])
    result["coverage"] = _ordered(result["coverage"])
    return result


def _gap(kind: str, candidate: NativeCandidate, detail: str) -> CoverageGap:
    return {"kind": kind, "scope": candidate["candidate_id"], "detail": detail,
            "evidence_ids": sorted(set(candidate["evidence_ids"]))}


def _upstreams(package: Mapping[str, Any]) -> set[str]:
    return {str(package[field]) for field in ("homepage", "downloadLocation")
            if package.get(field) not in {None, "", "NONE", "NOASSERTION"}} | {
                ref["referenceLocator"] for ref in package.get("externalRefs", [])
                if ref["referenceType"] in {"vcs", "url"}
            }


def _root_matches(
    candidate: NativeCandidate, package: Mapping[str, Any], files: Mapping[str, Any],
) -> bool:
    root = candidate["package_root"].rstrip("/")
    if not root or root in {".", ".."} or any(part in {"", ".", ".."} for part in root.split("/")):
        return False
    names = [package.get("packageFileName", "")]
    names.extend(files[identifier]["fileName"] for identifier in package.get("hasFiles", [])
                 if identifier in files)
    return any(name.removeprefix("./") == root or name.removeprefix("./").startswith(root + "/")
               for name in names)


def _candidate_matches(
    candidate: NativeCandidate, by_purl: Mapping[str, list[Any]],
    by_identity: Mapping[tuple[str, str], list[Any]], files: Mapping[str, Any],
) -> tuple[list[Mapping[str, Any]], str]:
    purl = candidate.get("purl")
    if _valid_purl(purl):
        matches = by_purl.get(purl, [])
        if matches:
            return matches, "exact_purl"
    identity, release, upstream = (candidate[field] for field in ("identity", "release", "upstream"))
    if identity["status"] == release["status"] == "corroborated":
        matches = [package for package in by_identity.get((identity["value"], release["value"]), [])
                   if (upstream["status"] == "corroborated"
                        and upstream["value"] in _upstreams(package)
                        or _root_matches(candidate, package, files))]
        return matches, "corroborated_identity"
    return [], "unmatched"


def _conflicts(candidate: NativeCandidate, package: Mapping[str, Any] | None) -> list[CoverageGap]:
    result = []
    for field, kind in (("identity", "identity_conflict"), ("release", "version_conflict"),
                        ("upstream", "repository_conflict")):
        claim = candidate[field]
        conflict = claim["status"] == "conflicted"
        if package and claim["value"]:
            if field == "release" and package.get("versionInfo"):
                conflict |= claim["value"] != package["versionInfo"]
            elif field == "identity" and claim["status"] == "corroborated":
                conflict |= claim["value"] != package["name"]
            elif field == "upstream" and claim["status"] == "corroborated" and _upstreams(package):
                conflict |= claim["value"] not in _upstreams(package)
        if conflict:
            result.append(_gap(kind, candidate, f"{field} claim conflicts; baseline values retained"))
    return result


def _native_package(candidate: NativeCandidate) -> dict[str, Any]:
    package: dict[str, Any] = {
        "SPDXID": "SPDXRef-Native-" + _digest(candidate["candidate_id"]),
        "name": candidate["native_name"], "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False, "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
        "sourceInfo": _encode({
            "candidate_id": candidate["candidate_id"], "root_id": candidate["root_id"],
            "package_root": candidate["package_root"],
            "identity": candidate["identity"]["status"], "release": candidate["release"]["status"],
            "upstream": candidate["upstream"]["status"],
            "provenance": "native-sbom-provenance.json",
        }).decode("utf-8").rstrip("\n"),
    }
    if candidate["release"]["status"] == "corroborated":
        package["versionInfo"] = candidate["release"]["value"]
    if _valid_purl(candidate.get("purl")):
        package["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                    "referenceLocator": candidate["purl"]}]
    return package


def build_spdx(
    *, source_fingerprint: str, created: str, baselines: Sequence[SpdxBaseline],
    discovery: DiscoveryResult, input_identities: Sequence[ArtifactRef], bounds: SbomBounds,
) -> SbomResult:
    """Enrich valid baselines without promoting hints or discarding accepted records."""
    _utc(created)
    discovered = _discovery(discovery, source_fingerprint)
    baseline_inputs = _sorted_unique([deepcopy(dict(item)) for item in baselines])
    for item in baseline_inputs:
        for field in ("artifact", "source_artifact"):
            size = item[field]["size_bytes"]
            if type(size) is not int or size < 0 or size > bounds.input_bytes:
                raise SpdxValidationError(f"Baseline {field} bytes exceed input bound {bounds.input_bytes}")
        _validate(item["document"], bounds=bounds, baseline=True)
    documents = [item["document"] for item in baseline_inputs]
    license_maps = _declaration_maps(
        documents, "hasExtractedLicensingInfos", "licenseId", "LicenseRef-"
    )
    external_maps = _declaration_maps(
        documents, "externalDocumentRefs", "externalDocumentId", "DocumentRef-"
    )
    declaration_conflicts: list[CoverageGap] = []
    for label, mappings in (("extracted-license", license_maps), ("external-document", external_maps)):
        for identifier in sorted({key for mapping in mappings for key, value in mapping.items()
                                  if key != value}):
            declaration_conflicts.append({
                "kind": "identity_conflict", "scope": "baseline-declaration-" + _digest((label, identifier)),
                "detail": f"Conflicting {label} declarations remapped; all original values retained",
                "evidence_ids": [],
            })
    baseline_records = []
    baseline_selectors: dict[str, list[Any]] = {}
    collections: dict[str, list[Any]] = {key: [] for key in (
        *_ELEMENTS, "externalDocumentRefs", "annotations", "revieweds", "documentDescribes",
    )}
    creators = ["Tool: appsec-review-native-sbom/1"]
    comments = []
    creation_comments = []
    license_versions = []
    semantic_identities = []
    baseline_package_count = 0
    for item, license_map, external_map in zip(baseline_inputs, license_maps, external_maps):
        original = item["document"]
        semantic = deepcopy(dict(original))
        semantic.pop("documentNamespace", None)
        semantic["creationInfo"].pop("created", None)
        semantic_hash = _digest(_ordered(semantic))
        semantic_identities.append({
            "semantic_sha256": semantic_hash, "source_artifact": item["source_artifact"],
            "tool_identity": item["tool_identity"],
        })
        renamed = _rewrite(original, {}, license_map, external_map)
        graph = _digest(_ordered({
            key: renamed.get(key, []) for key in ("packages", "files", "snippets")
        }))
        id_map = {"SPDXRef-DOCUMENT": "SPDXRef-DOCUMENT"}
        for kind in ("packages", "files", "snippets"):
            for record in renamed.get(kind, []):
                content = {key: value for key, value in record.items() if key != "SPDXID"}
                has_references = any(
                    key in _REF_LISTS or key in _REF_FIELDS for key in content
                ) or kind == "snippets"
                id_map[record["SPDXID"]] = "SPDXRef-Baseline-" + _digest({
                    "kind": kind, "record": _ordered(record),
                    "bindings": graph if has_references else None,
                })
        rewritten = _rewrite(renamed, id_map, {}, {})
        for key in collections:
            collections[key].extend(rewritten.get(key, []))
        for record in original.get("packages", []):
            baseline_selectors.setdefault(id_map[record["SPDXID"]], []).append({
                "artifact": item["artifact"], "source_artifact": item["source_artifact"],
                "selector": {"json_pointer": "/packages", "SPDXID": record["SPDXID"]},
            })
        baseline_package_count += len(original.get("packages", []))
        creators.extend(original["creationInfo"]["creators"])
        if original.get("comment"):
            comments.append(original["comment"])
        if original["creationInfo"].get("comment"):
            creation_comments.append(original["creationInfo"]["comment"])
        if original["creationInfo"].get("licenseListVersion"):
            license_versions.append(original["creationInfo"]["licenseListVersion"])
        baseline_records.append({
            "artifact": item["artifact"], "source_artifact": item["source_artifact"],
            "tool_identity": item["tool_identity"], "semantic_sha256": semantic_hash,
            "document_metadata": _ordered({
                key: value for key, value in original.items()
                if key not in collections and key not in {"packages", "files", "snippets"}
            }),
            "spdx_id_map": id_map, "license_ref_map": license_map,
            "external_document_ref_map": external_map,
        })
    collections = {key: _ordered(value) for key, value in collections.items()}
    packages, package_map = _merge_baseline_packages(collections["packages"])
    collections["packages"] = packages
    collections = _rewrite(collections, package_map, {}, {})
    package_sources: dict[str, Any] = {}
    for original, selectors in baseline_selectors.items():
        identifier = package_map[original]
        entry = package_sources.setdefault(identifier, {
            "baseline_packages": [], "native_candidate_ids": [], "evidence_ids": [],
            "merge_decisions": [], "conflicts": [],
        })
        entry["baseline_packages"].extend(selectors)
    baseline_conflicts: list[CoverageGap] = []
    by_purl: dict[str, list[Any]] = {}
    by_identity: dict[tuple[str, str], list[Any]] = {}
    for package in packages:
        for purl in _purls(package):
            by_purl.setdefault(purl, []).append(package)
        by_identity.setdefault((package["name"], package.get("versionInfo", "")), []).append(package)
    for shared in by_purl.values():
        scalars: dict[str, set[bytes]] = {}
        for package in shared:
            for key, value in package.items():
                if key != "SPDXID" and (not isinstance(value, list) or key in _IDENTITY_COLLECTIONS):
                    scalars.setdefault(key, set()).add(_encode(value))
        if any(len(values) > 1 for values in scalars.values()):
            gap: CoverageGap = {
                "kind": ("version_conflict" if len(scalars.get("versionInfo", ())) > 1
                         else "identity_conflict"),
                "scope": "baseline-packages-" + _digest(sorted(item["SPDXID"] for item in shared)),
                "detail": "Exact-purl baseline packages have incompatible fields; all retained",
                "evidence_ids": [],
            }
            baseline_conflicts.append(gap)
            for package in shared:
                package_sources[package["SPDXID"]]["conflicts"].append(gap)
    for entry in package_sources.values():
        entry["merge_decisions"].append(
            "baseline_exact" if len(entry["baseline_packages"]) > 1 else "baseline_retained"
        )
    for record in baseline_records:
        record["spdx_id_map"] = {key: package_map.get(value, value)
                                 for key, value in record["spdx_id_map"].items()}
    converted_refs = {_encode(item["artifact"]) for item in baseline_inputs}
    accepted_identities = _sorted_unique(list(input_identities))
    fingerprint = _digest({
        "source_fingerprint": source_fingerprint, "created": created, "bounds": asdict(bounds),
        "algorithm": MERGE_IDENTITY, "schema_sha256": schema_sha256(),
        "discovery_identity": DISCOVERY_IDENTITY, "discovery_sha256": _digest(discovered),
        "baselines": _sorted_unique(semantic_identities),
        "input_identities": [ref for ref in accepted_identities if _encode(ref) not in converted_refs],
    })
    document: dict[str, Any] = {
        "spdxVersion": SPDX_VERSION, "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "appsec-review enriched source inventory",
        "documentNamespace": "https://appsec-review.invalid/spdx/" + fingerprint,
        "creationInfo": {"created": created, "creators": sorted(set(creators))},
    }
    if comments:
        document["comment"] = "\n".join(sorted(set(comments)))
    if creation_comments:
        document["creationInfo"]["comment"] = "\n".join(sorted(set(creation_comments)))
    if len(set(license_versions)) == 1:
        document["creationInfo"]["licenseListVersion"] = license_versions[0]
    for key, values in collections.items():
        if values:
            document[key] = values
    document.setdefault("packages", [])
    document.setdefault("relationships", [])
    for package in document["packages"]:
        document["relationships"].append({
            "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package["SPDXID"],
        })
    document = _ordered(document)
    gaps = [*discovered["gaps"], *declaration_conflicts, *baseline_conflicts]
    if not baseline_inputs and not any(gap["kind"] in {
        "input_missing", "sbom_conversion_failed", "sbom_validation_failed"
    } for gap in gaps):
        gaps.append({"kind": "input_missing", "scope": "source-syft-baseline",
                     "detail": "No accepted source SPDX baseline was supplied", "evidence_ids": []})
    provenance: dict[str, Any] = {
        "schema": PROVENANCE_SCHEMA, "source_fingerprint": source_fingerprint,
        "created": created, "input_fingerprint": fingerprint, "bounds": asdict(bounds),
        "algorithm": MERGE_IDENTITY,
        "spdx_schema": {"version": SPDX_VERSION, "sha256": schema_sha256(),
                        "resource": _SCHEMA_RESOURCE},
        "input_identities": accepted_identities, "baselines": _sorted_unique(baseline_records),
        "discovery": {"schema": DISCOVERY_SCHEMA, "identity": DISCOVERY_IDENTITY,
                      "sha256": _digest(discovered), "coverage": discovered["coverage"],
                      "candidate_count": len(discovered["candidates"]),
                      "evidence_count": len(discovered["evidence"])},
        "packages": package_sources, "decisions": [], "gaps": _sorted_unique(gaps),
        "native_omitted": 0,
    }
    provenance["packages"] = {key: {field: _sorted_unique(value) for field, value in entry.items()}
                               for key, entry in package_sources.items()}
    _validate(document, bounds=bounds, baseline=False)
    _payload_bounds(provenance, limit=bounds.output_bytes, field_bytes=bounds.field_bytes)
    files = {record["SPDXID"]: record for record in document.get("files", [])}
    baseline_packages = list(document["packages"])
    accepted: list[tuple[NativeCandidate, dict[str, Any], list[CoverageGap], dict[str, Any] | None]] = []
    omitted = 0
    for candidate in discovered["candidates"]:
        matches, basis = _candidate_matches(candidate, by_purl, by_identity, files)
        conflicts = _conflicts(candidate, matches[0] if len(matches) == 1 else None)
        package = None
        if len(matches) == 1 and not conflicts:
            identifier = matches[0]["SPDXID"]
        else:
            package = _native_package(candidate)
            identifier = package["SPDXID"]
        if len(matches) > 1:
            conflicts.append(_gap("identity_conflict", candidate,
                                  "Multiple baseline packages match; no ambiguous merge performed"))
        if candidate.get("purl") is not None and not _valid_purl(candidate["purl"]):
            conflicts.append(_gap("unsupported_metadata", candidate, "Invalid observed purl omitted"))
        decision = {
            "candidate_id": candidate["candidate_id"], "spdx_id": identifier,
            "decision": basis if package is None else (
                "conflict" if conflicts else "native_addition"
            ),
            "matching_spdx_ids": sorted(record["SPDXID"] for record in matches),
            "conflicts": conflicts,
        }
        try:
            _payload_bounds(package or {}, limit=bounds.output_bytes, field_bytes=bounds.field_bytes)
            _payload_bounds(decision, limit=bounds.output_bytes, field_bytes=bounds.field_bytes)
        except SpdxValidationError:
            omitted += 1
            continue
        accepted.append((candidate, decision, conflicts, package))

    def assemble(
        contributions: Sequence[tuple[NativeCandidate, dict[str, Any], list[CoverageGap], dict[str, Any] | None]],
        omitted_count: int,
    ) -> tuple[dict[str, Any], dict[str, Any], list[CoverageGap]]:
        output = deepcopy(document)
        sidecar = deepcopy(provenance)
        output_gaps = list(gaps)
        for candidate, decision, conflicts, package in contributions:
            identifier = decision["spdx_id"]
            if package is not None:
                output["packages"].append(package)
                output["relationships"].append({
                    "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": identifier,
                })
            entry = sidecar["packages"].setdefault(identifier, {
                "baseline_packages": [], "native_candidate_ids": [], "evidence_ids": [],
                "merge_decisions": [], "conflicts": [],
            })
            entry["native_candidate_ids"].append(candidate["candidate_id"])
            entry["evidence_ids"].extend(candidate["evidence_ids"])
            for claim in ("identity", "release", "upstream"):
                entry["evidence_ids"].extend(candidate[claim]["evidence_ids"])
            entry["merge_decisions"].append(decision["decision"])
            entry["conflicts"].extend(conflicts)
            output_gaps.extend(conflicts)
            sidecar["decisions"].append(decision)
        if omitted_count:
            output_gaps.append({
                "kind": "bounds", "scope": "native-additions",
                "detail": f"Omitted {omitted_count} native candidate contributions at publication bounds",
                "evidence_ids": [],
            })
        output_gaps = _sorted_unique(output_gaps)
        sidecar["gaps"] = output_gaps
        sidecar["native_omitted"] = omitted_count
        for entry in sidecar["packages"].values():
            for field in entry:
                entry[field] = _sorted_unique(entry[field])
        return _ordered(output), sidecar, output_gaps

    # Find the longest stable candidate prefix that fits both independent publications.
    # Baseline records are never among the removable contributions.
    low, high = 0, len(accepted) - 1
    best: tuple[dict[str, Any], dict[str, Any], list[CoverageGap]] | None = None
    complete = assemble(accepted, omitted)
    try:
        _document_bounds(complete[0], bounds, baseline=False)
        _payload_bounds(complete[1], limit=bounds.output_bytes, field_bytes=bounds.field_bytes)
    except SpdxValidationError:
        pass
    else:
        best = complete
        high = -1
    while low <= high:
        count = (low + high) // 2
        current = assemble(accepted[:count], omitted + len(accepted) - count)
        try:
            _document_bounds(current[0], bounds, baseline=False)
            _payload_bounds(current[1], limit=bounds.output_bytes, field_bytes=bounds.field_bytes)
        except SpdxValidationError:
            high = count - 1
        else:
            best = current
            low = count + 1
    if best is None:
        raise SpdxValidationError("Baseline and required provenance exceed publication bounds")
    document, provenance, gaps = best
    validate_spdx(document, bounds=bounds)
    emitted = {package["SPDXID"] for package in document["packages"]}
    if set(provenance["packages"]) != emitted:
        raise SpdxValidationError("Provenance package map does not equal emitted SPDX packages")
    known_evidence = {record["evidence_id"] for record in discovered["evidence"]}
    known_candidates = {candidate["candidate_id"] for candidate in discovered["candidates"]}
    for entry in provenance["packages"].values():
        if not set(entry["evidence_ids"]) <= known_evidence or not set(
            entry["native_candidate_ids"]
        ) <= known_candidates or not (entry["baseline_packages"] or entry["native_candidate_ids"]):
            raise SpdxValidationError("Unbound provenance package selector")
    metrics = dict.fromkeys(SBOM_COUNTERS, 0)
    candidate_names = {candidate["candidate_id"]: candidate["native_name"]
                       for candidate in discovered["candidates"]}
    baseline_names = {package["name"] for package in baseline_packages}
    metrics.update({
        "baseline_packages": baseline_package_count,
        "native_additions": sum(package["SPDXID"].startswith("SPDXRef-Native-")
                                for package in document["packages"]),
        "exact_merges": baseline_package_count - len(baseline_packages) + sum(
            decision["decision"] in {"exact_purl", "corroborated_identity"}
            for decision in provenance["decisions"]
        ),
        "unresolved_matches": sum(
            decision["decision"] not in {"exact_purl", "corroborated_identity"}
            and (bool(decision["matching_spdx_ids"])
                 or candidate_names[decision["candidate_id"]] in baseline_names)
            for decision in provenance["decisions"]
        ),
        "conflicts": sum(gap["kind"] in {
            "identity_conflict", "version_conflict", "repository_conflict"
        } for gap in gaps),
        "output_packages": len(document["packages"]),
        "output_relationships": len(document["relationships"]),
        "output_bytes": len(_encode(document)),
    })
    return {"document": document, "provenance": provenance, "gaps": gaps, "metrics": metrics}
