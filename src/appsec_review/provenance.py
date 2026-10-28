"""Detached native outputs and exact, verifiable normalization provenance."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping
import xml.etree.ElementTree as ET

from appsec_review.interchange import (
    ArtifactReference, NativeResultReference, ObservationMetadata, ResultSelector,
    artifact_reference_from_mapping, gap_id, native_result_reference_from_mapping,
)
from appsec_review.retrieval.observations import (
    classify, normalize_reported_severity, rule_of, scanner_of,
)
from appsec_review.storage import canonical_json
from appsec_review.storage import shared
from appsec_review.observability.spans import count_work


RETENTION_SCHEMA = "appsec-review/native-output-retention/1"
VALIDATION_SCHEMA = "appsec-review/observation-provenance-validation/1"


def json_selector(*parts: str | int) -> ResultSelector:
    return ResultSelector("json_pointer", "".join(
        "/" + str(part).replace("~", "~0").replace("/", "~1") for part in parts))


def xml_selector(element: ET.Element, ordinal: int) -> ResultSelector:
    return ResultSelector("xml_ordinal", {"element": element.tag, "ordinal": ordinal})


def artifact_reference(root: Path, value: Mapping[str, Any]) -> ArtifactReference:
    """Verify a pinned identity; never substitute a current digest for its expected hash."""
    path = shared.safe_path(root, str(value["path"]))
    ref = shared.reference(root, path, expected_sha256=str(value["sha256"]))
    if "size_bytes" in value and value["size_bytes"] != ref["size_bytes"]:
        raise ValueError("native artifact size differs from pinned identity")
    shared.verify_reference(root, ref)
    return artifact_reference_from_mapping(ref)


def _owner(root: Path, owner: shared.SharedArtifacts | None) -> shared.SharedArtifacts:
    owner = owner or shared.current()
    if owner is None or owner.run_root != root:
        raise ValueError("native provenance requires a run-owned publication attempt")
    return owner


def retain_native_output(
    root: Path, path: Path, *, parser_identity: str, complete: bool,
    native_result_count: int, expected: Mapping[str, Any] | None = None,
    execution_reference: Mapping[str, Any] | None = None,
    owner: shared.SharedArtifacts | None = None, events: Any = None,
    unit_id: str | None = None,
) -> NativeResultReference:
    owner = _owner(root, owner)
    source = artifact_reference(root, expected or shared.reference(root, path))
    if shared.safe_path(root, source.path) != path:
        raise ValueError("native output path differs from pinned identity")
    execution = artifact_reference(root, execution_reference) if execution_reference is not None else None
    obj = artifact_reference_from_mapping(shared.put_private_file(root, path))
    if (obj.sha256, obj.size_bytes) != (source.sha256, source.size_bytes):
        raise ValueError("native output changed during retention")
    identity = {
        "schema": RETENTION_SCHEMA, "artifact": obj.as_dict(),
        "execution_reference": execution.as_dict() if execution else None,
        "parser_identity": parser_identity, "complete": complete, "truncated": not complete,
        "retained_bytes": obj.size_bytes, "native_result_count": native_result_count,
    }
    if type(native_result_count) is not int or native_result_count < 0:
        raise ValueError("native result count must be nonnegative")
    fingerprint = hashlib.sha256(canonical_json(identity)).hexdigest()
    hit = owner.lookup("native-output", fingerprint)
    receipt = (hit[1] if hit is not None else owner.computed(
        "native-output", fingerprint, obj.as_dict(), computation=identity))
    reference = NativeResultReference(obj, ResultSelector("document"), parser_identity, execution,
                                      artifact_reference_from_mapping(receipt), complete)
    verify_native_reference(root, reference)
    count_work("native_output_references")
    count_work("native_output_bytes", obj.size_bytes)
    if events is not None:
        events.write("NATIVE_OUTPUT_RETAINED", unit_id=unit_id,
                     **{key: owner.actor[key] for key in ("run_id", "job_id", "attempt_id")},
                     **identity, retention_receipt=receipt)
    return reference


def select_native(reference: NativeResultReference | Mapping[str, Any],
                  selector: ResultSelector | Mapping[str, Any]) -> NativeResultReference:
    from appsec_review.interchange import result_selector_from_mapping
    native = (reference if isinstance(reference, NativeResultReference)
              else native_result_reference_from_mapping(reference))
    selected = selector if isinstance(selector, ResultSelector) else result_selector_from_mapping(selector)
    return replace(native, selector=selected)


def verify_native_reference(root: Path, reference: NativeResultReference | Mapping[str, Any],
                            *, resolve: bool = False) -> Any:
    native = (reference if isinstance(reference, NativeResultReference)
              else native_result_reference_from_mapping(reference))
    if native.artifact.path != f"{shared.OBJECTS}/{native.artifact.sha256}":
        raise ValueError("native output must be detached content-addressed bytes")
    path = shared.verify_reference(root, native.artifact.as_dict())
    if native.execution_reference is not None:
        shared.verify_reference(root, native.execution_reference.as_dict())
    if native.retention_receipt is None:
        raise ValueError("native output has no retention receipt")
    receipt = shared.verify_receipt(root, native.retention_receipt.as_dict())
    computation = receipt["computation"]
    if (receipt["object"] != native.artifact.as_dict()
            or computation.get("schema") != RETENTION_SCHEMA
            or computation.get("artifact") != native.artifact.as_dict()
            or computation.get("parser_identity") != native.parser_identity
            or computation.get("complete") is not native.complete
            or computation.get("execution_reference") != (
                native.execution_reference.as_dict() if native.execution_reference else None)):
        raise ValueError("native retention receipt does not bind this output")
    if not resolve:
        return path
    return _resolve_selector(path, native.selector, {})


def _resolve_selector(path: Path, selector: ResultSelector, cache: dict[Any, Any]) -> Any:
    if selector.kind == "document":
        return path
    if selector.kind == "byte_range":
        with path.open("rb") as stream:
            stream.seek(selector.value["start"])
            return stream.read(selector.value["end"] - selector.value["start"])
    if selector.kind == "xml_ordinal":
        key = (path, "xml")
        if key not in cache:
            elements: dict[str, list[ET.Element]] = {}
            for item in ET.fromstring(path.read_bytes()).iter():
                elements.setdefault(item.tag, []).append(item)
            cache[key] = elements
        matches = cache[key].get(selector.value["element"], ())
        if selector.value["ordinal"] >= len(matches):
            raise ValueError("native XML ordinal does not resolve")
        return matches[selector.value["ordinal"]]
    key = (path, "json")
    if key not in cache:
        cache[key] = json.loads(path.read_bytes())
    value = cache[key]
    if selector.value:
        for part in selector.value[1:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(value, list):
                if not part.isascii() or not part.isdigit() or (part != "0" and part.startswith("0")):
                    raise ValueError("native JSON array index is invalid")
                index = int(part)
                if index >= len(value):
                    raise ValueError("native JSON pointer does not resolve")
                value = value[index]
            elif isinstance(value, dict) and part in value:
                value = value[part]
            else:
                raise ValueError("native JSON pointer does not resolve")
    return value


def merge_native_references(*groups: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    unique = {}
    for group in groups:
        for value in group:
            reference = native_result_reference_from_mapping(value).as_dict()
            unique[canonical_json(reference)] = reference
    return [unique[key] for key in sorted(unique)]


def common_metadata(payload: Mapping[str, Any], *, evidence_refs: Iterable[Mapping[str, Any]],
                    payload_schema: str, record_kind: str = "finding",
                    gaps: Iterable[str] = ()) -> dict[str, Any]:
    references = tuple(native_result_reference_from_mapping(ref)
                       for ref in merge_native_references(evidence_refs))
    codes = list(gaps)
    if not references:
        codes.append("provenance_unavailable")
    return ObservationMetadata(
        classify(payload), record_kind, scanner_of(payload), rule_of(payload),
        normalize_reported_severity(payload), references,
        tuple(sorted({gap_id({"code": code, "scanner": scanner_of(payload),
                              "rule_id": rule_of(payload)}) for code in codes})),
        payload_schema,
    ).as_dict()


def consume_native_references(root: Path, references: Iterable[Mapping[str, Any]], *,
                              owner: shared.SharedArtifacts | None = None) -> list[dict[str, Any]]:
    owner = _owner(root, owner)
    receipts = []
    for ref in merge_native_references(references):
        verify_native_reference(root, ref)
        count_work("native_output_references")
        count_work("native_output_bytes", ref["artifact"]["size_bytes"])
        receipts.append(owner.consume_receipt(ref["retention_receipt"]))
    return receipts


def validate_observation_provenance(
    root: Path, records: Iterable[Mapping[str, Any]], *, parser_identity: str,
    owner: shared.SharedArtifacts | None = None, events: Any = None, unit_id: str | None = None,
) -> dict[str, Any]:
    """Validate selectors once at publication, not by reparsing reports during retrieval."""
    from appsec_review.interchange import observation_metadata_from_mapping
    owner = _owner(root, owner)
    count = reference_count = 0
    references: list[dict[str, Any]] = []
    cache: dict[Any, Any] = {}
    verified: dict[bytes, Path] = {}
    gap_count = 0
    for record in records:
        metadata = observation_metadata_from_mapping(record["common"])
        if not metadata.evidence_refs:
            if not metadata.gap_ids:
                raise ValueError("observation lacks native evidence and an explicit gap")
        for ref in metadata.evidence_refs:
            identity = ref.as_dict()
            identity.pop("selector")
            key = canonical_json(identity)
            if key not in verified:
                verified[key] = verify_native_reference(root, ref)
            _resolve_selector(verified[key], ref.selector, cache)
            references.append(ref.as_dict())
        count += 1
        gap_count += len(metadata.gap_ids)
        reference_count += len(metadata.evidence_refs)
    unique = merge_native_references(references)
    artifacts = {ref["artifact"]["path"]: ref["artifact"] for ref in unique}
    complete = not gap_count and bool(unique) and all(ref["complete"] for ref in unique)
    document = {
        "schema": VALIDATION_SCHEMA, "parser_identity": parser_identity,
        "observation_count": count, "native_reference_count": reference_count,
        "complete": complete, "truncated": any(not ref["complete"] for ref in unique),
        "provenance_gap_count": gap_count,
        "artifacts": [artifacts[key] for key in sorted(artifacts)],
        "actor": {key: owner.actor[key] for key in ("run_id", "job_id", "attempt_id")},
    }
    obj = shared.put_bytes(root, canonical_json(document))
    fingerprint = hashlib.sha256(canonical_json(document)).hexdigest()
    receipt = owner.computed("native-output", fingerprint, obj, computation=document,
                             dependencies=tuple(document["artifacts"]))
    count_work("observation_references", reference_count)
    count_work("provenance_gaps", gap_count)
    if events is not None:
        events.write("OBSERVATION_PROVENANCE_VALIDATED", unit_id=unit_id,
                     **{key: owner.actor[key] for key in ("run_id", "job_id", "attempt_id")},
                     **{key: document[key] for key in (
                         "parser_identity", "observation_count", "native_reference_count", "complete", "truncated")},
                     provenance_receipt=receipt)
    return receipt
