from __future__ import annotations

from array import array
from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import re
import sqlite3
import time
from typing import Any

from appsec_review.config.compiler_target import CompilerTarget
from appsec_review.config.debug_symbols import parse_debug_symbol_settings
from appsec_review.debug_symbols.contract import (
    DECISION_SCHEMA, INDEX_NAME, JOB_ID, RECORD_SCHEMA, Extraction, RecordKind,
    record_fingerprint, selected_path,
)
from appsec_review.jobs.job_artifact_indexing import (
    canonical_artifact_identity, load_accepted_artifact_index,
)
from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.retrieval import (
    INDEX_SCHEMA, EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity,
    RelationKind, RelationRecord, write_manifest,
)
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.retrieval.model import canonical_json
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import safe_path

from .datasets import CONSUMES, DATASETS


SCHEMA = "appsec-review/debug-symbol-indexing/1"
READER_IDENTITY = "appsec-review/offline-debug-symbol-readers/1"
_TOPOLOGY = {"decide": ("target",), "extract": ("clang_dwarf", "msvc_pdb"),
             "acceptance": ("publish_handoff",)}
_ARTIFACT_KINDS = {EntityKind.EXECUTABLE, EntityKind.OBJECT_FILE, EntityKind.LIBRARY,
                   EntityKind.BUILD_ARTIFACT}
_DEBUG_KINDS = {"native-symbols", "debug-information", "debug-metadata"}
_RECORD_KINDS = {
    RecordKind.SYMBOL: EntityKind.SYMBOL,
    RecordKind.SOURCE_RANGE: EntityKind.IR_ENTITY,
    RecordKind.TYPE_LAYOUT: EntityKind.IR_ENTITY,
    RecordKind.INLINE_FRAME: EntityKind.IR_ENTITY,
    RecordKind.COMPILATION_UNIT: EntityKind.COMPILE_UNIT,
    RecordKind.GRAPH_LINK: EntityKind.IR_ENTITY,
}


class FrameworkIntegrityError(ValueError):
    """Accepted run-owned evidence or its resolving reference changed."""


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _ref(root: Path, path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _verify(root: Path, ref: Mapping[str, Any], label: str, maximum: int | None = None) -> Path:
    try:
        path = safe_path(root, str(ref["path"]))
        size = path.stat().st_size
        if not path.is_file() or maximum is not None and size > maximum:
            raise ValueError("missing or oversized file")
        if size != ref["size_bytes"] or file_sha256(path) != ref["sha256"]:
            raise ValueError("content hash mismatch")
        return path
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise FrameworkIntegrityError(f"{label} integrity verification failed") from exc


def _artifact(unit: UnitContext, name: str, document: Mapping[str, Any]) -> dict[str, Any]:
    path = unit.job.attempt_root / "artifacts" / "debug-symbols" / name
    atomic_json(path, document)
    return _ref(unit.job.run_root, path)


def _reader_identity(extractor) -> str:
    if extractor is None:
        return READER_IDENTITY
    try:
        implementation = inspect.getsource(extractor)
    except (OSError, TypeError):
        implementation = type(extractor).__qualname__
    return _digest({"module": getattr(extractor, "__module__", ""),
                    "name": getattr(extractor, "__qualname__", ""),
                    "implementation": implementation})


def _emit(unit: UnitContext, event: str, *, target: str, lane: str, started: float,
          record_count: int = 0, artifact_count: int = 0, gap_count: int = 0) -> None:
    unit.job.events.write(event, unit_id=unit.unit_id, compiler_target=target, lane=lane,
                          record_count=record_count, artifact_count=artifact_count,
                          duration_ms=max(0, int((time.monotonic() - started) * 1000)),
                          gap_count=gap_count)


def _accepted_inputs(unit: UnitContext, settings: Mapping[str, Any]) -> dict[str, Any]:
    accepted = load_accepted_artifact_index(unit.job.run_root)
    if accepted.get("source_fingerprint") != unit.job.source_fingerprint:
        raise ValueError("accepted artifact catalog belongs to another target snapshot")
    upstream = accepted.get("index_manifest")
    if not isinstance(upstream, Mapping):
        raise ValueError("accepted artifact catalog has no index manifest")
    manifest_path = _verify(unit.job.run_root, upstream, "accepted artifact manifest")
    manifest, _ = load_verified_manifest(unit.job.run_root, manifest_path, upstream["sha256"])
    if manifest["run_id"] != unit.job.run_id or manifest["target_snapshot"] != unit.job.source_fingerprint:
        raise ValueError("accepted artifact manifest belongs to another run or target")
    refs = {item["canonical_identity"]: dict(item) for item in accepted.get("target_artifacts", ())
            if isinstance(item, Mapping) and "canonical_identity" in item}
    language_sha = None
    language_pointer = unit.job.run_root / "data" / "jobs" / "job_language_build" / "latest.json"
    if language_pointer.is_file():
        language = load_accepted_language_build(unit.job.run_root)
        language_sha = language["language_build_handoff_sha256"]
        if (language.get("source_fingerprint") != unit.job.source_fingerprint
                or language_sha != accepted.get("language_build_handoff_sha256")):
            raise ValueError("artifact catalog and accepted language-build metadata differ")
        for receipt in language.get("receipts", ()):
            if not isinstance(receipt, Mapping) or receipt.get("terminal_status") != "SUCCEEDED":
                continue
            for item in receipt.get("artifacts", ()):
                logical = canonical_artifact_identity(
                    unit.job.source_fingerprint, str(receipt["build_unit_id"]), item)
                refs[logical.value] = {**item, "canonical_identity": logical.value}
    artifacts = []
    seen_artifacts = set()
    gaps = list(accepted.get("gaps", ()))
    limit = settings["max_artifacts"]
    for shard in manifest["indexes"]:
        if shard["name"] != "artifacts" or not shard.get("shard_id", "").startswith("catalog-"):
            continue
        path = safe_path(unit.job.run_root, shard["relative_path"])
        with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro&immutable=1", uri=True) as db:
            kinds = sorted(kind.value for kind in _ARTIFACT_KINDS)
            rows = db.execute(
                "SELECT identity, kind, payload_json FROM entities WHERE kind IN ("
                + ",".join("?" for _ in kinds) + ") ORDER BY identity LIMIT ?",
                (*kinds, limit + 1)).fetchall()
        for logical_id, kind, payload_json in rows:
            if logical_id in seen_artifacts:
                continue
            if len(artifacts) >= limit:
                gaps.append("max_artifacts: accepted artifact catalog exceeded configured limit")
                break
            payload = json.loads(payload_json)
            ref = refs.get(logical_id)
            if ref is None and isinstance(payload, Mapping) and payload.get("path"):
                ref = dict(payload)
            if ref is not None and (
                    ref.get("sha256") != payload.get("sha256")
                    or ref.get("size_bytes") != payload.get("size_bytes")):
                raise ValueError("accepted artifact reference does not match catalog identity")
            artifacts.append({"artifact_identity": logical_id, "kind": payload.get("kind"),
                              "reference": ref})
            seen_artifacts.add(logical_id)
    artifacts.sort(key=lambda item: item["artifact_identity"])
    if not artifacts:
        gaps.append("accepted_artifacts_unavailable: no native artifact catalog entries")
    return {"artifacts": artifacts, "gaps": sorted(set(gaps)),
            "upstream_manifest": dict(upstream),
            "artifact_handoff_sha256": accepted["handoff_sha256"],
            "language_build_handoff_sha256": language_sha}


def _decision(unit: UnitContext, reader_identity: str) -> Mapping[str, Any]:
    started = time.monotonic()
    settings = parse_debug_symbol_settings(unit.job.config.settings)
    inputs = _accepted_inputs(unit, settings)
    target = CompilerTarget(settings["compiler_target"])
    document = {"schema": DECISION_SCHEMA, "compiler_target": target.value,
                "selected_lane": selected_path(target), "source_fingerprint": unit.job.source_fingerprint,
                "reader_identity": reader_identity, "settings": settings, **inputs}
    document["input_fingerprint"] = _digest(document)
    identity = _artifact(unit, "decision.json", document)
    _emit(unit, "DEBUG_SYMBOL_TARGET_SELECTED", target=target.value, lane=selected_path(target),
          started=started, artifact_count=len(inputs["artifacts"]), gap_count=len(inputs["gaps"]))
    return {"artifact": identity, "input_fingerprint": document["input_fingerprint"],
            "compiler_target": target.value, "selected_lane": selected_path(target),
            "terminal_status": "SUCCEEDED"}


def _read_decision(unit: UnitContext, reader_identity: str) -> dict[str, Any]:
    output = unit.output("decide.target")
    path = _verify(unit.job.run_root, output["artifact"], "debug-symbol decision")
    decision = json.loads(path.read_text(encoding="utf-8"))
    body = {key: value for key, value in decision.items() if key != "input_fingerprint"}
    settings = parse_debug_symbol_settings(unit.job.config.settings)
    if (decision.get("schema") != DECISION_SCHEMA or _digest(body) != decision.get("input_fingerprint")
            or output["input_fingerprint"] != decision["input_fingerprint"]
            or decision["settings"] != settings or decision["reader_identity"] != reader_identity
            or decision["source_fingerprint"] != unit.job.source_fingerprint
            or decision["selected_lane"] != selected_path(CompilerTarget(settings["compiler_target"]))):
        raise ValueError("debug-symbol decision does not match immutable inputs")
    return decision


def _probe(root: Path, artifact: Mapping[str, Any], maximum: int) -> dict[str, Any]:
    ref = artifact.get("reference")
    value = {"artifact_identity": artifact["artifact_identity"], "expected": ref}
    is_debug = artifact.get("kind") in _DEBUG_KINDS
    try:
        if not isinstance(ref, Mapping):
            raise ValueError("accepted object reference unavailable")
        try:
            path = safe_path(root, ref["path"])
        except (KeyError, TypeError, ValueError) as exc:
            raise FrameworkIntegrityError("binary/debug artifact reference is invalid") from exc
        size = path.stat().st_size
        if size > maximum:
            value["observed"] = {"size_bytes": size, "error": "max_input_bytes"}
            return {**artifact, "probe": value, "is_debug": is_debug, "gap": "max_input_bytes"}
        value["observed"] = {"sha256": file_sha256(path), "size_bytes": size}
        _verify(root, ref, "binary/debug artifact", maximum)
        with path.open("rb") as stream:
            header = stream.read(64)
        debug = header.startswith(b"Microsoft C/C++ MSF") or is_debug
        return {**artifact, "probe": value, "path": path, "is_debug": debug}
    except FrameworkIntegrityError:
        raise
    except (OSError, KeyError, TypeError, ValueError):
        value.setdefault("observed", {"error": "artifact_integrity_unavailable"})
        return {**artifact, "probe": value, "is_debug": is_debug, "gap": "artifact_integrity_unavailable"}


def _private_text(value: str) -> str:
    if re.search(r"(?:[A-Za-z]:[\\/]|(?:^|\s)/[^/\s]|\\\\)", value):
        return "source-name-sha256:" + hashlib.sha256(value.encode()).hexdigest()
    return value


def _approved_data(value: Any, *, depth: int = 0) -> Any:
    if depth > 16:
        raise ValueError("normalized debug-symbol metadata exceeds depth limit")
    if isinstance(value, Mapping):
        output = {}
        for key, child in value.items():
            if (any(part in str(key).lower() for part in ("path", "directory", "comp_dir", "source"))
                    or str(key).lower() in {"file", "filename", "file_name", "source", "source_file"}):
                output[str(key) + "_sha256"] = _digest(child)
            else:
                output[_private_text(str(key))] = _approved_data(child, depth=depth + 1)
        return output
    if isinstance(value, (tuple, list)):
        return [_approved_data(child, depth=depth + 1) for child in value]
    return _private_text(value) if isinstance(value, str) else value


class _Sources:
    """Resolve checksums against bounded accepted indices, never a recorded source path."""

    def __init__(self, unit: UnitContext, decision: Mapping[str, Any]):
        self.unit = unit
        self.maximum = min(decision["settings"]["reader"]["max_input_bytes"], 16 * 1024 * 1024)
        self.limit = decision["settings"]["reader"]["max_records"]
        self.rows = []
        self.cache = {}
        self.by_path = {}
        self.by_sha256 = {}
        self.line_offsets = {}
        self.line_offset_bytes = 0
        prior, _ = load_verified_manifest(
            unit.job.run_root, unit.job.run_root / decision["upstream_manifest"]["path"],
            decision["upstream_manifest"]["sha256"])
        seen = set()
        for shard in prior["indexes"]:
            if shard["name"] != "source":
                continue
            path = safe_path(unit.job.run_root, shard["relative_path"])
            with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro&immutable=1", uri=True) as db:
                rows = db.execute(
                    "SELECT e.identity,l.path,l.file_sha256,e.payload_json "
                    "FROM entities e JOIN locations l ON e.identity=l.entity_id "
                    "WHERE e.kind=? ORDER BY e.identity LIMIT ?",
                    (EntityKind.SOURCE_FILE.value, self.limit + 1)).fetchall()
            for identity, source_path, digest, payload in rows:
                if identity not in seen and len(self.rows) < self.limit:
                    logical = LogicalIdentity.parse(identity)
                    expected = LogicalIdentity.derive(EntityKind.SOURCE_FILE, unit.job.source_fingerprint,
                                                       {"path": source_path, "sha256": digest})
                    if logical != expected:
                        continue
                    seen.add(identity)
                    self.rows.append({"identity": identity, "path": source_path, "sha256": digest,
                                      "payload": json.loads(payload), "shard": path})
                    self.by_path.setdefault(source_path, []).append(self.rows[-1])
                    self.by_sha256.setdefault(digest, []).append(self.rows[-1])

    def _bytes(self, row: Mapping[str, Any]) -> bytes:
        digest = row["sha256"]
        if digest in self.cache:
            return self.cache[digest]
        root = self.unit.job.run_root
        path = safe_path(root, f"data/shared/objects/{digest}")
        if path.is_file():
            if path.stat().st_size > self.maximum:
                raise ValueError("accepted source exceeds byte limit")
            data = path.read_bytes()
        elif "source_backing" in row["payload"]:
            from appsec_review.retrieval.source_resolution import read_source_bytes
            data = read_source_bytes(
                root, root, target_snapshot=self.unit.job.source_fingerprint, path=row["path"],
                sha256=digest, native={"source_domain": "generated",
                                       "source_backing": row["payload"]["source_backing"]},
                limit=self.maximum)
        else:
            # Full source text is run-owned evidence only if its reconstructed bytes match the
            # accepted file checksum. Truncated text or newline conversion cannot establish this.
            with sqlite3.connect(f"{row['shard'].resolve().as_uri()}?mode=ro&immutable=1", uri=True) as db:
                text = db.execute("SELECT text FROM entities WHERE identity=?", (row["identity"],)).fetchone()[0]
            data = text.encode("utf-8")
        if len(data) > self.maximum or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("accepted source bytes unavailable or changed")
        if sum(len(item) for item in self.cache.values()) + len(data) <= self.maximum:
            self.cache[digest] = data
        return data

    def _line_table(self, digest: str, data: bytes) -> array[int] | None:
        if digest in self.line_offsets:
            return self.line_offsets[digest]
        offsets = array("Q", [0])
        for match in re.finditer(rb"\r\n|\r|\n", data):
            offsets.append(match.end())
            if len(offsets) * offsets.itemsize > self.maximum:
                return None
        if offsets[-1] != len(data):
            offsets.append(len(data))
        size = len(offsets) * offsets.itemsize
        if size > self.maximum:
            return None
        if self.line_offset_bytes + size <= self.maximum:
            self.line_offsets[digest] = offsets
            self.line_offset_bytes += size
        return offsets

    def resolve(self, span) -> tuple[Mapping[str, Any] | None, str | None]:
        if not span.checksum or not span.checksum_kind:
            return None, "source_mapping_unverified: checksum unavailable"
        if not isinstance(span.checksum, str) or not isinstance(span.checksum_kind, str):
            return None, "source_checksum_invalid"
        algorithm = span.checksum_kind.lower().replace("-", "")
        if algorithm not in {"sha256", "md5"}:
            return None, "source_checksum_algorithm_unsupported"
        expected_length = 64 if algorithm == "sha256" else 32
        if re.fullmatch(r"[0-9a-fA-F]{" + str(expected_length) + "}", span.checksum) is None:
            return None, "source_checksum_invalid"
        recorded = span.path.replace("\\", "/")
        candidates = {}
        if algorithm == "sha256":
            for row in self.by_sha256.get(span.checksum.lower(), ()):
                candidates[row["identity"]] = row
        parts = recorded.split("/")
        for position in range(len(parts)):
            for row in self.by_path.get("/".join(parts[position:]), ()):
                candidates[row["identity"]] = row
        matched = []
        for identity in sorted(candidates):
            row = candidates[identity]
            try:
                data = self._bytes(row)
            except (OSError, ValueError):
                continue
            if hashlib.new(algorithm, data, usedforsecurity=False).hexdigest() != span.checksum.lower():
                continue
            offsets = self._line_table(row["sha256"], data)
            if offsets is None:
                return None, "source_line_offset_bound"
            if not 1 <= span.line < len(offsets):
                continue
            start, end = offsets[span.line - 1], offsets[span.line]
            if span.column > len(data[start:end].rstrip(b"\r\n")) + 1:
                continue
            matched.append({**row, "start_byte": start, "end_byte": end})
            if len(matched) > 1:
                return None, "source_checksum_ambiguous"
        if len(matched) != 1:
            return None, "source_checksum_ambiguous" if matched else "source_checksum_unverified"
        return matched[0], None


def _normalize(builder: IndexBuilder, artifact: Mapping[str, Any], debug: Mapping[str, Any] | None,
               extraction: Extraction, unit: UnitContext, target: str, sources: _Sources) -> list[str]:
    ref = artifact["reference"]
    debug_ref = debug["reference"] if debug else ref
    identities = {}
    source_bindings = {}
    gaps = [_private_text(gap) for gap in extraction.gaps]
    for record in extraction.records:
        if record.key in identities:
            raise ValueError("duplicate native debug-symbol record key")
        binding, gap = sources.resolve(record.source) if record.source is not None else (None, None)
        source_bindings[record.key] = binding
        if gap:
            gaps.append(gap)
        kind = (EntityKind.SOURCE_SPAN if record.kind is RecordKind.SOURCE_RANGE and binding
                else _RECORD_KINDS[record.kind])
        identities[record.key] = LogicalIdentity.derive(
            kind, unit.job.source_fingerprint, {
                "compiler_target": target, "artifact_identity": artifact["artifact_identity"],
                "record_fingerprint": record_fingerprint(ref["sha256"], debug_ref["sha256"], record.key),
                "record_kind": record.kind.value})
    for record in extraction.records:
        data = dict(_approved_data(record.data))
        # A reader's recorded path or asserted identity cannot create accepted source authority.
        for key in ("source_identity", "location", "evidence", "artifact_identity"):
            data.pop(key, None)
        payload = {**data, "record_kind": record.kind.value,
                   "artifact_identity": artifact["artifact_identity"], "artifact_sha256": ref["sha256"],
                   "debug_sha256": debug_ref["sha256"], "compiler_target": target,
                   "address_ranges": [asdict(interval) for interval in record.ranges],
                   "native_key": _private_text(record.key),
                   "parent_key": _private_text(record.parent_key) if record.parent_key else None,
                   "evidence": dict(ref), "debug_evidence": dict(debug_ref),
                   "reader_identity": _private_text(extraction.producer or READER_IDENTITY)}
        binding = source_bindings[record.key]
        location = None
        if record.source is not None:
            source = record.source
            payload.update({"source_name_sha256": hashlib.sha256(source.path.encode()).hexdigest(),
                            "line": source.line, "column": source.column, "end_line": source.line,
                            "source_mapping": "checksum-verified" if binding else "unverified"})
            if binding:
                from appsec_review.retrieval.model import SourceLocation
                payload.update({"source_identity": binding["identity"], "source_path": binding["path"]})
                location = SourceLocation(
                    unit.job.source_fingerprint, binding["path"], binding["sha256"],
                    binding["start_byte"], binding["end_byte"], source.line, source.line,
                    max(1, source.column), max(1, source.column),
                    {"artifact_identity": artifact["artifact_identity"], "checksum_kind": source.checksum_kind,
                     **({"source_domain": "generated", "source_backing": binding["payload"]["source_backing"]}
                        if "source_backing" in binding["payload"] else {})},
                    "debug-symbol-checksum-verified", 1.0)
        identity = identities[record.key]
        name = _private_text(record.name)
        if record.kind is RecordKind.COMPILATION_UNIT:
            name = binding["path"] if binding else "compilation-unit:" + hashlib.sha256(record.name.encode()).hexdigest()
        elif record.source is not None and record.name == record.source.path:
            name = binding["path"] if binding else "source-name-sha256:" + hashlib.sha256(record.name.encode()).hexdigest()
        builder.add_entity(EntityRecord(identity, _private_text(record.key), name, name, payload, location))
        builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, identity.value,
                            artifact["artifact_identity"], True, 1.0,
                            payload={"evidence": dict(ref)}))
        if binding:
            builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT, identity.value,
                                binding["identity"], True, 1.0,
                                payload={"checksum_kind": record.source.checksum_kind}))
        if record.parent_key in identities:
            builder.add_relation(RelationRecord(RelationKind.CONTAINS, identities[record.parent_key].value,
                                identity.value, True, 1.0, payload={"evidence": dict(debug_ref)}))
        elif record.parent_key is not None:
            gaps.append("native_parent_unavailable")
    return sorted(set(gaps))


def _extract(unit: UnitContext, lane: str, reader_identity: str, extractor) -> Mapping[str, Any]:
    started = time.monotonic()
    decision = _read_decision(unit, reader_identity)
    target = CompilerTarget(decision["compiler_target"])
    if lane != decision["selected_lane"]:
        unit.job.events.write("DEBUG_SYMBOL_LANE_SKIPPED", unit_id=unit.unit_id,
                              compiler_target=target.value, lane=lane, record_count=0,
                              artifact_count=0, gap_count=0, duration_ms=0)
        return {"status": "SKIPPED", "terminal_status": "SKIPPED_NA", "reason": "unselected_compiler_target",
                "input_fingerprint": _digest([decision["input_fingerprint"], lane, reader_identity]),
                "indexes": [], "gaps": []}
    settings = decision["settings"]
    probes = [_probe(unit.job.run_root, artifact, settings["reader"]["max_input_bytes"])
              for artifact in decision["artifacts"]]
    fingerprint = _digest({"schema": RECORD_SCHEMA, "decision": decision["input_fingerprint"],
                           "lane": lane, "reader_identity": reader_identity,
                           "probes": [item["probe"] for item in probes]})
    shard_id = f"symbols-{lane}"
    path = unit.job.run_root / "data" / "indices" / INDEX_NAME / f"{fingerprint}.sqlite"
    builder = IndexBuilder(path, name=INDEX_NAME, fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard_id)
    all_gaps = list(decision["gaps"])
    raw_refs = []
    sources = _Sources(unit, decision)
    debug_candidates = [item for item in probes if item.get("is_debug")]
    artifact_count = 0
    output_bytes = 0
    reader = extractor
    if reader is None:
        try:
            reader = importlib.import_module("appsec_review.debug_symbols.readers").extract_symbols
        except ImportError:
            all_gaps.append("debug_symbol_reader_unavailable")
    for artifact in probes:
        if artifact.get("is_debug"):
            continue
        artifact_started = time.monotonic()
        artifact_count += 1
        gaps = []
        extracted = None
        debug = None
        if artifact.get("gap"):
            gaps.append(artifact["gap"])
        elif not settings["enabled"]:
            gaps.append("debug_symbol_indexing_disabled")
        elif reader is None:
            gaps.append("debug_symbol_reader_unavailable")
        else:
            companions = debug_candidates if target is CompilerTarget.MSVC else [None, *debug_candidates]
            if not companions:
                gaps.append("missing_debug_artifact")
            matches = []
            for candidate in companions:
                if candidate is not None and candidate.get("gap"):
                    gaps.append(candidate["gap"])
                    continue
                try:
                    binary_path = _verify(unit.job.run_root, artifact["reference"],
                                          "binary artifact", settings["reader"]["max_input_bytes"])
                    debug_path = (_verify(unit.job.run_root, candidate["reference"], "debug artifact",
                                          settings["reader"]["max_input_bytes"]) if candidate else None)
                    result = reader(binary_path, debug_path, target=target, settings=settings["reader"])
                    _verify(unit.job.run_root, artifact["reference"], "binary artifact",
                            settings["reader"]["max_input_bytes"])
                    if candidate:
                        _verify(unit.job.run_root, candidate["reference"], "debug artifact",
                                settings["reader"]["max_input_bytes"])
                    if not isinstance(result, Extraction):
                        raise FrameworkIntegrityError("invalid extraction contract")
                    if len(result.records) > settings["reader"]["max_records"]:
                        gaps.append("max_records")
                        continue
                    if len(builder.entities) + len(result.records) > settings["reader"]["max_records"]:
                        gaps.append("max_records_total")
                        continue
                    result_bytes = len(canonical_json(asdict(result)))
                    if output_bytes + result_bytes > settings["reader"]["max_output_bytes"]:
                        gaps.append("max_output_bytes")
                        continue
                    if result.records:
                        matches.append((result, candidate))
                        if candidate is None:
                            break
                    else:
                        gaps.extend(_private_text(gap) for gap in result.gaps or ("debug_symbols_unavailable",))
                except FrameworkIntegrityError:
                    raise
                except Exception as exc:
                    gaps.append(f"reader_failed: {type(exc).__name__}")
            distinct = {(candidate["reference"]["sha256"] if candidate else artifact["reference"]["sha256"])
                        for _, candidate in matches}
            if len(distinct) > 1:
                gaps.append("ambiguous_debug_artifact")
            elif matches:
                extracted, debug = matches[0]
                # Failed candidate pairing is not a coverage gap after exactly one match is proved.
                gaps = list(extracted.gaps)
                try:
                    gaps = _normalize(builder, artifact, debug, extracted, unit, target.value, sources)
                    output_bytes += len(canonical_json(asdict(extracted)))
                except (ValueError, KeyError, TypeError):
                    raise ValueError("invalid normalized debug-symbol records") from None
        if extracted is None and not gaps:
            gaps.append("debug_symbols_unavailable")
        coverage = "partial" if extracted and gaps else "complete" if extracted else "unavailable"
        builder.add_coverage(artifact["artifact_identity"], coverage, "; ".join(sorted(set(gaps))) or None)
        all_gaps.extend(f"{artifact['artifact_identity']}: {gap}" for gap in gaps)
        raw_refs.append({"artifact_identity": artifact["artifact_identity"],
                         "binary": artifact.get("reference"),
                         "debug": debug.get("reference") if debug else None,
                         "reader_records": [asdict(record) for record in extracted.records] if extracted else [],
                         "status": coverage})
        _emit(unit, "DEBUG_SYMBOL_ARTIFACT_COMPLETED" if extracted else "DEBUG_SYMBOL_ARTIFACT_FAILED",
              target=target.value, lane=lane, started=artifact_started, artifact_count=1,
              record_count=len(extracted.records) if extracted else 0, gap_count=len(set(gaps)))
    if not artifact_count:
        all_gaps.append("native_binary_unavailable")
        builder.add_coverage("native-artifacts", "unavailable", "native_binary_unavailable")
    all_gaps = sorted(set(all_gaps))
    digest = builder.build()
    identity = IndexIdentity(INDEX_NAME, INDEX_SCHEMA, digest, fingerprint,
                             path.relative_to(unit.job.run_root).as_posix(),
                             {"job_id": JOB_ID, "compiler_target": target.value, "lane": lane,
                              "reader_identity": reader_identity}, tuple(all_gaps), shard_id)
    raw = _artifact(unit, "raw-refs.json", {"schema": "appsec-review/debug-symbol-inputs/1",
                                         "compiler_target": target.value, "artifacts": raw_refs})
    coverage_ref = _artifact(unit, "coverage.json", {
        "schema": "appsec-review/debug-symbol-coverage/1", "compiler_target": target.value,
        "coverage": [{"artifact_identity": area, "status": status, "gap": gap}
                     for area, status, gap in builder.coverage]})
    return {"status": "COMPLETED", "indexes": [asdict(identity)], "artifact": raw,
            "coverage": coverage_ref,
            "input_fingerprint": fingerprint, "record_count": len(builder.entities),
            "artifact_count": artifact_count, "gaps": all_gaps,
            "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
            "terminal_status": "COMPLETED_WITH_GAPS" if all_gaps else "SUCCEEDED"}


def _publish(unit: UnitContext, reader_identity: str) -> Mapping[str, Any]:
    started = time.monotonic()
    decision = _read_decision(unit, reader_identity)
    lane = decision["selected_lane"]
    selected = unit.output(f"extract.{lane}")
    other = unit.output("extract.msvc_pdb" if lane == "clang_dwarf" else "extract.clang_dwarf")
    if other.get("status") != "SKIPPED" or other.get("indexes") or not selected.get("indexes"):
        raise ValueError("debug-symbol publication requires exactly one selected lane")
    prior, _ = load_verified_manifest(unit.job.run_root,
                                      unit.job.run_root / decision["upstream_manifest"]["path"],
                                      decision["upstream_manifest"]["sha256"])
    current = [item for item in prior["indexes"] if item["name"] != INDEX_NAME] + selected["indexes"]
    indexes = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))}) for item in current]
    manifest_path = (unit.job.run_root / "data" / "indices" / "manifests"
                     / f"debug-symbol-indexing-{unit.job.attempt_id}.json")
    write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                   target_root=unit.job.target_root or unit.job.repository_root, indexes=indexes,
                   upstream_manifests=(decision["upstream_manifest"],))
    manifest_ref = _ref(unit.job.run_root, manifest_path)
    load_verified_manifest(unit.job.run_root, manifest_path, manifest_ref["sha256"])
    summary = {"schema": SCHEMA, "source_fingerprint": unit.job.source_fingerprint,
               "compiler_target": decision["compiler_target"], "selected_lane": lane,
               "decision": dict(unit.output("decide.target")["artifact"]),
               "input_fingerprint": selected["input_fingerprint"],
               "artifact_handoff_sha256": decision["artifact_handoff_sha256"],
               "record_count": selected["record_count"], "artifact_count": selected["artifact_count"],
               "gaps": selected["gaps"], "index_manifest": manifest_ref}
    artifact = _artifact(unit, "accepted-index.json", summary)
    _emit(unit, "DEBUG_SYMBOL_INDEX_COMPLETED", target=decision["compiler_target"], lane=lane,
          started=started - selected.get("duration_ms", 0) / 1000,
          record_count=selected["record_count"], artifact_count=selected["artifact_count"],
          gap_count=len(selected["gaps"]))
    return {"schema": SCHEMA, "artifact": artifact, "index_manifest": manifest_ref,
            "item_count": selected["record_count"], "gaps": selected["gaps"],
            "terminal_status": "COMPLETED_WITH_GAPS" if selected["gaps"] else "SUCCEEDED"}


def _validate_config(context, _result) -> None:
    parse_debug_symbol_settings(context.config.settings)
    if tuple(context.config.steps) != tuple(_TOPOLOGY):
        raise ValueError("debug-symbol indexing topology differs from central configuration")
    if any(tuple(context.config.step(step).tasks) != tasks for step, tasks in _TOPOLOGY.items()):
        raise ValueError("debug-symbol indexing tasks differ from central configuration")


def load_accepted_debug_symbols(run_root: Path) -> Mapping[str, Any]:
    pointer_path = run_root / "data" / "jobs" / JOB_ID / "latest.json"
    if not pointer_path.is_file():
        raise ValueError("accepted debug-symbol handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff_ref = {"path": pointer["handoff_path"], "sha256": pointer["handoff_sha256"]}
    path = safe_path(run_root, handoff_ref["path"])
    handoff_ref["size_bytes"] = path.stat().st_size
    handoff = json.loads(_verify(run_root, handoff_ref, "accepted debug-symbol handoff").read_text())
    if (handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED"
            or handoff.get("job_id") != JOB_ID):
        raise ValueError("debug-symbol handoff is not accepted")
    published = handoff.get("outputs", {}).get("acceptance.publish_handoff", {})
    artifact = published.get("artifact", {})
    if not any(item.get("path") == artifact.get("path") and item.get("sha256") == artifact.get("sha256")
               for item in handoff.get("artifacts", ())):
        raise ValueError("debug-symbol summary is not bound to accepted handoff")
    document = json.loads(_verify(run_root, artifact, "accepted debug-symbol summary").read_text())
    if document.get("schema") != SCHEMA:
        raise ValueError("unsupported accepted debug-symbol schema")
    decision = json.loads(_verify(run_root, document["decision"], "accepted debug-symbol decision").read_text())
    body = {key: value for key, value in decision.items() if key != "input_fingerprint"}
    if (decision.get("schema") != DECISION_SCHEMA
            or decision.get("input_fingerprint") != _digest(body)
            or decision.get("compiler_target") != document.get("compiler_target")
            or decision.get("source_fingerprint") != document.get("source_fingerprint")
            or decision.get("selected_lane") != document.get("selected_lane")
            or document.get("selected_lane") != selected_path(CompilerTarget(document.get("compiler_target")))):
        raise ValueError("accepted debug-symbol decision binding differs")
    manifest = published["index_manifest"]
    if manifest != document["index_manifest"]:
        raise ValueError("accepted debug-symbol manifest binding differs")
    load_verified_manifest(run_root, _verify(run_root, manifest, "accepted debug-symbol manifest"),
                           manifest["sha256"])
    return {**document, "handoff_sha256": pointer["handoff_sha256"]}


def build_job(*, extractor=None) -> Job:
    """Build the four-unit decision/extraction/publication DAG.

    An injected extractor implements ``extract_symbols`` from ``debug_symbols.readers`` and
    receives the flat, validated ``settings["reader"]`` mapping. The unselected task persists a
    semantic SKIPPED result with SKIPPED_NA disposition; its successful execution receipt allows
    the shared executor to join both branches without treating deliberate routing as a failure.
    """
    reader_identity = _reader_identity(extractor)
    units = (
        Unit("decide.target", lambda unit: _decision(unit, reader_identity)),
        Unit("extract.clang_dwarf", lambda unit: _extract(unit, "clang_dwarf", reader_identity, extractor),
             ("decide.target",)),
        Unit("extract.msvc_pdb", lambda unit: _extract(unit, "msvc_pdb", reader_identity, extractor),
             ("decide.target",)),
        Unit("acceptance.publish_handoff", lambda unit: _publish(unit, reader_identity),
             ("extract.clang_dwarf", "extract.msvc_pdb")),
    )
    return Job(JOB_ID, "debug_symbol_indexing", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA, units=units,
               datasets=DATASETS, consumes=CONSUMES)
