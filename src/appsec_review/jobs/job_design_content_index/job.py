"""Full-text content chunks and structured interface operations for discovered design artifacts."""
from __future__ import annotations

from bisect import bisect_right
from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256

from .chunking import (
    CHUNKER_IDENTITY, SKIPPED_SUFFIXES, Chunk, Lines, markdown, split_oversized, structural_chunks, windows,
)
from .interfaces import EXTRACTOR_IDENTITY, EXTRACTORS, SpecificationError


JOB_ID = "job_design_content_index"
SHARD_ID = "design_content"
TOPOLOGY: Mapping[str, tuple[str, ...]] = {
    "content_input": ("load_inputs",),
    "interface_extraction": ("extract_interfaces",),
    "content_chunking": ("chunk_documents",),
    "content_publication": ("build_index", "publish_handoff"),
}
_CONTENT_CATEGORIES = {"design_document", "threat_model", "api_specification", "interface_definition",
                       "data_schema", "api_test"}


def _rel(run_root: Path, path: Path) -> str:
    return path.resolve().relative_to(run_root.resolve()).as_posix()


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": _rel(run_root, path), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _write(unit: UnitContext, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    path = unit.job.attempt_root / "artifacts" / "design-content" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(path, value)
    return _artifact(unit.job.run_root, path)


def _read(run_root: Path, identity: Mapping[str, Any]) -> Any:
    path = (run_root / str(identity["path"])).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or file_sha256(path) != identity["sha256"]:
        raise ValueError("design content artifact identity mismatch")
    return json.loads(path.read_text(encoding="utf-8"))


def _bounds(settings: Mapping[str, Any]) -> dict[str, int]:
    values = {"max_files": int(settings.get("max_files", 5_000)),
              "max_file_bytes": int(settings.get("max_file_bytes", 1_048_576)),
              "max_chunk_lines": int(settings.get("max_chunk_lines", 80)),
              "max_chunk_bytes": int(settings.get("max_chunk_bytes", 8_192)),
              "max_chunks": int(settings.get("max_chunks", 100_000)),
              "max_operations": int(settings.get("max_operations", 50_000))}
    if not 1 <= values["max_files"] <= 100_000 or not 1 <= values["max_file_bytes"] <= 16 * 1024 * 1024:
        raise ValueError("design content file bounds are outside the supported range")
    if not 5 <= values["max_chunk_lines"] <= 2_000 or not 512 <= values["max_chunk_bytes"] <= 131_072:
        raise ValueError("design content chunk bounds are outside the supported range")
    if not 1 <= values["max_chunks"] <= 1_000_000 or not 1 <= values["max_operations"] <= 1_000_000:
        raise ValueError("design content count bounds are outside the supported range")
    return values


def _subtype(artifact: Mapping[str, Any], categories: set[str]) -> str | None:
    for wanted in ("api_specification", "interface_definition"):
        for item in artifact["categories"]:
            if item["category"] == wanted and item["subtype"] in EXTRACTORS:
                return str(item["subtype"])
    return None


def _source_text(unit: UnitContext, artifact: Mapping[str, Any], bounds: Mapping[str, int]
                 ) -> tuple[str | None, str | None]:
    target_root = (unit.job.target_root or Path()).resolve()
    source = (target_root / str(artifact["path"])).resolve()
    if target_root not in source.parents or not source.is_file():
        return None, "cataloged file is unavailable"
    if source.stat().st_size > bounds["max_file_bytes"]:
        return None, f"content skipped above max_file_bytes={bounds['max_file_bytes']}"
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != artifact["sha256"]:
        raise ValueError(f"target file changed after catalog acceptance: {artifact['path']}")
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "content is not UTF-8 text"


def _fill(lines: Lines, chunks: list[Chunk], *, max_lines: int, kind: str = "specification") -> list[Chunk]:
    """Cover lines that no structural chunk owns, so every non-blank line stays searchable."""
    covered = {line for chunk in chunks for line in range(chunk.start_line, chunk.end_line + 1)}
    extra: list[Chunk] = []
    start = None
    for number in range(1, len(lines) + 2):
        free = number <= len(lines) and number not in covered
        if free and start is None:
            start = number
        elif not free and start is not None:
            extra.extend(windows(lines, max_lines=max_lines, start=start, end=number - 1, kind=kind,
                                 heading=kind))
            start = None
    return sorted([*chunks, *extra], key=lambda chunk: (chunk.start_line, chunk.end_line))


def build_job() -> Job:
    def validate(context, result) -> None:
        if context.target_root is None:
            raise ValueError("design content indexing requires a graph-provided target root")
        if tuple(context.config.steps) != tuple(TOPOLOGY):
            raise ValueError("design content topology does not match central configuration")
        for step, tasks in TOPOLOGY.items():
            if tuple(context.config.step(step).tasks) != tasks:
                raise ValueError(f"design content task order mismatch: {step}")
        _bounds(context.config.settings)

    def load_inputs(unit: UnitContext) -> Mapping[str, Any]:
        from appsec_review.jobs.job_design_artifact_discovery import load_accepted_design_artifacts
        from appsec_review.jobs.job_document_conversion import load_accepted_conversions

        design = load_accepted_design_artifacts(unit.job.run_root)
        if design is None:
            raise ValueError("accepted job_design_artifact_discovery handoff is required")
        if design["source_fingerprint"] != unit.job.source_fingerprint:
            raise ValueError("design content fingerprint does not match accepted design discovery")
        conversions = load_accepted_conversions(unit.job.run_root)
        gaps: list[str] = []
        status = "ACCEPTED"
        if conversions is None:
            status = "UNAVAILABLE"
            gaps.append("converted documents: job_document_conversion has no accepted handoff for this run")
        elif conversions["design_handoff_sha256"] != design["handoff_sha256"]:
            status = "STALE"
            gaps.append("converted documents: accepted conversion is bound to a different design discovery")
        else:
            gaps.extend(f"converted documents: {gap}" for gap in conversions["gaps"])
        document = {"schema": "appsec-review/design-content-inputs/1",
                    "design_handoff_sha256": design["handoff_sha256"],
                    "conversion_status": status,
                    "conversion_handoff_sha256": conversions["handoff_sha256"] if conversions else None,
                    "artifacts": design["artifacts"],
                    "converted": conversions["documents"] if status == "ACCEPTED" else [], "gaps": gaps}
        return {"artifact": _write(unit, "inputs.json", document), "gaps": gaps,
                "conversion_status": status, "design_handoff_sha256": design["handoff_sha256"]}

    def extract(unit: UnitContext) -> Mapping[str, Any]:
        inputs = _read(unit.job.run_root, unit.output("content_input.load_inputs")["artifact"])
        bounds = _bounds(unit.job.config.settings)
        operations: list[dict[str, Any]] = []
        specifications: list[dict[str, Any]] = []
        gaps: list[str] = []
        for artifact in inputs["artifacts"]:
            categories = {item["category"] for item in artifact["categories"]}
            subtype = _subtype(artifact, categories)
            if subtype is None or not artifact["cataloged"]:
                continue
            text, gap = _source_text(unit, artifact, bounds)
            if text is None:
                gaps.append(f"{artifact['path']}: interface extraction skipped; {gap}")
                continue
            try:
                found, facts = EXTRACTORS[subtype](text)
            except (SpecificationError, RecursionError) as exc:
                gaps.append(f"{artifact['path']}: interface extraction failed; {exc}")
                continue
            specifications.append({"path": artifact["path"], "sha256": artifact["sha256"],
                                   "artifact_id": artifact["artifact_id"], "subtype": subtype, "facts": facts})
            for operation in found:
                if len(operations) >= bounds["max_operations"]:
                    gaps.append(f"interface extraction stopped at max_operations={bounds['max_operations']}")
                    break
                operation_id = "dio:" + hashlib.sha256(canonical_json({
                    "path": artifact["path"], "sha256": artifact["sha256"], "name": operation["name"],
                    "start_line": operation["start_line"]})).hexdigest()
                operations.append({**operation, "interface_operation_id": operation_id,
                                   "artifact_path": artifact["path"], "artifact_sha256": artifact["sha256"],
                                   "artifact_id": artifact["artifact_id"], "specification": subtype})
        document = {"schema": "appsec-review/design-interface-operations/1", "extractor": EXTRACTOR_IDENTITY,
                    "specifications": specifications, "operations": operations, "gaps": gaps}
        return {"artifact": _write(unit, "interface-operations.json", document), "item_count": len(operations),
                "gaps": gaps}

    def chunk(unit: UnitContext) -> Mapping[str, Any]:
        inputs = _read(unit.job.run_root, unit.output("content_input.load_inputs")["artifact"])
        extracted = _read(unit.job.run_root, unit.output("interface_extraction.extract_interfaces")["artifact"])
        bounds = _bounds(unit.job.config.settings)
        by_path: dict[str, list[Mapping[str, Any]]] = {}
        for operation in extracted["operations"]:
            by_path.setdefault(operation["artifact_path"], []).append(operation)
        chunks: list[dict[str, Any]] = []
        gaps: list[str] = []
        files = 0
        stopped = False

        def emit(source: Mapping[str, Any], lines: Lines, parts: list[Chunk], method: str,
                 converted: Mapping[str, Any] | None = None) -> None:
            nonlocal stopped
            for part in split_oversized(lines, parts, max_lines=bounds["max_chunk_lines"],
                                        max_bytes=bounds["max_chunk_bytes"]):
                if len(chunks) >= bounds["max_chunks"]:
                    if not stopped:
                        gaps.append(f"content chunking stopped at max_chunks={bounds['max_chunks']}")
                    stopped = True
                    return
                text = lines.span_text(part.start_line, part.end_line)
                start_byte, end_byte = lines.bytes_span(part.start_line, part.end_line)
                start_char, end_char = lines.chars_span(part.start_line, part.end_line)
                identity = {"path": source["path"], "sha256": source["sha256"],
                            "converted": converted is not None, "start_line": part.start_line,
                            "end_line": part.end_line}
                record = {
                    "chunk_id": "dcc:" + hashlib.sha256(canonical_json(identity)).hexdigest(),
                    "artifact_path": source["path"], "artifact_id": source["artifact_id"],
                    "file_sha256": source["sha256"], "categories": source["categories"],
                    "subtypes": source["subtypes"], "chunk_kind": part.kind, "chunk_method": method,
                    "heading": part.heading, "heading_path": list(part.heading_path),
                    "start_line": part.start_line, "end_line": part.end_line,
                    "start_byte": start_byte, "end_byte": end_byte, "converted": converted is not None,
                    "operation_ids": sorted(item["interface_operation_id"] for item in by_path.get(source["path"], ())
                                            if part.start_line <= item["start_line"] <= part.end_line),
                    "text": text,
                }
                if converted is not None:
                    record.update(conversion_text_artifact={"artifact_path": converted["text"]["path"],
                                                            "sha256": converted["text"]["sha256"]},
                                  start_char=start_char, end_char=end_char,
                                  segment=part.attributes.get("segment"), start_byte=None, end_byte=None)
                chunks.append(record)

        for artifact in inputs["artifacts"]:
            categories = {item["category"] for item in artifact["categories"]}
            suffix = PurePosixPath(str(artifact["path"])).suffix.lower()
            if not artifact["cataloged"] or not categories & _CONTENT_CATEGORIES or suffix in SKIPPED_SUFFIXES:
                continue
            if stopped:
                break
            if files >= bounds["max_files"]:
                gaps.append(f"content chunking stopped at max_files={bounds['max_files']}")
                break
            text, gap = _source_text(unit, artifact, bounds)
            if text is None:
                gaps.append(f"{artifact['path']}: content not indexed; {gap}")
                continue
            files += 1
            lines = Lines(text)
            operations = by_path.get(str(artifact["path"]), [])
            if operations and _subtype(artifact, categories) in {"openapi", "swagger", "asyncapi"}:
                parts = [Chunk(item["start_line"], item["end_line"], "operation", item["name"])
                         for item in operations]
                parts, method = _fill(lines, parts, max_lines=bounds["max_chunk_lines"]), "specification-operations"
            else:
                parts, method = structural_chunks(str(artifact["path"]), lines, max_lines=bounds["max_chunk_lines"])
            source = {"path": artifact["path"], "sha256": artifact["sha256"], "artifact_id": artifact["artifact_id"],
                      "categories": sorted(categories),
                      "subtypes": sorted({item["subtype"] for item in artifact["categories"]})}
            emit(source, lines, parts, method)

        for record in inputs["converted"]:
            if stopped:
                break
            if record.get("text") is None:
                continue
            text_identity = record["text"]
            text_path = (unit.job.run_root / text_identity["path"]).resolve()
            if file_sha256(text_path) != text_identity["sha256"]:
                raise ValueError(f"converted text identity mismatch: {record['path']}")
            lines = Lines(text_path.read_text(encoding="utf-8"))
            artifact = next(item for item in inputs["artifacts"] if item["artifact_id"] == record["artifact_id"])
            if record["format"] == "pdf":
                parts = []
                for segment in record["segments"]:
                    if segment["end_char"] <= segment["start_char"]:
                        continue
                    # Line n spans char_offsets[n-1]..char_offsets[n]; bisection finds the lines
                    # holding the segment's first and last characters.
                    first = bisect_right(lines.char_offsets, segment["start_char"])
                    last = min(len(lines), bisect_right(lines.char_offsets, segment["end_char"] - 1))
                    if 1 <= first <= last:
                        parts.extend(windows(lines, max_lines=bounds["max_chunk_lines"], start=first, end=last,
                                             kind="page", heading=segment["label"],
                                             attributes={"segment": segment["label"]}))
                method = "converted-pdf-pages"
            else:
                parts, method = markdown(lines), "converted-markdown-sections"
            source = {"path": record["path"], "sha256": record["input_sha256"], "artifact_id": record["artifact_id"],
                      "categories": sorted({item["category"] for item in artifact["categories"]}),
                      "subtypes": sorted({item["subtype"] for item in artifact["categories"]})}
            emit(source, lines, parts, method, converted=record)

        document = {"schema": "appsec-review/design-content-chunks/1", "chunker": CHUNKER_IDENTITY,
                    "chunks": chunks, "gaps": gaps, "file_count": files}
        return {"artifact": _write(unit, "chunks.json", document), "item_count": len(chunks), "gaps": gaps}

    def build_index(unit: UnitContext) -> Mapping[str, Any]:
        chunk_output = unit.output("content_chunking.chunk_documents")
        operation_output = unit.output("interface_extraction.extract_interfaces")
        inputs_output = unit.output("content_input.load_inputs")
        chunk_doc = _read(unit.job.run_root, chunk_output["artifact"])
        operation_doc = _read(unit.job.run_root, operation_output["artifact"])
        gaps = list(dict.fromkeys([*inputs_output["gaps"], *operation_doc["gaps"], *chunk_doc["gaps"]]))
        fingerprint = index_fingerprint(
            name="analysis", target_snapshot=unit.job.source_fingerprint,
            producer_artifacts=[inputs_output["artifact"], chunk_output["artifact"], operation_output["artifact"]],
            tool_identity={"chunker": CHUNKER_IDENTITY, "extractor": EXTRACTOR_IDENTITY,
                           "config": hashlib.sha256(canonical_json(dict(unit.job.config.settings))).hexdigest()},
            parser_identity=EXTRACTOR_IDENTITY, normalizer_identity=CHUNKER_IDENTITY,
            mapping_identity="design-content-span/1",
        )
        path = unit.job.run_root / "data" / "indices" / "analysis" / SHARD_ID / f"{fingerprint}.sqlite"
        if not path.exists():
            builder = IndexBuilder(path, name="analysis", fingerprint=fingerprint,
                                   target_snapshot=unit.job.source_fingerprint, shard_id=SHARD_ID)
            chunk_identities: dict[str, str] = {}
            for record in chunk_doc["chunks"]:
                identity = LogicalIdentity.derive(EntityKind.SOURCE_SPAN, unit.job.source_fingerprint,
                                                  {"design_chunk": record["chunk_id"]})
                chunk_identities[record["chunk_id"]] = identity.value
                location = None
                if not record["converted"]:
                    location = SourceLocation(
                        target_snapshot=unit.job.source_fingerprint, path=record["artifact_path"],
                        file_sha256=record["file_sha256"], start_byte=record["start_byte"],
                        end_byte=record["end_byte"], start_line=record["start_line"], end_line=record["end_line"],
                        start_column=1, end_column=1, producer_location={"producer": JOB_ID},
                        mapping_method="design-content-chunk", confidence=1.0)
                payload = {key: value for key, value in record.items() if key != "text"}
                if record["converted"]:
                    # Converted text is a run-owned artifact, not target bytes, so the bounded chunk
                    # text travels as data with its artifact identity and character range.
                    payload["converted_excerpt"] = record["text"]
                search_text = " ".join([*record["heading_path"], record["heading"], record["text"]])
                builder.add_entity(EntityRecord(identity, record["chunk_id"],
                                                f"{record['artifact_path']}#{record['heading']}"[:4096],
                                                search_text, payload, location))
                artifact_identity = LogicalIdentity.derive(EntityKind.SOURCE_FILE, unit.job.source_fingerprint,
                                                           {"design_artifact_id": record["artifact_id"]})
                builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, identity.value,
                                                    artifact_identity.value, True, 1.0))
            tables: dict[str, Lines] = {}
            chunk_by_operation = {operation_id: record["chunk_id"] for record in chunk_doc["chunks"]
                                  for operation_id in record["operation_ids"]}
            for operation in operation_doc["operations"]:
                identity = LogicalIdentity.derive(EntityKind.INTERFACE_OPERATION, unit.job.source_fingerprint,
                                                  {"interface_operation": operation["interface_operation_id"]})
                if operation["artifact_path"] not in tables:
                    source = (unit.job.target_root or Path()) / operation["artifact_path"]
                    data = source.read_bytes()
                    if hashlib.sha256(data).hexdigest() != operation["artifact_sha256"]:
                        raise ValueError(f"target file changed after extraction: {operation['artifact_path']}")
                    tables[operation["artifact_path"]] = Lines(data.decode("utf-8"))
                table = tables[operation["artifact_path"]]
                end_line = min(operation["end_line"], len(table))
                start_byte, end_byte = table.bytes_span(operation["start_line"], end_line)
                location = SourceLocation(
                    target_snapshot=unit.job.source_fingerprint, path=operation["artifact_path"],
                    file_sha256=operation["artifact_sha256"], start_byte=start_byte, end_byte=end_byte,
                    start_line=operation["start_line"], end_line=end_line, start_column=1,
                    end_column=1, producer_location={"producer": JOB_ID, "extractor": EXTRACTOR_IDENTITY},
                    mapping_method="design-interface-span", confidence=1.0)
                text = " ".join(str(value) for value in (
                    operation["protocol"], operation["method"], operation["route"], operation.get("operation_id") or "",
                    operation["security_state"], *operation["security_schemes"], *operation["security_scheme_types"],
                    "client_streaming" if operation["client_streaming"] else "",
                    "server_streaming" if operation["server_streaming"] else "",
                    *(rule["path"] for rule in operation.get("http_rules", []))))
                builder.add_entity(EntityRecord(identity, operation["interface_operation_id"], operation["name"],
                                                text, operation, location))
                chunk_id = chunk_by_operation.get(operation["interface_operation_id"])
                if chunk_id in chunk_identities:
                    builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, identity.value,
                                                        chunk_identities[chunk_id], True, 1.0))
            status = "partial" if gaps else "complete"
            builder.add_coverage("design-content:chunks", status, "; ".join(chunk_doc["gaps"][:10]) or None)
            builder.add_coverage("design-content:interfaces", "partial" if operation_doc["gaps"] else "complete",
                                 "; ".join(operation_doc["gaps"][:10]) or None)
            builder.add_coverage("design-content:converted",
                                 "complete" if inputs_output["conversion_status"] == "ACCEPTED" and
                                 not inputs_output["gaps"] else
                                 "unavailable" if inputs_output["conversion_status"] != "ACCEPTED" else "partial",
                                 "; ".join(inputs_output["gaps"][:10]) or None)
            sha256 = builder.build()
        else:
            sha256 = file_sha256(path)
        identity = IndexIdentity("analysis", "appsec-review/retrieval-index/2", sha256, fingerprint,
                                 _rel(unit.job.run_root, path), {"job": JOB_ID, "chunker": CHUNKER_IDENTITY,
                                                                 "extractor": EXTRACTOR_IDENTITY},
                                 tuple(gaps), SHARD_ID)
        return {"artifact": _artifact(unit.job.run_root, path), "index_identity": asdict(identity),
                "item_count": chunk_output["item_count"] + operation_output["item_count"], "gaps": gaps}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        indexed = unit.output("content_publication.build_index")
        chunk_doc = _read(unit.job.run_root, unit.output("content_chunking.chunk_documents")["artifact"])
        operation_doc = _read(unit.job.run_root, unit.output("interface_extraction.extract_interfaces")["artifact"])
        inputs_output = unit.output("content_input.load_inputs")
        manifest_path, manifest_sha = resolve_accepted_manifest(unit.job.run_root)
        upstream, _ = load_verified_manifest(unit.job.run_root, manifest_path, manifest_sha)
        identities = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))})
                      for item in upstream["indexes"]
                      if not (item["name"] == "analysis" and item.get("shard_id") == SHARD_ID)]
        identities.append(IndexIdentity(**{**indexed["index_identity"],
                                           "gaps": tuple(indexed["index_identity"].get("gaps", ()))}))
        combined = unit.job.run_root / "data" / "indices" / "manifests" / f"design-content-{unit.job.attempt_id}.json"
        write_manifest(combined, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                       target_root=unit.job.target_root or Path(), indexes=identities,
                       upstream_manifests=({"path": _rel(unit.job.run_root, manifest_path), "sha256": manifest_sha},))
        load_verified_manifest(unit.job.run_root, combined, file_sha256(combined))
        operations = operation_doc["operations"]
        summary = {
            "schema": "appsec-review/design-content-index-handoff/1",
            "target_fingerprint": unit.job.source_fingerprint,
            "design_handoff_sha256": inputs_output["design_handoff_sha256"],
            "conversion_status": inputs_output["conversion_status"],
            "chunks": unit.output("content_chunking.chunk_documents")["artifact"],
            "interface_operations": unit.output("interface_extraction.extract_interfaces")["artifact"],
            "index_manifest": _artifact(unit.job.run_root, combined),
            "chunk_count": len(chunk_doc["chunks"]), "indexed_file_count": chunk_doc["file_count"],
            "converted_chunk_count": sum(1 for item in chunk_doc["chunks"] if item["converted"]),
            "operation_counts_by_protocol": dict(sorted(Counter(item["protocol"] for item in operations).items())),
            "operation_counts_by_security_state": dict(sorted(Counter(item["security_state"]
                                                                      for item in operations).items())),
            "gaps": indexed["gaps"], "security_findings": [],
        }
        return {**summary, "artifact": _write(unit, "handoff.json", summary),
                "terminal_status": "PARTIAL" if summary["gaps"] else "SUCCEEDED"}

    units = (
        Unit("content_input.load_inputs", load_inputs),
        Unit("interface_extraction.extract_interfaces", extract, ("content_input.load_inputs",)),
        Unit("content_chunking.chunk_documents", chunk,
             ("content_input.load_inputs", "interface_extraction.extract_interfaces")),
        Unit("content_publication.build_index", build_index,
             ("content_input.load_inputs", "interface_extraction.extract_interfaces",
              "content_chunking.chunk_documents")),
        Unit("content_publication.publish_handoff", publish,
             ("content_input.load_inputs", "interface_extraction.extract_interfaces",
              "content_chunking.chunk_documents", "content_publication.build_index")),
    )
    sources = (Path(__file__), Path(__file__).with_name("chunking.py"), Path(__file__).with_name("interfaces.py"))
    implementation = hashlib.sha256(b"".join(path.read_bytes() for path in sources)).hexdigest()
    return Job(JOB_ID, "design_content_index", UnitExecutor(units).execute, input_validators=(validate,),
               schema_identity="appsec-review/design-content-index-job/1", implementation_identity=implementation,
               validation_identity=hashlib.sha256(Path(__file__).read_bytes() + b"validation").hexdigest(),
               units=units)


def load_accepted_design_content(run_root: Path) -> dict[str, Any] | None:
    """Return accepted interface operations and their binding, or None when never accepted."""
    run_root = Path(run_root)
    pointer_path = run_root / "data" / "jobs" / JOB_ID / "latest.json"
    if not pointer_path.is_file():
        return None
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff = _read(run_root, {"path": pointer["handoff_path"], "sha256": pointer["handoff_sha256"]})
    if handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED":
        raise ValueError("design content handoff is not accepted")
    summary = _read(run_root, handoff["outputs"]["content_publication.publish_handoff"]["artifact"])
    if summary.get("schema") != "appsec-review/design-content-index-handoff/1":
        raise ValueError("design content summary schema is unsupported")
    operations = _read(run_root, summary["interface_operations"])
    if operations.get("schema") != "appsec-review/design-interface-operations/1":
        raise ValueError("design interface operation schema is unsupported")
    return {"handoff_sha256": str(pointer["handoff_sha256"]),
            "source_fingerprint": str(handoff.get("source_fingerprint")),
            "design_handoff_sha256": summary.get("design_handoff_sha256"),
            "summary_artifact": dict(handoff["outputs"]["content_publication.publish_handoff"]["artifact"]),
            "operations": list(operations["operations"]), "specifications": list(operations["specifications"]),
            "gaps": list(operations["gaps"])}
