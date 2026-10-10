"""Offline text conversion of design documents the target catalog identifies only by name."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
from typing import Any

from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, load_catalog
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256


JOB_ID = "job_document_conversion"
TOOL_ID = "tool-doc-convert"
TOPOLOGY: Mapping[str, tuple[str, ...]] = {
    "conversion_planning": ("select_documents",),
    "conversion_execution": ("convert_documents",),
    "conversion_publication": ("publish_handoff",),
}
FORMATS = {".pdf": "pdf", ".docx": "docx", ".odt": "odt", ".rtf": "rtf", ".epub": "epub"}
UNSUPPORTED = {".doc", ".pptx", ".ppt", ".vsdx", ".vsd", ".xlsx"}
_CONVERTIBLE_CATEGORIES = {"design_document", "threat_model", "api_specification"}
_OUTPUT_SCHEMA = "appsec-review/document-conversion-output/1"
_TERMINAL = {"SUCCEEDED", "NO_TEXT", "ENCRYPTED", "TIMEOUT", "FAILED", "UNSUPPORTED"}

ExecutorFactory = Callable[[UnitContext], ContainerExecutor]


def _rel(run_root: Path, path: Path) -> str:
    return path.resolve().relative_to(run_root.resolve()).as_posix()


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": _rel(run_root, path), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _write(unit: UnitContext, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    path = unit.job.attempt_root / "artifacts" / "conversion" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(path, value)
    return _artifact(unit.job.run_root, path)


def _bounds(settings: Mapping[str, Any]) -> dict[str, int]:
    values = {"max_documents": int(settings.get("max_documents", 200)),
              "max_input_bytes": int(settings.get("max_input_bytes", 32 * 1024 * 1024)),
              "max_pages": int(settings.get("max_pages", 500)),
              "max_chars": int(settings.get("max_chars", 2_000_000)),
              "pandoc_timeout_seconds": int(settings.get("pandoc_timeout_seconds", 120))}
    if not 1 <= values["max_documents"] <= 10_000 or not 1 <= values["max_input_bytes"] <= 256 * 1024 * 1024:
        raise ValueError("document conversion input bounds are outside the supported range")
    if not 1 <= values["max_pages"] <= 10_000 or not 1 <= values["max_chars"] <= 64 * 1024 * 1024:
        raise ValueError("document conversion output bounds are outside the supported range")
    if not 1 <= values["pandoc_timeout_seconds"] <= 3600:
        raise ValueError("document conversion timeout is outside the supported range")
    return values


def select_documents(artifacts: list[Mapping[str, Any]], *, max_documents: int
                     ) -> tuple[list[dict[str, Any]], list[str]]:
    """Choose convertible design documents from accepted discovery output."""
    selected: list[dict[str, Any]] = []
    gaps: list[str] = []
    for artifact in sorted(artifacts, key=lambda item: str(item["path"])):
        categories = {item["category"] for item in artifact["categories"]}
        if not categories & _CONVERTIBLE_CATEGORIES:
            continue
        suffix = PurePosixPath(str(artifact["path"])).suffix.lower()
        if suffix in UNSUPPORTED:
            gaps.append(f"{artifact['path']}: {suffix} has no offline text converter")
            continue
        if suffix not in FORMATS:
            continue
        if len(selected) >= max_documents:
            gaps.append(f"document conversion stopped at configured max_documents={max_documents}")
            break
        selected.append({"path": str(artifact["path"]), "format": FORMATS[suffix],
                         "artifact_id": str(artifact["artifact_id"]),
                         "catalog_sha256": artifact.get("sha256"), "categories": sorted(categories)})
    return selected, gaps


def _load_design(run_root: Path) -> Mapping[str, Any]:
    from appsec_review.jobs.job_design_artifact_discovery import load_accepted_design_artifacts

    design = load_accepted_design_artifacts(run_root)
    if design is None:
        raise ValueError("accepted job_design_artifact_discovery handoff is required")
    return design


def _convert_one(unit: UnitContext, document: Mapping[str, Any], index: int, executor: ContainerExecutor,
                 tool, bounds: Mapping[str, int]) -> dict[str, Any]:
    target_root = (unit.job.target_root or Path()).resolve()
    source = (target_root / document["path"]).resolve()
    record: dict[str, Any] = {"path": document["path"], "format": document["format"],
                              "artifact_id": document["artifact_id"], "status": "FAILED", "gaps": [],
                              "input_sha256": None, "text": None, "segments": [], "converter": None}
    if target_root not in source.parents or not source.is_file() or (target_root / document["path"]).is_symlink():
        record["gaps"].append("document is unavailable in the target snapshot")
        return record
    size = source.stat().st_size
    if size > bounds["max_input_bytes"]:
        record.update(status="TOO_LARGE")
        record["gaps"].append(f"input exceeds max_input_bytes={bounds['max_input_bytes']}")
        return record
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    if document.get("catalog_sha256") and document["catalog_sha256"] != expected:
        raise ValueError(f"target document changed after catalog acceptance: {document['path']}")
    record["input_sha256"] = expected
    scratch = unit.unit_root / "scratch" / f"document_{index:04d}"
    output_dir = scratch / "out"
    argv = (tool.executable, "--input", f"/target/{document['path']}", "--format", document["format"],
            "--output-dir", "/scratch/out", "--max-pages", str(bounds["max_pages"]),
            "--max-chars", str(bounds["max_chars"]),
            "--pandoc-timeout", str(bounds["pandoc_timeout_seconds"]))
    try:
        result = executor.execute(ExecutionRequest(tool_id=TOOL_ID, argv=argv, target_root=target_root,
                                                   scratch_root=scratch))
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        record["gaps"].append(f"converter unavailable ({type(exc).__name__}: {exc})")
        return record
    record["execution_receipt"] = result.receipt_path
    if result.timed_out or result.oom_killed or result.exit_code != 0:
        record["status"] = "TIMEOUT" if result.timed_out else "FAILED"
        record["gaps"].append(f"converter exited {result.exit_code}"
                              f"{' (timeout)' if result.timed_out else ''}{' (oom)' if result.oom_killed else ''}")
        return record
    manifest_path, text_path = output_dir / "manifest.json", output_dir / "text.txt"
    if not manifest_path.is_file() or not text_path.is_file():
        record["gaps"].append("converter produced no manifest or text output")
        return record
    if manifest_path.stat().st_size > 4 * 1024 * 1024 or text_path.stat().st_size > 4 * bounds["max_chars"] + 4096:
        raise ValueError(f"converter output exceeds its bound: {document['path']}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != _OUTPUT_SCHEMA or manifest.get("status") not in _TERMINAL:
        raise ValueError(f"converter output schema is unsupported: {document['path']}")
    if manifest.get("input_sha256") != expected:
        raise ValueError(f"converter read different bytes than the target snapshot: {document['path']}")
    if manifest.get("text_sha256") != file_sha256(text_path):
        raise ValueError(f"converter text identity mismatch: {document['path']}")
    text = text_path.read_text(encoding="utf-8")
    segments = []
    for segment in manifest.get("segments", []):
        start, end = int(segment["start_char"]), int(segment["end_char"])
        if not 0 <= start <= end <= len(text):
            raise ValueError(f"converter segment is outside its text: {document['path']}")
        segments.append({"label": str(segment["label"])[:64], "start_char": start, "end_char": end})
    record.update(status=manifest["status"], segments=segments, converter=str(manifest.get("converter")),
                  truncated=bool(manifest.get("truncated")),
                  gaps=[str(item)[:512] for item in manifest.get("gaps", [])][:50])
    if manifest["status"] == "SUCCEEDED":
        record["text"] = _artifact(unit.job.run_root, text_path)
    return record


def build_job(*, executor_factory: ExecutorFactory | None = None) -> Job:
    def validate(context, result) -> None:
        if context.target_root is None:
            raise ValueError("document conversion requires a graph-provided target root")
        if tuple(context.config.steps) != tuple(TOPOLOGY):
            raise ValueError("document conversion topology does not match central configuration")
        for step, tasks in TOPOLOGY.items():
            if tuple(context.config.step(step).tasks) != tasks:
                raise ValueError(f"document conversion task order mismatch: {step}")
        _bounds(context.config.settings)
        design = _load_design(context.run_root)
        if design["source_fingerprint"] != context.source_fingerprint:
            raise ValueError("document conversion fingerprint does not match accepted design discovery")

    def factory(unit: UnitContext) -> ContainerExecutor:
        return executor_factory(unit) if executor_factory is not None else ContainerExecutor(
            load_catalog(unit.job.repository_root), unit.job.run_root)

    def select_handler(unit: UnitContext) -> Mapping[str, Any]:
        design = _load_design(unit.job.run_root)
        bounds = _bounds(unit.job.config.settings)
        documents, gaps = select_documents(design["artifacts"], max_documents=bounds["max_documents"])
        document = {"schema": "appsec-review/document-conversion-selection/1",
                    "design_handoff_sha256": design["handoff_sha256"], "documents": documents, "gaps": gaps}
        return {"artifact": _write(unit, "selection.json", document), "item_count": len(documents),
                "gaps": gaps, "documents": documents, "design_handoff_sha256": design["handoff_sha256"]}

    def convert_handler(unit: UnitContext) -> Mapping[str, Any]:
        selection = unit.output("conversion_planning.select_documents")
        bounds = _bounds(unit.job.config.settings)
        documents = list(selection["documents"])
        records: list[dict[str, Any]] = []
        gaps = list(selection["gaps"])
        image_id = None
        if documents:
            try:
                executor = factory(unit)
                tool = executor.catalog.tool(TOOL_ID)
                image_id = executor.resolve_image(tool)
            except (KeyError, RuntimeError, ValueError) as exc:
                gaps.append(f"{TOOL_ID}: pinned offline image unavailable ({type(exc).__name__}: {exc})")
                executor = tool = None
            for index, document in enumerate(documents, 1):
                if executor is None:
                    records.append({"path": document["path"], "format": document["format"],
                                    "artifact_id": document["artifact_id"], "status": "UNAVAILABLE",
                                    "gaps": ["converter image unavailable"], "input_sha256": None,
                                    "text": None, "segments": [], "converter": None})
                    continue
                records.append(_convert_one(unit, document, index, executor, tool, bounds))
        for record in records:
            gaps.extend(f"{record['path']}: {gap}" for gap in record["gaps"])
            if record["status"] not in {"SUCCEEDED"} and not record["gaps"]:
                gaps.append(f"{record['path']}: conversion ended {record['status']}")
        converted = sum(1 for record in records if record["status"] == "SUCCEEDED")
        terminal = ("NOT_APPLICABLE" if not documents and not gaps else
                    "PARTIAL" if gaps else "SUCCEEDED")
        document = {"schema": "appsec-review/document-conversion-catalog/1", "tool_id": TOOL_ID,
                    "image_id": image_id, "documents": records, "gaps": list(dict.fromkeys(gaps)),
                    "design_handoff_sha256": selection["design_handoff_sha256"]}
        return {"artifact": _write(unit, "conversions.json", document), "item_count": converted,
                "gaps": document["gaps"], "terminal_status": terminal}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        converted = unit.output("conversion_execution.convert_documents")
        selection = unit.output("conversion_planning.select_documents")
        summary = {"schema": "appsec-review/document-conversion-handoff/1",
                   "target_fingerprint": unit.job.source_fingerprint,
                   "design_handoff_sha256": selection["design_handoff_sha256"],
                   "conversions": converted["artifact"], "converted_count": converted["item_count"],
                   "selected_count": selection["item_count"], "gaps": converted["gaps"],
                   "security_findings": []}
        return {**summary, "artifact": _write(unit, "handoff.json", summary),
                "terminal_status": converted["terminal_status"]}

    units = (
        Unit("conversion_planning.select_documents", select_handler),
        Unit("conversion_execution.convert_documents", convert_handler, ("conversion_planning.select_documents",)),
        Unit("conversion_publication.publish_handoff", publish,
             ("conversion_planning.select_documents", "conversion_execution.convert_documents")),
    )
    implementation = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def runtime_identity() -> str:
        root = Path(os.environ.get("APPSEC_REVIEW_CONFIG", "appsec-review.toml")).resolve().parent
        digest = hashlib.sha256(b"injected-executor" if executor_factory else b"container-executor")
        try:
            tool = load_catalog(root).tool(TOOL_ID)
            digest.update(canonical_json({"id": TOOL_ID, "tag": tool.tag, "manifest": file_sha256(tool.manifest_path),
                                          "image": tool.expected_image_id}))
            converter = root / "containers" / "tools" / "doc-convert" / "doc_convert.py"
            if converter.is_file():
                digest.update(file_sha256(converter).encode())
        except (KeyError, OSError, ValueError):
            digest.update(f"{TOOL_ID}:UNAVAILABLE".encode())
        return digest.hexdigest()

    return Job(JOB_ID, "document_conversion", UnitExecutor(units).execute, input_validators=(validate,),
               schema_identity="appsec-review/document-conversion-job/1", implementation_identity=implementation,
               validation_identity=hashlib.sha256(Path(__file__).read_bytes() + b"validation").hexdigest(),
               runtime_identity=runtime_identity, units=units)


def load_accepted_conversions(run_root: Path) -> dict[str, Any] | None:
    """Return accepted conversion records with verified text artifacts, or None when never accepted."""
    run_root = Path(run_root)
    pointer_path = run_root / "data" / "jobs" / JOB_ID / "latest.json"
    if not pointer_path.is_file():
        return None
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))

    def read(identity: Mapping[str, Any]) -> Mapping[str, Any]:
        path = (run_root / str(identity["path"])).resolve()
        if run_root.resolve() not in path.parents or not path.is_file() or file_sha256(path) != identity["sha256"]:
            raise ValueError("document conversion artifact identity mismatch")
        return json.loads(path.read_text(encoding="utf-8"))

    handoff = read({"path": pointer["handoff_path"], "sha256": pointer["handoff_sha256"]})
    if handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED":
        raise ValueError("document conversion handoff is not accepted")
    summary = read(handoff["outputs"]["conversion_publication.publish_handoff"]["artifact"])
    catalog = read(summary["conversions"])
    if catalog.get("schema") != "appsec-review/document-conversion-catalog/1":
        raise ValueError("document conversion catalog schema is unsupported")
    for record in catalog["documents"]:
        if record.get("text") is not None:
            text_path = (run_root / record["text"]["path"]).resolve()
            if run_root.resolve() not in text_path.parents or file_sha256(text_path) != record["text"]["sha256"]:
                raise ValueError(f"converted text identity mismatch: {record['path']}")
    return {"handoff_sha256": str(pointer["handoff_sha256"]), "summary": summary,
            "source_fingerprint": str(handoff.get("source_fingerprint")),
            "design_handoff_sha256": summary.get("design_handoff_sha256"),
            "documents": list(catalog["documents"]), "gaps": list(catalog.get("gaps", []))}
