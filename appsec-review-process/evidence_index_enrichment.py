"""Bounded F01 index of accepted derived evidence records.

Producer payloads are untrusted evidence.  Only schema-valid artifacts published by an exact
common accepted pointer/envelope are admitted.  The index stores provenance labels, stable ids and
short redacted search text; it never republishes a producer record or grants it authority.
"""
from __future__ import annotations

import tunables
import json
from pathlib import Path, PurePosixPath
from typing import Any

import evidence_redaction as redaction
from execution_state import Blocked, ROOT, data_path, digest, file_hash, read_json, tree_hashes
import size_log
from publish_job_output import ACCEPTED_SCHEMA
from schema_validate import validate_document
from validate_job_output import NO_ORCHESTRATION_FACTS, validate_job_output
from worker_result import validate_worker_result
import registry_paths

SELECTION = "evidence-index-producers.json"
RESULT = "evidence-index-enrichment.json"
SCHEMA = "appsec-review/evidence-index-enrichment/1.0"
PERMISSION_SCHEMA = "appsec-review/producer-permission-receipt/1.0"
LINEAGE_SCHEMA = "appsec-review/producer-lineage-receipt/1.0"
LIMITS = {"max_producers": tunables.value("02-evidence-index", "derived_producers_logged"),
          "max_records": tunables.value("02-evidence-index", "derived_records_logged"),
          "max_links": tunables.value("02-evidence-index", "derived_links_logged"),
          "max_search_text": tunables.value("02-evidence-index", "derived_search_text_max"),
          "max_query_results": tunables.value("02-evidence-index", "derived_query_results_max")}

# job: (contract, result artifact, result schema, indexed top-level arrays, authority)
PROFILES = {
    "02-doc-intelligence-ingest": ("doc-intelligence", "doc-intelligence.json", "doc-intelligence.schema.json", ("records",), "untrusted_documented_intent"),
    "02-api-collection-intelligence-ingest": ("api-collection-intelligence", "api-collection-intelligence.json", "api-collection-intelligence.schema.json", ("records",), "untrusted_documented_intent"),
    "02-test-intelligence-ingest": ("test-intelligence", "test-intelligence.json", "test-intelligence.schema.json", ("records",), "untrusted_documented_intent"),
    "02-operations-doc-ingest": ("operations-doc-intelligence", "operations-doc-intelligence.json", "operations-doc-intelligence.schema.json", ("records",), "untrusted_documented_intent"),
    "02-native-sast": ("native-sast", "native-sast.json", "native-sast.schema.json", ("units",), "derived_evidence"),
    "02-ir-facts": ("ir-facts", "ir-facts.json", "ir-facts.schema.json", ("debug_locations", "facts"), "derived_evidence"),
    "02-code-property-graph": ("code-property-graph", "code-property-graph.json", "code-property-graph.schema.json", ("records",), "derived_evidence"),
    "02-debug-symbol-index": ("debug-symbol-index", "debug-symbol-index.json", "debug-symbol-index.schema.json", ("records",), "derived_evidence"),
    "02-binary-triage": ("binary-triage", "binary-triage-manifest.json", "binary-triage.schema.json", ("records",), "derived_evidence"),
    "02-binary-cfg": ("binary-cfg", "cfg-manifest.json", "binary-cfg.schema.json", ("records",), "derived_evidence"),
    "02-binary-intelligence-ingest": ("binary-intelligence", "binary-intelligence.json", "binary-intelligence.schema.json", ("records",), "derived_evidence"),
    "02-test-execution": ("test-execution", "test-execution.json", "test-execution.schema.json", ("artifacts",), "derived_evidence"),
    "02-test-result-ingest": ("test-result-intelligence", "test-results.json", "test-results.schema.json", ("outcomes",), "derived_evidence"),
    "02-test-coverage-ingest": ("test-coverage-intelligence", "test-coverage.json", "test-coverage.schema.json", ("files",), "derived_evidence"),
    "02-repository-partition-discovery": ("repository-partition-map", "repository-partition-map.json", "repository-partition-map.schema.json", ("partitions",), "derived_characterization"),
    "01-component-characterization": ("component-map", "component-purpose-map.json", "component-purpose-map.schema.json", ("code_scope_classification", "functional_components", "component_relationships"), "derived_characterization"),
    # Brief U0.3: tool leads index rule id, category, CWE, path and line only. The SARIF message
    # text never reaches these producers' results (decision D-02 item 6), so it cannot be indexed.
    "02-source-sast": ("source-sast", "source-sast.json", "source-sast.schema.json", ("leads",), "derived_evidence"),
    **{f"02-codeql-{language}": ("codeql-language", "codeql-language.json", "codeql-language.schema.json", ("leads",), "derived_evidence")
       for language in ("cpp", "csharp", "go", "java", "javascript", "python", "ruby", "rust")},
    "02-treesitter-ast": ("treesitter-ast", "treesitter-ast.json", "treesitter-ast-job.schema.json", ("records",), "derived_evidence"),
}
# Producers brief U0.3 names that this index cannot admit yet: they publish no F02 permission/lineage
# receipts (vendor B13 adapters), and load_producer's admission rule requires them. Each stays
# readable through the supporting-evidence menu; the gap is reported, not papered over.
NOT_INDEXABLE = {job: "vendor producer publishes no F02 permission/lineage receipts" for job in (
    "02-secrets-inventory", "02-sca-vulnerability-match", "02-sbom-inventory", "02-iac-config-scan", "02-license-scan")}

_TEXT_KEYS = frozenset({"title", "summary", "name", "kind", "description", "purpose", "method",
                        "route", "status", "semantics", "symbol", "function", "test_name", "outcome",
                        "full_name", "caller", "type_name", "code", "search_text", "source_path",
                        "rule_id", "rule_name", "category", "cwe", "language", "path", "detail"})
_IDENTITY_KEYS = ("record_id", "lead_id", "fact_id", "partition_id", "component_id", "relationship_id",
                  "test_id", "artifact_id", "binary_id", "symbol_id", "cfg_id", "location_id", "path")


def _hash(value: Any) -> str:
    return "sha256:" + digest(value)


def _relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str):
        raise Blocked("derived producer artifact path is not a normalized relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise Blocked("derived producer artifact path is not a normalized relative path")
    return path


def _owned(attempt: Path, relative: str) -> Path:
    rel = _relative(relative)
    path = attempt.joinpath(*rel.parts)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(attempt.resolve())
    except (OSError, ValueError) as exc:
        raise Blocked("derived producer artifact escapes its immutable attempt") from exc
    cursor = attempt
    for part in rel.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise Blocked("derived producer artifact traverses a symbolic link")
    if not path.is_file():
        raise Blocked("derived producer artifact is missing")
    return path


def _plain_directory(owner: Path, path: Path, label: str) -> Path:
    """Require a real directory lexically and physically beneath its canonical owner."""
    try:
        relative = path.relative_to(owner)
        owner_resolved = owner.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(owner_resolved)
    except (OSError, ValueError) as exc:
        raise Blocked(f"02-evidence-index: selected producer {label} escapes its canonical root") from exc
    cursor = owner
    if cursor.is_symlink() or not cursor.is_dir():
        raise Blocked(f"02-evidence-index: selected producer {label} root is not a real directory")
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink() or not cursor.is_dir():
            raise Blocked(f"02-evidence-index: selected producer {label} traverses a linked directory")
    return path


def _root_file(base: Path, name: str, job: str) -> Path:
    path = base / name
    try:
        path.resolve(strict=True).relative_to(base.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise Blocked(f"02-evidence-index: selected producer {job} control file escapes its root") from exc
    if path.is_symlink() or not path.is_file():
        raise Blocked(f"02-evidence-index: selected producer {job} control file is not regular")
    return path


def _producer_root(run_id: str, job: str) -> Path:
    try:
        jobs = data_path(run_id, "jobs")
    except ValueError as exc:
        raise Blocked(f"02-evidence-index: selected producer {job} jobs root is unsafe") from exc
    base = _plain_directory(jobs, jobs / job, job)
    direct, whole = base / "accepted.json", base / "whole/accepted.json"
    direct_exists = direct.is_file() and not direct.is_symlink()
    whole_exists = whole.is_file() and not whole.is_symlink()
    if direct_exists == whole_exists:
        raise Blocked(f"02-evidence-index: selected producer {job} has no unique accepted root")
    selected = base if direct_exists else _plain_directory(base, base / "whole", job)
    _root_file(selected, "accepted.json", job)
    return selected


def _template_permissions(job: str) -> list[str]:
    value = read_json(registry_paths.template(job)).get("permissions")
    if not isinstance(value, list) or len(value) != len(set(value)):
        raise Blocked(f"02-evidence-index: selected producer {job} has invalid canonical permissions")
    return value


def load_producer(run_id: str, job: str) -> dict[str, Any]:
    if job not in PROFILES:
        raise Blocked("02-evidence-index: producer selection contains an unsupported job")
    contract, result_name, schema_name, arrays, authority = PROFILES[job]
    base = _producer_root(run_id, job)
    pointer_path = _root_file(base, "accepted.json", job)
    pointer = read_json(pointer_path)
    required = {"schema", "status", "run_id", "job", "attempt_id", "fingerprint", "envelope_path",
                "envelope_sha256", "hashes", "accepted_at"}
    if (set(pointer) != required or pointer.get("schema") != ACCEPTED_SCHEMA or
            pointer.get("status") not in {"OK", "OK_WITH_GAPS"} or pointer.get("run_id") != run_id or
            pointer.get("job") != job or pointer.get("envelope_path") != "result.json"):
        raise Blocked(f"02-evidence-index: selected producer {job} accepted pointer is invalid")
    latest = read_json(_root_file(base, "latest.json", job))
    if latest.get("attempt_id") != pointer["attempt_id"]:
        raise Blocked(f"02-evidence-index: selected producer {job} accepted pointer is stale")
    attempts = _plain_directory(base, base / "attempts", job)
    attempt = _plain_directory(attempts, attempts / pointer["attempt_id"], job)
    try:
        hashes = tree_hashes(attempt)
    except (OSError, ValueError) as exc:
        raise Blocked(f"02-evidence-index: selected producer {job} attempt tree is unsafe") from exc
    if hashes != pointer["hashes"]:
        raise Blocked(f"02-evidence-index: selected producer {job} attempt tree is corrupt")
    envelope_path = _owned(attempt, pointer["envelope_path"])
    envelope = read_json(envelope_path)
    if (file_hash(envelope_path) != pointer["envelope_sha256"] or validate_worker_result(envelope) or
            envelope.get("run_id") != run_id or envelope.get("job_id") != job or
            envelope.get("attempt_id") != pointer["attempt_id"] or
            envelope.get("input_fingerprint") != pointer["fingerprint"] or
            envelope.get("execution_status") != pointer["status"] or
            envelope.get("acceptance_status") != "CURRENT" or envelope.get("output_contract") != contract):
        raise Blocked(f"02-evidence-index: selected producer {job} envelope is invalid")
    if validate_job_output(attempt, envelope, pointer["fingerprint"], expected_run_id=run_id,
                           expected_job_id=job, orchestration=NO_ORCHESTRATION_FACTS):
        raise Blocked(f"02-evidence-index: selected producer {job} output contract is invalid")
    artifacts = {item["path"]: item for item in envelope["artifacts"]}
    if len(artifacts) != len(envelope["artifacts"]):
        raise Blocked(f"02-evidence-index: selected producer {job} repeats an artifact path")
    for relative, artifact in artifacts.items():
        if file_hash(_owned(attempt, relative)) != artifact.get("sha256"):
            raise Blocked(f"02-evidence-index: selected producer {job} artifact is corrupt")
    if not {result_name, "permission.json", "lineage.json"} <= set(artifacts):
        raise Blocked(f"02-evidence-index: selected producer {job} omits result or F02 receipts")
    result_path = _owned(attempt, result_name)
    payload = read_json(result_path)
    if validate_document(payload, schema_name):
        raise Blocked(f"02-evidence-index: selected producer {job} result fails its schema")
    permission = read_json(attempt / "permission.json")
    lineage = read_json(attempt / "lineage.json")
    expected_permission = {"schema": PERMISSION_SCHEMA, "run_id": run_id, "job_id": job,
                           "source_snapshot_sha256": lineage.get("source_snapshot_sha256"),
                           "permissions": _template_permissions(job)}
    if permission != expected_permission or set(lineage) != {"schema", "run_id", "job_id", "source_snapshot_sha256", "build_lineage_sha256"} or \
            lineage.get("schema") != LINEAGE_SCHEMA or lineage.get("run_id") != run_id or lineage.get("job_id") != job:
        raise Blocked(f"02-evidence-index: selected producer {job} F02 receipts are invalid")
    return {"job_id": job, "contract": contract, "attempt_id": pointer["attempt_id"],
            "pointer_sha256": "sha256:" + file_hash(pointer_path),
            "envelope_sha256": "sha256:" + file_hash(envelope_path), "artifact_path": result_name,
            "artifact_sha256": "sha256:" + file_hash(result_path), "schema_name": schema_name,
            "arrays": list(arrays), "authority": authority, "source_snapshot_sha256": lineage["source_snapshot_sha256"],
            "build_lineage_sha256": lineage["build_lineage_sha256"]}


def selected_inputs(run_id: str) -> dict[str, Any]:
    path = data_path(run_id, "inputs", SELECTION)
    if not path.exists():
        return {"selection_sha256": None, "producers": []}
    if not path.is_file() or path.is_symlink():
        raise Blocked("02-evidence-index: producer selection must be a regular run-owned file")
    selection = read_json(path)
    if validate_document(selection, "evidence-index-producer-selection.schema.json") or selection.get("run_id") != run_id:
        raise Blocked("02-evidence-index: producer selection is invalid")
    jobs = selection["producer_jobs"]
    if len(jobs) != len(set(jobs)):
        raise Blocked("02-evidence-index: producer selection repeats a job")
    return {"selection_sha256": "sha256:" + file_hash(path),
            "producers": [load_producer(run_id, job) for job in sorted(jobs)]}


def _text(record: dict[str, Any]) -> tuple[str, str]:
    parts = []
    for key, value in sorted(record.items()):
        if key in _TEXT_KEYS and isinstance(value, (str, int, float, bool)):
            parts.append(str(value))
    text = " | ".join(parts)[:LIMITS["max_search_text"]]
    outcome = redaction._process(text.encode("utf-8"), "record.txt", redaction.DEFAULT_LIMITS)
    if outcome.data is None:
        return "", "withheld"
    rendered = outcome.data.decode("utf-8", errors="replace")[:LIMITS["max_search_text"]]
    return rendered, "redacted" if outcome.disposition != "unchanged" else "unchanged"


def _logical_id(record: dict[str, Any]) -> str:
    for key in _IDENTITY_KEYS:
        value = record.get(key)
        if isinstance(value, str) and value:
            return f"{key}:{value}"
    return "content:" + digest(record)


def _jsonl(path: Path):
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def build(run_id: str, selection: dict[str, Any], source_snapshot_sha256: str | None = None) -> dict[str, Any]:
    producers = selection["producers"]
    size_log.observe(run_id, "02-evidence-index", "producers", len(producers), LIMITS["max_producers"])
    sources = {item["source_snapshot_sha256"] for item in producers}
    if source_snapshot_sha256 is not None:
        sources.add(source_snapshot_sha256)
    builds = {item["build_lineage_sha256"] for item in producers if item["build_lineage_sha256"] is not None}
    if len(sources) > 1 or len(builds) > 1:
        raise Blocked("02-evidence-index: selected producers are mixed-generation")
    records, partitions, components, seen = [], [], [], set()
    for producer in producers:
        live = load_producer(run_id, producer["job_id"])
        if live != producer:
            raise Blocked("02-evidence-index: selected producer changed during enrichment")
        payload = read_json(_producer_root(run_id, producer["job_id"]) / "attempts" /
                            producer["attempt_id"] / producer["artifact_path"])
        for array_name in producer["arrays"]:
            values = payload.get(array_name)
            records_file = payload.get("records_file") if isinstance(payload, dict) else None
            if values is None and array_name == "records" and isinstance(records_file, dict):
                values = _jsonl(_producer_root(run_id, producer["job_id"]) / "attempts" /
                                producer["attempt_id"] / records_file["path"])
            for index, record in enumerate(values or []):
                if not isinstance(record, dict):
                    raise Blocked("02-evidence-index: selected derived record is not an object")
                logical = (producer["job_id"], array_name, _logical_id(record))
                if logical in seen:
                    raise Blocked("02-evidence-index: selected producer repeats a derived record identity")
                seen.add(logical)
                record_path = f"/{array_name}/{index}"
                record_id = "derived_" + digest((producer["job_id"], producer["attempt_id"],
                                                  producer["artifact_path"], record_path, digest(record)))[:24]
                text, disposition = _text(record)
                partition_ids = sorted({value for key, value in record.items()
                                        if key == "partition_id" and isinstance(value, str)} |
                                       {value for value in record.get("partition_ids", [])
                                        if isinstance(value, str)})
                component_ids = sorted({value for key, value in record.items()
                                        if key in {"component_id", "from_component_id", "to_component_id"}
                                        and isinstance(value, str)} |
                                       {value for value in record.get("component_ids", [])
                                        if isinstance(value, str)})
                item = {"record_id": record_id, "producer_job_id": producer["job_id"],
                    "producer_attempt_id": producer["attempt_id"], "producer_contract": producer["contract"],
                    "artifact_path": producer["artifact_path"], "artifact_sha256": producer["artifact_sha256"],
                    "record_path": record_path, "record_sha256": _hash(record),
                    "type_label": f"{producer['contract']}:{array_name}", "authority": producer["authority"],
                    "redaction": disposition, "source_snapshot_sha256": producer["source_snapshot_sha256"],
                    "build_lineage_sha256": producer["build_lineage_sha256"],
                    "partition_ids": partition_ids, "component_ids": component_ids, "search_text": text}
                records.append(item)
                partitions.extend({"partition_id": value, "record_id": record_id} for value in partition_ids)
                components.extend({"component_id": value, "record_id": record_id} for value in component_ids)
    size_log.observe(run_id, "02-evidence-index", "derived_records", len(records), LIMITS["max_records"])
    size_log.observe(run_id, "02-evidence-index", "partition_component_links",
                     len(partitions) + len(components), LIMITS["max_links"])
    records.sort(key=lambda item: (item["producer_job_id"], item["type_label"], item["record_path"], item["record_id"]))
    partitions.sort(key=lambda item: (item["partition_id"], item["record_id"]))
    components.sort(key=lambda item: (item["component_id"], item["record_id"]))
    gaps = [] if producers else ["no-derived-producers-selected"]
    result = {"schema": SCHEMA, "run_id": run_id,
              "source_snapshot_sha256": next(iter(sources), "sha256:" + "0" * 64),
              "build_lineage_sha256": next(iter(builds), None), "producer_count": len(producers),
              "record_count": len(records), "records": records, "partitions": partitions,
              "components": components, "coverage_gaps": gaps, "limits": LIMITS,
              "claim_boundary": "DERIVED_INDEX_NOT_AUTHORITY_OR_RUNTIME_PROOF"}
    errors = validate_document(result, "evidence-index-enrichment.schema.json")
    if errors:
        raise Blocked("02-evidence-index: derived enrichment fails its closed schema")
    return result


def query(document: dict[str, Any], *, text: str = "", partition_id: str = "",
          component_id: str = "", limit: int = 10) -> list[dict[str, Any]]:
    if not 1 <= limit <= LIMITS["max_query_results"] or len(text) > LIMITS["max_search_text"]:
        raise ValueError("derived query bounds: limit 1..50 and text <=1000 characters")
    needle = text.casefold().strip()
    rows = [item for item in document["records"]
            if (not needle or needle in item["search_text"].casefold())
            and (not partition_id or partition_id in item["partition_ids"])
            and (not component_id or component_id in item["component_ids"])]
    return rows[:limit]
