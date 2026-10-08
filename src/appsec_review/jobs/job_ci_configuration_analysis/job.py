from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, load_catalog
from appsec_review.jobs.job_evidence_collection.job import load_target_catalog
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256

from .discovery import PROVIDERS, discover
from .static_rules import RULESET_IDENTITY, hierarchy, scan_text


@dataclass(frozen=True, slots=True)
class ToolSpec:
    provider: str
    name: str
    tool_id: str
    mode: str
    framework: str | None = None

    @property
    def key(self) -> str:
        return f"{self.provider}_{self.name}"


SPECS = (
    ToolSpec("github", "zizmor", "tool-zizmor", "external"),
    ToolSpec("github", "checkov", "tool-checkov", "external", "github_actions"),
    ToolSpec("github", "actionlint", "tool-actionlint", "external"),
    ToolSpec("github", "schema", "ci-schema", "static"),
    ToolSpec("azure", "checkov", "tool-checkov", "external", "azure_pipelines"),
    ToolSpec("azure", "schema", "ci-schema", "static"),
    ToolSpec("gitlab", "checkov", "tool-checkov", "external", "gitlab_ci"),
    ToolSpec("gitlab", "schema", "ci-schema", "static"),
    ToolSpec("circleci", "checkov", "tool-checkov", "external", "circleci_pipelines"),
    ToolSpec("circleci", "schema", "ci-schema", "static"),
    ToolSpec("bitbucket", "checkov", "tool-checkov", "external", "bitbucket_pipelines"),
    ToolSpec("bitbucket", "schema", "ci-schema", "static"),
    ToolSpec("jenkins", "structural", "ci-jenkins-structural", "static"),
    ToolSpec("teamcity", "structural", "ci-teamcity-structural", "static"),
    ToolSpec("other", "discovery", "supported_discovery_without_linter", "discovery"),
)
PROVIDER_TOOLS: Mapping[str, tuple[str, ...]] = {
    provider: tuple(spec.name for spec in SPECS if spec.provider == provider) for provider in PROVIDERS
}
TOPOLOGY: Mapping[str, tuple[str, ...]] = {
    "ci_discovery": ("discover_definitions", "classify_providers"),
    "ci_analysis": tuple(f"{spec.key}_scan" for spec in SPECS),
    "ci_normalization": tuple(f"{spec.key}_normalize" for spec in SPECS),
    "ci_enrichment": ("build_hierarchy",),
    "ci_observation_publication": tuple(f"{spec.key}_index" for spec in SPECS),
    "ci_correlation": ("correlate_findings",),
    "ci_coverage": ("join_coverage", "publish_handoff"),
}

ExecutorFactory = Callable[[UnitContext], ContainerExecutor]


def _rel(run_root: Path, path: Path) -> str:
    return path.resolve().relative_to(run_root.resolve()).as_posix()


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": _rel(run_root, path), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _write(unit: UnitContext, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    task_key = hashlib.sha256(unit.unit_id.encode()).hexdigest()[:12]
    path = unit.job.attempt_root / "artifacts" / "ci" / task_key / name
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(path, value)
    return _artifact(unit.job.run_root, path)


def _read(run_root: Path, identity: Mapping[str, Any]) -> Mapping[str, Any]:
    path = (run_root / str(identity["path"])).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or file_sha256(path) != identity["sha256"]:
        raise ValueError("CI artifact identity mismatch")
    return json.loads(path.read_text(encoding="utf-8"))


def _bounds(unit: UnitContext) -> tuple[int, int, int]:
    settings = unit.job.config.settings
    values = (int(settings.get("max_files", 128)), int(settings.get("max_file_bytes", 1_048_576)),
              int(settings.get("max_observations_per_tool", 5_000)))
    if values[0] < 1 or values[0] > 5_000 or values[1] < 1 or values[1] > 16 * 1024 * 1024:
        raise ValueError("CI analysis bounds are outside the supported range")
    if values[2] < 1 or values[2] > 100_000:
        raise ValueError("CI observation bound is outside the supported range")
    return values


def discover_ci_definitions(files: tuple[Mapping[str, Any], ...], *, max_files: int = 128):
    return discover(files, max_files=max_files)


def _selected(unit: UnitContext, provider: str) -> list[dict[str, Any]]:
    output = unit.output("ci_discovery.classify_providers")
    return [dict(item) for item in output["definitions"] if item["provider"] == provider]


def _argv(spec: ToolSpec, executable: str, path: str) -> tuple[str, ...]:
    mounted = f"/target/{path}"
    if spec.tool_id == "tool-zizmor":
        return (executable, "--offline", "--no-exit-codes", "--format", "json", mounted)
    if spec.tool_id == "tool-actionlint":
        return (executable, "-format", "{{json .}}", mounted)
    if spec.tool_id == "tool-checkov":
        return (executable, "--quiet", "--compact", "--output", "json", "--framework",
                str(spec.framework), "--file", mounted)
    raise ValueError(f"no external CI argv for {spec.tool_id}")


def _generic_external_records(spec: ToolSpec, payload: bytes, path: str) -> list[dict[str, Any]]:
    text = payload.decode("utf-8", "replace").strip()
    if not text:
        return []
    values: list[Any] = []
    try:
        decoded = json.loads(text)
        values = decoded if isinstance(decoded, list) else [decoded]
    except json.JSONDecodeError:
        for line in text.splitlines():
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    records: list[dict[str, Any]] = []
    for document in values:
        candidates: list[Any]
        if isinstance(document, Mapping) and isinstance(document.get("results"), Mapping):
            candidates = list(document["results"].get("failed_checks", []))
        elif isinstance(document, Mapping) and isinstance(document.get("diagnostics"), list):
            candidates = list(document["diagnostics"])
        else:
            candidates = [document]
        for item in candidates:
            if not isinstance(item, Mapping):
                continue
            location = item.get("location") if isinstance(item.get("location"), Mapping) else {}
            lines = item.get("file_line_range") if isinstance(item.get("file_line_range"), list) else []
            start_line = int(location.get("line") or item.get("line") or (lines[0] if lines else 1) or 1)
            end_line = int(location.get("end_line") or (lines[-1] if lines else start_line) or start_line)
            message = str(item.get("message") or item.get("check_name") or item.get("description") or
                          item.get("details") or "CI linter observation")[:4096]
            records.append({
                "provider": spec.provider, "tool_id": spec.tool_id,
                "native_rule_id": str(item.get("check_id") or item.get("rule_id") or item.get("kind") or
                                      item.get("code") or spec.name),
                "category": "dangerous-defaults-and-uncaught-static-misconfiguration",
                "message": message, "severity": str(item.get("severity") or "medium").lower(),
                "path": path, "start_line": max(1, start_line), "end_line": max(start_line, end_line),
                "start_column": int(location.get("column") or 1),
                "end_column": int(location.get("end_column") or location.get("column") or 1),
            })
    return records


def _scan(unit: UnitContext, spec: ToolSpec, executor_factory: ExecutorFactory,
          fail_tool: str | None) -> Mapping[str, Any]:
    definitions = _selected(unit, spec.provider)
    _, max_bytes, max_observations = _bounds(unit)
    gaps: list[str] = []
    records: list[dict[str, Any]] = []
    executions: list[dict[str, Any]] = []
    if not definitions:
        raw = {"schema": "appsec-review/ci-raw-observations/1", "provider": spec.provider,
               "tool_id": spec.tool_id, "definitions": [], "records": [],
               "gaps": [f"no {spec.provider} CI definitions discovered"], "terminal_status": "NOT_APPLICABLE"}
        artifact = _write(unit, "raw-observations.json", raw)
        return {"provider": spec.provider, "tool_id": spec.tool_id, "terminal_status": "NOT_APPLICABLE",
                "raw_artifact": artifact, "record_count": 0, "gaps": raw["gaps"], "executions": []}
    if spec.mode == "discovery":
        gaps.append("supported_discovery_without_linter: definition cataloged but no provider linter is enabled")
    elif spec.mode == "static":
        for definition in definitions:
            source = (unit.job.target_root or Path()) / definition["path"]
            try:
                data = source.read_bytes()
                if len(data) > max_bytes:
                    gaps.append(f"{definition['path']}: configured max_file_bytes exceeded")
                    continue
                text = data.decode("utf-8", "strict")
            except (OSError, UnicodeError) as exc:
                gaps.append(f"{definition['path']}: static parse unavailable ({type(exc).__name__})")
                continue
            records.extend(scan_text(spec.provider, definition["path"], text, tool_id=spec.tool_id))
    else:
        try:
            executor = executor_factory(unit)
            tool = executor.catalog.tool(spec.tool_id)
            image_id = executor.resolve_image(tool)
        except (KeyError, RuntimeError, ValueError) as exc:
            gaps.append(f"{spec.tool_id}: pinned offline image unavailable ({type(exc).__name__}: {exc})")
            tool = None
            image_id = None
        if tool is not None:
            for index, definition in enumerate(definitions, 1):
                scratch = unit.unit_root / "scratch" / f"file_{index:04d}"
                try:
                    if fail_tool in {spec.tool_id, spec.key}:
                        raise RuntimeError(f"injected bounded failure: {fail_tool}")
                    result = executor.execute(ExecutionRequest(
                        tool_id=spec.tool_id, argv=_argv(spec, tool.executable, definition["path"]),
                        target_root=unit.job.target_root or Path(), scratch_root=scratch,
                    ))
                    executions.append(asdict(result))
                    stdout = unit.job.run_root / result.stdout_path
                    if result.timed_out or result.oom_killed or result.exit_code not in {0, 1}:
                        gaps.append(f"{definition['path']}: {spec.tool_id} failed with exit={result.exit_code}")
                        continue
                    records.extend(_generic_external_records(spec, stdout.read_bytes(), definition["path"]))
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                    gaps.append(f"{definition['path']}: {spec.tool_id} unavailable ({type(exc).__name__}: {exc})")
    if len(records) > max_observations:
        records = records[:max_observations]
        gaps.append(f"observation bound reached at {max_observations}")
    for record in records:
        message = str(record.get("message", ""))
        message = re.sub(r"\$\{\{\s*secrets\.[^}]+\}\}", "<redacted>", message, flags=re.I)
        message = re.sub(r"(?i)\b(token|secret|password|api[_-]?key)\s*[=:]\s*\S+",
                         r"\1=<redacted>", message)
        record["message"] = message
    terminal = "FAILED" if gaps and not records and spec.mode == "external" else ("PARTIAL" if gaps else "SUCCEEDED")
    raw = {"schema": "appsec-review/ci-raw-observations/1", "provider": spec.provider,
           "tool_id": spec.tool_id, "tool_name": spec.name, "framework": spec.framework,
           "definitions": definitions, "records": records, "gaps": list(dict.fromkeys(gaps)),
           "executions": executions, "image_id": image_id if spec.mode == "external" else None,
           "ruleset_identity": RULESET_IDENTITY if spec.mode == "static" else None,
           "terminal_status": terminal}
    artifact = _write(unit, "raw-observations.json", raw)
    return {"provider": spec.provider, "tool_id": spec.tool_id, "terminal_status": terminal,
            "raw_artifact": artifact, "record_count": len(records), "gaps": raw["gaps"],
            "executions": executions}


def _normalize(unit: UnitContext, scan_id: str) -> Mapping[str, Any]:
    output = dict(unit.output(scan_id))
    raw = _read(unit.job.run_root, output["raw_artifact"])
    records = []
    for record in raw["records"]:
        value = {key: record.get(key) for key in (
            "provider", "tool_id", "native_rule_id", "category", "message", "severity", "path",
            "start_line", "end_line", "start_column", "end_column", "start_byte", "end_byte")}
        value["provider"] = value["provider"] or raw["provider"]
        value["tool_id"] = value["tool_id"] or raw["tool_id"]
        value["start_line"] = max(1, int(value["start_line"] or 1))
        value["end_line"] = max(value["start_line"], int(value["end_line"] or value["start_line"]))
        value["start_column"] = max(1, int(value["start_column"] or 1))
        value["end_column"] = max(1, int(value["end_column"] or value["start_column"]))
        value["observation_id"] = "cio:" + hashlib.sha256(canonical_json(value)).hexdigest()
        records.append(value)
    unique = {record["observation_id"]: record for record in records}
    document = {"schema": "appsec-review/ci-normalized-observations/1", "provider": raw["provider"],
                "tool_id": raw["tool_id"], "records": [unique[key] for key in sorted(unique)],
                "gaps": raw["gaps"], "terminal_status": raw["terminal_status"],
                "raw_artifact": output["raw_artifact"], "normalizer_identity": "ci-normalizer/1"}
    artifact = _write(unit, "normalized-observations.json", document)
    return {**output, "normalized_artifact": artifact, "record_count": len(unique),
            "raw_record_count": len(records), "duplicate_observation_count": len(records) - len(unique)}


def _hierarchy(unit: UnitContext) -> Mapping[str, Any]:
    definitions = unit.output("ci_discovery.classify_providers")["definitions"]
    _, max_bytes, _ = _bounds(unit)
    nodes: list[dict[str, Any]] = []
    gaps: list[str] = []
    for definition in definitions:
        source = (unit.job.target_root or Path()) / definition["path"]
        try:
            data = source.read_bytes()
            if len(data) > max_bytes:
                gaps.append(f"{definition['path']}: hierarchy max_file_bytes exceeded")
                continue
            nodes.extend(hierarchy(definition["provider"], definition["path"], data.decode("utf-8", "strict")))
        except (OSError, UnicodeError) as exc:
            gaps.append(f"{definition['path']}: hierarchy unavailable ({type(exc).__name__})")
    document = {"schema": "appsec-review/ci-hierarchy/1", "nodes": nodes,
                "gaps": list(dict.fromkeys(gaps)), "parser_identity": "ci-structural-hierarchy/1"}
    return {"artifact": _write(unit, "hierarchy.json", document), "node_count": len(nodes), "gaps": document["gaps"]}


def _enrich(record: dict[str, Any], nodes: list[Mapping[str, Any]]) -> dict[str, Any]:
    candidates = [node for node in nodes if node["path"] == record["path"] and
                  int(node["start_line"]) <= int(record["start_line"])]
    context: dict[str, str] = {}
    for kind in ("stage", "job", "step"):
        matches = [node for node in candidates if node["kind"] == kind]
        if matches:
            context[kind] = str(max(matches, key=lambda item: int(item["start_line"]))["name"])
    return {**record, "pipeline": record["path"], "workflow": record["path"], **context}


def _source_location(unit: UnitContext, record: Mapping[str, Any]) -> SourceLocation | None:
    source = (unit.job.target_root or Path()) / str(record["path"])
    if not source.is_file():
        return None
    data = source.read_bytes()
    offsets = [0, *(match.end() for match in re.finditer(b"\n", data))]
    start_line, end_line = int(record["start_line"]), int(record["end_line"])
    start_byte = int(record.get("start_byte") or offsets[min(start_line - 1, len(offsets) - 1)])
    end_byte = int(record.get("end_byte") or (offsets[end_line] if end_line < len(offsets) else len(data)))
    return SourceLocation(
        target_snapshot=unit.job.source_fingerprint, path=str(record["path"]), file_sha256=file_sha256(source),
        start_byte=min(start_byte, len(data)), end_byte=min(max(start_byte, end_byte), len(data)),
        start_line=start_line, end_line=end_line, start_column=int(record["start_column"]),
        end_column=int(record["end_column"]), producer_location={"tool_id": record["tool_id"]},
        mapping_method="ci-static-source-span", confidence=1.0,
    )


def _index(unit: UnitContext, spec: ToolSpec, normalize_id: str) -> Mapping[str, Any]:
    output = dict(unit.output(normalize_id))
    normalized = _read(unit.job.run_root, output["normalized_artifact"])
    hierarchy_doc = _read(unit.job.run_root, unit.output("ci_enrichment.build_hierarchy")["artifact"])
    records = [_enrich(dict(record), hierarchy_doc["nodes"]) for record in normalized["records"]]
    config_identity = hashlib.sha256(canonical_json(dict(unit.job.config.settings))).hexdigest()
    fingerprint = index_fingerprint(
        name="observations", target_snapshot=unit.job.source_fingerprint,
        producer_artifacts=[output["normalized_artifact"], unit.output("ci_enrichment.build_hierarchy")["artifact"]],
        tool_identity={"tool_id": spec.tool_id, "provider": spec.provider, "framework": spec.framework,
                       "ruleset": RULESET_IDENTITY, "config": config_identity},
        parser_identity="ci-provider-parser/1", normalizer_identity="ci-normalizer/1",
        mapping_identity="ci-static-source-span/1",
    )
    shard_id = f"ci_{spec.key}"
    path = unit.job.run_root / "data" / "indices" / "observations" / shard_id / f"{fingerprint}.sqlite"
    builder = IndexBuilder(path, name="observations", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard_id)
    for record in records:
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, unit.job.source_fingerprint,
                                          {"ci_observation_id": record["observation_id"]})
        builder.add_entity(EntityRecord(identity, record["observation_id"], str(record["native_rule_id"]),
                                         " ".join(str(record.get(key, "")) for key in
                                                  ("provider", "category", "message", "pipeline", "job", "step")),
                                         record, _source_location(unit, record)))
    status = "complete" if output["terminal_status"] == "SUCCEEDED" else (
        "unavailable" if output["terminal_status"] in {"FAILED", "NOT_APPLICABLE"} else "partial")
    gap = "; ".join(output.get("gaps", [])[:10]) or None
    builder.add_coverage(f"{spec.provider}:{spec.name}", status, gap)
    sha256 = builder.build()
    identity = IndexIdentity("observations", "appsec-review/retrieval-index/1", sha256, fingerprint,
                             _rel(unit.job.run_root, path), {"job": "job_ci_configuration_analysis",
                             "provider": spec.provider, "tool_id": spec.tool_id},
                             tuple(output.get("gaps", ())), shard_id)
    return {"provider": spec.provider, "tool_id": spec.tool_id, "terminal_status": output["terminal_status"],
            "artifact": _artifact(unit.job.run_root, path), "index_identity": asdict(identity),
            "normalized_artifact": output["normalized_artifact"], "record_count": len(records),
            "gaps": output.get("gaps", []), "records": records}


def _correlate(unit: UnitContext, index_ids: tuple[str, ...]) -> Mapping[str, Any]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for unit_id in index_ids:
        for record in unit.output(unit_id)["records"]:
            key = correlation_key(record)
            grouped[key].append(record)
    findings = []
    for key, observations in sorted(grouped.items(), key=lambda item: repr(item[0])):
        finding_id = "cif:" + hashlib.sha256(canonical_json(key)).hexdigest()
        findings.append({
            "finding_id": finding_id, "provider": key[0], "path": key[1], "start_line": key[2],
            "end_line": key[3], "start_column": key[4], "end_column": key[5], "category": key[6],
            "message": key[7], "observation_ids": sorted(item["observation_id"] for item in observations),
            "tools": sorted({item["tool_id"] for item in observations}),
            "exact_duplicate_count": len(observations),
        })
    document = {"schema": "appsec-review/canonical-ci-findings/1", "correlation": "exact-only/1",
                "findings": findings, "finding_count": len(findings)}
    artifact = _write(unit, "canonical-findings.json", document)
    fingerprint = index_fingerprint(
        name="evidence", target_snapshot=unit.job.source_fingerprint,
        producer_artifacts=[artifact], tool_identity={"correlator": "ci-exact-only/1"},
        parser_identity="canonical-ci-findings/1", normalizer_identity="ci-normalizer/1",
        mapping_identity="ci-static-source-span/1",
    )
    path = unit.job.run_root / "data" / "indices" / "evidence" / "ci_findings" / f"{fingerprint}.sqlite"
    builder = IndexBuilder(path, name="evidence", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id="ci_findings")
    for finding in findings:
        identity = LogicalIdentity.derive(EntityKind.FINDING_PACKAGE, unit.job.source_fingerprint,
                                          {"ci_finding_id": finding["finding_id"]})
        builder.add_entity(EntityRecord(identity, finding["finding_id"], finding["category"],
                                         f"{finding['provider']} {finding['category']} {finding['message']}", finding,
                                         _source_location(unit, {**finding, "tool_id": "ci-correlator"})))
    builder.add_coverage("ci-correlation", "complete")
    sha256 = builder.build()
    identity = IndexIdentity("evidence", "appsec-review/retrieval-index/1", sha256, fingerprint,
                             _rel(unit.job.run_root, path), {"job": "job_ci_configuration_analysis",
                             "producer": "ci-exact-correlator"}, (), "ci_findings")
    return {"artifact": artifact, "index_artifact": _artifact(unit.job.run_root, path),
            "index_identity": asdict(identity), "finding_count": len(findings), "findings": findings, "gaps": []}


def correlation_key(record: Mapping[str, Any]) -> tuple[Any, ...]:
    """Exact-only canonical key; intentionally excludes tool identity and nothing else."""
    return (record["provider"], record["path"], record["start_line"], record["end_line"],
            record["start_column"], record["end_column"], record["category"], record["message"])


def _coverage(unit: UnitContext, index_ids: tuple[str, ...]) -> Mapping[str, Any]:
    classified = unit.output("ci_discovery.classify_providers")
    by_provider = {provider: len([item for item in classified["definitions"] if item["provider"] == provider])
                   for provider in PROVIDERS}
    tools = []
    gaps = list(classified["gaps"])
    for unit_id in index_ids:
        output = unit.output(unit_id)
        tools.append({key: output[key] for key in ("provider", "tool_id", "terminal_status", "record_count")}
                     | {"gaps": output.get("gaps", [])})
        gaps.extend(output.get("gaps", []))
    coverage = {"schema": "appsec-review/ci-coverage/1", "definitions_by_provider": by_provider,
                "tools": tools, "gaps": list(dict.fromkeys(gaps)),
                "coverage_status": "complete" if not gaps else "partial"}
    return {"artifact": _write(unit, "coverage.json", coverage), **coverage}


def build_job(*, executor_factory: ExecutorFactory | None = None, fail_tool: str | None = None) -> Job:
    def validate(context, result) -> None:
        if context.target_root is None:
            raise ValueError("CI configuration analysis requires a graph-provided target root")
        if tuple(context.config.steps) != tuple(TOPOLOGY):
            raise ValueError("CI configuration topology does not match central configuration")
        for step, tasks in TOPOLOGY.items():
            if tuple(context.config.step(step).tasks) != tasks:
                raise ValueError(f"CI configuration task order mismatch: {step}")
        catalog = load_target_catalog(context.run_root)
        if catalog.source_fingerprint != context.source_fingerprint:
            raise ValueError("CI target fingerprint does not match the accepted target catalog")

    def factory(unit: UnitContext) -> ContainerExecutor:
        return executor_factory(unit) if executor_factory is not None else ContainerExecutor(
            load_catalog(unit.job.repository_root), unit.job.run_root)

    def discover_handler(unit: UnitContext) -> Mapping[str, Any]:
        catalog = load_target_catalog(unit.job.run_root)
        max_files, _, _ = _bounds(unit)
        definitions, gaps = discover_ci_definitions(catalog.files, max_files=max_files)
        document = {"schema": "appsec-review/ci-definition-catalog/1", "definitions": definitions,
                    "gaps": gaps, "catalog_handoff_sha256": catalog.handoff_sha256}
        return {"artifact": _write(unit, "ci-definitions.json", document), **document}

    def classify_handler(unit: UnitContext) -> Mapping[str, Any]:
        source = unit.output("ci_discovery.discover_definitions")
        by_provider = {provider: [item["path"] for item in source["definitions"] if item["provider"] == provider]
                       for provider in PROVIDERS}
        document = {"schema": "appsec-review/ci-provider-classification/1",
                    "definitions": source["definitions"], "by_provider": by_provider, "gaps": source["gaps"]}
        return {"artifact": _write(unit, "provider-classification.json", document), **document}

    units: list[Unit] = [
        Unit("ci_discovery.discover_definitions", discover_handler),
        Unit("ci_discovery.classify_providers", classify_handler, ("ci_discovery.discover_definitions",)),
    ]
    normalize_ids: list[str] = []
    index_ids: list[str] = []
    for spec in SPECS:
        scan_id = f"ci_analysis.{spec.key}_scan"
        normalize_id = f"ci_normalization.{spec.key}_normalize"
        index_id = f"ci_observation_publication.{spec.key}_index"
        units.append(Unit(scan_id, lambda unit, selected=spec: _scan(unit, selected, factory, fail_tool),
                          ("ci_discovery.classify_providers",)))
        units.append(Unit(normalize_id, lambda unit, source=scan_id: _normalize(unit, source), (scan_id,)))
        normalize_ids.append(normalize_id)
        index_ids.append(index_id)
    units.append(Unit("ci_enrichment.build_hierarchy", _hierarchy,
                      ("ci_discovery.classify_providers", *tuple(normalize_ids))))
    for spec, normalize_id, index_id in zip(SPECS, normalize_ids, index_ids, strict=True):
        units.append(Unit(index_id, lambda unit, selected=spec, source=normalize_id: _index(unit, selected, source),
                          (normalize_id, "ci_enrichment.build_hierarchy")))
    units.append(Unit("ci_correlation.correlate_findings", lambda unit: _correlate(unit, tuple(index_ids)),
                      tuple(index_ids)))
    units.append(Unit("ci_coverage.join_coverage", lambda unit: _coverage(unit, tuple(index_ids)),
                      ("ci_correlation.correlate_findings", *tuple(index_ids))))

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        manifest_path, manifest_sha = resolve_accepted_manifest(unit.job.run_root)
        upstream, _ = load_verified_manifest(unit.job.run_root, manifest_path, manifest_sha)
        identities = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))}) for item in upstream["indexes"]]
        identities.extend(IndexIdentity(**{**unit.output(unit_id)["index_identity"],
                                            "gaps": tuple(unit.output(unit_id)["index_identity"].get("gaps", ()))})
                          for unit_id in index_ids)
        correlation = unit.output("ci_correlation.correlate_findings")
        identities.append(IndexIdentity(**{**correlation["index_identity"],
                                           "gaps": tuple(correlation["index_identity"].get("gaps", ())) }))
        combined = unit.job.run_root / "data" / "indices" / "manifests" / f"ci-{unit.job.attempt_id}.json"
        write_manifest(combined, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                       target_root=unit.job.target_root or Path(), indexes=identities,
                       upstream_manifests=({"path": _rel(unit.job.run_root, manifest_path),
                                            "sha256": manifest_sha},))
        load_verified_manifest(unit.job.run_root, combined, file_sha256(combined))
        coverage = unit.output("ci_coverage.join_coverage")
        document = {"schema": "appsec-review/ci-configuration-analysis-handoff/1",
                    "target_fingerprint": unit.job.source_fingerprint,
                    "coverage": coverage["artifact"], "canonical_findings": correlation["artifact"],
                    "index_manifest": _artifact(unit.job.run_root, combined),
                    "finding_count": correlation["finding_count"], "gaps": coverage["gaps"],
                    "security_findings": []}
        artifact = _write(unit, "handoff.json", document)
        return {**document, "artifact": artifact,
                "terminal_status": "PARTIAL" if document["gaps"] else "SUCCEEDED"}

    units.append(Unit("ci_coverage.publish_handoff", publish,
                      ("ci_coverage.join_coverage", "ci_correlation.correlate_findings", *tuple(index_ids))))
    source_files = (Path(__file__), Path(__file__).with_name("discovery.py"), Path(__file__).with_name("static_rules.py"))
    implementation = hashlib.sha256(b"".join(path.read_bytes() for path in source_files) +
                                    str(fail_tool).encode()).hexdigest()

    def runtime_identity() -> str:
        root = Path(os.environ.get("APPSEC_REVIEW_CONFIG", "appsec-review.toml")).resolve().parent
        digest = hashlib.sha256(RULESET_IDENTITY.encode())
        for tool_id in ("tool-actionlint", "tool-checkov", "tool-zizmor"):
            try:
                tool = load_catalog(root).tool(tool_id)
                digest.update(canonical_json({"id": tool_id, "tag": tool.tag, "manifest": file_sha256(tool.manifest_path)}))
            except (KeyError, OSError, ValueError):
                digest.update(f"{tool_id}:UNAVAILABLE".encode())
        digest.update(b"injected-executor" if executor_factory else b"container-executor")
        return digest.hexdigest()

    return Job("job_ci_configuration_analysis", "ci_configuration_analysis", UnitExecutor(tuple(units)).execute,
               input_validators=(validate,), schema_identity="appsec-review/ci-configuration-analysis-job/1",
               implementation_identity=implementation,
               validation_identity=hashlib.sha256(Path(__file__).read_bytes() + b"validation").hexdigest(),
               runtime_identity=runtime_identity, units=tuple(units))
