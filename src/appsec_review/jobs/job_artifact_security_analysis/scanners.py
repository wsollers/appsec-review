"""Pinned scanner command and bounded-output adapters for produced artifacts.

Adapters describe scanners; execution remains delegated to the repository container runtime so
target artifacts are mounted read-only and are never invoked as programs.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import inspect
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
import xml.etree.ElementTree as ET

from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, Mount, load_catalog
from appsec_review import blint_report
from appsec_review.jobs.job_third_party_data_sync.publication import verify_current
from appsec_review.osv_offline import (
    DATABASE_ROOT as OSV_DATABASE_ROOT, ENVIRONMENT as OSV_DB_ENVIRONMENT, offline_database_mounts,
    snapshot_ecosystems,
)
from appsec_review.tool_inputs import osv_ecosystem, osv_missing_ecosystem_gap, osv_reported_no_package_sources
from appsec_review.storage import file_sha256
from appsec_review.provenance import xml_selector
from appsec_review.runtime import execution_safety as safety


def _bounded(value: Any, *, depth: int = 0, truncations: set[str] | None = None) -> Any:
    if truncations is None:
        truncations = set()
    if depth > 8:
        truncations.add("depth")
        return "<depth-limit>"
    if isinstance(value, Mapping):
        if len(value) > 2_000:
            truncations.add("object_members")
        if any(len(str(key)) > 128 for key in value):
            truncations.add("object_key")
        return {str(key)[:128]: _bounded(child, depth=depth + 1, truncations=truncations)
                for key, child in list(value.items())[:2_000]}
    if isinstance(value, list):
        if len(value) > 20_000:
            truncations.add("array_items")
        return [_bounded(child, depth=depth + 1, truncations=truncations) for child in value[:20_000]]
    if isinstance(value, str):
        if len(value) > 65_536:
            truncations.add("string")
        return value[:65_536]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:4_096]


def parse_json(payload: bytes) -> Mapping[str, Any]:
    if len(payload) > 64 * 1024 * 1024:
        raise ValueError("scanner JSON exceeds parser byte bound")
    if not payload.strip():
        raise ValueError("scanner JSON output is empty")
    raw = json.loads(payload.decode("utf-8"))
    truncations: set[str] = set()
    value = _bounded(raw, truncations=truncations)
    return {**(value if isinstance(value, Mapping) else {"records": value}),
            "_parser_truncated": bool(truncations), "_parser_bounds": sorted(truncations),
            "_native_result_count": native_result_count(raw)}


def native_result_count(value: Any) -> int:
    if not isinstance(value, Mapping):
        return len(value) if isinstance(value, list) else 0
    for key in ("findings", "matches", "artifacts"):
        if isinstance(value.get(key), list):
            return len(value[key])
    results = value.get("results")
    if isinstance(results, list):
        return sum(len(package.get("vulnerabilities", []))
                   for result in results if isinstance(result, Mapping)
                   for package in result.get("packages", []) if isinstance(package, Mapping)
                   if isinstance(package.get("vulnerabilities", []), list))
    return 0


def parse_spotbugs(payload: bytes) -> Mapping[str, Any]:
    if len(payload) > 64 * 1024 * 1024:
        raise ValueError("SpotBugs XML exceeds parser byte bound")
    root = ET.fromstring(payload.decode("utf-8"))
    findings = []
    bugs = [element for element in root.iter() if element.tag.rsplit("}", 1)[-1] == "BugInstance"]
    ordinals: dict[str, int] = {}
    for bug in bugs[:20_000]:
        ordinal = ordinals.get(bug.tag, 0)
        ordinals[bug.tag] = ordinal + 1
        source = next((element for element in bug if element.tag.rsplit("}", 1)[-1] == "SourceLine"), None)
        findings.append({"type": bug.get("type"), "category": bug.get("category"),
            "priority": bug.get("priority"), "class": (source.get("classname") if source is not None else None),
            "source": (source.get("sourcepath") if source is not None else None),
            "start": (source.get("start") if source is not None else None),
            "end": (source.get("end") if source is not None else None),
            "_native_selector": xml_selector(bug, ordinal).as_dict()})
    return {"findings": findings, "finding_count": len(findings),
            "finding_count_reported": len(bugs), "_parser_truncated": len(bugs) > 20_000,
            "_native_result_count": len(bugs),
            "_parser_bounds": ["array_items"] if len(bugs) > 20_000 else []}


@dataclass(frozen=True, slots=True)
class ScannerAdapter:
    capability: str
    tool_id: str
    accepted_exit_codes: frozenset[int]
    output_file: str

    @property
    def identity(self) -> str:
        return "undeclared"

    def argv(self, executable: str, artifact_name: str) -> tuple[str, ...]:
        name = PurePosixPath(artifact_name).name
        target = f"/target/{name}"
        if self.capability == "blint":
            # blint writes findings.json and <name>-metadata.json into --reports; see blint_report.
            return (executable, "--no-banner", "--no-error", "--quiet", "--src", target,
                    "--reports", "/scratch")
        if self.capability == "syft":
            return (executable, f"file:{target}", "--output", f"json={self.output_file}")
        if self.capability == "grype":
            return (executable, f"file:{target}", "--output", "json", "--file", self.output_file,
                    "--only-fixed=false")
        if self.capability == "osv":
            # --lockfile selects the extractor by file name; a single-file --recursive scan instead
            # trips osv-scanner's gitignore resolution and finds no package sources.
            return (executable, "scan", "--experimental-offline", "--format", "json", "--output",
                    self.output_file, "--lockfile", target)
        if self.capability == "spotbugs":
            return (executable, "-textui", "-xml:withMessages", "-output", self.output_file, target)
        raise ValueError(f"unknown scanner capability: {self.capability}")

    def parse(self, payload: bytes) -> Mapping[str, Any]:
        return parse_spotbugs(payload) if self.capability == "spotbugs" else parse_json(payload)


ADAPTERS = {item.capability: item for item in (
    ScannerAdapter("blint", "tool-blint", frozenset({0}), "/scratch/blint-report.json"),
    ScannerAdapter("syft", "tool-syft", frozenset({0}), "/scratch/output.json"),
    ScannerAdapter("grype", "tool-grype", frozenset({0}), "/scratch/output.json"),
    ScannerAdapter("osv", "tool-osv-scanner", frozenset({0, 1}), "/scratch/output.json"),
    ScannerAdapter("spotbugs", "tool-spotbugs", frozenset({0}), "/scratch/output.xml"),
)}


def _execution_token(capability: str, artifact: Mapping[str, Any]) -> str:
    """Keep scanner receipts distinct for equal-content artifacts at different identities."""
    canonical_identity = artifact.get("canonical_identity")
    if not isinstance(canonical_identity, str) or not canonical_identity:
        raise ValueError("scanner artifact canonical identity is required")
    material = f"{canonical_identity}:{artifact.get('sha256')}:{capability}"
    return hashlib.sha256(material.encode()).hexdigest()[:16]


class ContainerScannerRunner:
    """Run pinned scanners with one produced artifact mounted read-only as data."""

    def __init__(self, repository_root: Path, run_root: Path, scratch_root: Path, *,
                 osv_memory: str | None = None):
        self.repository_root = repository_root
        self.osv_memory = osv_memory
        self.run_root = run_root
        self.scratch_root = scratch_root
        self.catalog = load_catalog(repository_root)
        self.executor = ContainerExecutor(self.catalog, run_root)
        self._identities: dict[str, Mapping[str, Any]] = {}
        self._feeds: dict[str, Mapping[str, Any]] = {}
        self._osv_ecosystems: Mapping[str, Path] = {}

    def identity(self, capability: str, artifact: Mapping[str, Any]) -> Mapping[str, Any]:
        if capability in self._identities:
            return self._identities[capability]
        adapter = ADAPTERS[capability]
        try:
            tool = self.catalog.tool(adapter.tool_id)
            image_id = self.executor.resolve_image(tool)
        except (KeyError, RuntimeError) as exc:
            safety.fail(f"artifact image resolution failed: {exc}", action="artifact.image")
            value = {"scanner": adapter.tool_id, "adapter": adapter.identity,
                     "unavailable": f"pinned scanner image unavailable: {type(exc).__name__}: {exc}"}
            self._identities[capability] = value
            return value
        value: dict[str, Any] = {"scanner": adapter.tool_id, "version": tool.version,
            "image": image_id,
            "adapter": adapter.identity, "rules": None}
        if capability in {"grype", "osv"}:
            feed = "grype" if capability == "grype" else "osv"
            try:
                current = verify_current(self.repository_root / "data" / "feeds" / feed, feed)
                self._feeds[capability] = current
                if capability == "osv":
                    self._osv_ecosystems = snapshot_ecosystems(Path(str(current["directory"])))
                value["rules"] = {"feed": feed, "snapshot_id": current["snapshot_id"],
                                  "manifest_sha256": current["manifest_sha256"]}
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                safety.fail(f"artifact feed integrity failed: {type(exc).__name__}", action="artifact.feed")
                value["unavailable"] = f"verified immutable {feed} database unavailable: {type(exc).__name__}"
        self._identities[capability] = value
        return value

    def __call__(self, capability: str, path: Path, artifact: Mapping[str, Any],
                 timeout: int, limit: int) -> Mapping[str, Any]:
        adapter = ADAPTERS[capability]
        identity = self.identity(capability, artifact)
        if identity.get("unavailable"):
            raise RuntimeError(str(identity["unavailable"]))
        token = _execution_token(capability, artifact)
        scratch = self.scratch_root / "containers" / token
        scratch.mkdir(parents=True, exist_ok=True)
        mounts: list[Mount] = []
        input_name, target_root = path.name, path.parent
        if artifact.get("artifact_origin") == "target-intake":
            from appsec_review.retrieval.model import normalize_relative_path
            original = normalize_relative_path(str(artifact["target_relative_path"]))
            input_name = PurePosixPath(original).name
            target_root = self.scratch_root / "target-inputs" / token
            target_root.mkdir(parents=True, exist_ok=True)
            (target_root / input_name).touch(exist_ok=True)
            mounts.append(Mount(path, f"/target/{input_name}", True))
        environment: dict[str, str] = {}
        memory = None
        if capability == "grype":
            snapshot = self._feeds[capability]
            mounts.append(Mount(Path(str(snapshot["directory"])), "/database", True))
            environment["GRYPE_DB_CACHE_DIR"] = "/database"
        elif capability == "osv":
            ecosystem = osv_ecosystem(input_name)
            if ecosystem is not None and ecosystem not in self._osv_ecosystems:
                # osv-scanner would abort with exit 127; record the data-coverage gap instead.
                gap = osv_missing_ecosystem_gap((ecosystem,), f"produced lockfile {input_name}")
                return {"stdout": b"", "stderr": gap.encode(), "exit_code": None, "timed_out": False,
                        "truncated": False, "precondition_gap": gap, "tool_identity": identity,
                        "execution_receipt": None}
            # Offline mode loads every mounted database into memory: mount only this lockfile's.
            mounts.extend(offline_database_mounts(
                self._osv_ecosystems, () if ecosystem is None else (ecosystem,)))
            environment[OSV_DB_ENVIRONMENT] = OSV_DATABASE_ROOT
            memory = self.osv_memory
        tool = self.catalog.tool(adapter.tool_id)
        result = self.executor.execute(ExecutionRequest(adapter.tool_id,
            adapter.argv(tool.executable, input_name), target_root, scratch,
            extra_mounts=tuple(mounts), environment=environment, memory=memory,
            accepted_exit_codes=frozenset(adapter.accepted_exit_codes),
            expected_nonzero=lambda code, stdout, stderr: (
                capability == "osv" and osv_reported_no_package_sources(code, stdout + b"\n" + stderr))))
        stdout = (self.run_root / result.stdout_path).read_bytes()
        stderr = (self.run_root / result.stderr_path).read_bytes()
        output = scratch / PurePosixPath(adapter.output_file).name
        if (capability == "blint" and not result.timed_out
                and result.exit_code in adapter.accepted_exit_codes):
            blint_report.write(scratch, output)
        payload = output.read_bytes() if output.is_file() else stdout
        return {"stdout": stdout, "stderr": stderr, "exit_code": result.exit_code,
            "timed_out": result.timed_out, "truncated": result.stdout_truncated or result.stderr_truncated,
            "payload": payload, "tool_identity": identity,
            "payload_truncated": result.stdout_truncated if not output.is_file() else False,
            "native_reports": ({"findings.json": (scratch / "findings.json").relative_to(self.run_root).as_posix()}
                               if capability == "blint" and (scratch / "findings.json").is_file() else {}),
            "execution_receipt": {"path": result.receipt_path,
                                  "sha256": file_sha256(self.run_root / result.receipt_path)}}
