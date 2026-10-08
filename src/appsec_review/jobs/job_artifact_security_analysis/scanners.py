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
import shutil
from typing import Any, Mapping
import xml.etree.ElementTree as ET

from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, Mount, load_catalog
from appsec_review.jobs.job_third_party_data_sync.publication import verify_current
from appsec_review.storage import file_sha256


def _bounded(value: Any, *, depth: int = 0) -> Any:
    if depth > 8:
        return "<depth-limit>"
    if isinstance(value, Mapping):
        return {str(key)[:128]: _bounded(child, depth=depth + 1)
                for key, child in list(value.items())[:2_000]}
    if isinstance(value, list):
        return [_bounded(child, depth=depth + 1) for child in value[:20_000]]
    if isinstance(value, str):
        return value[:65_536]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:4_096]


def parse_json(payload: bytes) -> Mapping[str, Any]:
    if len(payload) > 64 * 1024 * 1024:
        raise ValueError("scanner JSON exceeds parser byte bound")
    raw = json.loads(payload.decode("utf-8")) if payload.strip() else {}
    value = _bounded(raw)
    return value if isinstance(value, Mapping) else {"records": value}


def parse_spotbugs(payload: bytes) -> Mapping[str, Any]:
    if len(payload) > 64 * 1024 * 1024:
        raise ValueError("SpotBugs XML exceeds parser byte bound")
    root = ET.fromstring(payload.decode("utf-8"))
    findings = []
    for bug in root.findall(".//BugInstance")[:20_000]:
        source = bug.find("SourceLine")
        findings.append({"type": bug.get("type"), "category": bug.get("category"),
            "priority": bug.get("priority"), "class": (source.get("classname") if source is not None else None),
            "source": (source.get("sourcepath") if source is not None else None),
            "start": (source.get("start") if source is not None else None),
            "end": (source.get("end") if source is not None else None)})
    return {"findings": findings, "finding_count": len(findings)}


@dataclass(frozen=True, slots=True)
class ScannerAdapter:
    capability: str
    tool_id: str
    accepted_exit_codes: frozenset[int]
    output_file: str

    @property
    def identity(self) -> str:
        return hashlib.sha256(repr((self.capability, self.tool_id,
            sorted(self.accepted_exit_codes), self.output_file, inspect.getsource(parse_json),
            inspect.getsource(parse_spotbugs))).encode()).hexdigest()

    def argv(self, executable: str, artifact_name: str) -> tuple[str, ...]:
        name = PurePosixPath(artifact_name).name
        target = f"/target/{name}"
        if self.capability == "blint":
            return (executable, "--no-banner", "--format", "json", "--output", self.output_file, target)
        if self.capability == "syft":
            return (executable, f"file:{target}", "--output", f"json={self.output_file}")
        if self.capability == "grype":
            return (executable, f"file:{target}", "--output", "json", "--file", self.output_file,
                    "--only-fixed=false")
        if self.capability == "osv":
            return (executable, "scan", "--experimental-offline", "--format", "json", "--output",
                    self.output_file, "--recursive", target)
        if self.capability == "spotbugs":
            return (executable, "-textui", "-xml:withMessages", "-output", self.output_file, target)
        raise ValueError(f"unknown scanner capability: {self.capability}")

    def parse(self, payload: bytes) -> Mapping[str, Any]:
        return parse_spotbugs(payload) if self.capability == "spotbugs" else parse_json(payload)


ADAPTERS = {item.capability: item for item in (
    ScannerAdapter("blint", "tool-blint", frozenset({0, 1}), "/scratch/output.json"),
    ScannerAdapter("syft", "tool-syft", frozenset({0}), "/scratch/output.json"),
    ScannerAdapter("grype", "tool-grype", frozenset({0}), "/scratch/output.json"),
    ScannerAdapter("osv", "tool-osv-scanner", frozenset({0, 1}), "/scratch/output.json"),
    ScannerAdapter("spotbugs", "tool-spotbugs", frozenset({0}), "/scratch/output.xml"),
)}


class ContainerScannerRunner:
    """Run pinned scanners with one produced artifact mounted read-only as data."""

    def __init__(self, repository_root: Path, run_root: Path, scratch_root: Path):
        self.repository_root = repository_root
        self.run_root = run_root
        self.scratch_root = scratch_root
        self.catalog = load_catalog(repository_root)
        self.executor = ContainerExecutor(self.catalog, run_root)
        self._identities: dict[str, Mapping[str, Any]] = {}
        self._feeds: dict[str, Mapping[str, Any]] = {}

    def identity(self, capability: str, artifact: Mapping[str, Any]) -> Mapping[str, Any]:
        if capability in self._identities:
            return self._identities[capability]
        adapter = ADAPTERS[capability]
        try:
            tool = self.catalog.tool(adapter.tool_id)
            image_id = self.executor.resolve_image(tool)
        except (KeyError, RuntimeError) as exc:
            value = {"scanner": adapter.tool_id, "adapter": adapter.identity,
                     "unavailable": f"pinned scanner image unavailable: {type(exc).__name__}: {exc}"}
            self._identities[capability] = value
            return value
        value: dict[str, Any] = {"scanner": adapter.tool_id, "version": tool.version,
            "image": image_id, "manifest_sha256": file_sha256(tool.manifest_path),
            "adapter": adapter.identity, "rules": None}
        if capability in {"grype", "osv"}:
            feed = "grype" if capability == "grype" else "osv"
            try:
                current = verify_current(self.repository_root / "data" / "feeds" / feed, feed)
                self._feeds[capability] = current
                value["rules"] = {"feed": feed, "snapshot_id": current["snapshot_id"],
                                  "manifest_sha256": current["manifest_sha256"]}
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                value["unavailable"] = f"verified immutable {feed} database unavailable: {type(exc).__name__}"
        self._identities[capability] = value
        return value

    def __call__(self, capability: str, path: Path, artifact: Mapping[str, Any],
                 timeout: int, limit: int) -> Mapping[str, Any]:
        adapter = ADAPTERS[capability]
        identity = self.identity(capability, artifact)
        if identity.get("unavailable"):
            raise RuntimeError(str(identity["unavailable"]))
        token = hashlib.sha256(f"{artifact.get('sha256')}:{capability}".encode()).hexdigest()[:16]
        scratch = self.scratch_root / "containers" / token
        scratch.mkdir(parents=True, exist_ok=True)
        mounts: list[Mount] = []
        environment: dict[str, str] = {}
        if capability == "grype":
            snapshot = self._feeds[capability]
            mounts.append(Mount(Path(str(snapshot["directory"])), "/database", True))
            environment["GRYPE_DB_CACHE_DIR"] = "/database"
        elif capability == "osv":
            snapshot = self._feeds[capability]
            source = Path(str(snapshot["directory"])) / "sources" / "PyPI.zip"
            database = scratch / "inputs" / "osv-db" / "osv-scanner" / "PyPI"
            database.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, database / "all.zip")
            mounts.append(Mount(scratch / "inputs" / "osv-db", "/database", True))
            environment["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = "/database"
        tool = self.catalog.tool(adapter.tool_id)
        result = self.executor.execute(ExecutionRequest(adapter.tool_id,
            adapter.argv(tool.executable, path.name), path.parent, scratch,
            extra_mounts=tuple(mounts), environment=environment))
        stdout = (self.run_root / result.stdout_path).read_bytes()
        stderr = (self.run_root / result.stderr_path).read_bytes()
        output = scratch / PurePosixPath(adapter.output_file).name
        payload = output.read_bytes() if output.is_file() else stdout
        return {"stdout": stdout, "stderr": stderr, "exit_code": result.exit_code,
            "timed_out": result.timed_out, "truncated": result.stdout_truncated or result.stderr_truncated,
            "observation": adapter.parse(payload), "tool_identity": identity,
            "execution_receipt": {"path": result.receipt_path,
                                  "sha256": file_sha256(self.run_root / result.receipt_path)}}
