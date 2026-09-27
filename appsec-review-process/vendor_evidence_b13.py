#!/usr/bin/env python3
"""B13 execution seam for M03/M04 vendor evidence tools.

All argv are repository-owned constants, all executions are offline, and a successful adapter
result is re-verified using the caller-retained result digest before any scanner output is read.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import threading
from typing import Any, Callable

import container_execution as ce
import permission_capabilities as pc


@dataclass(frozen=True)
class ToolSpec:
    image_id: str
    argv: tuple[str, ...]
    output: str


SPECS = {
    "gitleaks": ToolSpec("tool-gitleaks", ("/opt/tool/bin/gitleaks", "detect", "--no-git", "--source", "/inputs",
                                             "--report-format", "json", "--report-path", "/scratch/gitleaks.json",
                                             "--redact"), "gitleaks.json"),
    "checkov": ToolSpec("tool-checkov", ("/opt/tool/bin/checkov", "-d", "/inputs", "-o", "json",
                                           "--output-file-path", "/scratch/checkov.json", "--skip-download"), "checkov.json"),
    "trivy-config": ToolSpec("tool-trivy", ("/opt/tool/bin/trivy", "config", "--skip-db-update", "--format", "json",
                                                 "--output", "/scratch/trivy-config.json", "/inputs"), "trivy-config.json"),
    "tfsec": ToolSpec("audit-iac", ("/opt/tools/tfsec", "--format", "json", "--out", "/scratch/tfsec.json",
                                      "/inputs"), "tfsec.json"),
    "kube-linter": ToolSpec("audit-iac", ("/opt/tools/kube-linter", "lint", "--format", "json", "/inputs"),
                            "kube-linter.json"),
    "hadolint": ToolSpec("tool-hadolint", ("/opt/tool/bin/hadolint", "--format", "json", "/inputs/Dockerfile"),
                         "hadolint.json"),
    "oci-archive-inventory": ToolSpec("tool-syft", ("/opt/tool/bin/syft", "scan", "file:/inputs/image.tar",
                                                          "-o", "json=/scratch/oci-inventory.json"), "oci-inventory.json"),
    "image-package-and-config-inspection": ToolSpec("tool-trivy", ("/opt/tool/bin/trivy", "image", "--input",
                                                                       "/inputs/image.tar", "--skip-db-update", "--format",
                                                                       "json", "--output", "/scratch/image-inspection.json"),
                                                    "image-inspection.json"),
    "binskim": ToolSpec("audit-binary-analysis", ("/opt/binskim/BinSkim", "analyze", "/inputs", "--output",
                                                    "/scratch/binskim.sarif", "--force"), "binskim.sarif"),
    "mobsfscan-android": ToolSpec("tool-mobsfscan", ("/opt/tool/bin/mobsfscan", "--sarif", "--output",
                                                          "/scratch/mobsfscan-android.sarif", "/inputs"),
                                      "mobsfscan-android.sarif"),
    "mobsfscan-ios": ToolSpec("tool-mobsfscan", ("/opt/tool/bin/mobsfscan", "--sarif", "--output",
                                                      "/scratch/mobsfscan-ios.sarif", "/inputs"),
                                  "mobsfscan-ios.sarif"),
}


class VendorToolBlocked(RuntimeError): pass
class VendorToolFailed(RuntimeError): pass


def _path(value: Any) -> str:
    if not isinstance(value, str): raise VendorToolFailed("output-path-invalid")
    value = value.replace("\\", "/").removeprefix("/inputs/").removeprefix("inputs/")
    if value.startswith("/") or any(p in ("", ".", "..") for p in value.split("/")):
        raise VendorToolFailed("output-path-invalid")
    return value


def _sarif(document: dict) -> list[dict[str, Any]]:
    records = []
    for run in document.get("runs", []):
        for result in run.get("results", []):
            locations = result.get("locations") or []
            physical = locations[0].get("physicalLocation", {}) if locations else {}
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            records.append({"rule_id": result.get("ruleId"), "path": _path(artifact.get("uri")),
                            "line": region.get("startLine", 1)})
    return records


def normalize(tool_id: str, data: bytes) -> list[dict[str, Any]]:
    """Reduce vendor JSON to bounded identifiers and locations; never retain messages/snippets."""
    try: document = json.loads(data)
    except (UnicodeDecodeError, ValueError) as exc: raise VendorToolFailed("expected-output-invalid") from exc
    records: list[dict[str, Any]] = []
    if tool_id == "gitleaks":
        if not isinstance(document, list): raise VendorToolFailed("gitleaks-shape-invalid")
        for item in document:
            records.append({"rule_id": item.get("RuleID"), "path": _path(item.get("File")),
                            "start_line": item.get("StartLine"), "end_line": item.get("EndLine")})
    elif tool_id == "checkov":
        failed = document.get("results", {}).get("failed_checks", [])
        for item in failed:
            span = item.get("file_line_range") or [None, None]
            records.append({"rule_id": item.get("check_id"), "path": _path(item.get("file_path")),
                            "start_line": span[0], "end_line": span[-1]})
    elif tool_id == "trivy-config":
        for result in document.get("Results", []):
            path = _path(result.get("Target"))
            for item in result.get("Misconfigurations") or []:
                records.append({"rule_id": item.get("ID"), "path": path,
                                "start_line": item.get("CauseMetadata", {}).get("StartLine", 1),
                                "end_line": item.get("CauseMetadata", {}).get("EndLine", 1)})
    elif tool_id == "tfsec":
        for item in document.get("results", []):
            loc = item.get("location", {})
            records.append({"rule_id": item.get("rule_id"), "path": _path(loc.get("filename")),
                            "start_line": loc.get("start_line"), "end_line": loc.get("end_line")})
    elif tool_id == "kube-linter":
        for item in document.get("Reports", document.get("reports", [])):
            obj = item.get("Object", item.get("object", {})); check = item.get("Check", item.get("check", "kube-linter"))
            records.append({"rule_id": check, "path": _path(obj.get("FilePath", obj.get("filePath"))),
                            "start_line": 1, "end_line": 1})
    elif tool_id == "hadolint":
        if not isinstance(document, list): raise VendorToolFailed("hadolint-shape-invalid")
        records = [{"rule_id": i.get("code"), "path": _path(i.get("file", "Dockerfile")),
                    "start_line": i.get("line"), "end_line": i.get("line")} for i in document]
    elif tool_id.startswith("mobsfscan-") or tool_id == "binskim":
        records = _sarif(document)
    elif tool_id in ("oci-archive-inventory", "image-package-and-config-inspection"):
        # Container parsers retain only package coordinates; config values and vendor prose are discarded.
        artifacts = document.get("artifacts", []) if tool_id == "oci-archive-inventory" else [
            pkg for result in document.get("Results", []) for pkg in (result.get("Packages") or [])]
        for item in artifacts:
            records.append({"name": item.get("name", item.get("Name")),
                            "version": item.get("version", item.get("Version")),
                            "ecosystem": item.get("type", item.get("Type", "unknown"))})
    else: raise VendorToolFailed("tool-parser-unavailable")
    for item in records:
        for key, value in item.items():
            if key.endswith("line") and (not isinstance(value, int) or isinstance(value, bool) or value < 1):
                raise VendorToolFailed("output-line-invalid")
            if key == "rule_id" and (not isinstance(value, str) or not value):
                raise VendorToolFailed("output-rule-invalid")
    return records


def _runtime(source_sha: str, clock: Callable[[], str]) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise VendorToolBlocked("docker-unavailable")
    return ce.ContainerRuntime(docker_executable=defaults["docker_executable"], docker_host=None,
                               images_dir=ce.IMAGES_DIR, host_flavor=defaults["host_flavor"],
                               container_user=defaults["container_user"], source_snapshot_sha256=source_sha,
                               registry_ceiling=[], clock=clock, cancel=threading.Event())


def request(tool_id: str, *, run_id: str, job_id: str, attempt_id: str, source_root: Path,
            scratch_name: str, source_sha: str, now: str) -> dict[str, Any]:
    spec = SPECS[tool_id]
    registry = ce.load_image_registry(ce.IMAGES_DIR)
    if spec.image_id not in registry:
        raise VendorToolBlocked("image-record-unavailable")
    image = registry[spec.image_id]
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": job_id, "capabilities": []}
    context = {"run_id": run_id, "job_id": job_id, "source_snapshot_sha256": source_sha, "now": now,
               "registry_ceiling": []}
    decision = pc.evaluate(requirement, [], context)
    pc.require_granted(decision, requirement=requirement, grants=[], context=context)
    return {"schema": ce.REQUEST_ID, "run_id": run_id, "job_id": job_id, "attempt_id": attempt_id,
            "image": {"image_id": image["image_id"], "digest": image["digest"]}, "argv": list(spec.argv),
            "environment": [{"name": "LANG", "value": "C"}, {"name": "LC_ALL", "value": "C"},
                            {"name": "NO_COLOR", "value": "1"}],
            "target_mounts": [{"host_path": str(source_root.resolve()), "container_path": "/inputs"}],
            "scratch_path": scratch_name, "log_path": "logs/container", "network": {"mode": "none", "destinations": []},
            "permission": {"requirement": requirement, "grants": [], "decision": decision},
            "limits": {"timeout_seconds": 900, "memory_bytes": 2 * 1024**3, "cpu_millis": 2000, "pids": 256,
                       "tmpfs_bytes": 256 * 1024**2, "stdout_limit_bytes": 1024**2, "stderr_limit_bytes": 1024**2}}


def execute(tool_id: str, *, runtime: ce.ContainerRuntime, run_id: str, job_id: str, attempt_id: str,
            attempt_root: Path, request_document: dict[str, Any],
            run_container: Callable[..., dict] = ce.run_container,
            verify: Callable[..., list[str]] = ce.verify_container_result) -> tuple[dict, bytes]:
    """Execute, re-verify, then return (terminal, raw output bytes)."""
    terminal = run_container(runtime, run_id=run_id, job_id=job_id, attempt_id=attempt_id,
                             attempt_root=attempt_root, request=request_document)
    errors = verify(attempt_root, run_id=run_id, job_id=job_id, attempt_id=attempt_id,
                    request=request_document, images_dir=runtime.images_dir,
                    expected_result_sha256=terminal["result_sha256"], host_flavor=runtime.host_flavor,
                    docker_host=runtime.docker_host, docker_executable=runtime.docker_executable,
                    container_user=runtime.container_user)
    if errors:
        raise VendorToolFailed("b13-verification-failed")
    if terminal["execution_status"] == "BLOCKED": raise VendorToolBlocked(terminal.get("cause") or "blocked")
    if terminal["execution_status"] != "OK": raise VendorToolFailed(terminal.get("cause") or "tool-failed")
    output = attempt_root / "scratch" / SPECS[tool_id].output
    if not output.is_file() or output.is_symlink(): raise VendorToolFailed("expected-output-missing")
    data = output.read_bytes()
    normalize(tool_id, data)
    return terminal, data
