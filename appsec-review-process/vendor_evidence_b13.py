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
import hashlib
import re
import base64
from typing import Any, Callable

import container_execution as ce
import permission_capabilities as pc


@dataclass(frozen=True)
class ToolSpec:
    image_id: str
    argv: tuple[str, ...]
    output: str
    captured_stdout: bool = False


SPECS = {
    "gitleaks": ToolSpec("tool-gitleaks", ("/opt/tool/bin/gitleaks", "dir", "/workspace", "--no-banner",
                                             "--report-format", "json", "--report-path", "/scratch/gitleaks.json",
                                             "--redact", "--exit-code", "0"), "gitleaks.json"),
    "checkov": ToolSpec("tool-checkov", ("/opt/tool/bin/checkov", "-d", "/workspace", "-o", "json",
                                           "--output-file-path", "/scratch/checkov.json", "--skip-download", "--soft-fail"), "checkov.json/results_json.json"),
    "trivy-config": ToolSpec("tool-trivy", ("/opt/tool/bin/trivy", "config", "--skip-check-update", "--skip-version-check", "--format", "json",
                                                 "--output", "/scratch/trivy-config.json", "/workspace"), "trivy-config.json"),
    "tfsec": ToolSpec("audit-iac", ("/root/go/bin/tfsec", "--soft-fail", "--format", "json", "--out", "/scratch/tfsec.json",
                                      "/workspace"), "tfsec.json"),
    "kube-linter": ToolSpec("audit-iac", ("/root/go/bin/kube-linter", "lint", "--format", "json", "/workspace"),
                            "stdout.log", True),
    "hadolint": ToolSpec("tool-hadolint", ("/opt/tool/bin/hadolint", "--no-fail", "--format", "json", "/workspace/Dockerfile"),
                         "stdout.log", True),
    "oci-archive-inventory": ToolSpec("tool-syft", ("/opt/tool/bin/syft", "scan", "file:/workspace/image.tar",
                                                          "-o", "json=/scratch/oci-inventory.json"), "oci-inventory.json"),
    # Syft's archive parser provides the package inventory without a mutable vulnerability DB.
    # Run it as a separate authenticated attempt so inventory and metadata coverage stay explicit.
    "image-package-and-config-inspection": ToolSpec("tool-syft", ("/opt/tool/bin/syft", "scan",
                                                                       "file:/workspace/image.tar", "-o",
                                                                       "json=/scratch/image-inspection.json"),
                                                    "image-inspection.json"),
    "binskim": ToolSpec("audit-binary-analysis", ("/usr/bin/checksec", "--dir=/workspace", "--output=json"),
                        "stdout.log", True),
    "mobsfscan-android": ToolSpec("tool-mobsfscan", ("/opt/tool/bin/mobsfscan", "--sarif", "--output",
                                                          "/scratch/mobsfscan-android.sarif", "/workspace"),
                                      "mobsfscan-android.sarif"),
    "mobsfscan-ios": ToolSpec("tool-mobsfscan", ("/opt/tool/bin/mobsfscan", "--sarif", "--output",
                                                      "/scratch/mobsfscan-ios.sarif", "/workspace"),
                                  "mobsfscan-ios.sarif"),
}


class VendorToolBlocked(RuntimeError): pass
class VendorToolFailed(RuntimeError): pass

VERSION_ARGV={
 "gitleaks":["/opt/tool/bin/gitleaks","version"],"checkov":["/opt/tool/bin/checkov","--version"],
 "trivy-config":["/opt/tool/bin/trivy","--version"],"tfsec":["/root/go/bin/tfsec","--version"],
 "kube-linter":["/root/go/bin/kube-linter","version"],"hadolint":["/opt/tool/bin/hadolint","--version"],
 "oci-archive-inventory":["/opt/tool/bin/syft","version"],
 "image-package-and-config-inspection":["/opt/tool/bin/syft","version"],
 "binskim":["/usr/bin/checksec","--version"],"mobsfscan-android":["/opt/tool/bin/mobsfscan","--version"],
 "mobsfscan-ios":["/opt/tool/bin/mobsfscan","--version"]}


def verified_version(tool_id: str, *, runtime: ce.ContainerRuntime, run_id: str, job_id: str,
                     attempt_id: str, attempt_root: Path, base_request: dict,
                     run_container=ce.run_container, verify=ce.verify_container_result) -> str:
    attempt_root.mkdir(parents=True,exist_ok=False)
    req=json.loads(json.dumps(base_request)); req["attempt_id"]=attempt_id; req["argv"]=VERSION_ARGV[tool_id]
    terminal=run_container(runtime,run_id=run_id,job_id=job_id,attempt_id=attempt_id,attempt_root=attempt_root,request=req)
    errors=verify(attempt_root,run_id=run_id,job_id=job_id,attempt_id=attempt_id,request=req,images_dir=runtime.images_dir,
      expected_result_sha256=terminal["result_sha256"],host_flavor=runtime.host_flavor,docker_host=runtime.docker_host,
      docker_executable=runtime.docker_executable,container_user=runtime.container_user)
    if errors or terminal["execution_status"]!="OK": raise VendorToolFailed("version-probe-failed")
    text=(attempt_root/"logs/container/stdout.log").read_text(errors="replace")+(attempt_root/"logs/container/stderr.log").read_text(errors="replace")
    match=re.search(r"(?<![0-9])v?([0-9]+(?:\.[0-9]+){1,3})(?![0-9])",text)
    if not match: raise VendorToolFailed("version-unverified")
    return match.group(1)


def _path(value: Any) -> str:
    if not isinstance(value, str): raise VendorToolFailed("output-path-invalid")
    value = value.replace("\\", "/").removeprefix("file://")
    for prefix in ("/workspace/", "/inputs/", "workspace/", "inputs/"):
        if value.startswith(prefix):
            value = value.removeprefix(prefix)
            break
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
            if artifact.get("uri") in ("file:///workspace","/workspace","workspace"):
                continue  # directory-level best-practice note has no source-file citation
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
        # Checkov emits one object for a single framework and a top-level list for
        # multi-framework scans. Validate every framework independently before reducing it.
        frameworks = document if isinstance(document, list) else [document]
        if not frameworks or len(frameworks) > 64:
            raise VendorToolFailed("checkov-shape-invalid")
        for framework in frameworks:
            if not isinstance(framework, dict) or not isinstance(framework.get("results"), dict):
                raise VendorToolFailed("checkov-shape-invalid")
            failed = framework["results"].get("failed_checks")
            if not isinstance(failed, list) or len(failed) > 100_000:
                raise VendorToolFailed("checkov-shape-invalid")
            for item in failed:
                if not isinstance(item, dict):
                    raise VendorToolFailed("checkov-shape-invalid")
                span = item.get("file_line_range")
                if (not isinstance(span, list) or len(span) != 2 or
                        not all(isinstance(line, int) and not isinstance(line, bool) and line >= 1 for line in span)):
                    raise VendorToolFailed("checkov-shape-invalid")
                if not isinstance(item.get("check_id"), str) or not item["check_id"]:
                    raise VendorToolFailed("checkov-shape-invalid")
                records.append({"rule_id": item["check_id"], "path": _path(str(item.get("file_path")).lstrip("/")),
                                "start_line": span[0], "end_line": span[1]})
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
    elif tool_id.startswith("mobsfscan-"):
        records = _sarif(document)
    elif tool_id == "binskim":
        if "runs" in document: records=_sarif(document)
        else:
            mapping={"pie":"BA2001","nx":"BA2010","canary":"BA2005","fortify_source":"BA2004"}
            for path,facts in document.items():
                for field,rule in mapping.items():
                    if str(facts.get(field,"")).lower() in ("no","none","partial"):
                        records.append({"rule_id":rule,"path":_path(path),"line":1})
    elif tool_id in ("oci-archive-inventory", "image-package-and-config-inspection"):
        # Container parsers retain only package coordinates; config values and vendor prose are discarded.
        artifacts = document.get("artifacts", []) if "artifacts" in document else [
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


def container_image_facts(data: bytes, archive_path: str) -> dict[str, dict[str, Any]]:
    """Project the closed image metadata required by the V07 contract from pinned Syft JSON."""
    try: document=json.loads(data); meta=document["source"]["metadata"]
    except (ValueError, KeyError, TypeError) as exc: raise VendorToolFailed("container-metadata-invalid") from exc
    layers=[]
    for n,layer in enumerate(meta.get("layers",[])):
        digest=layer.get("digest"); size=layer.get("size")
        if not isinstance(digest,str) or not digest.startswith("sha256:") or not isinstance(size,int):
            raise VendorToolFailed("container-layer-invalid")
        layers.append({"layer_index":n,"layer_digest":digest,"layer_bytes":size})
    manifest=meta.get("manifestDigest"); config=meta.get("config",{})
    if isinstance(config,str):
        try: config=json.loads(base64.b64decode(config))["config"]
        except Exception as exc: raise VendorToolFailed("container-config-invalid") from exc
    if not layers or not isinstance(manifest,str) or not manifest.startswith("sha256:"):
        raise VendorToolFailed("container-metadata-invalid")
    if "digest" in config:
        closed={"config_digest":config.get("digest"),"architecture":config.get("architecture"),"os":config.get("os"),
                "declared_user":config.get("user"),"declared_entrypoint_executable":config.get("entrypoint"),
                "declared_entrypoint_argument_count":config.get("entrypointArgs",0),"declared_command_executable":config.get("command"),
                "declared_command_argument_count":config.get("commandArgs",0),"declared_ports":config.get("ports",[]),
                "declared_env_names":config.get("envNames",[])}
    else:
      entry=config.get("Entrypoint") or []; command=config.get("Cmd") or []
      ports=[]
      for value in (config.get("ExposedPorts") or {}):
        number,_,protocol=value.partition("/");
        if number.isdigit(): ports.append({"port":int(number),"protocol":protocol or "tcp","exposure_label":"DECLARED_EXPOSURE"})
      closed={"config_digest":meta.get("imageID"),"architecture":meta.get("architecture"),"os":meta.get("os"),
              "declared_user":config.get("User") or None,"declared_entrypoint_executable":entry[0] if entry else None,
              "declared_entrypoint_argument_count":max(0,len(entry)-1),
              "declared_command_executable":command[0] if command else None,"declared_command_argument_count":max(0,len(command)-1),
              "declared_ports":ports,"declared_env_names":sorted({v.split("=",1)[0] for v in (config.get("Env") or [])})}
    if not isinstance(closed["config_digest"],str) or not closed["config_digest"].startswith("sha256:"):
        raise VendorToolFailed("container-config-invalid")
    return {archive_path:{"manifest_digest":manifest,"layers":layers,"config":closed}}


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
            "target_mounts": [{"host_path": str(source_root.resolve()), "container_path": "/workspace"}],
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
    spec=SPECS[tool_id]
    output = attempt_root / ("logs/container" if spec.captured_stdout else "scratch") / spec.output
    if not output.is_file() or output.is_symlink(): raise VendorToolFailed("expected-output-missing")
    data = output.read_bytes()
    normalize(tool_id, data)
    return terminal, data


def collect(job_id: str, tool_ids: list[str], *, run_id: str, node_attempt_id: str, source_root: Path,
            source_sha: str, attempt_root: Path, now: str,
            runtime_factory: Callable[[str, Callable[[], str]], ce.ContainerRuntime] = _runtime,
            run_container: Callable[..., dict] = ce.run_container,
            verify: Callable[..., list[str]] = ce.verify_container_result,
            version_probe: Callable[..., str] = verified_version) -> dict[str, dict[str, Any]]:
    """Run every applicable declared tool independently; one failure cannot erase sibling evidence."""
    runtime = runtime_factory(source_sha, lambda: now)
    results = {}
    for position, tool_id in enumerate(tool_ids, 1):
        tool_attempt = f"{tool_id}-{node_attempt_id[:24]}-{position}"
        root = attempt_root / "tools" / tool_id
        try:
            req = request(tool_id, run_id=run_id, job_id=job_id, attempt_id=tool_attempt,
                          source_root=source_root, scratch_name="scratch", source_sha=source_sha, now=now)
            version=version_probe(tool_id,runtime=runtime,run_id=run_id,job_id=job_id,
                attempt_id=tool_attempt+"-version",attempt_root=attempt_root/"versions"/tool_id,
                base_request=req,run_container=run_container,verify=verify)
            root.mkdir(parents=True,exist_ok=False)
            terminal, data = execute(tool_id, runtime=runtime, run_id=run_id, job_id=job_id,
                                     attempt_id=tool_attempt, attempt_root=root, request_document=req,
                                     run_container=run_container, verify=verify)
            output_sha="sha256:"+hashlib.sha256(data).hexdigest()
            record=ce.load_image_registry(ce.IMAGES_DIR)[SPECS[tool_id].image_id]
            permission_sha="sha256:"+hashlib.sha256(json.dumps(req["permission"],sort_keys=True,separators=(",",":")).encode()).hexdigest()
            receipt={"schema":"appsec-review/vendor-b13-execution-receipt/1","tool_id":tool_id,
                     "attempt_id":tool_attempt,"request_sha256":terminal["request_sha256"],
                     "result_sha256":terminal["result_sha256"],"output_sha256":output_sha,
                     "permission_sha256":permission_sha,
                     "permission_fingerprint_sha256":terminal["permission_fingerprint_sha256"],
                     "image_id":req["image"]["image_id"],"image_digest":req["image"]["digest"],
                     "argv":req["argv"],"tool_version":version,
                     "tool_name":("checksec" if tool_id=="binskim" else "syft" if tool_id in
                                  ("oci-archive-inventory","image-package-and-config-inspection") else
                                  tool_id.replace("-android","").replace("-ios",""))}
            results[tool_id] = {"status": "OK", "attempt_id": tool_attempt, "request": req,
                                "terminal": terminal, "raw": data, "records": normalize(tool_id, data),
                                "auth":{"attempt_id":tool_attempt,"argv":req["argv"],"exit_code":terminal["exit_code"],
                                        "identity":{"repository":record["repository"],"digest":record["digest"],
                                                    "tool_version":version,"tool_name":receipt["tool_name"]},
                                        "receipt":receipt}}
        except VendorToolBlocked as exc:
            results[tool_id] = {"status": "BLOCKED", "cause": str(exc)}
        except VendorToolFailed as exc:
            results[tool_id] = {"status": "FAILED", "cause": str(exc)}
    return results
