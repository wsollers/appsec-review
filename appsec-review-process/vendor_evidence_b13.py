#!/usr/bin/env python3
"""B13 execution seam for M03/M04 vendor evidence tools.

All argv are repository-owned constants, all executions are offline, and a successful adapter
result is re-verified using the caller-retained result digest before any scanner output is read.
"""
from __future__ import annotations

import tunables
from dataclasses import dataclass
import json
import os
from pathlib import Path
import threading
import hashlib
import re
import base64
from typing import Any, Callable

import container_execution as ce
import container_mobile_binary_contracts as cmb
import iac_files
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
    # JSON on stdout: with --output-file-path the pinned checkov printed its results to stdout and left
    # no results_json.json (run 20261001T032047Z-fd64eb: 646 KB of results discarded, tool BLOCKED).
    "checkov": ToolSpec("tool-checkov", ("/opt/tool/bin/checkov", "-d", "/workspace", "-o", "json",
                                           "--skip-download", "--soft-fail"), "stdout.log", True),
    "trivy-config": ToolSpec("tool-trivy", ("/opt/tool/bin/trivy", "config", "--skip-check-update", "--skip-version-check", "--format", "json",
                                                 "--output", "/scratch/trivy-config.json", "/workspace"), "trivy-config.json"),
    "tfsec": ToolSpec("audit-iac", ("/usr/local/bin/tfsec", "--soft-fail", "--format", "json", "--out", "/scratch/tfsec.json",
                                      "/workspace"), "tfsec.json"),
    "kube-linter": ToolSpec("audit-iac", ("/usr/local/bin/kube-linter", "lint", "--format", "json", "/workspace"),
                            "stdout.log", True),
    # The trailing path is replaced by every Dockerfile in the checkout (``_dockerfiles``); a fixed
    # /workspace/Dockerfile failed on repositories without a root Dockerfile (run 20261001T032047Z-fd64eb).
    "hadolint": ToolSpec("tool-hadolint", ("/opt/tool/bin/hadolint", "--no-fail", "--format", "json", "/workspace/Dockerfile"),
                         "stdout.log", True),
    # GitHub Actions workflows and composite actions (D-34): offline audits only, SARIF on stdout, findings
    # never change the exit code (exit non-zero means the tool failed).
    "zizmor": ToolSpec("tool-zizmor", ("/opt/tool/bin/zizmor", "--offline", "--no-exit-codes", "--format", "sarif",
                                       "/workspace"), "stdout.log", True),
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
    # blint writes one <name>-metadata.json per binary into the output directory (plus findings.json and
    # an HTML page, neither read). /workspace is the binary_id view (``blint_view``): blint names its
    # reports by basename, so two `a.out` files would overwrite each other (blint 3.4.0, reproduced).
    "blint": ToolSpec("tool-blint", ("/opt/tool/bin/blint", "--no-banner", "-q", "--no-error", "--no-reviews",
                                     "--no-wasm-strings", "-i", "/workspace", "-o", "/scratch/blint"), "blint"),
    "mobsfscan-android": ToolSpec("tool-mobsfscan", ("/opt/tool/bin/mobsfscan", "--sarif", "--output",
                                                          "/scratch/mobsfscan-android.sarif", "/workspace"),
                                      "mobsfscan-android.sarif"),
    "mobsfscan-ios": ToolSpec("tool-mobsfscan", ("/opt/tool/bin/mobsfscan", "--sarif", "--output",
                                                      "/scratch/mobsfscan-ios.sarif", "/workspace"),
                                  "mobsfscan-ios.sarif"),
}


class VendorToolBlocked(RuntimeError): pass
class VendorToolFailed(RuntimeError):
    def __init__(self, cause: str, exit_code: int | None = None) -> None:
        super().__init__(cause)
        self.exit_code = exit_code   # the container's exit code when it ran; None when it never started

VERSION_ARGV={
 "gitleaks":["/opt/tool/bin/gitleaks","version"],"checkov":["/opt/tool/bin/checkov","--version"],
 "trivy-config":["/opt/tool/bin/trivy","--version"],"tfsec":["/usr/local/bin/tfsec","--version"],
 "kube-linter":["/usr/local/bin/kube-linter","version"],"hadolint":["/opt/tool/bin/hadolint","--version"],
 "zizmor":["/opt/tool/bin/zizmor","--version"],
 "oci-archive-inventory":["/opt/tool/bin/syft","version"],
 "image-package-and-config-inspection":["/opt/tool/bin/syft","version"],
 "binskim":["/usr/bin/checksec","--version"],"mobsfscan-android":["/opt/tool/bin/mobsfscan","--version"],
 "blint":["/opt/tool/bin/python","-c","import importlib.metadata as m; print('blint', m.version('blint'))"],
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
                        not all(isinstance(line, int) and not isinstance(line, bool) and line >= 0 for line in span)):
                    raise VendorToolFailed("checkov-shape-invalid")
                # File-level checks (e.g. CKV2_GHA_1 on a workflow) report [0, n]: cite line 1.
                span = [max(1, span[0]), max(1, span[1])]
                if not isinstance(item.get("check_id"), str) or not item["check_id"]:
                    raise VendorToolFailed("checkov-shape-invalid")
                records.append({"rule_id": item["check_id"], "path": _path(str(item.get("file_path")).lstrip("/")),
                                "start_line": span[0], "end_line": span[1],
                                "framework": str(framework.get("check_type") or "")})
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
    elif tool_id == "zizmor":
        for run in document.get("runs", []) if isinstance(document, dict) else []:
            for result in run.get("results", []):
                locations = result.get("locations") or []
                physical = locations[0].get("physicalLocation", {}) if locations else {}
                region = physical.get("region", {})
                start = region.get("startLine", 1)
                rule = result.get("ruleId")
                if isinstance(rule, str):
                    rule = rule.removeprefix("zizmor/")   # the pack is zizmor; ids are its audit names
                records.append({"rule_id": rule,
                                "path": _path(physical.get("artifactLocation", {}).get("uri")),
                                "start_line": start, "end_line": max(start, region.get("endLine", start))})
    elif tool_id.startswith("mobsfscan-"):
        records = _sarif(document)
    elif tool_id == "binskim":
        if "runs" in document: records=_sarif(document)
        else:
            # relro: checksec "partial" lacks BIND_NOW, so full RELRO is absent (run 20261001T032047Z-fd64eb
            # normalized "partial" to present). No BinSkim rule exists for it; the id names checksec.
            mapping={"pie":"BA2001","nx":"BA2010","canary":"BA2005","fortify_source":"BA2004",
                     "relro":"CHECKSEC-FULL-RELRO"}
            for path,facts in document.items():
                for field,rule in mapping.items():
                    if str(facts.get(field,"")).lower() in ("no","none","partial"):
                        records.append({"rule_id":rule,"path":_path(path),"line":1})
    elif tool_id == "blint":
        if not isinstance(document, dict) or document.get("schema") != BLINT_PROJECTION:
            raise VendorToolFailed("blint-shape-invalid")
        for item in document.get("binaries", []):
            for observation in item.get("observations", []):
                records.append({"path": _path(item.get("path")), "check": observation.get("check"),
                                "reported": observation.get("reported")})
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


BLINT_PROJECTION = "blint-security-properties-1"
BLINT_REPORT_MAX_BYTES = 256 * 1024 * 1024
# IMAGE_DLLCHARACTERISTICS bits. blint 3.4.0 prints the field through LIEF 1.0, which renders every
# flag as UNKNOWN(<value>), so blint's own `"DYNAMIC_BASE" in ...` test (its `aslr`) is always false.
_DLL_FLAGS = {"HIGH_ENTROPY_VA": 0x20, "DYNAMIC_BASE": 0x40, "FORCE_INTEGRITY": 0x80, "NX_COMPAT": 0x100,
              "NO_ISOLATION": 0x200, "NO_SEH": 0x400, "NO_BIND": 0x800, "APPCONTAINER": 0x1000,
              "WDM_DRIVER": 0x2000, "GUARD_CF": 0x4000, "TERMINAL_SERVER_AWARE": 0x8000}


def blint_view(source_root: Path, paths: list[str], destination: Path) -> dict[str, str]:
    """Copy each candidate binary to ``destination/<binary_id>``; blint names a report after the
    input's basename, so this is what keeps two `a.out` files from overwriting each other."""
    destination.mkdir(parents=True, exist_ok=False)
    view = {}
    for path in paths:
        identifier = cmb.binary_id(path)
        if identifier in view:
            raise VendorToolBlocked("binary-id-collision")
        (destination / identifier).write_bytes((Path(source_root) / path).read_bytes())
        view[identifier] = path
    return view


def _dll_characteristics(value: Any) -> int | None:
    """The flag bits of blint's `dll_characteristics` text, or None when any item is not a known
    name or `UNKNOWN(<n>)`: an unreadable field is no observation, never `absent`."""
    if not isinstance(value, str):
        return None
    bits = 0
    for item in (part.strip() for part in value.split(",")):
        if not item:
            continue
        match = re.fullmatch(r"UNKNOWN\(([0-9]{1,5})\)", item)
        name = item.rsplit(".", 1)[-1]
        if match:
            bits |= int(match.group(1))
        elif name in _DLL_FLAGS:
            bits |= _DLL_FLAGS[name]
        else:
            return None
    return bits


def blint_observations(fmt: str, metadata: Any) -> list[dict[str, str]]:
    """Closed per-check verdicts from one blint report's `security_properties`, for the format the
    worker derived from the file's own bytes. Only fields reproduced against real binaries are read:
    never `relro` (wrong when GNU_RELRO is missing), never `aslr` (always false under LIEF 1.0),
    never findings.json (CHECK_CANARY never fires)."""
    props = metadata.get("security_properties") if isinstance(metadata, dict) else None
    if not isinstance(props, dict):
        raise VendorToolFailed("blint-shape-invalid")
    def flag(key: str) -> bool:
        value = props.get(key)
        if not isinstance(value, bool):
            raise VendorToolFailed("blint-shape-invalid")
        return value
    observed: dict[str, bool] = {"non_executable_data": flag("nx")}
    pie, canary = flag("pie"), flag("canary")
    if fmt == "elf":
        observed.update(position_independent=pie, stack_protector=canary)
    elif fmt == "macho":
        observed["stack_protector"] = canary
        if metadata.get("file_type") == "EXECUTE":   # MH_PIE exists only for executables
            observed["position_independent"] = pie
    elif fmt == "pe":
        observed["position_independent"] = pie       # LIEF is_pie = DYNAMIC_BASE (reproduced)
        config = metadata.get("load_configuration")
        if isinstance(config, dict) and config:
            observed["stack_protector"] = canary
            observed["control_flow_guard"] = props.get("control_flow_guard") is True
            if metadata.get("exe_type") == "PE32":
                observed["safe_seh"] = props.get("safe_seh") is True
        bits = _dll_characteristics(metadata.get("dll_characteristics"))
        if metadata.get("exe_type") == "PE64" and bits is not None:
            observed["high_entropy_aslr"] = bool(bits & _DLL_FLAGS["HIGH_ENTROPY_VA"])
    else:
        return []
    return [{"check": name, "reported": "present" if value else "absent"} for name, value in sorted(observed.items())]


def blint_projection(report_dir: Path, view: dict[str, str], view_root: Path) -> bytes:
    """The closed document published for blint: one entry per binary it reported on, and the binaries
    it silently skipped (it exits 0 for a file LIEF cannot parse). The raw reports carry every string
    and symbol of the binary and are never published."""
    reported, missing = [], []
    expected = {f"{identifier}-metadata.json" for identifier in view}
    for name in sorted(p.name for p in report_dir.glob("*-metadata.json")):
        if name not in expected:
            raise VendorToolFailed("blint-unexpected-report")
    for identifier, path in sorted(view.items()):
        report = report_dir / f"{identifier}-metadata.json"
        if not report.is_file() or report.is_symlink():
            missing.append({"binary_id": identifier, "path": path})
            continue
        if report.stat().st_size > BLINT_REPORT_MAX_BYTES:
            raise VendorToolFailed("blint-report-too-large")
        try:
            metadata = json.loads(report.read_bytes())
        except (UnicodeDecodeError, ValueError) as exc:
            raise VendorToolFailed("blint-report-invalid") from exc
        fmt = cmb.detect_format((view_root / identifier).read_bytes()[:8])
        reported.append({"binary_id": identifier, "path": path, "format": fmt,
                         "observations": blint_observations(fmt, metadata)})
    return (json.dumps({"schema": BLINT_PROJECTION, "binaries": reported, "not_reported": missing},
                       sort_keys=True, indent=2) + "\n").encode()


# checksec 2.6.0 JSON values (recorded: tests/fixtures/binary-hardening-real/checksec-2.6.0.json) -> verdict.
# relro "partial" lacks BIND_NOW, so full RELRO is absent (D-33). Any other value is no observation.
_CHECKSEC_VERDICTS = {
    "position_independent": ("pie", {"yes": "present", "dso": "present", "no": "absent"}),
    "non_executable_data": ("nx", {"yes": "present", "no": "absent"}),
    "stack_protector": ("canary", {"yes": "present", "no": "absent"}),
    "relro": ("relro", {"full": "present", "partial": "absent", "no": "absent"}),
    "fortify_source": ("fortify_source", {"yes": "present", "no": "absent"}),
}


def checksec_observations(data: bytes) -> dict[str, list[dict[str, str]]]:
    """Per-path closed verdicts from checksec's `--output=json`; checksec inspects ELF files only."""
    document = json.loads(data)
    if not isinstance(document, dict) or "runs" in document:
        return {}
    result = {}
    for path, facts in document.items():
        if path == "dir" or not isinstance(facts, dict) or "relro" not in facts:
            continue
        observed = []
        for check, (field, verdicts) in sorted(_CHECKSEC_VERDICTS.items()):
            verdict = verdicts.get(str(facts.get(field, "")).strip().lower())
            if verdict:
                observed.append({"check": check, "reported": verdict})
        result[_path(path)] = observed
    return result


def checksec_reported(data: bytes) -> set[str]:
    """Paths checksec printed a record for (its JSON also carries a top-level `dir` entry)."""
    document = json.loads(data)
    return {_path(path) for path, facts in document.items()
            if path != "dir" and isinstance(facts, dict) and "relro" in facts}


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


MAX_HADOLINT_FILES = 500
_SKIP_DIRS = {".git", "node_modules"}


def _dockerfiles(source_root: Path) -> list[str]:
    """Checkout-relative Dockerfiles and Containerfiles (``iac_files.containerfile``), sorted."""
    root = Path(source_root)
    found = []
    for current, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in names:
            if iac_files.containerfile(name):
                path = Path(current, name)
                if path.is_file() and not path.is_symlink():
                    found.append(path.relative_to(root).as_posix())
    return sorted(found)[:MAX_HADOLINT_FILES]


def argv_for(tool_id: str, source_root: Path) -> list[str]:
    argv = list(SPECS[tool_id].argv)
    if tool_id == "hadolint":
        files = _dockerfiles(source_root)
        if not files:
            raise VendorToolBlocked("required-input-missing")
        argv = argv[:-1] + ["/workspace/" + path for path in files]
    return argv


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
            "image": {"image_id": image["image_id"], "digest": image["digest"]}, "argv": argv_for(tool_id, source_root),
            "environment": [{"name": "LANG", "value": "C"}, {"name": "LC_ALL", "value": "C"},
                            {"name": "NO_COLOR", "value": "1"}],
            "target_mounts": [{"host_path": str(source_root.resolve()), "container_path": "/workspace"}],
            "scratch_path": scratch_name, "log_path": "logs/container", "network": {"mode": "none", "destinations": []},
            "permission": {"requirement": requirement, "grants": [], "decision": decision},
            "limits": tunables.container_limits(job_id)}


def execute(tool_id: str, *, runtime: ce.ContainerRuntime, run_id: str, job_id: str, attempt_id: str,
            attempt_root: Path, request_document: dict[str, Any],
            run_container: Callable[..., dict] = ce.run_container,
            verify: Callable[..., list[str]] = ce.verify_container_result,
            view: dict[str, str] | None = None, view_root: Path | None = None) -> tuple[dict, bytes]:
    """Execute, re-verify, then return (terminal, output bytes). For blint the bytes are the closed
    projection of its report directory (``blint_projection``), built from the verified scratch."""
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
    if terminal["execution_status"] != "OK":
        raise VendorToolFailed(terminal.get("cause") or "tool-failed", terminal.get("exit_code"))
    spec=SPECS[tool_id]
    output = attempt_root / ("logs/container" if spec.captured_stdout else "scratch") / spec.output
    if tool_id == "blint":
        if view is None or view_root is None or not output.is_dir() or output.is_symlink():
            raise VendorToolFailed("expected-output-missing", terminal.get("exit_code"))
        try:
            data = blint_projection(output, view, view_root)
        except VendorToolFailed as exc:
            raise VendorToolFailed(str(exc), terminal.get("exit_code")) from None
        return terminal, data
    if not output.is_file() or output.is_symlink():
        raise VendorToolFailed("expected-output-missing", terminal.get("exit_code"))
    data = output.read_bytes()
    try:
        normalize(tool_id, data)
    except VendorToolFailed as exc:
        raise VendorToolFailed(str(exc), terminal.get("exit_code")) from None
    return terminal, data


def collect(job_id: str, tool_ids: list[str], *, run_id: str, node_attempt_id: str, source_root: Path,
            source_sha: str, attempt_root: Path, now: str,
            runtime_factory: Callable[[str, Callable[[], str]], ce.ContainerRuntime] = _runtime,
            run_container: Callable[..., dict] = ce.run_container,
            verify: Callable[..., list[str]] = ce.verify_container_result,
            version_probe: Callable[..., str] = verified_version,
            candidates: dict[str, list[str]] | None = None) -> dict[str, dict[str, Any]]:
    """Run every applicable declared tool independently; one failure cannot erase sibling evidence.
    ``candidates`` (tool -> paths) is required for blint, which scans a binary_id view of them."""
    runtime = runtime_factory(source_sha, lambda: now)
    results = {}
    for position, tool_id in enumerate(tool_ids, 1):
        tool_attempt = f"{tool_id}-{node_attempt_id[:24]}-{position}"
        root = attempt_root / "tools" / tool_id
        try:
            mount_root, view = source_root, None
            if tool_id == "blint":
                if not candidates or not candidates.get("blint"):
                    raise VendorToolBlocked("required-input-missing")
                mount_root = (attempt_root / "inputs" / "blint").absolute()
                view = blint_view(source_root, candidates["blint"], mount_root)
            req = request(tool_id, run_id=run_id, job_id=job_id, attempt_id=tool_attempt,
                          source_root=mount_root, scratch_name="scratch", source_sha=source_sha, now=now)
            version=version_probe(tool_id,runtime=runtime,run_id=run_id,job_id=job_id,
                attempt_id=tool_attempt+"-version",attempt_root=attempt_root/"versions"/tool_id,
                base_request=req,run_container=run_container,verify=verify)
            root.mkdir(parents=True,exist_ok=False)
            terminal, data = execute(tool_id, runtime=runtime, run_id=run_id, job_id=job_id,
                                     attempt_id=tool_attempt, attempt_root=root, request_document=req,
                                     run_container=run_container, verify=verify,
                                     view=view, view_root=mount_root if view is not None else None)
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
            if tool_id == "binskim":
                extra = {"reported": sorted(checksec_reported(data))}
            elif tool_id == "blint":
                extra = {"not_reported": sorted(item["path"] for item in json.loads(data)["not_reported"])}
            else:
                extra = {}
            results[tool_id] = {"status": "OK", "attempt_id": tool_attempt, "request": req, **extra,
                                "terminal": terminal, "raw": data, "records": normalize(tool_id, data),
                                "auth":{"attempt_id":tool_attempt,"argv":req["argv"],"exit_code":terminal["exit_code"],
                                        "identity":{"repository":record["repository"],"digest":record["digest"],
                                                    "tool_version":version,"tool_name":receipt["tool_name"]},
                                        "receipt":receipt}}
        except VendorToolBlocked as exc:
            results[tool_id] = {"status": "BLOCKED", "cause": str(exc)}
        except VendorToolFailed as exc:
            results[tool_id] = {"status": "FAILED", "cause": str(exc), "exit_code": exc.exit_code}
    return results
