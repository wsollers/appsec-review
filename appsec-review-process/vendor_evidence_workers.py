#!/usr/bin/env python3
"""Nominal, fail-closed workers for the ADR-0010 M03/M04 evidence families.

The module owns deterministic applicability and the parts which do not need a vendor executable.
Vendor tools are never simulated: an unavailable B13 image becomes a BLOCKED tool instance and a
named coverage gap.  The resulting documents use the already-accepted V03/V04/V07 contracts and
can be published through the repository redaction boundary by :func:`materialize_attempt`.

This is deliberately an evidence-lead boundary.  It cannot emit findings, severity, compliance or
runtime observations.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable

import container_mobile_binary_contracts as cmb
import evidence_redaction
import permission_capabilities as permissions
import secrets_iac_contracts as sic
import tool_instance_shapes as shapes
import registry_paths

SKIP = shapes.SKIP_REASON
HASH = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()
REDACTOR = {"name": evidence_redaction.REDACTOR_NAME,
            "module_version": evidence_redaction.MODULE_VERSION,
            "ruleset_sha256": evidence_redaction.RULESET_SHA256}

SPECS = {
    "02-secrets-inventory": ("secrets-inventory", ["gitleaks", "key-material-file-inventory"]),
    "02-iac-config-scan": ("iac-config-evidence", ["checkov", "trivy-config", "tfsec", "kube-linter",
                                                      "hadolint", "dockerfile-base-image-inventory"]),
    "02-container-image-inventory": ("container-image-inventory", ["oci-archive-inventory",
                                                                      "image-package-and-config-inspection"]),
    "02-binary-hardening": ("binary-hardening", ["binskim"]),
    "02-mobile-sast": ("mobile-sast", ["mobsfscan-android", "mobsfscan-ios"]),
}
REGISTRY = registry_paths.JOB_TEMPLATES_DIR
PERMISSION_SCHEMA = "appsec-review/producer-permission-receipt/1.0"
LINEAGE_SCHEMA = "appsec-review/producer-lineage-receipt/1.0"
IMPLEMENTATION = "vendor-evidence-workers-v2-producer-receipts"

PROBE_PATTERNS = {
    "gitleaks": ["**/*"], "key-material-file-inventory": ["**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx"],
    "checkov": ["**/*.tf", "**/*.yaml", "**/*.yml"], "trivy-config": ["**/*.tf", "**/*.yaml", "**/*.yml"],
    "tfsec": ["**/*.tf"], "kube-linter": ["**/*.yaml", "**/*.yml"], "hadolint": ["**/Dockerfile*"],
    "dockerfile-base-image-inventory": ["**/Dockerfile*"],
    "oci-archive-inventory": ["**/*.tar", "**/*.oci.tar"],
    "image-package-and-config-inspection": ["**/*.tar", "**/*.oci.tar"],
    "binskim": ["**/*.exe", "**/*.dll", "**/*.so", "**/*.dylib"],
    "mobsfscan-android": ["**/AndroidManifest.xml", "**/build.gradle*"],
    "mobsfscan-ios": ["**/Info.plist", "**/*.xcodeproj/*"],
}

KEY_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}


def _dump(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def _files(root: Path) -> list[tuple[str, Path]]:
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise ValueError("source_root must be an absolute, real directory")
    values = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            relative = path.relative_to(root).as_posix()
            if all(part not in ("", ".", "..") for part in relative.split("/")):
                values.append((relative, path))
    return values


def _dockerfile(path: str) -> bool:
    return Path(path).name == "Dockerfile" or Path(path).name.startswith("Dockerfile.")


_CHECKOV_KINDS = {"dockerfile": "dockerfile", "terraform": "terraform", "kubernetes": "kubernetes",
                  "helm": "helm", "cloudformation": "cloudformation"}


def _iac_kind(tool: str, record: dict) -> str | None:
    """The contract's iac_kind for one hit, or None when the file is not IaC this node publishes. Run
    20261001T032047Z-fd64eb (relaunch): checkov's github_actions hits on .github/workflows/*.yml were
    published as kubernetes with a Dockerfile-only address disposition and failed validation."""
    path = record["path"]
    if _dockerfile(path):
        return "dockerfile"
    if path.endswith(".tf"):
        return "terraform"
    if tool == "checkov":
        return _CHECKOV_KINDS.get(record.get("framework", ""))
    return "kubernetes" if tool == "kube-linter" else None


def _iac(path: str) -> bool:
    return path.endswith((".tf", ".yaml", ".yml")) or _dockerfile(path)


def _android(path: str) -> bool:
    return Path(path).name == "AndroidManifest.xml" or Path(path).name.startswith("build.gradle")


def _ios(path: str) -> bool:
    return Path(path).name == "Info.plist" or ".xcodeproj/" in path


def _binary(path: Path) -> bool:
    try:
        return cmb.detect_format(path.read_bytes()[:8]) != "unsupported"
    except OSError:
        return False


def probe(job_id: str, source_root: Path) -> dict[str, Any]:
    """Deterministically enumerate candidate inputs.  Bare Java/Kotlin/Swift files are not mobile markers."""
    if job_id not in SPECS:
        raise ValueError(f"unknown vendor evidence job {job_id!r}")
    files = _files(source_root)
    paths = [name for name, _ in files]
    if job_id == "02-secrets-inventory":
        candidates = {"gitleaks": paths,
                      "key-material-file-inventory": [n for n, _ in files if Path(n).suffix.lower() in KEY_SUFFIXES]}
    elif job_id == "02-iac-config-scan":
        tf = [n for n in paths if n.endswith(".tf")]
        yaml = [n for n in paths if n.endswith((".yaml", ".yml"))]
        docker = [n for n in paths if _dockerfile(n)]
        candidates = {"checkov": tf + yaml + docker, "trivy-config": tf + yaml + docker, "tfsec": tf,
                      "kube-linter": yaml, "hadolint": docker, "dockerfile-base-image-inventory": docker}
    elif job_id == "02-container-image-inventory":
        archives = [n for n in paths if n.endswith((".tar", ".oci.tar"))]
        candidates = {tool: archives for tool in SPECS[job_id][1]}
    elif job_id == "02-binary-hardening":
        binaries = [n for n, p in files if _binary(p)]
        candidates = {"binskim": binaries}
    else:
        android_markers=[n for n in paths if _android(n)]; ios_markers=[n for n in paths if _ios(n)]
        candidates = {"mobsfscan-android": ([n for n in paths if n.endswith((".java",".kt",".xml"))] if android_markers else []),
                      "mobsfscan-ios": ([n for n in paths if n.endswith((".swift",".m",".mm",".plist"))] if ios_markers else [])}
    return {"files_examined": len(files), "candidates": {k: sorted(set(v)) for k, v in candidates.items()}}


def fingerprint(job_id: str, source_root: Path, source_snapshot_sha256: str) -> str:
    listing = [(name, HASH(path.read_bytes())) for name, path in _files(source_root)]
    return HASH(_dump({"implementation": IMPLEMENTATION, "job_id": job_id,
                       "source_snapshot_sha256": source_snapshot_sha256, "files": listing}))


def producer_receipts(documents: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return common producer receipts derived from tracked permissions and attempt evidence."""
    header = documents["header"]
    job_id = header["job_id"]
    try:
        template = json.loads((REGISTRY / f"{job_id}.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise ValueError(f"{job_id}: registry job template is unreadable") from None
    permissions = template.get("permissions")
    if (template.get("job_template_id") != job_id or not isinstance(permissions, list) or not all(
            isinstance(item, str) and item for item in permissions) or
            len(set(permissions)) != len(permissions)):
        raise ValueError(f"{job_id}: registry template permissions are invalid")
    source = header["source_snapshot_sha256"]
    lineage_material = {
        "header": header,
        "contract_id": documents["contract_id"],
        "probe": documents["probe"],
        "tool_results": documents["tool-results.json"],
    }
    return (
        {"schema": PERMISSION_SCHEMA, "run_id": header["run_id"], "job_id": job_id,
         "source_snapshot_sha256": source, "permissions": permissions},
        {"schema": LINEAGE_SCHEMA, "run_id": header["run_id"], "job_id": job_id,
         "source_snapshot_sha256": source,
         "build_lineage_sha256": HASH(_dump(lineage_material))},
    )


def permission_receipt(job_id: str, run_id: str, source_snapshot_sha256: str, *, now: str) -> dict[str, Any]:
    """Canonical default-deny evaluation for these offline static workers (zero capabilities)."""
    if job_id not in SPECS:
        raise ValueError(f"unknown vendor evidence job {job_id!r}")
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": job_id,
                   "capabilities": []}
    context = {"run_id": run_id, "job_id": job_id, "source_snapshot_sha256": source_snapshot_sha256,
               "now": now, "registry_ceiling": []}
    decision = permissions.evaluate(requirement, [], context)
    permissions.require_granted(decision, requirement=requirement, grants=[], context=context)
    return {"requirement": requirement, "grants": [], "decision": decision,
            "fingerprint_sha256": permissions.input_fingerprint_component(decision)}


def _header(job_id: str, run_id: str, attempt_id: str, source_sha: str) -> dict[str, str]:
    return {"run_id": run_id, "job_id": job_id, "attempt_id": attempt_id,
            "source_snapshot_sha256": source_sha}


def _instance(tool: str, status: str, *, executor: str, records: int | None = None,
              output: dict | None = None, failure_exit: int | None = None) -> dict:
    """``failure_exit``: a FAILED tool's container exit code. Non-zero is a tool error; 0 means the tool
    ended cleanly but its output was unusable (``output-invalid``)."""
    started = status not in ("SKIPPED", "BLOCKED")
    cause = {"OK": None, "OK_WITH_GAPS": "partial-input-coverage", "SKIPPED": None,
             "BLOCKED": "image-unavailable", "FAILED": "tool-error"}[status]
    meaning = {"OK": "findings-present" if records else "clean", "OK_WITH_GAPS": "clean",
               "SKIPPED": "not-started", "BLOCKED": "not-started", "FAILED": "tool-error"}[status]
    if status == "FAILED" and failure_exit == 0:
        cause, meaning = "output-invalid", "clean"
    outputs = []
    if output:
        outputs = [{"path": output["path"], "sha256": HASH(output["data"]), "bytes": len(output["data"]),
                    "media_type": "application/json", "role": output.get("role", "normalized-result"),
                    "validation": output.get("validation", "schema-validated"),
                    "validated_against": output["schema"]}]
    container = executor == "pinned_container"
    auth=(output or {}).get("auth") if container and status == "OK" else None
    identity=(auth or {}).get("identity",{})
    return {"tool_id": tool, "attempt_id": auth["attempt_id"] if auth else f"{tool}-attempt-0001", "terminal_status": status,
            "skip_reason": SKIP if status == "SKIPPED" else None, "cause_code": cause,
            "identity": {"executor_kind": executor,
                         "image_repository": identity.get("repository") if auth else ("registry.invalid/unavailable" if container else None),
                         "image_digest": identity.get("digest") if auth else (HASH(tool.encode()) if container else None),
                         "executable_sha256": None if container else HASH(("module:" + tool).encode()),
                         "tool_name": identity.get("tool_name",tool), "tool_version": identity.get("tool_version") if auth else ("1.0.0" if started else None),
                         # The scanner rules ship in the authenticated image. Bind the policy
                         # identity to that exact image rather than inventing a ruleset hash.
                         "data_identities": ([{"kind": "policy-bundle", "identity_id": f"{tool}-image-rules",
                                                "version": identity["tool_version"], "sha256": identity["digest"]}]
                                               if auth else []),
                         "redactor": ({"redactor_id": "evidence-redaction",
                                       "redactor_version": evidence_redaction.MODULE_VERSION,
                                       "ruleset_sha256": "sha256:" + evidence_redaction.RULESET_SHA256}
                                      if output else None)},
            "argv": auth["argv"] if auth else [tool, "--offline", "/inputs"],
            "exit": {"exit_code": auth["exit_code"] if auth else (failure_exit if status == "FAILED"
                                                                    else 0 if started else None),
                     "exit_meaning": meaning, "timed_out": False,
                     "nonzero_exit_on_findings": False, "findings_exit_codes": []},
            "outputs": outputs, "result_record_count": records if output else None,
            "execution_receipt": auth["execution_receipt"] if auth else None}


def _cause_slug(cause: Any) -> str:
    return re.sub(r"[^0-9a-z]+", "-", str(cause or "").lower()).strip("-")[:40] or "unknown"


def _aggregate(header: dict, tools: list[str], candidates: dict[str, list[str]],
               successful: dict[str, dict], *, can_skip: bool,
               failures: dict[str, tuple[str, Any]] | None = None) -> tuple[str, dict, dict, dict | None, dict]:
    """``failures`` maps a tool the collector ran (or tried to) to its (FAILED|BLOCKED, cause). Before,
    every tool without a result was reported BLOCKED / image-unavailable, which hid that checkov had run
    (output path), hadolint had failed (wrong input) and kube-linter could not start (permissions):
    run 20261001T032047Z-fd64eb."""
    failures = failures or {}
    instances, coverage_tools, gaps, probe_tools, raw = [], [], [], [], {}
    any_candidates = any(candidates[t] for t in tools)
    for tool in tools:
        paths = candidates[tool]
        if not paths and can_skip:
            status = "SKIPPED"
        elif tool in successful:
            status = "OK"
        elif tool in failures and failures[tool][0] == "FAILED" and isinstance(failures[tool][2], int):
            status = "FAILED"   # it ran and exited: its exit code is on the instance
        elif tool in failures:
            status = "BLOCKED"  # it never produced an exit code (could not start, version probe, request)
        else:
            status = "BLOCKED"
        output = None
        if status == "OK":
            output = successful[tool]
            raw[output["path"]] = output["data"]
        instances.append(_instance(tool, status,
                                   executor="deterministic_python" if tool in {"key-material-file-inventory",
                                                                              "dockerfile-base-image-inventory"}
                                   else "pinned_container",
                                   records=successful[tool]["count"] if tool in successful else None, output=output,
                                   failure_exit=failures[tool][2] if status == "FAILED" else None))
        unanalyzed = [] if status in ("OK", "SKIPPED") else [
            {"path": p, "reason_code": "tool-instance-did-not-complete"} for p in paths]
        coverage_tools.append({"tool_id": tool, "applicability": "applicable" if paths or status != "SKIPPED" else SKIP,
                               "candidate_input_count": len(paths), "analyzed_input_count": len(paths) if status == "OK" else 0,
                               "not_analyzed_input_count": len(unanalyzed), "unsupported_input_count": 0,
                               "not_analyzed_inputs": unanalyzed, "unsupported_inputs": [], "input_lists_truncated": False})
        if status in ("BLOCKED", "FAILED"):
            cause = failures.get(tool, (status, None, None))[1]
            suffix = "-" + _cause_slug(cause) if cause else ""
            gaps += [{"gap_id": f"gap-{tool}-{status.lower()}{suffix}"[:96], "kind": shapes.INSTANCE_GAP_KIND[status],
                      "tool_id": tool, "affected_input_count": None},
                     {"gap_id": f"gap-{tool}-inputs", "kind": "inputs-not-analyzed", "tool_id": tool,
                      "affected_input_count": len(paths)}]
        elif status == "OK" and not paths:
            gaps.append({"gap_id": f"gap-{tool}-zero", "kind": "zero-analyzed-inputs", "tool_id": tool,
                         "affected_input_count": None})
        probe_tools.append({"tool_id": tool,
                            "detectors": [{"detector_id": f"{tool}-probe", "patterns_searched": PROBE_PATTERNS[tool],
                                           "matching_input_count": len(paths)}],
                            "matching_input_count": len(paths), "applicable": bool(paths)})
    tool_results = {"schema": "appsec-review/tool-results/1.0", **header, "tool_instances": instances}
    coverage = {"schema": "appsec-review/scan-coverage/1.0", **header, "tools": coverage_tools, "gaps": gaps}
    probe_doc = None
    if can_skip:
        probe_doc = {"schema": "appsec-review/applicability-probe-receipt/1.0", **header,
                     "probe": {"probe_id": f"{header['job_id']}-probe", "probe_version": "1.0.0",
                               "probe_sha256": HASH(header["job_id"].encode())},
                     "files_examined_count": max(1, sum(len(v) for v in candidates.values())), "tools": probe_tools,
                     "node_applicable": any_candidates, "skip_reason": None if any_candidates else SKIP}
    status = shapes.supportable_success_status(tool_results, coverage)
    if status is None:
        status = "BLOCKED"
    return status, tool_results, coverage, probe_doc, raw


def _scan_keys(root: Path, paths: list[str]) -> list[dict]:
    entries = []
    for path in paths:
        data = (root / path).read_bytes()[:8192]
        pem = b"-----BEGIN " in data and b"PRIVATE KEY-----" in data
        assertion = "private-key-header-present" if pem else "credential-store-file-present"
        entries.append({"assertion": assertion, "tool_id": "key-material-file-inventory",
                        "rule_id": "pem-private-key-header" if pem else "key-store-extension",
                        "data_class": "private-key" if pem else "key-store-file", "confidence": "high",
                        "location": {"path": path, "path_disposition": "published",
                                     "start_line": 1 if pem else None, "end_line": 1 if pem else None}})
    return entries


def _scan_base_images(root: Path, paths: list[str]) -> list[dict]:
    values = []
    for path in paths:
        for line_no, line in enumerate((root / path).read_text(errors="replace").splitlines(), 1):
            match = re.match(r"\s*FROM\s+([^\s]+)", line, re.I)
            if not match:
                continue
            token = match.group(1)
            form, repository, tag, digest = "literal", token, None, None
            if token.lower() == "scratch": form, repository = "scratch", None
            elif "$" in token: form, repository = "build-arg-parameterized", None
            elif "@sha256:" in token: repository, digest = token.split("@", 1)
            elif ":" in token.rsplit("/", 1)[-1]: repository, tag = token.rsplit(":", 1)
            values.append({"reference_form": form, "repository": repository, "tag": tag, "digest": digest,
                           "location": {"path": path, "path_disposition": "published",
                                        "start_line": line_no, "end_line": line_no}})
    return values


def build_documents(job_id: str, source_root: Path, *, run_id: str, attempt_id: str,
                    source_snapshot_sha256: str, vendor_results: dict[str, dict] | None = None) -> dict[str, Any]:
    """Build one deterministic contract document set; no filesystem publication occurs here."""
    contract, tools = SPECS[job_id]
    found = probe(job_id, source_root)
    candidates = found["candidates"]
    header = _header(job_id, run_id, attempt_id, source_snapshot_sha256)
    successful: dict[str, dict] = {}
    vendor_results = vendor_results or {}
    key_entries, base_images = [], []
    if job_id == "02-secrets-inventory":
        key_entries = _scan_keys(source_root, candidates["key-material-file-inventory"])
        raw = _dump({"records": [{"ordinal": n + 1, "path": e["location"]["path"]} for n, e in enumerate(key_entries)]})
        successful["key-material-file-inventory"] = {"data": raw, "count": len(key_entries),
            "schema": "vendor-key-material-result-1", "path": "outputs/tools/key-material-file-inventory/result.json"}
    elif job_id == "02-iac-config-scan" and candidates["dockerfile-base-image-inventory"]:
        base_images = _scan_base_images(source_root, candidates["dockerfile-base-image-inventory"])
        raw = _dump({"records": len(base_images)})
        successful["dockerfile-base-image-inventory"] = {"data": raw, "count": len(base_images),
            "schema": "vendor-base-image-result-1", "path": "outputs/tools/dockerfile-base-image-inventory/result.json"}
    for tool, result in vendor_results.items():
        if tool not in tools or result.get("status") != "OK":
            continue
        auth=result.get("auth")
        if not isinstance(auth,dict) or not isinstance(auth.get("receipt"),dict):
            raise ValueError(f"{tool}: successful vendor result lacks verified B13 identity")
        receipt_data=_dump(auth["receipt"]); receipt_path=f"outputs/tools/{tool}/execution-receipt.json"
        receipt_ref={"path":receipt_path,"sha256":HASH(receipt_data),
                     **{k:auth["receipt"][k] for k in ("request_sha256","result_sha256","output_sha256","permission_sha256",
                                                        "permission_fingerprint_sha256","image_id","image_digest")}}
        auth={**auth,"execution_receipt":receipt_ref}
        path = "outputs/binskim.sarif" if tool == "binskim" else f"outputs/tools/{tool}/" + (
            f"{tool}.sarif" if tool.startswith("mobsfscan-") else "result.json")
        successful[tool] = {"data": result["raw"], "count": len(result["records"]), "schema":
            ("checksec-json-1" if tool == "binskim" else "sarif-2.1.0" if path.endswith(".sarif") else "vendor-json-1"), "path": path,
            "role": "raw-tool-output", "validation": "format-validated", "auth":auth,
            "receipt_data":receipt_data,"receipt_path":receipt_path}
    if "binskim" in successful:
        successful["binskim"]["count"] = len(candidates["binskim"])
    if "oci-archive-inventory" in successful:
        successful["oci-archive-inventory"]["count"] = len(candidates["oci-archive-inventory"])
    failures = {tool: (result.get("status"), result.get("cause"), result.get("exit_code"))
                for tool, result in vendor_results.items()
                if tool in tools and result.get("status") in ("FAILED", "BLOCKED")}
    status, tool_results, coverage, probe_doc, raw_files = _aggregate(
        header, tools, candidates, successful, can_skip=job_id != "02-secrets-inventory", failures=failures)
    for value in successful.values():
        if "receipt_data" in value: raw_files[value["receipt_path"]]=value["receipt_data"]

    docs: dict[str, Any] = {"status": status, "contract_id": contract, "header": header,
                            "tool-results.json": tool_results, "coverage.json": coverage,
                            "raw_files": raw_files, "probe": probe_doc}
    if job_id == "02-secrets-inventory":
        for record in vendor_results.get("gitleaks", {}).get("records", []):
            key_entries.append({"assertion": "candidate-secret-location", "tool_id": "gitleaks",
                "rule_id": record["rule_id"].lower().replace("_", "-")[:48], "data_class": "other", "confidence": "medium",
                "location": {"path": record["path"], "path_disposition": "published",
                             "start_line": record["start_line"], "end_line": record["end_line"]}})
        for n, entry in enumerate(key_entries, 1):
            instance = next(i for i in tool_results["tool_instances"] if i["tool_id"] == entry["tool_id"])
            out = instance["outputs"][0]
            entry.update({"entry_id": f"SI-{n:06d}", "citation": {"source_class": "raw", "producer": job_id,
                          "attempt_id": instance["attempt_id"], "path": out["path"],
                          "sha256": out["sha256"].removeprefix("sha256:")}})
        docs["secrets-inventory.redacted.json"] = {"schema": "appsec-review/secrets-inventory/1.0", **header,
                                                    "redactor": REDACTOR, "entries": key_entries}
    elif job_id == "02-iac-config-scan":
        instance = tool_results["tool_instances"][-1]
        out = instance["outputs"][0] if instance["outputs"] else None
        rendered = []
        for n, image in enumerate(base_images, 1):
            image.update({"reference_id": f"BI-{n:06d}", "assertion": "declared-base-image-reference",
                          "tool_id": "dockerfile-base-image-inventory",
                          "citation": {"source_class": "raw", "producer": job_id,
                                       "attempt_id": instance["attempt_id"], "path": out["path"],
                                       "sha256": out["sha256"].removeprefix("sha256:")}})
            rendered.append(image)
        hits=[]
        for tool,result in vendor_results.items():
            if tool not in {"checkov","trivy-config","tfsec","kube-linter","hadolint"} or result.get("status") != "OK": continue
            inst=next(i for i in tool_results["tool_instances"] if i["tool_id"]==tool); out=inst["outputs"][0]
            identity=inst["identity"]["data_identities"][0]
            for record in result["records"]:
                path=record["path"]; kind=_iac_kind(tool, record)
                if kind is None:
                    continue   # outside this contract's IaC kinds (e.g. checkov github_actions); raw output keeps it
                disposition="not-applicable" if kind=="dockerfile" else "withheld-unsafe-address"
                hits.append({"hit_id":f"IC-{len(hits)+1:06d}","assertion":"declared-configuration-rule-hit","tool_id":tool,
                    "rule":{"rule_id":record["rule_id"],"rule_pack":{"kind":identity["kind"],"identity_id":identity["identity_id"],"sha256":identity["sha256"]}},
                    "category":"other","exposure":None,"resource":{"iac_kind":kind,"address":None,"address_disposition":disposition},
                    "location":{"path":path,"path_disposition":"published","start_line":record["start_line"],"end_line":record["end_line"]},
                    "citation":{"source_class":"raw","producer":job_id,"attempt_id":inst["attempt_id"],"path":out["path"],"sha256":out["sha256"].removeprefix("sha256:")}})
        docs["iac-config-evidence.json"] = {"schema": "appsec-review/iac-config-evidence/1.0", **header,
                                            "redactor": REDACTOR, "rule_hits": hits}
        docs["base-image-inventory.json"] = {"schema": "appsec-review/iac-config-base-image-inventory/1.0", **header,
                                             "redactor": REDACTOR, "base_images": rendered}
    elif job_id == "02-mobile-sast":
        hits=[]
        for platform,tool in (("android","mobsfscan-android"),("ios","mobsfscan-ios")):
            for record in vendor_results.get(tool,{}).get("records",[]):
                path=record["path"]; data=(source_root/path).read_bytes()
                hits.append({"hit_id":f"hit-{len(hits)+1:04d}","tool_id":tool,"platform":platform,
                             "rule_id":record["rule_id"],"category":"other-mobile-rule","file_path":path,
                             "file_sha256":HASH(data),"line":record["line"]})
        docs["mobile-sast.json"] = {"schema": "appsec-review/mobile-sast/1.0", **header,
                                    "platforms": [{"platform": "android", "tool_id": "mobsfscan-android",
                                                   "marker_present": bool(candidates["mobsfscan-android"])},
                                                  {"platform": "ios", "tool_id": "mobsfscan-ios",
                                                   "marker_present": bool(candidates["mobsfscan-ios"])}],
                                    "rule_hits": hits}
    elif job_id == "02-binary-hardening":
        records = []
        mapped={"BA2001":"position_independent","BA2002":"control_flow_guard","BA2004":"fortify_source",
                "BA2005":"stack_protector","BA2010":"non_executable_data","CHECKSEC-FULL-RELRO":"relro"}
        hits_by={p:[] for p in candidates["binskim"]}
        for hit in vendor_results.get("binskim",{}).get("records",[]):
            if hit["path"] in hits_by: hits_by[hit["path"]].append(hit)
        for path in candidates["binskim"]:
            data = (source_root / path).read_bytes()
            fmt=cmb.detect_format(data[:8]); checks={name:("present" if fmt in formats else "not-applicable-for-format")
                                                    for name,formats in cmb.CHECK_FORMATS.items()}
            rule_hits=[]
            for hit in hits_by[path]:
                check=mapped.get(hit["rule_id"],"other")
                if check != "other" and fmt in cmb.CHECK_FORMATS[check]: checks[check]="absent"
                rule_hits.append({"rule_id":hit["rule_id"],"check":check})
            records.append({"binary_id": "bin-" + hashlib.sha256(path.encode()).hexdigest()[:12], "tool_id": "binskim",
                            "path": path, "sha256": HASH(data), "bytes": len(data), "format": fmt,
                            "checks": checks if "binskim" in successful else {name:"not-assessed" for name in cmb.CHECK_FORMATS},
                            "rule_hits": rule_hits if "binskim" in successful else []})
        docs["binary-hardening.json"] = {"schema": "appsec-review/binary-hardening/1.0", **header, "binaries": records}
    else:
        records = []
        image_facts=vendor_results.get("oci-archive-inventory",{}).get("image_facts",{})
        package_records=vendor_results.get("image-package-and-config-inspection",{}).get("records",[])
        for path in candidates["oci-archive-inventory"]:
            data = (source_root / path).read_bytes()
            fact=image_facts.get(path)
            inspected=bool(fact and "oci-archive-inventory" in successful and "image-package-and-config-inspection" in successful)
            packages=[]
            if inspected:
                for package in package_records:
                    if package.get("archive_path",path)==path:
                        packages.append({"tool_id":"image-package-and-config-inspection","layer_index":package.get("layer_index",0),
                                         "ecosystem":package["ecosystem"],"name":package["name"],"version":package["version"]})
            records.append({"image_id": "img-" + hashlib.sha256(path.encode()).hexdigest()[:12],
                            "tool_id": "oci-archive-inventory",
                            "source": {"kind": "supplied-archive", "archive_path": path,
                                       "archive_sha256": HASH(data), "archive_bytes": len(data)},
                            "archive_format": "oci-layout" if path.endswith(".oci.tar") else "docker-save",
                            "inspection": "inspected" if inspected else "not-inspected",
                            "image_manifest_digest": fact["manifest_digest"] if inspected else None,
                            "layers": fact["layers"] if inspected else [], "config": fact["config"] if inspected else None,
                            "packages": packages if inspected else [], "hardening_rule_hits": []})
        docs["container-image-inventory.json"] = {"schema": "appsec-review/container-image-inventory/1.0", **header,
                                                  "images": records}
    return docs


def execute_and_build(job_id: str, source_root: Path, *, run_id: str, attempt_id: str,
                      source_snapshot_sha256: str, execution_root: Path, now: str,
                      collector=None) -> dict[str, Any]:
    """Applicability -> authenticated B13 collection -> exact contract projection."""
    import vendor_evidence_b13 as b13
    found=probe(job_id,source_root); tools=[t for t in SPECS[job_id][1]
        if found["candidates"][t] and t not in {"key-material-file-inventory","dockerfile-base-image-inventory"}]
    collector=collector or b13.collect
    results=collector(job_id,tools,run_id=run_id,node_attempt_id=attempt_id,source_root=source_root,
                      source_sha=source_snapshot_sha256,attempt_root=execution_root,now=now)
    if job_id=="02-container-image-inventory" and results.get("oci-archive-inventory",{}).get("status")=="OK":
        paths=found["candidates"]["oci-archive-inventory"]
        if len(paths)!=1: raise b13.VendorToolFailed("container-batch-association-ambiguous")
        results["oci-archive-inventory"]["image_facts"]=b13.container_image_facts(
            results["oci-archive-inventory"]["raw"],paths[0])
        for item in results.get("image-package-and-config-inspection",{}).get("records",[]): item["archive_path"]=paths[0]
    return build_documents(job_id,source_root,run_id=run_id,attempt_id=attempt_id,
                           source_snapshot_sha256=source_snapshot_sha256,vendor_results=results)


def _reconcile_redacted_outputs(attempt: Path) -> None:
    """Redaction can rewrite a raw tool output after tool-results.json listed its size and hash
    (freeciv21: gitleaks matched text our redactor also masks). Re-list those outputs as they are
    on disk, since the redacted bytes are what is published."""
    listing_path = attempt / "outputs" / "tool-results.json"
    if not listing_path.is_file():
        return
    listing = json.loads(listing_path.read_text(encoding="utf-8"))
    changed = False
    for instance in listing.get("tool_instances", []):
        for output in instance.get("outputs", []):
            path = attempt / output.get("path", "")
            if not path.is_file():
                continue
            data = path.read_bytes()
            if "bytes" in output and output["bytes"] != len(data):
                output["bytes"] = len(data); changed = True
            if "sha256" in output and output["sha256"] != HASH(data):
                output["sha256"] = HASH(data); changed = True
    if changed:
        data = _dump(listing)
        listing_path.write_bytes(data)
        receipt_path = attempt / "outputs" / "redaction-receipt.json"
        if receipt_path.is_file():
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            for entry in receipt.get("files", []):
                if entry.get("path") == "tool-results.json":
                    digest_hex = hashlib.sha256(data).hexdigest()
                    entry.update(published_bytes=len(data), published_sha256=digest_hex, source_sha256=digest_hex)
            receipt_path.write_bytes(_dump(evidence_redaction._seal(receipt)))


def materialize_attempt(documents: dict[str, Any], attempt: Path, *, dagster_run_id: str,
                        started_at: str | None = None, finished_at: str | None = None) -> None:
    """Publish a closed immutable-attempt layout through V06. Existing paths are never reused."""
    if attempt.exists():
        raise FileExistsError(str(attempt))
    staging = attempt.parent / (attempt.name + ".staging")
    staging.mkdir(parents=True)
    contract = documents["contract_id"]
    result_names = {"secrets-inventory": ["secrets-inventory.redacted.json"],
                    "iac-config-evidence": ["iac-config-evidence.json", "base-image-inventory.json"],
                    "container-image-inventory": ["container-image-inventory.json"],
                    "binary-hardening": ["binary-hardening.json"], "mobile-sast": ["mobile-sast.json"]}[contract]
    payload = {name: _dump(documents[name]) for name in result_names}
    payload["tool-results.json"] = _dump(documents["tool-results.json"])
    payload["coverage.json"] = _dump(documents["coverage.json"])
    if documents["probe"] is not None:
        probe_name = {"iac-config-evidence": "applicability-probe-receipt.json",
                      "container-image-inventory": "container-image-applicability.json",
                      "binary-hardening": "binary-hardening-applicability.json",
                      "mobile-sast": "mobile-applicability.json"}[contract]
        payload[probe_name] = _dump(documents["probe"])
    for relative, data in documents["raw_files"].items():
        payload[relative.removeprefix("outputs/")] = data
    for relative, data in payload.items():
        path = staging / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    header = documents["header"]
    permission, lineage = producer_receipts(documents)
    attempt.mkdir(parents=True)
    evidence_redaction.redact_tree(staging, attempt / "outputs", on_unhandled="refuse",
                                   limits=evidence_redaction.DEFAULT_LIMITS)
    (attempt / "permission.json").write_bytes(_dump(permission))
    (attempt / "lineage.json").write_bytes(_dump(lineage))
    status = {"status": documents["status"], "attempt_id": header["attempt_id"],
              "dagster_run_id": dagster_run_id}
    if contract in ("secrets-inventory", "iac-config-evidence"):
        status.update({"run_id": header["run_id"], "job_id": header["job_id"]})
    (attempt / "status.json").write_bytes(_dump(status))
    outputs = [{"path": p.relative_to(attempt).as_posix(), "sha256": HASH(p.read_bytes())}
               for p in sorted((attempt / "outputs").rglob("*")) if p.is_file()]
    (attempt / "manifest.json").write_bytes(_dump({"schema": sic.MANIFEST_SCHEMA,
                                                    "contract_id": contract, "outputs": outputs}))
    if started_at is not None and finished_at is not None:
        from worker_result import artifact_records, terminal_envelope, validate_worker_result
        artifacts=["manifest.json", "status.json", "permission.json", "lineage.json",
                   *[entry["path"] for entry in outputs]]
        gaps=[g["gap_id"] for g in documents["coverage.json"]["gaps"]]
        envelope=terminal_envelope(run_id=header["run_id"],job_id=header["job_id"],attempt_id=header["attempt_id"],
            worker_kind="pinned_container",execution_status=documents["status"],
            acceptance_status="CURRENT" if documents["status"] in ("OK","OK_WITH_GAPS","SKIPPED") else "NOT_ACCEPTED",
            input_fingerprint=HASH(_dump({"implementation": IMPLEMENTATION, "header": header,
                                         "contract": contract, "lineage": lineage})),output_contract=contract,
            started_at=started_at,finished_at=finished_at,summary=f"{header['job_id']} vendor evidence attempt",
            artifacts=artifact_records(attempt,artifacts),gaps=gaps,
            skip_reason=SKIP if documents["status"]=="SKIPPED" else None,
            cause="vendor-tool-unavailable" if documents["status"] in ("BLOCKED","FAILED") else None)
        errors=validate_worker_result(envelope)
        if errors: raise RuntimeError("common envelope invalid: "+"; ".join(errors))
        (attempt/"result.json").write_bytes(_dump(envelope))
    for path in sorted(staging.rglob("*"), reverse=True):
        if path.is_file(): path.unlink()
        elif path.is_dir(): path.rmdir()
    staging.rmdir()
