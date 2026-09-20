#!/usr/bin/env python3
"""Validated, run-owned conversion of verified-finding Markdown to SARIF 2.1.0.

The converter preserves the legacy ``md_to_sarif.py`` format, but accepted workflow output is
stricter: the input is a fixed run-owned file, every finding is validated, work runs in a bounded
child process with separate streams, and publication records immutable hashes. Target Markdown is
untrusted data; it is parsed as data and is never executed or interpolated into a command.

The conversion semantics below are unchanged. Only the execution wrapper is common: attempts are
allocated, recovered, published and reused through ``publish_job_output.py`` against the v1.0
worker-result envelope, read-only validation stays in ``validate_job_output.py``, and the bounded
child obeys ``appsec-review/deterministic-child/1.0``. This worker is still the standalone
``critical_findings_sarif`` Dagster job; it is deliberately not bound to synthesis.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import sys
from typing import Any

import yaml

from deterministic_child import CONTRACT as CHILD_CONTRACT, ChildExecutionSpec, execute_child
from execution_state import (ROOT, Blocked, atomic_json, data_path, digest, file_hash, identifier,
                             now, read_json, run_path, tree_hashes)
from job_graph import composition
from phase1 import config_for
from publish_job_output import (common_pointer, coordinate_worker_lifecycle,
                                record_terminal_current, validate_published)
from validate_job_output import validate_contract_result

JOB_ID = "10-critical-findings-sarif"
INPUT_NAME = "critical-findings.md"
OUTPUT_NAME = "critical-findings.sarif"
OUTPUT_CONTRACT = "critical-findings-sarif"
WORKER_KIND = "deterministic_python"
MAX_INPUT_BYTES = 4 * 1024 * 1024
TIMEOUT_SECONDS = 120
STDOUT_LIMIT_BYTES = 1024 * 1024
STDERR_LIMIT_BYTES = 1024 * 1024
REQUIRED_FIELDS = {"id", "title", "severity", "status", "location", "confidence"}
SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
SEVERITY_TO_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"
}
FRONTMATTER_OPEN_RE = re.compile(r"^---[ \t]*\n(?=id\s*:)", re.MULTILINE)
FRONTMATTER_CLOSE_RE = re.compile(r"\n---[ \t]*\n")
LOCATION_RE = re.compile(r"^(?P<path>[^\s:]+):(?P<line>\d+)(?:-(?P<end_line>\d+))?$")


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB_ID, "whole")


def input_path(run_id: str) -> Path:
    return run_path(run_id) / "inputs" / INPUT_NAME


def template() -> dict[str, Any]:
    value = read_json(ROOT / "registry" / "job-templates" / f"{JOB_ID}.json")
    composition(value)
    return value


def parse_findings(md_text: str, *, strict: bool = False) -> list[dict[str, Any]]:
    # Inputs staged from Windows retain CRLF when read as bytes by the bounded worker.
    md_text = md_text.replace("\r\n", "\n").replace("\r", "\n")
    opens = list(FRONTMATTER_OPEN_RE.finditer(md_text))
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, open_match in enumerate(opens):
        fm_start = open_match.end()
        close_match = FRONTMATTER_CLOSE_RE.search(md_text, fm_start)
        if not close_match:
            errors.append(f"finding block {index + 1} has no closing frontmatter delimiter")
            continue
        body_start = close_match.end()
        body_end = opens[index + 1].start() if index + 1 < len(opens) else len(md_text)
        try:
            meta = yaml.safe_load(md_text[fm_start:close_match.start()]) or {}
        except yaml.YAMLError as exc:
            errors.append(f"finding block {index + 1} has invalid YAML: {exc}")
            continue
        if not isinstance(meta, dict) or "id" not in meta:
            errors.append(f"finding block {index + 1} is not a finding object")
            continue
        meta["_body"] = md_text[body_start:body_end].strip()
        findings.append(meta)
    if strict:
        if not opens:
            errors.append("no finding frontmatter blocks found")
        for index, finding in enumerate(findings, 1):
            missing = sorted(REQUIRED_FIELDS - set(finding))
            if missing:
                errors.append(f"finding {index} missing required fields: {', '.join(missing)}")
            if finding.get("severity") not in SEVERITIES:
                errors.append(f"finding {index} has unsupported severity")
            raw_location = str(finding.get("location", "")).strip()
            path, region = location_to_region(raw_location)
            if not LOCATION_RE.fullmatch(raw_location) or path == "UNKNOWN" or region["startLine"] < 1:
                errors.append(f"finding {index} has invalid location")
            if "endLine" in region and region["endLine"] < region["startLine"]:
                errors.append(f"finding {index} has an inverted location range")
        ids = [str(finding.get("id")) for finding in findings]
        if len(ids) != len(set(ids)):
            errors.append("finding IDs must be unique")
    if errors:
        raise ValueError("; ".join(errors))
    return findings


def location_to_region(location: str | None) -> tuple[str, dict[str, Any]]:
    if not location:
        return "UNKNOWN", {"startLine": 1}
    match = LOCATION_RE.match(str(location).strip())
    if not match:
        return str(location).strip(), {"startLine": 1}
    region: dict[str, Any] = {"startLine": int(match.group("line"))}
    if match.group("end_line"):
        region["endLine"] = int(match.group("end_line"))
    return match.group("path"), region


def body_section(body: str, heading: str) -> str:
    match = re.search(rf"###\s*{re.escape(heading)}\s*\n(.*?)(?=\n###\s|\Z)", body,
                      re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def finding_to_result(meta: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    severity = str(meta.get("severity", "Medium")).lower()
    rule_id = meta.get("cwe") or meta.get("category") or meta.get("id")
    title = meta.get("title", meta.get("id", "Untitled finding"))
    body = meta.get("_body", "")
    description = body_section(body, "Description") or title
    impact = body_section(body, "Impact")
    remediation = body_section(body, "Remediation")
    message = description + (f"\n\nImpact: {impact}" if impact else "") + (
        f"\n\nRemediation: {remediation}" if remediation else "")
    path, region = location_to_region(meta.get("location"))
    rule = {
        "id": str(rule_id),
        "name": re.sub(r"[^A-Za-z0-9]+", "", str(title))[:60] or str(rule_id),
        "shortDescription": {"text": title}, "fullDescription": {"text": description or title},
        "helpUri": "", "properties": {
            "tags": [tag for tag in (meta.get("category"), meta.get("asvs")) if tag],
            "security-severity": {"critical": "9.0", "high": "7.5", "medium": "5.0",
                                  "low": "3.0", "info": "1.0"}.get(severity, "5.0")}}
    result = {
        "ruleId": str(rule_id), "level": SEVERITY_TO_LEVEL.get(severity, "warning"),
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": region}}],
        "properties": {"findingId": meta.get("id"), "severity": meta.get("severity"),
                       "status": meta.get("status"), "confidence": meta.get("confidence"),
                       "component": meta.get("component"), "asvs": meta.get("asvs"),
                       "dataClasses": meta.get("data_classes") or [],
                       "regulatory": meta.get("regulatory") or [], "cve": meta.get("cve") or [],
                       "discoveredBy": meta.get("discovered_by")}}
    return rule, result


def build_sarif(findings: list[dict[str, Any]], tool_name: str = "vendor-audit-playbook") -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for meta in findings:
        rule, result = finding_to_result(meta)
        rules[rule["id"]] = rule
        results.append(result)
    return {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0", "runs": [{"tool": {"driver": {"name": tool_name,
            "informationUri": "", "version": "1.0.0", "rules": list(rules.values())}},
            "results": results}]}


def convert(source: Path, output: Path, *, strict: bool = True) -> dict[str, Any]:
    raw = source.read_bytes()
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    text = raw.decode("utf-8")
    findings = parse_findings(text, strict=strict)
    sarif = build_sarif(findings)
    atomic_json(output, sarif)
    return {"finding_count": len(findings), "rule_count": len(sarif["runs"][0]["tool"]["driver"]["rules"])}


def validate_sarif(path: Path, expected_findings: int) -> dict[str, Any]:
    value = read_json(path)
    if value.get("version") != "2.1.0" or len(value.get("runs", [])) != 1:
        raise Blocked("invalid SARIF 2.1.0 envelope")
    run = value["runs"][0]
    results = run.get("results")
    rules = run.get("tool", {}).get("driver", {}).get("rules")
    if not isinstance(results, list) or len(results) != expected_findings or not isinstance(rules, list):
        raise Blocked("SARIF result or rule counts do not match validated input")
    for result in results:
        region = result.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {})
        if not result.get("ruleId") or not result.get("properties", {}).get("findingId") or region.get("startLine", 0) < 1:
            raise Blocked("SARIF result is missing identity or a valid source location")
    return value


def current_inputs(run_id: str) -> dict[str, Any]:
    """Derive the immutable input fingerprint record for one attempt.

    Strict fixed-input validation happens here, before any attempt is allocated, so a malformed or
    missing finding document is a preflight ``BLOCKED`` outcome rather than a failed child.
    """
    config_for(run_id)
    source = input_path(run_id)
    if not source.is_file() or source.is_symlink():
        raise Blocked(f"stage a regular run-owned input at inputs/{INPUT_NAME}")
    if source.stat().st_size > MAX_INPUT_BYTES:
        raise Blocked(f"inputs/{INPUT_NAME} exceeds {MAX_INPUT_BYTES} bytes")
    findings = parse_findings(source.read_text(encoding="utf-8"), strict=True)
    job = template()
    return {"source": {"path": f"inputs/{INPUT_NAME}", "sha256": file_hash(source),
                       "bytes": source.stat().st_size, "finding_count": len(findings)},
            "composition": job["composition"], "timeout_seconds": job["timeout_seconds"],
            "output_contract": OUTPUT_CONTRACT, "worker_kind": WORKER_KIND,
            "tool": {"name": "critical_findings_sarif", "version": "1.0.0",
                     "python": platform.python_version(), "pyyaml": yaml.__version__,
                     "executable": str(Path(sys.executable).resolve()),
                     "image": os.environ.get("APPSEC_WORKER_IMAGE", "appsec-review-dagster:local")},
            "code": {"critical_findings_sarif.py": file_hash(Path(__file__)),
                     "deterministic_child.py": file_hash(ROOT / "deterministic_child.py"),
                     "execution_state.py": file_hash(ROOT / "execution_state.py"),
                     "process_gate.py": file_hash(ROOT / "process_gate.py"),
                     "publish_job_output.py": file_hash(ROOT / "publish_job_output.py"),
                     "validate_job_output.py": file_hash(ROOT / "validate_job_output.py"),
                     "worker_result.py": file_hash(ROOT / "worker_result.py"),
                     f"registry/job-templates/{JOB_ID}.json": file_hash(
                         ROOT / "registry" / "job-templates" / f"{JOB_ID}.json"),
                     f"registry/output-contracts/{OUTPUT_CONTRACT}.json": file_hash(
                         ROOT / "registry" / "output-contracts" / f"{OUTPUT_CONTRACT}.json")},
            "child_execution": {"contract": CHILD_CONTRACT, "argv_only": True,
                                "shell_allowed": False,
                                "stdout_limit_bytes": STDOUT_LIMIT_BYTES,
                                "stderr_limit_bytes": STDERR_LIMIT_BYTES,
                                "child_tree_cleanup": "always"}}


def input_fingerprint(record: dict[str, Any]) -> str:
    return "sha256:" + digest(record)


def contract() -> dict[str, Any]:
    return read_json(ROOT / "registry" / "output-contracts" / f"{OUTPUT_CONTRACT}.json")


def _validate_attempt_payload(attempt: Path) -> None:
    """Contract-declared result validation plus the SARIF-specific identity and hash checks.

    The common validator owns the declared result artifact, its schema and the generic
    non-mutating checks. Finding-count agreement with the immutable validated input and the
    manifest hashes stay local to this worker.
    """
    errors = validate_contract_result(
        attempt, contract(), run_id=read_json(attempt / "status.json").get("run_id", ""))
    if errors:
        raise Blocked("invalid critical-findings SARIF result: " + "; ".join(errors))
    record = read_json(attempt / "inputs.json")
    output = attempt / "outputs" / OUTPUT_NAME
    validate_sarif(output, record["source"]["finding_count"])
    manifest = read_json(attempt / "manifest.json")
    if manifest.get("source_sha256") != record["source"]["sha256"]:
        raise Blocked("SARIF manifest source hash mismatch")
    if manifest.get("sarif_sha256") != file_hash(output):
        raise Blocked("SARIF manifest output hash mismatch")


def _validate_legacy(run_id: str, pointer: dict[str, Any]) -> Path:
    """Pre-migration pointers stay integrity-readable; run() never reuses them as current."""
    base = root(run_id)
    if pointer.get("status") != "OK":
        raise Blocked("SARIF transform is not accepted")
    attempt = base / "attempts" / identifier(pointer["attempt_id"])
    if tree_hashes(attempt) != pointer.get("hashes"):
        raise Blocked("SARIF attempt artifacts changed")
    if read_json(attempt / "status.json").get("status") != "OK":
        raise Blocked("SARIF attempt did not finish OK")
    _validate_attempt_payload(attempt)
    return attempt


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    if not common_pointer(pointer):
        return _validate_legacy(run_id, pointer)
    record = current_inputs(run_id)
    attempt, _envelope = validate_published(
        base, pointer, input_fingerprint(record), expected_run_id=run_id, expected_job_id=JOB_ID)
    if read_json(attempt / "inputs.json") != record:
        raise Blocked("SARIF inputs, tooling or implementation are stale")
    _validate_attempt_payload(attempt)
    return attempt


def _failure_record(run_id: str, exc: BaseException) -> dict[str, Any]:
    """Bounded preflight descriptor for an attempt that never reached validated inputs."""
    source = input_path(run_id)
    descriptor: dict[str, Any] = {"run_id": run_id, "job": JOB_ID,
                                  "preflight_error": f"{type(exc).__name__}: {exc}",
                                  "code": file_hash(Path(__file__))}
    if source.is_file() and not source.is_symlink():
        descriptor["source"] = {"path": f"inputs/{INPUT_NAME}", "sha256": file_hash(source),
                                "bytes": source.stat().st_size}
    return descriptor


def child_environment() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL"}}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)
    resume = (f"python -B appsec-review-process/launch_job.py --run-id {run_id} "
              "--job critical_findings_sarif --wait")

    def post_validate(attempt: Path, _envelope: dict[str, Any],
                      record: dict[str, Any]) -> None:
        if read_json(attempt / "inputs.json") != record:
            raise Blocked("SARIF immutable attempt inputs changed")
        _validate_attempt_payload(attempt)

    def on_reuse(admitted: dict[str, Any]) -> None:
        candidate, envelope = admitted["pointer"], admitted["envelope"]
        atomic_json(data_path(run_id, "orchestration", "dagster", dagster_id,
                              "critical-findings-sarif-reuse.json"),
                    {"status": envelope["execution_status"], "reused": True,
                     "publication_recovered": admitted["recovered_publication"],
                     "producer": candidate, "time": now()})

    def execute_attempt(allocation: dict[str, Any], record: dict[str, Any],
                        fingerprint: str) -> dict[str, Any]:
        attempt_id = allocation["attempt_id"]
        attempt = allocation["attempt"]
        (attempt / "outputs").mkdir(parents=True)
        started = allocation["started_at"]
        status = {"status": "RUNNING", "run_id": run_id, "attempt_id": attempt_id,
                  "dagster_run_id": dagster_id, "started_at": started, "fingerprint": fingerprint}
        atomic_json(attempt / "status.json", status)
        atomic_json(attempt / "pre.json", {"status": "OK", "validation": "strict finding schema",
                                            "source_sha256": record["source"]["sha256"]})
        output = attempt / "outputs" / OUTPUT_NAME
        executable = str(Path(sys.executable).resolve())
        argv = [executable, "-B", str(Path(__file__).resolve()), "worker",
                str(input_path(run_id)), str(output)]
        result = execute_child(ChildExecutionSpec(
            argv=tuple(argv), argv_prefix=tuple(argv[:4]), executable=Path(executable),
            cwd=ROOT.resolve(), owner_root=attempt.resolve(),
            log_dir=(attempt / "logs").resolve(),
            timeout_seconds=record["timeout_seconds"],
            stdout_limit_bytes=record["child_execution"]["stdout_limit_bytes"],
            stderr_limit_bytes=record["child_execution"]["stderr_limit_bytes"],
            env=child_environment()))
        atomic_json(attempt / "command.json", result)
        if result.get("error") or result.get("exit_code") != 0:
            raise Blocked("SARIF transform failed; inspect separate attempt logs")
        if file_hash(input_path(run_id)) != record["source"]["sha256"]:
            raise Blocked("critical findings input changed during conversion")
        if record["code"] != current_inputs(run_id)["code"]:
            raise Blocked("SARIF implementation changed during conversion")
        validate_sarif(output, record["source"]["finding_count"])
        manifest = {"schema": "appsec-review/critical-findings-sarif/1", "run_id": run_id,
                    "attempt_id": attempt_id, "source_path": record["source"]["path"],
                    "source_sha256": record["source"]["sha256"],
                    "sarif_path": f"outputs/{OUTPUT_NAME}", "sarif_sha256": file_hash(output),
                    "finding_count": record["source"]["finding_count"], "tool": record["tool"],
                    "target_execution": False}
        atomic_json(attempt / "manifest.json", manifest)
        atomic_json(attempt / "post.json", {"status": "OK", "schema_validation": "PASS",
                                             "freshness": "PASS", "hash_validation": "PASS"})
        return record_terminal_current(
            base, attempt, run_id=run_id, job_id=JOB_ID, dagster_run_id=dagster_id,
            worker_kind=WORKER_KIND, output_contract=OUTPUT_CONTRACT,
            input_fingerprint=fingerprint, started_at=started, execution_status="OK",
            summary="Verified-finding Markdown converted to accepted SARIF 2.1.0.",
            status_record=status,
            artifact_paths=["manifest.json", f"outputs/{OUTPUT_NAME}", "status.json"],
            pre_envelope_validate=lambda path, _status: _validate_attempt_payload(path))

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=JOB_ID, dagster_run_id=dagster_id,
        worker_kind=WORKER_KIND, output_contract=OUTPUT_CONTRACT, resume_command=resume,
        derive_inputs=lambda: current_inputs(run_id),
        fingerprint_inputs=input_fingerprint, execute_attempt=execute_attempt,
        preflight_failure_inputs=lambda exc: _failure_record(run_id, exc),
        force=force, post_validate=post_validate, on_reuse=on_reuse,
        blocked_summary="Critical-findings SARIF preflight did not complete.",
        failed_summary="Critical-findings SARIF transform did not publish.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    worker = sub.add_parser("worker")
    worker.add_argument("input", type=Path)
    worker.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    if args.command == "worker":
        counts = convert(args.input, args.output, strict=True)
        print(json.dumps({"status": "OK", **counts}, sort_keys=True))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
