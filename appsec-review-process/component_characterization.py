"""Immutable happy-path worker for ``01-component-characterization``.

The model performs the bounded semantic judgment; this module owns provenance, source/upstream
identity, citation hashes, independent schema/semantic validation and publication.  The output is
only a static scope/component map and review routing.  It cannot carry findings, severity, runtime
state, compliance verdicts or remediation status.

Dagster/graph/catalog/SAT wiring is intentionally outside this isolated core.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re
import threading
from typing import Any

from claude_cli_invoker import ClaudeCliInvoker
from execution_state import Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash, now, read_json, run_path
import intake
import model_version_registry as mvr
import persona_dispatch as pd
import persona_invocation as pi
import persona_prompt_assembly as ppa
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
import review_cli as rc
from schema_validate import SchemaStore, validate_document
from worker_result import validate_worker_result

JOB = "01-component-characterization"
DAGSTER_JOB = "component_characterization"
PERSONA_JOB_ID = "f03-components"
TEMPLATE = JOB
CONTRACT = "component-map"
RESULT = "component-purpose-map.json"
SUMMARY = "component-purpose-map.md"
SCHEMA = "appsec-review/component-purpose-map/1.0"
UPSTREAM_JOB = "02-evidence-assembly"
UPSTREAM_MANIFEST = "intel-manifest.json"
EXPECTED_SCOPE_CATEGORIES = {
    "first-party", "vendored", "generated", "test-sample", "documentation", "build-tooling",
}
PROHIBITED_KEYS = {
    "finding", "findings", "verified_finding", "verified_findings", "vulnerability",
    "vulnerabilities", "severity", "cvss", "cvss_score", "runtime_state",
    "runtime_observation", "observed_runtime", "compliance_verdict", "remediation_status",
}
CODE_FILES = (
    "component_characterization.py", "persona_dispatch.py", "persona_invocation.py",
    "persona_prompt_assembly.py", "claude_cli_invoker.py", "publish_job_output.py",
    "validate_job_output.py", "registry/job-templates/01-component-characterization.json",
    "registry/roles/component-characterizer.json", "registry/domains/component-characterization.json",
    "registry/tooling-profiles/component-evidence-router.json",
    "registry/output-contracts/component-map.json",
    "01-component-characterization/task-component-characterization.md",
)


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _clock() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _target(run_id: str) -> tuple[Path, dict[str, Any]]:
    manifest_path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise Blocked(f"{JOB}: staged artifact-manifest.json is required")
    manifest = read_json(manifest_path)
    target = manifest.get("target") if isinstance(manifest, dict) else None
    value = target.get("repo_path") if isinstance(target, dict) else None
    path = Path(value) if isinstance(value, str) else Path()
    if not value or not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked(f"{JOB}: target.repo_path must be an absolute real checkout directory")
    resolved = path.resolve()
    identity = intake.source_identity(str(resolved))
    return resolved, identity


def _code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    values["schemas/component-purpose-map.schema.json"] = file_hash(
        ROOT.parent / "schemas" / "component-purpose-map.schema.json")
    return values


def _accepted_evidence(run_id: str) -> tuple[Path, dict[str, Any]]:
    base = data_path(run_id, "jobs", UPSTREAM_JOB)
    pointer_path = base / "accepted.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        raise Blocked(f"{JOB}: requires an accepted {UPSTREAM_JOB} result")
    pointer = read_json(pointer_path)
    if (pointer.get("schema") != "appsec-review/accepted-worker-result/1.0" or
            pointer.get("run_id") != run_id or pointer.get("job") != UPSTREAM_JOB or
            pointer.get("status") not in {"OK", "OK_WITH_GAPS"}):
        raise Blocked(f"{JOB}: {UPSTREAM_JOB} pointer is not a current accepted result")
    attempt_id = pointer.get("attempt_id")
    if not isinstance(attempt_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,119}", attempt_id):
        raise Blocked(f"{JOB}: {UPSTREAM_JOB} pointer has an invalid attempt id")
    attempt = base / "attempts" / attempt_id
    envelope_path = attempt / pointer.get("envelope_path", "")
    if (not attempt.is_dir() or attempt.is_symlink() or not envelope_path.is_file() or
            file_hash(envelope_path) != pointer.get("envelope_sha256")):
        raise Blocked(f"{JOB}: accepted {UPSTREAM_JOB} attempt or envelope changed")
    envelope = read_json(envelope_path)
    if (validate_worker_result(envelope) or envelope.get("attempt_id") != attempt_id or
            envelope.get("job_id") != UPSTREAM_JOB or envelope.get("run_id") != run_id or
            envelope.get("acceptance_status") != "CURRENT" or
            envelope.get("execution_status") != pointer.get("status") or
            envelope.get("input_fingerprint") != pointer.get("fingerprint") or
            pointer.get("envelope_path") != "result.json" or
            envelope.get("output_contract") != "pregather"):
        raise Blocked(f"{JOB}: accepted {UPSTREAM_JOB} envelope is invalid")
    artifacts = envelope.get("artifacts", [])
    for record in artifacts:
        relative = record.get("path") if isinstance(record, dict) else None
        path = _beneath(attempt, relative)
        if path is None or not path.is_file() or path.is_symlink() or file_hash(path) != record.get("sha256"):
            raise Blocked(f"{JOB}: accepted {UPSTREAM_JOB} artifact set changed")
    manifest = attempt / UPSTREAM_MANIFEST
    if (UPSTREAM_MANIFEST not in {item.get("path") for item in artifacts if isinstance(item, dict)} or
            not manifest.is_file() or manifest.is_symlink()):
        raise Blocked(f"{JOB}: accepted {UPSTREAM_JOB} has no {UPSTREAM_MANIFEST}")
    return attempt, {
        "job": UPSTREAM_JOB, "attempt_id": attempt_id,
        "pointer_sha256": file_hash(pointer_path), "envelope_sha256": file_hash(envelope_path),
        "manifest_sha256": file_hash(manifest),
        "artifacts": sorted({item["path"]: item["sha256"] for item in artifacts}.items()),
    }


def _stage_evidence(run_id: str, source: Path, evidence: dict[str, Any]) -> Path:
    """Expose only the upstream envelope's published artifacts to the persona.

    Raw tool attempts and logs may coexist under the assembly attempt.  They are deliberately not
    readable inputs merely because they share a parent directory with published evidence.
    """
    artifact_map = dict(evidence["artifacts"])
    stage = root(run_id) / "upstream" / digest({"attempt": evidence["attempt_id"],
                                                  "artifacts": evidence["artifacts"]})[:20]
    stage.mkdir(parents=True, exist_ok=True)
    for relative, expected in artifact_map.items():
        source_path = _beneath(source, relative)
        destination = _beneath(stage, relative)
        if source_path is None or destination is None or not source_path.is_file():
            raise Blocked(f"{JOB}: published upstream artifact path is invalid")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            atomic_bytes(destination, source_path.read_bytes())
        if (not destination.is_file() or destination.is_symlink() or
                file_hash(destination) != expected):
            raise Blocked(f"{JOB}: staged upstream evidence changed")
    present = {path.relative_to(stage).as_posix() for path in stage.rglob("*") if path.is_file()}
    if present != set(artifact_map):
        raise Blocked(f"{JOB}: staged upstream evidence contains undeclared files")
    return stage


def current_inputs(run_id: str) -> dict[str, Any]:
    target, identity = _target(run_id)
    evidence_attempt, evidence = _accepted_evidence(run_id)
    evidence_root = _stage_evidence(run_id, evidence_attempt, evidence)
    return {
        "job": JOB, "run_id": run_id, "target_root": str(target),
        "target_name": target.name, "source_revision": identity.get("revision"),
        "source_snapshot_sha256": "sha256:" + identity["fingerprint"],
        "evidence_root": str(evidence_root), "evidence": evidence, "code": _code_hashes(),
    }


def _beneath(root_path: Path, value: Any) -> Path | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or "." in pure.parts or any(not part for part in pure.parts):
        return None
    path = (root_path / Path(*pure.parts)).resolve()
    try:
        path.relative_to(root_path.resolve())
    except ValueError:
        return None
    return path


def _pattern_ok(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        return False
    return ".." not in PurePosixPath(value).parts and not re.match(r"^[A-Za-z]:", value)


def _walk_keys(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower().replace("-", "_") in PROHIBITED_KEYS:
                errors.append(f"{path}.{key}: prohibited conclusion field")
            errors.extend(_walk_keys(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_walk_keys(item, f"{path}[{index}]"))
    return errors


def _walk_text(value: Any):
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk_text(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_text(item)
    elif isinstance(value, str):
        yield value


def _citations(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "evidence_citations" and isinstance(item, list):
                yield from item
            else:
                yield from _citations(item)
    elif isinstance(value, list):
        for item in value:
            yield from _citations(item)


def _backfill_citations(value: Any, target_hashes: dict[str, str], evidence_hashes: dict[str, str]) -> None:
    for citation in _citations(value):
        if not isinstance(citation, dict):
            continue
        table = target_hashes if citation.get("source_type") == "source_file" else (
            evidence_hashes if citation.get("source_type") == "upstream_lane" else {})
        expected = table.get(citation.get("path"))
        if expected:
            citation["content_hash"] = expected.split(":", 1)[-1]


def validate_payload(value: dict[str, Any], *, target_root: Path,
                     evidence_root: Path | None = None) -> list[str]:
    errors = list(validate_document(value, "component-purpose-map.schema.json"))
    if errors:
        return errors
    errors.extend(_walk_keys(value))
    conclusion_patterns = (
        re.compile(r"(?i)(?<!not a )(?<!no )\bverified[- ]finding\b"),
        re.compile(r"(?i)(?<!not a )(?<!no )\bconfirmed[- ]vulnerabilit(?:y|ies)\b"),
        re.compile(r"(?i)\bseverity\s*[:=]\s*(?:critical|high|medium|low)\b"),
        re.compile(r"(?i)\b(?:runtime[- ]verified|compliance verdict|remediation status)\b"),
    )
    if any(pattern.search(text) for text in _walk_text(value) for pattern in conclusion_patterns):
        errors.append("component map text promotes routing evidence to a prohibited conclusion")

    def unique(items: list[dict[str, Any]], key: str, label: str) -> set[str]:
        ids = [item[key] for item in items]
        if len(ids) != len(set(ids)):
            errors.append(f"{label} identifiers must be unique")
        return set(ids)

    scopes = unique(value["code_scope_classification"], "scope_id", "scope")
    components = unique(value["functional_components"], "component_id", "component")
    groups = unique(value["parallel_review_groups"], "group_id", "parallel review group")
    triggers = unique(value["rescope_triggers"], "trigger_id", "rescope trigger")
    unique(value["classification_gaps"], "gap_id", "classification gap")
    covered = {item["classification"] for item in value["code_scope_classification"]}
    covered |= {item["category"] for item in value["negative_evidence"]}
    missing = EXPECTED_SCOPE_CATEGORIES - covered
    if missing:
        errors.append("expected categories are neither classified nor recorded as negative evidence: " +
                      ", ".join(sorted(missing)))
    for item in value["code_scope_classification"]:
        for pattern in item["path_patterns"]:
            if not _pattern_ok(pattern):
                errors.append(f"scope {item['scope_id']} has a non-relative path pattern")
    for item in value["analysis_exclusions"]:
        if item["scope_id"] not in scopes:
            errors.append(f"exclusion scope does not resolve: {item['scope_id']}")
        if item["rescope_trigger_id"] not in triggers:
            errors.append(f"exclusion rescope trigger does not resolve: {item['rescope_trigger_id']}")
    for item in value["functional_components"]:
        if item["parallel_review_group"] not in groups:
            errors.append(f"component group does not resolve: {item['parallel_review_group']}")
        for location in item["representative_locations"]:
            if not _pattern_ok(location):
                errors.append(f"component {item['component_id']} has a non-relative location")
    for item in value["parallel_review_groups"]:
        missing_components = set(item["component_ids"]) - components
        if missing_components:
            errors.append(f"review group {item['group_id']} has unresolved component ids")
    for item in value["rescope_triggers"]:
        if set(item["affected_scope_ids"]) - scopes:
            errors.append(f"rescope trigger {item['trigger_id']} has unresolved scope ids")
        if set(item["affected_component_ids"]) - components:
            errors.append(f"rescope trigger {item['trigger_id']} has unresolved component ids")
    for citation in _citations(value):
        if not isinstance(citation, dict):
            continue
        source_type, citation_path = citation.get("source_type"), citation.get("path")
        owner = target_root if source_type == "source_file" else (
            evidence_root if source_type == "upstream_lane" else None)
        if owner is None:
            errors.append("component map citations must be source_file or upstream_lane evidence")
            continue
        path = _beneath(owner, citation_path)
        if path is None or not path.is_file() or path.is_symlink():
            errors.append(f"citation does not resolve beneath its evidence root: {citation_path}")
            continue
        if citation.get("content_hash") != file_hash(path):
            errors.append(f"citation content hash is stale: {citation_path}")
    return errors


def _dispatch_persona(run_id: str, allocation: dict[str, Any], record: dict[str, Any]) -> tuple[dict[str, Any], str, dict[str, Any]]:
    attempt, attempt_id = allocation["attempt"], allocation["attempt_id"]
    target_root, evidence_root = Path(record["target_root"]), Path(record["evidence_root"])
    mvr.resolve_run_model_versions(run_id)
    store = SchemaStore()
    template = ppa.load_job_template(TEMPLATE, store)
    budget = template["budget_default"]
    model = rc.resolve_model(TEMPLATE, budget)
    budget_usd = (rc.load_model_config().get("budget_max_usd_per_call") or {}).get(budget)
    request = pd.build_request(
        TEMPLATE, run_id=run_id, job_id=PERSONA_JOB_ID, attempt_id=attempt_id,
        target_root=target_root, source_snapshot_sha256=record["source_snapshot_sha256"],
        now=_clock(), store=store, upstream_root=evidence_root)
    model_identity = request["model"]
    runtime = pi.PersonaRuntime(
        invoker=ClaudeCliInvoker(effort=model["effort"], budget_usd=budget_usd),
        registry_dir=pd.REGISTRY_DIR, prompt_root=ppa.PROMPT_ROOT,
        readable_roots={pd.DEFAULT_READABLE_ROOT: target_root, pd.UPSTREAM_ROOT_ID: evidence_root},
        allowed_models=(model_identity,), source_snapshot_sha256=record["source_snapshot_sha256"],
        registry_ceiling=None, clock=_clock, cancel=threading.Event(), stop_grace_seconds=5)
    result = pi.run_invocation(runtime, run_id=run_id, job_id=PERSONA_JOB_ID,
                               attempt_id=attempt_id, attempt_root=attempt, request=request)
    if result["execution_status"] != "OK":
        raise RuntimeError(f"{JOB}: persona dispatch ended {result['execution_status']}")
    output = attempt / Path(*request["output_root"].split("/"))
    value = read_json(output / RESULT)
    value["target"] = record["target_name"]
    value["source_revision"] = record["source_revision"]
    value["source_snapshot_sha256"] = record["source_snapshot_sha256"]
    target_hashes = {item["path"]: item["sha256"] for item in request["readable_inputs"]
                     if item["root"] == pd.DEFAULT_READABLE_ROOT}
    evidence_hashes = {item["path"]: item["sha256"] for item in request["readable_inputs"]
                       if item["root"] == pd.UPSTREAM_ROOT_ID}
    _backfill_citations(value, target_hashes, evidence_hashes)
    summary = (output / SUMMARY).read_text(encoding="utf-8")
    facts = {"budget": budget, "persona": request["persona"], "model": dict(model_identity),
             "persona_result_sha256": result["result_sha256"],
             "artifacts_read": sorted({item["path"] for item in request["readable_inputs"]})}
    return value, summary, facts


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{JOB}: immutable attempt inputs changed")
    value = read_json(attempt / RESULT)
    expected_identity = {
        "target": inputs["target_name"],
        "source_revision": inputs["source_revision"],
        "source_snapshot_sha256": inputs["source_snapshot_sha256"],
    }
    if any(value.get(key) != expected for key, expected in expected_identity.items()):
        raise Blocked(f"{JOB}: result identity does not match its immutable inputs")
    errors = validate_payload(value, target_root=Path(inputs["target_root"]),
                              evidence_root=Path(inputs["evidence_root"]))
    if errors:
        raise Blocked(f"{JOB}: component map failed independent validation ({len(errors)} errors)")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)
    resume = f"python -B appsec-review-process/launch_job.py --run-id {run_id} --job {DAGSTER_JOB} --wait"

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if inputs["code"] != _code_hashes():
            raise Blocked(f"{JOB}: implementation changed before execution")
        value, summary, facts = _dispatch_persona(run_id, allocation, inputs)
        errors = validate_payload(value, target_root=Path(inputs["target_root"]),
                                  evidence_root=Path(inputs["evidence_root"]))
        if errors:
            raise ValueError(f"{JOB}: persona result failed independent validation: " + "; ".join(errors))
        attempt = allocation["attempt"]
        atomic_json(attempt / RESULT, value)
        atomic_bytes(attempt / SUMMARY, summary.encode("utf-8"))
        gaps = [item["reason"] for item in value["classification_gaps"]]
        status_name = "OK_WITH_GAPS" if gaps else "OK"
        persona = facts["persona"]
        status = {
            "process": JOB, "status": status_name, "budget": facts["budget"],
            "persona_id": persona["persona_id"], "role_id": persona["role_id"],
            "domain_id": persona["domain_id"], "tooling_profile_id": persona["tooling_profile_id"],
            "artifacts_read": facts["artifacts_read"], "classification_gaps": len(gaps),
            "dispatch_mode": "automatic", "persona_job_id": PERSONA_JOB_ID,
            "persona_result_sha256": facts["persona_result_sha256"], "model": facts["model"],
        }
        return record_terminal_current(
            base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
            worker_kind="persona", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=status_name,
            summary="Component purpose and downstream review routing map produced.",
            status_record=status, artifact_paths=[RESULT, SUMMARY, "status.json"], gaps=gaps,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="persona", output_contract=CONTRACT, resume_command=resume,
        derive_inputs=lambda: current_inputs(run_id),
        fingerprint_inputs=lambda value: "sha256:" + digest(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()},
        force=force, post_validate=lambda attempt, _envelope, inputs: _validate_attempt(run_id, attempt, inputs),
        blocked_summary="Component characterization preflight did not complete.",
        failed_summary="Component characterization did not publish; no older result may be used.")


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    inputs = current_inputs(run_id)
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(inputs),
                                    expected_run_id=run_id, expected_job_id=JOB)
    _validate_attempt(run_id, attempt, inputs)
    return attempt


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-component-characterization")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.run_id, args.dagster_run_id, args.force), indent=2))
