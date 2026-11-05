from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import time

from appsec_review.config.loader import BuildEnvironmentSettings, parse_bounded_settings
from appsec_review.interchange import decode_handoff
from appsec_review.runtime import Job, Unit, UnitExecutor
from appsec_review.storage import atomic_bytes, canonical_json
from appsec_review.storage.shared import safe_path

from .datasets import CONSUMES, DATASETS

JOB_ID = "job_build_environment_analysis"
SCHEMA = "appsec-review/build-environment-analysis/1"
RULES = "static-environment/1"
SECRET = re.compile(r"(?i)(?:password|passwd|secret|token|credential|private[_-]?key|api[_-]?key)")
URL_CREDENTIAL = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+@")
ASSIGNMENT = re.compile(r"(?i)^(?:export\s+|set\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
SUPPORTED = {".sh", ".bash", ".bat", ".cmd"}
WORKFLOWS = {"wave1_review", "project_build_review"}


def _assignment(line: str):
    declaration = line.strip()
    quoted = re.fullmatch(r'(?i)@?set\s+"([^"]*)"', declaration)
    if quoted:
        declaration = quoted[1]
    else:
        declaration = re.sub(r"(?i)^@set\s+", "set ", declaration)
    return ASSIGNMENT.fullmatch(declaration)


def redact(text: str) -> str:
    lines = []
    for original in text.splitlines(keepends=True):
        line = original.rstrip("\r\n")
        declaration = re.sub(r"(?i)^\s*(?:ENV|ARG)\s+", "", line)
        match = _assignment(declaration)
        sensitive = ((match and SECRET.search(match[1]))
                     or re.search(r"(?i)\b(?:ENV|ARG)\s+.*\b(?:password|passwd|secret|token|"
                                  r"credential|private[_-]?key|api[_-]?key)\b", line))
        lines.append(("[REDACTED assignment]" if sensitive else
                      URL_CREDENTIAL.sub(r"\1[REDACTED]@", line)) + original[len(line):])
    return "".join(lines)


def environment_contract(config, orchestration, upstream):
    """Host-authored launch identity, persisted in the signed attempt claim."""
    workflow = orchestration.get("workflow", "standalone")
    configured = config.jobs.get(JOB_ID)
    enabled = configured is not None and configured.settings.get("enabled", True)
    expected = enabled and (workflow in WORKFLOWS or JOB_ID in upstream)
    requested_mode = orchestration.get("environment_mode")
    if requested_mode not in {None, "OPTIONAL_PRIOR"}:
        raise ValueError("unsupported explicit environment mode")
    optional = requested_mode == "OPTIONAL_PRIOR"
    supplied_reference = orchestration.get("environment_reference")
    if supplied_reference is not None and (not optional or not isinstance(supplied_reference, str)
            or not re.fullmatch(r"[a-f0-9]{64}", supplied_reference)):
        raise ValueError("explicit environment reference requires optional prior mode and an exact hash")
    if optional and configured is not None and not enabled:
        raise ValueError("disabled environment producer cannot supply optional prior evidence")
    if optional and workflow in WORKFLOWS:
        raise ValueError("scheduled environment producer cannot be optional prior evidence")
    reference = upstream.get(JOB_ID)
    if optional:
        if supplied_reference is not None and reference is not None and supplied_reference != reference:
            raise ValueError("conflicting optional environment references")
        reference = supplied_reference if supplied_reference is not None else reference
        if not isinstance(reference, str) or not re.fullmatch(r"[a-f0-9]{64}", reference):
            raise ValueError("optional prior environment requires an explicitly supplied exact reference")
    mode = ("DISABLED" if configured is not None and not enabled else
            "OPTIONAL_PRIOR" if optional else "EXPECTED_CURRENT" if expected else "NOT_RUN")
    return {"schema": "appsec-review/build-environment-availability/1",
            "workflow": workflow, "expected_producer": JOB_ID if mode == "EXPECTED_CURRENT" else None,
            "mode": mode, "reference": reference,
            "reason": {"DISABLED": "explicit configuration disables the producer",
                       "NOT_RUN": "trusted standalone launch does not schedule the producer",
                       "OPTIONAL_PRIOR": "trusted standalone launch supplied optional prior evidence",
                       "EXPECTED_CURRENT": "workflow requires the current accepted producer"}[mode]}


def planning_environment_inputs(config, run_root, source_fingerprint, orchestration, upstream):
    contract = environment_contract(config, orchestration, upstream)
    required = dict(upstream)
    if contract["mode"] == "OPTIONAL_PRIOR":
        load_environment(run_root, source_fingerprint, contract)
        # Optional evidence keeps its signed reference but grants no required target lineage.
        required.pop(JOB_ID, None)
    return contract, required


def _read(run_root, identity, *, byte_limit=16 * 1024 * 1024):
    if byte_limit not in {16 * 1024 * 1024, 32 * 1024 * 1024}:
        raise ValueError("unsupported environment reader byte limit")
    path = safe_path(run_root, identity["path"])
    size = path.stat().st_size
    if not path.is_file() or size > byte_limit:
        raise ValueError("environment artifact is missing or exceeds its bound")
    data = path.read_bytes()
    if (len(data) != size or identity.get("size_bytes", size) != size
            or hashlib.sha256(data).hexdigest() != identity["sha256"]):
        raise ValueError("environment artifact identity mismatch")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("environment artifact must be an object")
    return value


def validate_environment(value):
    keys = {"schema", "source_fingerprint", "catalog_handoff_sha256", "rules", "availability",
            "coverage", "declarations", "gaps", "bounds"}
    if (set(value) != keys or value["schema"] != SCHEMA or value["rules"] != RULES
            or value["availability"] not in {"AVAILABLE", "UNAVAILABLE"}
            or value["coverage"] not in {"complete", "partial", "not_applicable"}
            or not isinstance(value["source_fingerprint"], str) or not value["source_fingerprint"]
            or not re.fullmatch(r"[a-f0-9]{64}", str(value["catalog_handoff_sha256"]))
            or not isinstance(value["declarations"], list) or not isinstance(value["gaps"], list)
            or len(value["declarations"]) > 4096 or not isinstance(value["bounds"], dict)
            or any(not isinstance(gap, str) or not gap for gap in value["gaps"])
            or value["coverage"] == "complete" and value["gaps"]):
        raise ValueError("invalid bounded environment schema")
    bounds = value["bounds"]
    settings_keys = set(asdict(BuildEnvironmentSettings()))
    if set(bounds) != settings_keys | {"inspected_scripts", "inventory_scope"}:
        raise ValueError("invalid environment coverage bounds")
    settings = parse_bounded_settings({key: bounds[key] for key in settings_keys}, BuildEnvironmentSettings)
    if (type(bounds["inspected_scripts"]) is not int
            or not 0 <= bounds["inspected_scripts"] <= settings.max_scripts
            or bounds["inventory_scope"] != "accepted inventory only; no whole-target absence claim"
            or len(value["declarations"]) > settings.max_assignments
            or value["coverage"] == "partial" and not value["gaps"]
            or value["availability"] == "UNAVAILABLE" and value["coverage"] != "partial"
            or value["coverage"] == "not_applicable" and (
                value["availability"] != "AVAILABLE" or value["declarations"] or value["gaps"]
                or bounds["inspected_scripts"])):
        raise ValueError("environment coverage does not match its bounded outcome")
    for declaration in value["declarations"]:
        if (set(declaration) != {"path", "sha256", "line", "name", "value", "status", "reason"}
                or not re.fullmatch(r"[a-f0-9]{64}", str(declaration["sha256"]))
                or not isinstance(declaration["path"], str)
                or not declaration["path"] or "\\" in declaration["path"] or ":" in declaration["path"]
                or PurePosixPath(declaration["path"]).is_absolute()
                or ".." in PurePosixPath(declaration["path"]).parts
                or PurePosixPath(declaration["path"]).as_posix() != declaration["path"]
                or declaration["status"] not in {"declared", "unknown", "redacted"}
                or type(declaration["line"]) is not int or declaration["line"] < 1
                or not isinstance(declaration["name"], str) or not isinstance(declaration["reason"], str)
                or (declaration["status"] != "declared" and declaration["value"] is not None)
                or (declaration["status"] == "declared" and (
                    not isinstance(declaration["value"], str)
                    or SECRET.search(declaration["name"])
                    or URL_CREDENTIAL.search(declaration["value"])))):
            raise ValueError("invalid bounded environment declaration")
    if value["availability"] == "UNAVAILABLE" and value["declarations"]:
        raise ValueError("unavailable environment cannot carry imported declarations")
    return value


def load_environment(run_root, source_fingerprint, contract):
    if (set(contract) != {"schema", "workflow", "expected_producer", "mode", "reference", "reason"}
            or contract["schema"] != "appsec-review/build-environment-availability/1"
            or contract["mode"] not in {"DISABLED", "NOT_RUN", "OPTIONAL_PRIOR", "EXPECTED_CURRENT"}
            or not isinstance(contract["workflow"], str) or not contract["workflow"]
            or not isinstance(contract["reason"], str) or not contract["reason"]
            or (contract["mode"] == "EXPECTED_CURRENT" and contract["expected_producer"] != JOB_ID)
            or (contract["mode"] != "EXPECTED_CURRENT" and contract["expected_producer"] is not None)
            or (contract["mode"] in {"NOT_RUN", "OPTIONAL_PRIOR"} and contract["workflow"] in WORKFLOWS)):
        raise ValueError("invalid authoritative environment launch contract")
    mode = contract["mode"]
    base = {**contract, "availability": "ABSENT" if mode == "NOT_RUN" else mode,
            "artifact": None, "evidence": None}
    if mode in {"DISABLED", "NOT_RUN"}:
        return base
    pointer_path = safe_path(run_root, "data/jobs/" + JOB_ID + "/latest.json")
    if not pointer_path.is_file():
        raise ValueError("expected environment producer has no accepted handoff")
    # Even optional prior evidence must pass all integrity checks before source staleness is considered.
    if pointer_path.stat().st_size > 65536:
        raise ValueError("environment pointer exceeds its byte bound")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    if contract["reference"] != pointer["handoff_sha256"]:
        raise ValueError("environment reference is not the accepted producer")
    handoff = decode_handoff(_read(run_root, {
        "path": pointer["handoff_path"], "sha256": pointer["handoff_sha256"]},
        byte_limit=32 * 1024 * 1024),
        run_id=run_root.name, job_id=JOB_ID)
    identity = handoff["outputs"]["environment_analysis.publish_handoff"]["artifact"]
    value = validate_environment(_read(run_root, identity))
    if handoff["source_fingerprint"] != value["source_fingerprint"]:
        raise ValueError("environment handoff and artifact source differ")
    if handoff["upstream_handoff_sha256"].get("job_target_catalog") != value["catalog_handoff_sha256"]:
        raise ValueError("environment catalog reference differs from accepted producer inputs")
    if mode == "EXPECTED_CURRENT":
        catalog_pointer = safe_path(run_root, "data/jobs/job_target_catalog/latest.json")
        if catalog_pointer.stat().st_size > 65536:
            raise ValueError("catalog pointer exceeds its byte bound")
        if json.loads(catalog_pointer.read_bytes())["handoff_sha256"] != value["catalog_handoff_sha256"]:
            raise ValueError("expected environment producer does not consume the current catalog")
    if value["source_fingerprint"] != source_fingerprint:
        if mode != "OPTIONAL_PRIOR":
            raise ValueError("expected current environment producer has the wrong source")
        return {**base, "availability": "UNAVAILABLE", "reason": "STALE optional prior source"}
    return {**base, "availability": value["availability"], "artifact": identity,
            "reason": "accepted " + value["coverage"] + " static environment",
            "evidence": value}


def analyze_environment(catalog, read_document, settings, *, clock=time.monotonic):
    started = clock()
    inventory = {item["path"]: item for item in catalog["files"]}
    selected = sorted(path for path in inventory
                      if PurePosixPath(path).suffix.lower() in SUPPORTED
                      and re.search(r"(?i)(?:env|setup|setvars|bootstrap)", PurePosixPath(path).stem))
    gaps = ["PowerShell environment scripts are not supported"] if any(
        PurePosixPath(path).suffix.lower() == ".ps1" for path in inventory) else []
    if len(selected) > settings.max_scripts:
        gaps.append("script_count_exhausted")
    pending = [(path, 0, False) for path in selected[:settings.max_scripts]]
    seen, declarations = set(), []
    while pending:
        if clock() - started >= settings.deadline_seconds:
            gaps.append("internal_environment_deadline")
            break
        path, depth, inherited_uncertainty = pending.pop(0)
        if path in seen:
            if inherited_uncertainty:
                gaps.append(f"{path}: unresolved_script_context_or_condition")
                for declaration in declarations:
                    if declaration["path"] == path and declaration["status"] != "redacted":
                        declaration.update(value=None, status="unknown", reason="unresolved_script_context_or_value")
            continue
        seen.add(path)
        item = inventory[path]
        if item.get("size_bytes", 0) > settings.max_script_bytes:
            gaps.append(f"{path}: script_byte_bound")
            continue
        payload = read_document(item, settings.max_script_bytes)
        if not isinstance(payload, bytes) or len(payload) > settings.max_script_bytes:
            raise ValueError("environment reader exceeded its byte contract")
        if hashlib.sha256(payload).hexdigest() != item["sha256"]:
            raise ValueError("accepted environment source bytes changed")
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            gaps.append(f"{path}: unsupported_script_encoding")
            continue
        # Relative sourcing and $0 depend on invocation context, not the defining file's location.
        uncertain = inherited_uncertainty or bool(re.search(
            r"(?im)^\s*(?:if\b|for\b|while\b|case\b|function\b|"
            r"[A-Za-z_][A-Za-z0-9_]*\s*\(\)|(?:source|\.)\s|call\s|"
            r"(?:cd|pushd|popd|eval|exec|setlocal|endlocal|goto|exit|return)\b)|[$`%;&|<>]", text))
        if uncertain:
            gaps.append(f"{path}: unresolved_script_context_or_condition")
        for line_number, line in enumerate(text.splitlines(), 1):
            if clock() - started >= settings.deadline_seconds:
                gaps.append("internal_environment_deadline")
                pending.clear()
                break
            source = re.match(r"(?i)^\s*(?:source|\.|call)\s+([A-Za-z0-9_./-]+)\s*$", line)
            if source:
                target = source[1]
                if (target in inventory and PurePosixPath(target).suffix.lower() in SUPPORTED
                        and ".." not in PurePosixPath(target).parts):
                    if depth >= settings.max_depth or len(seen) + len(pending) >= settings.max_scripts:
                        gaps.append(f"{path}: source_depth_or_script_bound")
                    else:
                        pending.append((target, depth + 1, True))
                else:
                    gaps.append(f"{path}: unresolved_sourcing")
            match = _assignment(line)
            if not match:
                if line.strip() and not line.lstrip().startswith(("#", "::", "REM ", "rem ")) and not source:
                    gaps.append(f"{path}: unsupported_script_statement")
                continue
            if len(declarations) >= settings.max_assignments:
                gaps.append("assignment_count_exhausted")
                pending.clear()
                break
            name, raw = match.group(1, 2)
            sensitive = bool(SECRET.search(name) or URL_CREDENTIAL.search(raw))
            literal = bool(re.fullmatch(r"[A-Za-z0-9_./:,+-]*", raw))
            if len(raw.encode()) > 2048:
                literal = False
                gaps.append(f"{path}: declaration_value_byte_bound")
            known = literal and not uncertain and not sensitive
            if not literal and not sensitive:
                gaps.append(f"{path}: unresolved_declaration_value")
            declarations.append({
                "path": path, "sha256": item["sha256"], "line": line_number,
                "name": "[REDACTED]" if sensitive else name,
                "value": raw if known else None,
                "status": "redacted" if sensitive else "declared" if known else "unknown",
                "reason": "secret_or_credential_url" if sensitive else
                          "static_literal_advisory_only" if known else "unresolved_script_context_or_value",
            })
    gaps = sorted(set(gaps))
    return validate_environment({
        "schema": SCHEMA, "source_fingerprint": catalog["source_fingerprint"],
        "catalog_handoff_sha256": catalog["catalog_handoff_sha256"], "rules": RULES,
        "availability": "AVAILABLE" if seen or not gaps else "UNAVAILABLE",
        "coverage": "partial" if gaps else "complete" if seen else "not_applicable",
        "declarations": declarations, "gaps": gaps,
        "bounds": {**asdict(settings), "inspected_scripts": len(seen),
                   "inventory_scope": "accepted inventory only; no whole-target absence claim"},
    })


def build_job():
    def validate_config(context, _result):
        if (tuple(context.config.steps) != ("environment_analysis",)
                or tuple(context.config.step("environment_analysis").tasks) != (
                    "analyze_scripts", "publish_handoff")):
            raise ValueError("environment job topology does not match configuration")
        parse_bounded_settings(context.config.settings, BuildEnvironmentSettings)

    def analyze(unit):
        from appsec_review.jobs.job_target_analysis_plan.job import _accepted_catalog
        catalog = _accepted_catalog(unit.job.run_root)
        if catalog["source_fingerprint"] != unit.job.source_fingerprint:
            raise ValueError("environment catalog source mismatch")
        settings = parse_bounded_settings(unit.job.config.settings, BuildEnvironmentSettings)

        def read_document(item, bound):
            if unit.job.target_root is None:
                raise ValueError("environment source custody is missing")
            path = safe_path(unit.job.target_root, item["path"])
            if not path.is_file():
                raise ValueError("accepted environment script is missing")
            with path.open("rb") as stream:
                return stream.read(bound + 1)

        return analyze_environment(catalog, read_document, settings)

    def publish(unit):
        value = validate_environment(unit.output("environment_analysis.analyze_scripts"))
        path = unit.unit_root / "build-environment.json"
        payload = canonical_json(value)
        if len(payload) > 16 * 1024 * 1024:
            raise ValueError("environment publication exceeds its accepted reader bound")
        atomic_bytes(path, payload)
        data = path.read_bytes()
        identity = {"path": path.relative_to(unit.job.run_root).as_posix(),
                    "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
        unit.job.events.write("BUILD_ENVIRONMENT_PUBLISHED", availability=value["availability"],
                              coverage=value["coverage"], gap_count=len(value["gaps"]),
                              artifact=identity)
        return {"schema": SCHEMA, "artifact": identity, "gaps": value["gaps"],
                "terminal_status": "COMPLETED_WITH_GAPS" if value["gaps"] else "SUCCEEDED"}

    units = (Unit("environment_analysis.analyze_scripts", analyze),
             Unit("environment_analysis.publish_handoff", publish,
                  ("environment_analysis.analyze_scripts",)))
    return Job(JOB_ID, "build_environment_analysis", UnitExecutor(units).execute,
               input_validators=(validate_config,), schema_identity=SCHEMA,
               units=units, datasets=DATASETS, consumes=CONSUMES)
