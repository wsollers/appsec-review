#!/usr/bin/env python3
"""Build the complete OWASP control/component applicability model.

This is the bounded T04 foundation. It consumes the accepted T03 lane-in manifest, enumerates the
selected ASVS/MASVS control catalogs against explicit components, applies deterministic rules and
append-only reviewer overrides, and preserves every unresolved target as a gap. It does not assess
control satisfaction, create findings, dispatch personas, or execute dynamic work.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re
import sys
import uuid
from typing import Any

from execution_state import (
    ROOT, Blocked, Lock, atomic_bytes, atomic_json, beneath, data_path, digest, emergency, event,
    file_hash, identifier, now, read_json, run_path,
)
import reference_snapshots
from schema_validate import validate_document


JOB_ID = "04-owasp-applicability"
UPSTREAM_JOB = "04-owasp-intel-lane-in"
REPO_ROOT = ROOT.parent
DEFAULT_REFERENCE_ROOT = REPO_ROOT / "data" / "reference"
CONTROL_FAMILIES = {"owasp_asvs", "owasp_masvs"}
STATUSES = {"applicable", "conditional", "not_applicable", "cannot_determine"}


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a nonempty string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp must include timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


def _relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"run-owned path must use nonempty POSIX syntax: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe run-owned path: {value!r}")
    return path


def _run_file(data_root: Path, relative: str, expected_hash: str) -> Path:
    ref = _relative(relative)
    path = beneath(data_root, data_root.joinpath(*ref.parts))
    if not path.is_file():
        raise Blocked(f"run-owned artifact is missing: {relative}")
    if file_hash(path) != expected_hash:
        raise Blocked(f"run-owned artifact hash mismatch: {relative}")
    return path


def _load_input_manifest(run_id: str, reference: dict[str, Any]) -> dict[str, Any]:
    data_root = data_path(run_id)
    attempt_id = identifier(reference["attempt_id"])
    pointer = _run_file(data_root, reference["accepted_pointer_path"],
                        reference["accepted_pointer_sha256"])
    pointer_parts = pointer.relative_to(data_root).parts
    if pointer_parts != ("jobs", UPSTREAM_JOB, "whole", "accepted.json"):
        raise ValueError("applicability input pointer must be the T03 whole-scope accepted pointer")
    accepted = read_json(pointer)
    if (accepted.get("status") not in {"OK", "OK_WITH_GAPS"} or
            accepted.get("attempt_id") != attempt_id or accepted.get("run_id") != run_id or
            accepted.get("job_id") != UPSTREAM_JOB):
        raise Blocked("T03 accepted pointer identity/status mismatch")
    latest = read_json(pointer.with_name("latest.json"))
    if latest.get("attempt_id") != attempt_id:
        raise Blocked("T03 accepted pointer is not the newest attempt")
    manifest_path = _run_file(data_root, reference["manifest_path"], reference["manifest_sha256"])
    expected = data_root / "jobs" / UPSTREAM_JOB / "whole" / "attempts" / attempt_id / "outputs" / "owasp-input-manifest.json"
    if manifest_path.absolute() != expected.absolute():
        raise ValueError("T03 manifest path does not belong to the accepted attempt")
    artifact_key = manifest_path.relative_to(expected.parents[1]).as_posix()
    if accepted.get("artifacts", {}).get(artifact_key) != reference["manifest_sha256"]:
        raise Blocked("T03 pointer does not publish the requested input manifest")
    manifest = read_json(manifest_path)
    errors = validate_document(manifest, "owasp-input-manifest.schema.json")
    if errors:
        raise Blocked("T03 input manifest is invalid: " + "; ".join(errors))
    if manifest["run_id"] != run_id or manifest["selection_id"] != manifest["selection"]["selection_id"]:
        raise Blocked("T03 input manifest run/selection mismatch")
    return manifest


def _reference_root(root: Path, pin: dict[str, Any]) -> Path:
    family, edition, snapshot_id = pin["family"], pin["edition"], pin["snapshot_id"]
    if family not in CONTROL_FAMILIES:
        raise ValueError(f"not a control family: {family}")
    if not re.fullmatch(r"sha256-[0-9a-f]{16}", snapshot_id):
        raise ValueError(f"invalid control snapshot ID: {snapshot_id!r}")
    if not edition or "/" in edition or "\\" in edition or edition in {".", ".."}:
        raise ValueError(f"invalid control edition: {edition!r}")
    return root / "owasp" / family / edition / snapshot_id


def _selected_controls(input_manifest: dict[str, Any], root: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    controls, profiles = [], {}
    for pin in input_manifest["reference_snapshots"]:
        if pin["family"] not in CONTROL_FAMILIES:
            continue
        snapshot_root = _reference_root(root, pin)
        manifest = reference_snapshots.verify_snapshot(snapshot_root)
        manifest_path = snapshot_root / "manifest.json"
        if (file_hash(manifest_path) != pin["manifest_sha256"] or manifest != pin["manifest"] or
                manifest["snapshot_id"] != pin["snapshot_id"]):
            raise Blocked(f"control reference pin changed: {pin['family']}")
        catalog = read_json(snapshot_root / "normalized" / "catalog.json")
        profile = pin["profile_or_level"]
        profiles[pin["family"]] = profile
        for record in catalog["records"]:
            if record.get("record_type") != "control":
                continue
            if pin["family"] == "owasp_asvs":
                if profile != "L2":
                    raise Blocked("T04 supports the approved ASVS L2 baseline only")
                if not set(record.get("profiles", [])).intersection({"L1", "L2"}):
                    continue
            controls.append(record)
    controls.sort(key=lambda row: (row["standard_family"], row["control_id"]))
    identities = [(row["standard_family"], row["control_id"]) for row in controls]
    if not controls:
        raise Blocked("selection contains no ASVS/MASVS controls for applicability")
    if len(identities) != len(set(identities)):
        raise ValueError("selected control catalogs contain duplicate identities")
    return controls, profiles


def _entry_map(input_manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = {entry["input_id"]: entry for entry in input_manifest["entries"]}
    if len(entries) != len(input_manifest["entries"]):
        raise ValueError("T03 input manifest contains duplicate input IDs")
    return entries


def _validate_citations(citations: list[dict[str, Any]], entries: dict[str, dict[str, Any]]) -> bool:
    canonical = False
    for citation in citations:
        if not citation["locator"].strip() or not citation["observed_fact"].strip():
            raise ValueError("applicability citations require locator and observed fact")
        entry = entries.get(citation["input_id"])
        if not entry:
            raise ValueError(f"citation names unknown admitted input: {citation['input_id']}")
        if (citation["artifact_path"] != entry["artifact"]["path"] or
                citation["sha256"] != entry["artifact"]["sha256"]):
            raise ValueError(f"citation does not match admitted artifact: {citation['input_id']}")
        canonical = canonical or bool(entry.get("may_support_control_status"))
    return canonical


def _validate_decision(decision: dict[str, Any], entries: dict[str, dict[str, Any]]) -> None:
    if decision["status"] not in STATUSES or not decision["rationale"].strip():
        raise ValueError("applicability decision needs a supported status and rationale")
    signal_types = set()
    for signal in decision["signals"]:
        if not signal["fact"].strip() or signal["input_id"] not in entries:
            raise ValueError("applicability signal needs a fact and admitted input")
        signal_types.add(signal["signal_type"])
    canonical = _validate_citations(decision["citations"], entries)
    status = decision["status"]
    if status == "applicable" and ("positive_presence" not in signal_types or not decision["citations"]):
        raise ValueError("applicable requires positive presence and a citation")
    if status == "conditional" and ("unresolved_condition" not in signal_types or
                                      not decision.get("conditional_expression")):
        raise ValueError("conditional requires an unresolved condition and expression")
    if status == "not_applicable" and ("positive_exclusion" not in signal_types or
                                         decision["source_completeness"] != "adequate" or not canonical):
        raise ValueError("not_applicable requires positive exclusion, adequate completeness, and canonical evidence")
    if status != "conditional" and decision.get("conditional_expression") is not None:
        raise ValueError("only conditional applicability may have a conditional expression")


def _domain(control: dict[str, Any]) -> str:
    group = control.get("group", {})
    return str(group.get("chapter_id") or group.get("category") or "ungrouped")


def _rule_priority(rule: dict[str, Any], control: dict[str, Any]) -> int:
    selector = rule["selector"]
    if selector["standard_family"] != control["standard_family"]:
        return 0
    modes = bool(selector["control_ids"]) + bool(selector["domain_ids"]) + bool(selector["all_controls"])
    if modes != 1:
        raise ValueError(f"{rule['rule_id']}: selector must choose exactly one specificity")
    if selector["control_ids"]:
        return 3 if control["control_id"] in selector["control_ids"] else 0
    if selector["domain_ids"]:
        return 2 if _domain(control) in selector["domain_ids"] else 0
    return 1


def _target_id(selection_id: str, control: dict[str, Any], component: dict[str, Any]) -> str:
    value = {"selection_id": selection_id, "family": control["standard_family"],
             "version": control["standard_version"], "control_id": control["control_id"],
             "component_id": component["component_id"]}
    return "target-" + digest(value)[:20]


def _base_row(selection_id: str, control: dict[str, Any], component: dict[str, Any],
              profile: str | None) -> dict[str, Any]:
    return {
        "target_id": _target_id(selection_id, control, component), "selection_id": selection_id,
        "standard_family": control["standard_family"], "standard_version": control["standard_version"],
        "profile_or_level": profile, "control_id": control["control_id"],
        "control_title": control["title"], "domain_id": _domain(control),
        "source_record_hash": digest(control), "component_id": component["component_id"],
        "proof_obligations": control["proof_obligations"],
        "component_name": component["name"], "classification_hash": component["classification_hash"],
        "classification_input_ids": component["input_ids"], "override_ids": [],
        "rescope_state": "none", "invalidated_result_ids": [], "rescope_actions": [],
    }


def _decision_row(base: dict[str, Any], decision: dict[str, Any], source: str,
                  rule_ids: list[str], scope_authority=None) -> dict[str, Any]:
    return {**base, "applicability_status": decision["status"], "rationale": decision["rationale"],
            "signals": decision["signals"], "citations": decision["citations"],
            "source_completeness": decision["source_completeness"],
            "conditional_expression": decision["conditional_expression"],
            "decision_source": source, "rule_ids": rule_ids, "scope_authority": scope_authority}


def _unresolved(base: dict[str, Any], rationale: str, rule_ids: list[str]) -> dict[str, Any]:
    decision = {"status": "cannot_determine", "rationale": rationale, "signals": [],
                "citations": [], "source_completeness": "unknown", "conditional_expression": None}
    return _decision_row(base, decision, "unresolved", rule_ids)


def _build(request: dict[str, Any], input_manifest: dict[str, Any], controls: list[dict[str, Any]],
           profiles: dict[str, str | None], instant: datetime) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes, str]:
    entries = _entry_map(input_manifest)
    components, component_ids = {}, set()
    for component in request["components"]:
        component_id = component["component_id"]
        if not component_id.strip() or component_id in component_ids:
            raise ValueError(f"invalid or duplicate component ID: {component_id!r}")
        component_ids.add(component_id)
        if not component["name"].strip() or len(component["classification_hash"]) != 64:
            raise ValueError(f"{component_id}: invalid name or classification hash")
        if len(component["input_ids"]) != len(set(component["input_ids"])) or any(i not in entries for i in component["input_ids"]):
            raise ValueError(f"{component_id}: classification inputs must be unique admitted inputs")
        authority = component["scope_authority"]
        if component["scope_status"] == "out_of_scope":
            if not authority or not authority["actor"].strip() or not authority["rationale"].strip():
                raise ValueError(f"{component_id}: out_of_scope requires named authority and rationale")
            if authority["actor"] != input_manifest["selection"]["approver"]:
                raise ValueError(f"{component_id}: out_of_scope authority must be the selection owner")
            _parse_time(authority["decided_at"])
        elif authority is not None:
            raise ValueError(f"{component_id}: in-scope component cannot carry exclusion authority")
        components[component_id] = component

    rules, rule_ids, matched_rules = [], set(), set()
    for rule in request["rules"]:
        if not rule["rule_id"].strip() or rule["rule_id"] in rule_ids:
            raise ValueError(f"invalid or duplicate rule ID: {rule['rule_id']!r}")
        rule_ids.add(rule["rule_id"])
        if rule["component_id"] not in components:
            raise ValueError(f"{rule['rule_id']}: unknown component")
        if components[rule["component_id"]]["scope_status"] != "in_scope":
            raise ValueError(f"{rule['rule_id']}: rules cannot override engagement out_of_scope")
        _validate_decision(rule["decision"], entries)
        rules.append(rule)

    selection_id = input_manifest["selection_id"]
    rows = []
    for control in controls:
        for component_id in sorted(components):
            component = components[component_id]
            base = _base_row(selection_id, control, component, profiles[control["standard_family"]])
            if component["scope_status"] == "out_of_scope":
                authority = component["scope_authority"]
                row = {**base, "applicability_status": "out_of_scope",
                       "rationale": authority["rationale"], "signals": [], "citations": [],
                       "source_completeness": "unknown", "conditional_expression": None,
                       "decision_source": "scope_authority", "rule_ids": [],
                       "scope_authority": authority}
            else:
                candidates = []
                for rule in rules:
                    if rule["component_id"] != component_id:
                        continue
                    priority = _rule_priority(rule, control)
                    if priority:
                        candidates.append((priority, rule))
                        matched_rules.add(rule["rule_id"])
                if not candidates:
                    row = _unresolved(base, "No deterministic applicability rule matched this target.", [])
                else:
                    highest = max(priority for priority, _ in candidates)
                    winners = [rule for priority, rule in candidates if priority == highest]
                    if len(winners) != 1:
                        row = _unresolved(base, "Equally specific applicability rules conflict; reviewer resolution is required.",
                                          [rule["rule_id"] for rule in winners])
                    else:
                        winner = winners[0]
                        row = _decision_row(base, winner["decision"], "deterministic_rule", [winner["rule_id"]])
            rows.append(row)
    unused = rule_ids - matched_rules
    if unused:
        raise ValueError("applicability rules match no selected target: " + ", ".join(sorted(unused)))

    row_map = {(row["standard_family"], row["control_id"], row["component_id"]): row for row in rows}
    override_ids, rendered_overrides, override_times = set(), [], {}
    assigned = request["assigned_reviewer"]
    if not assigned["reviewer_id"].strip():
        raise ValueError("assigned applicability reviewer identity is required")
    for override in request["overrides"]:
        if not override["override_id"].strip() or override["override_id"] in override_ids:
            raise ValueError(f"invalid or duplicate override ID: {override['override_id']!r}")
        override_ids.add(override["override_id"])
        if override["reviewer"] != assigned:
            raise ValueError(f"{override['override_id']}: override actor is not the assigned reviewer")
        decided_at = _parse_time(override["decided_at"])
        key = (override["standard_family"], override["control_id"], override["component_id"])
        row = row_map.get(key)
        if not row:
            raise ValueError(f"{override['override_id']}: override target does not exist")
        if row["applicability_status"] == "out_of_scope":
            raise ValueError(f"{override['override_id']}: reviewer cannot override engagement scope")
        if override["prior_status"] != row["applicability_status"]:
            raise ValueError(f"{override['override_id']}: prior status does not match append-only history")
        _validate_decision(override["decision"], entries)
        if not override["decision"]["citations"]:
            raise ValueError(f"{override['override_id']}: reviewer override requires a citation")
        if key in override_times and decided_at <= override_times[key]:
            raise ValueError(f"{override['override_id']}: override timestamps must advance per target")
        override_times[key] = decided_at
        if override["invalidated_result_ids"] and not override["rescope_actions"]:
            raise ValueError(f"{override['override_id']}: invalidated results require bounded rescope actions")
        decision = override["decision"]
        row.update(applicability_status=decision["status"], rationale=decision["rationale"],
                   signals=decision["signals"], citations=decision["citations"],
                   source_completeness=decision["source_completeness"],
                   conditional_expression=decision["conditional_expression"],
                   decision_source="reviewer_override", scope_authority=None)
        row["override_ids"].append(override["override_id"])
        row["invalidated_result_ids"].extend(override["invalidated_result_ids"])
        row["rescope_actions"].extend(override["rescope_actions"])
        if row["invalidated_result_ids"] or row["rescope_actions"]:
            row["rescope_state"] = "required"
        rendered_overrides.append(override)

    rows.sort(key=lambda row: (row["standard_family"], row["control_id"], row["component_id"]))
    expected = len(controls) * len(components)
    if len(rows) != expected or len({row["target_id"] for row in rows}) != expected:
        raise RuntimeError("no-silent-target applicability accounting failed")
    for index, row in enumerate(rows):
        errors = validate_document(row, "owasp-applicability-row.schema.json")
        if errors:
            raise ValueError(f"generated applicability row {index} is invalid: " + "; ".join(errors))

    gaps = []
    for row in rows:
        if row["applicability_status"] == "conditional":
            kind = "conditional_applicability"
        elif row["applicability_status"] == "cannot_determine":
            kind = "rule_conflict" if len(row["rule_ids"]) > 1 else "cannot_determine"
        else:
            kind = None
        if kind:
            gaps.append({"gap_id": "gap-" + digest({"target": row["target_id"], "kind": kind})[:20],
                         "target_id": row["target_id"], "kind": kind, "summary": row["rationale"]})
        if row["rescope_state"] == "required":
            gaps.append({"gap_id": "gap-" + digest({"target": row["target_id"], "kind": "rescope"})[:20],
                         "target_id": row["target_id"], "kind": "rescope_required",
                         "summary": "Applicability changed and bounded reassessment is required."})
    counts = {status: sum(row["applicability_status"] == status for row in rows)
              for status in ("applicable", "conditional", "not_applicable", "cannot_determine", "out_of_scope")}
    basis = {"request": request, "t03_input_fingerprint": input_manifest["input_fingerprint"],
             "controls": [{"family": row["standard_family"], "id": row["control_id"],
                            "hash": row["source_record_hash"]} for row in rows[::len(components)]],
             "components": request["components"]}
    fingerprint = digest(basis)
    reference_snapshots = [{key: pin[key] for key in ("family", "edition", "profile_or_level",
                                                        "snapshot_id", "manifest_sha256")}
                           for pin in input_manifest["reference_snapshots"]]
    model = {"schema": "appsec-review/owasp-applicability-model/1.0", "run_id": request["run_id"],
             "selection_id": selection_id, "input_fingerprint": fingerprint,
             "generated_at": instant.isoformat(), "assigned_reviewer": assigned,
             "reference_snapshots": reference_snapshots,
             "counts": {"selected_controls": len(controls), "components": len(components),
                        "control_targets": len(rows), **counts}, "rows": rows,
             "claim_limits": ["Applicability is not control satisfaction, a finding, severity, exploitability, or certification.",
                              "out_of_scope is an engagement boundary and is not technical not_applicable.",
                              "cannot_determine and conditional targets remain visible gaps."]}
    applicable = {"schema": "appsec-review/owasp-applicable-controls/1.0", "run_id": request["run_id"],
                  "selection_id": selection_id,
                  "rows": [row for row in rows if row["applicability_status"] in {"applicable", "conditional"}]}
    gap_output = {"schema": "appsec-review/owasp-applicability-gaps/1.0", "run_id": request["run_id"],
                  "selection_id": selection_id, "gaps": gaps}
    overrides_jsonl = b"".join((json.dumps(value, sort_keys=True) + "\n").encode() for value in rendered_overrides)
    for value, schema in ((model, "owasp-applicability-model.schema.json"),
                          (applicable, "owasp-applicable-controls.schema.json"),
                          (gap_output, "owasp-applicability-gaps.schema.json")):
        errors = validate_document(value, schema)
        if errors:
            raise ValueError(f"generated {schema} is invalid: " + "; ".join(errors))
    return model, applicable, gap_output, overrides_jsonl, fingerprint


def _validate_request(run_id: str, request: dict[str, Any], reference_root: Path,
                      instant: datetime) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes, str]:
    errors = validate_document(request, "owasp-applicability-request.schema.json")
    if errors:
        raise ValueError("invalid OWASP applicability request:\n" + "\n".join(errors))
    if request["run_id"] != run_id:
        raise ValueError("applicability request run mismatch")
    input_manifest = _load_input_manifest(run_id, request["input_manifest"])
    controls, profiles = _selected_controls(input_manifest, reference_root)
    return _build(request, input_manifest, controls, profiles, instant)


def _base(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB_ID, "whole")


def _reusable(base: Path, fingerprint: str) -> dict[str, Any] | None:
    if not (base / "accepted.json").is_file() or not (base / "latest.json").is_file():
        return None
    pointer = read_json(base / "accepted.json")
    if pointer.get("status") not in {"OK", "OK_WITH_GAPS"} or pointer.get("input_fingerprint") != fingerprint:
        return None
    attempt_id = identifier(pointer["attempt_id"])
    if read_json(base / "latest.json").get("attempt_id") != attempt_id:
        raise Blocked("OWASP applicability accepted/latest attempt mismatch")
    attempt = beneath(base, base / "attempts" / attempt_id)
    expected_artifacts = {
        "outputs/owasp-applicability-model.json", "outputs/applicable-controls.json",
        "outputs/applicability-gaps.json", "outputs/applicability-overrides.jsonl",
    }
    if set(pointer.get("artifacts", {})) != expected_artifacts:
        raise Blocked("OWASP applicability accepted pointer has incomplete artifacts")
    for relative, expected_hash in pointer["artifacts"].items():
        path = beneath(attempt, attempt.joinpath(*_relative(relative).parts))
        if not path.is_file() or file_hash(path) != expected_hash:
            raise Blocked("OWASP applicability accepted artifact is missing or corrupt")
    model = read_json(attempt / "outputs" / "owasp-applicability-model.json")
    if model.get("input_fingerprint") != fingerprint or validate_document(model, "owasp-applicability-model.schema.json"):
        raise Blocked("OWASP applicability accepted model no longer validates")
    return pointer


def build(run_id: str, request_path: Path | None = None, *, reference_root: Path | None = None,
          force: bool = False, clock=lambda: datetime.now(timezone.utc)) -> dict[str, Any]:
    run_id = identifier(run_id)
    root = run_path(run_id)
    if not (root / "run-status.json").is_file():
        raise Blocked("create the run through run_process.py --start first")
    request_path = beneath(root, Path(request_path or (root / "inputs" / "owasp-applicability-request.json")))
    request = read_json(request_path)
    instant = clock()
    if instant.tzinfo is None:
        raise ValueError("applicability clock must be timezone-aware")
    instant = instant.astimezone(timezone.utc)
    reference_root = Path(reference_root or DEFAULT_REFERENCE_ROOT)
    generated = _validate_request(run_id, request, reference_root, instant)
    model, applicable, gaps, overrides_jsonl, fingerprint = generated
    base = _base(run_id)
    with Lock(base / "job.lock"):
        if not force:
            reused = _reusable(base, fingerprint)
            if reused:
                return {**reused, "reused": True}
        attempt_id = uuid.uuid4().hex
        attempt = beneath(base, base / "attempts" / attempt_id)
        attempt.mkdir(parents=True, exist_ok=False)
        started = {"status": "RUNNING", "run_id": run_id, "job_id": JOB_ID,
                   "attempt_id": attempt_id, "input_fingerprint": fingerprint, "started_at": now()}
        atomic_json(base / "latest.json", {"attempt_id": attempt_id, "updated_at": now()})
        atomic_json(base / "accepted.json", {"status": "PENDING", "attempt_id": attempt_id,
                                               "input_fingerprint": fingerprint})
        try:
            atomic_json(attempt / "status.json", started)
            atomic_bytes(attempt / "logs" / "stdout.log", b"")
            atomic_bytes(attempt / "logs" / "stderr.log", b"")
            event(attempt / "logs" / "events.jsonl", "START", run_id=run_id, job_id=JOB_ID,
                  attempt_id=attempt_id, input_fingerprint=fingerprint)
            atomic_json(attempt / "inputs.json", request)
            atomic_json(attempt / "validation" / "pre.json",
                        {"status": "OK", "checks": ["T03 acceptance", "control catalogs", "component scope",
                                                       "decision evidence", "override authority"],
                         "input_fingerprint": fingerprint})
            output_dir = attempt / "outputs"
            paths = {
                "owasp-applicability-model.json": model,
                "applicable-controls.json": applicable,
                "applicability-gaps.json": gaps,
            }
            for name, value in paths.items():
                atomic_json(output_dir / name, value)
            atomic_bytes(output_dir / "applicability-overrides.jsonl", overrides_jsonl)
            if read_json(request_path) != request:
                raise Blocked("OWASP applicability request changed during model construction")
            rechecked = _validate_request(run_id, request, reference_root, instant)
            if rechecked != generated:
                raise Blocked("OWASP applicability inputs changed during model construction")
            artifacts = {path.relative_to(attempt).as_posix(): file_hash(path)
                         for path in [*(output_dir / name for name in paths),
                                      output_dir / "applicability-overrides.jsonl"]}
            atomic_json(attempt / "validation" / "post.json",
                        {"status": "OK", "schema_validation": "PASS", "no_silent_target": "PASS",
                         "artifacts": artifacts})
            status = "OK_WITH_GAPS" if gaps["gaps"] else "OK"
            terminal = {**started, "status": status, "ended_at": now(), "artifacts": artifacts}
            atomic_json(attempt / "status.json", terminal)
            event(attempt / "logs" / "events.jsonl", "END", status=status, run_id=run_id,
                  job_id=JOB_ID, attempt_id=attempt_id)
            pointer = {"status": status, "run_id": run_id, "job_id": JOB_ID,
                       "attempt_id": attempt_id, "input_fingerprint": fingerprint,
                       "selection_id": model["selection_id"], "artifacts": artifacts,
                       "accepted_at": now()}
            atomic_json(base / "accepted.json", pointer)
            return {**pointer, "reused": False}
        except BaseException as exc:
            failure = {**started, "status": "FAILED", "ended_at": now(),
                       "error_type": type(exc).__name__, "error": str(exc)}
            atomic_json(attempt / "status.json", failure)
            try:
                event(attempt / "logs" / "events.jsonl", "FAILURE", status="FAILED",
                      error_type=type(exc).__name__, run_id=run_id, job_id=JOB_ID,
                      attempt_id=attempt_id)
            except BaseException as diagnostic_error:
                emergency(diagnostic_error)
            atomic_json(base / "accepted.json", {"status": "FAILED", "attempt_id": attempt_id,
                                                   "input_fingerprint": fingerprint})
            raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--reference-root", type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = build(args.run_id, args.request, reference_root=args.reference_root, force=args.force)
    except (Blocked, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"OWASP_APPLICABILITY_BLOCKED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
