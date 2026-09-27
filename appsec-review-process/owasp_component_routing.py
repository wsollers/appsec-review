#!/usr/bin/env python3
"""Assemble the complete OWASP applicability request from accepted run evidence.

This bridge closes the hand-authored T04 request gap.  It binds the newest accepted
``01-component-characterization`` result to the newest accepted T03 OWASP lane-in manifest,
projects every functional component exactly once, and emits deterministic rules only where the
approved selection scope and a complete component classification positively match.  Ambiguity is
left unmatched so T04 emits ``cannot_determine``; this worker never invents technical N/A.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any

from execution_state import Blocked, atomic_json, data_path, digest, file_hash, identifier, read_json
import owasp_applicability
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document


JOB = "04-owasp-component-routing"
COMPONENT_JOB = "01-component-characterization"
LANE_IN_JOB = owasp_applicability.UPSTREAM_JOB
CONTRACT = "owasp-applicability-request"
REQUEST = "owasp-applicability-request.json"
ROUTING = "owasp-component-routing.json"


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise Blocked("OWASP routing: artifact path is not normalized POSIX syntax")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise Blocked("OWASP routing: artifact path escapes its run-owned root")
    return path


def _accepted_component(run_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    base = data_path(run_id, "jobs", COMPONENT_JOB)
    pointer_path = base / "accepted.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        raise Blocked("OWASP routing requires accepted 01-component-characterization")
    pointer = read_json(pointer_path)
    fingerprint = pointer.get("fingerprint")
    if not isinstance(fingerprint, str):
        raise Blocked("component accepted pointer lacks its exact input fingerprint")
    attempt, envelope = validate_published(
        base, pointer, fingerprint, expected_run_id=run_id, expected_job_id=COMPONENT_JOB)
    if envelope.get("execution_status") not in {"OK", "OK_WITH_GAPS"}:
        raise Blocked("component characterization is not an accepted successful result")
    result_path = attempt / "component-purpose-map.json"
    artifact_hashes = {row.get("path"): row.get("sha256") for row in envelope.get("artifacts", [])}
    if (not result_path.is_file() or result_path.is_symlink() or
            artifact_hashes.get("component-purpose-map.json") != file_hash(result_path)):
        raise Blocked("accepted component map is missing or no longer hash-bound")
    value = read_json(result_path)
    errors = validate_document(value, "component-purpose-map.schema.json")
    if errors:
        raise Blocked("accepted component map no longer validates: " + errors[0])
    binding = {
        "job_id": COMPONENT_JOB,
        "attempt_id": pointer["attempt_id"],
        "artifact_path": f"jobs/{COMPONENT_JOB}/attempts/{pointer['attempt_id']}/component-purpose-map.json",
        "artifact_sha256": file_hash(result_path),
        "accepted_pointer_path": f"jobs/{COMPONENT_JOB}/accepted.json",
        "accepted_pointer_sha256": file_hash(pointer_path),
        "source_snapshot_sha256": value["source_snapshot_sha256"],
        "generation_sha256": value["evidence_manifest_lineage"]["generation_sha256"],
    }
    return value, binding


def _accepted_lane_in(run_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    base = data_path(run_id, "jobs", LANE_IN_JOB, "whole")
    pointer_path = base / "accepted.json"
    latest_path = base / "latest.json"
    if not pointer_path.is_file() or not latest_path.is_file():
        raise Blocked("OWASP routing requires accepted 04-owasp-intel-lane-in")
    pointer = read_json(pointer_path)
    if (pointer.get("status") not in {"OK", "OK_WITH_GAPS"} or
            pointer.get("run_id") != run_id or pointer.get("job_id") != LANE_IN_JOB):
        raise Blocked("T03 accepted pointer identity/status mismatch")
    attempt_id = identifier(pointer.get("attempt_id"))
    if read_json(latest_path).get("attempt_id") != attempt_id:
        raise Blocked("T03 accepted pointer is not the newest attempt")
    manifest_path = base / "attempts" / attempt_id / "outputs" / "owasp-input-manifest.json"
    expected = pointer.get("artifacts", {}).get("outputs/owasp-input-manifest.json")
    if (not manifest_path.is_file() or manifest_path.is_symlink() or
            not isinstance(expected, str) or file_hash(manifest_path) != expected):
        raise Blocked("T03 accepted input manifest is missing or corrupt")
    manifest = read_json(manifest_path)
    errors = validate_document(manifest, "owasp-input-manifest.schema.json")
    if errors or manifest.get("run_id") != run_id:
        raise Blocked("T03 accepted input manifest no longer validates")
    return manifest, {
        "attempt_id": attempt_id,
        "accepted_pointer_path": f"jobs/{LANE_IN_JOB}/whole/accepted.json",
        "accepted_pointer_sha256": file_hash(pointer_path),
        "manifest_path": manifest_path.relative_to(data_path(run_id)).as_posix(),
        "manifest_sha256": expected,
    }


def _component_entry(manifest: dict[str, Any], binding: dict[str, Any]) -> dict[str, Any]:
    matches = []
    for entry in manifest["entries"]:
        producer = entry.get("producer") or {}
        if (entry.get("kind") == "component_map" and
                entry.get("artifact", {}).get("path") == binding["artifact_path"] and
                entry.get("artifact", {}).get("sha256") == binding["artifact_sha256"] and
                producer.get("job_id") == COMPONENT_JOB and
                producer.get("attempt_id") == binding["attempt_id"] and
                producer.get("accepted_pointer_path") == binding["accepted_pointer_path"] and
                producer.get("accepted_pointer_sha256") == binding["accepted_pointer_sha256"]):
            matches.append(entry)
    if len(matches) != 1:
        raise Blocked("T03 must admit exactly the newest accepted component map with exact pointer/hash lineage")
    entry = matches[0]
    snapshot = entry.get("source_snapshot")
    if not isinstance(snapshot, dict) or snapshot.get("snapshot_id") != binding["source_snapshot_sha256"]:
        raise Blocked("T03 component-map entry has mixed or absent source-generation lineage")
    if entry.get("evidence_class") != "derived_intelligence" or entry.get("use") != "locator_only":
        raise Blocked("component characterization must remain derived locator intelligence")
    return entry


def _validate_component_topology(component_map: dict[str, Any]) -> None:
    components = component_map["functional_components"]
    component_ids = [row["component_id"] for row in components]
    if len(component_ids) != len(set(component_ids)):
        raise Blocked("component map contains duplicate component identities")
    known = set(component_ids)
    assigned: dict[str, list[str]] = {component_id: [] for component_id in component_ids}
    group_ids: set[str] = set()
    for group in component_map["parallel_review_groups"]:
        if group["group_id"] in group_ids:
            raise Blocked("component map contains duplicate review-group identities")
        group_ids.add(group["group_id"])
        if len(group["component_ids"]) != len(set(group["component_ids"])):
            raise Blocked("review group duplicates a component reference")
        for component_id in group["component_ids"]:
            if component_id not in known:
                raise Blocked("review group contains an unresolved component reference")
            assigned[component_id].append(group["group_id"])
    for component in components:
        owners = assigned[component["component_id"]]
        if owners != [component["parallel_review_group"]]:
            reason = "unassigned" if not owners else "overlapping or contradictory"
            raise Blocked(f"component {component['component_id']} has {reason} review-group routing")
    for relation in component_map["component_relationships"]:
        if relation["from_component_id"] not in known or relation["to_component_id"] not in known:
            raise Blocked("component relationship contains an unresolved reference")
    for tag in component_map["tag_cloud"]:
        if len(tag["component_ids"]) != len(set(tag["component_ids"])) or set(tag["component_ids"]) - known:
            raise Blocked("component tag contains duplicate or unresolved references")


def _tags(component_map: dict[str, Any]) -> dict[str, list[str]]:
    result = {row["component_id"]: [] for row in component_map["functional_components"]}
    for tag in component_map["tag_cloud"]:
        for component_id in tag["component_ids"]:
            result[component_id].append(tag["tag"])
    return {key: sorted(set(value)) for key, value in result.items()}


def _classification_state(component: dict[str, Any], component_map: dict[str, Any]) -> str:
    affected = {component_id for row in component_map["unknowns"] for component_id in row["affected_component_ids"]}
    if (component["confidence"] == "low" or component["ownership"]["kind"] == "unknown" or
            component["deployability"] == "unknown"):
        return "unknown"
    if component["component_id"] in affected or component["confidence"] == "medium":
        return "partial"
    return "known"


def _tokens(component: dict[str, Any], tags: list[str]) -> set[str]:
    values = [component["component_type"], component["coarse_group"], component["observed_purpose"],
              component["security_control_relevance"], *component["aliases"], *tags]
    return {token for value in values for token in re.findall(r"[a-z0-9]+", value.lower())}


def _family_match(family: str, enabled_scope: list[str], tokens: set[str]) -> bool:
    scope = {token for value in enabled_scope for token in re.findall(r"[a-z0-9]+", value.lower())}
    if scope.intersection({"all", "application", "applications", "product"}):
        return True
    aliases = {
        "owasp_asvs": {"api", "backend", "server", "service", "web", "webapp", "authentication", "authorization"},
        "owasp_masvs": {"android", "ios", "mobile", "apk", "ipa"},
    }
    return bool(tokens.intersection(scope | aliases.get(family, set())))


def _component_evidence_inputs(manifest: dict[str, Any], binding: dict[str, Any],
                               component_ids: set[str]) -> dict[str, list[str]]:
    """Return canonical T03 input IDs explicitly bound to this component-map generation."""
    result = {component_id: [] for component_id in component_ids}
    for entry in manifest["entries"]:
        scope = entry.get("component_scope")
        if scope is None:
            continue
        if scope.get("component_map") != binding:
            raise Blocked(f"{entry['input_id']}: component evidence is bound to a mixed or stale generation")
        scoped = scope.get("component_ids", [])
        if len(scoped) != len(set(scoped)) or set(scoped) - component_ids:
            raise Blocked(f"{entry['input_id']}: component evidence has unresolved or duplicate scope")
        if (entry.get("admission") != "accepted_run_output" or entry.get("use") != "canonical_evidence" or
                entry.get("evidence_class") != "raw_evidence" or
                entry.get("freshness", {}).get("status") != "current" or not entry.get("producer")):
            raise Blocked(f"{entry['input_id']}: component evidence is not current accepted canonical raw evidence")
        for component_id in scoped:
            result[component_id].append(entry["input_id"])
    return {component_id: sorted(set(values)) for component_id, values in result.items()}


def assemble(run_id: str, *, reference_root: Path | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    run_id = identifier(run_id)
    component_map, component_binding = _accepted_component(run_id)
    manifest, manifest_binding = _accepted_lane_in(run_id)
    component_entry = _component_entry(manifest, component_binding)
    _validate_component_topology(component_map)
    controls, _profiles = owasp_applicability._selected_controls(
        manifest, Path(reference_root or owasp_applicability.DEFAULT_REFERENCE_ROOT))

    selections = {row["family"]: row for row in manifest["selection"]["selections"]}
    tag_map = _tags(component_map)
    evidence_inputs = _component_evidence_inputs(
        manifest, component_binding,
        {row["component_id"] for row in component_map["functional_components"]})
    components, rules, gaps = [], [], []
    for component in sorted(component_map["functional_components"], key=lambda row: row["component_id"]):
        component_id = component["component_id"]
        state = _classification_state(component, component_map)
        context = {
            "component_id": component_id,
            "name": component["name"],
            "classification_hash": digest(component),
            "input_ids": [component_entry["input_id"]],
            "evidence_input_ids": evidence_inputs[component_id],
            "scope_status": "in_scope",
            "scope_authority": None,
            "tags": tag_map[component_id],
            "trust_role": component["trust_boundary_relevance"],
            "evidence_roots": sorted(set(component["path_patterns"] + component["representative_locations"])),
            "classification_state": state,
            "component_type": component["component_type"],
            "coarse_group": component["coarse_group"],
            "deployability": component["deployability"],
        }
        components.append(context)
        if state != "known":
            gaps.append({"gap_id": "gap-" + digest((component_id, "classification"))[:20],
                         "component_id": component_id, "kind": "cannot_determine",
                         "summary": "Component classification is incomplete; OWASP targets require reviewer resolution.",
                         "rescope_required": True})
            continue
        tokens = _tokens(component, tag_map[component_id])
        matched = False
        for family in sorted({row["standard_family"] for row in controls}):
            selected = selections.get(family)
            if not selected or not _family_match(family, selected["enabled_scope"], tokens):
                continue
            matched = True
            citation = {"input_id": component_entry["input_id"],
                        "artifact_path": component_entry["artifact"]["path"],
                        "sha256": component_entry["artifact"]["sha256"],
                        "locator": f"$.functional_components[?component_id={component_id}]",
                        "observed_fact": f"Accepted characterization identifies {component['name']} as {component['component_type']}."}
            rules.append({
                "rule_id": f"auto-{component_id}-{family.replace('_', '-')}",
                "component_id": component_id,
                "selector": {"standard_family": family, "control_ids": [], "domain_ids": [], "all_controls": True},
                "decision": {"status": "applicable",
                             "rationale": "The approved OWASP selection scope positively matches the accepted component classification.",
                             "signals": [{"signal_type": "positive_presence",
                                          "fact": f"{component['component_type']} matches approved scope {selected['enabled_scope']}.",
                                          "input_id": component_entry["input_id"]}],
                             "citations": [citation], "source_completeness": "adequate",
                             "conditional_expression": None},
            })
        if not matched:
            gaps.append({"gap_id": "gap-" + digest((component_id, "selection-scope"))[:20],
                         "component_id": component_id, "kind": "cannot_determine",
                         "summary": "No approved OWASP selection scope positively matches this component; no N/A inference was made.",
                         "rescope_required": True})

    request = {
        "schema": "appsec-review/owasp-applicability-request/1.0", "run_id": run_id,
        "input_manifest": manifest_binding,
        "component_map": component_binding,
        "assigned_reviewer": {"reviewer_id": manifest["selection"]["approver"],
                              "role": "owasp-applicability-reviewer"},
        "components": components, "rules": sorted(rules, key=lambda row: row["rule_id"]), "overrides": [],
    }
    errors = validate_document(request, "owasp-applicability-request.schema.json")
    if errors:
        raise Blocked("assembled OWASP applicability request is invalid: " + errors[0])
    routing = {
        "schema": "appsec-review/owasp-component-routing/1.0", "run_id": run_id,
        "selection_id": manifest["selection_id"], "source_snapshot_sha256": component_binding["source_snapshot_sha256"],
        "generation_sha256": component_binding["generation_sha256"],
        "component_map": component_binding, "input_manifest": manifest_binding,
        "component_count": len(components), "selected_control_count": len(controls),
        "expected_target_count": len(components) * len(controls),
        "component_ids": [row["component_id"] for row in components],
        "rule_ids": [row["rule_id"] for row in request["rules"]],
        "gaps": sorted(gaps, key=lambda row: row["gap_id"]),
        "claim_limits": ["Routing does not assess or satisfy a control.",
                         "Unknown or unmatched classification remains cannot_determine and requires rescope.",
                         "No technical not_applicable decision is generated by this assembler."],
    }
    errors = validate_document(routing, "owasp-component-routing.schema.json")
    if errors:
        raise Blocked("assembled OWASP component routing is invalid: " + errors[0])
    return request, routing


def _validate_attempt(attempt: Path, expected_request: dict[str, Any], expected_routing: dict[str, Any]) -> None:
    if read_json(attempt / REQUEST) != expected_request or read_json(attempt / ROUTING) != expected_routing:
        raise Blocked("OWASP routing attempt changed after deterministic assembly")
    for value, schema in ((expected_request, "owasp-applicability-request.schema.json"),
                          (expected_routing, "owasp-component-routing.schema.json")):
        errors = validate_document(value, schema)
        if errors:
            raise Blocked("OWASP routing output no longer validates: " + errors[0])


def run(run_id: str, dagster_id: str = "standalone-owasp-component-routing", *,
        reference_root: Path | None = None, force: bool = False) -> dict[str, Any]:
    run_id = identifier(run_id)
    base = root(run_id)
    resume = f"python -B appsec-review-process/owasp_component_routing.py --run-id {run_id}"

    def derive() -> dict[str, Any]:
        request, routing = assemble(run_id, reference_root=reference_root)
        return {"request": request, "routing": routing}

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        atomic_json(attempt / REQUEST, inputs["request"])
        atomic_json(attempt / ROUTING, inputs["routing"])
        gaps = [row["summary"] for row in inputs["routing"]["gaps"]]
        status = "OK_WITH_GAPS" if gaps else "OK"
        return record_terminal_current(
            base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
            worker_kind="deterministic_python", output_contract=CONTRACT,
            input_fingerprint=fingerprint, started_at=allocation["started_at"],
            execution_status=status, summary="Complete OWASP component applicability routing assembled.",
            status_record={"process": JOB, "status": status,
                           "components": inputs["routing"]["component_count"],
                           "selected_controls": inputs["routing"]["selected_control_count"],
                           "expected_targets": inputs["routing"]["expected_target_count"]},
            artifact_paths=[REQUEST, ROUTING, "status.json"], gaps=gaps,
            pre_envelope_validate=lambda path, _status: _validate_attempt(
                path, inputs["request"], inputs["routing"]))

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="deterministic_python", output_contract=CONTRACT,
        resume_command=resume, derive_inputs=derive,
        fingerprint_inputs=lambda value: "sha256:" + digest(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}"}, force=force,
        post_validate=lambda attempt, _envelope, inputs: _validate_attempt(
            attempt, inputs["request"], inputs["routing"]),
        blocked_summary="OWASP component routing preflight did not complete.",
        failed_summary="OWASP component routing did not publish; no older request may be used.")


def request_path(run_id: str, pointer: dict[str, Any]) -> Path:
    attempt_id = identifier(pointer["attempt_id"])
    return root(identifier(run_id)) / "attempts" / attempt_id / REQUEST


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-owasp-component-routing")
    parser.add_argument("--reference-root", type=Path)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--run-applicability", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run(args.run_id, args.dagster_run_id, reference_root=args.reference_root, force=args.force)
        if args.run_applicability:
            result = {"routing": result, "applicability": owasp_applicability.build(
                args.run_id, request_path(args.run_id, result), reference_root=args.reference_root,
                force=args.force)}
    except (Blocked, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"OWASP_COMPONENT_ROUTING_BLOCKED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
