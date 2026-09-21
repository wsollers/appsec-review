#!/usr/bin/env python3
"""Partition the accepted OWASP applicability matrix into bounded deterministic work batches.

This is the bounded T05 foundation. It accounts for every T04 control/component row, routes each
applicable proof obligation through versioned policy, and emits immutable worklist and batch-plan
artifacts. It does not dispatch validators, assess controls, or execute dynamic/manual work.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
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


JOB_ID = "04-owasp-control-batcher"
UPSTREAM_JOB = "04-owasp-applicability"
REPO_ROOT = ROOT.parent
DEFAULT_REFERENCE_ROOT = REPO_ROOT / "data" / "reference"
CONFIG_ROOT = ROOT / "config" / "owasp-batching"
FIXTURE_ROOT = ROOT / "tests" / "fixtures"
CONTROL_FAMILIES = {"owasp_asvs", "owasp_masvs"}
TEST_FAMILY = "owasp_mastg"
CROSSWALK_FAMILY = "opencre"
ASSIGNED = {"applicable", "conditional"}
ACCOUNTED = {"not_applicable", "out_of_scope", "cannot_determine"}
EVIDENCE_MODES = {
    "document_or_process", "static_source", "static_config", "built_artifact", "test_evidence",
    "dynamic_runtime", "manual_inspection",
}
QUALIFIED_CASES = {
    "deterministic_order_and_ids", "row_limit_split", "component_limit_split",
    "domain_and_authorization_separation", "composite_obligation_split_and_join", "no_silent_skip",
}


def _relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"path must use nonempty POSIX syntax: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe relative path: {value!r}")
    return path


PROCESS_DIRECTORY = "appsec-review-process"


def tracked_file(relative: PurePosixPath, repo_root: Path | None = None, process_root: Path | None = None) -> Path:
    """Resolve a repository-relative identifier used inside a request or a config.

    Requests name tracked files by their repository path (``appsec-review-process/config/...``). On
    a host checkout that is ``REPO_ROOT/appsec-review-process/...``. In the Dagster code-server the
    same tree is mounted as ``/opt/process``, so ``REPO_ROOT/appsec-review-process`` does not exist
    and every T05+ worker failed there. The identifier keeps its meaning: when the repository root
    has no directory of that name, a path whose first segment is the process directory is resolved
    against the process root, whatever it is called where the code runs. Callers pass their own
    roots so that a module (or a test) that relocates them is honoured."""
    repo_root = REPO_ROOT if repo_root is None else repo_root
    process_root = ROOT if process_root is None else process_root
    if (relative.parts and relative.parts[0] == PROCESS_DIRECTORY
            and not (repo_root / PROCESS_DIRECTORY).is_dir()):
        return beneath(process_root, process_root.joinpath(*relative.parts[1:]))
    return beneath(repo_root, repo_root.joinpath(*relative.parts))


def _run_file(data_root: Path, relative: str, expected_hash: str) -> Path:
    ref = _relative(relative)
    path = beneath(data_root, data_root.joinpath(*ref.parts))
    if not path.is_file():
        raise Blocked(f"run-owned artifact is missing: {relative}")
    if file_hash(path) != expected_hash:
        raise Blocked(f"run-owned artifact hash mismatch: {relative}")
    return path


def _validate_override_log(path: Path) -> None:
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            raise Blocked(f"T04 override log has blank line {line_number}")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise Blocked(f"T04 override log line {line_number} is invalid JSON") from exc
        errors = validate_document(record, "owasp-applicability-override.schema.json")
        if errors:
            raise Blocked(f"T04 override log line {line_number} is invalid: " + "; ".join(errors))


def _load_applicability(run_id: str, reference: dict[str, Any]) -> dict[str, Any]:
    data_root = data_path(run_id)
    attempt_id = identifier(reference["attempt_id"])
    pointer_path = _run_file(data_root, reference["accepted_pointer_path"],
                             reference["accepted_pointer_sha256"])
    if pointer_path.relative_to(data_root).parts != ("jobs", UPSTREAM_JOB, "whole", "accepted.json"):
        raise ValueError("batching input pointer must be the T04 whole-scope accepted pointer")
    pointer = read_json(pointer_path)
    if (pointer.get("status") not in {"OK", "OK_WITH_GAPS"} or
            pointer.get("attempt_id") != attempt_id or pointer.get("run_id") != run_id or
            pointer.get("job_id") != UPSTREAM_JOB):
        raise Blocked("T04 accepted pointer identity/status mismatch")
    if read_json(pointer_path.with_name("latest.json")).get("attempt_id") != attempt_id:
        raise Blocked("T04 accepted pointer is not the newest attempt")

    expected_artifacts = {
        "outputs/owasp-applicability-model.json", "outputs/applicable-controls.json",
        "outputs/applicability-gaps.json", "outputs/applicability-overrides.jsonl",
    }
    if set(pointer.get("artifacts", {})) != expected_artifacts:
        raise Blocked("T04 accepted pointer has an incomplete artifact set")
    attempt = data_root / "jobs" / UPSTREAM_JOB / "whole" / "attempts" / attempt_id
    for relative, expected_hash in pointer["artifacts"].items():
        path = beneath(attempt, attempt.joinpath(*_relative(relative).parts))
        if not path.is_file() or file_hash(path) != expected_hash:
            raise Blocked(f"T04 accepted artifact is missing or corrupt: {relative}")

    model_path = _run_file(data_root, reference["model_path"], reference["model_sha256"])
    expected_model = attempt / "outputs" / "owasp-applicability-model.json"
    if model_path.absolute() != expected_model.absolute():
        raise ValueError("T04 model path does not belong to the accepted attempt")
    if pointer["artifacts"]["outputs/owasp-applicability-model.json"] != reference["model_sha256"]:
        raise Blocked("T04 pointer does not publish the requested applicability model")
    model = read_json(model_path)
    errors = validate_document(model, "owasp-applicability-model.schema.json")
    if errors:
        raise Blocked("T04 applicability model is invalid: " + "; ".join(errors))
    if (model["run_id"] != run_id or model["selection_id"] != pointer.get("selection_id") or
            model["input_fingerprint"] != pointer.get("input_fingerprint")):
        raise Blocked("T04 applicability model identity mismatch")

    applicable = read_json(attempt / "outputs" / "applicable-controls.json")
    gaps = read_json(attempt / "outputs" / "applicability-gaps.json")
    for value, schema in ((applicable, "owasp-applicable-controls.schema.json"),
                          (gaps, "owasp-applicability-gaps.schema.json")):
        errors = validate_document(value, schema)
        if errors:
            raise Blocked(f"T04 accepted {schema} no longer validates: " + "; ".join(errors))
    expected_applicable = [row for row in model["rows"] if row["applicability_status"] in ASSIGNED]
    if applicable["rows"] != expected_applicable:
        raise Blocked("T04 applicable-control projection does not match the complete model")
    target_ids = {row["target_id"] for row in model["rows"]}
    if any(gap["target_id"] not in target_ids for gap in gaps["gaps"]):
        raise Blocked("T04 applicability gaps name an unknown target")
    _validate_override_log(attempt / "outputs" / "applicability-overrides.jsonl")
    return model


def _load_batch_config(reference: dict[str, Any]) -> tuple[dict[str, Any], str]:
    relative = _relative(reference["path"])
    path = tracked_file(relative)
    if path.parent.absolute() != CONFIG_ROOT.absolute() or not path.is_file():
        raise ValueError("batch config must be a tracked file directly under the OWASP batching config directory")
    config = read_json(path)
    errors = validate_document(config, "owasp-batch-config.schema.json")
    if errors:
        raise ValueError("invalid OWASP batch config: " + "; ".join(errors))
    config_digest = digest(config)
    if config_digest != reference["config_digest"]:
        raise Blocked("OWASP batch config digest mismatch")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", config["version"]):
        raise ValueError("OWASP batch config version must be semantic numeric x.y.z")
    limits = config["limits"]
    if not 1 <= limits["max_control_target_rows"] <= 100:
        raise ValueError("max_control_target_rows must be between 1 and 100")
    if not 1 <= limits["max_components"] <= 25:
        raise ValueError("max_components must be between 1 and 25")

    fixture_id = identifier(config["qualification_fixture_id"])
    fixture_path = FIXTURE_ROOT / f"{fixture_id}.json"
    if not fixture_path.is_file():
        raise Blocked("batch config has no qualification fixture")
    fixture = read_json(fixture_path)
    if (fixture.get("schema") != "appsec-review/owasp-batch-qualification-fixture/1.0" or
            fixture.get("fixture_id") != fixture_id or fixture.get("config_id") != config["config_id"] or
            fixture.get("config_version") != config["version"] or
            fixture.get("config_digest") != config_digest or
            fixture.get("qualified_boundaries") != limits or
            set(fixture.get("required_cases", [])) != QUALIFIED_CASES):
        raise Blocked("batch config qualification fixture does not match the selected config")
    return config, config_digest


def _snapshot_root(root: Path, pin: dict[str, Any]) -> Path:
    family, edition, snapshot_id = pin["family"], pin["edition"], pin["snapshot_id"]
    if family not in CONTROL_FAMILIES | {TEST_FAMILY, CROSSWALK_FAMILY}:
        raise ValueError(f"unsupported standards catalog in applicability model: {family}")
    if not re.fullmatch(r"sha256-[0-9a-f]{16}", snapshot_id):
        raise ValueError(f"invalid reference snapshot ID: {snapshot_id!r}")
    if not edition or "/" in edition or "\\" in edition or edition in {".", ".."}:
        raise ValueError(f"invalid reference edition: {edition!r}")
    if family == CROSSWALK_FAMILY:
        return root / "opencre" / snapshot_id
    return root / "owasp" / family / edition / snapshot_id


def _load_reference_records(model: dict[str, Any], root: Path) -> tuple[
        dict[tuple[str, str], dict[str, Any]], dict[str, dict[str, Any]],
        dict[tuple[str, str], list[dict[str, Any]]]]:
    controls, tests, crosswalks = {}, {}, defaultdict(list)
    for pin in model["reference_snapshots"]:
        if pin["family"] not in CONTROL_FAMILIES | {TEST_FAMILY, CROSSWALK_FAMILY}:
            continue
        snapshot_root = _snapshot_root(root, pin)
        manifest = reference_snapshots.verify_snapshot(snapshot_root)
        if (file_hash(snapshot_root / "manifest.json") != pin["manifest_sha256"] or
                manifest["snapshot_id"] != pin["snapshot_id"]):
            raise Blocked(f"reference snapshot changed after applicability: {pin['family']}")
        catalog = read_json(snapshot_root / "normalized" / "catalog.json")
        for record in catalog["records"]:
            if record.get("record_type") == "control":
                key = (record["standard_family"], record["control_id"])
                if key in controls:
                    raise ValueError(f"duplicate control reference identity: {key}")
                controls[key] = record
            elif record.get("record_type") == "test":
                if record["test_id"] in tests:
                    raise ValueError(f"duplicate test reference identity: {record['test_id']}")
                tests[record["test_id"]] = record
            elif record.get("record_type") == "crosswalk":
                for mapping in record["mappings"]:
                    family = {"ASVS": "owasp_asvs", "MASVS": "owasp_masvs"}.get(
                        mapping["standard"].upper())
                    if family:
                        crosswalks[(family, mapping["section_id"])].append({
                            "record_id": record["record_id"], "cre_leaf_id": record["cre_leaf_id"],
                            "snapshot_id": record["source"]["snapshot_id"],
                            "source_record_hash": digest(record), "standard": mapping["standard"],
                            "section_id": mapping["section_id"], "version": mapping["version"],
                            "link_type": mapping["link_type"],
                        })

    for row in model["rows"]:
        record = controls.get((row["standard_family"], row["control_id"]))
        if (not record or digest(record) != row["source_record_hash"] or
                record["standard_version"] != row["standard_version"] or
                record["proof_obligations"] != row["proof_obligations"]):
            raise Blocked(f"T04 row no longer matches its reference control: {row['target_id']}")
    for values in crosswalks.values():
        values.sort(key=lambda value: (value["record_id"], value["section_id"], value["link_type"]))
    return controls, tests, dict(crosswalks)


def _contexts(request: dict[str, Any], model: dict[str, Any]) -> dict[str, dict[str, Any]]:
    expected_ids = {row["component_id"] for row in model["rows"]}
    contexts = {}
    classification_inputs: dict[str, set[str]] = defaultdict(set)
    for row in model["rows"]:
        classification_inputs[row["component_id"]].update(row["classification_input_ids"])
    for context in request["component_contexts"]:
        component_id = context["component_id"]
        if component_id in contexts or not all(context[key].strip() for key in
                                                ("component_id", "component_group_id", "trust_role")):
            raise ValueError(f"invalid or duplicate component context: {component_id!r}")
        roots = context["evidence_root_input_ids"]
        if len(roots) != len(set(roots)) or not set(roots).issubset(classification_inputs[component_id]):
            raise ValueError(f"{component_id}: evidence roots must be unique T04 classification inputs")
        contexts[component_id] = context
    if set(contexts) != expected_ids:
        raise ValueError("component contexts must exactly cover the T04 component set")
    return contexts


def _prepare_rules(request: dict[str, Any], component_ids: set[str]) -> list[dict[str, Any]]:
    route_ids, rules = set(), []
    for rule in request["routing_rules"]:
        route_id, selector = rule["route_id"], rule["selector"]
        if not route_id.strip() or route_id in route_ids:
            raise ValueError(f"invalid or duplicate route ID: {route_id!r}")
        route_ids.add(route_id)
        control_modes = (bool(selector["obligation_ids"]) + bool(selector["control_ids"]) +
                         bool(selector["domain_ids"]) + bool(selector["all_controls"]))
        component_modes = bool(selector["component_ids"]) + bool(selector["all_components"])
        if control_modes != 1 or component_modes != 1:
            raise ValueError(f"{route_id}: selector must choose one control and one component specificity")
        if len(selector["component_ids"]) != len(set(selector["component_ids"])) or not set(selector["component_ids"]).issubset(component_ids):
            raise ValueError(f"{route_id}: selector names duplicate or unknown components")
        if any(not value.strip() for key in ("tooling_profile_id", "validator_role")
               for value in [rule[key]]):
            raise ValueError(f"{route_id}: tooling profile and validator role are required")
        mode, boundary = rule["primary_evidence_mode"], rule["authorization_boundary"]
        if mode not in EVIDENCE_MODES:
            raise ValueError(f"{route_id}: unsupported evidence mode")
        if mode == "manual_inspection":
            raise Blocked(f"{route_id}: manual observation is not authorized")
        if mode == "dynamic_runtime":
            if boundary != "dynamic_request_only" or rule["validator_role"] != "dynamic-test-request-author":
                raise ValueError(f"{route_id}: dynamic work must be request-only and routed to its request author")
        elif boundary != "static_offline":
            raise ValueError(f"{route_id}: non-dynamic evidence must remain static/offline")
        if len(rule["linked_test_ids"]) != len(set(rule["linked_test_ids"])):
            raise ValueError(f"{route_id}: linked test IDs must be unique")
        rules.append(rule)
    return rules


def _route_priority(rule: dict[str, Any], row: dict[str, Any], obligation: dict[str, Any]) -> tuple[int, int] | None:
    selector = rule["selector"]
    if selector["standard_family"] != row["standard_family"]:
        return None
    if selector["component_ids"] and row["component_id"] not in selector["component_ids"]:
        return None
    component_priority = 2 if selector["component_ids"] else 1
    if selector["obligation_ids"]:
        control_priority = 4 if obligation["obligation_id"] in selector["obligation_ids"] else 0
    elif selector["control_ids"]:
        control_priority = 3 if row["control_id"] in selector["control_ids"] else 0
    elif selector["domain_ids"]:
        control_priority = 2 if row["domain_id"] in selector["domain_ids"] else 0
    else:
        control_priority = 1
    return (control_priority, component_priority) if control_priority else None


def _linked_tests(rule: dict[str, Any], row: dict[str, Any], tests: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rendered = []
    for test_id in sorted(rule["linked_test_ids"]):
        test = tests.get(test_id)
        if not test:
            raise ValueError(f"{rule['route_id']}: linked test is not in the pinned MASTG snapshot: {test_id}")
        if row["control_id"] not in test["covers_control_ids"]:
            raise ValueError(f"{rule['route_id']}: {test_id} does not cover {row['control_id']}")
        rendered.append({"test_id": test_id, "source_record_hash": digest(test),
                         "snapshot_id": test["source"]["snapshot_id"], "platform": test["platform"],
                         "test_modes": test["test_modes"]})
    return rendered


def _routed_obligation(row: dict[str, Any], obligation: dict[str, Any], rules: list[dict[str, Any]],
                       tests: dict[str, dict[str, Any]], matched: set[str]) -> dict[str, Any]:
    candidates = [(priority, rule) for rule in rules
                  if (priority := _route_priority(rule, row, obligation)) is not None]
    if not candidates:
        raise Blocked(f"no batch routing rule covers {row['target_id']} / {obligation['obligation_id']}")
    highest = max(priority for priority, _ in candidates)
    winners = [rule for priority, rule in candidates if priority == highest]
    if len(winners) != 1:
        raise ValueError(f"equally specific batch routes conflict for {row['target_id']} / {obligation['obligation_id']}")
    rule = winners[0]
    matched.add(rule["route_id"])
    minimum = obligation["minimum_evidence_modes"]
    if minimum and rule["primary_evidence_mode"] not in minimum:
        raise ValueError(f"{rule['route_id']}: evidence mode is below the catalog obligation policy")
    return {
        "obligation_id": obligation["obligation_id"], "text": obligation["text"],
        "evidence_classification": obligation["evidence_classification"],
        "catalog_minimum_evidence_modes": minimum,
        "primary_evidence_mode": rule["primary_evidence_mode"],
        "authorization_boundary": rule["authorization_boundary"],
        "tooling_profile_id": rule["tooling_profile_id"], "validator_role": rule["validator_role"],
        "linked_tests": _linked_tests(rule, row, tests), "route_id": rule["route_id"],
    }


def _fragment_key(row: dict[str, Any], context: dict[str, Any], obligation: dict[str, Any]) -> tuple[str, ...]:
    test_family = TEST_FAMILY if obligation["linked_tests"] else ""
    return (context["component_group_id"], context["trust_role"], row["domain_id"],
            obligation["primary_evidence_mode"], obligation["authorization_boundary"],
            obligation["tooling_profile_id"], obligation["validator_role"], row["standard_family"],
            row["standard_version"], row["profile_or_level"] or "", test_family)


def _build_outputs(request: dict[str, Any], model: dict[str, Any], config: dict[str, Any],
                   config_digest: str, tests: dict[str, dict[str, Any]],
                   crosswalks: dict[tuple[str, str], list[dict[str, Any]]]) -> tuple[dict[str, Any], dict[str, Any], bytes, str]:
    contexts = _contexts(request, model)
    rules = _prepare_rules(request, set(contexts))
    matched: set[str] = set()
    assignments, fragments_by_key = [], defaultdict(list)

    for row in sorted(model["rows"], key=lambda value: value["target_id"]):
        status = row["applicability_status"]
        assignment_id = "assignment-" + digest({"selection": model["selection_id"], "target": row["target_id"]})[:20]
        base = {
            "assignment_id": assignment_id, "target_id": row["target_id"],
            "standard_family": row["standard_family"], "standard_version": row["standard_version"],
            "profile_or_level": row["profile_or_level"], "control_id": row["control_id"],
            "component_id": row["component_id"], "domain_id": row["domain_id"],
            "applicability_status": status, "batch_ids": [], "proof_obligations": [],
            "crosswalk_lineage": crosswalks.get((row["standard_family"], row["control_id"]), []),
            "join_required": False, "source_row_hash": digest(row),
        }
        if status in ASSIGNED:
            routed = [_routed_obligation(row, obligation, rules, tests, matched)
                      for obligation in row["proof_obligations"]]
            grouped: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
            for obligation in routed:
                grouped[_fragment_key(row, contexts[row["component_id"]], obligation)].append(obligation)
            base.update(disposition="validator_assignment", proof_obligations=routed,
                        join_required=len(grouped) > 1)
            for key, obligations in sorted(grouped.items()):
                fragment_id = "fragment-" + digest({"assignment": assignment_id,
                                                     "obligations": [o["obligation_id"] for o in obligations],
                                                     "key": key})[:20]
                fragments_by_key[key].append({
                    "fragment_id": fragment_id, "assignment_id": assignment_id,
                    "target_id": row["target_id"], "control_id": row["control_id"],
                    "component_id": row["component_id"], "applicability_status": status,
                    "proof_obligations": obligations, "crosswalk_lineage": base["crosswalk_lineage"],
                    "final_control_status_authority": "obligation_fragment_only" if len(grouped) > 1 else "control_result",
                })
        elif status == "not_applicable":
            base["disposition"] = "not_applicable_accounted"
        elif status == "out_of_scope":
            base["disposition"] = "out_of_scope_accounted"
        elif status == "cannot_determine":
            base["disposition"] = "unresolved_applicability_gap"
        else:
            raise ValueError(f"unsupported T04 applicability status: {status}")
        assignments.append(base)

    unused = {rule["route_id"] for rule in rules} - matched
    if unused:
        raise ValueError("batch routing rules match no selected proof obligation: " + ", ".join(sorted(unused)))

    limits = config["limits"]
    batches, fragment_to_batch = [], {}
    for key in sorted(fragments_by_key):
        fragments = sorted(fragments_by_key[key], key=lambda value: (value["component_id"], value["target_id"], value["fragment_id"]))
        packs: list[list[dict[str, Any]]] = []
        current: list[dict[str, Any]] = []
        components: set[str] = set()
        for fragment in fragments:
            new_component = fragment["component_id"] not in components
            if current and (len(current) >= limits["max_control_target_rows"] or
                            new_component and len(components) >= limits["max_components"]):
                packs.append(current)
                current, components = [], set()
            current.append(fragment)
            components.add(fragment["component_id"])
        if current:
            packs.append(current)
        for pack in packs:
            batch_id = "batch-" + digest({"selection": model["selection_id"], "config": config_digest,
                                           "key": key, "fragments": [f["fragment_id"] for f in pack]})[:20]
            for fragment in pack:
                fragment_to_batch[fragment["fragment_id"]] = batch_id
            batches.append({"batch_id": batch_id, "key": key, "fragments": pack})

    batches.sort(key=lambda value: (value["key"], value["batch_id"]))
    rendered_batches = []
    for ordinal, batch in enumerate(batches, 1):
        key, fragments = batch["key"], batch["fragments"]
        rendered_batches.append({
            "batch_id": batch["batch_id"], "ordinal": ordinal,
            "component_group_id": key[0], "trust_role": key[1], "domain_id": key[2],
            "primary_evidence_mode": key[3], "authorization_boundary": key[4],
            "tooling_profile_id": key[5], "validator_role": key[6], "standard_family": key[7],
            "standard_version": key[8], "profile_or_level": key[9] or None,
            "linked_test_family": key[10] or None, "effective_limits": limits,
            "control_target_count": len({fragment["target_id"] for fragment in fragments}),
            "component_count": len({fragment["component_id"] for fragment in fragments}),
            "fragments": fragments, "dispatch_ready": False, "execution_authorized": False,
        })

    fragment_ids_by_assignment: dict[str, list[str]] = defaultdict(list)
    for fragments in fragments_by_key.values():
        for fragment in fragments:
            fragment_ids_by_assignment[fragment["assignment_id"]].append(fragment["fragment_id"])
    for assignment in assignments:
        assignment["batch_ids"] = sorted({fragment_to_batch[fragment_id]
                                           for fragment_id in fragment_ids_by_assignment[assignment["assignment_id"]]})
        if assignment["disposition"] == "validator_assignment" and not assignment["batch_ids"]:
            raise RuntimeError("applicable assignment has no batch")
        if assignment["disposition"] != "validator_assignment" and assignment["batch_ids"]:
            raise RuntimeError("accounted non-assignment unexpectedly has a batch")

    input_targets = {row["target_id"] for row in model["rows"]}
    output_targets = [assignment["target_id"] for assignment in assignments]
    if len(output_targets) != len(set(output_targets)) or set(output_targets) != input_targets:
        raise RuntimeError("no-silent-skip worklist accounting failed")
    counts = {status: sum(a["applicability_status"] == status for a in assignments)
              for status in ASSIGNED | ACCOUNTED}
    counts.update({"control_targets": len(assignments), "validator_assignments": sum(
        a["disposition"] == "validator_assignment" for a in assignments), "batches": len(rendered_batches)})
    config_identity = {"config_id": config["config_id"], "version": config["version"],
                       "config_digest": config_digest, "effective_limits": limits,
                       "qualification_fixture_id": config["qualification_fixture_id"]}
    worklist = {
        "schema": "appsec-review/owasp-validation-worklist/1.0", "run_id": request["run_id"],
        "selection_id": model["selection_id"], "applicability_fingerprint": model["input_fingerprint"],
        "batch_config": config_identity, "counts": counts, "assignments": assignments,
        "claim_limits": [
            "This artifact partitions work and does not assess a control or establish a finding.",
            "Static batches cannot satisfy dynamic, deployed, runtime, or manual proof obligations.",
            "No batch is dispatch-ready until the T06 handoff contract is implemented.",
        ],
    }
    manifest = {
        "schema": "appsec-review/owasp-batch-manifest/1.0", "run_id": request["run_id"],
        "selection_id": model["selection_id"], "applicability_fingerprint": model["input_fingerprint"],
        "batch_config": config_identity, "batch_count": len(rendered_batches), "batches": rendered_batches,
        "dispatch_state": "handoff_not_implemented", "dynamic_execution": False,
    }
    summary = (
        "# OWASP batch summary\n\n"
        f"- Selection: `{model['selection_id']}`\n"
        f"- Batch configuration: `{config['config_id']}@{config['version']}`\n"
        f"- Control/component targets accounted: {len(assignments)}\n"
        f"- Validator assignments: {counts['validator_assignments']}\n"
        f"- Deterministic batches: {len(rendered_batches)}\n"
        f"- Not applicable: {counts['not_applicable']}\n"
        f"- Out of scope: {counts['out_of_scope']}\n"
        f"- Unresolved applicability: {counts['cannot_determine']}\n"
        "- Dispatch: disabled until the T06 handoff contract exists.\n"
        "- Dynamic execution: disabled; dynamic-runtime batches are request-drafting only.\n"
    ).encode()
    for value, schema in ((worklist, "owasp-validation-worklist.schema.json"),
                          (manifest, "owasp-batch-manifest.schema.json")):
        errors = validate_document(value, schema)
        if errors:
            raise ValueError(f"generated {schema} is invalid: " + "; ".join(errors))
    fingerprint = digest({"request": request, "applicability": model["input_fingerprint"],
                          "applicability_model_sha256": request["applicability"]["model_sha256"],
                          "config_digest": config_digest})
    return worklist, manifest, summary, fingerprint


def _validate_request(run_id: str, request: dict[str, Any], reference_root: Path) -> tuple[dict[str, Any], dict[str, Any], bytes, str]:
    errors = validate_document(request, "owasp-batch-request.schema.json")
    if errors:
        raise ValueError("invalid OWASP batch request:\n" + "\n".join(errors))
    if request["run_id"] != run_id:
        raise ValueError("OWASP batch request run mismatch")
    model = _load_applicability(run_id, request["applicability"])
    config, config_digest = _load_batch_config(request["batch_config"])
    _, tests, crosswalks = _load_reference_records(model, reference_root)
    return _build_outputs(request, model, config, config_digest, tests, crosswalks)


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
        raise Blocked("OWASP batch accepted/latest attempt mismatch")
    attempt = beneath(base, base / "attempts" / attempt_id)
    expected = {"outputs/owasp-validation-worklist.json", "outputs/owasp-batch-manifest.json",
                "outputs/batch-summary.md"}
    if set(pointer.get("artifacts", {})) != expected:
        raise Blocked("OWASP batch accepted pointer has incomplete artifacts")
    for relative, expected_hash in pointer["artifacts"].items():
        path = beneath(attempt, attempt.joinpath(*_relative(relative).parts))
        if not path.is_file() or file_hash(path) != expected_hash:
            raise Blocked("OWASP batch accepted artifact is missing or corrupt")
    for name, schema in (("owasp-validation-worklist.json", "owasp-validation-worklist.schema.json"),
                         ("owasp-batch-manifest.json", "owasp-batch-manifest.schema.json")):
        if validate_document(read_json(attempt / "outputs" / name), schema):
            raise Blocked(f"OWASP batch accepted {name} no longer validates")
    return pointer


def build(run_id: str, request_path: Path | None = None, *, reference_root: Path | None = None,
          force: bool = False, clock=lambda: datetime.now(timezone.utc)) -> dict[str, Any]:
    run_id = identifier(run_id)
    root = run_path(run_id)
    if not (root / "run-status.json").is_file():
        raise Blocked("create the run through run_process.py --start first")
    request_path = beneath(root, Path(request_path or (root / "inputs" / "owasp-batch-request.json")))
    request = read_json(request_path)
    instant = clock()
    if instant.tzinfo is None:
        raise ValueError("batching clock must be timezone-aware")
    reference_root = Path(reference_root or DEFAULT_REFERENCE_ROOT)
    generated = _validate_request(run_id, request, reference_root)
    worklist, manifest, summary, fingerprint = generated
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
                        {"status": "OK", "checks": ["T04 acceptance", "reference control hashes",
                                                       "qualified batch config", "complete routing",
                                                       "dynamic/manual boundary"]})
            output_dir = attempt / "outputs"
            atomic_json(output_dir / "owasp-validation-worklist.json", worklist)
            atomic_json(output_dir / "owasp-batch-manifest.json", manifest)
            atomic_bytes(output_dir / "batch-summary.md", summary)
            if read_json(request_path) != request:
                raise Blocked("OWASP batch request changed during construction")
            if _validate_request(run_id, request, reference_root) != generated:
                raise Blocked("OWASP batch inputs changed during construction")
            output_paths = [output_dir / "owasp-validation-worklist.json",
                            output_dir / "owasp-batch-manifest.json", output_dir / "batch-summary.md"]
            artifacts = {path.relative_to(attempt).as_posix(): file_hash(path) for path in output_paths}
            atomic_json(attempt / "validation" / "post.json",
                        {"status": "OK", "schema_validation": "PASS", "no_silent_skip": "PASS",
                         "bounded_batches": "PASS", "artifacts": artifacts})
            has_gaps = any(a["applicability_status"] in {"conditional", "cannot_determine"}
                           for a in worklist["assignments"])
            status = "OK_WITH_GAPS" if has_gaps else "OK"
            atomic_json(attempt / "status.json", {**started, "status": status, "ended_at": now(),
                                                   "artifacts": artifacts})
            event(attempt / "logs" / "events.jsonl", "END", status=status, run_id=run_id,
                  job_id=JOB_ID, attempt_id=attempt_id)
            pointer = {"status": status, "run_id": run_id, "job_id": JOB_ID,
                       "attempt_id": attempt_id, "input_fingerprint": fingerprint,
                       "selection_id": worklist["selection_id"], "artifacts": artifacts,
                       "accepted_at": now()}
            atomic_json(base / "accepted.json", pointer)
            return {**pointer, "reused": False}
        except BaseException as exc:
            atomic_json(attempt / "status.json", {**started, "status": "FAILED", "ended_at": now(),
                                                   "error_type": type(exc).__name__, "error": str(exc)})
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
        print(f"OWASP_BATCHING_BLOCKED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
