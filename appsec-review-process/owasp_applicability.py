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
from publish_job_output import validate_published


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


def _validate_universe_binding(run_id: str, request: dict[str, Any], input_manifest: dict[str, Any]) -> None:
    """ADR-0034: recheck that the request is exactly the projection of the newest accepted universe."""
    import owasp_component_routing as routing
    import owasp_universe
    universe, binding = owasp_universe.accepted(run_id)
    if request["universe"] != binding:
        raise Blocked("applicability request does not bind the newest accepted, within-budget 04-owasp-universe")
    if "component_map" in request:
        raise ValueError("a universe projection cannot also carry a component-map routing")
    universe_entry, bundles = routing.admitted_universe(input_manifest, binding, universe)
    components, rules, _gaps = routing.projection(universe, universe_entry, bundles)
    if request["components"] != components or request["rules"] != sorted(rules, key=lambda row: row["rule_id"]):
        raise Blocked("applicability request is not the exact projection of the accepted universe")


def _validate_component_binding(run_id: str, request: dict[str, Any],
                                input_manifest: dict[str, Any]) -> None:
    """Recheck the assembler's accepted component-map lineage at the T04 trust boundary."""
    if "universe" in request:
        return _validate_universe_binding(run_id, request, input_manifest)
    binding = request.get("component_map")
    if binding is None:  # Historical explicit T04 requests remain supported.
        return
    data_root = data_path(run_id)
    pointer_path = _run_file(data_root, binding["accepted_pointer_path"],
                             binding["accepted_pointer_sha256"])
    if pointer_path.relative_to(data_root).parts != ("jobs", "01-component-characterization", "accepted.json"):
        raise ValueError("component-map pointer is not the characterization accepted pointer")
    pointer = read_json(pointer_path)
    fingerprint = pointer.get("fingerprint")
    if not isinstance(fingerprint, str):
        raise Blocked("component-map accepted pointer lacks its fingerprint")
    attempt, envelope = validate_published(
        pointer_path.parent, pointer, fingerprint, expected_run_id=run_id,
        expected_job_id="01-component-characterization")
    if pointer["attempt_id"] != binding["attempt_id"]:
        raise Blocked("component-map request does not name the newest accepted attempt")
    artifact_path = _run_file(data_root, binding["artifact_path"], binding["artifact_sha256"])
    expected = attempt / "component-purpose-map.json"
    artifacts = {row.get("path"): row.get("sha256") for row in envelope.get("artifacts", [])}
    if (artifact_path.absolute() != expected.absolute() or
            artifacts.get("component-purpose-map.json") != binding["artifact_sha256"]):
        raise Blocked("component-map request artifact is not published by the accepted attempt")
    component_map = read_json(artifact_path)
    errors = validate_document(component_map, "component-purpose-map.schema.json")
    if errors:
        raise Blocked("component-map request artifact no longer validates")
    if (component_map["source_snapshot_sha256"] != binding["source_snapshot_sha256"] or
            component_map["evidence_manifest_lineage"]["generation_sha256"] != binding["generation_sha256"]):
        raise Blocked("component-map request has mixed source/generation lineage")
    entry_matches = []
    for entry in input_manifest["entries"]:
        producer = entry.get("producer") or {}
        if (entry.get("kind") == "component_map" and
                entry.get("artifact") == {"path": binding["artifact_path"],
                                           "sha256": binding["artifact_sha256"]} and
                producer.get("job_id") == "01-component-characterization" and
                producer.get("attempt_id") == binding["attempt_id"] and
                producer.get("accepted_pointer_path") == binding["accepted_pointer_path"] and
                producer.get("accepted_pointer_sha256") == binding["accepted_pointer_sha256"] and
                (entry.get("source_snapshot") or {}).get("snapshot_id") == binding["source_snapshot_sha256"]):
            entry_matches.append(entry)
    if len(entry_matches) != 1:
        raise Blocked("T03 manifest does not admit the exact bound component map")
    source_components = {row["component_id"]: row for row in component_map["functional_components"]}
    projected = {row["component_id"]: row for row in request["components"]}
    if len(projected) != len(request["components"]) or set(projected) != set(source_components):
        raise Blocked("applicability request does not project every component exactly once")
    tags = {component_id: [] for component_id in source_components}
    for tag in component_map["tag_cloud"]:
        for component_id in tag["component_ids"]:
            tags.setdefault(component_id, []).append(tag["tag"])
    for component_id, source in source_components.items():
        row = projected[component_id]
        expected_evidence_inputs = sorted(
            entry["input_id"] for entry in input_manifest["entries"]
            if (entry.get("component_scope") or {}).get("component_map") == binding and
            component_id in (entry.get("component_scope") or {}).get("component_ids", []))
        expected_roots = sorted(set(source["path_patterns"] + source["representative_locations"]))
        affected = {value for unknown in component_map["unknowns"]
                    for value in unknown["affected_component_ids"]}
        state = ("unknown" if source["confidence"] == "low" or
                 source["ownership"]["kind"] == "unknown" or source["deployability"] == "unknown"
                 else "partial" if component_id in affected or source["confidence"] == "medium"
                 else "known")
        if (row["classification_hash"] != digest(source) or
                row["name"] != source["name"] or row["input_ids"] != [entry_matches[0]["input_id"]] or
                row.get("evidence_input_ids", []) != expected_evidence_inputs or
                row["scope_status"] != "in_scope" or row["scope_authority"] is not None or
                row.get("tags") != sorted(set(tags.get(component_id, []))) or
                row.get("trust_role") != source["trust_boundary_relevance"] or
                row.get("evidence_roots") != expected_roots or row.get("classification_state") != state or
                row.get("component_type") != source["component_type"] or
                row.get("coarse_group") != source["coarse_group"] or
                row.get("deployability") != source["deployability"]):
            raise Blocked(f"{component_id}: projected classification differs from the accepted map")


def _validate_assembled_request_path(run_id: str, request_path: Path,
                                     request: dict[str, Any]) -> None:
    """Automatic requests are consumed only from the newest accepted assembler attempt."""
    if "component_map" not in request and "universe" not in request:
        return
    base = data_path(run_id, "jobs", "04-owasp-component-routing")
    pointer_path = base / "accepted.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        raise Blocked("automatic applicability request has no accepted routing assembly")
    pointer = read_json(pointer_path)
    fingerprint = pointer.get("fingerprint")
    if not isinstance(fingerprint, str):
        raise Blocked("routing assembly pointer lacks its input fingerprint")
    attempt, envelope = validate_published(
        base, pointer, fingerprint, expected_run_id=run_id,
        expected_job_id="04-owasp-component-routing")
    expected = attempt / "owasp-applicability-request.json"
    artifacts = {row.get("path"): row.get("sha256") for row in envelope.get("artifacts", [])}
    if (request_path.absolute() != expected.absolute() or
            artifacts.get("owasp-applicability-request.json") != file_hash(request_path)):
        raise Blocked("automatic applicability request is not the newest accepted assembler artifact")


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


def _validate_decision(decision: dict[str, Any], entries: dict[str, dict[str, Any]],
                       classification: frozenset[str] = frozenset()) -> None:
    """``classification`` names the bound component-map input that may positively exclude a rule's component."""
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
    classified = (any(citation["input_id"] in classification for citation in decision["citations"]) and
                  any(signal["signal_type"] == "positive_exclusion" and signal["input_id"] in classification
                      for signal in decision["signals"]))
    if status == "not_applicable" and ("positive_exclusion" not in signal_types or
                                         decision["source_completeness"] != "adequate" or not (canonical or classified)):
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


def _in_scope(component: dict[str, Any], control: dict[str, Any]) -> bool:
    """ADR-0034: a ``control_scope`` limits the component to its chapters; no scope keeps every control."""
    scope = component.get("control_scope")
    return scope is None or _domain(control) in scope["domain_ids"]


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
        "component_evidence_input_ids": component.get("evidence_input_ids", component["input_ids"]),
        "component_tags": component.get("tags", []),
        "component_trust_role": component.get("trust_role", ""),
        "component_evidence_roots": component.get("evidence_roots", []),
        "component_classification_state": component.get("classification_state", "unknown"),
        "component_type": component.get("component_type", ""),
        "component_coarse_group": component.get("coarse_group", ""),
        "component_deployability": component.get("deployability", "unknown"),
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
    # With no matching rule no decision evidence was consulted; only conflicting rules leave its completeness unknown.
    decision = {"status": "cannot_determine", "rationale": rationale, "signals": [], "citations": [],
                "source_completeness": "unknown" if rule_ids else "not_evaluated", "conditional_expression": None}
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
        evidence_ids = component.get("evidence_input_ids")
        if evidence_ids is not None:
            if len(evidence_ids) != len(set(evidence_ids)) or any(i not in entries for i in evidence_ids):
                raise ValueError(f"{component_id}: evidence inputs must be unique admitted inputs")
            for input_id in evidence_ids:
                entry = entries[input_id]
                if entry.get("use") != "canonical_evidence" or entry.get("freshness", {}).get("status") != "current":
                    raise ValueError(f"{component_id}: evidence input is not current canonical evidence")
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
        component = components[rule["component_id"]]
        # The bound classification input that may positively exclude: the component map (explicit routing)
        # or the deterministic universe's chapter decision (ADR-0034).
        kind = "asvs_universe" if "universe" in request else "component_map" if "component_map" in request else None
        bound = kind is not None and component.get("classification_state") in {"known", "partial"}
        _validate_decision(rule["decision"], entries, frozenset(
            i for i in component["input_ids"] if bound and entries[i].get("kind") == kind))
        rules.append(rule)

    selection_id = input_manifest["selection_id"]
    rows = []
    scoped = {component_id: [control for control in controls if _in_scope(component, control)]
              for component_id, component in components.items()}
    empty = sorted(component_id for component_id, values in scoped.items() if not values)
    if empty:
        raise ValueError("control_scope selects no selected control for: " + ", ".join(empty))
    for control in controls:
        for component_id in sorted(components):
            component = components[component_id]
            if not _in_scope(component, control):
                continue
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
    expected = sum(len(values) for values in scoped.values())
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
             "controls": [{"family": control["standard_family"], "id": control["control_id"],
                            "hash": digest(control)} for control in controls],
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
    if "component_map" in request:
        model["component_map"] = request["component_map"]
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
    _validate_component_binding(run_id, request, input_manifest)
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
    _validate_assembled_request_path(run_id, request_path, request)
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
