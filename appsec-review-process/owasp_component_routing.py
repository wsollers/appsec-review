#!/usr/bin/env python3
"""Project the accepted OWASP universe into the T04 applicability request (ADR-0034).

The job id stays; the routing is no longer decided here. ``04-owasp-universe`` (deterministic Python)
already decided one target per ASVS 5.0.0 chapter. This job binds the newest accepted universe to the
newest accepted T03 lane-in manifest that admits it (``asvs-universe`` as locator-only derived
intelligence, every ``asvs-participants-V<n>`` bundle as canonical evidence) and projects every
chapter target exactly once as a synthetic component ``asvs-V<n>`` whose ``control_scope`` is that
chapter, so T04 enumerates only the chapter's L1+L2 controls (253 rows across the 17 chapters):

* ``participating`` -> one ``applicable`` chapter rule citing the canonical participants bundle;
* ``not_applicable`` -> one ``not_applicable`` chapter rule citing the universe decision;
* ``gap`` -> one ``cannot_determine`` chapter rule carrying the universe reason (a visible gap).

Nothing here reads component names, tags or the model's lanes; the component map is report context.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from execution_state import Blocked, atomic_json, data_path, digest, file_hash, identifier, read_json
import owasp_applicability
import owasp_universe
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document


JOB = "04-owasp-component-routing"
COMPONENT_JOB = "01-component-characterization"
LANE_IN_JOB = owasp_applicability.UPSTREAM_JOB
CONTRACT = "owasp-applicability-request"
REQUEST = "owasp-applicability-request.json"
ROUTING = "owasp-component-routing.json"
FAMILY = "owasp_asvs"
REVIEWER_ROLE = "owasp-applicability-reviewer"


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _accepted_component(run_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """The accepted component map (report context only) and its binding."""
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


def admitted_universe(manifest: dict[str, Any], binding: dict[str, Any],
                      universe: dict[str, Any]) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """The T03 entries that admit exactly this universe and every participating chapter's bundle."""
    attempt = f"jobs/{owasp_universe.JOB}/whole/attempts/{binding['attempt_id']}/"

    def produced(entry: dict[str, Any]) -> bool:
        producer = entry.get("producer") or {}
        return (entry.get("admission") == "accepted_run_output" and producer.get("job_id") == owasp_universe.JOB and
                producer.get("attempt_id") == binding["attempt_id"] and
                producer.get("accepted_pointer_path") == binding["accepted_pointer_path"] and
                producer.get("accepted_pointer_sha256") == binding["accepted_pointer_sha256"] and
                (entry.get("source_snapshot") or {}).get("snapshot_id") == binding["source_snapshot_sha256"] and
                entry.get("freshness", {}).get("status") == "current")

    universes = [entry for entry in manifest["entries"] if entry.get("kind") == owasp_universe.UNIVERSE_KIND]
    if (len(universes) != 1 or universes[0]["input_id"] != owasp_universe.UNIVERSE_INPUT or not produced(universes[0]) or
            universes[0]["artifact"] != {"path": binding["artifact_path"], "sha256": binding["artifact_sha256"]} or
            universes[0]["evidence_class"] != "derived_intelligence" or universes[0]["use"] != "locator_only"):
        raise Blocked("T03 must admit exactly the newest accepted 04-owasp-universe as locator-only derived intelligence")
    expected = {target["chapter_id"]: target["evidence_bundle"] for target in universe["targets"]
                if target["evidence_bundle"] is not None}
    bundles = {}
    for entry in manifest["entries"]:
        if entry.get("kind") != owasp_universe.BUNDLE_KIND:
            continue
        chapter = entry["input_id"].removeprefix("asvs-participants-")
        bundle = expected.get(chapter)
        if (bundle is None or chapter in bundles or entry["input_id"] != bundle["input_id"] or not produced(entry) or
                entry["artifact"] != {"path": attempt + bundle["path"], "sha256": bundle["sha256"]} or
                entry["evidence_class"] != "raw_evidence" or entry["use"] != "canonical_evidence"):
            raise Blocked(f"{entry['input_id']}: participants bundle is not the accepted universe's canonical evidence")
        bundles[chapter] = entry
    if set(bundles) != set(expected):
        raise Blocked("T03 does not admit every participating chapter's participants bundle")
    return universes[0], bundles


def _citation(entry: dict[str, Any], locator: str, fact: str) -> dict[str, Any]:
    return {"input_id": entry["input_id"], "artifact_path": entry["artifact"]["path"],
            "sha256": entry["artifact"]["sha256"], "locator": locator, "observed_fact": fact}


def projection(universe: dict[str, Any], universe_entry: dict[str, Any],
               bundles: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Components, rules and gaps for every chapter target; T04 recomputes this to verify a request."""
    components, rules, gaps = [], [], []
    for target in universe["targets"]:
        chapter, component_id, decision = target["chapter_id"], target["target_id"], target["decision"]
        locator = f"$.targets[?target_id={component_id}]"
        bundle = bundles.get(chapter)
        components.append({
            "component_id": component_id, "name": f"ASVS 5.0.0 {chapter} {target['chapter_name']}",
            "classification_hash": digest(target), "input_ids": [universe_entry["input_id"]],
            "evidence_input_ids": [bundle["input_id"]] if bundle else [],
            "scope_status": "in_scope", "scope_authority": None,
            "control_scope": {"domain_ids": [chapter]},
            "tags": [decision, target["reason_code"]], "trust_role": "asvs-chapter",
            "evidence_roots": [row["path"] for row in target["files"]],
            "classification_state": "unknown" if decision == "gap" else "known",
            "component_type": "asvs-chapter", "coarse_group": decision, "deployability": "source-snapshot",
        })
        universe_citation = _citation(universe_entry, locator,
                                      f"The universe decides {chapter} {decision} ({target['reason_code']}).")
        if decision == "participating":
            files = len(target["files"])
            fact = f"{len(target['participants'])} participating symbol(s) in {files} file(s) are cited for {chapter}."
            decided = {"status": "applicable",
                       "rationale": "Validated participation records cite code that implements, enforces or consumes "
                                    f"{chapter} controls; every L1+L2 control of the chapter applies to that code.",
                       "signals": [{"signal_type": "positive_presence", "fact": fact, "input_id": bundle["input_id"]}],
                       "citations": [_citation(bundle, "$.excerpts", fact), universe_citation],
                       "source_completeness": "adequate", "conditional_expression": None}
        elif decision == "not_applicable":
            decided = {"status": "not_applicable", "rationale": target["reason"],
                       "signals": [{"signal_type": "positive_exclusion",
                                    "fact": f"{target['reason_code']}: {target['reason']}",
                                    "input_id": universe_entry["input_id"]}],
                       "citations": [universe_citation], "source_completeness": "adequate",
                       "conditional_expression": None}
        else:
            decided = {"status": "cannot_determine", "rationale": target["reason"], "signals": [],
                       "citations": [universe_citation], "source_completeness": "unknown",
                       "conditional_expression": None}
            gaps.append({"gap_id": "gap-" + digest((component_id, target["reason_code"]))[:20],
                         "component_id": component_id, "kind": "cannot_determine",
                         "summary": f"{chapter}: {target['reason']}", "rescope_required": True})
        rules.append({"rule_id": f"universe-{component_id}", "component_id": component_id,
                      "selector": {"standard_family": FAMILY, "control_ids": [], "domain_ids": [chapter],
                                   "all_controls": False},
                      "decision": decided})
    return components, rules, gaps


def assemble(run_id: str, *, reference_root: Path | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    run_id = identifier(run_id)
    universe, binding = owasp_universe.accepted(run_id)
    manifest, manifest_binding = _accepted_lane_in(run_id)
    universe_entry, bundles = admitted_universe(manifest, binding, universe)
    controls, _profiles = owasp_applicability._selected_controls(
        manifest, Path(reference_root or owasp_applicability.DEFAULT_REFERENCE_ROOT))
    components, rules, gaps = projection(universe, universe_entry, bundles)
    scoped = {row["component_id"]: sum(control["standard_family"] == FAMILY and
                                      owasp_applicability._domain(control) in row["control_scope"]["domain_ids"]
                                      for control in controls) for row in components}
    if not all(scoped.values()):
        raise Blocked("OWASP routing: a chapter target selects no ASVS control of the approved selection")
    for family in sorted({row["standard_family"] for row in controls} - {FAMILY}):
        masvs = next((row for row in universe["families"] if row["family"] == family), None)
        decision = f"{masvs['decision']} ({masvs['reason_code']}): {masvs['reason']}" if masvs else "not decided"
        gaps.append({"gap_id": "gap-" + digest((family, "not-projected"))[:20], "component_id": None,
                     "kind": "family_not_projected",
                     "summary": f"{family} is selected but the universe projects ASVS chapters only; universe decision {decision}",
                     "rescope_required": True})
    request = {
        "schema": "appsec-review/owasp-applicability-request/1.0", "run_id": run_id,
        "input_manifest": manifest_binding, "universe": binding,
        "assigned_reviewer": {"reviewer_id": manifest["selection"]["approver"], "role": REVIEWER_ROLE},
        "components": components, "rules": sorted(rules, key=lambda row: row["rule_id"]), "overrides": [],
    }
    errors = validate_document(request, "owasp-applicability-request.schema.json")
    if errors:
        raise Blocked("projected OWASP applicability request is invalid: " + errors[0])
    routing = {
        "schema": "appsec-review/owasp-component-routing/2.0", "run_id": run_id,
        "selection_id": manifest["selection_id"], "source_snapshot_sha256": binding["source_snapshot_sha256"],
        "universe": binding, "input_manifest": manifest_binding,
        "component_count": len(components), "selected_control_count": len(controls),
        "expected_target_count": sum(scoped.values()),
        "planned_validator_calls": binding["planned_validator_calls"],
        "component_ids": [row["component_id"] for row in components],
        "rule_ids": [row["rule_id"] for row in request["rules"]],
        "gaps": sorted(gaps, key=lambda row: row["gap_id"]),
        "claim_limits": ["Routing does not assess or satisfy a control.",
                         "Every chapter target is the accepted 04-owasp-universe decision; nothing is inferred here.",
                         "A universe gap stays cannot_determine and requires rescope; it is never not_applicable."],
    }
    errors = validate_document(routing, "owasp-component-routing.schema.json")
    if errors:
        raise Blocked("projected OWASP component routing is invalid: " + errors[0])
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
            execution_status=status, summary="Accepted OWASP universe projected into the applicability request.",
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
        blocked_summary="OWASP universe projection preflight did not complete.",
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
