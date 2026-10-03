#!/usr/bin/env python3
"""T11-T13 nominal deterministic OWASP join, report, and candidate-route core.

The only entry authority is ``owasp_dispatch.load_verified_accounting``.  The loader then follows
that verified attempt to the exact T04/T05/T06/T07 artifacts it names and rechecks every byte.
The join never executes work, changes applicability, improves a validator status, or creates a
finding, severity, runtime, remediation, or compliance claim.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
from typing import Any, Mapping

from execution_state import Blocked, atomic_bytes, atomic_json, data_path, digest, file_hash
import owasp_batching
import owasp_applicability
import owasp_dispatch as dispatch
import owasp_validator_result
import pool_specification as ps
from schema_validate import validate_document

JOB_ID = "04-owasp-join-report"
MATRIX = "owasp-control-status-matrix.json"
GAPS = "owasp-coverage-gaps.json"
DYNAMIC = "owasp-dynamic-test-requests.json"
ROUTES = "owasp-candidate-promotion-routes.json"
SUMMARY = "owasp-workbench-summary.md"
ASSESSMENTS = frozenset(owasp_validator_result.ASSESSMENTS)
APPLICABLE = frozenset({"applicable", "conditional"})
PROHIBITED_KEYS = frozenset({"finding", "findings", "severity", "cvss", "exploitability",
    "runtime_state", "observed_runtime", "compliance", "certification", "remediation_status"})
PROHIBITED_TEXT = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    r"\bverified\s+finding\b", r"\bconfirmed\s+(?:finding|vulnerability)\b",
    r"\bseverity\s*(?::|is)\s*(?:critical|high|medium|low)\b",
    r"\bobserved\s+runtime\b", r"\b(?:is|are)\s+(?:compliant|certified)\b",
    r"\b(?:is|has been)\s+(?:fixed|remediated)\b"))


def _load_t07(run_id: str, cell: Any, accounting_cell: Mapping[str, Any]) -> dict[str, Any]:
    validation = accounting_cell["validation"]
    base = data_path(run_id, "jobs", owasp_validator_result.JOB_ID, cell.batch_id)
    pointer_path, latest_path = base / "accepted.json", base / "latest.json"
    pointer_bytes = dispatch._read_regular(base, pointer_path)
    latest_bytes = dispatch._read_regular(base, latest_path)
    pointer, latest = ps.parse_document(pointer_bytes), ps.parse_document(latest_bytes)
    attempt_id = validation["attempt_id"]
    if (pointer.get("status") not in owasp_validator_result.SUCCESS_TERMINALS or
            pointer.get("attempt_id") != attempt_id or latest.get("attempt_id") != attempt_id or
            pointer.get("handoff_id") != cell.handoff_id or
            dispatch._sha_hex(pointer_bytes) != validation["accepted_pointer_sha256"]):
        raise Blocked(f"{JOB_ID}: T07 result is not the exact newest accepted result for cell {cell.ordinal}")
    attempt = base / "attempts" / attempt_id
    expected = pointer.get("artifacts", {})
    required = {
        "outputs/control-assessment-result.json", "outputs/result-validation.json",
        "outputs/result-summary.md", "outputs/proposed-dynamic-test-candidates.json",
        "outputs/candidate-verification-routes.json",
    }
    if set(expected) != required:
        raise Blocked(f"{JOB_ID}: T07 artifact set is incomplete for cell {cell.ordinal}")
    artifact_bytes = {}
    for relative, sha256 in expected.items():
        path = attempt.joinpath(*relative.split("/"))
        try:
            content = dispatch._read_regular(attempt, path)
        except Exception as error:
            raise Blocked(f"{JOB_ID}: T07 artifact cannot be read for cell {cell.ordinal}") from error
        if dispatch._sha_hex(content) != sha256:
            raise Blocked(f"{JOB_ID}: T07 artifact changed for cell {cell.ordinal}")
        artifact_bytes[relative] = content
    result = ps.parse_document(artifact_bytes["outputs/control-assessment-result.json"])
    if (validate_document(result, "owasp-control-assessment-result.schema.json") or
            expected["outputs/control-assessment-result.json"] != validation["result_sha256"] or
            result["batch_identity"]["batch_id"] != cell.batch_id or
            result["handoff_identity"]["handoff_id"] != cell.handoff_id):
        raise Blocked(f"{JOB_ID}: T07 result identity is stale or contradictory for cell {cell.ordinal}")
    return result


def load_verified_inputs(run_id: str, *, facts: dispatch.DispatchFacts) -> dict[str, Any]:
    """Load only after T10's public deep verifier accepts the newest accounting."""
    accounting = dispatch.thaw(dispatch.load_verified_accounting(run_id, facts=facts))
    attempt = dispatch._base(run_id) / "attempts" / accounting["attempt_id"]
    request = ps.parse_document(dispatch._read_regular(attempt, attempt / dispatch.INPUTS_FILE))
    plan = dispatch.load_plan(run_id, request, facts)
    if plan.fingerprint != accounting["input_fingerprint"]:
        raise Blocked(f"{JOB_ID}: verified accounting and re-derived plan differ")

    _, _, _, handoff_request = dispatch._publication(run_id, plan.data_root, request["handoffs"])
    worklist_path = plan.data_root.joinpath(*handoff_request["batching"]["worklist_path"].split("/"))
    batch_attempt = worklist_path.parent.parent
    batch_request = ps.parse_document(dispatch._read_regular(batch_attempt, batch_attempt / "inputs.json"))
    model = owasp_batching._load_applicability(run_id, batch_request["applicability"])
    model_path = plan.data_root.joinpath(*batch_request["applicability"]["model_path"].split("/"))
    applicability_attempt = model_path.parent.parent
    applicability_request = ps.parse_document(dispatch._read_regular(
        applicability_attempt, applicability_attempt / "inputs.json"))
    input_manifest = owasp_applicability._load_input_manifest(
        run_id, applicability_request["input_manifest"])
    if input_manifest["selection_id"] != model["selection_id"]:
        raise Blocked(f"{JOB_ID}: T03 selection and T04 model differ")
    if len(model["rows"]) != len(plan.worklist["assignments"]):
        raise Blocked(f"{JOB_ID}: applicability/worklist row population differs")
    by_target = {row["target_id"]: row for row in model["rows"]}
    if len(by_target) != len(model["rows"]):
        raise Blocked(f"{JOB_ID}: duplicate applicability target")
    for assignment in plan.worklist["assignments"]:
        row = by_target.get(assignment["target_id"])
        if row is None or digest(row) != assignment["source_row_hash"]:
            raise Blocked(f"{JOB_ID}: worklist row is not the exact T04 row")

    accounting_cells = {item["cell_ordinal"]: item for item in accounting["cells"]}
    results = {}
    for cell in plan.cells:
        item = accounting_cells[cell.ordinal]
        if item["valid_result"]:
            results[cell.ordinal] = _load_t07(run_id, cell, item)
    return {"accounting": accounting, "plan": plan, "applicability": model, "results": results,
        "input_manifest": input_manifest,
        "input_manifest_sha256": applicability_request["input_manifest"]["manifest_sha256"],
        "applicability_model_sha256": file_hash(model_path)}


def _join_status(applicability: str, disposition: str, fragments: list[dict[str, Any]]) -> str:
    if applicability == "not_applicable": return "not_applicable"
    if applicability == "out_of_scope": return "out_of_scope"
    if applicability == "cannot_determine": return "cannot_determine"
    if disposition not in {"deferred_to_validated_results", "deferred_with_request_only_fragments"} or not fragments:
        return "not_assessed"
    authorities = [item["final_control_status"] for item in fragments
                   if item["final_control_status_authority"] == "control_result"]
    if authorities:
        if len(authorities) != 1 or authorities[0] is None:
            raise Blocked(f"{JOB_ID}: joined row has conflicting final-control authorities")
        return authorities[0]
    statuses = [item["assessment_status"] for item in fragments]
    if all(status == "satisfied" for status in statuses): return "satisfied"
    for status in ("not_assessed", "human_decision_required", "dynamic_test_required", "cannot_verify"):
        if status in statuses: return status
    if "partially_satisfied" in statuses or ("not_satisfied" in statuses and "satisfied" in statuses):
        return "partially_satisfied"
    if statuses and all(status == "not_satisfied" for status in statuses): return "not_satisfied"
    return "partially_satisfied"


def _citation_map(results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    found = {}
    for result in results:
        for fragment in result["fragment_results"]:
            for obligation in fragment["proof_obligation_results"]:
                for citation in [*obligation["evidence_citations"], *obligation["counterevidence_citations"]]:
                    prior = found.setdefault(citation["citation_id"], citation)
                    if prior != citation:
                        raise Blocked(f"{JOB_ID}: one citation id names contradictory evidence")
    return found


def _row_dynamic_candidates(assignment: Mapping[str, Any], fragments: list[dict[str, Any]],
                            results: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Attribute candidates through the exact row fragment and obligation that names them."""
    fragment_ids = {item["fragment_id"] for item in fragments}
    obligations = {(fragment["fragment_id"], obligation["obligation_id"]): obligation
                   for fragment in fragments for obligation in fragment["proof_obligation_results"]}
    referenced = {}
    for key, obligation in obligations.items():
        for candidate_id in obligation["dynamic_candidate_ids"]:
            prior = referenced.setdefault(candidate_id, key)
            if prior != key:
                raise Blocked(f"{JOB_ID}: dynamic candidate is ambiguously attributed to multiple obligations")
    occurrences = {}
    for result in results:
        for candidate in result["dynamic_test_candidates"]:
            occurrences.setdefault(candidate["candidate_id"], []).append(candidate)
    attributed, missing = [], []
    for candidate_id, (fragment_id, obligation_id) in sorted(referenced.items()):
        matches = occurrences.get(candidate_id, [])
        if not matches:
            missing.append(candidate_id)
            continue
        if len(matches) != 1:
            raise Blocked(f"{JOB_ID}: dynamic candidate identity is ambiguous across results")
        candidate = matches[0]
        expected = (fragment_id, assignment["target_id"], assignment["control_id"],
                    assignment["component_id"], obligation_id)
        actual = (candidate["fragment_id"], candidate["target_id"], candidate["control_id"],
                  candidate["component_id"], candidate["obligation_id"])
        if actual != expected:
            raise Blocked(f"{JOB_ID}: dynamic candidate attribution contradicts its row or obligation")
        attributed.append(candidate)
    for candidates in occurrences.values():
        for candidate in candidates:
            if candidate["fragment_id"] in fragment_ids and candidate["candidate_id"] not in referenced:
                missing.append(candidate["candidate_id"])
    return attributed, sorted(set(missing))


def _gap(gaps: dict, kind: str, row_index: int, statement: str, *, citations=(), results=()) -> str:
    """One gap per (kind, statement); rows, citations and results sharing it accumulate on that gap."""
    gap_id = "gap-" + digest({"kind": kind, "statement": statement})[:20]
    gap = gaps.setdefault(gap_id, {"gap_id": gap_id, "kind": kind, "row_indices": [], "statement": statement,
                                   "citation_ids": [], "result_ids": []})
    gap["row_indices"] = sorted({*gap["row_indices"], row_index})
    gap["citation_ids"] = sorted({*gap["citation_ids"], *citations})
    gap["result_ids"] = sorted({*gap["result_ids"], *results})
    return gap_id


def _reject_promoted_claims(value: Any, path: str = "$") -> None:
    """Reject semantic promotion even when hidden in an otherwise allowed string or key."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = key.lower().replace("-", "_")
            if normalized in PROHIBITED_KEYS and item not in (False, None, [], {}):
                raise Blocked(f"{JOB_ID}: prohibited promoted claim at {path}.{key}")
            _reject_promoted_claims(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_promoted_claims(item, f"{path}[{index}]")
    elif isinstance(value, str) and any(pattern.search(value) for pattern in PROHIBITED_TEXT):
        raise Blocked(f"{JOB_ID}: prohibited promoted claim text at {path}")


def derive(inputs: dict[str, Any]) -> dict[str, Any]:
    accounting, plan, model = inputs["accounting"], inputs["plan"], inputs["applicability"]
    manifest = inputs["input_manifest"]
    source_rows = {row["target_id"]: row for row in model["rows"]}
    accounting_rows = {row["row_index"]: row for row in accounting["rows"]}
    matrix_rows, gaps, dynamic_by_id, promotion_candidates = [], {}, {}, []
    for index, assignment in enumerate(plan.worklist["assignments"]):
        source = source_rows[assignment["target_id"]]
        dispatch_row = accounting_rows[index]
        result_by_id, fragments = {}, []
        for fragment_ref in dispatch_row["fragments"]:
            result = inputs["results"].get(fragment_ref["cell_ordinal"])
            if result is None:
                continue
            result_by_id[result["result_id"]] = result
            fragments.extend(item for item in result["fragment_results"]
                             if item["assignment_id"] == assignment["assignment_id"])
        results = [result_by_id[key] for key in sorted(result_by_id)]
        status = _join_status(source["applicability_status"], dispatch_row["row_disposition"], fragments)
        gap_ids = []
        if source["applicability_status"] in {"conditional", "cannot_determine"}:
            gap_ids.append(_gap(gaps, "applicability", index, source["rationale"]))
        if source["source_completeness"] in {"partial", "unknown"}:
            gap_ids.append(_gap(gaps, "source_version", index,
                f"Source completeness is {source['source_completeness']}."))
        if source["rescope_state"] == "required":
            gap_ids.append(_gap(gaps, "rescope", index, "; ".join(source["rescope_actions"])))
        if status == "not_assessed":
            gap_ids.append(_gap(gaps, "execution", index,
                f"No valid joined assessment: {dispatch_row['row_disposition']}."))
        result_ids = [item["result_id"] for item in results]
        citations = _citation_map(results)
        row_dynamic, unattributed_dynamic = _row_dynamic_candidates(assignment, fragments, results)
        for candidate_id in unattributed_dynamic:
            gap_ids.append(_gap(gaps, "dynamic_manual", index,
                f"Dynamic candidate {candidate_id} is missing or lacks exact row/obligation attribution.",
                results=result_ids))
        for candidate in row_dynamic:
            prior = dynamic_by_id.setdefault(candidate["candidate_id"], candidate)
            if prior != candidate: raise Blocked(f"{JOB_ID}: duplicate dynamic request id differs")
        for result in results:
            for text in result["evidence_gaps"] + result["unresolved_conditions"]:
                gap_ids.append(_gap(gaps, "evidence", index, text, results=result_ids))
            for dissent in result["dissent"]:
                if not dissent["resolved"]:
                    gap_ids.append(_gap(gaps, "dissent", index, dissent["summary"],
                                        citations=dissent["citation_ids"], results=result_ids))
            for fragment in result["fragment_results"]:
                if fragment["assignment_id"] != assignment["assignment_id"]: continue
                for obligation in fragment["proof_obligation_results"]:
                    for text in obligation["evidence_gaps"] + obligation["unresolved_conditions"]:
                        gap_ids.append(_gap(gaps, "evidence", index, text,
                            citations=[c["citation_id"] for c in obligation["evidence_citations"]], results=result_ids))
                    for contradiction in obligation["contradictions"]:
                        if contradiction["material"] and not contradiction["resolved"]:
                            gap_ids.append(_gap(gaps, "contradiction", index, contradiction["summary"],
                                               citations=contradiction["citation_ids"], results=result_ids))
            if status in {"not_satisfied", "partially_satisfied"}:
                for route in result["candidate_verification_routes"]:
                    if route["target_id"] != assignment["target_id"]: continue
                    if not route["hypothesis"].strip() or re.fullmatch(
                            r"(?i)(?:the )?(?:control|checklist)(?: is| was)? (?:failed|not satisfied)\.?",
                            route["hypothesis"].strip()):
                        gap_ids.append(_gap(gaps, "promotion", index,
                            "Bare checklist status has no concrete mechanism or impact hypothesis.", results=result_ids))
                        continue
                    cited = [citations.get(cid) for cid in route["evidence_citation_ids"]]
                    if not cited or any(item is None or item["source_kind"] in {"crosswalk", "locator"} for item in cited):
                        gap_ids.append(_gap(gaps, "promotion", index,
                            "Candidate route lacks canonical cited mechanism evidence.", results=result_ids))
                        continue
                    promotion_candidates.append((index, assignment, source, result, route, cited))
        matrix_rows.append({"row_index": index, "assignment_id": assignment["assignment_id"],
            "target_id": assignment["target_id"], "standard_family": assignment["standard_family"],
            "standard_version": assignment["standard_version"], "profile_or_level": assignment["profile_or_level"],
            "control_id": assignment["control_id"], "component_id": assignment["component_id"],
            "domain_id": assignment["domain_id"], "applicability_status": source["applicability_status"],
            "applicability_rationale": source["rationale"], "applicability_citations": source["citations"],
            "decision_source": source["decision_source"], "override_ids": source["override_ids"],
            "source_completeness": source["source_completeness"], "rescope_state": source["rescope_state"],
            "rescope_actions": source["rescope_actions"], "invalidated_result_ids": source["invalidated_result_ids"],
            "crosswalk_lineage": dispatch.thaw(assignment["crosswalk_lineage"]),
            "batch_ids": list(assignment["batch_ids"]),
            "proof_obligations": dispatch.thaw(assignment["proof_obligations"]),
            "dispatch_disposition": dispatch_row["row_disposition"],
            "joined_status": status, "assessment_results": results,
            "dynamic_candidate_ids": [item["candidate_id"] for item in row_dynamic],
            "gap_ids": sorted(set(gap_ids)), "dissent_ids": sorted({x["dissent_id"] for r in results for x in r["dissent"]}),
            "candidate_route_ids": []})

    grouped = {}
    for index, assignment, source, result, route, citations in promotion_candidates:
        aliases = assignment["crosswalk_lineage"]
        alias_key = sorted({item["cre_leaf_id"] for item in aliases})
        key = digest({"component": assignment["component_id"], "hypothesis": " ".join(route["hypothesis"].lower().split()),
                      "citations": sorted(item["artifact_sha256"] for item in citations), "crosswalk": alias_key})
        entry = grouped.setdefault(key, {"route_id": "candidate-route-" + key[:20], "dedupe_key": key,
            "component_id": assignment["component_id"], "mechanism_or_impact_hypothesis": route["hypothesis"],
            "proof_obligation_ids": set(), "evidence_citations": {}, "source_rows": [],
            "crosswalk_aliases": {}, "next_route": "09-independent-verification", "candidate_only": True,
            "finding_created": False, "severity_assigned": False, "runtime_claimed": False})
        entry["proof_obligation_ids"].update(route["obligation_ids"])
        entry["evidence_citations"].update({item["citation_id"]: item for item in citations})
        entry["source_rows"].append({"row_index": index, "target_id": assignment["target_id"],
            "control_id": assignment["control_id"], "result_id": result["result_id"], "source_route_id": route["route_id"]})
        entry["crosswalk_aliases"].update({digest(item): item for item in aliases})
        matrix_rows[index]["candidate_route_ids"].append(entry["route_id"])
    routes = []
    for key in sorted(grouped):
        item = grouped[key]
        item["proof_obligation_ids"] = sorted(item["proof_obligation_ids"])
        item["evidence_citations"] = [item["evidence_citations"][x] for x in sorted(item["evidence_citations"])]
        item["source_rows"] = [value for _, value in sorted(
            {digest(value): value for value in item["source_rows"]}.items())]
        item["crosswalk_aliases"] = [item["crosswalk_aliases"][x] for x in sorted(item["crosswalk_aliases"])]
        routes.append(item)
    for row in matrix_rows:
        row["candidate_route_ids"] = sorted(set(row["candidate_route_ids"]))

    applicability_counts = Counter(row["applicability_status"] for row in matrix_rows)
    assessment_counts = Counter(row["joined_status"] for row in matrix_rows)
    matrix = {"schema": "appsec-review/owasp-control-status-matrix/1.0", "run_id": accounting["run_id"],
        "selection_id": plan.worklist["selection_id"], "selection": manifest["selection"],
        "permissions": manifest["permissions"], "evidence_admitted_at": manifest["admitted_at"],
        "provenance": {
            "dispatch_attempt_id": accounting["attempt_id"], "dispatch_accounting_sha256": accounting["accounting_sha256"],
            "handoff_attempt_id": accounting["handoff_publication"]["attempt_id"],
            "handoff_set_sha256": accounting["handoff_publication"]["handoff_set_sha256"],
            "worklist_sha256": accounting["worklist"]["sha256"],
            "applicability_model_sha256": inputs["applicability_model_sha256"],
            "input_manifest_sha256": inputs["input_manifest_sha256"]},
        "denominators": {"selected": len(matrix_rows),
            "applicable": sum(row["applicability_status"] in APPLICABLE for row in matrix_rows),
            "assessed": sum(row["applicability_status"] in APPLICABLE and row["joined_status"] in ASSESSMENTS - {"not_assessed"} for row in matrix_rows),
            "satisfied": sum(row["joined_status"] == "satisfied" for row in matrix_rows)},
        "applicability_counts": {name: applicability_counts.get(name, 0) for name in ("applicable", "conditional", "not_applicable", "cannot_determine", "out_of_scope")},
        "assessment_counts": {name: assessment_counts.get(name, 0) for name in ("satisfied", "partially_satisfied", "not_satisfied", "cannot_verify", "dynamic_test_required", "human_decision_required", "not_assessed", "not_applicable", "cannot_determine", "out_of_scope")},
        "dispatch_cells": accounting["cells"], "rows": matrix_rows,
        "claim_limits": {"finding_created": False, "severity_assigned": False,
            "runtime_state_claimed": False, "compliance_certified": False, "status_upgrade_permitted": False}}
    output = {MATRIX: matrix,
        GAPS: {"schema": "appsec-review/owasp-coverage-gaps-report/1.0", "run_id": accounting["run_id"],
               "selection_id": plan.worklist["selection_id"],
               "gaps": [gaps[key] for key in sorted(gaps)]},
        DYNAMIC: {"schema": "appsec-review/owasp-joined-dynamic-requests/1.0", "run_id": accounting["run_id"],
                  "selection_id": plan.worklist["selection_id"], "authorization": "not_authorized",
                  "execution": "not_executed", "requests": [dynamic_by_id[x] for x in sorted(dynamic_by_id)]},
        ROUTES: {"schema": "appsec-review/owasp-candidate-promotion-routes/1.0", "run_id": accounting["run_id"],
                 "selection_id": plan.worklist["selection_id"], "finding_promotion": "not_performed", "routes": routes}}
    schemas = {MATRIX: "owasp-control-status-matrix.schema.json", GAPS: "owasp-coverage-gaps-report.schema.json",
               DYNAMIC: "owasp-joined-dynamic-requests.schema.json", ROUTES: "owasp-candidate-promotion-routes.schema.json"}
    for name, value in output.items():
        errors = validate_document(value, schemas[name])
        if errors: raise Blocked(f"{JOB_ID}: generated {name} is invalid ({len(errors)} errors): {errors[0]}")
        _reject_promoted_claims(value)
    return output


def summary(outputs: dict[str, Any]) -> str:
    matrix, gap_doc, dynamic, routes = outputs[MATRIX], outputs[GAPS], outputs[DYNAMIC], outputs[ROUTES]
    d = matrix["denominators"]
    lines = ["# OWASP control workbench summary", "", "## Selection and scope", "",
        f"- Selection: `{matrix['selection_id']}`", f"- Run: `{matrix['run_id']}`",
        f"- Approved by: `{matrix['selection']['approver']}` at `{matrix['selection']['approved_at']}`",
        f"- Evidence admission cutoff: `{matrix['evidence_admitted_at']}`",
        "- Standards/profiles: " + ", ".join(
            f"{item['family']} {item['edition']} ({item['profile_or_level'] or 'all'})"
            for item in matrix["selection"]["selections"]),
        "- Permissions: " + ", ".join(f"{key}={str(value).lower()}"
            for key, value in sorted(matrix["permissions"].items())),
        "- Static workbench join only; dynamic execution and manual observation are not authorized.", "",
        "## Population and denominators", "",
        f"- Selected rows: {d['selected']}", f"- Applicable or conditional rows: {d['applicable']}",
        f"- Assessed applicable rows: {d['assessed']}", f"- Satisfied rows: {d['satisfied']}", "",
        "## Exact applicability totals", ""]
    lines.extend(f"- {name}: {count}" for name, count in matrix["applicability_counts"].items())
    lines.extend(["", "## Exact joined control-status totals", ""])
    lines.extend(f"- {name}: {count}" for name, count in matrix["assessment_counts"].items())
    lines.extend(["", "## Gaps, requests, dissent, and rescope", "",
        f"- Coverage gaps: {len(gap_doc['gaps'])}", f"- Inert dynamic requests: {len(dynamic['requests'])}",
        f"- Contradictions: {sum(item['kind'] == 'contradiction' for item in gap_doc['gaps'])}",
        f"- Batches: {len({batch for row in matrix['rows'] for batch in row['batch_ids']})}",
        f"- Failed/degraded dispatch cells: {sum(cell['disposition'] == 'dispatched' and cell['state'] != 'succeeded' for cell in matrix['dispatch_cells'])}",
        f"- Unassessed rows: {matrix['assessment_counts']['not_assessed']}",
        f"- Rows with overrides: {sum(bool(row['override_ids']) for row in matrix['rows'])}",
        f"- Manual/human-decision backlog: {matrix['assessment_counts']['human_decision_required']}",
        f"- Candidate independent-verification routes: {len(routes['routes'])}",
        f"- Rows with dissent: {sum(bool(row['dissent_ids']) for row in matrix['rows'])}",
        f"- Rows requiring rescope: {sum(row['rescope_state'] == 'required' for row in matrix['rows'])}", "",
        "## Artifact pointers", "", f"- `{MATRIX}`", f"- `{GAPS}`", f"- `{DYNAMIC}`", f"- `{ROUTES}`", "",
        "Control statuses and candidate routes are evidence-accounting outputs, not findings, severity, runtime observations, certification, or compliance conclusions."])
    return "\n".join(lines) + "\n"


def write_outputs(output_root: Path, outputs: dict[str, Any]) -> dict[str, str]:
    output_root.mkdir(parents=True, exist_ok=True)
    for name, value in outputs.items(): atomic_json(output_root / name, value)
    atomic_bytes(output_root / SUMMARY, summary(outputs).encode())
    return {name: file_hash(output_root / name) for name in sorted([*outputs, SUMMARY])}


def run(run_id: str, *, facts: dispatch.DispatchFacts, output_root: Path) -> dict[str, str]:
    return write_outputs(output_root, derive(load_verified_inputs(run_id, facts=facts)))
