"""A small synthetic run directory with the shapes of a real review run.

Built on demand by the tests (the repository ignores ``*.jsonl``, so the ledger is generated, not
committed). It carries one fully reviewed package (a red cell with a denied retrieval, a blue cell, a
verifier cell, a claim in state ``supported``), one package whose content and recordings are missing
(a named gap), and hostile text in every place a model or a target could put it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

RUN_ID = "2026-10-21-0042"
MODEL = "claude-haiku-5-5"
LONG_ID = "A" * 300

HOSTILE = (
    "\\input{/etc/passwd}\\write18{id}\\immediate\\write18{touch /tmp/pwned} $x^2$ & # _ % ~ ^ } { "
    "\\end{document}\\begin{document} ^^M \x00 \x1b[31mred\x1b[0m \u202etxet\u202c <script>alert(1)</script> "
    "<img src=x onerror=alert(2)> \" ' ` \u4e2d\u6587 " + LONG_ID)


def h(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def pid(label: str) -> str:
    return f"finding_lead-{h('package-' + label)}"


def cid(label: str) -> str:
    return f"cell-{h('cell-' + label)}"


def aid(kind: str, label: str) -> str:
    return f"asr:{kind}:{h(kind + label)}"


PACKAGE_A = pid("A")
PACKAGE_B = pid("B")
CELL_RED, CELL_BLUE, CELL_VERIFY, CELL_B = cid("red"), cid("blue"), cid("verify"), cid("b-red")
CLAIM_ID = f"claim-{h('claim')}"


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=1) + "\n", encoding="utf-8")


def _package() -> dict[str, Any]:
    observation = aid("tool_observation", "lead")
    return {
        "assembly_rule": "appsec-review/assemble-review-packages/5",
        "context": [{"id": aid("ast_node", str(i)), "kind": "ast_node", "role": "neighbour"} for i in range(3)],
        "coverage_gaps": [{"gap_id": f"gap-{h('pg' + str(i))}", "producer": "code_graph" if i % 2 else "artifact_scanner",
                           "reason": f"graph family {i} unavailable for this scope; absence is a gap, never evidence",
                           "scope": "unit:unassigned", "state": "unavailable" if i % 3 else "partial"} for i in range(14)],
        "evidence": [{"entity_id": aid("ast_node", str(i)), "relation": "qualifies",
                      "resolution": "source_line" if i % 2 else "unresolved", "shard_id": "cpp-build-unit-ast",
                      "shard_sha256": h("shard")} for i in range(12)],
        "input_fingerprint": h("fingerprint"), "kind": "finding_lead", "lane": "lead", "lead_family": "source_sast",
        "lead_menu": [{
            "admission_reasons": ["reported_severity"], "advisory_context": None, "advisory_summary": None, "build_unit_id": None,
            "component_id": "component:0001", "duplicate_of": None, "flow_ids": [], "lead_family": "source_sast",
            "location": {"end_line": 58, "file_sha256": h("file"), "mapping_method": "producer-line-location",
                         "source_path": "src/main.cpp", "start_line": 58},
            "location_exact": True, "message": "Unchecked conversion of attacker-influenced text. " + HOSTILE,
            "native_severity": "WARNING", "observation_id": observation, "reported_severity": "medium",
            "rule_cwe": ["CWE-190"], "rule_id": "cpp.unchecked-strtol", "scanner": "tool-opengrep",
            "severity_basis": "native", "severity_rule": "appsec-review/lead-family/source_sast/1",
            "suppression_status": "unknown", "weaknesses": []}],
        "manifest_sha256": h("manifest"), "package_id": PACKAGE_A, "partition": {"count": 1, "number": 0},
        "persona": None, "proof_obligations": ["affected_construct", "attacker_input_control", "security_impact"],
        "rank": None, "retrieval": {"entity_ids": [observation], "indexes": ["source"], "max_depth": 2},
        "run_id": RUN_ID, "schema": "appsec-review/review-package/5",
        "scope": {"artifact_ids": [], "build_unit_id": None, "component_id": "component:0001",
                  "partition_key": f"lead/{observation}", "source_ids": [aid("source_file", "main")], "trust_boundary_id": None},
        "source_excerpt": "int parse(const char *s) {\n    char *end;\n    long v = strtol(s, &end, 10);   // unchecked\n"
                          "    return (int)v;\n}\n// " + HOSTILE.replace("\n", " ") + "\n" + "\n".join(f"    // filler line {i}" for i in range(60)),
        "stack_profile": None, "target_snapshot": h("snapshot"),
        "truncation": {"next_partition": None, "omitted_context": 0, "omitted_leads": 0}}


def _review_package() -> dict[str, Any]:
    return {
        "build_context": {
            "action_ids": [aid("build_action", "a")], "artifact_ids": [aid("build_artifact", "a")],
            "bindings": [{"source_path": "src/main.cpp", "match": "source_file"}],
            "command_facts": [{"build_action_id": aid("build_action", "a"), "tool_id": "clang++", "ordered_tokens": [
                {"kind": "tool", "ordinal": 0, "redacted": False, "safe_value": "clang++"},
                {"kind": "flag", "ordinal": 1, "redacted": False, "safe_value": "-O2"},
                {"kind": "positional", "ordinal": 2, "redacted": True}]}],
            "environment_facts": [{"class": "toolchain_selection", "name": "CC", "present": True, "redacted": False, "safe_value": "clang"}]},
        "compiled_context": [{"compile_unit_id": h("cu"), "entity_id": aid("ast_node", "0"), "kind": "FunctionDecl",
                              "line": 49, "name": "main", "source_path": "src/main.cpp"}],
        "tag_context": {"assignments": [], "cloud": [{"assignment_count": 2, "tag": "lang:cpp"}, {"assignment_count": 1, "tag": "gap:crosswalk-unmapped"}]},
        "package_id": PACKAGE_A}


def _schema_text() -> str:
    return "appsec-review/worker-turn/1"


def _task_input(role: str, lens: str, package: dict[str, Any]) -> dict[str, Any]:
    return {
        "capability": {"capability_sha256": h("cap"), "entities": [aid("tool_observation", "lead")], "indexes": ["source", "observations"],
                       "max_depth": 4, "max_queries": 40, "max_result_bytes": 65536, "max_turns": 12, "page_size": 20,
                       "tools": ["find", "read_excerpt", "trace", "query_code_graph"]},
        "input": {"echo": {"package": {"basis_sha256": h("basis")}, "role": role, "round_id": "0"}, "lens": lens, "package": package},
        "output_schema": "appsec-review/red-discovery-result/1", "package_identities": [aid("tool_observation", "lead")],
        "round": 0, "task": lens,
        "turn_protocol": {"actions": ["retrieve", "final"], "max_requests_per_turn": 16, "schema": _schema_text(),
                          "tool_catalog": [{"name": "find"}, {"name": "trace"}]}}


def _request(cell: str, role: str, lens: str, package: dict[str, Any], transcript: list[dict[str, Any]], persona: str = "generalist") -> dict[str, Any]:
    return {"cell_id": cell, "guidance_bundle_sha256": h("bundle"), "guidance_text": "governing rules", "max_input_tokens": 32000,
            "max_output_tokens": 8000, "model": MODEL, "persona": persona, "provider": "claude-cli", "reasoning": "high",
            "repair_errors": [], "role": role, "schema": _schema_text(), "stack_profile": "generic",
            "task_input": _task_input(role, lens, package), "transcript": transcript, "type": "review"}


def _recording(directory: Path, name: str, sequence: int, request: dict[str, Any], *, result: dict[str, Any] | None = None,
               error: dict[str, Any] | None = None) -> None:
    value: dict[str, Any] = {"job_id": "job_inference_security_review", "key": name, "request": request,
                             "schema": "appsec-review/model-recording/1", "sequence": sequence}
    if result is not None:
        value["result"] = result
    if error is not None:
        value["error"] = error
    _write(directory / f"{name}.{sequence:04d}.json", value)


def build_fixture(root: Path) -> Path:
    """Write the synthetic run under ``root/RUN_ID`` and return it."""
    run = Path(root) / RUN_ID
    data = run / "data"
    job = data / "jobs" / "job_inference_security_review"
    package = _package()
    # -- packages
    _write(job / "attempts" / "attempt_0001" / "steps" / "packages" / "tasks" / "assemble_lead_packages" / "assembly" / "packages" / f"{PACKAGE_A}.json", package)
    _write(data / "review-packages" / h("pkgset") / f"{PACKAGE_A}.json", _review_package())
    # -- recordings
    rec = data / "inference-recordings" / "job_inference_security_review"
    retrieve = {"action": "retrieve", "requests": [
        {"tool": "trace", "parameters": {"depth": 2, "identity": aid("tool_observation", "lead"), "limit": 20}},
        {"tool": "read_excerpt", "parameters": {"path": "/etc/passwd"}},
        {"tool": "query_code_graph", "parameters": {"scope": "unit"}}]}
    turn1 = {"content": retrieve, "from": "worker", "turn": 1}
    app1 = {"final_required": False, "from": "application", "remaining_queries": 37, "remaining_turns": 11, "turn": 1, "responses": [
        {"coverage_gaps": ["trace result bound reached"], "index": 0, "index_manifest_sha256": h("idx"), "next_cursor": None,
         "results": [{"kind": "OBSERVED_AT", "depth": 1, "source_id": aid("tool_observation", "lead"), "target_id": aid("object_file", "o"),
                      "relation_id": f"rel:{h('r1')}", "shard_id": "artifact-security", "payload": {}} for _ in range(3)] + [
                        {"kind": "CALLS", "depth": 2, "source_id": aid("ast_node", "0"), "target_id": aid("ast_node", "1"), "payload": {"note": HOSTILE}}],
         "status": "ok", "tool": "trace", "truncated": True, "withheld_out_of_scope": 20},
        {"code": "forbidden_parameter", "index": 1, "reason": "parameter is never grantable: path", "status": "denied"},
        {"error_class": "ValueError", "index": 2, "status": "tool_error", "tool": "query_code_graph"}]}
    final_red = {"action": "final", "result": {
        "lane": "lead", "lens": "lead_red_failure_modes", "schema": "appsec-review/red-discovery-result/1",
        "observed_facts": ["strtol result is cast to int without a range check at src/main.cpp:58.", HOSTILE],
        "predicate_status": {"affected_construct": "resolved at src/main.cpp:58", "attacker_input_control": "not established"},
        "lead_accounting": [{"disposition": "developed", "lead": aid("tool_observation", "lead"), "rule_id": "cpp.unchecked-strtol",
                             "note": "Developed into one proposal."}],
        "proposals": [{"title": "Integer truncation after strtol in parse()", "statement": "parse() casts a long to int without a range check. " + HOSTILE,
                       "weakness_cwe": "CWE-190", "evidence": [aid("tool_observation", "lead")], "stance": "proposed"}]}}
    usage1 = {"cache_tokens": 2234, "input_tokens": 2, "output_tokens": 1949}
    usage2 = {"cache_tokens": 0, "input_tokens": 3, "output_tokens": 5956}
    req0 = _request(CELL_RED, "red_team_analyst", "lead_red_failure_modes", package, [])
    req1 = _request(CELL_RED, "red_team_analyst", "lead_red_failure_modes", package, [turn1, app1])
    _recording(rec, h("red0"), 0, req0, result={**usage1, "proposal": retrieve})
    _recording(rec, h("red1"), 0, req1, result={**usage2, "proposal": final_red})
    blue = _request(CELL_BLUE, "blue_team_refuter", "blue_control", package, [])
    _recording(rec, h("blue"), 0, blue, result={"cache_tokens": 0, "input_tokens": 4, "output_tokens": 800, "proposal": {"action": "final", "result": {
        "counter_claim": "A range check exists in the caller, so truncation is not reachable for inputs above INT_MAX.",
        "stance": "insufficient_evidence", "controls_found": [{"control": "range check", "location": "src/main.cpp:41", "effective": "partial"}],
        "missing": ["caller of parse() was not retrieved"]}}})
    verify = _request(CELL_VERIFY, "independent_verifier", "verify_claim", package, [], persona="")
    _recording(rec, h("verify"), 0, verify, result={"cache_tokens": 0, "input_tokens": 5, "output_tokens": 1200, "proposal": {"action": "final", "result": {
        "verdict": "supported", "summary": "The cast is real; reachability from attacker input was not independently confirmed.",
        "predicates": [{"predicate": "affected_construct", "status": "supported"}, {"predicate": "attacker_input_control", "status": "unresolved"}]}}})
    # a cell whose model call failed (error chain) in package A's red lens
    failing = _request(cid("red-retry"), "red_team_analyst", "lead_red_stack", package, [])
    _recording(rec, h("fail"), 0, failing, error={"message": "expected exactly one appsec-review/worker-turn/1 JSON object, found 0", "type": "ModelOutputError"})
    # -- cell receipts
    for cell, status, reason in ((CELL_RED, "succeeded", None), (CELL_BLUE, "succeeded", None), (CELL_VERIFY, "succeeded", None),
                                 (CELL_B, "timed_out", "cell_budget_exceeded:cell_token_cap"), (cid("red-retry"), "invalid", "schema_violation")):
        _write(job / "cells" / cell / "attempt-1.json", {
            "attempt": 1, "attempt_id": f"{cell}/attempt-1", "cell_id": cell, "counts": {"denials": 1, "input_tokens": 9, "output_tokens": 7900, "queries": 5, "turns": 2},
            "gap_class": None, "gaps": [], "guidance_bundle_sha256": h("bundle"), "model": MODEL, "provider": "claude-cli", "reason": reason,
            "schema": "appsec-review/cell-attempt-receipt/1", "status": status, "turns": []})
    # -- ledger
    events = []

    def event(kind: str, subject: str, body: dict[str, Any]) -> None:
        events.append({"body": body, "event_id": f"event-{h(str(len(events)))}", "kind": kind, "prev_event_sha256": None if not events else h(str(len(events) - 1)),
                       "schema": "appsec-review/ledger-event/1", "sequence": len(events), "stream": "lead_review.teams", "subject_id": subject})

    claim = {"schema": "appsec-review/claim/1", "claim_id": CLAIM_ID, "lane": "lead", "package_id": PACKAGE_A,
             "affected_entities": [aid("tool_observation", "lead")], "weakness_cwe": "CWE-190", "security_predicate": "integer_overflow_or_truncation",
             "preconditions": ["attacker_controlled_input"], "statement": "parse() truncates an unchecked strtol result. " + HOSTILE,
             "state": "proposed", "duplicate_of": None, "origin_cell_ids": [CELL_RED]}
    event("claim_proposed", CLAIM_ID, {"claim": claim, "round": 0})
    for index, predicate in enumerate(("affected_construct", "security_impact")):
        event("relation_added", f"evrel-{h(predicate)}", {"round": 0, "relation": {
            "schema": "appsec-review/evidence-relation/1", "relation_id": f"evrel-{h(predicate)}", "claim_id": CLAIM_ID, "predicate": predicate,
            "kind": "supports", "entity_id": aid("ast_node", str(index)), "entity_kind": "ast_node", "admissibility": "direct", "shard_id": "ast",
            "content_sha256": h("c" + predicate), "locator": "src/main.cpp:58", "complete": True, "producing_cell_id": CELL_RED,
            "retrieval_receipt_sha256": None}})
    event("state_transition", CLAIM_ID, {"adjudication_id": None, "from_state": "proposed", "reason": "evidence supports the affected construct", "round": 1, "to_state": "supported"})
    for gap_class, reason in (("authority_error", "denied:forbidden_parameter"), ("schema_error", HOSTILE), ("budget_gap", "cell_budget_exceeded:cell_token_cap")):
        subject = CELL_B if gap_class == "budget_gap" else CELL_RED
        event("gap_recorded", f"gap-{h(gap_class)}", {"gap": {"gap_class": gap_class, "gap_id": f"gap-{h(gap_class)}", "predicate": None, "reason": reason,
                                                                "round": 0, "schema": "appsec-review/gap/1", "subject_id": subject}})
    for cell, package_id, role, persona, status, claim_id in (
            (CELL_RED, PACKAGE_A, "red_team_analyst", "generalist", "succeeded", None),
            (CELL_BLUE, PACKAGE_A, "blue_team_refuter", "generalist", "succeeded", CLAIM_ID),
            (CELL_VERIFY, PACKAGE_A, "independent_verifier", "", "succeeded", CLAIM_ID),
            (cid("red-retry"), PACKAGE_A, "red_team_analyst", "generalist", "invalid", None),
            (CELL_B, PACKAGE_B, "red_team_analyst", "generalist", "timed_out", None)):
        event("cell_terminal", cell, {"cell": {"schema": "appsec-review/cell-record/1", "cell_id": cell, "lane": "lead", "package_id": package_id,
                                               "role": role, "persona": persona, "stack_profile": "generic", "task": "lens", "claim_id": claim_id,
                                               "status": status, "attempts": 1, "gap_ids": [], "receipt_sha256": None}})
    shard = job / "attempts" / "attempt_0001" / "steps" / "lead_review" / "tasks" / "teams" / "ledger.jsonl"
    shard.parent.mkdir(parents=True, exist_ok=True)
    shard.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in events), encoding="utf-8")
    # -- final report and handoff
    finding = {
        "finding_package_id": f"finding-{h('fp')}", "sha256": h("fpsha"), "path": "data/review/finding.json", "claim_id": CLAIM_ID,
        "adjudication_id": f"adj-{h('adj')}", "lane": "lead", "state": "supported", "label": "not_independently_confirmed",
        "title": "Integer truncation after strtol in parse() " + HOSTILE,
        "ship_block": {"policy": "ship-block-policy/1", "policy_sha256": h("policy"), "status": "needs_verification", "reasons": ["not_independently_confirmed"],
                       "technical_severity": None, "technical_severity_score_id": None, "distinct_verification_required": True, "verifier_model_distinct": False},
        "independence": {"independent": False, "provider_distinct": False, "verifier_model_distinct": False},
        "verification_review_id": None, "direct_evidence": [f"rel-{h('d1')}"], "missing_predicates": ["attacker_input_control"], "gap_ids": [f"gap-{h('authority_error')}"],
        "scores": [], "poc": None, "attack_chains": [], "bucket": "verification_backlog", "withheld_reasons": []}
    report = {
        "schema": "appsec-review/final-report/1", "run_id": RUN_ID,
        "provenance": {"gate_handoff": {"path": "data/jobs/job_final_publication_gate/attempts/attempt_0001/handoff.json", "sha256": h("gh")},
                       "gate_document": {"path": "data/jobs/job_final_publication_gate/doc.json", "sha256": h("gd")},
                       "review_handoff": {"path": "data/jobs/job_inference_security_review/attempts/attempt_0001/handoff.json", "sha256": h("rh")},
                       "accepted_manifest_sha256": h("am"), "configuration_sha256": h("cfg"), "ledger_head_sha256": h("head"), "ship_block_policy_sha256": h("policy")},
        "status": {"review": "DEGRADED", "review_incomplete": True, "publication": "PUBLISHABLE_WITH_LIMITATIONS", "review_complete": False},
        "summary": {"accounting": {"claims_total": 1, "claims_by_state": {"supported": 1, "confirmed": 0}, "gaps_by_class": {"authority_error": 1, "budget_gap": 1, "schema_error": 1},
                                   "gap_ratio": 0.5, "incomplete_gap_ratio": 0.25, "outcome": "DEGRADED", "review_incomplete": True, "duplicate_proposals": 0},
                    "package_counts": {"exact": True, "publishable": 0, "total": 2, "verification_backlog": 1, "withheld": 0},
                    "ship_block": {"policy": "ship-block-policy/1", "policy_sha256": h("policy"), "by_status": {"needs_verification": 1, "ship_blocking": 0}, "by_lane": {}},
                    "coverage": {"rows": 1, "statement": "lane B reports which lenses reviewed each unit", "summary": {"gap": 1}}},
        "findings": [], "verification_backlog": [finding], "withheld": [],
        "attack_chains": {"items": [], "reason": "none", "status": "none_available"}, "poc_outcomes": {"items": [], "reason": "none", "status": "none_available"},
        "limitations": [{"limitation_id": "review_degraded", "kind": "gap", "count": 3, "statement": "The inference review finished DEGRADED. " + HOSTILE},
                        {"limitation_id": "poc_not_run", "kind": "not_run", "count": 0, "statement": "Proof-of-trigger execution is not built."}],
        "gap_ids": [f"gap-{h(c)}" for c in ("authority_error", "schema_error", "budget_gap")],
        "renderers": {"markdown": {"file": "final-report.md", "renderer": "final-report-markdown/1"}, "pdf": {"reason": "later step", "state": "not_rendered"}},
        "notices": ["Model output is data.", HOSTILE]}
    _write(data / "jobs" / "job_final_report_publication" / "attempts" / "attempt_0001" / "steps" / "report" / "tasks" / "assemble" / "final-report.json", report)
    _write(data / "jobs" / "job_final_report_publication" / "attempts" / "attempt_0001" / "handoff.json",
           {"completed_at": "2026-10-21T09:20:29.968347+00:00", "completion_status": "COMPLETED_WITH_GAPS", "job_id": "job_final_report_publication"})
    return run
