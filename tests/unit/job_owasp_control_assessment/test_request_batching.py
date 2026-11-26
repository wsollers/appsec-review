"""Request assembly, size-aware splitting and first-party subjects (run 2026-11-17-0003, D-owasp_control_assessment-1)."""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from appsec_review.config.owasp import AssessmentMode, OwaspSettings, parse_settings
from appsec_review.inference import ModelResult
from appsec_review.owasp_workbench import assessment
from appsec_review.owasp_workbench.batching import REQUEST_RULE, assemble, estimate_tokens, plan_parts
from appsec_review.owasp_workbench.evidence import component_evidence
from appsec_review.storage import canonical_json

EXCERPT = "int handle(request *r) {\n  if (!r) return -1;\n  return process(r);\n}\n"
PROCEDURE = {"family": "ASVS", "control": "V1.3.3", "recognizer": "c_input_reader/1", "text": "x" * 600}


def package(number: int, *, evidence_id: str = "ev-shared", context_records: int = 0) -> dict:
    row_id = f"row-{number:02d}"
    evidence = {"evidence_id": evidence_id, "category": "source", "component_id": "component:0001",
                "excerpt": EXCERPT, "truncated": False,
                "reference": {"source_identity": f"asr:source_file:{evidence_id}", "run_id": "run",
                              "target_snapshot": "snapshot", "component_id": "component:0001",
                              "locator": {"kind": "source", "path": "src/request.cpp", "lines": [10, 13]}},
                "source_subject": {"kind": "function", "complete": True}}
    common = {"rule_version": "owasp-proof-obligations/3", "control_identity": "ASVS:5.0.0:V1.3.3",
              "component_id": "component:0001", "procedure": PROCEDURE, "static_limits": ["a", "b"],
              "evidence_mode": "static_source", "criteria": {"satisfied": ["s"], "not_satisfied": ["n"]}}
    obligations = [{**common, "obligation_id": f"{row_id}:subject-{index}", "subject_id": f"subject-{index}",
                    "supported": True, "material": True, "evidence_ids": [evidence_id],
                    "subject": {"name": f"handle_{index}", "locator": {"path": "src/request.cpp"}}}
                   for index in range(3)]
    context = [{"identity": f"tag:{index}", "tag": "entry:socket", "payload": {"text": "y" * 400},
                "classifies_component": index == 0} for index in range(context_records)]
    return {
        "schema": "appsec-review/finding-package/1", "row_id": row_id, "batch_id": "batch", "package_id": f"pkg-{number}",
        "standard": "ASVS", "version": "5.0.0", "profile": "L2",
        "control": {"identity": "ASVS:5.0.0:V1.3.3", "id": f"V1.3.{number}", "family": "ASVS", "version": "5.0.0",
                    "title": "Input", "text": "Verify input handling."},
        "component": {"target_id": "snapshot", "project_id": "project", "component_id": "component:0001",
                      "roles": ["network_service"], "evidence": [{"source_identity": "asr:component:1"}]},
        "evidence_references": [evidence], "allowed_retrieval_tools": ["find", "read_excerpt", "resolve_evidence"],
        "retrieval_manifest": {"path": "data/indices/manifests/accepted.json", "sha256": "0" * 64},
        "assessment_mode": "assessment", "routing_context": context, "graph_context": list(context),
        "proof_obligations": obligations, "expansion_identities": [f"asr:source_file:{evidence_id}"],
        "limitations": ["component:0001: tag record cap reached", f"row {row_id} note"],
        "prohibited_claims": ["compliance certification"],
        "guidance": {"bundle_sha256": "a" * 64},
    }


def test_host_budgets_plan_the_same_rendered_twelve_rows_over_sixty_subjects():
    from pathlib import Path
    from appsec_review.config import load_config

    root = Path(__file__).resolve().parents[3]
    packages = [package(number) for number in range(12)]
    for number, row in enumerate(packages):
        evidence = [package(number, evidence_id=f"subject-{5 * number + j}")["evidence_references"][0]
                    for j in range(5)]
        row["evidence_references"] = [{**record, "excerpt": EXCERPT * 12} for record in evidence]
        row["proof_obligations"] = [{**row["proof_obligations"][0], "subject_id": record["evidence_id"],
                                     "obligation_id": f"{row['row_id']}:{record['evidence_id']}",
                                     "evidence_ids": [record["evidence_id"]]} for record in evidence]
        row["expansion_identities"] = [record["reference"]["source_identity"] for record in evidence]
    assert len(assemble(packages)["evidence"]) == 60
    counts = []
    for profile_name in ("dev", "wsollers1-dev"):
        config = load_config(root / "appsec-review.toml", profile=profile_name)
        job = config.job("job_owasp_control_assessment")
        profile = job.settings["model"]
        settings = parse_settings(job.settings)

        def estimate(view):
            request = assessment._request(
                view, batch={"batch_id": "batch", "assignment": {"persona": "general"}},
                role="control_assessor", guidance={"bundle_sha256": "a" * 64}, text="guidance",
                profile=profile, settings=settings, transcript=(), queries=0, turn=0, retry=0, part=None)
            return estimate_tokens(request)

        parts = plan_parts(packages, estimate=estimate, budget=profile["max_input_tokens"])
        assert all(part.dispatch and part.estimate <= profile["max_input_tokens"] for part in parts)
        assert [row_id for part in parts for row_id in part.row_ids] == [row["row_id"] for row in packages]
        counts.append(len(parts))
    assert counts[0] > counts[1] == 1


def test_twelve_rows_sharing_one_excerpt_serialize_it_once():
    packages = [package(number, context_records=4) for number in range(12)]
    before = canonical_json(packages)
    view = assemble(packages)
    after = canonical_json(view)
    needle = canonical_json(EXCERPT).strip()[1:-1]  # the excerpt as it is encoded inside the request
    assert before.count(needle) == 12 and after.count(needle) == 1
    assert list(view["evidence"]) == ["ev-shared"] and list(view["components"]) == ["component:0001"]
    assert after.count(b'"tag:0"') == 2  # once in routing_context, once in graph_context, not per row
    assert all(row["evidence_ids"] == ["ev-shared"] and "evidence_references" not in row for row in view["packages"])
    # The control's procedure is hoisted once per row; obligations keep only their own identity and subject.
    row = view["packages"][0]
    assert row["procedure"]["procedure"] == PROCEDURE and len(row["proof_obligations"]) == 3
    assert set(row["proof_obligations"][0]) == {"obligation_id", "subject_id", "supported", "material",
                                                "evidence_ids", "subject"}
    assert after.count(PROCEDURE["text"].encode()) == 12 and before.count(PROCEDURE["text"].encode()) == 36
    assert view["components"]["component:0001"]["limitations"] == ["component:0001: tag record cap reached"]
    assert row["limitations"] == ["row row-00 note"]
    assert "guidance" not in row and view["retrieval_manifest"]["sha256"] == "0" * 64
    assert len(after) < len(before) / 3


def test_oversize_batch_splits_until_each_part_fits():
    packages = [package(number) for number in range(12)]
    single = estimate_tokens(assemble(packages[:1]))
    budget = int(estimate_tokens(assemble(packages[:3])) * 1.05)
    assert estimate_tokens(assemble(packages)) > budget > single
    parts = plan_parts(packages, estimate=estimate_tokens, budget=budget)
    assert len(parts) >= 4 and all(part.estimate <= budget and part.dispatch and not part.gaps for part in parts)
    assert [row for part in parts for row in part.row_ids] == [item["row_id"] for item in packages]
    assert all(len(part.packages) >= 1 and "trimmed" not in part.view for part in parts)


def test_single_oversize_row_is_trimmed_with_a_named_gap():
    packages = [package(0, context_records=40)]
    full = estimate_tokens(assemble(packages))
    budget = full // 2
    part, = plan_parts(packages, estimate=estimate_tokens, budget=budget)
    assert part.dispatch and part.estimate <= budget
    gap, = part.gaps["row-00"]
    assert gap.startswith(f"input_budget: request estimate {full} tokens exceeded max_input_tokens {budget}; trimmed ")
    assert f"to {part.estimate} tokens" in gap and "graph_context" in gap
    trimmed = part.view["trimmed"]
    assert trimmed["rule"] == REQUEST_RULE and trimmed["estimate_before"] == full and trimmed["max_input_tokens"] == budget
    assert trimmed["tiers"][0] == "graph_context" and part.view["components"]["component:0001"]["graph_context"] == []
    # Cited evidence is the last thing to go: the excerpt survives a context-only trim.
    assert part.view["evidence"]["ev-shared"]["excerpt"] == EXCERPT


def test_single_row_beyond_every_trim_tier_is_not_dispatched_and_names_both_numbers():
    packages = [package(0, context_records=2)]
    part, = plan_parts(packages, estimate=estimate_tokens, budget=1)
    assert not part.dispatch
    gap, = part.gaps["row-00"]
    assert gap.startswith(f"input_budget: request estimate {part.estimate} tokens exceeds max_input_tokens 1 after trimming ")
    assert "row not dispatched" in gap and part.view["trimmed"]["tiers"] == [
        "graph_context", "routing_context", "limitations", "excerpts"]
    assert "excerpt" not in part.view["evidence"]["ev-shared"] and part.view["evidence"]["ev-shared"]["excerpt_omitted"]


def test_plan_rejects_an_untyped_budget():
    with pytest.raises(ValueError, match="positive integer"):
        plan_parts([package(0)], estimate=estimate_tokens, budget=0)


def test_investigate_dispatches_each_part_and_reports_rows(tmp_path, monkeypatch):
    monkeypatch.delenv("APPSEC_REVIEW_MODEL_RECORDING", raising=False)
    monkeypatch.setattr(assessment, "_guidance", lambda *args: ({"bundle_sha256": "a" * 64}, "guidance"))
    monkeypatch.setattr(assessment, "validate_final", lambda *args: None)
    monkeypatch.setattr(assessment, "consume_named", lambda *args, **kwargs: None)

    def publish(root, path, content, **kwargs):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    monkeypatch.setattr(assessment, "publish_named", publish)
    packages = [package(number, context_records=4) for number in range(4)]
    settings = OwaspSettings(True, AssessmentMode.ASSESSMENT, "reviewer", 2, 20, 2, 2, 2, 1)
    resolver = SimpleNamespace(scope=SimpleNamespace(run_id="run"),
                               metrics={"attempts": 0, "denials": 0, "truncations": 0, "missing": 0})
    args = dict(repository_root=tmp_path, run_root=tmp_path, batch={"batch_id": "batch", "assignment": {
        "persona": "api_web"}}, packages=packages, role="control_assessor", settings=settings,
        resolver=resolver, attempt_id="attempt", unit_id="validation.cell_1")
    probe = {**args, "profile": {"provider": "p", "model": "m", "reasoning": "high", "retries": 0,
                                 "timeout_seconds": 10, "max_input_tokens": 10_000_000, "max_output_tokens": 1000}}
    sizes = []

    def measure(request, *, timeout_seconds):
        from appsec_review.inference.request import review_prompt
        import json
        wire = json.dumps(review_prompt(request, include_guidance=True)).encode("utf-8")
        sizes.append(256 + (len(wire) * 115 + 279) // 280)
        return ModelResult({"schema": assessment.TURN_SCHEMA, "action": "final", "results": [
            {"row_id": row["row_id"], "obligations": []} for row in request.task_input["packages"]]})
    assert assessment.investigate(**probe, infer=measure)["status"] == "succeeded" and len(sizes) == 1
    budget = sizes[0] * 9 // 10  # the whole batch does not fit; each half does
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        assert estimate_tokens(request) <= budget
        assert "evidence_references" not in request.task_input["packages"][0]
        return ModelResult({"schema": assessment.TURN_SCHEMA, "action": "final", "results": [
            {"row_id": row["row_id"], "obligations": []} for row in request.task_input["packages"]]})
    result = assessment.investigate(**args, profile={**probe["profile"], "max_input_tokens": budget}, infer=infer)
    assert result["status"] == "succeeded" and len(calls) == 2
    assert [row["row_id"] for row in result["proposal"]["results"]] == [item["row_id"] for item in packages]
    assert result["row_status"] == {item["row_id"]: "succeeded" for item in packages}
    assert len(result["parts"]) == 2 and len(result["receipts"]) == 2 and result["receipt"] is None
    assert {calls[0].cell_id, calls[1].cell_id} == {"owasp:batch:control_assessor:0:0:part0",
                                                    "owasp:batch:control_assessor:0:0:part1"}
    assert len(result["attempts"]) == 2 and all(item["input_tokens_estimated"] <= budget for item in result["attempts"])
    # The whole batch is reused from its per-part receipts without a new model call.
    again = assessment.investigate(**args, profile={**probe["profile"], "max_input_tokens": budget}, infer=infer)
    assert again["status"] == "reused" and len(calls) == 2 and len(again["proposal"]["results"]) == 4


def test_investigate_names_estimate_and_limit_when_a_row_cannot_fit(tmp_path, monkeypatch):
    monkeypatch.setattr(assessment, "_guidance", lambda *args: ({"bundle_sha256": "a" * 64}, "guidance"))
    settings = OwaspSettings(True, AssessmentMode.ASSESSMENT, "reviewer", 2, 20, 2, 2, 2, 1)
    resolver = SimpleNamespace(scope=SimpleNamespace(run_id="run"),
                               metrics={"attempts": 0, "denials": 0, "truncations": 0, "missing": 0})
    calls = []
    result = assessment.investigate(
        repository_root=tmp_path, run_root=tmp_path, batch={"batch_id": "batch", "assignment": {"persona": None}},
        packages=[package(0), package(1)], role="control_assessor", settings=settings, resolver=resolver,
        profile={"provider": "p", "model": "m", "reasoning": "high", "retries": 0, "timeout_seconds": 10,
                 "max_input_tokens": 1, "max_output_tokens": 1000},
        infer=lambda request, *, timeout_seconds: calls.append(request))
    assert not calls and result["status"] == "input_budget" and result["proposal"] is None
    assert result["row_status"] == {"row-00": "input_budget", "row-01": "input_budget"}
    for row_id in ("row-00", "row-01"):
        gap, = result["row_gaps"][row_id]
        assert gap.startswith("input_budget: request estimate ") and "exceeds max_input_tokens 1 after trimming" in gap
        assert "row not dispatched" in gap
    assert all(not part["dispatch"] for part in result["parts"])


def test_vendored_sources_are_excluded_from_subjects_with_a_counted_gap(accepted, settings):
    source = "def query(value):\n    return db.execute('SELECT x FROM t WHERE id = ' + value)\n"
    fixture = accepted({"src/api.py": source, "third_party/cjson/shim.py": source})
    files = [replace(item, disposition="vendored") if item.path.startswith("third_party/") else item
             for item in fixture.files]
    evidence, gaps = component_evidence(fixture.resolver, "api", files, settings)
    assert [item["reference"]["locator"]["path"] for item in evidence] == ["src/api.py"]
    assert any("1 accepted source files outside the first-party disposition excluded from subject selection "
               "(vendored 1); their subjects are unassessed" in gap for gap in gaps)
    unfiltered, plain_gaps = component_evidence(fixture.resolver, "api", fixture.files, settings)
    assert len(unfiltered) == 2 and not any("first-party" in gap for gap in plain_gaps)


def test_settings_accept_the_inherited_dispositions_and_default_to_first_party():
    model = {"enabled": False, "provider": "fixture", "model": "fixture", "reasoning": "low",
             "max_input_tokens": 1000, "max_output_tokens": 500, "timeout_seconds": 2, "retries": 0}
    configured = {"enabled": True, "mode": "qualification", "reviewer_profile": "reviewer",
                  "max_evidence_per_component": 60, "max_source_lines": 120, "max_subjects_per_control": 8,
                  "max_batches": 10, "max_turns": 4, "max_queries": 8, "asvs_level": 1, "masvs_profile": "L1",
                  "max_batch_size": 4, "max_components_per_batch": 2, "max_components": 10,
                  "dynamic_authorized": False, "model": model, "models": {"reviewer": dict(model)},
                  "standards": {}, "parser_versions": {}}
    assert not parse_settings(configured).source_dispositions.configured
    typed = parse_settings({**configured, "source_dispositions": {"vendored": ["**/third_party/**"]}})
    assert typed.source_dispositions.classify("third_party/cjson/cJSON.c") == "vendored"
    assert typed.source_dispositions.classify("src/request.cpp") == "first_party"
    with pytest.raises(ValueError, match="source_dispositions"):
        parse_settings({**configured, "source_dispositions": {"vendor": ["x"]}})


def test_single_package_splits_across_obligations_preserving_excerpts_and_merges_proposals(tmp_path, monkeypatch):
    monkeypatch.setattr(assessment, "_guidance", lambda *args: ({"bundle_sha256": "a" * 64}, "guidance"))
    row = package(0, context_records=0)
    evidence_records = []
    obligations = []
    for index in range(4):
        eid = f"ev-{index}"
        rec = {
            **row["evidence_references"][0],
            "evidence_id": eid,
            "excerpt": EXCERPT * 25,
            "reference": {
                **row["evidence_references"][0]["reference"],
                "source_identity": f"asr:source_file:{eid}",
            },
        }
        evidence_records.append(rec)
        obligations.append({
            **row["proof_obligations"][0],
            "obligation_id": f"row-00:subject-{index}",
            "subject_id": f"subject-{index}",
            "evidence_ids": [eid],
        })
    row["evidence_references"] = evidence_records
    row["proof_obligations"] = obligations
    row["expansion_identities"] = [rec["reference"]["source_identity"] for rec in evidence_records]

    settings = OwaspSettings(True, AssessmentMode.ASSESSMENT, "reviewer", 60, 120, 8, 10, 4, 8)
    base_profile = {"provider": "p", "model": "m", "reasoning": "high", "retries": 0, "timeout_seconds": 10,
                    "max_input_tokens": 100000, "max_output_tokens": 2000}

    def est(view):
        req = assessment._request(
            view, batch={"batch_id": "batch", "assignment": {"persona": None}},
            role="control_assessor", guidance={"bundle_sha256": "a" * 64}, text="guidance",
            profile=base_profile, settings=settings, transcript=(), queries=0, turn=0, retry=0, part=1)
        return estimate_tokens(req)

    full_tokens = est(assemble([row]))
    single_slice_tokens = est(assemble([{
        **row,
        "proof_obligations": obligations[:1],
        "evidence_references": evidence_records[:1],
    }]))
    budget = single_slice_tokens + max(200, (full_tokens - single_slice_tokens) // 3)
    assert single_slice_tokens < budget < full_tokens

    parts = plan_parts([row], estimate=est, budget=budget)
    assert len(parts) >= 2
    assert all(part.dispatch and part.estimate <= budget for part in parts)
    assert all("excerpts" not in ((part.view.get("trimmed") or {}).get("tiers") or ()) for part in parts)

    resolver = SimpleNamespace(scope=SimpleNamespace(run_id="run"),
                               metrics={"attempts": 0, "denials": 0, "truncations": 0, "missing": 0})
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        pkg_view, = request.task_input["packages"]
        return ModelResult({
            "schema": assessment.TURN_SCHEMA,
            "action": "final",
            "results": [{
                "row_id": pkg_view["row_id"],
                "obligations": [
                    {
                        "obligation_id": item["obligation_id"],
                        "subject_id": item["subject_id"],
                        "outcome": "satisfied",
                        "rationale": f"Verified {item['obligation_id']}.",
                        "supporting": [],
                        "contradictory": [],
                        "assumptions": [],
                        "evidence_requests": [],
                        "hypotheses": [],
                        "limitations": [],
                    }
                    for item in pkg_view["proof_obligations"]
                    if item.get("supported")
                ],
            }],
        })

    profile = {**base_profile, "max_input_tokens": budget}
    result = assessment.investigate(
        repository_root=tmp_path, run_root=tmp_path, batch={"batch_id": "batch", "assignment": {"persona": None}},
        packages=[row], role="control_assessor", settings=settings, resolver=resolver, profile=profile, infer=infer)
    assert result["status"] == "succeeded"
    assert result["row_status"] == {"row-00": "succeeded"}
    assert len(calls) == len(parts)
    merged_row, = result["proposal"]["results"]
    assert [o["obligation_id"] for o in merged_row["obligations"]] == [o["obligation_id"] for o in obligations]

    reused = assessment.investigate(
        repository_root=tmp_path, run_root=tmp_path, batch={"batch_id": "batch", "assignment": {"persona": None}},
        packages=[row], role="control_assessor", settings=settings, resolver=resolver, profile=profile, infer=infer)
    assert reused["status"] == "reused" and len(calls) == len(parts)
    assert [o["obligation_id"] for o in reused["proposal"]["results"][0]["obligations"]] == [
        o["obligation_id"] for o in obligations
    ]


def test_investigate_dynamically_trims_view_when_retrieve_transcript_exceeds_budget(accepted, settings, tmp_path, monkeypatch):
    monkeypatch.setattr(assessment, "_guidance", lambda *args: ({"bundle_sha256": "a" * 64}, "guidance"))
    boundary = accepted({"src/request.cpp": EXCERPT * 20}, languages={"src/request.cpp": "C++"})
    ev = boundary.resolver.materialize(boundary.files[0].identity, component_id="api")
    row = package(0, evidence_id=ev["evidence_id"], context_records=10)
    row["component"]["component_id"] = "api"
    row["evidence_references"] = [ev]
    row["proof_obligations"] = [{**row["proof_obligations"][0], "component_id": "api"}]
    row["expansion_identities"] = [ev["reference"]["source_identity"]]
    batch_obj = {"batch_id": "batch", "component_id": "api", "assignment": {"persona": "general"}}

    probe_profile = {"provider": "p", "model": "m", "reasoning": "high", "retries": 0, "timeout_seconds": 10,
                     "max_input_tokens": 100000, "max_output_tokens": 2000}
    turn0_tokens = estimate_tokens(assessment._request(
        assemble([row]), batch=batch_obj, role="control_assessor", guidance={"bundle_sha256": "a" * 64}, text="guidance",
        profile=probe_profile, settings=settings, transcript=(), queries=0, turn=0, retry=0, part=None))
    # Budget admits untrimmed turn 0, while turn 1 after retrieve exceeds untrimmed budget and trims context tiers.
    budget = turn0_tokens + 10
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        if len(calls) == 1:
            return ModelResult({
                "schema": assessment.TURN_SCHEMA,
                "action": "retrieve",
                "requests": [{"source_identity": ev["reference"]["source_identity"], "locator": None}],
            })
        pkg_view, = request.task_input["packages"]
        obl, = pkg_view["proof_obligations"]
        return ModelResult({
            "schema": assessment.TURN_SCHEMA,
            "action": "final",
            "results": [{
                "row_id": pkg_view["row_id"],
                "obligations": [{
                    "obligation_id": obl["obligation_id"],
                    "subject_id": obl["subject_id"],
                    "outcome": "cannot_verify",
                    "rationale": "Checked after retrieve.",
                    "supporting": [],
                    "contradictory": [],
                    "assumptions": [],
                    "evidence_requests": ["Need caller."],
                    "hypotheses": [],
                    "limitations": [],
                }],
            }],
        })

    result = assessment.investigate(
        repository_root=tmp_path, run_root=tmp_path, batch=batch_obj, packages=[row], role="control_assessor",
        settings=settings, resolver=boundary.resolver, profile={**probe_profile, "max_input_tokens": budget},
        infer=infer)
    assert result["status"] == "succeeded" and len(calls) == 2
    assert "trimmed" not in calls[0].task_input
    assert calls[1].task_input.get("trimmed") is not None
    assert all(item["input_tokens_estimated"] <= budget for item in result["attempts"])
def test_assemble_scopes_limitations_routing_and_graph_context_per_component():
    pkg_a = package(0, evidence_id="ev-a", context_records=2)
    pkg_a["component"]["component_id"] = "component:alpha"
    pkg_a["limitations"] = ["component:alpha: alpha-only cap", "row row-00 note"]
    pkg_a["routing_context"] = [{"identity": "tag:alpha", "tag": "entry:http"}]
    pkg_a["graph_context"] = [{"identity": "graph:alpha", "kind": "call"}]

    pkg_b = package(1, evidence_id="ev-b", context_records=2)
    pkg_b["component"]["component_id"] = "component:beta"
    pkg_b["limitations"] = ["component:beta: beta-only cap", "row row-01 note"]
    pkg_b["routing_context"] = [{"identity": "tag:beta", "tag": "entry:grpc"}]
    pkg_b["graph_context"] = [{"identity": "graph:beta", "kind": "taint"}]

    view = assemble([pkg_a, pkg_b])
    comp_a = view["components"]["component:alpha"]
    comp_b = view["components"]["component:beta"]
    assert comp_a["limitations"] == ["component:alpha: alpha-only cap", "row row-00 note"]
    assert comp_b["limitations"] == ["component:beta: beta-only cap", "row row-01 note"]
    assert [item["identity"] for item in comp_a["routing_context"]] == ["tag:alpha"]
    assert [item["identity"] for item in comp_b["routing_context"]] == ["tag:beta"]
    assert [item["identity"] for item in comp_a["graph_context"]] == ["graph:alpha"]
    assert [item["identity"] for item in comp_b["graph_context"]] == ["graph:beta"]


def test_investigate_records_turn_1_input_budget_attempt_event_and_row_gap(accepted, settings, tmp_path, monkeypatch):
    from appsec_review.observability import EventLog

    monkeypatch.setattr(assessment, "_guidance", lambda *args: ({"bundle_sha256": "a" * 64}, "guidance"))
    boundary = accepted({"src/request.cpp": EXCERPT * 30}, languages={"src/request.cpp": "C++"})
    ev = boundary.resolver.materialize(boundary.files[0].identity, component_id="api")
    row = package(0, evidence_id=ev["evidence_id"], context_records=0)
    row["component"]["component_id"] = "api"
    row["evidence_references"] = [{**ev, "excerpt": "short\n"}]
    row["proof_obligations"] = [{**row["proof_obligations"][0], "component_id": "api"}]
    row["expansion_identities"] = [ev["reference"]["source_identity"]]
    batch_obj = {"batch_id": "batch", "component_id": "api", "assignment": {"persona": "general"}}

    probe_profile = {"provider": "p", "model": "m", "reasoning": "high", "retries": 0, "timeout_seconds": 10,
                     "max_input_tokens": 100000, "max_output_tokens": 2000}
    turn0_tokens = estimate_tokens(assessment._request(
        assemble([row]), batch=batch_obj, role="control_assessor", guidance={"bundle_sha256": "a" * 64}, text="guidance",
        profile=probe_profile, settings=settings, transcript=(), queries=0, turn=0, retry=0, part=None))
    budget = turn0_tokens + 5
    events_path = tmp_path / "data" / "logs" / "pipeline.jsonl"
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        return ModelResult({
            "schema": assessment.TURN_SCHEMA,
            "action": "retrieve",
            "requests": [{"source_identity": ev["reference"]["source_identity"], "locator": None}],
        })

    result = assessment.investigate(
        repository_root=tmp_path, run_root=tmp_path, batch=batch_obj, packages=[row], role="control_assessor",
        settings=settings, resolver=boundary.resolver, profile={**probe_profile, "max_input_tokens": budget},
        infer=infer)
    assert len(calls) == 1
    assert result["status"] == "input_budget"
    assert result["row_status"] == {"row-00": "input_budget"}
    assert len(result["attempts"]) == 2
    budget_attempt = result["attempts"][-1]
    assert budget_attempt["turn"] == 1
    assert budget_attempt["error_class"] == "input_budget"
    assert budget_attempt["input_tokens_estimated"] > budget
    assert any(gap.startswith("input_budget: turn 1 request estimate ") for gap in result["row_gaps"]["row-00"])
    assert not any("model turns exhausted" in gap for gap in result["row_gaps"]["row-00"])
    import json
    logged = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
    budget_events = [
        e for e in logged
        if e["event_type"] == "OWASP_MODEL_ATTEMPT" and e["details"].get("error_class") == "input_budget"
    ]
    assert len(budget_events) == 1 and budget_events[0]["details"]["turn"] == 1
