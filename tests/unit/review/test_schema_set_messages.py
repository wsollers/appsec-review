"""Schema rejections name what would have been accepted, so a repair turn can comply instead of guessing again.

On run 2026-11-15-0005 the red-compact validator rejected about 430 cell answers with messages such as
``is not in the closed set`` and ``does not match the declared pattern`` that named no accepted value; the repair
turn then guessed another value outside the set.
"""
from __future__ import annotations

from pathlib import Path

from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet

ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = SchemaSet(ROOT / "docs" / "schemas" / "inference-security-review")


def test_closed_set_pattern_property_and_one_of_rejections_name_the_accepted_values() -> None:
    claim = {
        "id": "c1", "leads": [], "security_predicate": "format_string", "statement": "x", "support": {},
        "counter": {"note": "weighs against"},
        "poc_basis": {"unknowns": ["no sanitizer is visible"]},
        "taint_paths": [{"source": "n1", "sink": "n2",
                         "nodes": [{"id": "n1", "role": "step", "label": None, "why": "a"},
                                   {"id": "n2", "role": "sink", "label": None, "why": "b"}],
                         "edges": [{"from": "n1", "to": "n2", "kind": "dataflow", "basis": "catalog-api", "cites": []}]}],
        "evidence_requests": [{"predicate": "security_impact", "requested_kind": "source_excerpt", "anchors": [],
                               "question": "q"}],
    }
    errors = SCHEMAS.errors("red-compact", {"claims": [claim]})
    joined = "\n".join(errors)
    assert ("$.claims[0].security_predicate: is not in the closed set (memory_corruption, out_of_bounds_read, "
            "use_after_free") in joined
    assert "$.claims[0].taint_paths[0].edges[0].kind: is not in the closed set (data, call, alias, control, cross_boundary)" in joined
    assert ("$.claims[0].taint_paths[0].edges[0].basis: is not in the closed set (accepted_tool_path, "
            "source_mapped_analysis, analyst_hypothesis)") in joined
    assert "$.claims[0].taint_paths[0].nodes[0].role: is not in the closed set (source, transform, sanitizer, guard, boundary, sink)" in joined
    assert ("$.claims[0].counter: unexpected property note; allowed: affected_construct, attacker_input_control, "
            "configuration_enables, missing_or_ineffective_guard, security_impact, source_to_sink_reachability") in joined
    assert "$.claims[0].poc_basis.unknowns[0]: does not match the declared pattern ^([A-Z][0-9]{1,4}|asr:" in joined
    assert ("$.claims[0].evidence_requests[0].requested_kind: matches 0 oneOf branches, expected exactly one "
            "(allowed values: source_line, compiled_view, dataflow, configuration, build_provenance, deployment, "
            "run_artifact, other, source_file, source_span") in joined
    assert "... " in joined and " more)" in joined  # the long entity-kind tail is counted, not listed in full


def test_length_rejections_state_the_measured_length_and_the_bounds() -> None:
    errors = SCHEMAS.errors("judge-result-compact", {"verdict": "A", "per_predicate": {}, "reason": "x" * 1001})
    assert errors == ["$.reason: string length out of bounds (1001 characters, allowed 1..1000)"]
    assert SCHEMAS.errors("judge-result-compact", {"verdict": "A", "per_predicate": {}, "reason": "x" * 1000}) == []


def test_accepted_values_keep_the_old_message_prefixes() -> None:
    errors = SCHEMAS.errors("blue-compact", {"stance": "supports"})
    assert len(errors) == 1 and errors[0].startswith("$.stance: is not in the closed set (")
    assert errors[0].endswith("(contradicts, qualifies, unresolved)")
