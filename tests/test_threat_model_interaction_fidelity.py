"""Qualification and physical-site regressions for generated routing hypotheses."""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.graph.analyzers import apply_analyzer_sinks
from appsec_review.graph.contract import admissibility
from appsec_review.graph.normalize import normalize_scope
from appsec_review.threat_model.assemble import assemble
from appsec_review.threat_model.contract import Basis, LaneResult, Limits, SourceSpan, canonical
from appsec_review.threat_model.lanes.interactions import interactions
from appsec_review.threat_model.reference import load_reference
from tests.test_threat_model_assembly import process
from tests.test_threat_model_index_view import Run, SNAPSHOT, SYNTAX, admitted, call
from tests.test_threat_model_lane_interactions import GRAPH, call_site, entry_point
from tests.threat_model_support import FakeEvidenceView, record

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("qualification", ["eligible", "partial", "disagree", "inexact", "coverage", "producer"],
                         ids=["eligible", "partial", "disagree", "inexact", "coverage", "producer"])
def test_normalized_graph_qualification_survives_publication(tmp_path: Path, monkeypatch, qualification: str) -> None:
    import os
    from tests.graph.test_normalize import CATALOG, SCOPE, SOURCES, _exports
    monkeypatch.setattr(os, "fsync", lambda _: None)
    normalized = normalize_scope(
        _exports(), scope=SCOPE, target_snapshot=SNAPSHOT, sources=SOURCES, catalog=CATALOG,
        tool_version="2.27.0", export_pack_sha256="e" * 64)
    rules = load_reference(ROOT)
    fact = next(f for f in normalized.facts if f.family.value == "entry_point"
                and rules.interaction_for_source_class(f.payload["result"]["source_class"]) is not None)
    payload = json.loads(canonical(fact.payload))
    if qualification in {"partial", "disagree"}:
        payload["cross_check"]["state"] = qualification
    elif qualification == "inexact":
        payload["exact"] = False
    elif qualification == "coverage":
        payload["coverage_status"] = "partial"
        payload["gaps"] = ["bounded graph export"]
    elif qualification == "producer":
        payload["producer"]["name"] = "clangd"
    payload["admissibility"] = admissibility(payload)
    entity = replace(fact, payload=payload).to_entity()
    run = Run(tmp_path)
    run.accept(GRAPH[0], [run.shard(GRAPH[0], "graph", "graph-qualified", [entity])])
    with admitted(run) as reads:
        result = interactions(run.view(), rules, Limits())
    assert any(r["output_kind"] == "code_graph_facts" for r in reads.document()["reads"])
    if qualification == "eligible":
        interaction, = result.facts
        assert interaction.basis is Basis.VERIFIED_SEMANTIC
        assert interaction.attributes["build_unit_id"] == SCOPE["build_unit_id"]
        assert interaction.evidence[0].entity_id == entity.identity.value
        assert interaction.native_identity["file_sha256"] == entity.location.file_sha256
    else:
        assert not result.facts
        assert any(g["scope_id"] == entity.identity.value for g in result.gaps)


def test_real_analyzer_only_sink_never_establishes_a_semantic_interaction() -> None:
    diagnostic = {
        "identity": "diagnostic:1", "name": "cert-env33-c",
        "payload": {"scanner": "clang-tidy", "native_rule_id": "cert-env33-c"},
        "location": {"path": "src/run.c", "file_sha256": "a" * 64,
                     "start_byte": 0, "end_byte": 0, "start_line": 1, "end_line": 1,
                     "start_column": 1, "end_column": 1},
    }
    generated = apply_analyzer_sinks(
        (), [diagnostic], [], target_snapshot="snapshot",
        scope={"scope_id": "scope", "language": "c", "build_unit_id": "unit", "component_id": None})
    fact, = generated.facts
    entity = fact.to_entity()
    location = entity.location
    observed = record(*GRAPH, "sink_site", entity.identity.value, entity.payload,
                      at=SourceSpan(location.path, location.file_sha256, 1, 1, 0, 0))
    result = interactions(FakeEvidenceView().add(observed), load_reference(ROOT), Limits())
    assert not result.facts
    gap, = [gap for gap in result.gaps if gap["scope_id"] == entity.identity.value]
    assert "clang-static" in gap["reason"]
    assert all(reason in gap["reason"] for reason in
               ("inexact_location", "incomplete_coverage", "cross_check_partial"))


@pytest.mark.parametrize("state", ["partial", "disagree"], ids=["partial", "disagree"])
def test_graph_crosscheck_limitations_are_not_verified(state: str) -> None:
    observed = entry_point("entry:unqualified", "remote", "src/a.c", 1)
    payload = {**observed.payload, "coverage_status": "complete",
               "producer": {"name": "codeql-export"}, "cross_check": {"state": state}}
    payload["admissibility"] = admissibility(payload)
    result = interactions(FakeEvidenceView().add(replace(observed, payload=payload)),
                          load_reference(ROOT), Limits())
    assert not result.facts
    assert any(f"cross_check_{state}" in gap["reason"] for gap in result.gaps)


@pytest.mark.parametrize("language", ["javascript", None, ""], ids=["wrong", "missing", "empty"])
def test_catalog_language_is_required(language: str | None) -> None:
    observed = call_site("ast:bind", "bind", "src/a.c")
    observed = replace(observed, payload={**observed.payload, "language": language})
    result = interactions(FakeEvidenceView().add_call("bind", observed), load_reference(ROOT), Limits())
    assert not result.facts
    if not language:
        assert any("language" in gap["reason"] for gap in result.gaps)


def test_language_filter_precedes_real_index_query_bound(tmp_path: Path, monkeypatch) -> None:
    import os
    monkeypatch.setattr(os, "fsync", lambda _: None)
    run = Run(tmp_path)
    valid = call("valid", "bind", 1)
    invalid = [replace(call(f"foreign-{i}", "bind", i + 2),
                       payload={**valid.payload, "language": "javascript"}) for i in range(5)]
    run.accept(SYNTAX[0], [run.shard(SYNTAX[0], "analysis", "ts-c", [*invalid, valid])])
    with admitted(run) as reads:
        result = interactions(run.view(), load_reference(ROOT), Limits(max_query_rows=1))
    fact, = result.facts
    assert fact.evidence[0].entity_id == valid.identity.value
    assert result.ledger[1].records_read == 1
    assert not any(g["scope_id"] == "syntax.call.bind" for g in result.gaps)
    assert any(r["output_kind"] == "tree_sitter_ast" for r in reads.document()["reads"])


@pytest.mark.parametrize("difference", ["bytes", "build", "digest", "symbol", "scope", "line-only"],
                         ids=["bytes", "build", "digest", "symbol", "scope", "line-only"])
def test_distinct_sites_keep_identity_and_ownership(difference: str) -> None:
    first = call_site("ast:a", "recv", "shared.h", enclosing="readA", build_unit_id="unit-a")
    first = replace(first, span=replace(first.span, start_byte=0, end_byte=9))
    second = replace(first, entity_id="ast:b")
    if difference == "bytes":
        second = replace(second, span=replace(first.span, start_byte=30, end_byte=39))
    elif difference == "build":
        second = replace(second, payload={**second.payload, "build_unit_id": "unit-b"})
    elif difference == "digest":
        second = replace(second, span=replace(first.span, file_sha256="c" * 64))
    elif difference == "symbol":
        second = replace(second, payload={**second.payload, "syntax": {
            **second.payload["syntax"], "syntactic_qualifiers": ["readB"]}})
    elif difference == "scope":
        second = replace(second, payload={**second.payload, "scope_id": "other-scope"})
    else:
        first = replace(first, span=replace(first.span, start_byte=None, end_byte=None))
        second = replace(second, span=first.span)
    rules = load_reference(ROOT)
    result = interactions(FakeEvidenceView().add_call("recv", first, second), rules, Limits())
    assert len(result.facts) == 2
    assert len({canonical(f.native_identity) for f in result.facts}) == 2
    assert all(len(f.evidence) == 1 for f in result.facts)
    structure = LaneResult((process("a", unit="unit-a", paths=("shared.h",)),
                            process("b", unit="unit-b", paths=("shared.h",))))
    assembled = assemble((structure, result), rules, Limits())
    assert len(assembled.entry_points) == 2
    assert sum(f.attributes["site_count"] for f in assembled.flows) == 2
    if difference == "build":
        assert len({entry.process for entry in assembled.entry_points}) == 2


def test_identical_supported_site_observations_merge_deterministically() -> None:
    first = call_site("ast:a", "recv", "src/a.c")
    first = replace(first, span=replace(first.span, start_byte=0, end_byte=9))
    second = replace(first, entity_id="ast:b")
    rules = load_reference(ROOT)
    forward = interactions(FakeEvidenceView().add_call("recv", first, second), rules, Limits())
    backward = interactions(FakeEvidenceView().add_call("recv", second, first), rules, Limits())
    assert canonical(forward) == canonical(backward)
    fact, = forward.facts
    assert fact.basis is Basis.OBSERVED_SYNTAX and len(fact.evidence) == 2
