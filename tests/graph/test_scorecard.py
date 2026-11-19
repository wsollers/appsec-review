"""The graph quality scorecard (T-5016): closed schema, first-party functions once, producers and paths."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.graph import contract as c
from appsec_review.graph.correlate import CORRELATION_RULE
from appsec_review.graph.crosscheck import CrossCheckInputs, cross_check
from appsec_review.graph.normalize import CoverageRow
from appsec_review.graph.scorecard import (
    SCHEMA_PATH, SCORECARD_SCHEMA, ScorecardError, assemble_scorecard, render_scorecard, scope_scorecard,
    validate_scorecard,
)
from appsec_review.retrieval.model import RelationKind, RelationRecord
from appsec_review.review.dispositions import SourceDispositions
from tests.fixtures.graph.secondary.builder import SCOPE, SNAPSHOT, build_secondary

ROOT = Path(__file__).resolve().parents[2]
CATALOG = {"version": c.CATALOG_SCHEMA, "revision": 2, "release_id": "fixture"}


def _graph(tmp_path, *, dispositions=None, with_tree_sitter=True):
    fixture = build_secondary(tmp_path)
    symbols = [fixture.symbol(name) for name in ("helper", "other", "process")]
    process = symbols[2].identity.value  # the normalizer names the CodeQL function symbol as the caller
    facts = {"agree": fixture.call("helper", "process", "helper(n)", caller_symbol=process),
             "disagree": fixture.call("other", "process", "other(a)", caller_symbol=process),
             "external": fixture.call("memcpy", "process", "memcpy(dst, src, b)", dispatch="external_undefined",
                                      callee_symbol=None, caller_symbol=process)}
    entry, sink = fixture.entry("read(0, buf, sizeof buf)"), fixture.sink("memcpy(out, buf, k)")
    path = fixture.path(entry, sink, [("read(0, buf, sizeof buf)", 0), ("n * 2", 0), ("memcpy(out, buf, k)", 0)])
    inputs = CrossCheckInputs(clangd=(fixture.read("clangd"),),
                              tree_sitter=(fixture.read("tree_sitter"),) if with_tree_sitter else ())
    result = cross_check([*facts.values(), entry, sink, path], inputs, target_snapshot=SNAPSHOT, scope=SCOPE,
                         sources=fixture.sources, graph_symbols=symbols)
    bridged = RelationRecord(RelationKind.DERIVED_FROM, path.identity.value, "asr:tool_observation:" + "a" * 64, True,
                             1.0, None, {"rule": CORRELATION_RULE, "state": "bridged", "code_flows": []})
    coverage = [CoverageRow(SCOPE["scope_id"], family, c.Coverage.COMPLETE, (), 0,
                            {"excluded_vendored": 7} if family is c.Family.CALL_SITE else {}) for family in c.Family]
    section = scope_scorecard(scope={**SCOPE, "export_status": "SUCCEEDED"}, facts=result.facts, symbols=symbols,
                              relations=[*result.relations, bridged], coverage=coverage, dispositions=dispositions,
                              cross_check={"producers": {"clangd": ["x"], **({"tree-sitter": ["y"]} if with_tree_sitter else {})}})
    return fixture, facts, path, section


def test_scorecard_validates_names_every_first_party_function_once_and_counts_edges_by_verdict(tmp_path) -> None:
    fixture, facts, path, section = _graph(tmp_path)
    document = assemble_scorecard(run_id="2026-10-12-0004", target_snapshot=SNAPSHOT, scopes=[section], catalog=CATALOG,
                                  dispositions=SourceDispositions(vendored=("**/third_party/**",)))
    validate_scorecard(document)
    assert document["schema"] == SCORECARD_SCHEMA and document["dispositions"]["configured"] is True
    names = [entry["name"] for entry in section["functions"]]
    assert sorted(names) == ["helper", "other", "process"] and len(set(entry["symbol"] for entry in section["functions"])) == 3
    process = next(entry for entry in section["functions"] if entry["name"] == "process")
    assert process["calls"]["total"] == 3 and process["calls"]["agree"] == 2 and process["calls"]["disagree"] == 1
    assert process["calls"]["not_covered"] == 0 and process["producers"] == {"clangd": 1, "tree-sitter": 3}
    helper = next(entry for entry in section["functions"] if entry["name"] == "helper")
    assert helper["calls"]["total"] == 0 and helper["producers"] == {}
    # ``return helper(b)`` on line 8 has no CodeQL call_site: clangd and tree-sitter each publish a secondary_only
    # fact whose caller is their own symbol, not a CodeQL function, so they are counted, not attributed.
    assert section["call_sites"]["secondary_only"] == 2 and section["call_sites"]["unattributed"] == {"secondary_only": 2}
    assert section["call_sites"]["total"] == 5 and section["cross_check_producers"] == ["clangd", "tree-sitter"]
    assert section["exclusions"] == {"call_site": {"vendored": 7}}
    assert section["sinks"] == {"total": 1, "classified": 1, "unclassified": 0, "by_class": {"memory_write": 1},
                                "unclassified_apis": {}}
    assert document["totals"]["first_party_functions"] == 3 and document["totals"]["excluded_facts"] == 7


def test_scorecard_paths_carry_endpoints_eligibility_producers_and_correlation(tmp_path) -> None:
    fixture, facts, path, section = _graph(tmp_path)
    [row] = section["paths"]
    assert row["identity"] == path.identity.value and row["correlation"] == "bridged"
    assert row["source"]["source_class"] == "file" and row["source"]["path"] == "src/io.c"
    assert row["sink"]["sink_class"] == "memory_write" and row["sink"]["path"] == "src/io.c"
    assert row["hop_count"] == 2 and row["direct_eligible"] is True and row["ineligibility_reasons"] == []
    assert row["producers"] == ["codeql-export"]
    assert section["correlation"] == {"bridged": 1, "partial": 0, "broken": 0, "uncorrelated": 0}


def test_totals_do_not_depend_on_display_samples(tmp_path, monkeypatch):
    from appsec_review.graph import scorecard
    _, _, _, full = _graph(tmp_path / "full")
    monkeypatch.setattr(scorecard, "MAX_FUNCTIONS", 1)
    monkeypatch.setattr(scorecard, "MAX_PATHS", 0)
    _, _, _, sample = _graph(tmp_path / "sample")
    complete = assemble_scorecard(run_id="r", target_snapshot=SNAPSHOT, scopes=[full], catalog=CATALOG)
    truncated = assemble_scorecard(run_id="r", target_snapshot=SNAPSHOT, scopes=[sample], catalog=CATALOG)
    assert truncated["totals"] == complete["totals"]
    assert sample["functions_omitted"] == 2 and sample["paths_omitted"] == 1


def test_dispositions_decide_which_functions_are_first_party(tmp_path) -> None:
    _, _, _, section = _graph(tmp_path, dispositions=SourceDispositions(vendored=("src/net.c",)))
    assert section["functions"] == []
    document = assemble_scorecard(run_id="r", target_snapshot=SNAPSHOT, scopes=[section], catalog=CATALOG,
                                  dispositions=SourceDispositions(vendored=("src/net.c",)))
    assert document["totals"]["first_party_functions"] == 0 and document["totals"]["call_sites"] == 5


def test_rendering_is_one_screen_and_names_producers_and_paths(tmp_path) -> None:
    _, _, _, section = _graph(tmp_path)
    document = assemble_scorecard(run_id="2026-10-12-0004", target_snapshot=SNAPSHOT, scopes=[section], catalog=CATALOG)
    text = render_scorecard(document)
    lines = text.splitlines()
    assert 5 <= len(lines) <= 40 and max(len(line) for line in lines) <= 200
    assert lines[0].startswith("Code-graph quality scorecard") and "producers clangd, tree-sitter" in text
    assert "fn process src/net.c:4 calls 3 (agree 2, codeql-only 0, secondary-only 0); clangd 1, tree-sitter 3" in text
    assert "path file -> memory_write src/io.c:8 hops 2 eligible bridged by codeql-export" in text
    assert "excluded: call_site vendored 7" in text


def test_the_schema_is_closed_and_the_document_is_deterministic(tmp_path) -> None:
    schema = json.loads((ROOT / SCHEMA_PATH).read_text(encoding="utf-8"))
    assert schema["additionalProperties"] is False and schema["$defs"]["scope"]["additionalProperties"] is False
    assert schema["$defs"]["function"]["additionalProperties"] is False and schema["$defs"]["path"]["additionalProperties"] is False
    _, _, _, section = _graph(tmp_path)
    first = assemble_scorecard(run_id="r", target_snapshot=SNAPSHOT, scopes=[section], catalog=CATALOG)
    second = assemble_scorecard(run_id="r", target_snapshot=SNAPSHOT, scopes=[dict(section)], catalog=CATALOG)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    with pytest.raises(ScorecardError, match="violates its schema"):
        validate_scorecard({**first, "extra": True})
    with pytest.raises(ScorecardError):
        validate_scorecard({**first, "scopes": [{**section, "functions": [{**section["functions"][0], "note": 1}]}]})
