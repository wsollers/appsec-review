from __future__ import annotations

from appsec_review.graph.correlate import (
    CORRELATION_RULE, METHOD_LINE, CorrelationState, correlate,
)
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.retrieval import IndexBuilder
from appsec_review.retrieval.model import RelationKind
from tests.fixtures.graph.secondary.builder import FILES, SNAPSHOT, build_secondary, sarif_step

SOURCES = {path: SourceFile.from_bytes(text.encode()) for path, text in FILES.items()}
ENTRY = ("read(0, buf, sizeof buf)", 0)
SINK = ("k", 1)
PATH_STEPS = (ENTRY, ("n * 2", 0), ("m + 1", 0), SINK)


def _flow(steps, *, code_flow: int = 0, start: int = 1):
    return [sarif_step(SOURCES, start + index, "src/io.c", needle, nth, code_flow=code_flow)
            for index, (needle, nth) in enumerate(steps)]


BRIDGED = _flow(PATH_STEPS)
LINE_ONLY = _flow((ENTRY, ("m = n * 2", 0), ("m + 1", 0), SINK))
SINK_MISS = _flow((ENTRY, ("n * 2", 0), ("out", 1)))
SOURCE_MISS = _flow((("buf[64]", 0), ("n * 2", 0), SINK))


def _setup(tmp_path, observations, *, priority=None, seed=None):
    fixture = build_secondary(tmp_path, clangd=None, ir_calls=None, ast_calls=None, observations=observations,
                              priority=priority, seed=seed)
    entry, sink = fixture.entry(*ENTRY), fixture.sink(*SINK)
    path = fixture.path(entry, sink, PATH_STEPS)
    rows = fixture.rows("observations", ["tool_observation"])
    priority_rows = fixture.rows("priority", ["review_signal", "review_flow_step"]) if priority is not None else None
    return fixture, (entry, sink, path), rows, priority_rows


def _derived(result, target):
    return [r for r in result.relations if r.kind is RelationKind.DERIVED_FROM and r.target_id == target]


def test_exact_endpoints_and_span_matched_middle_steps_are_bridged(tmp_path) -> None:
    fixture, (_, _, path), rows, _ = _setup(tmp_path, [{"key": "a", "flows": BRIDGED}])
    result = correlate([path, *_setup_facts(fixture)], rows, sources=fixture.sources)
    [flow] = result.correlations
    assert flow.state is CorrelationState.BRIDGED and flow.path == path.identity.value
    assert [step["path_step"] for step in flow.matched_steps] == [0, 1, 2, 3]
    [relation] = _derived(result, fixture.ids["obs:a"])
    assert (relation.source_id, relation.exact, relation.confidence) == (path.identity.value, True, 1.0)
    assert relation.payload["rule"] == CORRELATION_RULE and relation.payload["state"] == "bridged"
    assert relation.payload["code_flows"][0]["unmatched_steps"] == []
    assert not [r for r in result.relations if r.kind is RelationKind.SAME_AS]


def _setup_facts(fixture):
    return [fixture.entry(*ENTRY), fixture.sink(*SINK)]


def test_one_line_only_middle_step_is_partial_and_listed(tmp_path) -> None:
    fixture, (_, _, path), rows, _ = _setup(tmp_path, [{"key": "b", "flows": LINE_ONLY}])
    result = correlate([path, *_setup_facts(fixture)], rows, sources=fixture.sources)
    [flow] = result.correlations
    assert flow.state is CorrelationState.PARTIAL
    assert [dict(step) for step in flow.ambiguous_steps] == [{"ordinal": 2, "path_steps": [1], "method": METHOD_LINE}]
    [relation] = _derived(result, fixture.ids["obs:b"])
    assert relation.exact is False and "1 ambiguous" in relation.ambiguity
    assert relation.payload["state"] == "partial"


def test_sink_without_sink_site_is_broken_and_still_published(tmp_path) -> None:
    fixture, (_, _, path), rows, _ = _setup(tmp_path, [{"key": "c", "flows": SINK_MISS}])
    result = correlate([path, *_setup_facts(fixture)], rows, sources=fixture.sources)
    [flow] = result.correlations
    assert flow.state is CorrelationState.BROKEN and flow.reason == "sink_unmatched" and flow.path is None
    assert result.summary["broken"] == [{"observation": fixture.ids["obs:c"], "code_flow": 0, "thread_flow": 0,
                                         "reason": "sink_unmatched"}]
    assert result.summary["states"] == {"bridged": 0, "partial": 0, "broken": 1}


def test_broken_flow_with_a_matched_sink_is_related_from_the_sink_site(tmp_path) -> None:
    fixture, (_, sink, path), rows, _ = _setup(tmp_path, [{"key": "d", "flows": SOURCE_MISS}])
    result = correlate([path, *_setup_facts(fixture)], rows, sources=fixture.sources)
    [flow] = result.correlations
    assert flow.state is CorrelationState.BROKEN and flow.reason == "source_unmatched"
    [relation] = _derived(result, fixture.ids["obs:d"])
    assert relation.source_id == sink.identity.value and relation.exact is False and relation.confidence == 0.0
    assert relation.payload["state"] == "broken" and "source_unmatched" in relation.ambiguity


def test_same_as_to_review_flow_steps_only_when_priority_is_accepted(tmp_path) -> None:
    priority = [{"path_id": "path-a", "observation": "a", "code_flow": 0, "flow_steps": BRIDGED}]
    fixture, (_, _, path), rows, priority_rows = _setup(tmp_path / "with", [{"key": "a", "flows": BRIDGED}],
                                                        priority=priority)
    result = correlate([path, *_setup_facts(fixture)], rows, sources=fixture.sources, priority=priority_rows)
    same_as = sorted((r for r in result.relations if r.kind is RelationKind.SAME_AS),
                     key=lambda r: r.payload["review_flow_ordinal"])
    assert [(r.source_id, r.target_id) for r in same_as] == [
        (fixture.ids[f"step:path-a:{ordinal}"], path.identity.value) for ordinal in range(4)]
    assert [r.payload["path_steps"] for r in same_as] == [[0], [1], [2], [3]]
    assert all(r.exact is False and r.ambiguity for r in same_as)  # line-granular review steps
    assert result.summary["same_as"] == 4

    without, (_, _, path2), rows2, _ = _setup(tmp_path / "without", [{"key": "a", "flows": BRIDGED}])
    plain = correlate([path2, *_setup_facts(without)], rows2, sources=without.sources)
    assert not [r for r in plain.relations if r.kind is RelationKind.SAME_AS]
    assert plain.summary["priority_available"] is False


def test_code_flow_order_is_preserved_in_the_relation_payload(tmp_path) -> None:
    flows = [*_flow(PATH_STEPS, code_flow=1, start=1), *_flow(PATH_STEPS[:1] + (("m = n * 2", 0),) + PATH_STEPS[2:],
                                                               code_flow=0, start=5)]
    fixture, (_, _, path), rows, _ = _setup(tmp_path, [{"key": "e", "flows": flows}])
    result = correlate([path, *_setup_facts(fixture)], rows, sources=fixture.sources)
    assert [(item.code_flow, item.state.value) for item in result.correlations] == [(0, "partial"), (1, "bridged")]
    [relation] = _derived(result, fixture.ids["obs:e"])
    assert [entry["code_flow"] for entry in relation.payload["code_flows"]] == [0, 1]
    assert relation.payload["state"] == "partial" and relation.exact is False


def test_identical_inputs_produce_identical_relation_ids(tmp_path) -> None:
    observations = [{"key": "a", "flows": BRIDGED}, {"key": "b", "flows": LINE_ONLY},
                    {"key": "d", "flows": SOURCE_MISS}]
    priority = [{"path_id": "path-a", "observation": "a", "code_flow": 0, "flow_steps": BRIDGED}]
    first, (_, _, path1), rows1, prio1 = _setup(tmp_path / "1", observations, priority=priority)
    second, (_, _, path2), rows2, prio2 = _setup(tmp_path / "2", observations, priority=priority, seed=11)
    one = correlate([path1, *_setup_facts(first)], rows1, sources=first.sources, priority=prio1)
    two = correlate([*reversed(_setup_facts(second)), path2], list(reversed(rows2)), sources=second.sources,
                    priority=list(reversed(prio2)))
    assert [r.relation_id for r in one.relations] == [r.relation_id for r in two.relations]
    assert [r.payload for r in one.relations] == [r.payload for r in two.relations]
    assert one.correlations == two.correlations
    builder = IndexBuilder(tmp_path / "graph.sqlite", name="graph", fingerprint="f" * 64, target_snapshot=SNAPSHOT,
                           shard_id="graph-paths")
    for relation in one.relations:
        builder.add_relation(relation)
    assert len(builder.build()) == 64


def test_observations_without_flows_are_not_path_problems(tmp_path) -> None:
    fixture, (_, _, path), rows, _ = _setup(tmp_path, [{"key": "f", "flows": []}])
    result = correlate([path, *_setup_facts(fixture)], rows, sources=fixture.sources)
    assert result.correlations == () and result.relations == ()


def test_flow_ending_at_the_sink_operand_bridges_a_whole_expression_sink(tmp_path) -> None:
    """Real path-problem flows end at the argument; a sink located at the whole call still matches
    through its exact ``result.operand`` span, without changing the sink's identity."""
    from dataclasses import asdict, replace

    fixture, (entry, operand_sink, _), rows, _ = _setup(tmp_path, [{"key": "op", "flows": BRIDGED}])
    whole = fixture.location("src/io.c", "memcpy(out, buf, k)")
    result_block = {**operand_sink.payload["result"],
                    "operand": {"exact": True, "location": asdict(operand_sink.location)}}
    sink = replace(operand_sink, location=whole, payload={**operand_sink.payload, "result": result_block})
    path = fixture.path(entry, sink, PATH_STEPS)
    result = correlate([path, entry, sink], rows, sources=fixture.sources)
    [flow] = result.correlations
    assert flow.state is CorrelationState.BRIDGED and flow.path == path.identity.value
    inexact = {**result_block, "operand": {**result_block["operand"], "exact": False}}
    unmatched = replace(sink, payload={**sink.payload, "result": inexact})
    [flow] = correlate([fixture.path(entry, unmatched, PATH_STEPS), entry, unmatched], rows,
                       sources=fixture.sources).correlations
    assert flow.state is CorrelationState.BROKEN and flow.reason == "sink_unmatched"
