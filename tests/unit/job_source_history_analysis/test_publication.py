from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json

import pytest

from appsec_review.jobs.job_source_history_analysis import job, symbols
from appsec_review.storage import atomic_json
from .support import HEAD, PARENT, SOURCE, artifact, context, document, handler, nodes
from .test_handlers import baseline, invoke


def ranked_fixture(unit):
    source = symbols.extract({"nodes": nodes()}, SOURCE, "Python", "a.py")["symbols"][0]
    source.update({
        "path": "a.py", "component_id": "component", "churn_lines": 2, "change_count": 1,
        "relative_churn": 1.0, "revision_frequency": 0.166667, "author_entropy": 0.0, "attribution_gaps": [],
        "changes": [{"change_id": HEAD, "added": 1, "deleted": 1}]})
    metrics = document(unit, unit.outputs["analyze.compute_signals"])
    metrics["files"]["a.py"].update({
        "sii": {"rank": 1, "tier": 1, "score": 50}, "source": {"source_id": ".", "root": "."},
        "cyclomatic_complexity": 1, "cognitive_complexity": 0})
    metrics["components"]["component"]["priority"] = {"rank": 1, "score": 50}
    source["sii"] = {"rank": 1, "tier": 1, "score": 30}
    metrics.update({"symbols": {"a.py::f": source}, "file_ranking": ["a.py"],
                    "symbol_ranking": ["a.py::f"], "component_ranking": ["component"]})
    entries = [
        {"scope": scope, "rank": 1, "tier": 1, "score": score,
         "identity": {"path": "a.py", "symbol_id": symbol_id}, "window": {"months": 6}}
        for scope, symbol_id, score in (("file", None, 50), ("symbol", "a.py::f", 30))]
    unit.outputs["analyze.rank"] = {
        "artifact": artifact(unit, "ranked.json", metrics),
        "hotspots": artifact(unit, "hotspots.json", {
            "schema": job.HOTSPOT_SCHEMA, "selection": {
                "mode": "fixed",
                "configured": {"hotspot_count": 10, "proportional_ratio": None,
                               "min_hotspots": None, "max_hotspots": None},
                "effective_caps": {"file": 10, "symbol": 10},
                "selected_counts": {"file": 1, "symbol": 1}},
            "entries": entries}), "gaps": []}
    return unit


class Builder:
    def __init__(self, path, **kwargs):
        self.path, self.options = path, kwargs
        self.entities, self.relations, self.coverage = [], [], []

    def add_entity(self, value):
        self.entities.append(value)

    def add_relation(self, value):
        self.relations.append(value)

    def add_coverage(self, *args):
        self.coverage.append(args)

    def build(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(b"fixture index boundary")


@pytest.mark.parametrize("kind", ["ranked", "unavailable", "partial", "reuse"])
def test_index_handler_preserves_entities_locations_coverage_and_manifest(tmp_path, monkeypatch, kind):
    unit = baseline(context(tmp_path, "publish.index_history", files={"a.py": SOURCE, "generated/b.py": SOURCE}))
    if kind != "unavailable":
        ranked_fixture(unit)
    if kind == "partial":
        unit.outputs["acquire.normalize_changes"]["gaps"] = ["shallow_history"]
        unit.outputs["resolve_sources.bind_snapshot"]["eligible"]["a.py"]["exact"] = False
        unit.outputs["analyze.line_history"]["gaps"] = ["line_history_truncated"]
        unit.outputs["acquire.github_enrichment"] = {"artifact": artifact(unit, "github.json", {"facts": {}}),
                                                   "terminal_status": "PARTIAL", "gaps": ["github_page_unavailable"]}
        metrics = document(unit, unit.outputs["analyze.rank"])
        excluded = {**deepcopy(metrics["files"]["a.py"]), "path": "generated/b.py",
                    "component_id": "unranked", "rank_eligibility": "excluded:generated", "recent_changes": []}
        del excluded["sii"]
        metrics["files"]["generated/b.py"] = excluded
        unit.outputs["analyze.rank"]["artifact"] = artifact(unit, "ranked-with-excluded.json", metrics)
        unit.outputs["resolve_sources.bind_snapshot"]["eligible"]["generated/b.py"] = {
            **unit.outputs["resolve_sources.bind_snapshot"]["eligible"]["a.py"], "source_path": "generated/b.py"}
    builders = []

    def builder(path, **kwargs):
        value = Builder(path, **kwargs)
        builders.append(value)
        return value

    monkeypatch.setattr(job, "IndexBuilder", builder)
    upstream = artifact(unit, "upstream.json", {"indexes": []})
    monkeypatch.setattr(job, "resolve_context_manifest", lambda ctx: (ctx.run_root / upstream["path"], upstream["sha256"]))
    verified = []

    def verify(root, path, digest):
        verified.append((path, digest))
        return {"indexes": []}, digest

    monkeypatch.setattr(job, "load_verified_manifest", verify)
    manifests = []

    def manifest(path, **kwargs):
        manifests.append((path, kwargs))
        atomic_json(path, {"schema": "appsec-review/retrieval-manifest/2", "fixture": True})

    monkeypatch.setattr(job, "write_manifest", manifest)
    result = invoke(unit)
    assert result["index_identity"]["name"] == "history" and result["index_identity"]["shard_id"] == "git-history"
    assert result["index_identity"]["producer"] == {"job": "job_source_history_analysis", "vcs": "git"}
    assert result["index_identity"]["schema"] == "appsec-review/retrieval-index/2"
    assert manifests[0][1]["run_id"] == "fixture" and manifests[0][1]["target_snapshot"] == "snapshot"
    assert manifests[0][1]["indexes"][0].sha256 == result["index_identity"]["sha256"]
    assert len(verified) == 2 and result["manifest"]["path"].endswith("git-history-attempt_0001.json")
    built = builders[0]
    coverage = {item[0]: item[1:] for item in built.coverage}
    assert coverage["git-history"][0] == ("unavailable" if kind == "unavailable" else "partial" if kind == "partial" else "complete")
    assert coverage["pull-request-timing"] == ("unavailable", "pr_timing_not_acquired")
    assert coverage["changelog-history"] == ("unavailable", "no_changelog_files")
    if kind != "unavailable":
        entities = {entity.native_id: entity for entity in built.entities}
        expected = {HEAD, PARENT, "component:component", "file:a.py", "symbol:a.py::f",
                    "hotspot:file:a.py", "hotspot:symbol:a.py::f"}
        if kind == "partial":
            expected.add("file:generated/b.py")
            assert entities["file:generated/b.py"].payload["rank_eligibility"] == "excluded:generated"
        assert set(entities) == expected
        file = entities["file:a.py"]
        assert file.location.path == "a.py" and file.location.start_line == 1 and file.location.end_line == 2
        assert file.location.ambiguous is (kind == "partial")
        symbol = entities["symbol:a.py::f"]
        assert symbol.location.mapping_method == "tree-sitter-byte-and-point-exact"
        assert len(built.relations) == 6
    else:
        assert built.entities == [] and built.relations == []
    if kind == "reuse":
        assert invoke(unit)["index_identity"] == result["index_identity"]
        assert len(builders) == 1, "an already content-addressed index is reused"


def test_rank_symbol_metrics_and_coverage_gaps(tmp_path):
    unit = baseline(context(tmp_path, "analyze.rank"))
    unit.outputs["acquire.github_enrichment"] = {"terminal_status": "SUCCEEDED", "gaps": []}
    symbol = symbols.extract({"nodes": nodes()}, SOURCE, "Python", "a.py")["symbols"][0]
    symbol.update({
        "path": "a.py", "component_id": "component", "churn_lines": 2, "change_count": 1,
        "relative_churn": 1, "revision_frequency": 0.5, "author_entropy": 0, "attribution_gaps": ["symbol_attribution_incomplete"],
        "changes": [{"change_id": HEAD, "added": 1, "deleted": 1}], "complexity_gaps": ["parse_errors_in_span"]})
    unit.outputs["analyze.symbol_signals"]["artifact"] = artifact(unit, "symbol-signals-rank.json", {"symbols": {"a.py::f": symbol}})
    unit.outputs["analyze.symbol_spans"]["artifact"] = artifact(unit, "no-symbols.json", {"files": {}, "statuses": {}})
    unit.outputs["analyze.line_history"]["artifact"] = artifact(unit, "no-lines.json", {"files": {}, "statuses": {}})
    unit.outputs["analyze.fix_on_fix"]["artifact"] = artifact(unit, "incomplete-fixes.json", {
        "files": {"a.py": {"status": "unavailable", "count": None, "events": [], "undetermined": [{"reason": "missing"}]}}})
    unit.outputs["analyze.blame_age"]["young_line_share"] = {}
    unit.outputs["resolve_sources.bind_snapshot"]["eligible"]["a.py"]["exact"] = False
    result = invoke(unit)
    doc, hotspots = document(unit, result), document(unit, result, "hotspots")
    assert doc["symbol_ranking"] == ["a.py::f"] and result["ranked_symbol_count"] == 1
    assert [item["scope"] for item in hotspots["entries"]] == ["file", "symbol"]
    expected = {"working_tree_divergent", "line_history_unavailable:not_requested",
                "complexity_unavailable:not_requested", "fix_on_fix_unavailable", "young_line_share_unavailable"}
    assert expected <= set(hotspots["entries"][0]["coverage_gaps"])
    assert not any("review_bypass" in gap for gap in hotspots["entries"][0]["coverage_gaps"])
    symbol_entry = hotspots["entries"][1]
    assert symbol_entry["location"]["mapping_method"] == "tree-sitter-byte-and-point-exact"
    assert {"complexity:parse_errors_in_span", "symbol_attribution_incomplete"} <= set(symbol_entry["coverage_gaps"])
    assert hotspots["entries"][0]["inputs"]["missing_inputs"] == ["complexity"]


def test_publish_ranked_and_multi_source_projection(tmp_path, monkeypatch):
    unit = ranked_fixture(baseline(context(tmp_path, "publish.publish_handoff")))
    monkeypatch.setattr(job, "_run_history_identity", lambda *args: "identity")
    result = invoke(unit)
    doc = document(unit, result)
    assert doc["ranking"]["files"][0]["path"] == "a.py"
    assert doc["ranking"]["files"][0]["score"] == 50 and doc["ranking"]["components"][0]["rank"] == 1
    assert doc["hotspots"]["entries"] == [
        {"scope": "file", "rank": 1, "tier": 1, "score": 50, "path": "a.py", "symbol_id": None},
        {"scope": "symbol", "rank": 1, "tier": 1, "score": 30, "path": "a.py", "symbol_id": "a.py::f"}]
    outputs = {}
    for key, value in unit.outputs.items():
        if key == "publish.index_history":
            outputs[key] = value
        else:
            outputs[key] = {"by_source": {name: deepcopy(value) for name in ("left", "right")}}
    outputs["resolve_sources.resolve_history_source"]["identity"] = "identity"
    for name in ("left", "right"):
        outputs["resolve_sources.resolve_history_source"]["by_source"][name]["source"]["source_id"] = name
    multiple = replace(unit, outputs=outputs)
    result = invoke(multiple)
    combined = document(multiple, result)
    assert result["item_count"] == 2 and combined["ranking"]["scope"] == "per-source"
    assert [item["source_id"] for item in combined["ranking"]["files"]] == ["left", "right"]
    assert combined["changelog"]["scope"] == "per-source"
    assert [item["source_id"] for item in combined["sources"]["repositories"]] == ["left", "right"]
    assert len(document(multiple, combined["hotspots"])["entries"]) == 4


def test_rank_wires_sii_with_two_independent_populations(tmp_path, monkeypatch):
    unit = baseline(context(tmp_path, "analyze.rank"))
    calls = []

    def scorer(population, **kwargs):
        calls.append((population, kwargs))
        return {"ranked": [], "population": len(population), "normalization": {}, "constant_metrics": [], "tiers": {}}

    monkeypatch.setattr(job, "sii_score", scorer)
    result = invoke(unit)
    assert len(calls) == 2 and list(calls[0][0]) == ["a.py"] and calls[1][0] == {}
    assert calls[0][0]["a.py"] == {
        "relative_churn": 2.0, "revision_frequency": 0.333333, "author_entropy": 0.0,
        "complexity": 1, "churn_lines": 4, "change_count": 2}
    assert calls[0][1] == calls[1][1]
    assert calls[0][1]["weights"] == unit.job.config.settings["sii"]["weights"]
    assert str(calls[0][1]["tier_1_share"]) == "1/20"
    assert result["hotspot_entry_count"] == 0 and document(unit, result)["file_ranking"] == []


def test_publish_wires_changelog_section_without_combining_git_counts(tmp_path, monkeypatch):
    unit = baseline(context(tmp_path, "publish.publish_handoff"))
    monkeypatch.setattr(job, "_run_history_identity", lambda *args: "identity")
    calls = []

    def section(root, output, **kwargs):
        calls.append((root, output, kwargs))
        return {"role": "primary", "source": "changelog", "files": [{"path": "b.py", "change_count": 2}]}

    monkeypatch.setattr(job, "changelog_section", section)
    result = invoke(unit)
    assert calls == [(unit.job.run_root, unit.outputs["acquire.changelog_history"], {
        "git_ranked": False, "git_gaps": [], "source_id": ".", "top_n": unit.job.config.settings["ranking_top_n"]})]
    doc = document(unit, result)
    assert doc["changelog"]["files"] == [{"path": "b.py", "change_count": 2}]
    assert doc["ranking"]["files"] == [] and doc["window"]["change_count"] == 2


@pytest.mark.parametrize("git_population", ["formatting", "ranked", "absent"])
def test_changelog_precedence_uses_ranked_population_not_artifact_presence(tmp_path, monkeypatch, git_population):
    files = {"a.py": SOURCE, "ChangeLog": b"2023-11-14  Fixture\n\n\t* a.py: Update behavior.\n"}
    unit = baseline(context(tmp_path, "analyze.compute_signals", files=files))
    monkeypatch.setattr(job, "_run_history_identity", lambda *args: "identity")
    if git_population == "formatting":
        unit.outputs["analyze.classify_changes"]["artifact"] = artifact(
            unit, "formatting.json", {"classes": {HEAD: {"formatting": True}, PARENT: {"formatting": True}}})
    if git_population != "absent":
        unit.outputs["analyze.compute_signals"] = invoke(unit)
        unit.outputs["analyze.rank"] = invoke(replace(unit, unit_id="analyze.rank"))
    unit.outputs["resolve_sources.resolve_history_source"]["inputs"]["files"] = [
        {"path": path, "sha256": hashlib.sha256(data).hexdigest()} for path, data in files.items()]
    unit.outputs["acquire.changelog_history"] = invoke(replace(unit, unit_id="acquire.changelog_history"))
    assert unit.outputs["acquire.changelog_history"]["ranked_file_count"] == 1
    published = invoke(replace(unit, unit_id="publish.publish_handoff"))
    doc = document(unit, published)
    assert doc["changelog"]["role"] == ("supplement" if git_population == "ranked" else "primary")
    assert bool(doc["ranking"]["files"]) is (git_population == "ranked")
    assert doc["changelog"]["files"][0]["path"] == "a.py"


def test_rank_component_order_does_not_duplicate_a_shared_component(tmp_path):
    unit = baseline(context(tmp_path, "analyze.rank"))
    metrics = document(unit, unit.outputs["analyze.compute_signals"])
    metrics["files"]["b.py"] = {**deepcopy(metrics["files"]["a.py"]), "path": "b.py", "churn_lines": 1}
    unit.outputs["resolve_sources.bind_snapshot"]["eligible"]["b.py"] = {
        **unit.outputs["resolve_sources.bind_snapshot"]["eligible"]["a.py"], "source_path": "b.py"}
    unit.outputs["analyze.compute_signals"]["artifact"] = artifact(unit, "two-files.json", metrics)
    result = invoke(unit)
    assert result["ranked_file_count"] == 2 and result["ranked_component_count"] == 1
    assert document(unit, result)["component_ranking"] == ["component"]


def rank_population(unit, file_count, symbol_count, *, name="population"):
    metrics = document(unit, unit.outputs["analyze.compute_signals"])
    original = metrics["files"]["a.py"]
    facts = unit.outputs["resolve_sources.bind_snapshot"]["eligible"]["a.py"]
    paths = [f"{name}-{index:03d}.py" for index in range(file_count)]
    metrics["files"] = {path: {**deepcopy(original), "path": path} for path in paths}
    unit.outputs["resolve_sources.bind_snapshot"]["eligible"] = {
        path: {**facts, "source_path": path} for path in paths}
    unit.outputs["analyze.compute_signals"]["artifact"] = artifact(unit, f"{name}-signals.json", metrics)
    symbol_values = {}
    for path in paths[:symbol_count]:
        symbol = symbols.extract({"nodes": nodes()}, SOURCE, "Python", path)["symbols"][0]
        symbol.update({"path": path, "component_id": "component", "churn_lines": 2, "change_count": 1,
                       "relative_churn": 1, "revision_frequency": 0.5, "author_entropy": 0,
                       "attribution_gaps": [], "changes": [{"change_id": HEAD, "added": 1, "deleted": 1}]})
        symbol_values[symbol["symbol_id"]] = symbol
    unit.outputs["analyze.symbol_signals"]["artifact"] = artifact(
        unit, f"{name}-symbol-signals.json", {"symbols": symbol_values})
    unit.outputs["analyze.rank"] = invoke(replace(unit, unit_root=unit.unit_root / name))
    return unit.outputs["analyze.rank"]


@pytest.mark.parametrize("overrides,file_count,symbol_count,caps,counts", [
    ({"hotspot_count": 100}, 201, 2, (100, 100), (100, 2)),
    ({"proportional_ratio": 1.0, "min_hotspots": 50, "max_hotspots": 2000}, 201, 2, (201, 50), (201, 2)),
    ({"proportional_ratio": 1.0}, 0, 0, (50, 50), (0, 0)),
    ({}, 0, 0, (10, 10), (0, 0)),
    ({"proportional_ratio": 1.0, "min_hotspots": 10000, "max_hotspots": 10000}, 2, 0, (10000, 10000), (2, 0)),
], ids=["fixed", "proportional", "proportional-empty", "fixed-empty", "upper-cap"])
def test_proportional_hotspots_publish_schema_valid_effective_counts(
        tmp_path, monkeypatch, overrides, file_count, symbol_count, caps, counts):
    from jsonschema import Draft202012Validator

    unit = baseline(context(tmp_path, "analyze.rank", overrides=overrides))
    ranked = rank_population(unit, file_count, symbol_count)
    hotspots = document(unit, ranked, "hotspots")
    assert len(hotspots["entries"]) == sum(counts)
    expected = {"mode": "proportional" if overrides.get("proportional_ratio") else "fixed",
                "configured": {"hotspot_count": overrides.get("hotspot_count", 10),
                               **{key: overrides.get(key) for key in (
                                   "proportional_ratio", "min_hotspots", "max_hotspots")}},
                "effective_caps": dict(zip(("file", "symbol"), caps)),
                "selected_counts": dict(zip(("file", "symbol"), counts))}
    assert hotspots["selection"] == expected
    schema_root = unit.job.repository_root / "docs/schemas"
    schema = json.loads((schema_root / "history-hotspots-v2.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(hotspots)
    monkeypatch.setattr(job, "_run_history_identity", lambda *args: "identity")
    published = document(unit, invoke(replace(unit, unit_id="publish.publish_handoff")))
    assert published["hotspots"]["selection"] == expected
    assert "hotspot_count" not in published["hotspots"]
    validator.validate(document(unit, published["hotspots"]))
    assert len(published["hotspots"]["entries"]) == sum(counts)

    legacy = {key: value for key, value in hotspots.items() if key not in {"scope", "selection"}}
    legacy.update({"schema": job.LEGACY_HOTSPOT_SCHEMA, "hotspot_count": caps[0],
                   "selection": "top hotspot_count ranked files and top hotspot_count ranked symbols"})
    legacy_validator = Draft202012Validator(json.loads((schema_root / "history-hotspots.schema.json").read_text()))
    assert legacy_validator.is_valid(legacy) is (caps[0] <= 100 and sum(counts) <= 200)
    assert not validator.is_valid({**hotspots, "unexpected": True})
    invalid = deepcopy(hotspots)
    invalid["selection"]["effective_caps"]["file"] = 10001 if expected["mode"] == "proportional" else 101
    assert not validator.is_valid(invalid)
    invalid = deepcopy(hotspots)
    invalid["selection"]["selected_counts"]["file"] = -1
    assert not validator.is_valid(invalid)


def test_multi_source_publication_preserves_distinct_caps_and_actual_counts(tmp_path, monkeypatch):
    from jsonschema import validate

    base = baseline(context(tmp_path, "analyze.rank", overrides={"proportional_ratio": 1.0}))
    lanes = {}
    for name, file_count, symbol_count in (("left", 201, 2), ("right", 0, 0)):
        lane = replace(base, outputs=deepcopy(base.outputs))
        lane.outputs["resolve_sources.resolve_history_source"]["source"]["source_id"] = name
        rank_population(lane, file_count, symbol_count, name=name)
        lanes[name] = lane.outputs
    combined_outputs = {
        key: {"by_source": {name: outputs[key] for name, outputs in lanes.items()}}
        for key in base.outputs if key != "publish.index_history"}
    combined_outputs["publish.index_history"] = base.outputs["publish.index_history"]
    combined_outputs["resolve_sources.resolve_history_source"]["identity"] = "identity"
    monkeypatch.setattr(job, "_run_history_identity", lambda *args: "identity")
    combined = replace(base, unit_id="publish.publish_handoff", outputs=combined_outputs)
    published = document(combined, invoke(combined))
    hotspots = document(combined, published["hotspots"])
    schema = json.loads((base.job.repository_root / "docs/schemas/history-hotspots-v2.schema.json").read_text())
    validate(hotspots, schema)
    assert hotspots["selection"]["selected_counts"] == {"file": 201, "symbol": 2}
    assert "effective_caps" not in hotspots["selection"]
    sources = {item["source_id"]: item for item in hotspots["sources"]}
    assert sources["left"]["selection"]["effective_caps"] == {"file": 201, "symbol": 50}
    assert sources["right"]["selection"]["effective_caps"] == {"file": 50, "symbol": 50}
    assert sources["right"]["selection"]["selected_counts"] == {"file": 0, "symbol": 0}
    for source in sources.values():
        payload = document(combined, source)
        validate(payload, schema)
        assert payload["selection"] == source["selection"]
    assert published["hotspots"]["selection"] == hotspots["selection"]
    assert published["hotspots"]["sources"] == hotspots["sources"]
