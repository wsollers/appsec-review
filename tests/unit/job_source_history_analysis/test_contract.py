"""Exact input, dataset, graph and artifact contracts, without a graph execution."""
from __future__ import annotations

import ast
from dataclasses import asdict, replace
from fnmatch import fnmatch
import inspect
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_source_history_analysis import job
from appsec_review.jobs.job_source_history_analysis.datasets import CONTRACT, DATASETS
from .support import artifact, context, document


INPUTS = [
    ("job_review_intake", "handoff", "appsec-review/job-handoff/2", "required", "reject"),
    ("job_review_intake", "model_preflight", "appsec-review/model-preflight/1", "optional", "gap"),
    ("job_review_intake", "binary_evidence", "appsec-review/binary-evidence-intake/1", "optional", "gap"),
    ("job_review_intake", "review_intake", "appsec-review/review-intake/1", "optional", "gap"),
    ("job_target_catalog", "handoff", "appsec-review/job-handoff/2", "required", "reject"),
    ("job_target_catalog", "target_artifact_inputs", "appsec-review/target-artifact-intake/1", "optional", "gap"),
    *[("job_target_catalog", name, "appsec-review/retrieval-index/2", "optional", "gap")
      for name in ("source_files", "declaration_symbols", "components", "target_documents", "build_units")],
    ("job_target_catalog", "catalog_documents", "appsec-review/target-catalog/1", "optional", "gap"),
]
A = "data/jobs/job_source_history_analysis/attempts/*"
METADATA = "query_dataset_inventory (sanitized identity, hash, status and coverage only)"
OUTPUTS = [
    ("history_signals", "publish", "appsec-review/retrieval-index/2", "internal", "indexed",
     "Change, file, symbol and component history signals and SII hotspots with pseudonymous authors, "
     "and separately labelled change-log file signals.",
     ("history",), ("git-history",), (),
     "find/search/trace index=history; query_precomputed query_set=history_context", None),
    ("history_documents", "publish", "appsec-review/source-history-analysis/2", "internal", "artifact_only",
     "Normalized changes, classification, signals, line history, symbol spans, hotspots and "
     "change-log signals (source: changelog, no names, addresses or message text).", (), (),
     (A + "/steps/*/tasks/*/artifacts/*.json", A + "/steps/*/tasks/*/sources/*/artifacts/*.json"),
     METADATA, "normalized inputs of the history shard; full per-change lists exceed retrieval bounds"),
    ("raw_git_history", "acquire", "application/octet-stream", "sensitive", "protected",
     "Raw git log and commit messages, including author e-mail addresses.", (), (),
     (A + "/steps/acquire/tasks/git_history/protected/*",
      A + "/steps/acquire/tasks/git_history/sources/*/protected/*"), METADATA,
     "raw author identities and commit message text; only pseudonyms and classifications are indexed"),
    ("history_tool_io", "analyze", "appsec-review/container-execution/1", "sensitive", "protected",
     "Git and parser container scratch, including blame output and raw patches.", (), (),
     (A + "/steps/*/tasks/*/scratch/**", A + "/steps/*/tasks/*/sources/*/scratch/**"), METADATA,
     "raw tool streams and receipts may contain unredacted target content and host paths"),
]
GRAPH = {
    "resolve_sources.resolve_history_source": (),
    "resolve_sources.bind_snapshot": ("resolve_sources.resolve_history_source",),
    "acquire.git_history": ("resolve_sources.bind_snapshot",),
    "acquire.normalize_changes": ("acquire.git_history",),
    "acquire.github_enrichment": ("acquire.normalize_changes",),
    "acquire.changelog_history": ("resolve_sources.resolve_history_source",),
    "analyze.classify_changes": ("acquire.normalize_changes", "acquire.github_enrichment"),
    "analyze.compute_signals": ("analyze.classify_changes",),
    "analyze.blame_age": ("analyze.compute_signals",),
    "analyze.co_change": ("analyze.classify_changes",),
    "analyze.line_history": ("analyze.compute_signals",),
    "analyze.symbol_spans": ("analyze.compute_signals",),
    "analyze.fix_on_fix": ("analyze.line_history", "analyze.symbol_spans"),
    "analyze.symbol_signals": ("analyze.fix_on_fix",),
    "analyze.rank": ("analyze.blame_age", "analyze.co_change", "analyze.symbol_signals"),
    "publish.index_history": ("analyze.rank", "acquire.changelog_history"),
    "publish.publish_handoff": ("publish.index_history",),
}
WRITES = {
    "resolve": {"acquired-review-records.json"}, "bind": {"binding.json"},
    "normalize": {"changes.json"}, "github_enrichment": {"github-enrichment.json"},
    "classify": {"classification.json"}, "compute": {"raw-signals.json"}, "coupling": {"co-change.json"},
    "line_history": {"line-history.json"}, "symbol_spans": {"symbols.json"},
    "fix_detection": {"fix-on-fix.json"}, "symbol_signals": {"symbol-signals.json"},
    "changelog_lane": {"changelog.json"}, "rank": {"signals.json", "hotspots.json"},
    "publish": {"source-history.json"}, "publish_sources": {"source-history.json", "hotspots.json"},
}
READS = {
    "source_of": ("resolve_sources.resolve_history_source",),
    "git_ready": ("resolve_sources.bind_snapshot",),
    "eligible_of": ("resolve_sources.bind_snapshot",),
    "bind": ("resolve_sources.resolve_history_source",),
    "acquire": ("resolve_sources.resolve_history_source",),
    "normalize": ("acquire.git_history",),
    "github_enrichment": ("acquire.normalize_changes", "resolve_sources.resolve_history_source"),
    "github_facts": ("acquire.github_enrichment",),
    "classes_of": ("analyze.classify_changes",),
    "classify": ("acquire.git_history", "acquire.normalize_changes"),
    "compute": ("acquire.normalize_changes", "resolve_sources.resolve_history_source"),
    "file_signals": ("analyze.compute_signals",),
    "blame": ("acquire.normalize_changes", "analyze.compute_signals"),
    "coupling": ("acquire.normalize_changes", "resolve_sources.resolve_history_source"),
    "line_history": ("analyze.compute_signals",),
    "symbol_spans": ("analyze.compute_signals",),
    "lines_of": ("analyze.line_history",),
    "symbols_of": ("analyze.symbol_spans",),
    "fix_detection": ("analyze.compute_signals",),
    "symbol_signals": ("analyze.compute_signals", "analyze.fix_on_fix"),
    "changelog_lane": ("resolve_sources.resolve_history_source",),
    "changelog_history": ("resolve_sources.resolve_history_source",),
    "gaps_and_observations": ("acquire.normalize_changes",),
    "rank": ("acquire.github_enrichment", "acquire.normalize_changes", "analyze.blame_age", "analyze.classify_changes",
             "analyze.co_change", "analyze.compute_signals", "analyze.fix_on_fix", "analyze.symbol_signals"),
    "index": ("acquire.git_history", "acquire.github_enrichment", "acquire.normalize_changes", "analyze.rank",
              "resolve_sources.resolve_history_source"),
    "publish": ("acquire.github_enrichment", "acquire.normalize_changes", "analyze.rank", "publish.index_history",
                "resolve_sources.bind_snapshot", "resolve_sources.resolve_history_source"),
    "publish_sources": ("publish.index_history", "resolve_sources.resolve_history_source"),
}


def test_every_input_requirement_field_and_job_policy():
    assert [asdict(item) for item in CONTRACT.inputs] == [
        {"producer": producer, "output_kind": kind, "schema": schema, "availability": availability,
         "missing": missing, "authority": "producer_evidence", "coverage": "allow_partial", "channel": "handoff"}
        for producer, kind, schema, availability, missing in INPUTS]
    assert CONTRACT.consumes == ("job_review_intake", "job_target_catalog")
    assert CONTRACT.schedule_after == ("job_target_catalog",)
    assert (CONTRACT.dispatch, CONTRACT.target_access, CONTRACT.always_execute, CONTRACT.propagate_handoff) == (
        "review_graph", "checkout", False, True)


def test_every_dataset_field():
    assert [asdict(item) for item in DATASETS] == [
        {"output_kind": kind, "step": step, "family": "history", "schema": schema, "sensitivity": sensitivity,
         "disposition": disposition, "description": description, "indexes": indexes, "shard_prefixes": prefixes,
         "shard_suffixes": (), "artifacts": artifacts, "query_route": route, "reason": reason, "required": False,
         "store": "retrieval", "authority": "routing_context"}
        for kind, step, schema, sensitivity, disposition, description, indexes, prefixes, artifacts, route, reason
        in OUTPUTS]


def test_graph_validators_schema_and_identity_transform(tmp_path):
    built = job.build_job()
    assert {unit.unit_id: unit.dependencies for unit in built.units} == GRAPH
    assert [unit.unit_id for unit in built.units] == list(GRAPH)
    assert built.contract is CONTRACT and built.datasets is DATASETS
    assert built.schema_identity == "appsec-review/source-history-analysis/2"
    assert built.input_validators == (job._validate,)
    assert built.output_validators == () and all(unit.output_validators == () for unit in built.units)
    assert built.result_transform is None and built.strict_gaps is False
    result = {"outputs": {"publish.publish_handoff": {"schema": job.SCHEMA}}, "status": "SUCCEEDED"}
    assert built.finalize_result(context(tmp_path, "publish.publish_handoff").job, result) is result


def test_input_validation_checks_exact_task_order_and_settings(tmp_path):
    ctx = context(tmp_path, "resolve_sources.resolve_history_source").job
    job._validate(ctx, None)
    with pytest.raises(ValueError, match="topology"):
        job._validate(replace(ctx, config=SimpleNamespace(steps={})), None)
    fake = SimpleNamespace(steps=job.TOPOLOGY, step=lambda key: SimpleNamespace(tasks=("wrong",)))
    with pytest.raises(ValueError, match="task order mismatch: resolve_sources"):
        job._validate(replace(ctx, config=fake), None)
    with pytest.raises(ValueError, match="unknown source history setting: bad"):
        job._validate(replace(ctx, config=replace(ctx.config, settings={**ctx.config.settings, "bad": 1})), None)


def test_handlers_write_only_declared_document_names():
    tree = ast.parse(inspect.getsource(job.build_job))
    actual = {}
    for function in tree.body[0].body:
        if not isinstance(function, ast.FunctionDef):
            continue
        names = {node.args[1].value for node in ast.walk(function)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_write"
                 and len(node.args) > 1 and isinstance(node.args[1], ast.Constant)}
        if names:
            actual[function.name] = names
    assert actual == WRITES
    reads = {}
    for function in tree.body[0].body:
        if isinstance(function, ast.FunctionDef):
            names = tuple(sorted({node.args[0].value for node in ast.walk(function)
                                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                                  and node.func.attr == "output" and node.args
                                  and isinstance(node.args[0], ast.Constant)}))
            if names:
                reads[function.name] = names
    assert reads == READS
    for names in WRITES.values():
        for name in names:
            assert fnmatch(f"data/jobs/job_source_history_analysis/attempts/attempt_0001/"
                           f"steps/publish/tasks/publish_handoff/artifacts/{name}", DATASETS[1].artifacts[0])


@pytest.mark.parametrize("damage", ["none", "schema", "snapshot", "acquisition"], ids=str)
def test_accepted_inputs_read_exact_pinned_payloads(tmp_path, monkeypatch, damage):
    unit = context(tmp_path, "resolve_sources.resolve_history_source")
    partition = artifact(unit, "partition.json", {
        "files": [{"path": "a.py", "sha256": "a" * 64, "size_bytes": 4}],
        "gaps": [{"path": "ChangeLog", "reason": "file_too_large"}, {"path": "image.png"}, None]})
    components = artifact(unit, "components.json", {"components": [{"component_id": "c", "root": ""}]})
    acquisition = artifact(unit, "acquisition.json", {"schema": "appsec-review/target-acquisition/1"})
    intake = {"schema": "appsec-review/review-intake/1", "fingerprint": {"sha256": "snapshot"}}
    if damage == "acquisition":
        intake["fingerprint"]["acquisition"] = {
            "manifest": acquisition["path"], "manifest_sha256": acquisition["sha256"]}
    catalog = {"schema": "wrong" if damage == "schema" else "appsec-review/target-catalog/1",
               "source_fingerprint": "other" if damage == "snapshot" else "snapshot",
               "artifacts": {"repository_discovery.partition_repository": partition,
                             "component_discovery.catalog_components": components}}
    upstream = {
        "job_review_intake": ({"outputs": {"publish_intake.publish_handoff": {
            "artifact": artifact(unit, "intake.json", intake)}}}, "intake-pin"),
        "job_target_catalog": ({"outputs": {"publish_catalog.publish_handoff": {
            "artifact": artifact(unit, "catalog.json", catalog)}}}, "catalog-pin")}
    reads = []
    monkeypatch.setattr(job, "_accepted_handoff", lambda root, key: reads.append((root, key)) or upstream[key])
    if damage in {"schema", "snapshot"}:
        with pytest.raises(ValueError, match="unsupported schemas" if damage == "schema" else "identities disagree"):
            job._load_inputs(unit.job.run_root)
    else:
        result = job._load_inputs(unit.job.run_root)
        assert result["files"] == [{"path": "a.py", "sha256": "a" * 64, "size_bytes": 4, "language": None}]
        assert result["components"] == [{"component_id": "c", "root": "."}]
        assert result["changelog_exclusions"] == [{"path": "ChangeLog", "reason": "file_too_large"}]
        assert result["catalog_handoff_sha256"] == "catalog-pin"
        assert result["acquisition"] == ({"schema": "appsec-review/target-acquisition/1"}
                                          if damage == "acquisition" else None)
    assert reads == [(unit.job.run_root, "job_review_intake"), (unit.job.run_root, "job_target_catalog")]


@pytest.mark.parametrize("name,schema", [
    ("binding.json", "appsec-review/source-history-binding/1"),
    ("changes.json", "appsec-review/source-history-changes/2"),
    ("classification.json", "appsec-review/source-history-classification/2"),
    ("line-history.json", "appsec-review/source-history-lines/1"),
    ("symbols.json", "appsec-review/source-history-symbols/1"),
    ("fix-on-fix.json", "appsec-review/source-history-fix-on-fix/1"),
    ("symbol-signals.json", "appsec-review/source-history-symbol-signals/1"),
    ("changelog.json", "appsec-review/source-history-changelog/1"),
    ("signals.json", "appsec-review/source-history-signals/2"),
    ("hotspots.json", "appsec-review/history-hotspots/1"),
    ("source-history.json", "appsec-review/source-history-analysis/2"),
], ids=lambda value: value.split("/")[-1])
def test_artifact_writer_preserves_schema_and_declared_glob(tmp_path, name, schema):
    unit = context(tmp_path, "publish.publish_handoff")
    value = {"schema": schema, "entries": [1]}
    reference = job._write(unit, name, value)
    assert document(unit, {"artifact": reference}) == value
    assert job._read(unit.job.run_root, reference) == value
    assert any(fnmatch(reference["path"], pattern) for pattern in DATASETS[1].artifacts)
    assert reference["size_bytes"] > 0 and len(reference["sha256"]) == 64
