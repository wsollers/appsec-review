from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_source_history_analysis import job, signals, symbols
from appsec_review.jobs.job_source_history_analysis.git import GitRun, HistoryBoundError
from appsec_review.jobs.job_source_history_analysis.settings import parse_settings
from appsec_review.jobs.job_source_history_analysis.sources import GitSource
from .support import HEAD, PARENT, SOURCE, STAMP, artifact, change, context, document, eligible, handler, header, nodes, resolved


def baseline(unit):
    changes = [change(), change(PARENT, STAMP - signals.DAY)]
    classes = {HEAD: {"fix": True, "message_complete": True}, PARENT: {"fix": True, "message_complete": True}}
    files = eligible()
    parsed = parse_settings(unit.job.config.settings)
    metrics = signals.compute_signals(changes, classes, {}, eligible=files, roots=[(".", "component")],
                                      anchor_time=STAMP, window_months=6, half_life_days=90,
                                      minor_author_share=0.05, fix_interval_days=30, filters=parsed.filters)
    extracted = symbols.extract({"nodes": nodes()}, SOURCE, "Python", "a.py")
    values = {
        "resolve_sources.resolve_history_source": resolved(),
        "resolve_sources.bind_snapshot": {"eligible": files, "binding": "exact", "gaps": [], "terminal_status": "SUCCEEDED"},
        "acquire.git_history": {"gaps": [], "raw_log": artifact(unit, "log.bin", header() + b"1\t1\ta.py\0"),
                               "raw_messages": artifact(unit, "messages.bin", HEAD.encode() + b"\0fix\n\0"),
                               "terminal_status": "SUCCEEDED", "image_id": "image"},
        "acquire.normalize_changes": {"artifact": artifact(unit, "changes.json", {
            "changes": changes, "anchor_time": STAMP, "walked_commits": [HEAD], "window_start": STAMP - signals.DAY}),
            "anchor_time": STAMP, "window_start": STAMP - signals.DAY, "change_count": 2, "gaps": []},
        "acquire.github_enrichment": {"terminal_status": "SKIPPED_POLICY", "reason": "github_enrichment_disabled",
                                     "gaps": []},
        "acquire.changelog_history": {"terminal_status": "SKIPPED_NA", "reason": "no_changelog_files", "gaps": []},
        "analyze.classify_changes": {"artifact": artifact(unit, "classes.json", {"classes": classes}), "gaps": []},
        "analyze.compute_signals": {"artifact": artifact(unit, "raw-signals.json", metrics), "rank_exclusions": {}},
        "analyze.blame_age": {"young_line_share": {"a.py": 1.0}, "gaps": []},
        "analyze.co_change": {"artifact": artifact(unit, "coupling.json", {})},
        "analyze.line_history": {"artifact": artifact(unit, "lines.json", {
            "statuses": {"a.py": "complete"}, "files": {"a.py": [
                {"commit": HEAD, "hunks": [[1, 1, 1, 1]], "binary": False},
                {"commit": PARENT, "hunks": [[1, 1, 1, 1]], "binary": False}]}}), "gaps": []},
        "analyze.symbol_spans": {"artifact": artifact(unit, "symbols.json", {
            "statuses": {"a.py": "complete"}, "files": {"a.py": extracted}}), "gaps": []},
        "analyze.fix_on_fix": {"artifact": artifact(unit, "fixes.json", {"files": {}}), "gaps": []},
        "analyze.symbol_signals": {"artifact": artifact(unit, "symbol-signals.json", {"symbols": {}}), "gaps": []},
        "analyze.rank": {"gaps": [], "terminal_status": "SKIPPED_NA"},
        "publish.index_history": {"manifest": {"path": "manifest.json", "sha256": "a" * 64, "size_bytes": 1}},
    }
    return replace(unit, outputs=values)


class Runner:
    def __init__(self, unit, **modes):
        self.unit, self.modes, self.calls = unit, modes, []

    def result(self, name, data=b"", output=False):
        self.calls.append(name)
        path = self.unit.unit_root / "scratch" / f"{name}.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        receipt = artifact(self.unit, f"{name}-receipt.json", {"status": "complete"})
        return GitRun(data, path if output else None, self.modes.get("exit_code", 0),
                      self.modes.get("timed_out", False), self.modes.get("truncated", False),
                      {"image_id": "image", "argv_identity": "argv", "file_size_limit_bytes": 268435457,
                       "receipt_path": receipt["path"]}, self.modes.get("limited", False))

    def tree(self):
        return self.result("tree", self.modes.get("tree", f"100644 blob {eligible()['a.py']['blob_id']}\ta.py\0".encode()))

    def log(self, count):
        self.count = count
        return self.result("log", header() + b"1\t1\ta.py\0", True)

    def messages(self, count):
        return self.result("messages", HEAD.encode() + b"\0fix\n\0", True)

    def blame(self, index, path):
        assert index == 0 and path == "a.py"
        return self.result("blame", self.modes.get("blame", f"{HEAD} 1 1\ncommitter-time {STAMP}\n\tx\n".encode()))

    def file_history(self, index, path, count):
        assert index == 0 and path == "a.py" and count > 0
        return self.result("lines", self.modes.get("lines", f"\x01{HEAD}\n@@ -1 +1 @@\n".encode()))


def install_runner(monkeypatch, unit, **modes):
    runner = Runner(unit, **modes)
    monkeypatch.setattr(job, "GitRunner", lambda *args, **kwargs: runner)
    return runner


def invoke(unit):
    return handler(unit, executor_factory=lambda ctx: object())(unit)


@pytest.mark.parametrize("kind", ["normal", "no-target", "discovery-failed", "disabled", "swift", "mismatch"])
def test_resolve_handler_binds_catalog_and_policy(tmp_path, monkeypatch, kind):
    unit = context(tmp_path, "resolve_sources.resolve_history_source")
    if kind == "normal":
        unit = replace(unit, job=replace(unit.job, tools=replace(unit.job.tools, enable_swift=True)))
    inputs = {"source_fingerprint": "other" if kind == "mismatch" else "snapshot",
              "files": [{"path": "a.swift" if kind == "swift" else "a.py", "language": "Swift" if kind == "swift" else "Python",
                         "sha256": "a" * 64, "size_bytes": 1}], "components": [], "acquisition": None}
    monkeypatch.setattr(job, "_load_inputs", lambda root: inputs)
    monkeypatch.setattr(job, "_run_history_identity", lambda *args: "identity")
    calls = []

    def discover(**kwargs):
        calls.append(kwargs)
        if kind == "discovery-failed":
            raise ValueError("history_source_count_bound_reached")
        return [{"source_id": ".", "root": ".", "git": resolved()["git"], "github_repository": "acme/repo"}]

    monkeypatch.setattr(job, "discover_sources", discover)
    if kind == "no-target":
        unit = replace(unit, job=replace(unit.job, target_root=None))
    if kind == "disabled":
        unit = replace(unit, job=replace(unit.job, config=replace(
            unit.job.config, settings={**unit.job.config.settings, "git": {**unit.job.config.settings["git"], "enabled": False}})))
    if kind == "mismatch":
        with pytest.raises(ValueError, match="fingerprint does not match"):
            invoke(unit)
        return
    result = invoke(unit)
    assert result["identity"] == "identity" and result["source"]["source_count"] == 1
    expected = {"normal": ("SUCCEEDED", "resolved"), "no-target": ("SKIPPED_NA", "no_target"),
                "discovery-failed": ("GAP", "history_source_count_bound_reached"),
                "disabled": ("SKIPPED_POLICY", "git_history_disabled"),
                "swift": ("SKIPPED_POLICY", "swift_execution_disabled")}[kind]
    assert (result["git"]["decision"], result["git"]["reason"]) == expected
    if kind == "discovery-failed":
        assert result["gaps"] == ["history_source_count_bound_reached"]
        assert result["source"]["source_id"] == "."
    assert len(calls) == (0 if kind == "no-target" else 1)


def test_resolve_multi_source_ownership_and_export_integrity(tmp_path, monkeypatch):
    unit = context(tmp_path, "resolve_sources.resolve_history_source")
    inputs = {"source_fingerprint": "snapshot", "files": [
        {"path": path, "language": "Python", "size_bytes": 1, "sha256": "a" * 64} for path in ("a.py", "nested/a.py")],
        "components": [], "acquisition": None}
    monkeypatch.setattr(job, "_load_inputs", lambda root: inputs)
    monkeypatch.setattr(job, "_run_history_identity", lambda *args: "identity")
    descriptors = [
        {"source_id": ".", "root": ".", "git": resolved()["git"]},
        {"source_id": "nested", "root": "nested", "git": resolved()["git"],
         "review_export": {"export_path": "export.json", "export_sha256": "a" * 64}}]
    monkeypatch.setattr(job, "discover_sources", lambda **kwargs: descriptors)
    monkeypatch.setattr(job, "read_pinned", lambda *args, **kwargs: {"schema": "appsec-review/review-records/1"})
    result = invoke(unit)
    assert [item["path"] for item in result["by_source"]["."]["inputs"]["files"]] == ["a.py"]
    assert [item["path"] for item in result["by_source"]["nested"]["inputs"]["files"]] == ["nested/a.py"]
    assert result["terminal_status"] == "SUCCEEDED"
    assert result["by_source"]["nested"]["review_records"]["path"].endswith("acquired-review-records.json")
    monkeypatch.setattr(job, "read_pinned", lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("wrong pin")))
    result = invoke(unit)
    assert result["gaps"] == ["nested:acquired_review_records_unavailable:ValueError"]
    assert result["terminal_status"] == "PARTIAL"


@pytest.mark.parametrize("kind", ["exact", "partial", "unrelated", "changed", "failed", "skip"])
def test_bind_handler_compares_bytes_to_snapshot(tmp_path, monkeypatch, kind):
    unit = baseline(context(tmp_path, "resolve_sources.bind_snapshot", files={"a.py": SOURCE, "b.py": b"x"}))
    unit.outputs["resolve_sources.resolve_history_source"]["inputs"]["files"] = [
        {"path": path, **facts} for path, facts in eligible().items()]
    if kind == "partial":
        unit.outputs["resolve_sources.resolve_history_source"]["inputs"]["files"].append(
            {"path": "b.py", "sha256": hashlib.sha256(b"x").hexdigest()})
    if kind == "changed":
        (unit.job.target_root / "a.py").write_bytes(b"changed")
    if kind == "skip":
        unit.outputs["resolve_sources.resolve_history_source"]["git"] = GitSource("SKIPPED_NA", "no_target").as_dict()
    tree = (f"100644 blob {'0' * 40 if kind == 'unrelated' else eligible()['a.py']['blob_id']}\ta.py\0"
            f"160000 commit {HEAD}\tsubmodule\0").encode()
    install_runner(monkeypatch, unit, tree=tree, exit_code=1 if kind == "failed" else 0,
                   truncated=kind == "partial")
    if kind == "changed":
        with pytest.raises(ValueError, match="accepted target bytes changed: a.py"):
            invoke(unit)
        return
    result = invoke(unit)
    if kind in {"skip", "failed"}:
        assert result["eligible"] == {}
        assert result["binding"] == ("not_applicable" if kind == "skip" else "unavailable")
        assert result["gaps"] == ([] if kind == "skip" else ["git_execution_failed:ls-tree"])
    else:
        assert result["binding"] == kind
        assert result["counts"]["submodule_count"] == 1
        assert document(unit, result)["schema"] == "appsec-review/source-history-binding/1"
        if kind == "unrelated":
            assert result["eligible"] == {} and "history_not_of_snapshot" in result["gaps"]
        else:
            assert result["eligible"]["a.py"]["exact"] is True
            assert result["eligible"]["a.py"]["span_lines"] == 2
        if kind == "partial":
            assert result["gaps"] == ["submodule_history_not_followed", "tree_listing_truncated", "untracked_path"]


@pytest.mark.parametrize("kind", ["success", "failed", "limited", "retain-bound", "skip"])
def test_acquire_retains_complete_bytes_and_rejects_partial_streams(tmp_path, monkeypatch, kind):
    unit = baseline(context(tmp_path, "acquire.git_history"))
    runner = install_runner(monkeypatch, unit, exit_code=1 if kind == "failed" else 0, limited=kind == "limited")
    if kind == "skip":
        unit.outputs["resolve_sources.bind_snapshot"]["eligible"] = {}
    if kind == "retain-bound":
        monkeypatch.setattr(job, "_retain", lambda *args: (_ for _ in ()).throw(HistoryBoundError("git_output_limit_reached")))
    result = invoke(unit)
    if kind == "success":
        assert result["terminal_status"] == "SUCCEEDED" and runner.calls == ["log", "messages"]
        assert runner.count == unit.job.config.settings["max_changes"] + 1
        assert result["raw_log"]["source"]["snapshot_commit"] == HEAD
        assert result["raw_log"]["execution"]["argv_identity"] == "argv"
        assert (unit.job.run_root / result["raw_log"]["path"]).read_bytes() == header() + b"1\t1\ta.py\0"
        assert not (unit.unit_root / "scratch/log.bin").exists()
    else:
        assert "raw_log" not in result and "raw_messages" not in result
        assert result["gaps"] == {
            "skip": [], "failed": ["git_execution_failed:log", "git_execution_failed:messages"],
            "limited": ["git_output_limit_reached:log", "git_output_limit_reached:messages"],
            "retain-bound": ["git_output_limit_reached:log"]}[kind]
        assert result["terminal_status"] == ("SKIPPED_NA" if kind == "skip" else "PARTIAL")


def test_normalize_handler_streams_and_wires_normalizer(tmp_path, monkeypatch):
    unit = baseline(context(tmp_path, "acquire.normalize_changes"))
    seen = []

    def normalize(commits, **kwargs):
        seen.append((commits, kwargs))
        return {"anchor_time": STAMP, "window_start": STAMP - 1, "changes": [change()],
                "walked_change_count": 1, "author_count": 1, "gaps": [], "observations": ["fixture"]}

    monkeypatch.setattr(job.history_signals, "normalize", normalize)
    result = invoke(unit)
    assert seen[0][0][0]["commit"] == HEAD and seen[0][1]["current_paths"] == eligible()
    assert seen[0][1]["window_months"] == 6 and seen[0][1]["shallow"] == ()
    assert result["change_count"] == 1 and result["observations"] == ["fixture"]
    assert document(unit, result)["schema"] == "appsec-review/source-history-changes/2"
    assert document(unit, result)["walked_commits"] == [HEAD]


def test_normalize_handler_names_record_bound(tmp_path):
    unit = baseline(context(tmp_path, "acquire.normalize_changes"))
    unit = replace(unit, job=replace(unit.job, config=replace(
        unit.job.config, settings={**unit.job.config.settings, "git": {**unit.job.config.settings["git"], "max_record_bytes": 64}})))
    result = invoke(unit)
    assert result["gaps"] == ["git_record_bound_reached"] and result["change_count"] == 0
    assert result["resource_limit"]["producers"] == ["log"]
    assert result["resource_limit"]["partial_output"] == "rejected"


@pytest.mark.parametrize("kind", ["success", "missing-token", "policy", "no-history"])
def test_github_handler_wires_bounded_client_and_preserves_gap_scope(tmp_path, monkeypatch, kind):
    unit = baseline(context(tmp_path, "acquire.github_enrichment"))
    monkeypatch.setenv("GITHUB_TOKEN", "fixture")
    seen = []

    def enrich(client, snapshot, changes):
        seen.append((client.settings, snapshot, changes))
        return {"facts": {HEAD: {"review_bypass": False}}, "indeterminate_count": 0,
                "pagination": {"max_pages": 2}, "requests": 3,
                "gaps": ["github_page_unavailable"], "retriable": True}

    monkeypatch.setattr(job, "enrich", enrich)
    if kind == "missing-token":
        monkeypatch.delenv("GITHUB_TOKEN")
    elif kind == "policy":
        unit.outputs["resolve_sources.resolve_history_source"]["github"] = {
            "decision": "SKIPPED_POLICY", "reason": "github_enrichment_disabled"}
    elif kind == "no-history":
        unit.outputs["acquire.normalize_changes"] = {}
    result = invoke(unit)
    if kind == "success":
        assert seen[0][1:] == (HEAD, [HEAD, PARENT]) and seen[0][0].repository == "acme/repo"
        assert result["facts_count"] == 1 and result["gaps"] == ["github_page_unavailable"]
        assert document(unit, result)["schema"] == "appsec-review/source-history-github/1"
        assert document(unit, result)["repository"] == "acme/repo"
        assert result["dispositions"] == [{"disposition": "GAP", "reason": "github_enrichment_retriable"}]
    else:
        assert seen == [] and result["facts_count"] == 0
        assert result["reason"] == {"missing-token": "github_credentials_missing", "policy": "github_enrichment_disabled",
                                   "no-history": "no_git_history"}[kind]


def test_classify_compute_and_coupling_wiring_at_step_boundary(tmp_path, monkeypatch):
    unit = baseline(context(tmp_path, "analyze.classify_changes"))
    calls = []
    classes = {HEAD: {"fix": "heuristic", "message_complete": False}}
    monkeypatch.setattr(job.history_signals, "classify", lambda *args, **kwargs: calls.append((args, kwargs)) or classes)
    classified = invoke(unit)
    assert calls[0][0][1] == {HEAD: b"fix\n"} and calls[0][1]["known_commits"] == [HEAD]
    assert classified["counts"] == {"fix": 1, "security_fix": 0, "revert": 0, "formatting": 0, "message_incomplete": 1}
    assert document(unit, classified)["classes"] == classes
    assert document(unit, classified)["schema"] == "appsec-review/source-history-classification/2"
    compute = replace(unit, unit_id="analyze.compute_signals")
    calls.clear()
    value = {"files": {"a.py": {"rank_eligibility": "eligible"}, "b.py": {"rank_eligibility": "excluded:lockfile"}},
             "components": {"c": {}}}
    monkeypatch.setattr(job.history_signals, "compute_signals", lambda *args, **kwargs: calls.append((args, kwargs)) or value)
    result = invoke(compute)
    assert calls[0][1]["eligible"] == eligible() and calls[0][1]["roots"] == [(".", "component")]
    assert result["rank_exclusions"] == {"excluded:lockfile": 1}
    assert (result["file_count"], result["component_count"]) == (2, 1)
    assert document(unit, result) == value
    calls.clear()
    monkeypatch.setattr(job.history_signals, "co_change", lambda *args, **kwargs: calls.append((args, kwargs)) or {"a.py": []})
    result = invoke(replace(unit, unit_id="analyze.co_change"))
    assert result["file_count"] == 1 and document(unit, result) == {"a.py": []}
    assert calls[0][1]["eligible"] == eligible() and calls[0][1]["min_support"] == unit.job.config.settings["co_change_min_support"]


@pytest.mark.parametrize("unit_id", [
    "acquire.normalize_changes", "analyze.classify_changes", "analyze.compute_signals", "analyze.blame_age",
    "analyze.co_change", "analyze.line_history", "analyze.symbol_spans", "analyze.fix_on_fix",
    "analyze.symbol_signals", "analyze.rank",
])
def test_handlers_do_not_invent_outputs_without_upstream_history(tmp_path, unit_id):
    unit = baseline(context(tmp_path, unit_id))
    unit.outputs["acquire.git_history"] = {"terminal_status": "PARTIAL", "gaps": ["git_execution_failed:log"]}
    unit.outputs["acquire.normalize_changes"] = {}
    unit.outputs["analyze.compute_signals"] = {}
    output = invoke(unit)
    assert "artifact" not in output
    assert output["terminal_status"] == ("PARTIAL" if unit_id == "acquire.normalize_changes" else "SKIPPED_NA")
    assert output["gaps"] == (["git_execution_failed:log"] if unit_id == "acquire.normalize_changes" else [])


@pytest.mark.parametrize("kind", ["complete", "bound", "failed", "empty"])
def test_blame_handler_bounds_and_young_line_share(tmp_path, monkeypatch, kind):
    unit = baseline(context(tmp_path, "analyze.blame_age"))
    install_runner(monkeypatch, unit, exit_code=1 if kind == "failed" else 0,
                   blame=b"" if kind == "empty" else f"{HEAD} 1 1\ncommitter-time {STAMP}\n\tx\n".encode())
    if kind == "bound":
        unit = replace(unit, job=replace(unit.job, config=replace(
            unit.job.config, settings={**unit.job.config.settings, "blame_max_files": 0})))
    result = invoke(unit)
    assert result["candidate_count"] == 1
    assert result["young_line_share"] == ({"a.py": 1.0} if kind == "complete" else {})
    assert result["gaps"] == {"complete": [], "bound": ["blame_bound_reached"],
                             "failed": ["blame_execution_failed"], "empty": []}[kind]


@pytest.mark.parametrize("kind", ["complete", "failed", "truncated", "malformed", "divergent", "large", "bound"])
def test_line_history_handler_statuses_and_schema(tmp_path, monkeypatch, kind):
    unit = baseline(context(tmp_path, "analyze.line_history"))
    install_runner(monkeypatch, unit, exit_code=1 if kind == "failed" else 0, truncated=kind == "truncated",
                   lines=b"invalid" if kind == "malformed" else f"\x01{HEAD}\n@@ -1 +1 @@\n".encode())
    if kind == "divergent":
        unit.outputs["resolve_sources.bind_snapshot"]["eligible"]["a.py"]["exact"] = False
    if kind == "large":
        unit.outputs["resolve_sources.bind_snapshot"]["eligible"]["a.py"]["size_bytes"] = 20 * 1024 * 1024
    if kind == "bound":
        unit = replace(unit, job=replace(unit.job, config=replace(unit.job.config, settings={
            **unit.job.config.settings, "line_history": {**unit.job.config.settings["line_history"], "max_files": 0}})))
    result = invoke(unit)
    expected = {"complete": "complete", "failed": "git_execution_failed", "truncated": "line_history_truncated",
                "malformed": "line_history_unparseable", "divergent": "working_tree_divergent",
                "large": "line_history_file_too_large", "bound": "line_history_bound_reached"}[kind]
    doc = document(unit, result)
    assert doc["schema"] == "appsec-review/source-history-lines/1"
    assert doc["statuses"] == {"a.py": "complete" if kind == "complete" else f"unavailable:{expected}"}
    assert result["gaps"] == ([] if kind in {"complete", "divergent"} else [
        f"line_history:{expected}" if kind == "failed" else expected])
    if kind == "complete":
        assert doc["files"]["a.py"] == [{"commit": HEAD, "hunks": [[1, 1, 1, 1]], "binary": False}]


def test_fix_detection_and_symbol_signal_handlers_wire_region_steps(tmp_path, monkeypatch):
    unit = baseline(context(tmp_path, "analyze.fix_on_fix"))
    calls = []

    def fix(changes, **kwargs):
        calls.append((changes, kwargs))
        return {"count": None, "events": [], "undetermined": [{"reason": "fixture"}]}

    monkeypatch.setattr(job, "fix_on_fix", fix)
    result = invoke(unit)
    assert result["gaps"] == ["fix_on_fix_undetermined"] and result["event_count"] == 0
    assert calls[0][1]["interval_days"] == 30 and calls[0][1]["lines"].line_total == 2
    assert calls[0][1]["symbols"][0]["symbol_id"] == "a.py::f"
    assert document(unit, result)["files"]["a.py"]["count"] is None
    calls.clear()

    def attribute(changes, lines, symbols):
        calls.append((changes, lines, symbols))
        return {"a.py::f": [{"change_id": HEAD, "added": 2, "deleted": 1}]}, [PARENT]

    monkeypatch.setattr(job, "attribute", attribute)
    result = invoke(replace(unit, unit_id="analyze.symbol_signals"))
    value = document(unit, result)["symbols"]["a.py::f"]
    assert value["change_count"] == 1 and value["churn_lines"] == 3 and value["relative_churn"] == 1.5
    assert value["author_commit_shares"] == {"author-0001": 1.0}
    assert value["attribution_gaps"] == ["symbol_attribution_incomplete"]
    assert result["gaps"] == ["symbol_attribution_incomplete"] and calls[0][1].line_total == 2


def test_rank_handler_scores_files_and_publishes_exact_hotspot_schema(tmp_path):
    unit = baseline(context(tmp_path, "analyze.rank", files={"a.py": SOURCE}))
    result = invoke(unit)
    doc, hotspots = document(unit, result), document(unit, result, "hotspots")
    assert result["ranked_file_count"] == result["ranked_component_count"] == result["hotspot_entry_count"] == 1
    assert doc["file_ranking"] == ["a.py"] and doc["component_ranking"] == ["component"]
    assert doc["files"]["a.py"]["sii"]["rank"] == 1
    assert doc["schema"] == "appsec-review/source-history-signals/2"
    assert hotspots["schema"] == "appsec-review/history-hotspots/1"
    first = hotspots["entries"][0]
    assert first["schema"] == "appsec-review/history-hotspot/1"
    assert first["identity"] == {"path": "a.py", "symbol_id": None, "component_id": "component"}
    assert first["metrics"]["churn_lines"] == 4 and first["location"]["exact"] is True
    assert first["snapshot"]["snapshot_commit"] == HEAD
    assert "signal_unavailable:pull_request_timing:pr_timing_not_acquired" in first["coverage_gaps"]
    from jsonschema import validate
    schema = json.loads((unit.job.repository_root / "docs/schemas/history-hotspots.schema.json").read_text())
    validate(hotspots, schema)


def test_publish_handler_integrity_and_projection(tmp_path, monkeypatch):
    unit = baseline(context(tmp_path, "publish.publish_handoff"))
    monkeypatch.setattr(job, "_run_history_identity", lambda *args: "identity")
    result = invoke(unit)
    doc = document(unit, result)
    assert result["schema"] == doc["schema"] == "appsec-review/source-history-analysis/2"
    assert doc["ranking"]["files"] == [] and doc["ranking"]["components"] == []
    assert doc["binding"] == "exact" and doc["index_manifest"] == unit.outputs["publish.index_history"]["manifest"]
    assert doc["changelog"]["reason"] == "no_changelog_files"
    assert doc["sources"]["git"]["snapshot_commit"] == HEAD
    assert "SOURCE_HISTORY_COMPLETED" in (unit.job.run_root / "events.jsonl").read_text()
    unit.outputs["acquire.git_history"]["dispositions"] = [{"disposition": "GAP", "reason": "git_execution_failed"}]
    result = invoke(unit)
    assert result["dispositions"] == [{"disposition": "GAP", "reason": "git_execution_failed"}]
    monkeypatch.setattr(job, "_run_history_identity", lambda *args: "changed")
    with pytest.raises(ValueError, match="target history changed"):
        invoke(unit)


def test_resolve_operator_override_and_configured_exclusions(tmp_path, monkeypatch):
    from appsec_review.config.exclusions import ExclusionRule, PathExclusions
    unit = context(tmp_path, "resolve_sources.resolve_history_source")
    config = replace(unit.job.config,
                     exclusions=PathExclusions((ExclusionRule("skip.py", "job_source_history_analysis"),)),
                     settings={**unit.job.config.settings,
                               "github": {**unit.job.config.settings["github"], "repository": "operator/pinned"}})
    unit = replace(unit, job=replace(unit.job, config=config))
    monkeypatch.setattr(job, "_load_inputs", lambda root: {
        "source_fingerprint": "snapshot", "files": [{"path": "skip.py", "language": "Python"}],
        "components": [], "acquisition": None})
    monkeypatch.setattr(job, "_run_history_identity", lambda *args: "identity")
    monkeypatch.setattr(job, "discover_sources", lambda **kwargs: [
        {"source_id": ".", "root": ".", "git": resolved()["git"], "github_repository": "target/discovered"}])
    result = invoke(unit)
    assert result["source"]["github_repository"] == "operator/pinned" and result["inputs"]["files"] == []
    assert result["configured_exclusions"] == [
        {"path": "skip.py", "pattern": "skip.py", "scope": "job_source_history_analysis"}]


def test_binding_without_submodules_and_missing_output_acquisition(tmp_path, monkeypatch):
    unit = baseline(context(tmp_path, "resolve_sources.bind_snapshot", files={"a.py": SOURCE}))
    unit.outputs["resolve_sources.resolve_history_source"]["inputs"]["files"] = [{"path": "a.py", **eligible()["a.py"]}]
    runner = install_runner(monkeypatch, unit)
    assert invoke(unit)["gaps"] == []
    acquisition = replace(unit, unit_id="acquire.git_history")
    original = runner.messages
    monkeypatch.setattr(runner, "messages", lambda count: replace(original(count), output=None))
    result = invoke(acquisition)
    assert result["gaps"] == ["git_execution_failed:messages"]
    assert result["terminal_status"] == "PARTIAL"


def test_successful_github_and_symbols_with_unattributed_function(tmp_path, monkeypatch):
    unit = baseline(context(tmp_path, "acquire.github_enrichment"))
    monkeypatch.setenv("GITHUB_TOKEN", "fixture")
    monkeypatch.setattr(job, "enrich", lambda *args: {
        "facts": {}, "indeterminate_count": 0, "pagination": {}, "requests": 1, "gaps": [], "retriable": False})
    result = invoke(unit)
    assert result["terminal_status"] == "SUCCEEDED" and "dispositions" not in result
    symbol_unit = replace(unit, unit_id="analyze.symbol_signals")
    doc = document(unit, unit.outputs["analyze.symbol_spans"])
    unused = dict(doc["files"]["a.py"]["symbols"][0], symbol_id="a.py::unused")
    doc["files"]["a.py"]["symbols"].append(unused)
    unit.outputs["analyze.symbol_spans"]["artifact"] = artifact(unit, "more-symbols.json", doc)
    monkeypatch.setattr(job, "attribute", lambda *args: (
        {"a.py::f": [{"change_id": HEAD, "added": 1, "deleted": 0}]}, []))
    result = invoke(symbol_unit)
    assert result["gaps"] == [] and list(document(unit, result)["symbols"]) == ["a.py::f"]


def test_failed_source_acquisition_is_scoped_without_discarding_peer(tmp_path, monkeypatch):
    from copy import deepcopy
    unit = baseline(context(tmp_path, "acquire.git_history"))
    outputs = {key: {"by_source": {name: deepcopy(value) for name in ("bad", "good")}}
               for key, value in unit.outputs.items()}
    for name in ("bad", "good"):
        outputs["resolve_sources.resolve_history_source"]["by_source"][name]["source"]["source_id"] = name
    unit = replace(unit, outputs=outputs)
    calls = []

    def runner(executor, target, scratch, source, limits, **kwargs):
        source_id = "bad" if hashlib.sha256(b"bad").hexdigest()[:16] in str(scratch) else "good"
        calls.append(source_id)
        if source_id == "bad":
            raise OSError("fixture producer failed")
        return Runner(unit)

    monkeypatch.setattr(job, "GitRunner", runner)
    result = invoke(unit)
    assert calls == ["bad", "good"]
    assert result["gaps"] == ["bad:source_failed:acquire.git_history:OSError"]
    assert result["by_source"]["bad"]["source_error"] is True
    assert result["by_source"]["good"]["raw_log"]["source"]["snapshot_commit"] == HEAD
    outputs["acquire.git_history"] = result
    normalized = invoke(replace(unit, unit_id="acquire.normalize_changes"))
    assert normalized["by_source"]["bad"]["reason"] == "upstream_source_failed"
    assert normalized["by_source"]["good"]["change_count"] == 1
    assert "SOURCE_LANE_FAILED" in (unit.job.run_root / "events.jsonl").read_text()
