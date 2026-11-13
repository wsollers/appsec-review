from __future__ import annotations

from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_source_history_analysis import job
from .support import SOURCE, context, document, handler, nodes
from .test_handlers import baseline


class Executor:
    def __init__(self, mode):
        self.mode, self.requests = mode, []
        self.catalog = SimpleNamespace(tool=lambda key: key)

    def resolve_image(self, tool):
        assert tool == "tool-tree-sitter"
        if self.mode == "image":
            raise RuntimeError("unavailable")
        return "image"

    def execute(self, request):
        self.requests.append(request)
        if self.mode == "raise":
            raise OSError("offline")
        data = json.loads((request.scratch_root / "request.json").read_text())
        path = data["files"][0]["path"]
        record = {"path": path, "sha256": data["files"][0]["sha256"], "status": "SUCCEEDED", "nodes": nodes()}
        if self.mode == "hash":
            record["sha256"] = "0" * 64
        if self.mode == "path":
            record["path"] = "elsewhere.py"
        if self.mode == "truncated":
            record["status"] = "TRUNCATED"
        if self.mode == "partial":
            record["status"] = "PARTIAL"
        records = [] if self.mode == "omitted" else [record, record] if self.mode == "duplicate" else [record]
        result = {"scope_id": "wrong" if self.mode == "scope" else data["scope_id"],
                  "language": "C" if self.mode == "language" else data["language"], "records": records}
        if self.mode == "changed":
            (request.target_root / path).write_bytes(b"changed")
        if self.mode != "missing-output":
            (request.scratch_root / "output.json").write_text(json.dumps(result))
        return SimpleNamespace(exit_code=1 if self.mode == "exit" else 0, timed_out=self.mode == "timeout",
                               oom_killed=self.mode == "oom", image_id="image")


def install(monkeypatch, mode):
    from appsec_review.jobs.job_tree_sitter_ast import job as ast_job, scope_execution
    monkeypatch.setattr(ast_job, "_grammar_locks", lambda root: ({} if mode == "grammar" else {"Python": "lock"}, "asset"))
    validated = []
    monkeypatch.setattr(scope_execution, "_validate_container_output",
                        lambda value, **kwargs: validated.append((value, kwargs)))
    measured = []
    monkeypatch.setattr(job.TreeSitterInvocation, "for_unit", lambda *args: SimpleNamespace(
        record_output=lambda *values: measured.append(values)))
    return Executor(mode), validated, measured


@pytest.mark.parametrize("mode,reason", [
    ("ok", None), ("image", "tree_sitter_unavailable"), ("raise", "tree_sitter_execution_failed"),
    ("exit", "tree_sitter_execution_failed"), ("timeout", "tree_sitter_execution_failed"),
    ("oom", "tree_sitter_execution_failed"), ("missing-output", "tree_sitter_execution_failed"),
    ("grammar", "symbol_language_unsupported"), ("omitted", "tree_sitter_omitted_file"),
    ("truncated", "symbol_file_truncated"), ("partial", "node_limit_reached"),
], ids=["ok", "image", "raise", "exit", "timeout", "oom", "missing-output", "grammar", "omitted", "truncated", "partial"])
def test_symbols_handler_output_status_and_scope(tmp_path, monkeypatch, mode, reason):
    unit = baseline(context(tmp_path, "analyze.symbol_spans", files={"a.py": SOURCE}))
    executor, validated, measured = install(monkeypatch, mode)
    result = handler(unit, executor_factory=lambda ctx: executor)(unit)
    doc = document(unit, result)
    assert doc["schema"] == "appsec-review/source-history-symbols/1"
    assert result["gaps"] == ([] if reason is None else [reason])
    assert list(doc["statuses"]) == ["a.py"]
    assert doc["statuses"]["a.py"] == ("complete" if mode == "ok" else "partial" if mode == "partial"
                                     else "unavailable:" + reason)
    if mode == "ok":
        assert doc["files"]["a.py"]["symbols"][0]["symbol_id"] == "a.py::f"
        assert validated[0][1] == {"scope": None, "grammar": "lock", "asset_lock": "asset", "image_id": "image",
                                  "execution_image_id": "image"}
        request = executor.requests[0]
        assert request.tool_id == "tool-tree-sitter" and request.working_directory == "/scratch"
        captured = json.loads((request.scratch_root / "request.json").read_text())
        assert captured["files"] == [{"path": "a.py", "sha256": unit.outputs[
            "resolve_sources.bind_snapshot"]["eligible"]["a.py"]["sha256"]}]
        assert captured["max_nodes"] == captured["max_scope_nodes"] == 200000
        assert len(measured) == 1


@pytest.mark.parametrize("mode", ["hash", "path", "duplicate", "scope", "language", "changed"])
def test_symbols_refuse_identity_mismatch_before_publication(tmp_path, monkeypatch, mode):
    unit = baseline(context(tmp_path, "analyze.symbol_spans", files={"a.py": SOURCE}))
    executor, _, _ = install(monkeypatch, mode)
    with pytest.raises(ValueError, match="accepted target bytes changed: a.py" if mode == "changed" else "Tree-sitter"):
        handler(unit, executor_factory=lambda ctx: executor)(unit)
    assert len(executor.requests) == 1 and not (unit.unit_root / "artifacts/symbols.json").exists()


@pytest.mark.parametrize("mode,reason", [
    ("disabled", "symbol_spans_disabled"), ("divergent", "working_tree_divergent"),
    ("unsupported", "symbol_language_unsupported"), ("large", "symbol_file_too_large"),
    ("bound", "symbol_spans_bound_reached"),
], ids=["disabled", "divergent", "unsupported", "large", "bound"])
def test_symbols_exclusion_statuses_do_not_execute(tmp_path, mode, reason):
    unit = baseline(context(tmp_path, "analyze.symbol_spans"))
    item = unit.outputs["resolve_sources.bind_snapshot"]["eligible"]["a.py"]
    values = dict(unit.job.config.settings["symbols"])
    if mode == "disabled":
        values["enabled"] = False
    elif mode == "divergent":
        item["exact"] = False
    elif mode == "unsupported":
        item["language"] = "Other"
    elif mode == "large":
        item["size_bytes"] = 20 * 1024 * 1024
    else:
        values["max_files"] = 0
    unit = replace(unit, job=replace(unit.job, config=replace(
        unit.job.config, settings={**unit.job.config.settings, "symbols": values})))
    result = handler(unit, executor_factory=lambda ctx: pytest.fail("unselected parser executed"))(unit)
    assert document(unit, result)["statuses"] == {"a.py": "unavailable:" + reason}
    assert result["gaps"] == ([] if mode == "divergent" else [reason])


def test_symbol_handler_wires_extractor_with_accepted_bytes(tmp_path, monkeypatch):
    unit = baseline(context(tmp_path, "analyze.symbol_spans", files={"a.py": SOURCE}))
    executor, _, _ = install(monkeypatch, "ok")
    calls = []
    expected = {"status": "complete", "gaps": [], "symbols": [], "file_complexity": {"function_count": 0}}
    monkeypatch.setattr(job, "extract", lambda *args: calls.append(args) or expected)
    result = handler(unit, executor_factory=lambda ctx: executor)(unit)
    assert calls[0][1:] == (SOURCE, "Python", "a.py")
    assert calls[0][0]["nodes"] == nodes()
    assert document(unit, result)["files"] == {"a.py": expected}
