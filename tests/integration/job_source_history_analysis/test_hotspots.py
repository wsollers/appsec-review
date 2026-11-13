"""Pre-walk suite pending replacement: retained whole-graph hotspot scenarios."""
from pathlib import Path
import json
import pytest

from appsec_review.jobs.job_source_history_analysis import load_accepted_history, load_accepted_hotspots
from appsec_review.retrieval import RetrievalCore
from tests.integration.job_source_history_analysis.test_analysis import (
    DAY, GIT, T0, LocalDocker, build_repository, commit, configured, outputs, run_graph, write,
)
from tests.unit.job_source_history_analysis.test_legacy_hotspots import conforms

ROOT = Path(__file__).parents[3]
pytestmark = pytest.mark.skipif(GIT is None, reason="host git is required to emulate the tool-git image")


def test_hotspot_index_is_bounded_queryable_and_excludes_non_code(tmp_path: Path) -> None:
    config = configured(tmp_path, replacements=(("hotspot_count = 10", "hotspot_count = 1"),))
    target = tmp_path / "target"
    build_repository(target)
    write(target, "package-lock.json", '{"lockfileVersion": 3, "packages": {"a": 1, "b": 2}}\n' * 40)
    write(target, "README.md", "# Fixture\n" * 30)
    commit(target, "bump dependencies and docs", T0 + 7 * DAY)
    outcome = run_graph(config, target, LocalDocker())
    run_root = config.runtime.runs_dir / outcome["run_id"]
    history = load_accepted_history(run_root)
    signals = json.loads((run_root / history["ranking"]["signals"]["path"]).read_text(encoding="utf-8"))
    assert signals["files"]["package-lock.json"]["rank_eligibility"] == "excluded:lockfile"
    assert signals["files"]["README.md"]["rank_eligibility"] == "excluded:documentation"
    assert {item["path"] for item in history["ranking"]["files"]}.isdisjoint({"package-lock.json", "README.md"})
    assert history["window"]["months"] == 6 and "first-parent" in history["window"]["revision_semantics"]
    hotspots = load_accepted_hotspots(run_root)
    assert [(item["scope"], item["rank"]) for item in hotspots["entries"]] == [("file", 1), ("symbol", 1)]
    schema = json.loads((ROOT / "docs" / "schemas" / "history-hotspots.schema.json").read_text(encoding="utf-8"))
    conforms({key: value for key, value in hotspots.items() if key != "handoff_sha256"}, schema, schema)
    file_entry, symbol_entry = hotspots["entries"]
    assert file_entry["identity"]["path"] == "app/auth.py" and file_entry["tier"] == 1
    assert symbol_entry["identity"]["symbol_id"] == "app/auth.py::check"
    for entry in hotspots["entries"]:
        assert entry["snapshot"]["target_snapshot"] == history["target_snapshot"]
        assert entry["snapshot"]["snapshot_commit"] == history["sources"]["git"]["snapshot_commit"]
        assert len(entry["source"]["sha256"]) == 64 and len(entry["source"]["blob_id"]) == 40
        assert {"relative_churn", "revision_frequency", "author_entropy", "complexity"} == set(entry["inputs"]["values"])
        assert entry["metrics"]["lines_added"] + entry["metrics"]["lines_deleted"] == entry["metrics"]["churn_lines"]
        assert "signal_unavailable:pull_request_timing:pr_timing_not_acquired" in entry["coverage_gaps"]
        assert "never vulnerability evidence" in entry["authority"]
    assert symbol_entry["location"]["start_line"] == 1 and symbol_entry["metrics"]["cyclomatic_complexity"] == 3
    assert file_entry["metrics"]["fix_on_fix_count"] >= 1
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    found = core.find(kind="hotspot", indexes=("history",))
    assert len(found["results"]) == 2
    symbol = core.find(kind="hotspot", path="app/auth.py", name="app/auth.py::check", indexes=("history",))
    assert symbol["results"][0]["payload"]["tier"] == 1
    rows = {row["area"]: row for item in core.coverage(indexes=("history",))["results"] for row in item["coverage"]}
    assert rows["history-hotspots"]["status"] in {"complete", "partial"}
    assert rows["pull-request-timing"] == {"area": "pull-request-timing", "status": "unavailable",
                                           "gap": "pr_timing_not_acquired"}
    signal = core.find(kind="history_signal", name="app/auth.py::check", indexes=("history",))
    assert signal["results"][0]["payload"]["change_count"] >= 1


def test_missing_symbol_and_line_coverage_is_a_named_gap_not_zero(tmp_path: Path) -> None:
    config = configured(tmp_path, replacements=(
        ("max_files = 50\nmax_file_bytes = 1048576\n\n[jobs.job_source_history_analysis.settings.symbols]",
         "max_files = 0\nmax_file_bytes = 1048576\n\n[jobs.job_source_history_analysis.settings.symbols]"),))
    target = tmp_path / "target"
    build_repository(target)
    outcome = run_graph(config, target, LocalDocker(tree_sitter_fails=True))
    produced = outputs(outcome)
    assert produced["analyze.symbol_spans"]["dispositions"][0]["reason"] == "tree_sitter_execution_failed"
    assert {"tree_sitter_execution_failed", "line_history_bound_reached", "fix_on_fix_undetermined"} <= \
        set(produced["publish.publish_handoff"]["gaps"])
    assert produced["publish.publish_handoff"]["terminal_status"] == "PARTIAL"
    run_root = config.runtime.runs_dir / outcome["run_id"]
    hotspots = load_accepted_hotspots(run_root)
    assert hotspots["entries"] and {item["scope"] for item in hotspots["entries"]} == {"file"}
    auth = next(item for item in hotspots["entries"] if item["identity"]["path"] == "app/auth.py")
    assert auth["metrics"]["fix_on_fix_count"] is None and auth["metrics"]["fix_on_fix_status"] == "unavailable"
    assert auth["metrics"]["cyclomatic_complexity"] is None
    assert auth["inputs"]["missing_inputs"] == ["complexity"] and auth["inputs"]["weight_coverage"] == 0.75
    assert {"complexity_unavailable:tree_sitter_execution_failed", "fix_on_fix_unavailable",
            "line_history_unavailable:line_history_bound_reached"} <= set(auth["coverage_gaps"])
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    rows = {row["area"]: row for item in core.coverage(indexes=("history",))["results"] for row in item["coverage"]}
    assert rows["symbol-spans"]["status"] == "partial" and rows["fix-on-fix"]["status"] == "partial"
