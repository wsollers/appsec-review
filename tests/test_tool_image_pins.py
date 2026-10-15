"""Regression tests for ``appsec-review update-image-pins`` (no Docker; inspection is injected)."""

from __future__ import annotations

import json
from pathlib import Path
import tomllib

import pytest

from appsec_review.jobs.job_tool_image_rebuild.pins import (
    PinUpdateError, find_record, plan_updates, update_pins)


OLD_A, NEW_A = "sha256:" + "a" * 64, "sha256:" + "b" * 64
OLD_P, NEW_P = "sha256:" + "c" * 64, "sha256:" + "d" * 64
OLD_S, NEW_S = "sha256:" + "e" * 64, "sha256:" + "f" * 64

CATALOG = f'''schema = "fixture"

[[images]]
id = "tool-a"
tag = "fixture/tool-a:1"
image_id = "{OLD_A}"  # pinned after review

[[images]]
id = "tool-b"
tag = "fixture/tool-b:1"
image_id = "{OLD_A}"
'''

CONFIG = f'''# central configuration
[jobs.job_project_build.settings.profiles.node]
tag = "fixture/node:local"
image_id = "{OLD_P}"
user = "10001:10001"

[jobs.job_project_build.settings.profiles.wasm]
tag = "fixture/wasm:local"
image_id = "{OLD_P}"

[jobs.job_codeql_analysis.settings]
source_image_tag = "fixture/cpp:local"
source_image_id = "{OLD_S}"
'''


def _pin(source: str, tag: str, old: str, new: str, status: str = "mismatched") -> dict:
    return {"source": source, "tag": tag, "image_id": old, "rebuilt_image_id": new, "status": status}


RECORD = {"pins": [
    _pin("containers/catalog.toml images.tool-a.image_id", "fixture/tool-a:1", OLD_A, NEW_A),
    _pin("jobs.job_project_build.settings.profiles.node.image_id", "fixture/node:local", OLD_P, NEW_P),
    _pin("jobs.job_codeql_analysis.settings.source_image_id", "fixture/cpp:local", OLD_S, NEW_S),
    _pin("jobs.job_project_build.settings.profiles.wasm.image_id", "fixture/wasm:local", OLD_P, OLD_P, "matched"),
]}
LOCAL = {"fixture/tool-a:1": NEW_A, "fixture/node:local": NEW_P, "fixture/cpp:local": NEW_S}


def _files(tmp_path: Path, record: dict = RECORD) -> tuple[Path, Path, Path]:
    config, catalog = tmp_path / "appsec-review.toml", tmp_path / "catalog.toml"
    config.write_text(CONFIG, encoding="utf-8")
    catalog.write_text(CATALOG, encoding="utf-8")
    task = tmp_path / "runs" / "run-1" / "data" / "jobs" / "job_tool_image_rebuild" / "attempts"
    for attempt, pins in (("attempt_0001", []), ("attempt_0002", record["pins"])):
        root = task / attempt / "steps" / "build" / "tasks" / "build_images"
        root.mkdir(parents=True)
        (root / "tool-image-rebuild.json").write_text(json.dumps({"pins": pins}), encoding="utf-8")
    return config, catalog, tmp_path / "runs"


def test_dry_run_plans_only_mismatched_pins_and_writes_nothing(tmp_path: Path) -> None:
    config, catalog, runs = _files(tmp_path)
    report = update_pins(runs_dir=runs, run_id="run-1", config_path=config, catalog_path=catalog,
                         write=False, inspect=LOCAL.get)
    assert report["record"].endswith("attempt_0002/steps/build/tasks/build_images/tool-image-rebuild.json")
    assert [(edit["source"], edit["status"]) for edit in report["edits"]] == [
        ("containers/catalog.toml images.tool-a.image_id", "planned"),
        ("jobs.job_project_build.settings.profiles.node.image_id", "planned"),
        ("jobs.job_codeql_analysis.settings.source_image_id", "planned")]
    assert config.read_text(encoding="utf-8") == CONFIG and catalog.read_text(encoding="utf-8") == CATALOG


def test_write_changes_exactly_the_owning_lines(tmp_path: Path) -> None:
    config, catalog, runs = _files(tmp_path)
    report = update_pins(runs_dir=runs, run_id="run-1", config_path=config, catalog_path=catalog,
                         write=True, inspect=LOCAL.get)
    assert {edit["status"] for edit in report["edits"]} == {"applied"}
    # The same old ID pinned for another tag (tool-b, the wasm profile) is left alone, and comments stay.
    assert catalog.read_text(encoding="utf-8") == CATALOG.replace(
        f'image_id = "{OLD_A}"  # pinned', f'image_id = "{NEW_A}"  # pinned')
    parsed = tomllib.loads(config.read_text(encoding="utf-8"))
    profiles = parsed["jobs"]["job_project_build"]["settings"]["profiles"]
    assert profiles["node"]["image_id"] == NEW_P and profiles["wasm"]["image_id"] == OLD_P
    assert parsed["jobs"]["job_codeql_analysis"]["settings"]["source_image_id"] == NEW_S
    assert config.read_text(encoding="utf-8").startswith("# central configuration\n")


def test_local_image_must_be_the_rebuilt_image_unless_check_is_skipped(tmp_path: Path) -> None:
    config, catalog, _ = _files(tmp_path)
    edits = plan_updates(RECORD, config_path=config, catalog_path=catalog,
                         inspect={**LOCAL, "fixture/node:local": OLD_P}.get)
    refused = [edit for edit in edits if edit.status == "refused"]
    assert [edit.tag for edit in refused] == ["fixture/node:local"] and "not the rebuilt" in refused[0].detail
    assert {edit.status for edit in plan_updates(RECORD, config_path=config, catalog_path=catalog,
                                                 inspect=None)} == {"planned"}


def test_unlocatable_pin_is_manual_and_never_guessed(tmp_path: Path) -> None:
    config, catalog, _ = _files(tmp_path)
    record = {"pins": [_pin("jobs.job_missing.settings.image_id", "fixture/x:1", OLD_P, NEW_P)]}
    [edit] = plan_updates(record, config_path=config, catalog_path=catalog, inspect=None)
    assert edit.status == "manual" and edit.line is None


def test_invalid_record_and_missing_run_are_errors(tmp_path: Path) -> None:
    config, catalog, runs = _files(tmp_path)
    with pytest.raises(PinUpdateError, match="invalid rebuilt_image_id"):
        plan_updates({"pins": [_pin("x.image_id", "t", OLD_P, "latest")]}, config_path=config,
                     catalog_path=catalog, inspect=None)
    with pytest.raises(PinUpdateError, match="no tool-image rebuild record"):
        find_record(runs, "run-missing")


def test_cli_command_reports_and_exits_nonzero_on_refusal(tmp_path: Path, monkeypatch, capsys) -> None:
    from appsec_review import cli
    from appsec_review.jobs.job_tool_image_rebuild import pins as module

    config, catalog, runs = _files(tmp_path)
    captured = {}

    def fake_update(**kwargs):
        captured.update(kwargs)
        return {"run_id": kwargs["run_id"], "edits": [{"status": "refused"}]}

    class Runtime:
        runs_dir, repository_root = runs, tmp_path

    class Config:
        runtime = Runtime()

    monkeypatch.setattr(cli, "load_config", lambda _path: Config())
    monkeypatch.setattr(module, "update_pins", fake_update)
    assert cli.main(["--config", str(config), "update-image-pins", "--run-id", "run-1",
                     "--no-image-check"]) == 1
    assert captured["inspect"] is None and captured["write"] is False
    assert captured["config_path"] == config
    assert json.loads(capsys.readouterr().out)["run_id"] == "run-1"


def test_repository_default_reports_pin_mismatches() -> None:
    document = tomllib.loads((Path(__file__).parents[1] / "appsec-review.toml").read_text(encoding="utf-8"))
    assert document["jobs"]["job_tool_image_rebuild"]["settings"]["pin_mismatch"] == "report"
