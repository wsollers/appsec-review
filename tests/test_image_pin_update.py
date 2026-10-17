"""Regression tests for the host-side ``appsec-review update-image-pins`` (no Docker; the runner is faked)."""

from __future__ import annotations

import json
from pathlib import Path
import tomllib

import pytest

from appsec_review.jobs.job_image_pin_verification.pins import (
    PinUpdateError, configured_pins, plan_updates, update_pins, verify_pins)


OLD_A, NEW_A = "sha256:" + "a" * 64, "sha256:" + "b" * 64
OLD_P, NEW_P = "sha256:" + "c" * 64, "sha256:" + "d" * 64
OLD_S, NEW_S = "sha256:" + "e" * 64, "sha256:" + "f" * 64
OTHER = "sha256:" + "9" * 64

CATALOG = f'''schema = "fixture"

[[images]]
id = "tool-a"
state = "enabled"
tag = "fixture/tool-a:1"
image_id = "{OLD_A}"  # pinned after review

[[images]]
id = "tool-b"
state = "enabled"
tag = "fixture/tool-b:1"
image_id = "{OLD_A}"

[[images]]
id = "tool-c"
state = "enabled"
tag = "fixture/tool-c:1"
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

# tool-b and the wasm profile still resolve to their pins; the others moved.
LOCAL = {"fixture/tool-a:1": NEW_A, "fixture/tool-b:1": OLD_A, "fixture/tool-c:1": OTHER,
         "fixture/node:local": NEW_P, "fixture/wasm:local": OLD_P, "fixture/cpp:local": NEW_S}


def _runner(images: dict[str, str | None]):
    calls = []

    def run(argv, timeout):
        calls.append(tuple(argv))
        assert tuple(argv[:3]) == ("docker", "image", "inspect")
        image = images.get(argv[3])
        if image is None:
            return 1, b"", f"Error: No such image: {argv[3]}".encode(), False
        return 0, image.encode() + b"\n", b"", False

    run.calls = calls
    return run


def _files(tmp_path: Path, *, crlf: bool = False) -> tuple[Path, Path]:
    config, catalog = tmp_path / "appsec-review.toml", tmp_path / "catalog.toml"
    newline = "\r\n" if crlf else "\n"
    config.write_bytes(CONFIG.replace("\n", newline).encode())
    catalog.write_bytes(CATALOG.replace("\n", newline).encode())
    return config, catalog


def test_dry_run_plans_only_moved_pins_and_writes_nothing(tmp_path: Path) -> None:
    config, catalog = _files(tmp_path)
    report = update_pins(config_path=config, catalog_path=catalog, write=False, runner=_runner(LOCAL))
    assert [(edit["source"], edit["status"], edit["new"]) for edit in report["edits"]] == [
        ("containers/catalog.toml images.tool-a.image_id", "planned", NEW_A),
        ("jobs.job_codeql_analysis.settings.source_image_id", "planned", NEW_S),
        ("jobs.job_project_build.settings.profiles.node.image_id", "planned", NEW_P)]
    assert report["checked"] == 6 and report["unpinned_missing"] == []
    assert config.read_text(encoding="utf-8") == CONFIG and catalog.read_text(encoding="utf-8") == CATALOG


@pytest.mark.parametrize("crlf", [False, True], ids=["lf", "crlf"])
def test_write_changes_exactly_the_owning_lines_and_keeps_line_endings(tmp_path: Path, crlf: bool) -> None:
    config, catalog = _files(tmp_path, crlf=crlf)
    newline = "\r\n" if crlf else "\n"
    report = update_pins(config_path=config, catalog_path=catalog, write=True, runner=_runner(LOCAL))
    assert {edit["status"] for edit in report["edits"]} == {"applied"}
    # The same old ID pinned for another tag (tool-b, the wasm profile) is left alone, and comments stay.
    assert catalog.read_bytes().decode() == CATALOG.replace(
        f'image_id = "{OLD_A}"  # pinned', f'image_id = "{NEW_A}"  # pinned').replace("\n", newline)
    parsed = tomllib.loads(config.read_bytes().decode())
    profiles = parsed["jobs"]["job_project_build"]["settings"]["profiles"]
    assert profiles["node"]["image_id"] == NEW_P and profiles["wasm"]["image_id"] == OLD_P
    assert parsed["jobs"]["job_codeql_analysis"]["settings"]["source_image_id"] == NEW_S
    assert config.read_bytes().decode().startswith("# central configuration" + newline)


def test_a_missing_pinned_image_is_unresolved_and_an_unpinned_one_is_reported(tmp_path: Path) -> None:
    config, catalog = _files(tmp_path)
    report = update_pins(config_path=config, catalog_path=catalog, write=True,
                         runner=_runner({**LOCAL, "fixture/node:local": None, "fixture/tool-c:1": None}))
    by_source = {edit["source"]: edit for edit in report["edits"]}
    node = by_source["jobs.job_project_build.settings.profiles.node.image_id"]
    assert node["status"] == "unresolved" and "resolved missing" in node["detail"]
    assert report["unpinned_missing"] == [
        "containers/catalog.toml images.tool-c.image_id: tag fixture/tool-c:1 pinned <unpinned> resolved missing"]
    assert tomllib.loads(config.read_text())["jobs"]["job_project_build"]["settings"]["profiles"]["node"][
        "image_id"] == OLD_P


def test_unlocatable_pin_is_manual_and_never_guessed(tmp_path: Path) -> None:
    config, catalog = _files(tmp_path)
    results = [{"source": "jobs.job_missing.settings.image_id", "tag": "fixture/x:1", "image_id": OLD_P,
                "resolved_image_id": NEW_P, "status": "mismatched", "detail": ""}]
    [edit] = plan_updates(results, config_path=config, catalog_path=catalog)
    assert edit.status == "manual" and edit.line is None


def test_each_tag_is_inspected_once(tmp_path: Path) -> None:
    runner = _runner(LOCAL)
    pins = configured_pins([{"id": "a", "state": "enabled", "tag": "t:1", "image_id": OLD_A}],
                           {"jobs": {"job_x": {"settings": {"tag": "t:1", "image_id": OLD_A}}}})
    assert [item["status"] for item in verify_pins(pins, runner)] == ["missing", "missing"]
    assert len(runner.calls) == 1


def test_unreadable_configuration_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(PinUpdateError, match="cannot read the pins"):
        update_pins(config_path=tmp_path / "absent.toml", catalog_path=tmp_path / "catalog.toml",
                    write=False, runner=_runner({}))


def test_cli_command_reports_and_exits_nonzero_when_a_pin_cannot_be_updated(
        tmp_path: Path, monkeypatch, capsys) -> None:
    from appsec_review import cli
    from appsec_review.container_runtime import build_executor

    config, catalog = _files(tmp_path)
    (tmp_path / "containers").mkdir()
    catalog.rename(tmp_path / "containers" / "catalog.toml")

    class Runtime:
        runs_dir, repository_root = tmp_path / "runs", tmp_path

    class Config:
        runtime = Runtime()

    monkeypatch.setattr(cli, "load_config", lambda _path: Config())
    monkeypatch.setattr(build_executor, "_run", _runner({**LOCAL, "fixture/node:local": None}))
    assert cli.main(["--config", str(config), "update-image-pins"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["written"] is False and report["checked"] == 6
    monkeypatch.setattr(build_executor, "_run", _runner(LOCAL))
    assert cli.main(["--config", str(config), "update-image-pins", "--write"]) == 0
    assert tomllib.loads(config.read_text())["jobs"]["job_codeql_analysis"]["settings"]["source_image_id"] == NEW_S
