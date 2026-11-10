"""Host pin updates use real recipes and typed loading, with only Docker inspection faked."""

import json
from pathlib import Path
import shutil
import tomllib

import pytest

from appsec_review.config import load_config
from appsec_review.config.host_pins import HOST_PINS_ENV, HOST_PINS_PATH
from appsec_review.jobs.job_image_pin_verification.pins import PinUpdateError, update_pins
from tests.host_pins_support import ROOT, fixture_bindings, write_host_pins


def files(tmp_path, monkeypatch):
    config = tmp_path / "appsec-review.toml"
    shutil.copyfile(ROOT / "appsec-review.toml", config)
    catalog = tmp_path / "containers/catalog.toml"
    catalog.parent.mkdir()
    shutil.copyfile(ROOT / "containers/catalog.toml", catalog)
    host = tmp_path / HOST_PINS_PATH
    monkeypatch.setenv(HOST_PINS_ENV, str(host))
    return config, catalog, host


def runner(images):
    calls = []

    def run(argv, timeout):
        calls.append(tuple(argv))
        assert tuple(argv[:3]) == ("docker", "image", "inspect") and timeout == 60
        image = images.get(argv[3])
        if image is None:
            return 1, b"", f"No such image: {argv[3]}".encode(), False
        return 0, image.encode() + b"\n", b"", False

    run.calls = calls
    return run


def test_dry_run_bootstraps_without_loading_missing_pins_or_writing_files(tmp_path, monkeypatch):
    config, catalog, host = files(tmp_path, monkeypatch)
    before = config.read_bytes(), catalog.read_bytes()
    docker = runner(fixture_bindings())
    report = update_pins(config_path=config, catalog_path=catalog, write=False, runner=docker)
    assert not report["written"] and not report["failures"] and report["edits"]
    assert report["checked"] == len(fixture_bindings()) == len(docker.calls)
    assert not host.exists()
    assert before == (config.read_bytes(), catalog.read_bytes())


def test_write_changes_only_ignored_host_bindings_and_loads_every_consumer(tmp_path, monkeypatch):
    config, catalog, host = files(tmp_path, monkeypatch)
    before = config.read_bytes(), catalog.read_bytes()
    local = fixture_bindings()
    report = update_pins(config_path=config, catalog_path=catalog, write=True, runner=runner(local))
    assert report["written"] and not report["failures"]
    assert before == (config.read_bytes(), catalog.read_bytes())
    document = tomllib.loads(host.read_text())
    assert document["images"] == local and document["preinstalled_runtimes"] == []
    loaded = load_config(config)
    profiles = loaded.job("job_project_build").settings["profiles"]
    assert all(value["image_id"] == local[value["tag"]] for value in profiles.values())
    assert loaded.job("job_codeql_analysis").typed_settings.source_image_id == local["audit-codeql:custom-2.27.0"]
    assert loaded.telemetry_report.image_id == local["appsec-review/tool-report-latex:1.0.0"]
    again = update_pins(config_path=config, catalog_path=catalog, write=True, runner=runner(local))
    assert again["edits"] == [] and again["sha256"] == report["sha256"]


def test_missing_image_refuses_entire_update_and_preserves_existing_bytes(tmp_path, monkeypatch):
    config, catalog, host = files(tmp_path, monkeypatch)
    write_host_pins(host)
    before = host.read_bytes()
    local = fixture_bindings()
    missing, moved = sorted(local)[:2]
    del local[missing]
    local[moved] = "sha256:" + "f" * 64
    report = update_pins(config_path=config, catalog_path=catalog, write=True, runner=runner(local))
    assert not report["written"] and len(report["failures"]) == 1
    assert missing in report["failures"][0] and "resolved missing" in report["failures"][0]
    assert host.read_bytes() == before


def test_typed_configuration_refusal_never_publishes_candidate(tmp_path, monkeypatch):
    config, catalog, host = files(tmp_path, monkeypatch)
    config.write_text(config.read_text().replace('execution_mode = "auto"', 'execution_mode = "invalid"', 1))
    with pytest.raises(PinUpdateError, match="typed configuration.*no files changed"):
        update_pins(config_path=config, catalog_path=catalog, write=True, runner=runner(fixture_bindings()))
    assert not host.exists()


def test_moved_source_never_relabels_a_preinstalled_runtime(tmp_path, monkeypatch):
    config, catalog, host = files(tmp_path, monkeypatch)
    local = fixture_bindings()
    source = local["audit-codeql:custom-2.27.0"]
    declaration = {"source_image_id": source, "build_image_id": source,
                   "runtime_image_id": "sha256:" + "a" * 64, "runtime_user": "1000:1000",
                   "codeql_release_id": "codeql-2.27.0-cert-v2.62.0",
                   "runner_release_id": "appsec-codeql-runner-89568569", "runner_source": "application"}
    write_host_pins(host, images=local, runtimes=[declaration])
    before = host.read_bytes()
    local["audit-codeql:custom-2.27.0"] = "sha256:" + "f" * 64
    with pytest.raises(PinUpdateError, match="source.*no files changed"):
        update_pins(config_path=config, catalog_path=catalog, write=True, runner=runner(local))
    assert host.read_bytes() == before


def test_unreadable_configuration_is_an_error(tmp_path):
    with pytest.raises(PinUpdateError, match="cannot read the pins"):
        update_pins(config_path=tmp_path / "absent.toml", catalog_path=tmp_path / "catalog.toml",
                    write=False, runner=runner({}))


def test_cli_bootstrap_and_missing_image_exit_status(tmp_path, monkeypatch, capsys):
    from appsec_review import cli
    from appsec_review.container_runtime import build_executor
    config, _, host = files(tmp_path, monkeypatch)
    monkeypatch.setattr(build_executor, "_run", runner({}))
    assert cli.main(["--config", str(config), "update-image-pins", "--write"]) == 1
    assert json.loads(capsys.readouterr().out)["failures"] and not host.exists()
    monkeypatch.setattr(build_executor, "_run", runner(fixture_bindings()))
    assert cli.main(["--config", str(config), "update-image-pins", "--write"]) == 0
    assert json.loads(capsys.readouterr().out)["written"] and host.is_file()
