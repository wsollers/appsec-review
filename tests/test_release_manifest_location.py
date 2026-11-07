"""The implementation-release manifest is measured at launch from the mounted checkout."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.runtime import release
from appsec_review.runtime.release import MANIFEST_ENV, MANIFEST_NAME, load_release, manifest_path
from tests.release_support import write_release


def test_manifest_defaults_to_the_repository_root(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(MANIFEST_ENV, raising=False)
    assert manifest_path(tmp_path) == tmp_path / MANIFEST_NAME
    assert load_release(tmp_path) is None
    written = write_release(tmp_path, ("job_fixture",))
    assert load_release(tmp_path)["sha256"] == written["sha256"]


def test_mounted_deployments_read_the_manifest_the_launch_step_wrote(tmp_path: Path, monkeypatch) -> None:
    """Read-only sources under one root, the manifest on deployment storage under another."""
    source = tmp_path / "checkout"
    storage = tmp_path / "var-dagster" / "release" / MANIFEST_NAME
    written = write_release(source, ("job_fixture",))
    storage.parent.mkdir(parents=True)
    storage.write_bytes((source / MANIFEST_NAME).read_bytes())
    (source / MANIFEST_NAME).unlink()
    monkeypatch.setenv(MANIFEST_ENV, str(storage))
    assert manifest_path(source) == storage
    assert load_release(source)["sha256"] == written["sha256"]
    # A different manifest at the configured location is what counts, never the one beside the sources.
    write_release(source, ("job_fixture", "job_other"))
    assert load_release(source)["sha256"] == written["sha256"]


def test_relative_manifest_location_is_rejected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(MANIFEST_ENV, "relative/" + MANIFEST_NAME)
    with pytest.raises(ValueError, match="absolute"):
        manifest_path(tmp_path)


def test_launch_step_measures_then_execs_the_server(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "checkout"
    write_release(source, ("job_fixture",))
    manifest = json.loads((source / MANIFEST_NAME).read_text(encoding="utf-8"))
    (source / MANIFEST_NAME).unlink()
    (source / "release-dependencies.json").write_text(json.dumps({
        "schema": "appsec-review/release-dependencies/1", "common": ["release-src/shared.py"],
        "validators": ["release-src/validator.json"], "scripts": ["release-src/mounted.sh"],
        "job_pattern": "release-src/{job_id}/*.py",
        "environment_requirements": ["APPSEC_REVIEW_TARGET", "MODEL_TOKEN"]}), encoding="utf-8")
    output = tmp_path / "var-dagster" / "release" / MANIFEST_NAME
    monkeypatch.setenv(MANIFEST_ENV, str(output))

    class Registry:
        @staticmethod
        def job_ids():
            return ("job_fixture",)

    monkeypatch.setattr("appsec_review.runtime.registry.builtin_registry", lambda: Registry())
    executed: list[list[str]] = []
    code = release.main(["--root", str(source), "--manifest", str(source / "release-dependencies.json"),
                         "--exec", "dagster", "code-server", "start", "--host", "0.0.0.0"],
                        execvp=lambda program, argv: executed.append([program, *argv[1:]]))
    assert code == 0
    assert executed == [["dagster", "code-server", "start", "--host", "0.0.0.0"]]
    measured = json.loads(output.read_text(encoding="utf-8"))
    assert measured["sha256"] == manifest["sha256"]
    assert load_release(source)["sha256"] == manifest["sha256"]


def test_launch_step_requires_a_command_after_exec(tmp_path: Path) -> None:
    write_release(tmp_path, ("job_fixture",))
    with pytest.raises(SystemExit):
        release.main(["--root", str(tmp_path), "--exec"], execvp=lambda *_: None)


def test_launch_step_refuses_a_missing_dependency_manifest_before_exec(tmp_path: Path, monkeypatch) -> None:
    executed: list[list[str]] = []
    monkeypatch.setenv(MANIFEST_ENV, str(tmp_path / "out" / MANIFEST_NAME))
    with pytest.raises(FileNotFoundError):
        release.main(["--root", str(tmp_path), "--exec", "dagster"],
                     execvp=lambda program, argv: executed.append(argv))
    assert executed == []
