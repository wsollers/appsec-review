"""cve_bin_tool_db_build: settings, NVD snapshot resolution, staging, the build record check,
publication and verification, with the container builder replaced by an injected runner."""
from __future__ import annotations

import gzip
import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.jobs.job_third_party_data_sync.steps.cve_bin_tool_db_build import database as cve_db
from appsec_review.storage import file_sha256
from tests.fixtures.reference_feeds import nvd_vulnerability, publish_nvd

ROOT = Path(__file__).resolve().parents[3]
BUILD_CONTEXT = ROOT / "tools" / "cve-bin-tool"


def _settings(tmp_path: Path, **overrides) -> cve_db.CveBinToolSettings:
    values = {"feed_root": str(tmp_path / "feeds" / "cve-bin-tool"), "image": "appsec-review/cve-bin-tool:fixture",
              "tool_version": "3.4", "build_context": str(BUILD_CONTEXT)}
    values.update(overrides)
    return cve_db.CveBinToolSettings.from_mapping(tmp_path, values)


def write_databases(directory: Path, *, tool_version: str = "3.4", cve_count: int = 1,
                    sources=("NVD",), extra_source: str | None = None) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(directory / "cve.db") as connection:
        connection.execute("CREATE TABLE cve_severity(cve_number TEXT, data_source TEXT)")
        connection.executemany("INSERT INTO cve_severity VALUES (?, 'NVD')",
                               [(f"CVE-2026-{index:04d}",) for index in range(cve_count)])
        if extra_source:
            connection.execute("INSERT INTO cve_severity VALUES ('CVE-2026-9999', ?)", (extra_source,))
        connection.execute("CREATE TABLE cve_range(cve_number TEXT, data_source TEXT)")
    with sqlite3.connect(directory / "version_map.db") as connection:
        connection.execute("CREATE TABLE latest_update_sqlite(datestamp DATETIME PRIMARY KEY)")
    (directory / "build.json").write_text(json.dumps({"tool_version": tool_version, "sources": list(sources),
                                                      "cve_count": cve_count, "range_count": 0,
                                                      "layer_records": cve_count}), encoding="utf-8")


def fake_runner(settings, input_dir: Path, output_dir: Path):
    staged = sorted((input_dir / "layers").glob("*.json.gz"))
    records = sum(len(json.loads(gzip.decompress(path.read_bytes()))["vulnerabilities"]) for path in staged)
    write_databases(output_dir, tool_version=settings.tool_version, cve_count=records)
    return {"image": settings.image, "image_id": "sha256:" + "f" * 64, "tool_version": settings.tool_version}


# --- settings ---------------------------------------------------------------------------------------

def test_settings_resolve_paths_relative_to_the_repository_and_keep_timeouts(tmp_path: Path) -> None:
    settings = cve_db.CveBinToolSettings.from_mapping(ROOT, {
        "feed_root": "data/feeds/cve-bin-tool", "image": "img:1", "tool_version": "3.4",
        "build_context": "tools/cve-bin-tool", "build_timeout_seconds": 10, "run_timeout_seconds": 20,
        "image_id": "sha256:" + "a" * 64})
    assert settings.feed_root == (ROOT / "data" / "feeds" / "cve-bin-tool").resolve()
    assert settings.build_context == BUILD_CONTEXT.resolve()
    assert (settings.build_timeout_seconds, settings.run_timeout_seconds) == (10, 20)
    assert settings.image_id == "sha256:" + "a" * 64


@pytest.mark.parametrize(("overrides", "message"), [
    ({"image_id": "latest"}, "image_id must be sha256"),
    ({"image_id": "sha256:" + "A" * 64}, "image_id must be sha256"),
    ({"image": ""}, "image, version, and positive timeouts are required"),
    ({"tool_version": ""}, "image, version, and positive timeouts are required"),
    ({"run_timeout_seconds": 0}, "positive timeouts"),
    ({"build_context": "missing-context"}, "build context is incomplete"),
], ids=["tag-as-id", "uppercase-id", "no-image", "no-version", "zero-timeout", "no-context"])
def test_settings_refuse_incomplete_or_unsafe_values(tmp_path: Path, overrides, message) -> None:
    with pytest.raises(ValueError, match=message):
        _settings(tmp_path, **overrides)


# --- resolve_nvd_snapshot ---------------------------------------------------------------------------

def _nvd_root(tmp_path: Path) -> tuple[Path, dict]:
    root = publish_nvd(tmp_path / "nvd", [nvd_vulnerability("CVE-2026-0001"), nvd_vulnerability("CVE-2026-0002")])
    return root, json.loads((root / "current.json").read_text(encoding="utf-8"))


def test_resolve_returns_the_bound_snapshot_chain_and_its_verified_raw_layers(tmp_path: Path) -> None:
    root, pointer = _nvd_root(tmp_path)
    resolved = cve_db.resolve_nvd_snapshot(root, pointer)
    assert resolved["schema"] == "appsec-review/resolved-nvd-snapshot/1"
    assert resolved["snapshot_id"] == pointer["snapshot_id"]
    assert resolved["manifest_sha256"] == pointer["manifest_sha256"]
    assert resolved["chain_snapshot_ids"] == [pointer["snapshot_id"]]
    assert resolved["layer_count"] == len(resolved["layers"]) >= 1
    for layer in resolved["layers"]:
        path = Path(layer["path"])
        assert path.is_relative_to(root) and path.stat().st_size == layer["size_bytes"]
        assert file_sha256(path) == layer["sha256"]


def test_resolve_refuses_a_pointer_that_moved_or_a_tampered_layer(tmp_path: Path) -> None:
    root, pointer = _nvd_root(tmp_path)
    with pytest.raises(ValueError, match="NVD current pointer changed after this execution bound it"):
        cve_db.resolve_nvd_snapshot(root, {**pointer, "snapshot_id": "sha256-other"})
    with pytest.raises(ValueError, match="NVD current pointer changed after this execution bound it"):
        cve_db.resolve_nvd_snapshot(root, {**pointer, "manifest_sha256": "0" * 64})
    layer = Path(cve_db.resolve_nvd_snapshot(root, pointer)["layers"][0]["path"])
    layer.write_bytes(layer.read_bytes() + b"\0")
    with pytest.raises(ValueError, match="NVD raw blob integrity mismatch"):
        cve_db.resolve_nvd_snapshot(root, pointer)


# --- the build record check -------------------------------------------------------------------------

def test_check_reads_counts_from_a_consistent_build(tmp_path: Path) -> None:
    write_databases(tmp_path / "out", cve_count=3)
    assert cve_db._check(tmp_path / "out", "3.4") == {"cve_count": 3, "range_count": 0, "layer_records": 3}


@pytest.mark.parametrize(("kwargs", "message"), [
    ({"tool_version": "3.3"}, "build record does not match the configured tool"),
    ({"sources": ("NVD", "OSV")}, "build record does not match the configured tool"),
    ({"cve_count": 0}, "database is empty or contains an unexpected data source"),
    ({"extra_source": "REDHAT"}, "database is empty or contains an unexpected data source"),
], ids=["version", "sources", "empty", "foreign-source"])
def test_check_refuses_a_mismatched_record_or_database(tmp_path: Path, kwargs, message) -> None:
    write_databases(tmp_path / "out", **kwargs)
    with pytest.raises(ValueError, match=message):
        cve_db._check(tmp_path / "out", "3.4")


def test_check_refuses_a_record_whose_count_disagrees_with_the_database(tmp_path: Path) -> None:
    write_databases(tmp_path / "out", cve_count=2)
    record = json.loads((tmp_path / "out" / "build.json").read_text(encoding="utf-8"))
    (tmp_path / "out" / "build.json").write_text(json.dumps({**record, "cve_count": 5}), encoding="utf-8")
    with pytest.raises(ValueError, match="database is empty or contains an unexpected data source"):
        cve_db._check(tmp_path / "out", "3.4")


# --- build, publish, verify -------------------------------------------------------------------------

def test_build_stages_layers_in_order_runs_the_injected_builder_and_reports_the_facts(tmp_path: Path) -> None:
    root, pointer = _nvd_root(tmp_path)
    resolved = cve_db.resolve_nvd_snapshot(root, pointer)
    settings = _settings(tmp_path)
    seen: dict = {}

    def runner(received, input_dir, output_dir):
        seen.update(settings=received, input_dir=input_dir, output_dir=output_dir,
                    staged=sorted(path.name for path in (input_dir / "layers").iterdir()))
        return fake_runner(received, input_dir, output_dir)

    built = cve_db.build(settings, resolved, tmp_path / "work", runner)
    assert seen["settings"] is settings
    assert seen["input_dir"] == tmp_path / "work" / "input" and seen["output_dir"] == tmp_path / "work" / "output"
    assert seen["staged"] == [f"{index:06d}.json.gz" for index in range(resolved["layer_count"])]
    assert built["schema"] == "appsec-review/cve-bin-tool-build/1"
    assert built["directory"] == str(tmp_path / "work" / "output")
    assert (built["nvd_snapshot_id"], built["nvd_manifest_sha256"]) == (pointer["snapshot_id"], pointer["manifest_sha256"])
    assert built["tool"] == {"image": settings.image, "image_id": "sha256:" + "f" * 64, "tool_version": "3.4"}
    assert built["cve_count"] == 2 and built["layer_records"] == 2


def test_build_refuses_a_layer_that_changed_between_resolution_and_staging(tmp_path: Path) -> None:
    root, pointer = _nvd_root(tmp_path)
    resolved = cve_db.resolve_nvd_snapshot(root, pointer)
    resolved["layers"][0]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="NVD layer changed while staging cve-bin-tool input"):
        cve_db.build(_settings(tmp_path), resolved, tmp_path / "work", fake_runner)


def test_build_fails_when_the_builder_output_does_not_match_the_configured_tool(tmp_path: Path) -> None:
    root, pointer = _nvd_root(tmp_path)
    resolved = cve_db.resolve_nvd_snapshot(root, pointer)

    def wrong_version(settings, input_dir, output_dir):
        write_databases(output_dir, tool_version="9.9")
        return {"image": settings.image, "image_id": "sha256:" + "f" * 64, "tool_version": "9.9"}

    with pytest.raises(ValueError, match="build record does not match the configured tool"):
        cve_db.build(_settings(tmp_path), resolved, tmp_path / "work", wrong_version)


def test_publish_then_verify_pins_the_database_to_the_nvd_snapshot_it_was_built_from(tmp_path: Path) -> None:
    root, pointer = _nvd_root(tmp_path)
    resolved = cve_db.resolve_nvd_snapshot(root, pointer)
    settings = _settings(tmp_path)
    built = cve_db.build(settings, resolved, tmp_path / "work", fake_runner)
    published = cve_db.publish(settings, built)
    assert published["schema"] == "appsec-review/feed-pointer/1" and published["feed_id"] == "cve-bin-tool"
    snapshot = settings.feed_root / "snapshots" / published["snapshot_id"]
    manifest = json.loads((snapshot / "manifest.json").read_text(encoding="utf-8"))
    assert set(manifest["files"]) == {"cve.db", "version_map.db", "build.json"}
    assert manifest["nvd_snapshot_id"] == pointer["snapshot_id"] and manifest["tool"] == built["tool"]
    verified = cve_db.verify(settings, resolved)
    assert verified["snapshot_id"] == published["snapshot_id"] and verified["cve_count"] == 2
    assert verified["nvd_snapshot_id"] == pointer["snapshot_id"]
    with pytest.raises(ValueError, match="was not built from this execution's NVD snapshot"):
        cve_db.verify(settings, {**resolved, "snapshot_id": "sha256-other"})
