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
        connection.execute("""CREATE TABLE cve_range(
            cve_number TEXT, data_source TEXT, vendor TEXT, product TEXT, version TEXT,
            versionStartIncluding TEXT, versionStartExcluding TEXT,
            versionEndIncluding TEXT, versionEndExcluding TEXT)""")
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


def test_settings_resolve_and_check_cover_remaining_validation_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="cve-bin-tool image, version, and positive timeouts are required"):
        _settings(tmp_path, run_timeout_seconds=0)

    root, pointer = _nvd_root(tmp_path)
    manifest_path = root / "snapshots" / pointer["snapshot_id"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Bound manifest hash mismatch
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="NVD bound manifest hash mismatch"):
        cve_db.resolve_nvd_snapshot(root, pointer)

    # Snapshot manifest identity mismatch
    bad_id = {**manifest, "snapshot_id": "sha256-wrong"}
    manifest_path.write_text(json.dumps(bad_id), encoding="utf-8")
    with pytest.raises(ValueError, match="NVD snapshot manifest identity mismatch"):
        cve_db.resolve_nvd_snapshot(root, pointer)

    # Empty layers
    no_layers = {**manifest, "layers": [], "parent_snapshot_id": None}
    manifest_path.write_text(json.dumps(no_layers), encoding="utf-8")
    pointer_no_layers = {**pointer, "manifest_sha256": file_sha256(manifest_path)}
    (root / "current.json").write_text(json.dumps(pointer_no_layers), encoding="utf-8")
    with pytest.raises(ValueError, match="NVD snapshot has no replayable layers"):
        cve_db.resolve_nvd_snapshot(root, pointer_no_layers)

    # Cycle detection
    cyclic = {**manifest, "parent_snapshot_id": pointer["snapshot_id"]}
    manifest_path.write_text(json.dumps(cyclic), encoding="utf-8")
    pointer_cycle = {**pointer, "manifest_sha256": file_sha256(manifest_path)}
    (root / "current.json").write_text(json.dumps(pointer_cycle), encoding="utf-8")
    with pytest.raises(ValueError, match="NVD snapshot chain contains a cycle"):
        cve_db.resolve_nvd_snapshot(root, pointer_cycle)


def test_docker_and_native_builders_and_bind_source_preserve_pinned_image_isolation(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess
    from contextlib import contextmanager
    from types import SimpleNamespace
    from appsec_review.config import native_dagster
    from appsec_review.container_runtime import native_client
    from appsec_review.runtime import resources
    from appsec_review.signing.core import SignatureVerificationError

    pinned_id = "sha256:" + "a" * 64
    other_id = "sha256:" + "b" * 64
    pinned_settings = _settings(tmp_path, image_id=pinned_id)
    unpinned_settings = _settings(tmp_path)

    class Verifier:
        def __init__(self, fail: bool = False):
            self.fail = fail
            self.calls: list[tuple[str, str | None]] = []

        def verify(self, image_id: str, *, reference: str | None = None):
            self.calls.append((image_id, reference))
            if self.fail:
                raise SignatureVerificationError("bad signature")

    with pytest.raises(SignatureVerificationError, match="not the pinned"):
        cve_db._verify_pinned_image(other_id, pinned_settings, Verifier())
    with pytest.raises(SignatureVerificationError, match="bad signature"):
        cve_db._verify_pinned_image(pinned_id, pinned_settings, Verifier(fail=True))

    monkeypatch.setattr(native_dagster, "native_execution_requested", lambda: False)
    in_dir = tmp_path / "in"
    out_dir = tmp_path / "out"
    in_dir.mkdir()
    out_dir.mkdir()

    # Refuses building when image_id is pinned and inspect fails
    monkeypatch.setattr(
        cve_db.subprocess,
        "run",
        lambda argv, **kw: SimpleNamespace(returncode=1, stdout="", stderr="not found"),
    )
    with pytest.raises(SignatureVerificationError, match="refusing to build cve-bin-tool image"):
        cve_db._docker_builder(pinned_settings, in_dir, out_dir, image_verifier=Verifier())

    # Unpinned build failure
    def build_fail(argv, **kw):
        if argv[:3] == ["docker", "image", "inspect"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        return SimpleNamespace(returncode=2, stdout="", stderr="dockerfile boom")

    monkeypatch.setattr(cve_db.subprocess, "run", build_fail)
    with pytest.raises(RuntimeError, match="cve-bin-tool image build failed: dockerfile boom"):
        cve_db._docker_builder(unpinned_settings, in_dir, out_dir, image_verifier=Verifier())

    # Unpinned build + inspect + run success
    def build_and_run_ok(argv, **kw):
        if argv[:3] == ["docker", "image", "inspect"]:
            if not getattr(build_and_run_ok, "built", False):
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout=pinned_id + "\n", stderr="")
        if argv[:2] == ["docker", "build"]:
            build_and_run_ok.built = True
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="ok stderr")

    monkeypatch.setattr(cve_db.subprocess, "run", build_and_run_ok)
    res = cve_db._docker_builder(unpinned_settings, in_dir, out_dir, image_verifier=Verifier(fail=True))
    assert res == {"image": unpinned_settings.image, "image_id": pinned_id, "tool_version": "3.4"}
    assert (out_dir / "builder.stderr.txt").read_text(encoding="utf-8") == "ok stderr"

    # Pre-existing image verified + TimeoutExpired removes container + nonzero run raises
    rm_calls: list[list[str]] = []
    verifier = Verifier()

    def timeout_run(argv, **kw):
        if argv[:3] == ["docker", "image", "inspect"]:
            return SimpleNamespace(returncode=0, stdout=pinned_id + "\n", stderr="")
        if argv[:2] == ["docker", "rm"]:
            rm_calls.append(argv)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise subprocess.TimeoutExpired(argv, 5)

    monkeypatch.setattr(cve_db.subprocess, "run", timeout_run)
    with pytest.raises(subprocess.TimeoutExpired):
        cve_db._docker_builder(pinned_settings, in_dir, out_dir, image_verifier=verifier)
    assert verifier.calls == [(pinned_id, pinned_settings.image)]
    assert len(rm_calls) == 1 and rm_calls[0][:3] == ["docker", "rm", "--force"]

    monkeypatch.setattr(
        cve_db.subprocess,
        "run",
        lambda argv, **kw: SimpleNamespace(returncode=0, stdout=pinned_id + "\n", stderr="")
        if argv[:3] == ["docker", "image", "inspect"]
        else SimpleNamespace(returncode=7, stdout="", stderr="builder failed"),
    )
    with pytest.raises(RuntimeError, match="cve-bin-tool database build failed with exit 7"):
        cve_db._docker_builder(pinned_settings, in_dir, out_dir, image_verifier=Verifier())

    # Native builder paths
    @contextmanager
    def dummy_ctx(*a, **k):
        yield

    monkeypatch.setattr(resources, "reserve_execution", dummy_ctx)
    monkeypatch.setattr(resources, "tracked_container", dummy_ctx)
    monkeypatch.setattr(native_dagster, "native_execution_requested", lambda: True)

    monkeypatch.setattr(native_client, "native_run", lambda argv, timeout: None)
    with pytest.raises(RuntimeError, match="requires an approved preinstalled image"):
        cve_db._docker_builder(pinned_settings, in_dir, out_dir, image_verifier=Verifier())

    monkeypatch.setattr(
        native_client,
        "native_run",
        lambda argv, timeout: (0, (pinned_id + "\n").encode(), b"", False)
        if argv[:3] == ("docker", "image", "inspect")
        else None,
    )
    with pytest.raises(RuntimeError, match="lost its engine scope"):
        cve_db._native_builder(pinned_settings, in_dir, out_dir, image_verifier=Verifier())

    monkeypatch.setattr(
        native_client,
        "native_run",
        lambda argv, timeout: (0, (pinned_id + "\n").encode(), b"", False)
        if argv[:3] == ("docker", "image", "inspect")
        else (1, b"", b"native err", False),
    )
    with pytest.raises(RuntimeError, match="native cve-bin-tool database execution failed"):
        cve_db._native_builder(pinned_settings, in_dir, out_dir, image_verifier=Verifier())

    monkeypatch.setattr(
        native_client,
        "native_run",
        lambda argv, timeout: (0, (pinned_id + "\n").encode(), b"", False)
        if argv[:3] == ("docker", "image", "inspect")
        else (0, b"", b"native ok", False),
    )
    assert cve_db._native_builder(pinned_settings, in_dir, out_dir, image_verifier=Verifier()) == {
        "image": pinned_settings.image,
        "image_id": pinned_id,
        "tool_version": "3.4",
    }

    # _docker_bind_source inside & outside container
    monkeypatch.delenv("HOSTNAME", raising=False)
    assert cve_db._docker_bind_source(in_dir) == in_dir
    monkeypatch.setenv("HOSTNAME", "dagster-ctr")
    orig_exists = Path.exists
    monkeypatch.setattr(Path, "exists", lambda self: True if str(self) == "/.dockerenv" else orig_exists(self))
    monkeypatch.setattr(
        cve_db.subprocess,
        "run",
        lambda argv, **kw: SimpleNamespace(returncode=1, stdout="", stderr="inspect err"),
    )
    with pytest.raises(RuntimeError, match="could not inspect Dagster container mounts"):
        cve_db._docker_bind_source(Path("/workspace/runs/r1"))

    mounts = [
        {"Destination": "/workspace", "Source": "/host/ws"},
        {"Destination": "/workspace/runs", "Source": "/host/runs"},
        {"Destination": "/other", "Source": "/host/other"},
    ]
    monkeypatch.setattr(
        cve_db.subprocess,
        "run",
        lambda argv, **kw: SimpleNamespace(returncode=0, stdout=json.dumps(mounts), stderr=""),
    )
    assert cve_db._docker_bind_source(Path("/workspace/runs/r1/work")) == Path("/host/runs/r1/work")
    with pytest.raises(RuntimeError, match="not backed by a host mount"):
        cve_db._docker_bind_source(Path("/unmounted/path"))


# --- scanning consumer -------------------------------------------------------------------------------

def _published(tmp_path: Path):
    root, pointer = _nvd_root(tmp_path)
    resolved = cve_db.resolve_nvd_snapshot(root, pointer)
    settings = _settings(tmp_path)
    built = cve_db.build(settings, resolved, tmp_path / "work", fake_runner)
    return settings, pointer, cve_db.publish(settings, built)


def test_verify_consumer_resolves_the_current_snapshot_for_the_exact_tool_release(tmp_path: Path) -> None:
    settings, pointer, published = _published(tmp_path)
    verified = cve_db.verify_consumer(settings, tool_version="3.4")
    assert verified["snapshot_id"] == published["snapshot_id"]
    assert verified["manifest_sha256"] == published["manifest_sha256"]
    assert Path(verified["directory"]) == settings.feed_root / "snapshots" / published["snapshot_id"]
    assert verified["nvd_snapshot_id"] == pointer["snapshot_id"] and verified["cve_count"] == 2
    assert verified["tool"] == {"image": settings.image, "image_id": "sha256:" + "f" * 64, "tool_version": "3.4"}
    with pytest.raises(ValueError, match="consumer release differs from the configured database builder"):
        cve_db.verify_consumer(settings, tool_version="3.5")


def test_verify_consumer_refuses_a_missing_tampered_or_foreign_snapshot(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with pytest.raises((OSError, ValueError)):
        cve_db.verify_consumer(settings, tool_version="3.4")      # nothing published yet
    settings, _pointer, published = _published(tmp_path)
    snapshot = settings.feed_root / "snapshots" / published["snapshot_id"]
    record = snapshot / "build.json"
    original = record.read_bytes()
    record.chmod(0o644)
    record.write_bytes(original.replace(b'"3.4"', b'"9.9"'))
    with pytest.raises(ValueError, match="integrity mismatch"):
        cve_db.verify_consumer(settings, tool_version="3.4")
    record.write_bytes(original)
    assert cve_db.verify_consumer(settings, tool_version="3.4")["snapshot_id"] == published["snapshot_id"]
    # A snapshot whose manifest names another tool release is refused even when every hash verifies.
    manifest_path = snapshot / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["tool"]["tool_version"] = "3.3"
    manifest_path.chmod(0o644)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    with pytest.raises(ValueError):
        cve_db.verify_consumer(settings, tool_version="3.4")


def test_consumer_settings_read_the_builder_settings_the_run_froze(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    (run_root / "data" / "configuration").mkdir(parents=True)
    (run_root / "data" / "configuration" / "resolved.json").write_text(json.dumps({"jobs": {
        "job_third_party_data_sync": {"steps": {"cve_bin_tool_db_build": {"settings": {
            "feed_root": "data/feeds/cve-bin-tool", "image": "appsec-review/cve-bin-tool:3.4",
            "tool_version": "3.4", "build_context": "tools/cve-bin-tool"}}}}}}), encoding="utf-8")
    settings = cve_db.consumer_settings(ROOT, run_root)
    assert settings.feed_root == (ROOT / "data" / "feeds" / "cve-bin-tool").resolve()
    assert settings.tool_version == "3.4" and settings.image == "appsec-review/cve-bin-tool:3.4"
