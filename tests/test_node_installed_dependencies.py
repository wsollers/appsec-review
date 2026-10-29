"""Fast, fixture-only coverage for npm's installer record parser; no npm or network."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from appsec_review.jobs.job_language_build import node_installed
from appsec_review.jobs.job_language_build.node_installed import (
    DISCOVERY_BOUND_GAP, discover_prefixes, parse_installed_record,
)


def _install(root: Path, key: str, name: str, version: str, **extra) -> Path:
    directory = root / key
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "package.json").write_text(json.dumps({"name": name, "version": version, **extra}))
    (directory / "index.js").write_text("module.exports = 1;\n")
    return directory


def _record(root: Path, packages: dict, version=3) -> Path:
    path = root / "node_modules" / ".package-lock.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"name": "fixture", "lockfileVersion": version, "requires": True,
                                "packages": packages}))
    return path


@pytest.mark.parametrize("version", [2, 3])
def test_record_entries_cover_scoped_aliased_and_nested_installs(tmp_path, version):
    _install(tmp_path, "node_modules/left-pad", "left-pad", "1.3.0")
    _install(tmp_path, "node_modules/@scope/util", "@scope/util", "2.0.0")
    _install(tmp_path, "node_modules/alias", "real-name", "4.1.0")
    _install(tmp_path, "node_modules/a", "a", "1.0.0")
    _install(tmp_path, "node_modules/a/node_modules/b", "b", "0.1.0")
    _install(tmp_path, "node_modules/opt", "opt", "1.0.0")
    _install(tmp_path, "backend", "backend", "0.0.0")
    path = _record(tmp_path, {
        "": {"name": "fixture", "workspaces": ["backend"]},
        "backend": {"name": "backend", "version": "0.0.0"},
        "node_modules/backend": {"resolved": "backend", "link": True},
        "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.example/left-pad.tgz",
                                  "integrity": "sha512-left", "dev": True},
        "node_modules/@scope/util": {"version": "2.0.0", "devOptional": True},
        "node_modules/alias": {"name": "real-name", "version": "4.1.0"},
        "node_modules/a": {"version": "1.0.0"},
        "node_modules/a/node_modules/b": {"version": "0.1.0", "dev": True},
        "node_modules/opt": {"version": "1.0.0", "optional": True},
    }, version)
    record = parse_installed_record(tmp_path, ".")
    assert record.available and record.reason is None and record.lockfile_version == version
    assert record.record.workspace_path == "node_modules/.package-lock.json"
    assert record.record.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert record.record.size_bytes == path.stat().st_size
    assert not record.unverified
    by_entry = {package.entry: package for package in record.packages}
    assert sorted(by_entry) == ["node_modules/@scope/util", "node_modules/a", "node_modules/a/node_modules/b",
                                "node_modules/alias", "node_modules/left-pad", "node_modules/opt"]
    assert by_entry["node_modules/alias"].name == "real-name"
    assert by_entry["node_modules/@scope/util"].name == "@scope/util"
    assert by_entry["node_modules/a/node_modules/b"].install_path == "node_modules/a/node_modules/b"
    left = by_entry["node_modules/left-pad"]
    assert (left.resolved, left.integrity, left.dev, left.build_only) == (
        "https://registry.example/left-pad.tgz", "sha512-left", True, True)
    util = by_entry["node_modules/@scope/util"]
    assert (util.dev, util.dev_optional, util.build_only) == (False, True, True)
    opt = by_entry["node_modules/opt"]
    assert (opt.optional, opt.build_only, opt.resolved, opt.integrity) == (True, False, None, None)
    assert not by_entry["node_modules/a"].build_only
    manifest = tmp_path / "node_modules/a/package.json"
    assert by_entry["node_modules/a"].manifest.workspace_path == "node_modules/a/package.json"
    assert by_entry["node_modules/a"].manifest.sha256 == hashlib.sha256(manifest.read_bytes()).hexdigest()


def test_nested_prefix_paths_are_workspace_relative(tmp_path):
    prefix = tmp_path / "web"
    _install(prefix, "node_modules/dep", "dep", "1.0.0")
    _record(prefix, {"node_modules/dep": {"version": "1.0.0"}})
    record = parse_installed_record(tmp_path, "web")
    assert record.record.workspace_path == "web/node_modules/.package-lock.json"
    [package] = record.packages
    assert package.install_path == "web/node_modules/dep"
    assert package.manifest.workspace_path == "web/node_modules/dep/package.json"
    with pytest.raises(ValueError):
        parse_installed_record(tmp_path, "../outside")


def _write_raw(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "node_modules" / ".package-lock.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


@pytest.mark.parametrize("payload,reason", [
    (b"{not json", "invalid-json"),
    (b"\xff\xfe", "invalid-json"),
    (b"[]", "invalid-json"),
    (json.dumps({"lockfileVersion": 3, "packages": []}).encode(), "invalid-json"),
    (json.dumps({"lockfileVersion": 1, "packages": {}}).encode(), "unsupported-lockfile-version:1"),
    (json.dumps({"lockfileVersion": "3", "packages": {}}).encode(), 'unsupported-lockfile-version:"3"'),
    (json.dumps({"lockfileVersion": True, "packages": {}}).encode(), "unsupported-lockfile-version:true"),
    (json.dumps({"packages": {}}).encode(), "unsupported-lockfile-version:null"),
    (json.dumps({"lockfileVersion": 3, "packages": {"node_modules/../x": {"version": "1"}}}).encode(),
     "entry-invalid:node_modules/../x"),
    (json.dumps({"lockfileVersion": 3, "packages": {"/node_modules/x": {"version": "1"}}}).encode(),
     "entry-invalid:/node_modules/x"),
    (json.dumps({"lockfileVersion": 3, "packages": {"node_modules/x/lib": {"version": "1"}}}).encode(),
     "entry-invalid:node_modules/x/lib"),
    (json.dumps({"lockfileVersion": 3, "packages": {"node_modules/@scope": {"version": "1"}}}).encode(),
     "entry-invalid:node_modules/@scope"),
    (json.dumps({"lockfileVersion": 3, "packages": {"node_modules/x": {}}}).encode(),
     "entry-invalid:node_modules/x"),
    (json.dumps({"lockfileVersion": 3, "packages": {"node_modules/x": {"version": ""}}}).encode(),
     "entry-invalid:node_modules/x"),
    (json.dumps({"lockfileVersion": 3, "packages": {"node_modules/x": []}}).encode(),
     "entry-invalid:node_modules/x"),
    (json.dumps({"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1", "dev": "yes"}}}).encode(),
     "entry-invalid:node_modules/x"),
    (json.dumps({"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1", "name": "../y"}}}).encode(),
     "entry-invalid:node_modules/x"),
    (json.dumps({"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1", "resolved": 7}}}).encode(),
     "entry-invalid:node_modules/x"),
])
def test_unusable_record_is_unavailable_and_covers_nothing(tmp_path, payload, reason):
    _install(tmp_path, "node_modules/x", "x", "1")
    _write_raw(tmp_path, payload)
    record = parse_installed_record(tmp_path)
    assert (record.status, record.reason) == ("unavailable", reason)
    assert record.packages == () and record.unverified == ()


def test_one_invalid_entry_makes_the_whole_record_unavailable(tmp_path):
    _install(tmp_path, "node_modules/good", "good", "1.0.0")
    _record(tmp_path, {"node_modules/good": {"version": "1.0.0"},
                       "node_modules/bad\\name": {"version": "1.0.0"}})
    record = parse_installed_record(tmp_path)
    assert record.reason == "entry-invalid:node_modules/bad\\name"
    assert record.packages == ()


def test_entry_invalid_reason_bounds_target_text(tmp_path):
    key = "node_modules/" + "\x07" + "x" * 500
    _write_raw(tmp_path, json.dumps({"lockfileVersion": 3, "packages": {key: {"version": "1"}}}).encode())
    reason = parse_installed_record(tmp_path).reason
    assert reason.startswith("entry-invalid:node_modules/?xxx") and reason.endswith("...")
    assert len(reason) == len("entry-invalid:") + 200


def test_missing_symlinked_and_unreadable_records(tmp_path, monkeypatch):
    (tmp_path / "node_modules").mkdir()
    assert parse_installed_record(tmp_path).reason == "missing"
    real = tmp_path / "elsewhere.json"
    real.write_text(json.dumps({"lockfileVersion": 3, "packages": {}}))
    (tmp_path / "node_modules" / ".package-lock.json").symlink_to(real)
    assert parse_installed_record(tmp_path).reason == "missing"
    (tmp_path / "node_modules" / ".package-lock.json").unlink()
    _record(tmp_path, {})
    original = Path.open

    def failing_open(self, *args, **kwargs):
        if self.name == ".package-lock.json":
            raise PermissionError("denied")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)
    record = parse_installed_record(tmp_path)
    assert (record.status, record.reason, record.record) == ("unavailable", "unreadable", None)


def test_installed_tree_must_match_the_record(tmp_path):
    _install(tmp_path, "node_modules/ok", "ok", "1.0.0")
    _install(tmp_path, "node_modules/renamed", "other", "1.0.0")
    _install(tmp_path, "node_modules/drifted", "drifted", "2.0.0")
    (tmp_path / "node_modules/no-manifest").mkdir(parents=True)
    _install(tmp_path, "node_modules/broken", "broken", "1.0.0")
    (tmp_path / "node_modules/broken/package.json").write_text("{broken")
    _install(tmp_path, "node_modules/array", "array", "1.0.0")
    (tmp_path / "node_modules/array/package.json").write_text("[]")
    _install(tmp_path, "outside", "linked", "1.0.0")
    os.symlink(tmp_path / "outside", tmp_path / "node_modules/linked")
    _install(tmp_path, "node_modules/manifest-link", "manifest-link", "1.0.0")
    (tmp_path / "node_modules/manifest-link/package.json").unlink()
    (tmp_path / "node_modules/manifest-link/package.json").symlink_to(tmp_path / "outside/package.json")
    _record(tmp_path, {key: {"version": "1.0.0"} for key in (
        "node_modules/ok", "node_modules/renamed", "node_modules/drifted", "node_modules/no-manifest",
        "node_modules/broken", "node_modules/array", "node_modules/linked", "node_modules/absent",
        "node_modules/manifest-link")})
    record = parse_installed_record(tmp_path)
    assert record.available
    assert [package.entry for package in record.packages] == ["node_modules/ok"]
    assert {item.entry: item.reason for item in record.unverified} == {
        "node_modules/renamed": "name-mismatch",
        "node_modules/drifted": "version-mismatch",
        "node_modules/no-manifest": "manifest-missing",
        "node_modules/broken": "manifest-invalid",
        "node_modules/array": "manifest-invalid",
        "node_modules/linked": "install-path-missing",
        "node_modules/absent": "install-path-missing",
        "node_modules/manifest-link": "manifest-missing",
    }
    assert all(item.install_path == item.entry for item in record.unverified)


def test_record_and_package_count_bounds_at_limit_and_beyond(tmp_path, monkeypatch):
    for name in ("a", "b", "c"):
        _install(tmp_path, f"node_modules/{name}", name, "1.0.0")
    path = _record(tmp_path, {f"node_modules/{name}": {"version": "1.0.0"} for name in ("a", "b", "c")})
    monkeypatch.setattr(node_installed, "MAX_PACKAGES", 3)
    assert len(parse_installed_record(tmp_path).packages) == 3
    monkeypatch.setattr(node_installed, "MAX_PACKAGES", 2)
    assert parse_installed_record(tmp_path).reason == "bound-exceeded:packages"
    monkeypatch.setattr(node_installed, "MAX_PACKAGES", 3)
    monkeypatch.setattr(node_installed, "MAX_RECORD_BYTES", path.stat().st_size)
    assert parse_installed_record(tmp_path).available
    monkeypatch.setattr(node_installed, "MAX_RECORD_BYTES", path.stat().st_size - 1)
    record = parse_installed_record(tmp_path)
    assert (record.reason, record.packages) == ("bound-exceeded:record-bytes", ())


def test_manifest_bound_at_limit_and_beyond(tmp_path, monkeypatch):
    _install(tmp_path, "node_modules/a", "a", "1.0.0")
    _record(tmp_path, {"node_modules/a": {"version": "1.0.0"}})
    size = (tmp_path / "node_modules/a/package.json").stat().st_size
    monkeypatch.setattr(node_installed, "MAX_MANIFEST_BYTES", size)
    assert len(parse_installed_record(tmp_path).packages) == 1
    monkeypatch.setattr(node_installed, "MAX_MANIFEST_BYTES", size - 1)
    [item] = parse_installed_record(tmp_path).unverified
    assert item.reason == "manifest-invalid"


def test_prefix_discovery_skips_dependency_trees_and_symlinks(tmp_path):
    for prefix in (".", "backend", "frontend"):
        (tmp_path / prefix / "node_modules" / "dep" / "node_modules").mkdir(parents=True)
    (tmp_path / "linked").mkdir()
    (tmp_path / "linked" / "node_modules").symlink_to(tmp_path / "backend" / "node_modules")
    (tmp_path / "frontend" / "dist").mkdir()
    assert discover_prefixes(tmp_path) == ([".", "backend", "frontend"], [])
    assert discover_prefixes(tmp_path, 3) == ([".", "backend", "frontend"], [])
    assert discover_prefixes(tmp_path, 2) == ([".", "backend"], [DISCOVERY_BOUND_GAP])
    assert DISCOVERY_BOUND_GAP == ("npm installer record discovery bound reached; "
                                   "remaining prefixes cataloged per-file")


def test_default_prefix_bound_is_thirty_two(tmp_path):
    for ordinal in range(33):
        (tmp_path / f"p{ordinal:02d}" / "node_modules").mkdir(parents=True)
    prefixes, gaps = discover_prefixes(tmp_path)
    assert len(prefixes) == 32 and gaps == [DISCOVERY_BOUND_GAP]
