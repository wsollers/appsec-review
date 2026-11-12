"""Fast, fixture-only coverage for Composer's installed.json record parser; no composer or network."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from appsec_review.jobs.job_language_build import php_installed
from appsec_review.jobs.job_language_build.php_installed import (
    DISCOVERY_BOUND_GAP, discover_prefixes, installer_owned, parse_installed_record,
)


def _package(root: Path, directory: str, name: str | None = None, **manifest) -> Path:
    path = root / "vendor" / directory
    (path / "src").mkdir(parents=True, exist_ok=True)
    (path / "src" / "Code.php").write_text("<?php\n")
    if name is not None:
        (path / "composer.json").write_text(json.dumps({"name": name, **manifest}))
    return path


def _record(root: Path, document) -> Path:
    path = root / "vendor" / "composer" / "installed.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(document if isinstance(document, bytes) else json.dumps(document).encode())
    return path


def _entry(name: str, version: str = "1.0.0", **fields) -> dict:
    return {"name": name, "version": version, "install-path": f"../{name}", **fields}


def test_composer_2_record_lists_packages_dev_names_and_install_paths(tmp_path):
    _package(tmp_path, "acme/runtime", "acme/runtime")
    _package(tmp_path, "acme/devtool", "Acme/DevTool", version="9.9.9")
    _package(tmp_path, "composer/semver", "composer/semver")
    _package(tmp_path, "acme/runtime/plugins/extra", "acme/extra")
    path = _record(tmp_path, {
        "packages": [
            _entry("acme/runtime", "1.2.3", version_normalized="1.2.3.0", type="library",
                   dist={"type": "zip", "url": "https://example.invalid/r.zip", "reference": "abc123",
                         "shasum": ""},
                   source={"type": "git", "url": "https://example.invalid/r.git", "reference": "abc123"}),
            _entry("acme/devtool", "v2.0.0"),
            {"name": "composer/semver", "version": "3.4.0", "install-path": "./semver"},
            {"name": "acme/extra", "version": "0.1.0", "type": "acme-plugin",
             "install-path": "../acme/runtime/plugins/extra"},
            {"name": "acme/meta", "version": "1.0.0", "type": "metapackage", "install-path": None},
        ],
        "dev": True, "dev-package-names": ["acme/devtool", "acme/not-installed"]})

    record = parse_installed_record(tmp_path, ".")

    assert record.available and record.reason is None and record.layout == "composer-2"
    assert record.record.workspace_path == "vendor/composer/installed.json"
    assert record.record.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert record.record.size_bytes == path.stat().st_size
    assert record.unverified == () and record.without_install == 1
    by_entry = {package.entry: package for package in record.packages}
    assert [package.install_path for package in record.packages] == [
        "vendor/acme/devtool", "vendor/acme/runtime", "vendor/acme/runtime/plugins/extra",
        "vendor/composer/semver"]
    runtime = by_entry["acme/runtime"]
    assert (runtime.name, runtime.version, runtime.version_normalized, runtime.package_type, runtime.dev) == (
        "acme/runtime", "1.2.3", "1.2.3.0", "library", False)
    # Only the identity fields of dist and source are retained; URLs are not.
    assert runtime.dist == {"type": "zip", "reference": "abc123", "shasum": ""}
    assert runtime.source == {"type": "git", "reference": "abc123"}
    manifest = tmp_path / "vendor/acme/runtime/composer.json"
    assert runtime.manifest.workspace_path == "vendor/acme/runtime/composer.json"
    assert runtime.manifest.sha256 == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert runtime.manifest.size_bytes == manifest.stat().st_size
    # Names compare without case; an installed manifest's own version is not compared.
    devtool = by_entry["acme/devtool"]
    assert (devtool.version, devtool.dev, devtool.dist, devtool.source) == ("v2.0.0", True, None, None)
    assert (by_entry["acme/extra"].package_type, by_entry["acme/extra"].dev) == ("acme-plugin", False)
    assert by_entry["composer/semver"].install_path == "vendor/composer/semver"


def test_composer_1_list_uses_default_paths_and_marks_no_package_dev(tmp_path):
    _package(tmp_path, "acme/runtime", "acme/runtime")
    _package(tmp_path, "acme/devtool", "acme/devtool")
    _record(tmp_path, [
        {"name": "acme/runtime", "version": "1.2.3", "version_normalized": "1.2.3.0"},
        {"name": "acme/devtool", "version": "v2.0.0", "type": "library"},
        {"name": "acme/meta", "version": "1.0.0", "type": "metapackage"},
    ])

    record = parse_installed_record(tmp_path)

    assert record.available and record.layout == "composer-1" and record.without_install == 1
    assert [(package.entry, package.install_path, package.dev) for package in record.packages] == [
        ("acme/devtool", "vendor/acme/devtool", False), ("acme/runtime", "vendor/acme/runtime", False)]
    assert record.unverified == ()


def test_nested_prefix_paths_are_workspace_relative(tmp_path):
    _package(tmp_path / "svc", "acme/dep", "acme/dep")
    _record(tmp_path / "svc", {"packages": [_entry("acme/dep")]})
    record = parse_installed_record(tmp_path, "svc")
    assert record.record.workspace_path == "svc/vendor/composer/installed.json"
    [package] = record.packages
    assert package.install_path == "svc/vendor/acme/dep"
    assert package.manifest.workspace_path == "svc/vendor/acme/dep/composer.json"
    with pytest.raises(ValueError):
        parse_installed_record(tmp_path, "../outside")


def test_installed_tree_must_match_the_record(tmp_path):
    _package(tmp_path, "acme/ok", "acme/ok")
    _package(tmp_path, "acme/nomanifest")
    _package(tmp_path, "acme/badjson").joinpath("composer.json").write_text("{not json")
    _package(tmp_path, "acme/notobject").joinpath("composer.json").write_text("[]")
    _package(tmp_path, "acme/unnamed").joinpath("composer.json").write_text("{}")
    _package(tmp_path, "acme/renamed", "evil/other")
    _package(tmp_path, "acme/local", "acme/local")
    _package(tmp_path, "outside/pkg", "acme/linked")
    os.symlink(tmp_path / "vendor/outside/pkg", tmp_path / "vendor/acme/linked")
    os.symlink(tmp_path / "vendor/outside", tmp_path / "vendor/linkvendor")
    _package(tmp_path, "acme/linkfile")
    (tmp_path / "vendor/acme/linkfile/composer.json").symlink_to(tmp_path / "vendor/acme/ok/composer.json")
    (tmp_path / "plugins/installed").mkdir(parents=True)
    (tmp_path / "plugins/installed/composer.json").write_text('{"name": "acme/elsewhere"}')
    _record(tmp_path, {"packages": [
        _entry("acme/absent"), _entry("acme/badjson"), _entry("acme/linked"), _entry("acme/linkfile"),
        _entry("acme/local", dist={"type": "path", "url": "../local", "reference": "x"}),
        _entry("acme/nomanifest"), _entry("acme/notobject"), _entry("acme/ok"), _entry("acme/renamed"),
        _entry("acme/unnamed"),
        {"name": "acme/elsewhere", "version": "1.0.0", "install-path": "../../plugins/installed"},
        {"name": "linkvendor/pkg", "version": "1.0.0", "install-path": "../linkvendor/pkg"},
    ]})

    record = parse_installed_record(tmp_path)

    assert record.available
    assert [package.entry for package in record.packages] == ["acme/ok"]
    assert {item.entry: (item.install_path, item.reason) for item in record.unverified} == {
        "acme/absent": ("vendor/acme/absent", "install-path-missing"),
        "acme/badjson": ("vendor/acme/badjson", "manifest-invalid"),
        "acme/elsewhere": ("plugins/installed", "install-path-outside-vendor"),
        "acme/linked": ("vendor/acme/linked", "install-path-missing"),
        "acme/linkfile": ("vendor/acme/linkfile", "manifest-missing"),
        "acme/local": ("vendor/acme/local", "path-repository"),
        "acme/nomanifest": ("vendor/acme/nomanifest", "manifest-missing"),
        "acme/notobject": ("vendor/acme/notobject", "manifest-invalid"),
        "acme/renamed": ("vendor/acme/renamed", "name-mismatch"),
        "acme/unnamed": ("vendor/acme/unnamed", "name-mismatch"),
        # A symlinked directory between vendor and the package is an escape, not an install path.
        "linkvendor/pkg": ("vendor/linkvendor/pkg", "install-path-missing"),
    }


def _one(**fields) -> dict:
    return {"packages": [{"name": "acme/x", "version": "1.0.0", **fields}]}


MALFORMED = sorted({
    "not-json": (b"{not json", "invalid-json"),
    "undecodable-bytes": (b'["\xff\xfe"]', "invalid-json"),
    "scalar-root": ("installed", "unsupported-structure"),
    "object-without-packages": ({"dev": True}, "unsupported-structure"),
    "packages-not-a-list": ({"packages": {"acme/x": {}}}, "unsupported-structure"),
    "dev-flag-not-boolean": ({"packages": [], "dev": "yes"}, "dev-flag-invalid"),
    "dev-names-not-a-list": ({"packages": [], "dev-package-names": "acme/x"}, "dev-package-names-invalid"),
    "dev-names-not-strings": ({"packages": [], "dev-package-names": [1]}, "dev-package-names-invalid"),
    "entry-not-an-object": ({"packages": ["acme/x"]}, "entry-invalid:not-an-object"),
    "entry-in-composer-1-list": ([["acme/x"]], "entry-invalid:not-an-object"),
    "name-missing": ({"packages": [{"version": "1.0.0"}]}, "entry-invalid:null"),
    "name-without-vendor": ({"packages": [{"name": "x", "version": "1.0.0"}]}, "entry-invalid:x"),
    "name-parent-segment": ({"packages": [{"name": "../x", "version": "1.0.0"}]}, "entry-invalid:../x"),
    "name-three-segments": ({"packages": [{"name": "a/b/c", "version": "1.0.0"}]}, "entry-invalid:a/b/c"),
    "name-backslash": ({"packages": [{"name": "acme\\x", "version": "1.0.0"}]}, "entry-invalid:acme\\x"),
    "version-missing": ({"packages": [{"name": "acme/x"}]}, "entry-invalid:acme/x"),
    "version-empty": (_one(version=""), "entry-invalid:acme/x"),
    "version-not-a-string": (_one(version=1), "entry-invalid:acme/x"),
    "version-control-character": (_one(version="1.0\n2"), "entry-invalid:acme/x"),
    "normalized-not-a-string": (_one(version_normalized=1), "entry-invalid:acme/x"),
    "type-not-a-string": (_one(type=["library"]), "entry-invalid:acme/x"),
    "dist-not-an-object": (_one(dist="zip"), "entry-invalid:acme/x"),
    "dist-field-not-a-string": (_one(dist={"type": 1}), "entry-invalid:acme/x"),
    "source-field-too-long": (_one(source={"reference": "r" * 1025}), "entry-invalid:acme/x"),
    "install-path-not-a-string": (_one(**{"install-path": 1}), "entry-invalid:acme/x"),
    "install-path-empty": (_one(**{"install-path": ""}), "entry-invalid:acme/x"),
    "install-path-absolute": (_one(**{"install-path": "/etc"}), "entry-invalid:acme/x"),
    "install-path-backslash": (_one(**{"install-path": "..\\acme\\x"}), "entry-invalid:acme/x"),
    "install-path-empty-segment": (_one(**{"install-path": "../acme//x"}), "entry-invalid:acme/x"),
    "install-path-control-character": (_one(**{"install-path": "../acme/x\x00"}), "entry-invalid:acme/x"),
    "install-path-leaves-prefix": (_one(**{"install-path": "../../../outside"}), "entry-invalid:acme/x"),
    "install-path-is-prefix": (_one(**{"install-path": "../.."}), "entry-invalid:acme/x"),
    "install-path-is-vendor": (_one(**{"install-path": ".."}), "entry-invalid:acme/x"),
    "install-path-is-record-directory": (_one(**{"install-path": "."}), "entry-invalid:acme/x"),
    "duplicate-name": ({"packages": [_entry("acme/x"), {"name": "Acme/X", "version": "2.0.0"}]},
                       "duplicate-package:Acme/X"),
    "duplicate-install-path": ({"packages": [_entry("acme/x"), {
        "name": "acme/y", "version": "1.0.0", "install-path": "../acme/x"}]}, "duplicate-install-path:acme/y"),
}.items())


@pytest.mark.parametrize("payload,reason", [case for _, case in MALFORMED], ids=[name for name, _ in MALFORMED])
def test_unusable_record_is_unavailable_and_covers_nothing(tmp_path, payload, reason):
    _package(tmp_path, "acme/x", "acme/x")
    path = _record(tmp_path, payload)
    record = parse_installed_record(tmp_path)
    assert (record.status, record.reason) == ("unavailable", reason)
    assert record.packages == () and record.unverified == () and record.without_install == 0
    assert record.record.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_one_invalid_entry_makes_the_whole_record_unavailable(tmp_path):
    _package(tmp_path, "acme/good", "acme/good")
    _record(tmp_path, {"packages": [_entry("acme/good"), {"name": "acme/bad", "version": None}]})
    record = parse_installed_record(tmp_path)
    assert (record.reason, record.packages, record.layout) == ("entry-invalid:acme/bad", (), "composer-2")


def test_reason_bounds_target_text(tmp_path):
    _record(tmp_path, {"packages": [{"name": "acme/" + "x" * 400 + "\n", "version": "1.0.0"}]})
    reason = parse_installed_record(tmp_path).reason
    assert reason.startswith("entry-invalid:acme/xxx") and reason.endswith("...")
    assert len(reason) == len("entry-invalid:") + 200 and "\n" not in reason


def test_empty_record_is_available_and_lists_nothing(tmp_path):
    for payload, layout in (([], "composer-1"), ({"packages": []}, "composer-2"),
                            ({"packages": [], "dev": False, "dev-package-names": []}, "composer-2")):
        _record(tmp_path, payload)
        record = parse_installed_record(tmp_path)
        assert (record.status, record.reason, record.packages, record.unverified, record.layout) == (
            "available", None, (), (), layout)


def test_missing_symlinked_and_unreadable_records(tmp_path, monkeypatch):
    (tmp_path / "vendor" / "composer").mkdir(parents=True)
    assert parse_installed_record(tmp_path).reason == "missing"
    real = tmp_path / "elsewhere.json"
    real.write_text("[]")
    (tmp_path / "vendor" / "composer" / "installed.json").symlink_to(real)
    record = parse_installed_record(tmp_path)
    assert (record.status, record.reason, record.record) == ("unavailable", "missing", None)
    (tmp_path / "vendor" / "composer" / "installed.json").unlink()
    _record(tmp_path, [])
    original = Path.open

    def failing_open(self, *args, **kwargs):
        if self.name == "installed.json":
            raise PermissionError("denied")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)
    record = parse_installed_record(tmp_path)
    assert (record.status, record.reason, record.record) == ("unavailable", "unreadable", None)


def test_record_package_and_manifest_bounds_at_limit_and_beyond(tmp_path, monkeypatch):
    for name in ("a", "b", "c"):
        _package(tmp_path, f"acme/{name}", f"acme/{name}")
    path = _record(tmp_path, {"packages": [_entry(f"acme/{name}") for name in ("a", "b", "c")]})
    monkeypatch.setattr(php_installed, "MAX_RECORD_BYTES", path.stat().st_size)
    assert len(parse_installed_record(tmp_path).packages) == 3
    monkeypatch.setattr(php_installed, "MAX_RECORD_BYTES", path.stat().st_size - 1)
    record = parse_installed_record(tmp_path)
    assert (record.reason, record.record, record.packages) == ("bound-exceeded:record-bytes", None, ())
    monkeypatch.undo()
    monkeypatch.setattr(php_installed, "MAX_PACKAGES", 3)
    assert parse_installed_record(tmp_path).available
    monkeypatch.setattr(php_installed, "MAX_PACKAGES", 2)
    assert parse_installed_record(tmp_path).reason == "bound-exceeded:packages"
    monkeypatch.undo()
    size = (tmp_path / "vendor/acme/a/composer.json").stat().st_size
    monkeypatch.setattr(php_installed, "MAX_MANIFEST_BYTES", size)
    assert len(parse_installed_record(tmp_path).packages) == 3
    monkeypatch.setattr(php_installed, "MAX_MANIFEST_BYTES", size - 1)
    record = parse_installed_record(tmp_path)
    assert record.packages == () and {item.reason for item in record.unverified} == {"manifest-invalid"}


def test_default_bounds_are_the_documented_values():
    assert (php_installed.MAX_PREFIXES, php_installed.MAX_RECORD_BYTES, php_installed.MAX_PACKAGES,
            php_installed.MAX_MANIFEST_BYTES, php_installed.MAX_FIELD_CHARS) == (
        32, 64 * 1024 * 1024, 20_000, 4 * 1024 * 1024, 1024)


def test_installer_owned_files_are_the_loader_and_the_record_directory_only():
    assert installer_owned(".", "vendor/autoload.php")
    assert installer_owned("svc", "svc/vendor/composer/ClassLoader.php")
    assert installer_owned(".", "vendor/composer/installed.json")
    assert not installer_owned(".", "vendor/composer/semver/src/Semver.php")
    assert not installer_owned(".", "vendor/acme/x/autoload.php")
    assert not installer_owned("svc", "vendor/autoload.php")


def test_prefix_discovery_needs_a_record_or_project_file_and_skips_vendor_trees(tmp_path):
    (tmp_path / "composer.json").write_text("{}")
    (tmp_path / "vendor" / "acme" / "dep" / "vendor").mkdir(parents=True)
    (tmp_path / "vendor" / "acme" / "dep" / "composer.json").write_text("{}")
    (tmp_path / "svc" / "vendor" / "composer").mkdir(parents=True)
    (tmp_path / "svc" / "vendor" / "composer" / "installed.json").write_text("[]")
    (tmp_path / "go" / "vendor").mkdir(parents=True)
    (tmp_path / "go" / "vendor" / "modules.txt").write_text("")
    (tmp_path / "go" / "go.mod").write_text("module example.com/m\n")
    (tmp_path / "linked").mkdir()
    (tmp_path / "linked" / "composer.json").write_text("{}")
    (tmp_path / "linked" / "vendor").symlink_to(tmp_path / "svc" / "vendor")
    (tmp_path / "web" / "vendor").mkdir(parents=True)
    (tmp_path / "web" / "composer.json").write_text("{}")
    assert discover_prefixes(tmp_path) == ([".", "svc", "web"], [])
    assert discover_prefixes(tmp_path, 3) == ([".", "svc", "web"], [])
    assert discover_prefixes(tmp_path, 2) == ([".", "svc"], [DISCOVERY_BOUND_GAP])
    assert DISCOVERY_BOUND_GAP == ("Composer installer record discovery bound reached; "
                                   "remaining prefixes cataloged per-file")


def test_default_prefix_bound_is_thirty_two(tmp_path):
    for ordinal in range(33):
        (tmp_path / f"p{ordinal:02d}" / "vendor").mkdir(parents=True)
        (tmp_path / f"p{ordinal:02d}" / "composer.json").write_text("{}")
    prefixes, gaps = discover_prefixes(tmp_path)
    assert len(prefixes) == 32 and gaps == [DISCOVERY_BOUND_GAP]
