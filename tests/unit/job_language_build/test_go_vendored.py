"""Fast, fixture-only coverage for Go's vendor/modules.txt record parser; no go command or network."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from appsec_review.jobs.job_language_build import go_vendored
from appsec_review.jobs.job_language_build.go_vendored import (
    DISCOVERY_BOUND_GAP, discover_prefixes, parse_vendor_record,
)


def _package(root: Path, import_path: str, *names: str) -> Path:
    directory = root / "vendor" / import_path
    directory.mkdir(parents=True, exist_ok=True)
    for name in names or ("doc.go",):
        (directory / name).write_text(f"package {directory.name.replace('.', '_')}\n")
    return directory


def _record(root: Path, text: str | bytes) -> Path:
    path = root / "vendor" / "modules.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text if isinstance(text, bytes) else text.encode())
    return path


def test_well_formed_record_lists_modules_annotations_and_nested_modules(tmp_path):
    _package(tmp_path, "example.com/alpha", "b.go", "a.go")
    (tmp_path / "vendor/example.com/alpha/LICENSE").write_text("license\n")
    _package(tmp_path, "example.com/alpha/sub")
    _package(tmp_path, "example.com/alpha/nested/pkg")
    _package(tmp_path, "golang.org/x/beta/unix")
    _package(tmp_path, "gopkg.in/yaml.v3")
    path = _record(tmp_path, (
        "# example.com/alpha v1.2.3\n"
        "## explicit; go 1.21\n"
        "example.com/alpha\n"
        "example.com/alpha/sub\n"
        "# example.com/alpha/nested v0.1.0\n"
        "## go 1.17\n"
        "example.com/alpha/nested/pkg\n"
        "# example.com/listed-only v1.0.0\n"
        "## explicit\n"
        "# golang.org/x/beta v0.0.0-20240101000000-abcdefabcdef\n"
        "golang.org/x/beta/unix\n"
        "# gopkg.in/yaml.v3 v3.0.1+incompatible\n"
        "## explicit\n"
        "gopkg.in/yaml.v3\n"))

    record = parse_vendor_record(tmp_path, ".")

    assert record.available and record.reason is None and not record.workspace_mode
    assert record.record.workspace_path == "vendor/modules.txt"
    assert record.record.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert record.record.size_bytes == path.stat().st_size
    assert record.unverified == () and record.without_packages == 1
    by_entry = {module.entry: module for module in record.modules}
    assert sorted(by_entry) == ["example.com/alpha", "example.com/alpha/nested", "golang.org/x/beta",
                                "gopkg.in/yaml.v3"]
    alpha = by_entry["example.com/alpha"]
    assert (alpha.name, alpha.version, alpha.explicit, alpha.go_version) == (
        "example.com/alpha", "v1.2.3", True, "1.21")
    assert alpha.install_path == "vendor/example.com/alpha"
    assert alpha.packages == ("example.com/alpha", "example.com/alpha/sub")
    assert (alpha.replacement_path, alpha.replacement_version) == (None, None)
    anchor = tmp_path / "vendor/example.com/alpha/a.go"
    assert alpha.anchor.workspace_path == "vendor/example.com/alpha/a.go"
    assert alpha.anchor.sha256 == hashlib.sha256(anchor.read_bytes()).hexdigest()
    assert alpha.anchor.size_bytes == anchor.stat().st_size
    nested = by_entry["example.com/alpha/nested"]
    assert (nested.explicit, nested.go_version) == (False, "1.17")
    assert nested.anchor.workspace_path == "vendor/example.com/alpha/nested/pkg/doc.go"
    beta = by_entry["golang.org/x/beta"]
    assert (beta.version, beta.explicit, beta.go_version) == (
        "v0.0.0-20240101000000-abcdefabcdef", False, None)
    assert by_entry["gopkg.in/yaml.v3"].version == "v3.0.1+incompatible"


def test_replacements_workspace_marker_and_crlf_lines(tmp_path):
    _package(tmp_path, "example.com/forked/pkg")
    _package(tmp_path, "example.com/local")
    _record(tmp_path, (
        "## workspace\r\n"
        "# example.com/forked v1.0.0 => example.org/fork v1.0.1-rc.1\r\n"
        "## explicit\r\n"
        "example.com/forked/pkg\r\n"
        "# example.com/local v0.0.0 => ./internal/local\r\n"
        "example.com/local\r\n"
        "# example.com/unused v1.4.0 => ../elsewhere\r\n"
        "# example.com/wild => /abs/wild\r\n"
        "# example.com/pinned => example.org/pinned v2.0.0\r\n"))

    record = parse_vendor_record(tmp_path)

    assert record.available and record.workspace_mode and record.without_packages == 3
    [forked] = record.modules
    assert (forked.entry, forked.version, forked.replacement_path, forked.replacement_version) == (
        "example.com/forked", "v1.0.0", "example.org/fork", "v1.0.1-rc.1")
    # A directory replacement vendors local content under a registry name; it is never summarized.
    assert [(item.entry, item.install_path, item.reason) for item in record.unverified] == [
        ("example.com/local", "vendor/example.com/local", "local-replacement")]


def test_nested_prefix_paths_are_workspace_relative(tmp_path):
    _package(tmp_path / "svc", "example.com/dep")
    _record(tmp_path / "svc", "# example.com/dep v1.0.0\nexample.com/dep\n")
    record = parse_vendor_record(tmp_path, "svc")
    assert record.record.workspace_path == "svc/vendor/modules.txt"
    [module] = record.modules
    assert module.install_path == "svc/vendor/example.com/dep"
    assert module.anchor.workspace_path == "svc/vendor/example.com/dep/doc.go"
    with pytest.raises(ValueError):
        parse_vendor_record(tmp_path, "../outside")


def test_vendored_tree_must_match_the_record(tmp_path):
    _package(tmp_path, "example.com/ok/pkg")
    _package(tmp_path, "example.com/partial/one")
    (tmp_path / "vendor/example.com/empty/pkg").mkdir(parents=True)
    (tmp_path / "vendor/example.com/empty/pkg/README").write_text("no go files\n")
    _package(tmp_path, "example.com/extra/pkg")
    _package(tmp_path, "example.com/extra/unlisted")
    _package(tmp_path, "outside/pkg")
    (tmp_path / "vendor/example.com/linked").parent.mkdir(parents=True, exist_ok=True)
    os.symlink(tmp_path / "vendor/outside", tmp_path / "vendor/example.com/linked")
    _package(tmp_path, "example.com/linkfile/pkg")
    (tmp_path / "vendor/example.com/linkfile/pkg/doc.go").unlink()
    (tmp_path / "vendor/example.com/linkfile/pkg/doc.go").symlink_to(tmp_path / "vendor/outside/pkg/doc.go")
    _record(tmp_path, "".join(f"# example.com/{name} v1.0.0\n{packages}" for name, packages in (
        ("absent", "example.com/absent/pkg\n"),
        ("empty", "example.com/empty/pkg\n"),
        ("extra", "example.com/extra/pkg\n"),
        ("linked", "example.com/linked/pkg\n"),
        ("linkfile", "example.com/linkfile/pkg\n"),
        ("ok", "example.com/ok/pkg\n"),
        ("partial", "example.com/partial/one\nexample.com/partial/two\n"))))

    record = parse_vendor_record(tmp_path)

    assert record.available
    assert [module.entry for module in record.modules] == ["example.com/ok"]
    assert {item.entry: item.reason for item in record.unverified} == {
        "example.com/absent": "install-path-missing",
        "example.com/empty": "package-empty:example.com/empty/pkg",
        "example.com/extra": "unrecorded-package:vendor/example.com/extra/unlisted",
        "example.com/linked": "install-path-missing",
        "example.com/linkfile": "package-empty:example.com/linkfile/pkg",
        "example.com/partial": "package-missing:example.com/partial/two",
    }
    assert all(item.install_path == f"vendor/{item.entry}" for item in record.unverified)


MALFORMED = sorted({
    "annotation-before-module": ("## explicit\n# example.com/x v1.0.0\nexample.com/x\n", "line-invalid:1"),
    "annotation-repeated": ("# example.com/x v1.0.0\n## explicit\n## go 1.20\nexample.com/x\n", "line-invalid:3"),
    "annotation-after-package": ("# example.com/x v1.0.0\nexample.com/x\n## explicit\n", "line-invalid:3"),
    "annotation-unknown-token": ("# example.com/x v1.0.0\n## explicit; future\nexample.com/x\n", "line-invalid:2"),
    "annotation-bad-go-version": ("# example.com/x v1.0.0\n## go one\nexample.com/x\n", "line-invalid:2"),
    "blank-line": ("# example.com/x v1.0.0\n\nexample.com/x\n", "line-invalid:2"),
    "comment-form": ("#example.com/x v1.0.0\n", "line-invalid:1"),
    "duplicate-module": ("# example.com/x v1.0.0\nexample.com/x\n# example.com/x v1.1.0\n", "duplicate-module:3"),
    "duplicate-package": ("# example.com/x v1.0.0\nexample.com/x\nexample.com/x\n", "duplicate-package:3"),
    "module-double-space": ("# example.com/x  v1.0.0\n", "line-invalid:1"),
    "module-no-version": ("# example.com/x\n", "line-invalid:1"),
    "module-not-semver": ("# example.com/x latest\n", "line-invalid:1"),
    "module-parent-segment": ("# example.com/../x v1.0.0\n", "line-invalid:1"),
    "module-trailing-field": ("# example.com/x v1.0.0 extra\n", "line-invalid:1"),
    "package-absolute": ("# example.com/x v1.0.0\n/etc/passwd\n", "line-invalid:2"),
    "package-backslash": ("# example.com/x v1.0.0\nexample.com\\x\n", "line-invalid:2"),
    "package-before-module": ("example.com/x\n", "package-outside-module:1"),
    "package-in-deeper-module": (
        "# example.com/x v1.0.0\nexample.com/x/y/z\n# example.com/x/y v1.0.0\nexample.com/x/y\n",
        "package-outside-module:example.com/x/y/z"),
    "package-other-module": ("# example.com/x v1.0.0\nexample.com/xy\n", "package-outside-module:2"),
    "package-under-wildcard": ("# example.com/x => ./x\nexample.com/x\n", "package-outside-module:2"),
    "package-with-space": ("# example.com/x v1.0.0\nexample.com/x extra\n", "line-invalid:2"),
    "replacement-bad-version": ("# example.com/x v1.0.0 => example.org/y latest\n", "line-invalid:1"),
    "replacement-missing-path": ("# example.com/x v1.0.0 =>\n", "line-invalid:1"),
    "replacement-too-long": ("# example.com/x v1.0.0 => example.org/y v1.0.0 z\n", "line-invalid:1"),
    "undecodable-bytes": (b"# example.com/x v1.0.0\n\xff\xfe\n", "invalid-encoding:2"),
    "workspace-not-first": ("# example.com/x v1.0.0\nexample.com/x\n## workspace\n", "line-invalid:3"),
}.items())


@pytest.mark.parametrize("payload,reason", [case for _, case in MALFORMED], ids=[name for name, _ in MALFORMED])
def test_unusable_record_is_unavailable_and_covers_nothing(tmp_path, payload, reason):
    _package(tmp_path, "example.com/x")
    path = _record(tmp_path, payload)
    record = parse_vendor_record(tmp_path)
    assert (record.status, record.reason) == ("unavailable", reason)
    assert record.modules == () and record.unverified == () and record.without_packages == 0
    assert record.record.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_one_invalid_line_makes_the_whole_record_unavailable(tmp_path):
    _package(tmp_path, "example.com/good")
    _record(tmp_path, "# example.com/good v1.0.0\nexample.com/good\n# example.com/bad v1.0.0 one two three\n")
    record = parse_vendor_record(tmp_path)
    assert (record.reason, record.modules) == ("line-invalid:3", ())


def test_reason_bounds_target_text(tmp_path):
    deep = "example.com/x/" + "/".join("p" * 60 for _ in range(6))
    _record(tmp_path, f"# example.com/x v1.0.0\n{deep}\n")
    _package(tmp_path, "example.com/x")
    [item] = parse_vendor_record(tmp_path).unverified
    assert item.reason.startswith("package-missing:example.com/x/ppp") and item.reason.endswith("...")
    assert len(item.reason) == len("package-missing:") + 200


def test_empty_record_is_available_and_lists_nothing(tmp_path):
    for payload in (b"", b"## workspace\n"):
        _record(tmp_path, payload)
        record = parse_vendor_record(tmp_path)
        assert (record.status, record.reason, record.modules, record.unverified) == ("available", None, (), ())
        assert record.record.size_bytes == len(payload)


def test_missing_symlinked_and_unreadable_records(tmp_path, monkeypatch):
    (tmp_path / "vendor").mkdir()
    assert parse_vendor_record(tmp_path).reason == "missing"
    real = tmp_path / "elsewhere.txt"
    real.write_text("# example.com/x v1.0.0\n")
    (tmp_path / "vendor" / "modules.txt").symlink_to(real)
    record = parse_vendor_record(tmp_path)
    assert (record.status, record.reason, record.record) == ("unavailable", "missing", None)
    (tmp_path / "vendor" / "modules.txt").unlink()
    _record(tmp_path, "")
    original = Path.open

    def failing_open(self, *args, **kwargs):
        if self.name == "modules.txt":
            raise PermissionError("denied")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)
    record = parse_vendor_record(tmp_path)
    assert (record.status, record.reason, record.record) == ("unavailable", "unreadable", None)


def test_record_line_module_and_package_bounds_at_limit_and_beyond(tmp_path, monkeypatch):
    text = "".join(f"# example.com/{name} v1.0.0\nexample.com/{name}\n" for name in ("a", "b", "c"))
    for name in ("a", "b", "c"):
        _package(tmp_path, f"example.com/{name}")
    path = _record(tmp_path, text)
    monkeypatch.setattr(go_vendored, "MAX_RECORD_BYTES", path.stat().st_size)
    assert len(parse_vendor_record(tmp_path).modules) == 3
    monkeypatch.setattr(go_vendored, "MAX_RECORD_BYTES", path.stat().st_size - 1)
    record = parse_vendor_record(tmp_path)
    assert (record.reason, record.record, record.modules) == ("bound-exceeded:record-bytes", None, ())
    monkeypatch.undo()
    longest = max(len(line) for line in text.encode().split(b"\n"))
    monkeypatch.setattr(go_vendored, "MAX_LINE_BYTES", longest)
    assert parse_vendor_record(tmp_path).available
    monkeypatch.setattr(go_vendored, "MAX_LINE_BYTES", longest - 1)
    assert parse_vendor_record(tmp_path).reason == "bound-exceeded:line-bytes:1"
    monkeypatch.undo()
    monkeypatch.setattr(go_vendored, "MAX_MODULES", 3)
    assert parse_vendor_record(tmp_path).available
    monkeypatch.setattr(go_vendored, "MAX_MODULES", 2)
    assert parse_vendor_record(tmp_path).reason == "bound-exceeded:modules"
    monkeypatch.undo()
    monkeypatch.setattr(go_vendored, "MAX_PACKAGES", 3)
    assert parse_vendor_record(tmp_path).available
    monkeypatch.setattr(go_vendored, "MAX_PACKAGES", 2)
    assert parse_vendor_record(tmp_path).reason == "bound-exceeded:packages"


def test_default_bounds_are_the_documented_values():
    assert (go_vendored.MAX_PREFIXES, go_vendored.MAX_RECORD_BYTES, go_vendored.MAX_LINE_BYTES,
            go_vendored.MAX_MODULES, go_vendored.MAX_PACKAGES, go_vendored.MAX_TREE_ENTRIES) == (
        32, 16 * 1024 * 1024, 4096, 20_000, 200_000, 500_000)


def test_verification_walk_bound_leaves_later_modules_unverified(tmp_path, monkeypatch):
    for name in ("a", "b"):
        _package(tmp_path, f"example.com/{name}", "one.go", "two.go")
    _record(tmp_path, "".join(f"# example.com/{name} v1.0.0\nexample.com/{name}\n" for name in ("a", "b")))
    # Each module costs four entries: two listing its package's sources, two walking its tree.
    monkeypatch.setattr(go_vendored, "MAX_TREE_ENTRIES", 8)
    assert [module.entry for module in parse_vendor_record(tmp_path).modules] == ["example.com/a", "example.com/b"]
    monkeypatch.setattr(go_vendored, "MAX_TREE_ENTRIES", 7)
    record = parse_vendor_record(tmp_path)
    assert [module.entry for module in record.modules] == ["example.com/a"]
    assert [(item.entry, item.reason) for item in record.unverified] == [
        ("example.com/b", "bound-exceeded:tree-entries")]


def test_prefix_discovery_needs_a_record_or_module_root_and_skips_vendor_trees(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/root\n")
    (tmp_path / "vendor" / "example.com" / "dep" / "vendor").mkdir(parents=True)
    (tmp_path / "vendor" / "example.com" / "dep" / "go.mod").write_text("module example.com/dep\n")
    (tmp_path / "svc" / "vendor").mkdir(parents=True)
    (tmp_path / "svc" / "vendor" / "modules.txt").write_text("")
    (tmp_path / "work" / "vendor").mkdir(parents=True)
    (tmp_path / "work" / "go.work").write_text("go 1.22\n")
    (tmp_path / "php" / "vendor" / "composer").mkdir(parents=True)
    (tmp_path / "linked").mkdir()
    (tmp_path / "linked" / "go.mod").write_text("module example.com/linked\n")
    (tmp_path / "linked" / "vendor").symlink_to(tmp_path / "svc" / "vendor")
    assert discover_prefixes(tmp_path) == ([".", "svc", "work"], [])
    assert discover_prefixes(tmp_path, 3) == ([".", "svc", "work"], [])
    assert discover_prefixes(tmp_path, 2) == ([".", "svc"], [DISCOVERY_BOUND_GAP])
    assert DISCOVERY_BOUND_GAP == ("Go installer record discovery bound reached; "
                                   "remaining prefixes cataloged per-file")


def test_default_prefix_bound_is_thirty_two(tmp_path):
    for ordinal in range(33):
        (tmp_path / f"p{ordinal:02d}" / "vendor").mkdir(parents=True)
        (tmp_path / f"p{ordinal:02d}" / "go.mod").write_text("module example.com/m\n")
    prefixes, gaps = discover_prefixes(tmp_path)
    assert len(prefixes) == 32 and gaps == [DISCOVERY_BOUND_GAP]
