"""Count regression for installer-record dependency filtering in the PHP catalog; no composer."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.config.build_outputs import BuildOutputDiscovery, BuildOutputPolicy
from appsec_review.jobs.build_output_scope import BuildOutputDispositions
from appsec_review.jobs.delivery_scope import analysis_scope
from appsec_review.jobs.job_artifact_security_analysis import job as security
from appsec_review.jobs.job_artifact_security_analysis.scanners import scanner_input
from appsec_review.jobs.job_language_build import php
from appsec_review.jobs.job_tree_sitter_ast.generated_sources import _SOURCE_KINDS
from appsec_review.storage import file_sha256


SUMMARY = "dependency-content-summarized: "
RECORD_PATH = "vendor/composer/installed.json"
PACKAGES = [
    {"name": "acme/runtime", "version": "1.2.3", "version_normalized": "1.2.3.0", "type": "library",
     "install-path": "../acme/runtime",
     "dist": {"type": "zip", "url": "https://example.invalid/runtime.zip", "reference": "abc123", "shasum": ""},
     "source": {"type": "git", "url": "https://example.invalid/runtime.git", "reference": "abc123"}},
    {"name": "acme/devtool", "version": "v2.0.0", "install-path": "../acme/devtool"},
    {"name": "composer/semver", "version": "3.4.0", "install-path": "./semver"},
    {"name": "acme/gone", "version": "1.0.0", "install-path": "../acme/gone"},
    {"name": "acme/local", "version": "dev-main", "install-path": "../acme/local",
     "dist": {"type": "path", "url": "../local", "reference": "0000"}},
    {"name": "acme/meta", "version": "1.0.0", "type": "metapackage", "install-path": None},
]
COMPOSER_2 = {"packages": PACKAGES, "dev": True, "dev-package-names": ["acme/devtool"]}
# Composer 1 wrote a bare list with no install paths and no dev marking.
COMPOSER_1 = [{key: value for key, value in package.items() if key != "install-path"} for package in PACKAGES]
VENDORED = {
    "vendor/autoload.php": b"<?php require __DIR__ . '/composer/autoload_real.php';\n",
    "vendor/composer/autoload_real.php": b"<?php // loader\n",
    "vendor/composer/ClassLoader.php": b"<?php namespace Composer\\Autoload;\n",
    "vendor/composer/installed.php": b"<?php return [];\n",
    "vendor/bin/devtool": b"#!/usr/bin/env php\n",
    "vendor/acme/runtime/composer.json": b'{"name": "acme/runtime"}',
    "vendor/acme/runtime/LICENSE": b"license text\n",
    "vendor/acme/runtime/src/Runtime.php": b"<?php final class Runtime {}\n",
    "vendor/acme/runtime/ext/libnative.so": b"prebuilt library bytes, not an ELF file",
    "vendor/acme/devtool/composer.json": b'{"name": "acme/devtool"}',
    "vendor/acme/devtool/src/Tool.php": b"<?php final class Tool {}\n",
    "vendor/composer/semver/composer.json": b'{"name": "composer/semver"}',
    "vendor/composer/semver/src/Semver.php": b"<?php final class Semver {}\n",
    "vendor/acme/local/composer.json": b'{"name": "acme/local"}',
    "vendor/acme/local/src/Local.php": b"<?php final class Local {}\n",
    "vendor/stray/x.php": b"<?php // stray\n",
}
SOURCE = {"composer.json": b'{"name": "fixture/app"}', "src/App.php": b"<?php final class App {}\n"}
GENERATED = {"generated/Proxy.php": b"<?php final class Proxy {}\n"}
ANCHORS = ["vendor/acme/devtool/composer.json", "vendor/acme/runtime/composer.json",
           "vendor/composer/semver/composer.json"]


def _write(workspace: Path, files: dict[str, bytes]) -> None:
    for relative, data in files.items():
        path = workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _workspace(tmp_path: Path, record=COMPOSER_2) -> tuple[Path, dict[str, str]]:
    """A project whose build ran ``composer install`` and a generator after the snapshot."""
    workspace = tmp_path / "workspace"
    _write(workspace, SOURCE)
    before = {relative: file_sha256(workspace / relative) for relative in SOURCE}
    _write(workspace, {**VENDORED, **GENERATED})
    if record is not None:
        _write(workspace, {RECORD_PATH: record if isinstance(record, bytes) else json.dumps(record).encode()})
    return workspace, before


def _catalog(tmp_path: Path, workspace: Path, before: dict[str, str], **options):
    return php.catalog(tmp_path, workspace, before, 10_000, "php-unit", **options)


def _per_file(rows: list[dict]) -> dict[str, str]:
    return {row["workspace_path"]: row["kind"] for row in rows if "package_metadata" not in row
            and "dependency_metadata" not in row}


def _kind(relative: str) -> str | None:
    if relative.endswith(("composer.json", "installed.php")):
        return "package-metadata"
    if relative in {"vendor/autoload.php", "vendor/composer/autoload_real.php"}:
        return "generated-autoload"
    return {".php": "generated-source", ".so": "native-extension"}.get(Path(relative).suffix)


# What the catalog lists when no record covers anything: one row per recognized file.
BASELINE = {relative: _kind(relative) for relative in (*SOURCE, *VENDORED, *GENERATED)
            if _kind(relative) is not None and relative != "src/App.php"}
TARGET = ["generated/Proxy.php", "vendor/acme/local/src/Local.php", "vendor/autoload.php",
          "vendor/composer/ClassLoader.php", "vendor/composer/autoload_real.php", "vendor/stray/x.php"]


def test_installed_record_bounds_target_rows_with_exact_counts_and_gaps(tmp_path: Path) -> None:
    workspace, before = _workspace(tmp_path)

    rows, gaps = _catalog(tmp_path, workspace, before)

    record_sha = file_sha256(workspace / RECORD_PATH)
    by_path = {row["workspace_path"]: row for row in rows}
    packages = [row for row in rows
                if row.get("package_metadata", {}).get("role") == "installed-dependency-package"]
    assert sorted(row["workspace_path"] for row in packages) == ANCHORS
    assert all((row["kind"], row["analysis_lane"], row["delivery_status"], row["artifact_origin"]) == (
        "package-metadata", "supply_chain", "not_established", "build-output") for row in packages)
    # Composer 2's dev-package-names decides the role.
    assert {row["workspace_path"]: row["scope_role"] for row in packages} == dict(zip(
        ANCHORS, ("build_dependency", "runtime_dependency", "runtime_dependency")))
    runtime = by_path["vendor/acme/runtime/composer.json"]
    assert runtime["sha256"] == file_sha256(workspace / "vendor/acme/runtime/composer.json")
    assert runtime["build_output_root"] == "vendor/acme/runtime"
    assert runtime["delivery_evidence"] == {
        "kind": "composer-installed-record", "workspace_path": RECORD_PATH,
        "sha256": record_sha, "entry": "acme/runtime"}
    assert runtime["package_metadata"] == {
        "format": "composer.json", "role": "installed-dependency-package", "ecosystem": "composer",
        "manager": "composer", "name": "acme/runtime", "version": "1.2.3",
        "version_normalized": "1.2.3.0", "package_type": "library", "dev": False,
        "dist": {"type": "zip", "reference": "abc123", "shasum": ""},
        "source": {"type": "git", "reference": "abc123"}, "install_path": "vendor/acme/runtime",
        "files": 4,
        "bytes": sum(len(data) for relative, data in VENDORED.items()
                     if relative.startswith("vendor/acme/runtime/")),
        "retained_files": 1}
    devtool = by_path["vendor/acme/devtool/composer.json"]["package_metadata"]
    assert (devtool["version"], devtool["dev"], devtool["dist"], devtool["files"], devtool["retained_files"]) == (
        "v2.0.0", True, None, 2, 0)
    assert by_path["vendor/composer/semver/composer.json"]["package_metadata"]["install_path"] == (
        "vendor/composer/semver")

    [record_row] = [row for row in rows
                    if row.get("dependency_metadata", {}).get("role") == "installed-dependency-record"]
    assert (record_row["workspace_path"], record_row["kind"], record_row["sha256"]) == (
        RECORD_PATH, "resolved-dependency-metadata", record_sha)
    assert record_row["dependency_metadata"] == {
        "format": "installed.json", "manager": "composer", "role": "installed-dependency-record"}
    assert (record_row["scope_role"], record_row["analysis_lane"]) == ("build_chain", "supply_chain")

    library = by_path["vendor/acme/runtime/ext/libnative.so"]
    assert (library["kind"], library["scope_role"], library["analysis_lane"]) == (
        "native-extension", "runtime_dependency", "supply_chain")
    assert library["delivery_evidence"]["entry"] == "acme/runtime"
    assert analysis_scope(library, "blint")[0]

    assert sorted(row["workspace_path"] for row in rows if row["analysis_lane"] == "target") == TARGET
    # The unverified package's manifest, the root manifest and Composer's PHP record stay per-file.
    assert sorted(path for path, kind in _per_file(rows).items() if kind == "package-metadata") == [
        "composer.json", "vendor/acme/local/composer.json", "vendor/composer/installed.php"]
    assert len(rows) == 3 + 1 + 1 + len(TARGET) + 3

    summarized = sum(len(data) for relative, data in VENDORED.items() if relative.startswith(
        ("vendor/acme/runtime/", "vendor/acme/devtool/", "vendor/composer/semver/"))
        and not relative.endswith(".so"))
    # Composer's own loader and bookkeeping files are not counted as uncovered dependency files.
    assert [gap for gap in gaps if gap.startswith(SUMMARY)] == [
        f"{SUMMARY}3 packages (7 files, {summarized} bytes) recorded by {RECORD_PATH} routed to "
        "supply_chain review; per-file target review not performed; 4 files under vendor not covered "
        "by the installer record remain per-file"]
    assert [gap for gap in gaps if "Composer installer record" in gap] == [
        "vendor/acme/gone: installed package is not verified against the Composer installer record "
        "(install-path-missing); cataloged per-file",
        "vendor/acme/local: installed package is not verified against the Composer installer record "
        "(path-repository); cataloged per-file"]
    assert sorted(gap.split(": ", 1)[0] for gap in gaps if "delivery_fact_unavailable" in gap) == TARGET
    assert len(gaps) == 1 + 2 + len(TARGET)


def test_composer_1_list_record_summarizes_every_verified_package_as_runtime(tmp_path: Path) -> None:
    workspace, before = _workspace(tmp_path, record=COMPOSER_1)

    rows, gaps = _catalog(tmp_path, workspace, before)

    packages = {row["workspace_path"]: row for row in rows if "package_metadata" in row}
    assert sorted(packages) == ANCHORS
    # The Composer 1 layout records no dev marking, so nothing is a build_dependency.
    assert {row["scope_role"] for row in packages.values()} == {"runtime_dependency"}
    assert not any(row["package_metadata"]["dev"] for row in packages.values())
    assert sorted(row["workspace_path"] for row in rows if row["analysis_lane"] == "target") == TARGET
    assert len([gap for gap in gaps if gap.startswith(f"{SUMMARY}3 packages (7 files, ")]) == 1
    assert len([gap for gap in gaps if "is not verified against the Composer installer record" in gap]) == 2


def test_no_vendor_tree_keeps_the_per_file_catalog_without_installer_gaps(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, SOURCE)
    before = {relative: file_sha256(workspace / relative) for relative in SOURCE}
    _write(workspace, GENERATED)

    rows, gaps = _catalog(tmp_path, workspace, before)

    assert _per_file(rows) == {"composer.json": "package-metadata", "generated/Proxy.php": "generated-source"}
    assert len(rows) == 2
    assert gaps == ["Composer autoload generation produced no retained autoload artifact",
                    "generated/Proxy.php: delivery status is unknown (delivery_fact_unavailable)"]


def test_removed_record_restores_per_file_catalog_with_one_named_gap(tmp_path: Path) -> None:
    workspace, before = _workspace(tmp_path, record=None)

    rows, gaps = _catalog(tmp_path, workspace, before)

    assert _per_file(rows) == BASELINE and len(rows) == len(BASELINE)
    assert not any("delivery_evidence" in row for row in rows)
    assert not any(row["scope_role"] in {"runtime_dependency", "build_dependency"} for row in rows)
    assert [gap for gap in gaps if "installer record" in gap] == [
        "vendor: Composer installer record unavailable (missing); dependency files cataloged per-file "
        "in the target lane"]
    assert not any(gap.startswith(SUMMARY) for gap in gaps)


@pytest.mark.parametrize("record,reason", [
    (b"{not json", "invalid-json"),
    ({"installed": PACKAGES}, "unsupported-structure"),
    ({**COMPOSER_2, "dev-package-names": "acme/devtool"}, "dev-package-names-invalid"),
    ({"packages": [*PACKAGES, {"name": "acme/escape", "version": "1.0.0",
                               "install-path": "../../../outside"}]}, "entry-invalid:acme/escape"),
    ([*COMPOSER_1, {"name": "acme/runtime", "version": "9.9.9"}], "duplicate-package:acme/runtime"),
], ids=["not-json", "unknown-shape", "dev-names-not-a-list", "path-traversal", "duplicate-package"])
def test_malformed_record_is_a_named_gap_and_everything_stays_per_file(tmp_path: Path, record, reason) -> None:
    workspace, before = _workspace(tmp_path, record=record)

    rows, gaps = _catalog(tmp_path, workspace, before)

    assert _per_file(rows) == BASELINE
    [record_row] = [row for row in rows if "dependency_metadata" in row]
    assert (record_row["workspace_path"], record_row["analysis_lane"]) == (RECORD_PATH, "supply_chain")
    assert not any("package_metadata" in row for row in rows)
    assert [gap for gap in gaps if "installer record" in gap] == [
        f"vendor: Composer installer record unavailable ({reason}); dependency files cataloged per-file "
        "in the target lane"]
    assert not any(gap.startswith(SUMMARY) for gap in gaps)


def test_oversized_record_is_a_named_gap_at_one_byte_past_its_bound(tmp_path: Path, monkeypatch) -> None:
    workspace, before = _workspace(tmp_path)
    size = (workspace / RECORD_PATH).stat().st_size
    monkeypatch.setattr(php.php_installed, "MAX_RECORD_BYTES", size)
    rows, gaps = _catalog(tmp_path, workspace, before)
    assert sum("package_metadata" in row for row in rows) == 3
    assert len([gap for gap in gaps if gap.startswith(SUMMARY)]) == 1

    monkeypatch.setattr(php.php_installed, "MAX_RECORD_BYTES", size - 1)
    rows, gaps = _catalog(tmp_path, workspace, before)
    # An unread record has no identity, so its row keeps the kind its name gives it.
    assert _per_file(rows) == {**BASELINE, RECORD_PATH: "package-metadata"}
    assert [gap for gap in gaps if "installer record" in gap] == [
        "vendor: Composer installer record unavailable (bound-exceeded:record-bytes); dependency files "
        "cataloged per-file in the target lane"]


@pytest.mark.parametrize("record", [[], {"packages": [], "dev": True, "dev-package-names": []}],
                         ids=["composer-1", "composer-2"])
def test_empty_record_covers_nothing_and_names_the_files_left_per_file(tmp_path: Path, record) -> None:
    workspace, before = _workspace(tmp_path, record=record)

    rows, gaps = _catalog(tmp_path, workspace, before)

    assert _per_file(rows) == BASELINE
    assert [row["workspace_path"] for row in rows if "dependency_metadata" in row] == [RECORD_PATH]
    uncovered = sum(1 for relative in VENDORED if not php.php_installed.installer_owned(".", relative))
    assert uncovered == 12
    assert [gap for gap in gaps if "installer record" in gap] == [
        f"vendor: Composer installer record covers no installed package; {uncovered} files under vendor "
        "remain per-file"]
    assert not any(gap.startswith(SUMMARY) for gap in gaps)


def test_record_with_only_the_loader_beside_it_is_not_a_gap(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, SOURCE)
    before = {relative: file_sha256(workspace / relative) for relative in SOURCE}
    _write(workspace, {"vendor/autoload.php": b"<?php\n", "vendor/composer/autoload_real.php": b"<?php\n",
                       RECORD_PATH: b"[]"})

    rows, gaps = _catalog(tmp_path, workspace, before)

    assert [row["workspace_path"] for row in rows if "dependency_metadata" in row] == [RECORD_PATH]
    assert not any("installer record" in gap or gap.startswith(SUMMARY) for gap in gaps)


def test_committed_vendor_tree_is_target_content_and_is_not_summarized(tmp_path: Path) -> None:
    workspace, _ = _workspace(tmp_path)
    committed = {path.relative_to(workspace).as_posix(): file_sha256(path)
                 for path in workspace.rglob("*") if path.is_file()}
    _write(workspace, {"vendor/acme/runtime/src/Runtime.php": b"<?php final class Runtime { /* patched */ }\n"})

    rows, gaps = _catalog(tmp_path, workspace, committed)

    # Exactly the per-file behaviour: metadata and binaries are listed, with one changed source.
    assert _per_file(rows) == {
        **{relative: kind for relative, kind in BASELINE.items()
           if kind in {"package-metadata", "native-extension"}},
        RECORD_PATH: "package-metadata", "vendor/acme/runtime/src/Runtime.php": "generated-source"}
    assert len(rows) == len(_per_file(rows))
    assert not any("delivery_evidence" in row for row in rows)
    assert not any("installer record" in gap or gap.startswith(SUMMARY) for gap in gaps)

    # A vendor directory with no record that the build did not write into is not a gap either.
    (workspace / RECORD_PATH).unlink()
    committed.pop(RECORD_PATH)
    rows, gaps = _catalog(tmp_path, workspace, committed)
    assert not any("installer record" in gap for gap in gaps)


def test_dispositions_record_verified_trees_and_nested_unverified_carve_out(tmp_path: Path) -> None:
    workspace, before = _workspace(tmp_path, record={"packages": [
        PACKAGES[0], {"name": "acme/nested", "version": "0.1.0", "install-path": "../acme/runtime/nested"}]})
    _write(workspace, {"vendor/acme/runtime/nested/n.php": b"<?php // nested\n"})
    dispositions = BuildOutputDispositions(family="php")

    rows, gaps = _catalog(tmp_path, workspace, before, dispositions=dispositions)

    roots = {root["root"]: root for root in dispositions.document()["roots"]}
    assert set(roots) == {"vendor/acme/runtime", "vendor/acme/runtime/nested"}
    verified = roots["vendor/acme/runtime"]
    assert {key: verified[key] for key in (
        "disposition", "basis", "confidence", "name", "reason", "evidence_ref", "scope_role",
        "files", "kept", "bound_group")} == {
        "disposition": "supply_chain", "basis": "installer-record", "confidence": "fact",
        "name": "composer-installed-package", "reason": "verified against installed manifest",
        "evidence_ref": f"{RECORD_PATH}#acme/runtime", "scope_role": "runtime_dependency",
        "files": 4, "bound_group": "vendor",
        "kept": ["vendor/acme/runtime/composer.json", "vendor/acme/runtime/ext/libnative.so"]}
    carve_out = roots["vendor/acme/runtime/nested"]
    assert (carve_out["disposition"], carve_out["name"], carve_out["reason"]) == (
        "per_file", "composer-unverified-package", "manifest-missing")
    by_path = {row["workspace_path"]: row for row in rows}
    assert by_path["vendor/acme/runtime/nested/n.php"]["analysis_lane"] == "target"
    assert "vendor/acme/runtime/src/Runtime.php" not in by_path
    assert ("vendor/acme/runtime/nested: installed package is not verified against the Composer installer "
            "record (manifest-missing); cataloged per-file") in gaps
    assert not any(gap.startswith("build-output-") for gap in gaps)


def test_root_bound_counts_vendor_trees_and_leaves_a_refused_tree_per_file(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    for prefix in ("", "svc/"):
        _write(workspace, {f"{prefix}vendor/acme/a/composer.json": b'{"name": "acme/a"}',
                           f"{prefix}vendor/acme/b/composer.json": b'{"name": "acme/b"}',
                           f"{prefix}{RECORD_PATH}": json.dumps([
                               {"name": "acme/a", "version": "1.0.0"},
                               {"name": "acme/b", "version": "1.0.0"}]).encode()})
    policy = BuildOutputPolicy(discovery=BuildOutputDiscovery(max_layout_roots=1))
    dispositions = BuildOutputDispositions(policy, family="php")

    rows, gaps = _catalog(tmp_path, workspace, {}, dispositions=dispositions)

    # Install paths register in sorted order, so `svc/vendor` takes the only slot.
    assert {root["root"]: root.get("bound_group") for root in dispositions.document()["roots"]} == {
        "svc/vendor/acme/a": "svc/vendor", "svc/vendor/acme/b": "svc/vendor"}
    by_path = {row["workspace_path"]: row for row in rows}
    assert by_path["svc/vendor/acme/a/composer.json"]["scope_role"] == "runtime_dependency"
    refused = by_path["vendor/acme/a/composer.json"]
    assert (refused["kind"], refused["scope_role"]) == ("package-metadata", "build_chain")
    assert "package_metadata" not in refused and "delivery_evidence" not in refused
    assert [gap for gap in gaps if gap.startswith(SUMMARY)] == [
        f"{SUMMARY}2 packages (2 files, 36 bytes) recorded by svc/{RECORD_PATH} routed to supply_chain "
        "review; per-file target review not performed"]
    assert ("build-output-root-bound-exceeded: 2 roots beyond max_layout_roots stay per-file target "
            "content") in gaps


def test_manifest_changed_after_verification_fails_the_catalog(tmp_path: Path, monkeypatch) -> None:
    workspace, before = _workspace(tmp_path)
    original = BuildOutputDispositions.walk

    def rewriting_walk(self, root):
        (root / "vendor/acme/runtime/composer.json").write_bytes(b'{"name": "acme/runtime", "swapped": 1}')
        return original(self, root)

    monkeypatch.setattr(BuildOutputDispositions, "walk", rewriting_walk)
    with pytest.raises(ValueError, match="installed Composer package manifest changed during cataloging"):
        _catalog(tmp_path, workspace, before)


def test_dev_package_binary_stays_out_of_blint(tmp_path: Path) -> None:
    workspace, before = _workspace(tmp_path)
    _write(workspace, {"vendor/acme/devtool/ext/libdev.so": b"prebuilt dev library, not an ELF file"})

    rows, _ = _catalog(tmp_path, workspace, before)

    [library] = [row for row in rows if row["workspace_path"] == "vendor/acme/devtool/ext/libdev.so"]
    assert (library["kind"], library["scope_role"], library["analysis_lane"]) == (
        "native-extension", "build_dependency", "supply_chain")
    assert not analysis_scope(library, "blint")[0]


def test_package_rows_are_not_source_and_do_not_enter_the_npm_record_scan(tmp_path: Path) -> None:
    workspace, before = _workspace(tmp_path)

    rows, _ = _catalog(tmp_path, workspace, before)

    anchors = [row for row in rows if "package_metadata" in row]
    [record_row] = [row for row in rows if "dependency_metadata" in row]
    assert len(anchors) == 3 and all(row["kind"] not in _SOURCE_KINDS for row in (*anchors, record_row))
    assert all(row["scope_role"] not in {"deliverable", "shipped_dependency"} for row in anchors)
    # The npm scan-once presentation is keyed on npm's own record and evidence kind.
    assert scanner_input(record_row) is None
    assert all(security._anchor_key(row) is None for row in anchors)
    assert php.CAPTURE_IDENTITY == "appsec-review/php-composer-build-capture/3"


def test_lock_metadata_marks_production_packages_runtime_dependencies(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, {"composer.json": b'{"name": "fixture/app"}', "composer.lock": json.dumps({
        "packages": [{"name": "fixture/runtime", "version": "1.0"}],
        "packages-dev": [{"name": "fixture/builder", "version": "1.0"}]}).encode()})

    metadata, gaps = php.composer_metadata(workspace, ".")

    assert [(row["name"], row["scope_role"], row["analysis_lane"], row["delivery_status"])
            for row in metadata["packages"]] == [
        ("fixture/runtime", "runtime_dependency", "supply_chain", "not_established"),
        ("fixture/builder", "build_dependency", "supply_chain", "not_established")]
    assert gaps == []
