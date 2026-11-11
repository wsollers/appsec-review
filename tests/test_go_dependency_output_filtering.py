"""Count regression for installer-record dependency filtering in the Go catalog; no go command."""
from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.config.build_outputs import BuildOutputDiscovery, BuildOutputPolicy
from appsec_review.jobs.build_output_scope import BuildOutputDispositions
from appsec_review.jobs.job_artifact_security_analysis import job as security
from appsec_review.jobs.job_artifact_security_analysis.scanners import scanner_input
from appsec_review.jobs.job_language_build import go
from appsec_review.jobs.job_language_build.job import _catalog
from appsec_review.jobs.job_tree_sitter_ast.generated_sources import _SOURCE_KINDS
from appsec_review.storage import file_sha256


SUMMARY = "dependency-content-summarized: "
RECORD = (
    "# example.com/alpha v1.2.3\n"
    "## explicit; go 1.21\n"
    "example.com/alpha\n"
    "example.com/alpha/sub\n"
    "# example.com/alpha/nested v0.1.0\n"
    "## go 1.17\n"
    "example.com/alpha/nested/pkg\n"
    "# example.com/gone v2.0.0+incompatible\n"
    "## explicit\n"
    "example.com/gone/pkg\n"
    "# example.com/local v1.0.0 => ./local\n"
    "example.com/local\n"
    "# golang.org/x/beta v0.0.0-20240101000000-abcdefabcdef => example.org/fork/beta v0.9.0\n"
    "## explicit\n"
    "golang.org/x/beta/unix\n"
    "# example.com/unused v1.0.0 => ../elsewhere\n"
)
VENDORED = {
    "vendor/example.com/alpha/a.go": b"package alpha\n",
    "vendor/example.com/alpha/b.go": b"package alpha\n\nfunc B() {}\n",
    "vendor/example.com/alpha/LICENSE": b"license text\n",
    "vendor/example.com/alpha/sub/helper.c": b"int helper(void) { return 1; }\n",
    "vendor/example.com/alpha/sub/s.go": b"package sub\n",
    "vendor/example.com/alpha/nested/pkg/n.go": b"package pkg\n",
    "vendor/golang.org/x/beta/unix/libnative.so": b"prebuilt library bytes, not an ELF file",
    "vendor/golang.org/x/beta/unix/u.go": b"package unix\n",
    "vendor/example.com/local/l.go": b"package local\n",
    "vendor/stray/x.go": b"package stray\n",
}
SOURCE = {"go.mod": b"module example.com/app\n\ngo 1.21\n", "main.go": b"package main\n\nfunc main() {}\n"}
GENERATED = {"gen/zz_generated.go": b"package gen\n"}


def _write(workspace: Path, files: dict[str, bytes]) -> None:
    for relative, data in files.items():
        path = workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _workspace(tmp_path: Path, record: str | bytes | None = RECORD) -> tuple[Path, dict[str, str]]:
    """A module whose build ran ``go mod vendor`` and ``go generate`` after the snapshot."""
    workspace = tmp_path / "workspace"
    _write(workspace, SOURCE)
    before = {relative: file_sha256(workspace / relative) for relative in SOURCE}
    _write(workspace, {**VENDORED, **GENERATED})
    if record is not None:
        _write(workspace, {"vendor/modules.txt": record if isinstance(record, bytes) else record.encode()})
    return workspace, before


def _catalog_go(tmp_path: Path, workspace: Path, before: dict[str, str], **options):
    return _catalog(tmp_path, workspace, before, 10_000, "go-unit", "go", **options)


def _per_file(rows: list[dict]) -> dict[str, str]:
    return {row["workspace_path"]: row["kind"] for row in rows if "package_metadata" not in row
            and "dependency_metadata" not in row}


BASELINE = {**{relative: "generated-source" for relative in (*VENDORED, *GENERATED)
               if relative.endswith((".go", ".c"))},
            "vendor/golang.org/x/beta/unix/libnative.so": "shared-library"}


def test_vendor_record_bounds_target_rows_with_exact_counts_and_gaps(tmp_path: Path) -> None:
    workspace, before = _workspace(tmp_path)

    rows, gaps = _catalog_go(tmp_path, workspace, before)

    record_sha = file_sha256(workspace / "vendor/modules.txt")
    by_path = {row["workspace_path"]: row for row in rows}
    modules = [row for row in rows
               if row.get("package_metadata", {}).get("role") == "installed-dependency-package"]
    assert sorted(row["workspace_path"] for row in modules) == [
        "vendor/example.com/alpha/a.go", "vendor/example.com/alpha/nested/pkg/n.go",
        "vendor/golang.org/x/beta/unix/u.go"]
    assert all((row["kind"], row["scope_role"], row["analysis_lane"], row["delivery_status"],
                row["artifact_origin"]) == ("package-metadata", "runtime_dependency", "supply_chain",
                                            "not_established", "build-output") for row in modules)
    alpha = by_path["vendor/example.com/alpha/a.go"]
    assert alpha["sha256"] == file_sha256(workspace / "vendor/example.com/alpha/a.go")
    assert alpha["build_output_root"] == "vendor/example.com/alpha"
    assert alpha["delivery_evidence"] == {
        "kind": "go-vendor-modules-record", "workspace_path": "vendor/modules.txt",
        "sha256": record_sha, "entry": "example.com/alpha"}
    # The nested module's file is counted by its own entry, not by its parent.
    assert alpha["package_metadata"] == {
        "format": "go-source-file", "role": "installed-dependency-package", "ecosystem": "go",
        "manager": "go", "name": "example.com/alpha", "version": "v1.2.3", "replacement": None,
        "explicit": True, "go_version": "1.21", "packages": 2,
        "install_path": "vendor/example.com/alpha", "files": 5,
        "bytes": sum(len(data) for relative, data in VENDORED.items()
                     if relative.startswith("vendor/example.com/alpha/") and "/nested/" not in relative),
        "retained_files": 0}
    nested = by_path["vendor/example.com/alpha/nested/pkg/n.go"]["package_metadata"]
    assert (nested["name"], nested["version"], nested["explicit"], nested["go_version"], nested["files"]) == (
        "example.com/alpha/nested", "v0.1.0", False, "1.17", 1)
    beta = by_path["vendor/golang.org/x/beta/unix/u.go"]["package_metadata"]
    assert beta["replacement"] == {"path": "example.org/fork/beta", "version": "v0.9.0"}
    assert (beta["version"], beta["files"], beta["retained_files"]) == (
        "v0.0.0-20240101000000-abcdefabcdef", 2, 1)

    [record_row] = [row for row in rows
                    if row.get("dependency_metadata", {}).get("role") == "installed-dependency-record"]
    assert (record_row["workspace_path"], record_row["kind"], record_row["sha256"]) == (
        "vendor/modules.txt", "resolved-dependency-metadata", record_sha)
    assert record_row["dependency_metadata"] == {
        "format": "modules.txt", "manager": "go", "role": "installed-dependency-record"}
    assert (record_row["scope_role"], record_row["analysis_lane"]) == ("build_chain", "supply_chain")

    library = by_path["vendor/golang.org/x/beta/unix/libnative.so"]
    assert (library["kind"], library["scope_role"], library["analysis_lane"]) == (
        "shared-library", "runtime_dependency", "supply_chain")
    assert library["delivery_evidence"]["entry"] == "golang.org/x/beta"

    target = sorted(row["workspace_path"] for row in rows if row["analysis_lane"] == "target")
    assert target == ["gen/zz_generated.go", "vendor/example.com/local/l.go", "vendor/stray/x.go"]
    assert len(rows) == 8

    summarized = sum(len(data) for relative, data in VENDORED.items() if relative.startswith(
        ("vendor/example.com/alpha/", "vendor/golang.org/")) and not relative.endswith(".so"))
    assert [gap for gap in gaps if gap.startswith(SUMMARY)] == [
        f"{SUMMARY}3 modules (7 files, {summarized} bytes) recorded by vendor/modules.txt routed to "
        "supply_chain review; per-file target review not performed; 2 files under vendor not covered "
        "by the installer record remain per-file"]
    assert [gap for gap in gaps if "Go installer record" in gap] == [
        "vendor/example.com/gone: vendored module is not verified against the Go installer record "
        "(install-path-missing); cataloged per-file",
        "vendor/example.com/local: vendored module is not verified against the Go installer record "
        "(local-replacement); cataloged per-file"]
    assert sorted(gap.split(": ", 1)[0] for gap in gaps if "delivery_fact_unavailable" in gap) == target
    [loader] = [gap for gap in gaps if "loader dependencies were not parseable" in gap]
    assert loader.startswith("vendor/golang.org/x/beta/unix/libnative.so: ")
    assert len(gaps) == 1 + 2 + len(target) + 1


def test_no_vendor_tree_keeps_the_per_file_catalog_without_installer_gaps(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, SOURCE)
    before = {relative: file_sha256(workspace / relative) for relative in SOURCE}
    _write(workspace, GENERATED)

    rows, gaps = _catalog_go(tmp_path, workspace, before)

    assert _per_file(rows) == {"gen/zz_generated.go": "generated-source"} and len(rows) == 1
    assert gaps == ["gen/zz_generated.go: delivery status is unknown (delivery_fact_unavailable)"]


def test_removed_record_restores_per_file_catalog_with_one_named_gap(tmp_path: Path) -> None:
    workspace, before = _workspace(tmp_path, record=None)

    rows, gaps = _catalog_go(tmp_path, workspace, before)

    assert _per_file(rows) == BASELINE and len(rows) == len(BASELINE)
    assert all(row["analysis_lane"] == "target" and "delivery_evidence" not in row for row in rows)
    assert [gap for gap in gaps if "installer record" in gap] == [
        "vendor: Go installer record unavailable (missing); dependency files cataloged per-file "
        "in the target lane"]
    assert not any(gap.startswith(SUMMARY) for gap in gaps)


@pytest.mark.parametrize("record,reason", [
    (RECORD + "not an import path!\n", "line-invalid:17"),
    (RECORD.replace("## go 1.17", "## go 1.17; vendored"), "line-invalid:6"),
    (RECORD.encode() + b"\xff\n", "invalid-encoding:17"),
], ids=["garbage-line", "unknown-annotation", "undecodable"])
def test_malformed_record_is_a_named_gap_and_everything_stays_per_file(tmp_path: Path, record, reason) -> None:
    workspace, before = _workspace(tmp_path, record=record)

    rows, gaps = _catalog_go(tmp_path, workspace, before)

    assert _per_file(rows) == BASELINE
    [record_row] = [row for row in rows if "dependency_metadata" in row]
    assert (record_row["workspace_path"], record_row["analysis_lane"]) == ("vendor/modules.txt", "supply_chain")
    assert not any("package_metadata" in row for row in rows)
    assert [gap for gap in gaps if "installer record" in gap] == [
        f"vendor: Go installer record unavailable ({reason}); dependency files cataloged per-file "
        "in the target lane"]
    assert not any(gap.startswith(SUMMARY) for gap in gaps)


def test_oversized_record_is_a_named_gap_at_one_byte_past_its_bound(tmp_path: Path, monkeypatch) -> None:
    workspace, before = _workspace(tmp_path)
    monkeypatch.setattr(go.go_vendored, "MAX_RECORD_BYTES", len(RECORD.encode()))
    rows, gaps = _catalog_go(tmp_path, workspace, before)
    assert sum("package_metadata" in row for row in rows) == 3
    assert len([gap for gap in gaps if gap.startswith(SUMMARY)]) == 1

    monkeypatch.setattr(go.go_vendored, "MAX_RECORD_BYTES", len(RECORD.encode()) - 1)
    rows, gaps = _catalog_go(tmp_path, workspace, before)
    assert _per_file(rows) == BASELINE and len(rows) == len(BASELINE)
    assert [gap for gap in gaps if "installer record" in gap] == [
        "vendor: Go installer record unavailable (bound-exceeded:record-bytes); dependency files "
        "cataloged per-file in the target lane"]


def test_empty_record_covers_nothing_and_names_the_files_left_per_file(tmp_path: Path) -> None:
    workspace, before = _workspace(tmp_path, record="")

    rows, gaps = _catalog_go(tmp_path, workspace, before)

    assert _per_file(rows) == BASELINE
    assert [row["workspace_path"] for row in rows if "dependency_metadata" in row] == ["vendor/modules.txt"]
    assert [gap for gap in gaps if "installer record" in gap] == [
        "vendor: Go installer record covers no vendored module; 10 files under vendor remain per-file"]
    assert not any(gap.startswith(SUMMARY) for gap in gaps)


def test_committed_vendor_tree_is_target_content_and_is_not_summarized(tmp_path: Path) -> None:
    workspace, _ = _workspace(tmp_path)
    committed = {path.relative_to(workspace).as_posix(): file_sha256(path)
                 for path in workspace.rglob("*") if path.is_file()}
    _write(workspace, {"vendor/example.com/alpha/a.go": b"package alpha // regenerated\n"})

    rows, gaps = _catalog_go(tmp_path, workspace, committed)

    # Exactly the generic behaviour: unchanged files give no rows; the changed one is per-file.
    assert {row["workspace_path"]: (row["kind"], row["analysis_lane"]) for row in rows} == {
        "vendor/example.com/alpha/a.go": ("generated-source", "target"),
        "vendor/golang.org/x/beta/unix/libnative.so": ("shared-library", "target")}
    assert not any("installer record" in gap or gap.startswith(SUMMARY) for gap in gaps)

    # A vendor directory with no record that the build did not write into is not a gap either.
    (workspace / "vendor/modules.txt").unlink()
    committed.pop("vendor/modules.txt")
    rows, gaps = _catalog_go(tmp_path, workspace, committed)
    assert not any("installer record" in gap for gap in gaps)


def test_dispositions_record_verified_trees_and_nested_unverified_carve_out(tmp_path: Path) -> None:
    workspace, before = _workspace(tmp_path, record=(
        "# example.com/alpha v1.2.3\nexample.com/alpha\nexample.com/alpha/sub\n"
        "# example.com/alpha/nested v0.1.0\nexample.com/alpha/nested/missing\n"))
    dispositions = BuildOutputDispositions(family="go")

    rows, gaps = _catalog_go(tmp_path, workspace, before, dispositions=dispositions)

    roots = {root["root"]: root for root in dispositions.document()["roots"]}
    assert set(roots) == {"vendor/example.com/alpha", "vendor/example.com/alpha/nested"}
    verified = roots["vendor/example.com/alpha"]
    assert {key: verified[key] for key in (
        "disposition", "basis", "confidence", "name", "reason", "evidence_ref", "scope_role",
        "files", "kept", "bound_group")} == {
        "disposition": "supply_chain", "basis": "installer-record", "confidence": "fact",
        "name": "go-vendored-module", "reason": "verified against vendored packages",
        "evidence_ref": "vendor/modules.txt#example.com/alpha", "scope_role": "runtime_dependency",
        "files": 5, "bound_group": "vendor", "kept": ["vendor/example.com/alpha/a.go"]}
    carve_out = roots["vendor/example.com/alpha/nested"]
    assert (carve_out["disposition"], carve_out["name"], carve_out["reason"]) == (
        "per_file", "go-unverified-module", "package-missing:example.com/alpha/nested/missing")
    by_path = {row["workspace_path"]: row for row in rows}
    assert by_path["vendor/example.com/alpha/nested/pkg/n.go"]["analysis_lane"] == "target"
    assert "vendor/example.com/alpha/b.go" not in by_path
    assert ("vendor/example.com/alpha/nested: vendored module is not verified against the Go installer "
            "record (package-missing:example.com/alpha/nested/missing); cataloged per-file") in gaps
    assert not any(gap.startswith("build-output-") for gap in gaps)


def test_root_bound_counts_vendor_trees_and_leaves_a_refused_tree_per_file(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    for prefix in ("", "svc/"):
        _write(workspace, {f"{prefix}go.mod": b"module example.com/m\n",
                           f"{prefix}vendor/example.com/a/a.go": b"package a\n",
                           f"{prefix}vendor/example.com/b/b.go": b"package b\n",
                           f"{prefix}vendor/modules.txt": (b"# example.com/a v1.0.0\nexample.com/a\n"
                                                           b"# example.com/b v1.0.0\nexample.com/b\n")})
    policy = BuildOutputPolicy(discovery=BuildOutputDiscovery(max_layout_roots=1))
    dispositions = BuildOutputDispositions(policy, family="go")

    rows, gaps = _catalog_go(tmp_path, workspace, {}, dispositions=dispositions)

    # Install paths register in sorted order, so `svc/vendor` takes the only slot.
    assert {root["root"]: root.get("bound_group") for root in dispositions.document()["roots"]} == {
        "svc/vendor/example.com/a": "svc/vendor", "svc/vendor/example.com/b": "svc/vendor"}
    by_path = {row["workspace_path"]: row for row in rows}
    assert by_path["svc/vendor/example.com/a/a.go"]["scope_role"] == "runtime_dependency"
    assert (by_path["vendor/example.com/a/a.go"]["kind"],
            by_path["vendor/example.com/a/a.go"]["analysis_lane"]) == ("generated-source", "target")
    assert [gap for gap in gaps if gap.startswith(SUMMARY)] == [
        f"{SUMMARY}2 modules (2 files, 20 bytes) recorded by svc/vendor/modules.txt routed to supply_chain "
        "review; per-file target review not performed"]
    assert ("build-output-root-bound-exceeded: 2 roots beyond max_layout_roots stay per-file target "
            "content") in gaps


def test_anchor_changed_after_verification_fails_the_catalog(tmp_path: Path, monkeypatch) -> None:
    workspace, before = _workspace(tmp_path)
    original = BuildOutputDispositions.walk

    def rewriting_walk(self, root):
        (root / "vendor/example.com/alpha/a.go").write_bytes(b"package alpha // swapped\n")
        return original(self, root)

    monkeypatch.setattr(BuildOutputDispositions, "walk", rewriting_walk)
    with pytest.raises(ValueError, match="vendored Go module anchor changed during cataloging"):
        _catalog_go(tmp_path, workspace, before)


def test_module_rows_are_not_source_and_do_not_enter_the_npm_record_scan(tmp_path: Path) -> None:
    workspace, before = _workspace(tmp_path)

    rows, _ = _catalog_go(tmp_path, workspace, before)

    anchors = [row for row in rows if "package_metadata" in row]
    [record_row] = [row for row in rows if "dependency_metadata" in row]
    assert len(anchors) == 3 and all(row["kind"] not in _SOURCE_KINDS for row in (*anchors, record_row))
    assert all(row["scope_role"] not in {"deliverable", "shipped_dependency"} for row in anchors)
    # The npm scan-once presentation is keyed on npm's own record and evidence kind.
    assert scanner_input(record_row) is None
    assert all(security._anchor_key(row) is None for row in anchors)
    assert go.CAPTURE_IDENTITY == "appsec-review/go-build-capture/4"
