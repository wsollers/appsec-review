"""Count regression for installer-record dependency filtering in the Node catalog."""
from __future__ import annotations

from collections import Counter
import io
import json
from pathlib import Path
import tarfile
import time
import tomllib

from appsec_review.config.build_outputs import BuildOutputDiscovery, BuildOutputPolicy, parse_build_outputs
from appsec_review.jobs.build_output_scope import BuildOutputDispositions
from appsec_review.jobs.job_language_build import node
from appsec_review.storage import file_sha256


REPOSITORY = Path(__file__).resolve().parents[1]
SUMMARY = "dependency-content-summarized: "
MISSING = ("node_modules: npm installer record unavailable (missing); "
           "dependency files cataloged per-file in the target lane")


def _write(path: Path, data: bytes) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return len(data)


def _package(workspace: Path, install_path: str, name: str, version: str, *, addon: bool = False) -> int:
    """Write 25 files: the manifest plus 24 others; return their total bytes."""
    root = workspace / install_path
    total = _write(root / "package.json", json.dumps({"name": name, "version": version}).encode())
    others = [f"lib/f{index:02d}.js" for index in range(23 if addon else 24)]
    for relative in others:
        total += _write(root / relative, f"module.exports = '{name}:{relative}';\n".encode())
    if addon:
        total += _write(root / "build/Release/addon.node", b"\x7fELF-native-addon")
    return total


def _workspace(tmp_path: Path) -> tuple[Path, dict[str, int]]:
    workspace = tmp_path / "workspace"
    _write(workspace / "package.json", json.dumps({
        "name": "fixture", "version": "1.0.0", "private": True, "workspaces": ["backend", "frontend"],
    }).encode())
    packages = [(f"node_modules/dev-{index:02d}", f"dev-{index:02d}", True) for index in range(29)]
    packages += [("node_modules/@scope/tool", "@scope/tool", True),
                 ("node_modules/a", "a", False), ("node_modules/a/node_modules/b", "b", False)]
    packages += [(f"node_modules/prod-{index:02d}", f"prod-{index:02d}", False) for index in range(6)]
    entries: dict[str, dict] = {}
    sizes: dict[str, int] = {}
    for key, name, dev in packages:
        entries[key] = {"version": "1.0.0", "resolved": f"https://registry.npmjs.org/{name}/-/{name}.tgz",
                        "integrity": "sha512-fixture", **({"dev": True} if dev else {})}
        sizes[key] = _package(workspace, key, name, "1.0.0", addon=name == "prod-00")
    entries["node_modules/mismatch"] = {"version": "1.0.0"}
    _package(workspace, "node_modules/mismatch", "mismatch", "9.9.9")
    entries["node_modules/backend"] = {"resolved": "backend", "link": True}
    assert len(entries) == 40
    _write(workspace / "node_modules/.package-lock.json", json.dumps({
        "name": "fixture", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
        "packages": entries,
    }).encode())
    _write(workspace / "node_modules/.cache/loader/x.js", b"cached();\n")
    _write(workspace / "frontend/dist/app.js", b"console.log('app');\n")
    _write(workspace / "frontend/dist/app.js.map",
           json.dumps({"version": 3, "file": "app.js", "sources": []}).encode())
    _write(workspace / "frontend/dist/index.html", b"<script src=app.js></script>\n")
    return workspace, sizes


def _mismatch_rows() -> list[str]:
    return [f"node_modules/mismatch/lib/f{index:02d}.js" for index in range(24)]


def test_installed_record_bounds_target_rows_with_exact_counts_and_gaps(tmp_path: Path) -> None:
    workspace, sizes = _workspace(tmp_path)
    started = time.monotonic()

    rows, gaps = node.catalog(tmp_path, workspace, {}, 10_000, "node-unit")

    assert time.monotonic() - started < 2
    packages = [row for row in rows
                if row.get("package_metadata", {}).get("role") == "installed-dependency-package"]
    assert len(packages) == 38
    assert Counter(row["scope_role"] for row in packages) == {"build_dependency": 30, "runtime_dependency": 8}
    assert all(row["analysis_lane"] == "supply_chain" and row["delivery_status"] == "not_established"
               for row in packages)
    record = file_sha256(workspace / "node_modules/.package-lock.json")
    by_path = {row["workspace_path"]: row for row in rows}
    scoped = by_path["node_modules/@scope/tool/package.json"]
    assert scoped["delivery_evidence"] == {
        "kind": "npm-installed-record", "workspace_path": "node_modules/.package-lock.json",
        "sha256": record, "entry": "node_modules/@scope/tool"}
    assert scoped["package_metadata"] == {
        "format": "package.json", "role": "installed-dependency-package", "ecosystem": "npm",
        "manager": "npm", "name": "@scope/tool", "version": "1.0.0",
        "resolved": "https://registry.npmjs.org/@scope/tool/-/@scope/tool.tgz",
        "integrity": "sha512-fixture", "dev": True, "optional": False, "dev_optional": False,
        "install_path": "node_modules/@scope/tool", "files": 25,
        "bytes": sizes["node_modules/@scope/tool"], "retained_files": 0}
    # Nested install paths are counted by their own entry, not by their parent.
    assert by_path["node_modules/a/package.json"]["package_metadata"]["files"] == 25
    assert by_path["node_modules/a/package.json"]["package_metadata"]["bytes"] == sizes["node_modules/a"]
    assert by_path["node_modules/a/node_modules/b/package.json"]["scope_role"] == "runtime_dependency"

    [record_row] = [row for row in rows
                    if row.get("dependency_metadata", {}).get("role") == "installed-dependency-record"]
    assert record_row["workspace_path"] == "node_modules/.package-lock.json"
    assert record_row["dependency_metadata"] == {
        "format": ".package-lock.json", "manager": "npm", "role": "installed-dependency-record"}
    assert record_row["analysis_lane"] == "supply_chain"

    [addon] = [row for row in rows if row["kind"] == "native-addon"]
    assert addon["workspace_path"] == "node_modules/prod-00/build/Release/addon.node"
    assert addon["scope_role"] == "runtime_dependency"
    assert addon["delivery_evidence"]["entry"] == "node_modules/prod-00"
    assert by_path["node_modules/prod-00/package.json"]["package_metadata"]["retained_files"] == 1

    target = sorted(row["workspace_path"] for row in rows if row["analysis_lane"] == "target")
    assert target == sorted(["frontend/dist/app.js", "frontend/dist/index.html",
                             "node_modules/.cache/loader/x.js", *_mismatch_rows()])
    assert by_path["frontend/dist/app.js.map"]["analysis_lane"] == "evidence"
    assert by_path["node_modules/mismatch/package.json"]["analysis_lane"] == "supply_chain"
    assert len(rows) <= 70

    retained_bytes = (workspace / "node_modules/prod-00/build/Release/addon.node").stat().st_size
    summarized_bytes = sum(sizes.values()) - retained_bytes
    assert [gap for gap in gaps if gap.startswith(SUMMARY)] == [
        f"{SUMMARY}38 packages (949 files, {summarized_bytes} bytes) recorded by "
        "node_modules/.package-lock.json routed to supply_chain review; per-file target review "
        "not performed; 26 files under node_modules not covered by the installer record remain per-file"]
    assert [gap for gap in gaps if "does not match npm installer record" in gap] == [
        "node_modules/mismatch: installed package does not match npm installer record "
        "(version-mismatch); cataloged per-file"]
    unknown = sorted(gap.split(": ", 1)[0] for gap in gaps if "delivery_fact_unavailable" in gap)
    assert unknown == target
    assert len(gaps) == 2 + len(target)


def test_removed_record_restores_per_file_catalog_with_one_named_gap(tmp_path: Path) -> None:
    workspace, _ = _workspace(tmp_path)
    (workspace / "node_modules/.package-lock.json").unlink()
    expected = sorted(path.relative_to(workspace).as_posix() for path in workspace.rglob("*")
                      if path.is_file() and node.artifact_kind(path) is not None)

    rows, gaps = node.catalog(tmp_path, workspace, {}, 10_000, "node-unit")

    assert sorted(row["workspace_path"] for row in rows) == expected
    assert len(expected) == 980
    assert not any(row.get("package_metadata", {}).get("role") == "installed-dependency-package"
                   for row in rows)
    assert gaps.count(MISSING) == 1
    assert not any(gap.startswith(SUMMARY) for gap in gaps)


def test_accepted_npm_pack_member_stays_shipped_inside_verified_package(tmp_path: Path) -> None:
    workspace, sizes = _workspace(tmp_path)
    member = workspace / "node_modules/dev-00/lib/f00.js"
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        data = member.read_bytes()
        info = tarfile.TarInfo("package/node_modules/dev-00/lib/f00.js")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    archive_path = workspace / "pkg/fixture-1.0.0.tgz"
    _write(archive_path, payload.getvalue())
    facts = [{"workspace_path": "pkg/fixture-1.0.0.tgz", "sha256": file_sha256(archive_path),
              "source_dir": "."}]

    rows, gaps = node.catalog(tmp_path, workspace, {}, 10_000, "node-unit", package_facts=facts)

    by_path = {row["workspace_path"]: row for row in rows}
    shipped = by_path["node_modules/dev-00/lib/f00.js"]
    assert shipped["scope_role"] == "shipped_dependency"
    assert shipped["delivery_evidence"]["kind"] == "accepted-package-member"
    assert by_path["pkg/fixture-1.0.0.tgz"]["scope_role"] == "deliverable"
    assert by_path["node_modules/dev-00/package.json"]["scope_role"] == "build_dependency"
    assert by_path["node_modules/dev-00/package.json"]["package_metadata"]["retained_files"] == 1
    assert "node_modules/dev-00/lib/f01.js" not in by_path
    summarized_bytes = (sum(sizes.values()) - member.stat().st_size
                        - (workspace / "node_modules/prod-00/build/Release/addon.node").stat().st_size)
    [summary] = [gap for gap in gaps if gap.startswith(SUMMARY)]
    assert summary.startswith(f"{SUMMARY}38 packages (948 files, {summarized_bytes} bytes) ")


def test_dispositions_record_verified_trees_and_nested_unverified_carve_out(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    a_bytes = _package(workspace, "node_modules/a", "a", "1.0.0", addon=True)
    _package(workspace, "node_modules/a/node_modules/c", "c", "1.0.0")
    (workspace / "node_modules/a/node_modules/c/package.json").unlink()
    _write(workspace / "node_modules/.package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/a": {"version": "1.0.0"},
        "node_modules/a/node_modules/c": {"version": "1.0.0", "dev": True},
    }}).encode())
    dispositions = BuildOutputDispositions(family="node")

    rows, gaps = node.catalog(tmp_path, workspace, {}, 1_000, "node-unit", dispositions=dispositions)

    record = file_sha256(workspace / "node_modules/.package-lock.json")
    roots = {root["root"]: root for root in dispositions.document()["roots"]}
    assert set(roots) == {"node_modules/a", "node_modules/a/node_modules/c"}
    verified = roots["node_modules/a"]
    assert {key: verified[key] for key in (
        "disposition", "basis", "confidence", "name", "reason", "evidence_ref", "scope_role",
        "files", "bytes", "kept", "bound_group")} == {
        "disposition": "supply_chain", "basis": "installer-record", "confidence": "fact",
        "name": "npm-installed-package", "reason": "verified against installed manifest",
        "evidence_ref": "node_modules/.package-lock.json#node_modules/a", "scope_role": "runtime_dependency",
        "files": 25, "bytes": a_bytes, "bound_group": "node_modules",
        "kept": ["node_modules/a/build/Release/addon.node", "node_modules/a/package.json"]}
    carve_out = roots["node_modules/a/node_modules/c"]
    assert (carve_out["disposition"], carve_out["name"], carve_out["reason"]) == (
        "per_file", "npm-unverified-package", "manifest-missing")
    carved = sorted(row["workspace_path"] for row in rows
                    if row["workspace_path"].startswith("node_modules/a/node_modules/c/"))
    assert len(carved) == 24 and all(path.endswith(".js") for path in carved)
    assert not any(row["workspace_path"].startswith("node_modules/a/lib/") for row in rows)
    anchor, = (row for row in rows if row["workspace_path"] == "node_modules/a/package.json")
    assert anchor["delivery_evidence"]["sha256"] == record
    assert anchor["package_metadata"]["files"] == 25 and anchor["package_metadata"]["retained_files"] == 1
    assert ("node_modules/a/node_modules/c: installed package does not match npm installer record "
            "(manifest-missing); cataloged per-file") in gaps
    assert not any(gap.startswith("build-output-") for gap in gaps)


def test_shipped_bundler_cache_rule_excludes_cache_by_name_not_as_uncovered(tmp_path: Path) -> None:
    workspace, _ = _workspace(tmp_path)
    shipped = tomllib.loads((REPOSITORY / "appsec-review.toml").read_text(encoding="utf-8"))["build_outputs"]
    dispositions = BuildOutputDispositions(parse_build_outputs(shipped), family="node")

    rows, gaps = node.catalog(tmp_path, workspace, {}, 10_000, "node-unit", dispositions=dispositions)

    assert "node_modules/.cache/loader/x.js" not in {row["workspace_path"] for row in rows}
    [summary] = [gap for gap in gaps if gap.startswith(SUMMARY)]
    assert summary.endswith("; 25 files under node_modules not covered by the installer record remain per-file")
    document = dispositions.document()
    assert [(item["path"], item["name"], item["files"]) for item in document["configured_exclusions"]] == [
        ("node_modules/.cache", "node-bundler-cache", 1)]
    assert len([root for root in document["roots"] if root["disposition"] == "supply_chain"]) == 38


def test_root_bound_counts_installer_prefixes_and_leaves_a_refused_prefix_per_file(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    for prefix, names in (("", ("a", "b")), ("web/", ("c",))):
        for name in names:
            _package(workspace, f"{prefix}node_modules/{name}", name, "1.0.0")
        _write(workspace / f"{prefix}node_modules/.package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            f"node_modules/{name}": {"version": "1.0.0"} for name in names}}).encode())
    policy = BuildOutputPolicy(discovery=BuildOutputDiscovery(max_layout_roots=1))
    dispositions = BuildOutputDispositions(policy, family="node")

    rows, gaps = node.catalog(tmp_path, workspace, {}, 1_000, "node-unit", dispositions=dispositions)

    roots = {root["root"]: root.get("bound_group") for root in dispositions.document()["roots"]}
    assert roots == {"node_modules/a": "node_modules", "node_modules/b": "node_modules"}
    per_file = [row["workspace_path"] for row in rows if row["workspace_path"].startswith("web/node_modules/c/")]
    assert len(per_file) == 25
    assert not any(row["workspace_path"].startswith(("node_modules/a/lib/", "node_modules/b/lib/")) for row in rows)
    summaries = [gap for gap in gaps if gap.startswith(SUMMARY)]
    assert any(gap.startswith(f"{SUMMARY}2 packages (50 files, ") for gap in summaries), summaries
    assert "build-output-root-bound-exceeded: 1 roots beyond max_layout_roots stay per-file target content" in gaps


def test_more_than_512_verified_packages_under_one_prefix_stay_within_the_root_bound(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    names = [f"pkg-{index:03d}" for index in range(520)]
    for name in names:
        _write(workspace / f"node_modules/{name}/package.json",
               json.dumps({"name": name, "version": "1.0.0"}).encode())
        _write(workspace / f"node_modules/{name}/index.js", f"module.exports = '{name}';\n".encode())
    _write(workspace / "node_modules/.package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        f"node_modules/{name}": {"version": "1.0.0"} for name in names}}).encode())
    dispositions = BuildOutputDispositions(family="node")

    rows, gaps = node.catalog(tmp_path, workspace, {}, 10_000, "node-unit", dispositions=dispositions)

    anchors = {row["workspace_path"] for row in rows if row.get("package_metadata")}
    assert anchors == {f"node_modules/{name}/package.json" for name in names}
    assert not [row["workspace_path"] for row in rows if row["workspace_path"].endswith("/index.js")]
    assert not [gap for gap in gaps if gap.startswith("build-output-")], gaps
    [summary] = [gap for gap in gaps if gap.startswith(SUMMARY)]
    assert summary.startswith(f"{SUMMARY}520 packages (1040 files, ")


def test_nested_prefix_described_by_parent_record_has_no_missing_gap(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _package(workspace, "backend/node_modules/x", "x", "2.0.0")
    _write(workspace / "backend/package.json", b'{"name":"backend","version":"1.0.0"}')
    _write(workspace / "node_modules/.package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "backend": {"name": "backend", "version": "1.0.0"},
        "backend/node_modules/x": {"version": "2.0.0"},
    }}).encode())

    dispositions = BuildOutputDispositions(family="node")

    rows, gaps = node.catalog(tmp_path, workspace, {}, 1_000, "node-unit", dispositions=dispositions)

    assert [(root["root"], root["bound_group"]) for root in dispositions.document()["roots"]] == [
        ("backend/node_modules/x", "backend/node_modules")]
    assert not any("installer record unavailable" in gap for gap in gaps)
    assert {row["workspace_path"] for row in rows} == {
        "backend/package.json", "backend/node_modules/x/package.json", "node_modules/.package-lock.json"}
    assert [gap for gap in gaps if gap.startswith(SUMMARY)] == [
        f"{SUMMARY}1 packages (25 files, "
        f"{sum(path.stat().st_size for path in (workspace / 'backend/node_modules/x').rglob('*') if path.is_file())}"
        " bytes) recorded by node_modules/.package-lock.json routed to supply_chain review; "
        "per-file target review not performed"]
