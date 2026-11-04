from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs import cataloging
from appsec_review.config.exclusions import ExclusionRule, PathExclusions
from appsec_review.jobs.build_discovery import descriptor_package, discover_build_units
from appsec_review.jobs.cataloging import Bounds, inventory, raw_snapshot
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.observability import PipelineLog, aggregate_run_metrics


def _target(root: Path) -> dict[str, str]:
    documents = {
        "a-content/0.txt": "xxxx", "a-content/1.txt": "xxxx", "a-content/2.txt": "xxxx",
        "z-server/proj/login/login.vcxproj": "<Project />\n",
        "z-server/proj/login/makefile": "all:\n\t$(CXX) -c login.cpp\n",
        "z-server/proj/login/fbuild.bff": "// native build context\n",
        "z-server/proj/login/build_ms.bat": "msbuild login.vcxproj\n",
    }
    for relative, text in documents.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    return documents


@pytest.mark.parametrize("bounds", [Bounds(max_files=2), Bounds(max_total_bytes=8)])
def test_all_project_names_survive_unrelated_content_inventory_limits(tmp_path: Path, bounds: Bounds) -> None:
    documents = _target(tmp_path)
    result = inventory(tmp_path, bounds)
    retained = {item["path"]: item for item in result["files"]}
    assert set(retained) == set(documents) - {"a-content/2.txt"}
    assert result["gaps"] == [{"path": "a-content/2.txt", "reason": "inventory_bound_reached"}]
    assert result["file_discovery"] == {
        "semantics": "appsec-review/file-discovery/1", "descriptor_coverage": "complete",
        "file_paths_examined": 7, "descriptors_matched": 4, "descriptors_retained": 4,
        "descriptors_unavailable": 0, "content_files_retained": 2,
        "content_bytes_retained": 8, "content_files_omitted": 1,
    }
    units = discover_build_units(result["files"])
    assert {(unit["root"], unit["family"], unit["build_system"]) for unit in units} == {
        ("z-server/proj/login", "native", "msbuild"), ("z-server/proj/login", "native", "make"),
    }
    project = next(unit for unit in units if unit["build_system"] == "msbuild")
    package = descriptor_package(tmp_path, project, result["files"])
    assert {item["path"] for item in package["documents"]} == {
        "z-server/proj/login/login.vcxproj", "z-server/proj/login/fbuild.bff",
        "z-server/proj/login/build_ms.bat",
    }
    assert package["gaps"] == []
    for relative, item in retained.items():
        assert item["sha256"] == hashlib.sha256(documents[relative].encode()).hexdigest()


def test_default_ten_thousand_entry_boundary_cannot_hide_late_native_project(tmp_path: Path) -> None:
    noise = tmp_path / "a-content"
    noise.mkdir()
    for index in range(Bounds().max_files + 1):
        (noise / f"{index:05}.txt").touch()
    project = tmp_path / "z-server" / "login.vcxproj"
    project.parent.mkdir()
    project.write_text("<Project />\n", encoding="utf-8")
    result = inventory(tmp_path)
    assert result["file_discovery"]["file_paths_examined"] == 10_002
    assert result["file_discovery"]["content_files_retained"] == 10_000
    assert result["file_discovery"]["content_files_omitted"] == 1
    assert result["file_discovery"]["descriptors_retained"] == 1
    assert result["snapshot"]["file_count"] == 10_002
    assert discover_build_units(result["files"])[0]["markers"][0]["path"] == "z-server/login.vcxproj"


def test_stream_yields_before_visiting_the_next_directory(tmp_path: Path, monkeypatch) -> None:
    advanced = []

    def walk(*args, **kwargs):
        yield str(tmp_path), [], ["first.txt"]
        advanced.append(True)
        yield str(tmp_path / "later"), [], ["last.vcxproj"]

    monkeypatch.setattr(cataloging.os, "walk", walk)
    paths = cataloging._walk_files(tmp_path)
    assert next(paths) == tmp_path / "first.txt"
    assert advanced == []
    assert list(paths) == [tmp_path / "later" / "last.vcxproj"]
    assert advanced == [True]


def test_stream_reports_directory_errors_instead_of_claiming_complete_coverage(tmp_path: Path, monkeypatch) -> None:
    def walk(*args, onerror, **kwargs):
        onerror(PermissionError("unreadable target directory"))
        yield str(tmp_path), [], []

    monkeypatch.setattr(cataloging.os, "walk", walk)
    with pytest.raises(PermissionError, match="unreadable target directory"):
        inventory(tmp_path)


def test_streaming_snapshot_preserves_sorted_wire_identity(tmp_path: Path) -> None:
    contents = {"z.txt": b"last", "a.txt": b"first", "b/nested.txt": b"nested"}
    for relative, value in contents.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    excluded = tmp_path / ".git" / "config"
    excluded.parent.mkdir()
    excluded.write_text("metadata", encoding="utf-8")
    expected = hashlib.sha256()
    for relative in ("a.txt", "z.txt", "b/nested.txt"):
        value = contents[relative]
        expected.update(f"FILE\0{relative}\0{len(value)}\0{hashlib.sha256(value).hexdigest()}\n".encode())
    assert raw_snapshot(tmp_path)["sha256"] == expected.hexdigest()
    assert raw_snapshot(tmp_path)["file_count"] == 3


def test_selected_descriptors_keep_per_file_bounds_and_named_coverage_gaps(tmp_path: Path) -> None:
    (tmp_path / "large.vcxproj").write_text("<Project />", encoding="utf-8")
    result = inventory(tmp_path, Bounds(max_file_bytes=4, max_files=0))
    assert result["files"] == []
    assert result["gaps"] == [{"path": "large.vcxproj", "reason": "file_too_large"}]
    assert result["file_discovery"]["descriptors_matched"] == 1
    assert result["file_discovery"]["descriptors_unavailable"] == 1
    assert result["file_discovery"]["descriptor_coverage"] == "partial"


def test_descriptor_filters_preserve_explicit_file_and_directory_exclusions(tmp_path: Path) -> None:
    for relative in ("skip/login.vcxproj", "keep/hidden.vcxproj", "keep/login.vcxproj"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"<Project />")
    exclusions = PathExclusions((ExclusionRule("skip/", "global"),
                                 ExclusionRule("hidden.vcxproj", "global")))
    result = inventory(tmp_path, Bounds(max_files=0), exclusions)
    assert [item["path"] for item in result["files"]] == ["keep/login.vcxproj"]
    assert [item["path"] for item in result["configured_exclusions"]] == ["keep/hidden.vcxproj", "skip/"]
    assert result["file_discovery"]["descriptors_matched"] == 1
    assert result["snapshot"]["file_count"] == 3


def test_utf16_project_is_discovered_by_filename_not_misclassified_as_an_artifact(tmp_path: Path) -> None:
    path = tmp_path / "login.vcxproj"
    path.write_bytes("<Project />".encode("utf-16"))
    result = inventory(tmp_path, Bounds(max_files=0))
    assert result["artifact_candidates"] == []
    assert discover_build_units(result["files"])[0]["build_system"] == "msbuild"
    assert result["file_discovery"]["descriptors_retained"] == 1


def test_prebuilt_wasm_remains_an_artifact_not_a_source_build_descriptor(tmp_path: Path) -> None:
    (tmp_path / "customer.wasm").write_bytes(b"\0asm\x01\0\0\0")
    result = inventory(tmp_path)
    assert result["files"] == []
    assert result["artifact_candidates"][0]["path"] == "customer.wasm"
    assert result["file_discovery"]["descriptors_matched"] == 0


def test_intake_catalog_and_metrics_share_verified_full_tree_discovery(tmp_path: Path, monkeypatch) -> None:
    from appsec_review.jobs.job_review_intake import job as intake_module
    from appsec_review.jobs.job_target_catalog import job as catalog_module

    target = tmp_path / "target"
    _target(target)
    bounds = Bounds(max_files=2)
    expected = inventory(target, bounds)["file_discovery"]

    def bounded_inventory(root, *args, exclusions=None):
        return inventory(root, bounds, exclusions)

    monkeypatch.setattr(intake_module, "inventory", bounded_inventory)
    monkeypatch.setattr(catalog_module, "inventory", bounded_inventory)
    run_root = tmp_path / "run"
    outputs = {}
    job = SimpleNamespace(target_root=target, config=SimpleNamespace(exclusions=None),
                          source_fingerprint=raw_snapshot(target)["sha256"], run_root=run_root,
                          attempt_root=run_root / "data" / "jobs" / "job_target_catalog" / "attempts" / "attempt_0001")

    def context(name):
        return SimpleNamespace(job=job, unit_id=name, output=lambda key: outputs[key])

    task = next(unit for unit in build_intake().units if unit.unit_id == "prepare_target.validate_target")
    assert task.handler(context(task.unit_id))["file_discovery"] == expected
    handlers = {unit.unit_id: unit.handler for unit in build_catalog().units}
    for name in ("repository_discovery.partition_repository", "build_discovery.discover_build_systems",
                 "repository_discovery.discover_projects", "build_discovery.catalog_build_targets"):
        outputs[name] = handlers[name](context(name))
    projects = outputs["repository_discovery.discover_projects"]
    assert projects["projects"][0]["manifest"] == "z-server/proj/login/login.vcxproj"
    assert {item["kind"] for item in outputs["build_discovery.discover_build_systems"]["systems"]} == {
        "makefile", "login.vcxproj",
    }
    builds = outputs["build_discovery.catalog_build_targets"]
    assert {unit["build_system"] for unit in builds["targets"]} == {"make", "msbuild"}
    partition = outputs["repository_discovery.partition_repository"]
    assert partition["file_discovery"] == expected
    assert json.loads((run_root / partition["artifact"]["path"]).read_text())["file_discovery"] == expected
    PipelineLog(run_root).write("REVIEW_SCOPE_CATALOGED", run_id="run", details={
        "source_receipt": partition["artifact"], "project_receipt": projects["artifact"],
        "build_target_receipt": builds["artifact"], "file_discovery": {"descriptors_retained": 0},
    })
    metrics = aggregate_run_metrics(run_root)["review"]
    assert metrics["file_discovery"] == expected
    assert metrics["projects"]["discovered"] == 1
    assert metrics["build_units"]["discovered"] == 2
    assert metrics["source_gap_count"] == 1
