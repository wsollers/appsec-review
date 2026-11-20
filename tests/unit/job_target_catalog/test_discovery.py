from __future__ import annotations

import hashlib
import json

import pytest

from appsec_review.interchange import validate_unit_output
from appsec_review.jobs import engine_discovery
from appsec_review.jobs.job_target_catalog import job as catalog
from appsec_review.storage import shared
from tests.unit.job_target_catalog.support import (
    COMPILE, COMPONENTS, DEPENDENCIES, PARTITION, PROJECTS, SYSTEMS, TARGETS,
    context, document, handler, partition, source,
)


def test_partition_wires_inventory_bounds_scope_and_binary_publication(tmp_path, monkeypatch):
    unit = context(tmp_path, PARTITION)
    entries = [source(unit, "z.py"), source(unit, "a/x.py")]
    binary = source(unit, "app.wasm", b"\0asm\x01\0\0\0", None)
    snapshot = partition(entries, gaps=[{"path": ".hg", "reason": "excluded_directory"}])
    snapshot["artifact_candidates"] = [binary]
    snapshot["configured_exclusions"] = [{"path": "a.png", "asset_class": "raster-image"}]
    snapshot["excluded_assets"]["files"] = 1
    calls = []

    def inventory(target, bounds, *, exclusions):
        calls.append((target, bounds.max_file_bytes, exclusions))
        return snapshot

    monkeypatch.setattr(catalog, "inventory", inventory)
    unit.job.config.exclusions = object()
    result = handler(PARTITION)(unit)
    validate_unit_output(result, unit_id=PARTITION, strict_gaps=True)
    assert calls == [(unit.job.target_root, 128, unit.job.config.exclusions)]
    doc = document(unit, result)
    assert doc["schema"] == "appsec-review/repository-partition/1"
    assert doc["source_fingerprint"] == "fixture-snapshot"
    assert doc["partitions"] == [{"path": "a", "file_count": 1}, {"path": "z.py", "file_count": 1}]
    assert result["configured_exclusions"] == snapshot["configured_exclusions"]
    assert result["excluded_assets"] == snapshot["excluded_assets"]
    assert result["file_discovery"] == {"file_paths_examined": 2}
    assert result["inventory_gaps"] == [{"path": ".hg", "reason": "excluded_directory"}]
    assert [gap["reason"] for gap in result["gaps"]] == [".hg: excluded_directory"]
    for row in result["files"]:
        assert row["artifact_origin"] == "target-intake"
        assert row["scope_role"] == "unknown" and row["analysis_lane"] == "target"
    [artifact] = result["target_artifacts"]
    assert artifact["schema"] == "appsec-review/target-artifact-intake/1"
    assert artifact["target_relative_path"] == artifact["workspace_path"] == "app.wasm"
    assert artifact["kind"] == "wasm-module" and artifact["source_fingerprint"] == "fixture-snapshot"
    assert artifact["mapping"] == "exact-target-path" and artifact["mapping_confidence"] == 1
    assert artifact["delivery_status"] == "unknown"
    assert (unit.job.run_root / artifact["path"]).read_bytes() == b"\0asm\x01\0\0\0"
    assert doc["target_artifacts"] == result["target_artifacts"]


def test_partition_unknown_binary_kind_uses_resource(tmp_path, monkeypatch):
    from appsec_review.jobs import artifact_kinds
    unit = context(tmp_path, PARTITION)
    candidate = source(unit, "data.bin", b"resource", None)
    snapshot = partition()
    snapshot["artifact_candidates"] = [candidate]
    monkeypatch.setattr(catalog, "inventory", lambda *args, **kwargs: snapshot)
    monkeypatch.setattr(artifact_kinds, "binary_role", lambda path: (None, "unknown"))
    result = handler(PARTITION)(unit)
    assert result["target_artifacts"][0]["kind"] == "resource"
    assert result["target_artifacts"][0]["format"] == "unknown"


@pytest.mark.parametrize("damage", ["escape", "hash", "length", "published-hash", "published-length"])
def test_partition_rejects_changed_binary_before_acceptance(tmp_path, monkeypatch, damage):
    unit = context(tmp_path, PARTITION)
    binary = source(unit, "app.wasm", b"\0asm\x01\0\0\0", None)
    if damage == "escape":
        binary["path"] = "../outside.wasm"
        message = "^shared artifact path is not run-relative canonical POSIX$"
    snapshot = partition()
    snapshot["artifact_candidates"] = [binary]
    monkeypatch.setattr(catalog, "inventory", lambda *args, **kwargs: snapshot)
    if damage.startswith("published"):
        monkeypatch.setattr(shared, "put_bytes", lambda *args: {
            "sha256": "b" * 64 if damage == "published-hash" else binary["sha256"],
            "size_bytes": 1 if damage == "published-length" else binary["size_bytes"]})
        message = "^target artifact changed during intake publication$"
    elif damage != "escape":
        (unit.job.target_root / "app.wasm").write_bytes(
            b"\0asm\x02\0\0\0" if damage == "hash" else b"\0asm\x01\0\0\0extra")
        message = "^target artifact changed during bounded intake$"
    with pytest.raises(catalog.CatalogIntegrityError, match=message):
        handler(PARTITION)(unit)
    assert not (unit.job.attempt_root / "artifacts/catalog/repository-partition.json").exists()


def test_census_counts_languages_and_other_in_sorted_order(tmp_path):
    unit = context(tmp_path, "repository_discovery.census_languages", {
        PARTITION: partition([{"language": "Python"}, {"language": None},
                              {"language": "C"}, {"language": "Python"}])})
    result = handler(unit.unit_id)(unit)
    assert document(unit, result) == {
        "schema": "appsec-review/language-census/1", "languages": [
            {"language": "C", "file_count": 1}, {"language": "Other", "file_count": 1},
            {"language": "Python", "file_count": 2}]}
    assert unit.reads == [PARTITION]


@pytest.mark.parametrize("engine_root", [".", "game"], ids=["root", "nested"])
def test_projects_skip_engine_generated_manifests_but_keep_other_projects(tmp_path, engine_root):
    prefix = "" if engine_root == "." else "game/"
    paths = [prefix + "generated.csproj", prefix + "Packages/lib/package.json",
             prefix + "package.json", "plain/pyproject.toml", "README.md"]
    entries = [{"path": path, "sha256": str(i)} for i, path in enumerate(paths)]
    marker = {"path": prefix + "ProjectSettings/ProjectVersion.txt", "sha256": "marker"}
    engines = {"projects": [{"root": engine_root, "engine": "unity", "markers": [marker]}],
               "observations": [{"kind": "unity"}], "gaps": []}
    unit = context(tmp_path, PROJECTS, {PARTITION: partition(entries), SYSTEMS: {"engine_discovery": engines}})
    result = handler(PROJECTS)(unit)
    assert result["projects"] == [
        {"manifest": prefix + "package.json", "root": engine_root, "sha256": "2"},
        {"manifest": "plain/pyproject.toml", "root": "plain", "sha256": "3"},
        {"manifest": marker["path"], "root": engine_root, "sha256": "marker", "engine": "unity"},
    ]
    assert document(unit, result)["engine_observations"] == [{"kind": "unity"}]
    assert result["gaps"] == []


def test_project_csharp_suffix_outside_engine_is_retained(tmp_path):
    unit = context(tmp_path, PROJECTS, {
        PARTITION: partition([{"path": "backend/App.CSPROJ", "sha256": "cs"}]),
        SYSTEMS: {"engine_discovery": {"projects": [], "observations": [], "gaps": []}},
    })
    assert handler(PROJECTS)(unit)["projects"] == [
        {"manifest": "backend/App.CSPROJ", "root": "backend", "sha256": "cs"}]


def test_no_project_manifest_preserves_named_scope_gap(tmp_path):
    unit = context(tmp_path, PROJECTS, {
        PARTITION: partition(), SYSTEMS: {"engine_discovery": {
            "projects": [], "observations": [], "gaps": ["game: engine marker missing"]}}})
    result = handler(PROJECTS)(unit)
    validate_unit_output(result, unit_id=PROJECTS, strict_gaps=True)
    assert result["projects"] == []
    expected = ["game: engine marker missing", "no recognized project manifests"]
    assert [gap["reason"] for gap in result["gaps"]] == expected
    assert [gap["code"] for gap in result["gaps"]] == ["producer_reported_gap", "empty_result"]
    assert document(unit, result)["gaps"] == expected


@pytest.mark.parametrize("shape", ["empty", "orphan", "units", "unread"], ids=["empty", "orphan", "units", "unread"])
def test_build_systems_wires_discovery_readers_inventory_scopes_and_event(tmp_path, monkeypatch, shape):
    unit = context(tmp_path, SYSTEMS)
    entries = [source(unit, path, b"descriptor", None)
               for path in ("meson.build", "package.json", "app.csproj", "notes.txt")]
    if shape == "unread":
        entries[0]["size_bytes"] = catalog.BUILD_DESCRIPTOR_READ_BYTES + 1
        entries[3]["size_bytes"] = catalog.BUILD_DESCRIPTOR_READ_BYTES + 2
    unit.outputs[PARTITION] = partition(entries)
    engines = {"projects": [], "counts": {}, "observations": [],
               "gaps": ["unity: marker unreadable"] if shape == "unread" else []}
    calls = []
    units = [{"build_unit_id": "root|meson"}] if shape == "units" else []
    orphans = [{"language": "C"}, {"language": "C"}, {"language": "Rust"}] if shape == "orphan" else []

    def unity(files, *, read_text):
        assert files is entries or files == entries
        observed = read_text(entries[0], 1)
        assert observed == (None if shape == "unread" else "descriptor")
        calls.append("engine")
        return engines

    def discover(files, *, read_text, engine_discovery):
        assert files == entries and engine_discovery is engines
        assert read_text("package.json") == "descriptor"
        if shape == "unread":
            assert read_text("notes.txt") is None
        calls.append("inventory")
        return {"units": units, "orphaned_sources": orphans,
                "folded_roots": [{"root": "member"}], "demoted_markers": [{"path": "app.csproj"}]}

    monkeypatch.setattr(engine_discovery, "discover_unity", unity)
    monkeypatch.setattr(catalog, "discover_build_inventory", discover)
    monkeypatch.setattr(catalog, "unsupported_build_gaps", lambda files, found: (
        calls.append(("unsupported", files, found))
        or (["bazel: unsupported build descriptor"] if shape == "unread" else [])))
    monkeypatch.setattr(catalog, "source_only_scopes", lambda files, found: (
        calls.append(("scopes", files, found)) or [{"root": "scripts"}]))
    result = handler(SYSTEMS)(unit)
    validate_unit_output(result, unit_id=SYSTEMS, strict_gaps=True)
    assert result["systems"] == [{"path": entry["path"], "kind": entry["path"], "sha256": entry["sha256"]}
                                  for entry in entries[:3]]
    assert result["build_units"] == units and result["orphaned_sources"] == orphans
    unread_reason = (
        f"build descriptor not read: meson.build: {catalog.BUILD_DESCRIPTOR_READ_BYTES + 1} bytes exceeds the "
        f"{catalog.BUILD_DESCRIPTOR_READ_BYTES}-byte read bound; its build points and driven directories are unknown"
    )
    expected_gaps = {
        "empty": ["no recognized build system"],
        "orphan": ["orphaned sources: 2 C, 1 Rust"],
        "units": [],
        "unread": ["bazel: unsupported build descriptor", "unity: marker unreadable", unread_reason],
    }
    assert [gap["reason"] for gap in result["gaps"]] == expected_gaps[shape]
    assert result["gap_reasons"] == expected_gaps[shape]
    assert result["folded_roots"] == [{"root": "member"}]
    assert result["demoted_markers"] == [{"path": "app.csproj"}]
    assert calls == ["engine", "inventory", ("unsupported", entries, units), ("scopes", entries, units)]
    doc = document(unit, result)
    assert doc["schema"] == "appsec-review/build-systems/4"
    assert doc["gaps"] == expected_gaps[shape]
    assert unit.events == [("BUILD_SYSTEMS_DISCOVERED", {
        "unit_id": SYSTEMS, "unit_count": len(units), "orphaned_source_count": len(orphans),
        "source_only_scope_count": 1, "gap_count": len(expected_gaps[shape])})]


def test_build_systems_refuses_changed_descriptor_even_when_engine_swallows_reader_error(tmp_path, monkeypatch):
    unit = context(tmp_path, SYSTEMS)
    entry = source(unit, "meson.build", b"old", None)
    unit.outputs[PARTITION] = partition([entry])
    (unit.job.target_root / "meson.build").write_bytes(b"new")

    def engine(files, *, read_text):
        with pytest.raises(catalog.CatalogIntegrityError, match="descriptor differs"):
            read_text(entry, 1)
        return {"projects": [], "gaps": []}

    monkeypatch.setattr(engine_discovery, "discover_unity", engine)
    with pytest.raises(catalog.CatalogIntegrityError, match="^engine/build descriptor differs from the accepted catalog: meson.build$"):
        handler(SYSTEMS)(unit)
    assert unit.events == []


@pytest.mark.parametrize("present", [False, True], ids=["absent", "present"])
def test_compile_commands_matches_exact_basename(tmp_path, present):
    entries = [{"path": "sub/compile_commands.json", "sha256": "a"}] if present else []
    unit = context(tmp_path, COMPILE, {PARTITION: partition([*entries, {"path": "not_compile_commands.json"}])})
    result = handler(COMPILE)(unit)
    validate_unit_output(result, unit_id=COMPILE, strict_gaps=True)
    assert result["files"] == entries
    expected = [] if present else ["compile_commands.json not present"]
    assert [gap["reason"] for gap in result["gaps"]] == expected
    doc = document(unit, result)
    assert doc["schema"] == "appsec-review/compile-commands/1"
    assert doc["gaps"] == expected


@pytest.mark.parametrize("kind", ["android", "generic", "unity", "unity-default"])
def test_build_targets_pass_descriptor_facts_and_image_profile(tmp_path, monkeypatch, kind):
    build = {"build_unit_id": "unit", "root": ".", "build_system": "unity" if kind.startswith("unity") else "gradle"}
    if kind.startswith("unity"):
        build.update(engine="unity", engine_project={"version": "2022"},
                     markers=[{"path": "ProjectVersion.txt"}],
                     descriptor_facts={"kind": "custom-engine"} if kind == "unity" else {})
    package = {"files": ["build.gradle"]}
    calls = []
    monkeypatch.setattr(catalog, "descriptor_package",
                        lambda target, item, files: calls.append(("package", target, item, files)) or dict(package))
    monkeypatch.setattr(catalog, "android_descriptor_facts", lambda value: (
        calls.append(("android", value)) or ({"kind": "android"} if kind == "android" else {})))
    monkeypatch.setattr(engine_discovery, "unity_configuration_fingerprint",
                        lambda project, snapshot: calls.append(("unity", project, snapshot)) or "unity-fp")
    monkeypatch.setattr(catalog, "required_image_profile",
                        lambda target: calls.append(("profile", target)) or "image-profile")
    engines = {"counts": {"unity": 1}, "observations": [], "gaps": []}
    unit = context(tmp_path, TARGETS, {
        SYSTEMS: {"build_units": [build], "engine_discovery": engines, "gaps": []},
        PARTITION: partition(),
    })
    result = handler(TARGETS)(unit)
    validate_unit_output(result, unit_id=TARGETS, strict_gaps=True)
    [target] = result["targets"]
    assert target["required_image_profile"] == "image-profile"
    assert target["project_type"] == {"android": "android", "generic": "generic",
                                      "unity": "custom-engine", "unity-default": "unity"}[kind]
    assert target["descriptor_package"]["files"] == ["build.gradle"]
    if kind.startswith("unity"):
        assert target["descriptor_package"]["inventory"] == build["markers"]
        assert target["descriptor_facts"]["configuration_fingerprint"] == "unity-fp"
        assert calls[0] == ("unity", build["engine_project"], "fixture-snapshot")
        assert not any(call[0] == "android" for call in calls)
    assert ("package", unit.job.target_root, build, []) in calls
    assert calls[-1] == ("profile", {key: value for key, value in target.items() if key != "required_image_profile"})
    assert result["engine_discovery"] == engines
    assert document(unit, result)["schema"] == "appsec-review/build-targets/2"


@pytest.mark.parametrize("has_projects", [False, True], ids=["fallback", "projects"])
def test_components_assign_stable_ids_and_fallback_root(tmp_path, has_projects):
    projects = [{"root": "a", "manifest": "a/package.json", "sha256": "hash-a"},
                {"root": "b", "manifest": "b/Cargo.toml", "sha256": "hash-b"}] if has_projects else []
    unit = context(tmp_path, COMPONENTS, {PROJECTS: {"projects": projects}})
    expected = ([{"component_id": f"component:{i:04d}", "root": item["root"],
                  "manifest": item["manifest"], "manifest_sha256": item["sha256"]}
                 for i, item in enumerate(projects, 1)] if has_projects else [
                     {"component_id": "component:0001", "root": ".", "manifest": None, "manifest_sha256": None}])
    result = handler(COMPONENTS)(unit)
    assert result["components"] == expected and result["gaps"] == []
    assert document(unit, result)["schema"] == "appsec-review/component-catalog/1"


def test_dependency_parser_sorts_sections_and_keeps_delivery_evidence(tmp_path):
    unit = context(tmp_path, DEPENDENCIES)
    raw = json.dumps({"dependencies": {"z": "2", "a": "^1"}, "devDependencies": {"tool": "3"}}).encode()
    entry = source(unit, "package.json", raw, None)
    unit.outputs[COMPONENTS] = {"components": [
        {"component_id": "component:0001", "manifest": "package.json", "manifest_sha256": entry["sha256"]}]}
    result = handler(DEPENDENCIES)(unit)
    validate_unit_output(result, unit_id=DEPENDENCIES, strict_gaps=True)
    assert [(row["name"], row["constraint"], row["scope_role"]) for row in result["dependencies"]] == [
        ("a", "^1", "unknown"), ("z", "2", "unknown"), ("tool", "3", "build_dependency")]
    for row in result["dependencies"]:
        assert row["component_id"] == "component:0001" and row["source"] == "package.json"
        assert row["delivery_evidence"] == {
            "kind": "manifest-dependency-declaration", "path": "package.json",
            "sha256": hashlib.sha256(raw).hexdigest(), "section": row["location"]}
        assert row["artifact_origin"] == "target-intake"
    expected_reasons = [
        "package.json#dependencies.a: dependency delivery status is unknown",
        "package.json#dependencies.z: dependency delivery status is unknown",
    ]
    assert [gap["reason"] for gap in result["gaps"]] == expected_reasons
    doc = document(unit, result)
    assert doc["schema"] == "appsec-review/dependency-catalog/1"
    assert doc["gaps"] == expected_reasons


@pytest.mark.parametrize("payload", [
    [], None, {"dependencies": None}, {"dependencies": ["bad"]},
    {"devDependencies": 2}, {"dependencies": {"bad": {"version": "1"}}},
], ids=["array", "null", "null-section", "array-section", "number-section", "object-version"])
def test_dependency_shape_errors_preserve_other_components_and_valid_sections(tmp_path, payload):
    unit = context(tmp_path, DEPENDENCIES)
    if isinstance(payload, dict) and "devDependencies" not in payload:
        payload = {**payload, "devDependencies": {"tool": "2"}}
    components = []
    for path, value in [("bad/package.json", payload),
                        ("good/package.json", {"dependencies": {"good": "^1"}})]:
        entry = source(unit, path, json.dumps(value).encode(), None)
        components.append({"component_id": path, "manifest": path,
                           "manifest_sha256": entry["sha256"]})
    unit.outputs[COMPONENTS] = {"components": components}
    result = handler(DEPENDENCIES)(unit)
    validate_unit_output(result, unit_id=DEPENDENCIES, strict_gaps=True)
    doc = document(unit, result)
    expected = (["tool"] if isinstance(payload, dict)
                and isinstance(payload.get("devDependencies"), dict) else []) + ["good"]
    assert [row["name"] for row in doc["dependencies"]] == expected
    errors = [gap for gap in result["gaps"] if gap["code"] == "parser_error"]
    assert len(errors) == 1 and errors[0]["scope_id"].startswith("bad/package.json")
    assert errors[0]["reason"] in doc["gaps"]


@pytest.mark.parametrize("kind", ["android", "java", "apply-false"])
def test_packaging_bound_preserves_discovered_android_profile(tmp_path, kind):
    unit = context(tmp_path, SYSTEMS)
    plugin = {
        "android": "id 'com.android.application'",
        "java": "id 'java'",
        "apply-false": "id 'com.android.application' version '8.1' apply false",
    }[kind]
    raw = (f"plugins {{ {plugin} }}\nandroid {{ compileSdk 35 }}\n"
           + "// padding\n" * 7000).encode()
    entry = source(unit, "build.gradle", raw, None)
    unit.outputs[PARTITION] = partition([entry])
    discovered = handler(SYSTEMS)(unit)
    unit.outputs[SYSTEMS] = discovered
    unit.unit_id = TARGETS
    result = handler(TARGETS)(unit)
    validate_unit_output(result, unit_id=TARGETS, strict_gaps=True)
    [target] = document(unit, result)["targets"]
    assert target["descriptor_package"]["documents"] == []
    assert target["descriptor_package"]["gaps"] == [
        "build.gradle: descriptor content omitted by byte bound"]
    assert target["required_image_profile"] == ("android" if kind == "android" else "java")
    if kind == "android":
        assert target["descriptor_facts"] == discovered["build_units"][0]["descriptor_facts"]
        assert target["descriptor_facts"]["compile_sdk"] == "35"
        assert target["project_type"] == "android-gradle-application"
    else:
        assert target["descriptor_facts"] == {} and target["project_type"] == "generic"


@pytest.mark.parametrize("case", ["missing", "no-manifest", "other", "syntax", "unicode"])
def test_dependency_parser_preserves_gap_reason_and_component_or_file_scope(tmp_path, case):
    unit = context(tmp_path, DEPENDENCIES)
    manifest = None if case == "no-manifest" else "Cargo.toml" if case == "other" else "package.json"
    if case in {"syntax", "unicode"}:
        source(unit, manifest, b"{" if case == "syntax" else b"\xff", None)
    unit.outputs[COMPONENTS] = {"components": [
        {"component_id": "component:0001", "manifest": manifest, "manifest_sha256": "hash"}]}
    result = handler(DEPENDENCIES)(unit)
    validate_unit_output(result, unit_id=DEPENDENCIES, strict_gaps=True)
    assert result["dependencies"] == []
    expected_reason = {
        "missing": "package.json: parse failed (FileNotFoundError)",
        "no-manifest": "component:0001: no manifest for dependency extraction",
        "other": "Cargo.toml: dependency parser deferred for this manifest type",
        "syntax": "package.json: parse failed (JSONDecodeError)",
        "unicode": "package.json: parse failed (UnicodeDecodeError)",
    }[case]
    [gap] = result["gaps"]
    assert gap["reason"] == expected_reason
    assert gap["code"] == ("parser_error" if case in {"missing", "syntax", "unicode"} else "producer_reported_gap")
