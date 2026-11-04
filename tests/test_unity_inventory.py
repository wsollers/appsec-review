from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import appsec_review.jobs.engine_discovery as discovery
from appsec_review.jobs.engine_contracts import ENGINE_METADATA_SCHEMA, UNITY_FINGERPRINT_SCHEMA
from appsec_review.jobs.engine_discovery import discover_unity, unity_configuration_fingerprint
from appsec_review.jobs.job_dependency_intelligence.discovery import discover_native_dependencies
from appsec_review.jobs.job_dependency_intelligence.integration import (
    collect_unity_inventory, publish_sbom, validate_publication,
)
from appsec_review.jobs.job_dependency_intelligence.native_sbom_contracts import NativeBounds, SbomBounds
from appsec_review.jobs.job_dependency_intelligence.sbom import build_spdx, validate_spdx
from appsec_review.jobs.job_dependency_intelligence.unity import enrich_unity_spdx
from appsec_review.storage import atomic_json
from appsec_review.storage.shared import reference


FIXTURE = Path(__file__).parent / "fixtures" / "unity_inventory"
SNAPSHOT = "a" * 64
BOUNDS = SbomBounds(1_000_000, 10_000, 2_000_000, 8192)
NATIVE_BOUNDS = NativeBounds(100, 100, 100, 262144, 1048576, 100, 100, 100, 8192, 1024)


def fixture_files() -> dict[str, bytes]:
    result = {path.relative_to(FIXTURE).as_posix(): path.read_bytes()
              for path in FIXTURE.rglob("*") if path.is_file()}
    result["Assets/Plugins/sample.dll"] = b"cataloged plugin bytes, not executed or analyzed"
    result["Assets/Scenes/Game.unity"] = b"scene data is not a package"
    result["Assets/unidentified.so"] = b"no importer, not a package"
    return result


def records(payloads):
    return [{"path": path, "sha256": hashlib.sha256(payload).hexdigest(), "size_bytes": len(payload)}
            for path, payload in payloads.items()]


def parse(payloads=None, *, read=None):
    payloads = fixture_files() if payloads is None else payloads
    return discover_unity(records(payloads), read_text=read or (
        lambda record, limit: payloads[record["path"]][:limit + 1]))


def native_discovery():
    result = discover_native_dependencies(
        source_fingerprint=SNAPSHOT, files=[], invocations=[], artifacts=[],
        read_file=lambda _record, _limit: b"", bounds=NATIVE_BOUNDS)
    return {**result, "source_fingerprint": SNAPSHOT}


def base_result(*, baselines=()):
    return build_spdx(source_fingerprint=SNAPSHOT, created="2026-11-04T00:00:00Z",
                      baselines=baselines, discovery=native_discovery(),
                      input_identities=[], bounds=BOUNDS)


def test_real_descriptors_validate_root_and_preserve_raw_configuration():
    seen = []
    files = fixture_files()

    def read(record, limit):
        assert set(record) == {"path", "sha256", "size_bytes"}
        assert 0 < limit <= discovery.MAX_DESCRIPTOR_BYTES
        seen.append(record["path"])
        return files[record["path"]]

    result = parse(files, read=read)
    assert len(result["projects"]) == 1
    project = result["projects"][0]
    assert project["root"] == "."
    assert project["engine"] == {
        "kind": "unity", "declared_version": "2022.3.20f1", "declared_revision": "61c2feb0970d"}
    facts = project["descriptor_facts"]
    assert facts["root_state"] == "validated" and facts["engine_conflict"] is False
    assert facts["raw_settings"]["scriptingBackend"] == {"Android": 0, "Standalone": 1}
    assert facts["raw_settings"]["iOSSDKVersion"] == 988
    assert facts["raw_settings"]["scriptingDefineSymbols"]["Standalone"] == "UNITY_EDITOR;FEATURE_GAME"
    assert facts["scenes"][0]["path"] == "Assets/Scenes/Game.unity"
    assert "licenseKey" not in facts["raw_settings"]
    assert "Assets/Scenes/Game.unity" not in seen
    assert "Assets/Plugins/sample.dll" not in seen
    assert result["counts"]["read_descriptors"] == len(seen)
    assert result["gaps"] == []


def test_regional_editor_source_stamp_and_revision_are_preserved_exactly():
    files = fixture_files()
    files["ProjectSettings/ProjectVersion.txt"] = (
        b"m_EditorVersion: 2022.3.62f2c1\n"
        b"m_EditorVersionWithRevision: 2022.3.62f2c1 (61c2feb0970d)\n")
    unity = parse(files)
    assert len(unity["projects"]) == 1
    project = unity["projects"][0]
    assert project["engine"] == {
        "kind": "unity", "declared_version": "2022.3.62f2c1", "declared_revision": "61c2feb0970d"}
    fingerprint = unity_configuration_fingerprint(project, SNAPSHOT)
    assert fingerprint["inputs"]["engine"] == project["engine"]
    spdx = enrich_unity_spdx(base_result(), unity, source_fingerprint=SNAPSHOT, bounds=BOUNDS)
    editor = next(item for item in spdx["document"]["packages"] if item["name"] == "Unity Editor")
    assert editor["versionInfo"] == "2022.3.62f2c1"
    assert json.loads(editor["comment"])["declared_revision"] == "61c2feb0970d"


@pytest.mark.parametrize("iphone_setting,expected", [
    ("  iPhoneSdkVersion: 988\n", 988),
    ("  iPhoneSdkVersion:\n    iPhone: 988\n    Simulator: 989\n", {"iPhone": 988, "Simulator": 989}),
])
def test_platform_architecture_and_iphone_sdk_raw_values_survive_discovery_and_fingerprint(
    iphone_setting, expected,
):
    files = fixture_files()
    files["ProjectSettings/ProjectSettings.asset"] += (
        "  platformArchitecture:\n    Standalone: 1\n    iPhone: 2\n" + iphone_setting).encode()
    project = parse(files)["projects"][0]
    settings = project["descriptor_facts"]["raw_settings"]
    assert settings["platformArchitecture"] == {"Standalone": 1, "iPhone": 2}
    assert settings["iPhoneSdkVersion"] == expected
    fingerprint = unity_configuration_fingerprint(project, SNAPSHOT)
    assert fingerprint["inputs"]["settings"]["platformArchitecture"] == settings["platformArchitecture"]
    assert fingerprint["inputs"]["settings"]["iPhoneSdkVersion"] == expected
    project["descriptor_facts"]["raw_settings"]["platformArchitecture"]["Standalone"] = 0
    assert unity_configuration_fingerprint(project, SNAPSHOT)["sha256"] != fingerprint["sha256"]


def test_declarations_resolution_builtin_context_and_assembly_evidence_are_distinct():
    inventory = parse()["projects"][0]["inventory"]
    assert len(inventory["declarations"]) == 3
    assert next(item for item in inventory["declarations"]
                if item["name"] == "com.example.direct")["requested"] == "^1.0.0"
    assert next(item for item in inventory["resolutions"]
                if item["name"] == "com.example.direct")["version"] == "1.2.0"
    assert all(not item["name"].startswith("com.unity.modules.") for item in inventory["resolutions"])
    assert {item["name"] for item in inventory["engine_context"]} == {"com.unity.modules.physics"}
    assert inventory["embedded_packages"][0]["name"] == "com.example.embedded"
    assert len(inventory["assemblies"]) == 3
    mixed = next(item for item in inventory["assemblies"] if item["path"].endswith("Mixed.asmdef"))
    assert mixed["facts"]["includePlatforms"] == ["Editor", "WindowsStandalone64"]
    assert mixed["facts"]["defineConstraints"] == ["FEATURE_GAME"]
    assert [item["name"] for item in inventory["plugins"]] == ["sample.dll"]
    assert inventory["plugins"][0]["importer"]["platformData"][0]["second"]["enabled"] == 1


@pytest.mark.parametrize("files", [
    {"Assets/Game.unity": b"scene", "Assets/test.asmdef": b'{"name":"Game"}'},
    {"ProjectSettings/ProjectVersion.txt": b"m_EditorVersion: 2022.3.20f1\n"},
    {"Packages/manifest.json": b'{"dependencies":{}}'},
    {"ProjectSettings/ProjectVersion.txt": b"m_EditorVersion: definitely not Unity\n",
     "Packages/manifest.json": b'{"dependencies":{}}'},
    {"ProjectSettings/ProjectVersion.txt": b"m_EditorVersion: 2022.3.20f1\n",
     "Packages/manifest.json": b'{"dependencies":[]}'},
])
def test_false_or_incomplete_roots_are_not_authoritative_projects(files):
    result = parse(files)
    assert not result["projects"]
    if "ProjectSettings/ProjectVersion.txt" in files or "Packages/manifest.json" in files:
        assert any(item["root_state"] == "incomplete" for item in result["observations"])
        assert result["gaps"]


def test_manifest_corroborates_version_without_settings_and_names_missing_resolution():
    result = parse({"game/ProjectSettings/ProjectVersion.txt": b"m_EditorVersion: 6000.0.1f1\n",
                    "game/Packages/manifest.json": b'{"dependencies":{"com.example.a":"1.0.0"}}'})
    assert result["projects"][0]["root"] == "game"
    assert result["projects"][0]["engine"]["declared_revision"] is None
    assert any("dependency_resolution_unavailable" in gap for gap in result["gaps"])


def test_settings_corroborate_without_manifest_but_dependencies_are_a_gap():
    files = {path: payload for path, payload in fixture_files().items()
             if path.startswith("ProjectSettings/")}
    project = parse(files)["projects"][0]
    assert project["descriptor_facts"]["root_state"] == "validated"
    assert any("dependency_declarations_unavailable" in gap for gap in project["gaps"])


@pytest.mark.parametrize("replacement", [
    b"m_EditorVersion: 2022.3.20f1\nm_EditorVersionWithRevision: 2021.1.1f1 (abcdef123456)\n",
    b"m_EditorVersion: 2022.3.20f1\nm_EditorVersion: 2022.3.20f1\n",
])
def test_version_content_not_filename_establishes_unity_identity(replacement):
    files = fixture_files()
    files["ProjectSettings/ProjectVersion.txt"] = replacement
    result = parse(files)
    assert result["projects"] == []
    assert any("descriptor_unavailable_invalid_or_uninspected" in gap for gap in result["gaps"])


def test_competing_unreal_descriptor_retains_ambiguous_root_and_observations():
    files = fixture_files()
    files["Game.uproject"] = b'{"EngineAssociation":"5.4"}'
    files["Plugin.uplugin"] = b'{"FileVersion":3}'
    result = parse(files)
    facts = result["projects"][0]["descriptor_facts"]
    assert facts["root_state"] == "ambiguous"
    assert facts["engine_conflict"] is True
    assert len(facts["competing_markers"]) == 2
    assert any("competing_engine_descriptors" in gap for gap in result["gaps"])
    assert len([item for item in result["observations"] if item["kind"] == "unreal"]) == 2


def test_nested_roots_do_not_claim_nested_project_packages():
    files = fixture_files()
    files.update({"Assets/Nested/" + path: payload for path, payload in fixture_files().items()})
    result = parse(files)
    assert {project["root"] for project in result["projects"]} == {".", "Assets/Nested"}
    assert all(len(project["inventory"]["assemblies"]) == 3 for project in result["projects"])
    assert all(len(project["inventory"]["plugins"]) == 1 for project in result["projects"])


def test_content_identified_packages_supported_but_arbitrary_package_json_not_identity():
    files = fixture_files()
    files["Assets/Content/package.json"] = b'{"name":"com.example.content","version":"1.0.0","unity":"2022.3"}'
    files["Assets/Random/package.json"] = b'{"name":"not-a-unity-package","version":"1.0.0"}'
    files["package.json"] = b'{"name":"not-unity","version":"1.0.0"}'
    result = parse(files)
    packages = result["projects"][0]["inventory"]["embedded_packages"]
    assert {item["name"] for item in packages} == {"com.example.embedded", "com.example.content"}
    assert any("unidentified_package_metadata" in gap for gap in result["gaps"])


@pytest.mark.parametrize("path", ["../ProjectSettings/ProjectVersion.txt", "/Packages/manifest.json",
                                  "Packages\\manifest.json", "Packages/../manifest.json",
                                  "C:/Packages/manifest.json", "./Packages/manifest.json"])
def test_noncanonical_catalog_paths_never_reach_reader(path):
    result = discover_unity([{"path": path, "sha256": "a" * 64, "size_bytes": 4}],
                            read_text=lambda *_: pytest.fail("unsafe path read"))
    assert result["gaps"] == ["invalid_catalog_descriptor: path/hash/size"]
    assert result["projects"] == []


def test_catalog_conflicts_and_invalid_hash_size_are_not_read():
    file = {"path": "Packages/manifest.json", "sha256": "a" * 64, "size_bytes": 4}
    result = discover_unity([file, {**file, "sha256": "b" * 64},
                            {"path": "x", "sha256": "invalid", "size_bytes": -1}],
                            read_text=lambda *_: pytest.fail("rejected descriptor read"))
    assert any("conflicting_catalog_descriptor" in gap for gap in result["gaps"])
    assert any("invalid_catalog_descriptor" in gap for gap in result["gaps"])


def test_callback_identity_change_unavailable_decode_and_symlink_are_named_gaps(tmp_path):
    files = fixture_files()
    assert any("descriptor_unavailable" in gap for gap in parse(
        files, read=lambda *_: b"tampered")["gaps"])
    assert any("descriptor_unavailable" in gap for gap in parse(
        files, read=lambda *_: (_ for _ in ()).throw(OSError("unavailable")))["gaps"])
    files["Packages/manifest.json"] = b"\xff"
    assert any("descriptor_unavailable" in gap for gap in parse(files)["gaps"])
    target = tmp_path / "source"
    target.mkdir()
    (target / "ProjectSettings").symlink_to(FIXTURE / "ProjectSettings", target_is_directory=True)
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target, source_fingerprint=SNAPSHOT))
    result = collect_unity_inventory(unit, [
        {**item, "domain": "target"} for item in records(fixture_files())])
    assert result["projects"] == []
    assert any("descriptor_unavailable" in gap for gap in result["gaps"])


def test_bounded_file_bytes_total_and_items_report_uninspected_content(monkeypatch):
    files = fixture_files()
    monkeypatch.setattr(discovery, "MAX_DESCRIPTOR_BYTES", 10)
    result = parse(files, read=lambda *_: pytest.fail("oversized descriptor read"))
    assert result["counts"]["uninspected_descriptors"] > 0
    assert result["projects"] == []
    monkeypatch.setattr(discovery, "MAX_DESCRIPTOR_BYTES", 262144)
    monkeypatch.setattr(discovery, "MAX_TOTAL_BYTES", 150)
    result = parse(files)
    assert result["counts"]["bytes_read"] <= 150
    assert result["counts"]["uninspected_descriptors"] > 0
    monkeypatch.setattr(discovery, "MAX_FILES", 1)
    assert any("catalog_file_limit" in gap for gap in parse(files)["gaps"])


def test_root_bound_retains_uninspected_root_observations(monkeypatch):
    files = {"first/" + path: payload for path, payload in fixture_files().items()}
    files.update({"second/" + path: payload for path, payload in fixture_files().items()})
    monkeypatch.setattr(discovery, "MAX_ROOTS", 1)
    result = parse(files)
    assert len(result["projects"]) == 1
    assert result["counts"]["uninspected_roots"] == 1
    assert any(item["root_state"] == "uninspected" for item in result["observations"])
    assert any("unity_root_limit" in gap for gap in result["gaps"])


@pytest.mark.parametrize("payload", [
    b'{"dependencies":{},"dependencies":{}}',
    b'{"dependencies":{"com.example.a":NaN}}',
    json.dumps({"dependencies": {f"com.example.p{i}": "1.0.0" for i in range(5000)}}).encode(),
])
def test_malformed_or_item_bounded_json_is_a_named_gap(payload):
    files = fixture_files()
    files["Packages/manifest.json"] = payload
    result = parse(files)
    assert len(result["projects"]) == 1  # independent valid settings still corroborate the root
    assert not result["projects"][0]["descriptor_facts"]["manifest_inspected"]
    assert any("descriptor_unavailable" in gap for gap in result["gaps"])


def test_yaml_aliases_cannot_expand_unbounded_content():
    files = fixture_files()
    files["ProjectSettings/ProjectSettings.asset"] = b"PlayerSettings:\n  x: &x [1,2]\n  y: *x\n"
    result = parse(files)
    assert result["projects"]
    assert any("ProjectSettings.asset" in gap for gap in result["gaps"])


def test_fingerprint_canonical_inputs_unknowns_and_secret_redaction():
    project = parse()["projects"][0]
    partial = unity_configuration_fingerprint(project, SNAPSHOT)
    assert partial["schema"] == UNITY_FINGERPRINT_SCHEMA
    assert partial["status"] == "partial"
    assert {"recipe", "toolchain", "target_platform", "architecture", "scripting_backend", "sdk",
            "dependency_resolution"} <= set(partial["unknown_inputs"])
    build = {"recipe": {"entrypoint": "Build.Perform", "password": "do-not-publish"},
             "toolchain": {"image_id": "sha256:abc", "modules": ["linux", "windows"],
                           "token": "do-not-publish"},
             "target_platform": "StandaloneLinux64", "architecture": "x86_64",
             "scripting_backend": "IL2CPP", "sdk": "sdk-1"}
    original = unity_configuration_fingerprint(project, SNAPSHOT, build)
    shuffled = deepcopy(project)
    shuffled["inventory"]["assemblies"].reverse()
    shuffled["inventory"]["declarations"].reverse()
    shuffled["markers"].reverse()
    reverse_build = deepcopy(build)
    reverse_build["toolchain"]["modules"].reverse()
    assert unity_configuration_fingerprint(shuffled, SNAPSHOT, reverse_build) == original
    assert "do-not-publish" not in json.dumps(original)
    assert original["sha256"] != partial["sha256"]
    assert unity_configuration_fingerprint(project, "b" * 64, build)["sha256"] != original["sha256"]
    changed = deepcopy(project)
    changed["descriptor_facts"]["raw_settings"]["scriptingBackend"]["Standalone"] = 0
    assert unity_configuration_fingerprint(changed, SNAPSHOT, build)["sha256"] != original["sha256"]
    assert original["status"] == "partial"  # unresolved declared Git request
    project["inventory"]["declarations"] = [
        item for item in project["inventory"]["declarations"] if item["name"] != "com.example.unresolved"]
    assert {"plugin_version:Assets/Plugins/sample.dll", "plugin_provenance:Assets/Plugins/sample.dll"} <= set(
        unity_configuration_fingerprint(project, SNAPSHOT, build)["unknown_inputs"])
    project["inventory"]["plugins"] = []
    assert unity_configuration_fingerprint(project, SNAPSHOT, build)["status"] == "complete"


def test_fingerprint_descriptor_hashes_are_evidence_not_configuration_or_package_identity():
    project = parse()["projects"][0]
    original = unity_configuration_fingerprint(project, SNAPSHOT)
    changed = deepcopy(project)
    changed["markers"][0]["sha256"] = "b" * 64
    changed["inventory"]["declarations"][0]["evidence"]["sha256"] = "c" * 64
    assert unity_configuration_fingerprint(changed, SNAPSHOT) == original
    changed["inventory"]["plugins"][0]["path"] = "Assets/Plugins/different.dll"
    assert unity_configuration_fingerprint(changed, SNAPSHOT)["sha256"] != original["sha256"]


def test_fingerprint_normalizes_unordered_defines_but_preserves_recipe_and_scene_order():
    project = parse()["projects"][0]
    project["descriptor_facts"]["raw_settings"]["scriptingDefineSymbols"]["Standalone"] = "ONE;TWO"
    original = unity_configuration_fingerprint(project, SNAPSHOT, {"recipe": {"argv": ["-a", "-b"]}})
    changed = deepcopy(project)
    changed["descriptor_facts"]["raw_settings"]["scriptingDefineSymbols"]["Standalone"] = "TWO;ONE"
    assert unity_configuration_fingerprint(changed, SNAPSHOT, {"recipe": {"argv": ["-a", "-b"]}}) == original
    assert unity_configuration_fingerprint(changed, SNAPSHOT, {"recipe": {"argv": ["-b", "-a"]}}) != original
    changed["descriptor_facts"]["scenes"].append({"path": "Assets/Second.unity", "enabled": 1})
    before = unity_configuration_fingerprint(changed, SNAPSHOT)
    changed["descriptor_facts"]["scenes"].reverse()
    assert unity_configuration_fingerprint(changed, SNAPSHOT)["sha256"] != before["sha256"]


def test_unknown_sdk_and_missing_git_revision_stay_explicitly_partial():
    project = parse()["projects"][0]
    project["inventory"]["resolutions"].append({
        "name": "com.example.unresolved", "source": "git", "version": "https://example.invalid/repo.git#main"})
    fingerprint = unity_configuration_fingerprint(project, SNAPSHOT, {
        "recipe": "build", "toolchain": "image", "target_platform": "Linux",
        "scripting_backend": "IL2CPP", "sdk": "unknown"})
    assert fingerprint["status"] == "partial"
    assert {"sdk", "dependency_revision:com.example.unresolved"} <= set(fingerprint["unknown_inputs"])


def test_dependency_url_credentials_not_published_or_fingerprinted():
    files = fixture_files()
    files["Packages/manifest.json"] = json.dumps({
        "dependencies": {"com.example.private": "https://user:password@example.invalid/repo.git?token=secret#rev"}
    }).encode()
    unity = parse(files)
    project = unity["projects"][0]
    assert project["inventory"]["declarations"][0]["requested"] == "https://example.invalid/repo.git#rev"
    encoded = json.dumps(unity_configuration_fingerprint(project, SNAPSHOT))
    assert "password" not in encoded and "secret" not in encoded and "?token" not in encoded


def test_fingerprint_removes_license_and_argv_credentials_without_erasing_package_token_names():
    files = fixture_files()
    files["Packages/com.example.embedded/package.json"] = (
        b'{"name":"com.example.embedded","version":"0.4.0","dependencies":{"com.example.token":"1.0.0"}}')
    project = parse(files)["projects"][0]
    fingerprint = unity_configuration_fingerprint(project, SNAPSHOT, {
        "recipe": {"argv": ["build", "--token", "sensitive-value"]},
        "toolchain": {"environment": {"UNITY_LICENSE": "sensitive-license"}},
    })
    encoded = json.dumps(fingerprint)
    assert "sensitive-value" not in encoded and "sensitive-license" not in encoded
    assert "com.example.token" in encoded


def test_builtin_source_is_context_even_without_unity_modules_prefix():
    files = fixture_files()
    manifest = json.loads(files["Packages/manifest.json"])
    lock = json.loads(files["Packages/packages-lock.json"])
    manifest["dependencies"]["com.unity.custom-builtin"] = "1.0.0"
    lock["dependencies"]["com.unity.custom-builtin"] = {
        "version": "1.0.0", "source": "builtin", "dependencies": {}}
    lock["dependencies"]["com.example.direct"]["dependencies"]["com.unity.custom-builtin"] = "1.0.0"
    files["Packages/manifest.json"] = json.dumps(manifest).encode()
    files["Packages/packages-lock.json"] = json.dumps(lock).encode()
    unity = parse(files)
    inventory = unity["projects"][0]["inventory"]
    assert "com.unity.custom-builtin" not in {item["name"] for item in inventory["declarations"]}
    enriched = enrich_unity_spdx(base_result(), unity, source_fingerprint=SNAPSHOT, bounds=BOUNDS)
    builtin = next(item for item in enriched["document"]["packages"]
                   if item["name"] == "com.unity.custom-builtin")
    assert builtin["versionInfo"] == "1.0.0"
    metadata = json.loads(builtin["comment"])
    assert metadata["kind"] == "builtin-module"
    assert metadata["declared_engine"] == unity["projects"][0]["engine"]


def test_builtin_spdx_keeps_requested_and_locked_versions_evidence_and_dependency_graph():
    files = fixture_files()
    manifest = json.loads(files["Packages/manifest.json"])
    lock = json.loads(files["Packages/packages-lock.json"])
    manifest["dependencies"]["com.unity.modules.physics"] = "0.9.0"
    lock["dependencies"]["com.unity.modules.physics"]["dependencies"] = {
        "com.unity.modules.submodule": "0.5.0"}
    lock["dependencies"]["com.unity.modules.submodule"] = {
        "version": "0.6.0", "source": "builtin", "depth": 1, "dependencies": {}}
    files["Packages/manifest.json"] = json.dumps(manifest).encode()
    files["Packages/packages-lock.json"] = json.dumps(lock).encode()
    unity = parse(files)
    enriched = enrich_unity_spdx(base_result(), unity, source_fingerprint=SNAPSHOT, bounds=BOUNDS)
    document = enriched["document"]
    validate_spdx(document, bounds=BOUNDS)
    by_name = {item["name"]: item for item in document["packages"]}
    physics, child = by_name["com.unity.modules.physics"], by_name["com.unity.modules.submodule"]
    assert physics["versionInfo"] == "1.0.0"  # Not the editor stamp or manifest's requested version.
    assert child["versionInfo"] == "0.6.0"
    metadata = json.loads(physics["comment"])
    assert metadata["requested"] == "0.9.0"
    assert metadata["resolution"] == "1.0.0"
    assert metadata["declared_engine"] == unity["projects"][0]["engine"]
    source = enriched["provenance"]["packages"][physics["SPDXID"]]["engine_metadata"]
    assert source["declaration_evidence"][0]["path"] == "Packages/manifest.json"
    assert source["resolution_evidence"][0]["path"] == "Packages/packages-lock.json"
    assert source["editor_evidence"][0]["path"] == "ProjectSettings/ProjectVersion.txt"
    for package in (physics, child):
        assert package["filesAnalyzed"] is False
        assert package["downloadLocation"] == package["licenseDeclared"] == "NOASSERTION"
        assert not {"checksums", "packageVerificationCode", "externalRefs", "hasFiles"} & package.keys()
    expected_edges = {
        ("Unity project .", "com.unity.modules.physics", "0.9.0"),
        ("com.example.direct", "com.unity.modules.physics", "1.0.0"),
        ("com.unity.modules.physics", "com.unity.modules.submodule", "0.5.0"),
    }
    id_to_name = {item["SPDXID"]: item["name"] for item in document["packages"]}
    actual_edges = {
        (id_to_name[edge["spdxElementId"]], id_to_name[edge["relatedSpdxElement"]],
         json.loads(edge["comment"]).get("requested"))
        for edge in document["relationships"] if edge["relationshipType"] == "DEPENDS_ON"
    }
    assert expected_edges <= actual_edges
    assert not any(edge["relationshipType"] == "CONTAINS" for edge in document["relationships"])


def test_spdx_preserves_mixed_editor_and_unknown_scopes_without_claiming_delivery():
    unity = parse()
    document = enrich_unity_spdx(base_result(), unity, source_fingerprint=SNAPSHOT, bounds=BOUNDS)["document"]
    project = next(item for item in document["packages"] if item["name"] == "Unity project .")
    metadata = json.loads(project["comment"])
    assemblies = {item["path"]: item for item in metadata["assembly_scope_observations"]}
    assert assemblies["Assets/Editor/EditorOnly.asmdef"]["contexts"] == ["editor"]
    assert assemblies["Assets/Scripts/Mixed.asmdef"]["contexts"] == ["editor", "runtime-capable"]
    assert assemblies["Assets/Scripts/Mixed.asmref"]["contexts"] == ["unknown"]
    assert all(item["delivery_status"] == "unknown" for item in assemblies.values())
    settings = metadata["configuration_observations"]
    assert settings["raw_settings"]["iOSSDKVersion"] == 988
    assert settings["basis"] == "configuration_presence_not_selected_targets_or_shipment"
    assert settings["descriptor_evidence"]
    assert all(json.loads(item["comment"])["delivery_status"] == "unknown" for item in document["packages"])
    validate_spdx(document, bounds=BOUNDS)


def test_invalid_assembly_filter_remains_a_gap_not_a_guessed_scope():
    files = fixture_files()
    files["Assets/Editor/EditorOnly.asmdef"] = b'{"name":"EditorOnly","includePlatforms":42}'
    unity = parse(files)
    assert any("invalid_assembly_platform_filter" in gap for gap in unity["gaps"])
    result = enrich_unity_spdx(base_result(), unity, source_fingerprint=SNAPSHOT, bounds=BOUNDS)
    package = next(item for item in result["document"]["packages"] if item["name"] == "Unity project .")
    scopes = json.loads(package["comment"])["assembly_scope_observations"]
    observed = next(item for item in scopes if item["path"] == "Assets/Editor/EditorOnly.asmdef")
    assert observed["contexts"] == ["unknown"] and observed["basis"] == "invalid_assembly_platform_filters"
    assert result["gaps"]


@pytest.mark.parametrize("other_version,other_revision", [
    ("2022.3.62f2c1", "123456abcdef"),
    ("2022.3.20f1", "123456abcdef"),
])
def test_builtin_package_identity_is_qualified_by_exact_declared_editor_context(
    other_version, other_revision,
):
    first = parse()
    files = fixture_files()
    files["ProjectSettings/ProjectVersion.txt"] = (
        f"m_EditorVersion: {other_version}\n"
        f"m_EditorVersionWithRevision: {other_version} ({other_revision})\n").encode()
    second = parse(files)
    results = [enrich_unity_spdx(base_result(), unity, source_fingerprint=SNAPSHOT, bounds=BOUNDS)
               for unity in (first, second)]
    modules = [next(item for item in result["document"]["packages"]
                    if item["name"] == "com.unity.modules.physics") for result in results]
    assert modules[0]["SPDXID"] != modules[1]["SPDXID"]
    assert all(item["versionInfo"] == "1.0.0" for item in modules)
    assert json.loads(modules[0]["comment"])["declared_engine"] == first["projects"][0]["engine"]
    assert json.loads(modules[1]["comment"])["declared_engine"] == second["projects"][0]["engine"]


def test_builtin_declaration_without_lock_resolution_does_not_invent_a_resolved_release():
    files = fixture_files()
    lock = json.loads(files["Packages/packages-lock.json"])
    del lock["dependencies"]["com.unity.modules.physics"]
    files["Packages/packages-lock.json"] = json.dumps(lock).encode()
    enriched = enrich_unity_spdx(base_result(), parse(files), source_fingerprint=SNAPSHOT, bounds=BOUNDS)
    builtin = next(item for item in enriched["document"]["packages"]
                   if item["name"] == "com.unity.modules.physics")
    assert "versionInfo" not in builtin
    metadata = json.loads(builtin["comment"])
    assert metadata["requested"] == "1.0.0" and metadata["resolution"] is None




def test_competing_embedded_identities_are_retained_not_silently_selected():
    files = fixture_files()
    files["Assets/Alternate/package.json"] = (
        b'{"name":"com.example.embedded","version":"9.0.0","type":"asset"}')
    unity = parse(files)
    assert any("competing_embedded_package_metadata" in gap for gap in unity["gaps"])
    enriched = enrich_unity_spdx(base_result(), unity, source_fingerprint=SNAPSHOT, bounds=BOUNDS)
    variants = [item for item in enriched["document"]["packages"]
                if json.loads(item["comment"])["kind"] == "embedded-package-candidate"]
    assert {item["versionInfo"] for item in variants} == {"0.4.0", "9.0.0"}


def test_lock_embedded_version_conflict_does_not_assert_an_arbitrary_release():
    files = fixture_files()
    files["Packages/com.example.embedded/package.json"] = (
        b'{"name":"com.example.embedded","version":"9.0.0","dependencies":{}}')
    unity = parse(files)
    assert any("dependency_version_conflict" in gap for gap in unity["gaps"])
    enriched = enrich_unity_spdx(base_result(), unity, source_fingerprint=SNAPSHOT, bounds=BOUNDS)
    package = next(item for item in enriched["document"]["packages"] if item["name"] == "com.example.embedded")
    assert "versionInfo" not in package
    metadata = json.loads(package["comment"])
    assert metadata["version_conflict"] is True
    assert metadata["locked_version"] == "0.4.0" and metadata["metadata_version"] == "9.0.0"
    assert any(gap["kind"] == "version_conflict" for gap in enriched["gaps"])


def test_spdx_metadata_only_packages_edges_comments_and_real_schema_validation():
    unity = parse()
    original = base_result()
    result = enrich_unity_spdx(original, unity, source_fingerprint=SNAPSHOT, bounds=BOUNDS)
    assert original["document"]["packages"] == []
    document = result["document"]
    validate_spdx(document, bounds=BOUNDS)
    by_name = {item["name"]: item for item in document["packages"]}
    assert set(by_name) == {"Unity project .", "Unity Editor", "com.example.direct",
                            "com.example.transitive", "com.example.embedded",
                            "com.example.unresolved", "com.unity.modules.physics", "sample.dll"}
    assert by_name["com.example.direct"]["versionInfo"] == "1.2.0"
    assert "versionInfo" not in by_name["com.example.unresolved"]
    assert by_name["Unity Editor"]["versionInfo"] == "2022.3.20f1"
    for package in by_name.values():
        assert package["filesAnalyzed"] is False
        assert package["downloadLocation"] == package["licenseDeclared"] == "NOASSERTION"
        assert not {"checksums", "packageVerificationCode", "externalRefs", "hasFiles"} & package.keys()
        assert json.loads(package["comment"])["schema"] == ENGINE_METADATA_SCHEMA
    edges = document["relationships"]
    assert all(edge["relationshipType"] != "CONTAINS" for edge in edges)
    project_id, editor_id = by_name["Unity project ."]["SPDXID"], by_name["Unity Editor"]["SPDXID"]
    assert any(edge["spdxElementId"] == editor_id and edge["relatedSpdxElement"] == project_id
               and edge["relationshipType"] == "BUILD_DEPENDENCY_OF" for edge in edges)
    direct_ids = {edge["relatedSpdxElement"] for edge in edges
                  if edge["spdxElementId"] == project_id and edge["relationshipType"] == "DEPENDS_ON"}
    assert by_name["com.example.direct"]["SPDXID"] in direct_ids
    assert by_name["com.example.transitive"]["SPDXID"] not in direct_ids
    parent_edge = next(edge for edge in edges
                       if edge["spdxElementId"] == by_name["com.example.direct"]["SPDXID"]
                       and edge["relatedSpdxElement"] == by_name["com.example.transitive"]["SPDXID"])
    assert json.loads(parent_edge["comment"])["requested"] == "2.0.0"
    assert set(result["provenance"]["packages"]) == {item["SPDXID"] for item in document["packages"]}
    assert result["metrics"]["output_packages"] == 8


def test_spdx_preserves_baseline_inventory_and_does_not_infer_package_scope_from_name():
    baseline = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "source baseline", "documentNamespace": "urn:fixture:source",
        "creationInfo": {"creators": ["Tool: fixture"], "created": "2026-11-04T00:00:00Z"},
        "packages": [{"SPDXID": "SPDXRef-Other", "name": "retained", "filesAnalyzed": False,
                      "downloadLocation": "NOASSERTION", "versionInfo": "1.0.0"}],
    }
    ref = {"path": "data/baseline.json", "sha256": "b" * 64, "size_bytes": 1000}
    result = base_result(baselines=[{"document": baseline, "artifact": ref, "source_artifact": ref,
                                   "tool_identity": {"tool_id": "fixture"}}])
    before = deepcopy(result["document"]["packages"])
    enriched = enrich_unity_spdx(result, parse(), source_fingerprint=SNAPSHOT, bounds=BOUNDS)
    assert all(item in enriched["document"]["packages"] for item in before)
    assert not any("scope" in json.loads(package["comment"]) for package in enriched["document"]["packages"]
                   if package["name"].startswith("com.example."))


def test_dependency_job_reads_accepted_target_files_without_engine_catalog_fields(tmp_path):
    files = fixture_files()
    target = tmp_path / "source"
    for relative, payload in files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target, source_fingerprint=SNAPSHOT))
    catalog = [{**item, "domain": "target"} for item in records(files)]
    catalog.append({"domain": "workspace", "path": "../do-not-read", "sha256": "b" * 64, "size_bytes": 1})
    result = collect_unity_inventory(unit, catalog)
    assert result["projects"][0]["engine"]["kind"] == "unity"
    assert result["projects"][0]["configuration_fingerprint"]["status"] == "partial"
    assert result["gaps"] == []


def test_real_publication_keeps_inventory_without_unity_or_language_executor(tmp_path):
    run_root = tmp_path / "run"
    unit_root = run_root / "data" / "publication"
    unit_root.mkdir(parents=True)
    settings = {
        "native_candidate_limit": 100, "command_token_limit": 100, "metadata_file_limit": 100,
        "metadata_bytes_per_file": 262144, "native_source_bytes_limit": 1048576,
        "native_root_limit": 100, "native_evidence_limit": 100, "native_evidence_per_candidate": 100,
        "native_field_bytes": 8192, "native_path_chars": 1024,
        "sbom_input_bytes": BOUNDS.input_bytes, "sbom_element_limit": BOUNDS.element_limit,
        "sbom_output_bytes": BOUNDS.output_bytes,
    }
    values = {"inputs.load_accepted": {
        "native_input_identities": [], "source_syft": None, "native_created": "2026-11-04T00:00:00Z",
        "unity_inventory": parse(),
    }, "resolution.investigate_components": {
        "native_discovery_document": native_discovery(), "artifact": {}, "inference_metrics": {},
    }, "resolution.curate_components": {"artifact": {}, "inference_metrics": {}}}
    events = SimpleNamespace(write=lambda *_args, **_kwargs: None)
    job = SimpleNamespace(run_root=run_root, source_fingerprint=SNAPSHOT,
                          config=SimpleNamespace(settings=settings), events=events,
                          run_id="run", attempt_id="attempt")
    unit = SimpleNamespace(job=job, unit_root=unit_root, unit_id="publication.publish_sbom",
                           output=values.__getitem__)
    published = publish_sbom(unit, None)
    assert published["artifact"] is not None
    document = json.loads((run_root / published["artifact"]["path"]).read_bytes())
    validate_spdx(document, bounds=BOUNDS)
    assert "com.example.direct" in {item["name"] for item in document["packages"]}
    assert published["spec_version"] == "2.3"
    provenance = json.loads((run_root / published["provenance"]["path"]).read_bytes())
    assert provenance["input_fingerprint"] == published["input_fingerprint"]
    assert provenance["unity_metadata"]["project_count"] == 1
    metrics = json.loads((run_root / published["metrics"]["path"]).read_bytes())
    assert metrics["counters"]["output_packages"] == 8
    # Validate exactly the same published artifact and its accepted Unity inventory binding.
    unity = {**values["inputs.load_accepted"]["unity_inventory"],
             "schema": "appsec-review/unity-inventory/1", "source_fingerprint": SNAPSHOT}
    # Re-publish with the complete accepted inventory envelope, as collect_inputs supplies it.
    values["inputs.load_accepted"]["unity_inventory"] = unity
    published = publish_sbom(unit, None)
    unity_path, native_path = unit_root / "unity-inventory.json", unit_root / "native.json"
    atomic_json(unity_path, unity)
    atomic_json(native_path, native_discovery())
    published.pop("inference_metrics")  # Native inference is outside this focused unit's boundary.
    artifact_refs = [published["artifact"], published["provenance"], published["metrics"],
                     reference(run_root, unity_path), reference(run_root, native_path)]
    accepted = {"artifacts": artifact_refs}
    handoff = {"source_fingerprint": SNAPSHOT, "sbom": published,
               "unity_inventory": reference(run_root, unity_path),
               "native_discovery": reference(run_root, native_path)}
    validate_publication(run_root, accepted, handoff)
    unity["projects"][0]["engine"]["declared_version"] = "6000.0.1f1"
    atomic_json(unity_path, unity)
    handoff["unity_inventory"] = reference(run_root, unity_path)
    accepted["artifacts"][-2] = handoff["unity_inventory"]
    with pytest.raises(ValueError, match="Unity inventory provenance differs"):
        validate_publication(run_root, accepted, handoff)
    settings["native_field_bytes"] = 200
    failed = publish_sbom(unit, None)
    assert failed["status"] == "FAILED"
    assert failed["artifact"] is None
    assert any(gap["kind"] == "sbom_validation_failed" for gap in failed["gaps"])
    failed.pop("inference_metrics")
    handoff["sbom"] = failed
    accepted["artifacts"] = [failed["provenance"], failed["metrics"],
                             handoff["unity_inventory"], handoff["native_discovery"]]
    validate_publication(run_root, accepted, handoff)
    assert json.loads(unity_path.read_bytes())["projects"]  # Metadata survives bounded SPDX failure.
