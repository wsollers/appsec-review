from __future__ import annotations

from dataclasses import replace
import hashlib
import importlib.util
import json
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from appsec_review.jobs.job_codeql_analysis.planning import build_codeql_plan
from appsec_review.jobs.job_codeql_analysis.sarif import map_location, normalize_sarif
from appsec_review.config.codeql import parse_codeql_settings
from appsec_review.codeql.runtime import _bounded_stream, load_asset_lock, tree_manifest
from appsec_review.jobs.job_codeql_analysis.job import (
    _database_identity,
    _query_identity,
    _query_profiles,
)


IMAGE = "sha256:" + "1" * 64
ROOT = Path(__file__).parents[1]


def source(path: str, digest: str = "a" * 64) -> dict[str, object]:
    return {"path": path, "sha256": digest, "size_bytes": 12}


def receipt(family: str, root: str, unit: str, *, status: str = "SUCCEEDED",
            commands: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "family": family, "root": root, "build_unit_id": unit, "terminal_status": status,
        "workspace": f"data/build/{family}/{unit}/workspace" if status == "SUCCEEDED" else None,
        "commands": ([{"ordinal": 1}] if commands is None else commands),
        "fingerprint": (unit[-1] * 64), "recipe_identity": "2" * 64,
        "dependency_identity": "3" * 64,
        "workspace_manifest": {"path": f"{unit}.json", "sha256": "4" * 64},
        "image": {"image_id": IMAGE},
    }


def test_routes_every_supported_mode_and_keeps_kotlin_and_typescript_visible() -> None:
    files = [
        source("cpp/a.cpp"), source("go/main.go"), source("jvm/A.java"), source("jvm/B.kt"),
        source("dotnet/A.cs"), source("node/a.js"), source("node/b.ts"), source("py/a.py"),
        source("rust/a.rs"), source("rust/Cargo.toml"), source("rust/Cargo.lock"),
        source(".github/workflows/ci.yml"), source("web/a.php"),
    ]
    receipts = [
        receipt("native", "cpp", "build-unit-aaaaaaaaaaaaaaaaaaaa"),
        receipt("go", "go", "build-unit-bbbbbbbbbbbbbbbbbbbb"),
        receipt("java", "jvm", "build-unit-cccccccccccccccccccc"),
        receipt("dotnet", "dotnet", "build-unit-dddddddddddddddddddd"),
        receipt("node", "node", "build-unit-eeeeeeeeeeeeeeeeeeee", commands=[]),
        receipt("python", "py", "build-unit-ffffffffffffffffffff", commands=[]),
        receipt("rust", "rust", "build-unit-11111111111111111111", commands=[]),
    ]
    plan = build_codeql_plan(
        source_fingerprint="f" * 64, files=files, receipts=receipts,
        supported_extractors={"cpp", "go", "java", "csharp", "javascript", "python", "rust", "actions"},
        source_image_id=IMAGE,
    )
    by_language = {item.language: item for item in plan.scopes}
    assert set(by_language) == {"cpp", "go", "java", "csharp", "javascript", "python", "rust", "actions"}
    assert {name: by_language[name].mode for name in by_language} == {
        "cpp": "manual", "go": "manual", "java": "manual", "csharp": "manual",
        "javascript": "none", "python": "none", "rust": "none", "actions": "none",
    }
    assert by_language["java"].source_languages == ("Java", "Kotlin")
    assert by_language["javascript"].source_languages == ("JavaScript", "TypeScript")
    assert all(not by_language[name].commands_permitted
               for name in ("javascript", "python", "rust", "actions"))
    assert [item["status"] for item in plan.non_applicable] == ["NOT_APPLICABLE", "NOT_APPLICABLE"]


def test_failed_sibling_is_a_gap_without_erasing_successful_scope() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=[source("one/a.go"), source("two/b.go")],
        receipts=[receipt("go", "one", "build-unit-aaaaaaaaaaaaaaaaaaaa"),
                  receipt("go", "two", "build-unit-bbbbbbbbbbbbbbbbbbbb", status="BLOCKED")],
        supported_extractors={"go"}, source_image_id=IMAGE,
    )
    assert [item.root for item in plan.scopes] == ["one"]
    assert any("build-unit-bbbbbbbbbbbbbbbbbbbb/go" in gap for gap in plan.gaps)


def test_dotnet_does_not_claim_visual_basic_or_fsharp() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=[source("net/a.cs"), source("net/b.vb"), source("net/c.fs")],
        receipts=[receipt("dotnet", "net", "build-unit-aaaaaaaaaaaaaaaaaaaa")],
        supported_extractors={"csharp"}, source_image_id=IMAGE,
    )
    assert len(plan.scopes) == 1 and plan.scopes[0].language == "csharp"
    assert any(gap.startswith("Visual Basic:") for gap in plan.gaps)
    assert any(gap.startswith("F#:") for gap in plan.gaps)


def test_missing_runtime_extractor_is_not_silently_planned() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64, files=[source("go/main.go")],
        receipts=[receipt("go", "go", "build-unit-aaaaaaaaaaaaaaaaaaaa")],
        supported_extractors={"python"}, source_image_id=IMAGE,
    )
    assert not plan.scopes
    assert "pinned runtime did not report the required extractor" in plan.gaps[0]


def test_manual_requires_commands_but_source_modes_prohibit_them() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64, files=[source("cpp/a.cpp"), source("py/a.py")],
        receipts=[receipt("native", "cpp", "build-unit-aaaaaaaaaaaaaaaaaaaa", commands=[]),
                  receipt("python", "py", "build-unit-bbbbbbbbbbbbbbbbbbbb")],
        supported_extractors={"cpp", "python"}, source_image_id=IMAGE,
    )
    assert [item.language for item in plan.scopes] == ["python"]
    assert plan.scopes[0].mode == "none" and not plan.scopes[0].commands_permitted
    assert any("accepted compiled build has no replayable commands" in gap for gap in plan.gaps)


def test_rust_cannot_be_represented_as_manual() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=[source("rust/a.rs"), source("rust/Cargo.toml"), source("rust/Cargo.lock")],
        receipts=[receipt("rust", "rust", "build-unit-aaaaaaaaaaaaaaaaaaaa")],
        supported_extractors={"rust"}, source_image_id=IMAGE,
    )
    assert plan.scopes[0].mode == "none"
    with pytest.raises(ValueError, match="Rust extractor"):
        replace(plan.scopes[0], mode="manual", commands_permitted=True)


def test_ruby_and_swift_require_an_accepted_executor_and_platform() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64, files=[source("lib/a.rb"), source("ios/a.swift")], receipts=[],
        supported_extractors={"ruby", "swift"}, source_image_id=IMAGE,
    )
    assert not plan.scopes
    assert any(gap.startswith("Ruby:") for gap in plan.gaps)
    assert any(gap.startswith("Swift:") for gap in plan.gaps)


def test_actions_are_planned_only_for_accepted_workflow_files() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=[source(".github/workflows/ci.yaml"), source("docs/example.yml")], receipts=[],
        supported_extractors={"actions"}, source_image_id=IMAGE,
    )
    assert len(plan.scopes) == 1
    assert [item["path"] for item in plan.scopes[0].files] == [".github/workflows/ci.yaml"]


def test_source_only_projects_do_not_require_language_build_receipts() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=[source("web/a.js"), source("typed/a.ts"), source("py/a.py"),
               source("rust/src/main.rs"), source("rust/Cargo.toml")],
        receipts=[], projects=[{"root": "web"}, {"root": "typed"}, {"root": "rust"}],
        supported_extractors={"javascript", "python", "rust"}, source_image_id=IMAGE,
    )
    assert [(item.language, item.root, item.mode) for item in plan.scopes] == [
        ("javascript", "typed", "none"), ("javascript", "web", "none"),
        ("python", "py", "none"),
    ]
    assert all(item.build_unit_id is None and not item.commands_permitted for item in plan.scopes)
    assert any("Cargo.lock prerequisite is absent" in gap for gap in plan.gaps)


def test_sarif_normalization_maps_results_and_code_flow_steps() -> None:
    files = [source("project/src/a.ts"), source("project/src/b.ts", "b" * 64)]
    sarif = {
        "version": "2.1.0", "runs": [{
            "tool": {"driver": {"rules": [{"id": "js/x", "helpUri": "https://example.invalid/x",
                                                "shortDescription": {"text": "x"}}]}},
            "results": [{
                "ruleId": "js/x", "level": "warning", "message": {"text": "observed"},
                "partialFingerprints": {"primaryLocationLineHash": "abc"},
                "locations": [{"physicalLocation": {"artifactLocation": {
                    "uri": "file:///scratch/workspace/project/src/a.ts"},
                    "region": {"startLine": 4, "startColumn": 2}}}],
                "codeFlows": [{"threadFlows": [{"locations": [{"location": {
                    "message": {"text": "source"}, "physicalLocation": {
                        "artifactLocation": {"uri": "/scratch/workspace/project/src/b.ts"},
                        "region": {"startLine": 2, "startColumn": 1}}}}]}]}],
            }],
        }],
    }
    records, gaps = normalize_sarif(sarif, files=files, root="project",
                                    query_identity="query", result_limit=10)
    assert gaps == []
    assert records[0]["location"]["path"] == "project/src/a.ts"
    assert records[0]["flows"][0]["location"]["path"] == "project/src/b.ts"
    assert records[0]["payload"]["help_uri"] == "https://example.invalid/x"
    assert records[0]["payload"]["supporting_relations"] == [1]


def test_sarif_ambiguity_and_unmapped_locations_are_preserved_as_gaps() -> None:
    files = [source("one/src/a.py"), source("two/src/a.py", "b" * 64)]
    physical = {"artifactLocation": {"uri": "src/a.py"}, "region": {"startLine": "bad"}}
    mapped = map_location(physical, files=files, root=".")
    assert mapped.path is None and mapped.ambiguous
    assert mapped.candidates == ("one/src/a.py", "two/src/a.py")
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": [{
        "ruleId": "py/x", "message": {"text": "x"},
        "locations": [{"physicalLocation": physical}],
    }]}]}
    records, gaps = normalize_sarif(sarif, files=files, root=".", query_identity="q", result_limit=10)
    assert records[0]["location"]["ambiguous"] is True
    assert "no uniquely mapped source location" in gaps[0]


def test_partial_and_malformed_sarif_results_do_not_erase_valid_siblings() -> None:
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": [
        "malformed",
        {"ruleId": "py/x", "message": {"text": "x"}, "locations": []},
    ]}]}
    records, gaps = normalize_sarif(sarif, files=[source("a.py")], root=".",
                                    query_identity="q", result_limit=10)
    assert len(records) == 1
    assert any("was not an object" in gap for gap in gaps)
    assert any("no uniquely mapped" in gap for gap in gaps)


def test_sarif_contract_rejects_malformed_top_level() -> None:
    with pytest.raises(ValueError, match="contract"):
        normalize_sarif({"version": "1.0"}, files=[], root=".", query_identity="q", result_limit=1)


def _settings_value() -> dict[str, object]:
    lock = json.loads((ROOT / "containers/tools/codeql/assets.lock.json").read_text(encoding="utf-8"))
    modes = {"cpp": "manual", "go": "manual", "java": "manual", "csharp": "manual",
             "javascript": "none", "python": "none", "rust": "none", "actions": "none"}
    source_languages = {"cpp": ["C", "C++"], "go": ["Go"], "java": ["Java", "Kotlin"],
                        "csharp": ["C#"], "javascript": ["JavaScript", "TypeScript"],
                        "python": ["Python"], "rust": ["Rust"], "actions": ["GitHub Actions"]}
    prerequisites = {name: [] for name in modes}
    prerequisites["javascript"] = ["bundled-typescript"]
    prerequisites["rust"] = ["Cargo.toml", "Cargo.lock", "bundled-rust-indexer"]
    languages = {}
    for name, mode in modes.items():
        pack = lock["query_packs"][name]
        languages[name] = {"enabled": True, "mode": mode, "platform": "linux-x86_64",
            "extractor_tree_sha256": lock["extractors"][name]["tree_sha256"],
            "extractor_file_count": lock["extractors"][name]["file_count"],
            "query_pack": pack["name"], "query_pack_version": pack["version"],
            "query_suite": pack["suite"], "query_suite_sha256": pack["suite_sha256"],
            "query_pack_sha256": pack["qlpack_sha256"], "query_lock_sha256": pack["lock_sha256"],
            "source_languages": source_languages[name], "prerequisites": prerequisites[name],
            "custom_queries": lock.get("custom_query_packs", {}).get(name, [])}
    return {"enabled": True, "source_image_tag": lock["source_image"]["tag"],
        "source_image_id": lock["source_image"]["image_id"],
        "version": "2.27.0", "commit": "b47b3e59262c95aff4eeb84ac72d09e25a9c37e9",
        "cli_sha256": lock["codeql"]["cli_sha256"], "license_sha256": lock["codeql"]["license_sha256"],
        "asset_lock_sha256": load_asset_lock(ROOT)["sha256"], "runtime_user": "10001:10001",
        "retention": "run-owned", "concurrency": 4, "inventory_timeout_seconds": 300,
        "database_timeout_seconds": 1800, "query_timeout_seconds": 1800, "output_bytes": 1024,
        "database_file_limit": 200000, "database_bytes_limit": 8589934592,
        "sarif_bytes_limit": 268435456, "result_limit": 100000, "threads": 2,
        "ram_mb": 4096, "max_paths": 4, "languages": languages}


def test_typed_codeql_configuration_enforces_language_contracts() -> None:
    value = _settings_value()
    settings = parse_codeql_settings(value)
    assert settings.languages["java"].source_languages == ("Java", "Kotlin")
    assert settings.languages["rust"].mode == "none"
    assert settings.languages["cpp"].query_suite == "codeql-suites/cpp-code-scanning.qls"
    assert [(item.query_id, item.query_suite) for item in settings.languages["cpp"].custom_queries] == [
        ("cert-cpp", "codeql-suites/cert-cpp-default.qls")]
    broken = _settings_value()
    broken["languages"]["java"]["source_languages"] = ["Java"]
    with pytest.raises(ValueError, match="Kotlin"):
        parse_codeql_settings(broken)


def test_database_and_query_checkpoint_inputs_invalidate_independently() -> None:
    settings = parse_codeql_settings(_settings_value())
    scope = build_codeql_plan(
        source_fingerprint="f" * 64, files=[source("go/main.go")],
        receipts=[receipt("go", "go", "build-unit-aaaaaaaaaaaaaaaaaaaa")],
        supported_extractors={"go"}, source_image_id=IMAGE,
    ).scopes[0]
    unit = SimpleNamespace(job=SimpleNamespace(source_fingerprint="f" * 64),
                           output=lambda _name: {"upstream_handoffs": {"job": {"sha256": "9" * 64}}})
    lock = {"sha256": "8" * 64}
    replay = {"commands": [{"argv_sha256": "7" * 64}]}
    database = _database_identity(unit, scope, image_identity="6" * 64, replay=replay,
                                  settings=settings, asset_lock=lock)
    language = settings.languages["go"]
    profile = _query_profiles(language)[0]
    query = _query_identity({"database_identity": database, "database_tree_sha256": "5" * 64},
                            profile, settings)
    changed_language = replace(language, query_suite="codeql-suites/go-security-extended.qls")
    changed_settings = replace(settings, languages=MappingProxyType(
        {**settings.languages, "go": changed_language}))
    assert _database_identity(unit, scope, image_identity="6" * 64, replay=replay,
                              settings=changed_settings, asset_lock=lock) == database
    assert _query_identity({"database_identity": database, "database_tree_sha256": "5" * 64},
                           _query_profiles(changed_language)[0], changed_settings) != query
    assert _database_identity(unit, scope, image_identity="6" * 64,
                              replay={"commands": [{"argv_sha256": "4" * 64}]},
                              settings=settings, asset_lock=lock) != database
    broken = _settings_value()
    broken["languages"]["csharp"]["source_languages"] = ["C#", "Visual Basic"]
    with pytest.raises(ValueError, match="VB"):
        parse_codeql_settings(broken)


def test_cpp_default_and_custom_queries_have_independent_identities() -> None:
    settings = parse_codeql_settings(_settings_value())
    language = settings.languages["cpp"]
    profiles = _query_profiles(language)
    assert [(item["query_id"], item["kind"]) for item in profiles] == [
        ("default", "default"), ("cert-cpp", "custom")]
    database = {"database_identity": "1" * 64, "database_tree_sha256": "2" * 64}
    identities = [_query_identity(database, profile, settings) for profile in profiles]
    assert len(set(identities)) == 2

    changed_custom = replace(language.custom_queries[0], query_suite_sha256="3" * 64)
    changed_language = replace(language, custom_queries=(changed_custom,))
    changed_settings = replace(settings, languages=MappingProxyType(
        {**settings.languages, "cpp": changed_language}))
    changed_profiles = _query_profiles(changed_language)
    assert _query_identity(database, changed_profiles[0], changed_settings) == identities[0]
    assert _query_identity(database, changed_profiles[1], changed_settings) != identities[1]


def test_runner_tree_identity_uses_posix_path_order(tmp_path: Path) -> None:
    runner_path = ROOT / "containers" / "tools" / "codeql" / "codeql_runner.py"
    spec = importlib.util.spec_from_file_location("appsec_review_codeql_runner", runner_path)
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    (tmp_path / "a").mkdir()
    (tmp_path / "a.b").write_text("dot", encoding="utf-8")
    (tmp_path / "a" / "Z").write_text("nested", encoding="utf-8")
    files = sorted((tmp_path / "a.b", tmp_path / "a" / "Z"), key=lambda item: item.as_posix())
    rows = [f"{runner._sha256(path)}  {path.as_posix()}\n".encode() for path in files]

    assert runner._tree(tmp_path) == (hashlib.sha256(b"".join(rows)).hexdigest(), 2)


def test_bounded_logs_retain_head_tail_and_total_size(tmp_path: Path) -> None:
    path = tmp_path / "stream.bin"
    digest, total, truncated, tail = _bounded_stream(path, b"0123456789", 6)
    assert path.read_bytes() == b"012789"
    assert total == 10 and truncated and tail == 3 and len(digest) == 64


def test_database_tree_manifest_detects_changes(tmp_path: Path) -> None:
    database = tmp_path / "db"
    database.mkdir()
    (database / "a").write_text("one", encoding="utf-8")
    before = tree_manifest(database, file_limit=10, bytes_limit=100)
    (database / "a").write_text("two", encoding="utf-8")
    after = tree_manifest(database, file_limit=10, bytes_limit=100)
    assert before["tree_sha256"] != after["tree_sha256"]
