"""Focused unit tests for CodeQL scope/export planning edge cases in planning.py."""

from __future__ import annotations

import pytest

from appsec_review.jobs.job_codeql_analysis.planning import (
    CodeQLScope,
    SCOPE_SCHEMA,
    _environment_identity,
    _files_for,
    _path,
    _rust_prerequisite_gaps,
    build_codeql_plan,
    export_lock_mismatches,
    plan_graph_exports,
    replay_commands,
)


IMAGE = "sha256:" + "1" * 64
H1 = "a" * 64
H2 = "b" * 64


def _file(path: str, sha: str = H1, size: int = 32) -> dict[str, object]:
    return {"path": path, "sha256": sha, "size_bytes": size}


def _receipt(
    unit_id: str,
    family: str,
    *,
    root: str = ".",
    status: str = "SUCCEEDED",
    workspace: str | None = "data/builds/ws",
    commands: object = None,
    recipe: object = None,
) -> dict[str, object]:
    default_recipe = {"configure_commands": [], "build_commands": [["make"]]}
    default_commands = [{"role": "build", "argv_sha256": H2}]
    return {
        "build_unit_id": unit_id,
        "family": family,
        "root": root,
        "terminal_status": status,
        "workspace": workspace,
        "fingerprint": "fp-" + unit_id,
        "recipe_identity": "rec-1",
        "dependency_identity": "dep-1",
        "image": {"image_id": IMAGE},
        "recipe": default_recipe if recipe is None else recipe,
        "commands": default_commands if commands is None else commands,
        "gaps": [],
    }


@pytest.mark.parametrize(
    ("language", "family", "filename"),
    [("cpp", "native", "a.cpp"), ("csharp", "dotnet", "Program.cs"),
     ("go", "go", "main.go"), ("java", "java", "Main.kt")],
)
@pytest.mark.parametrize("policy", ["auto", "build", "disabled", "source"])
def test_compiled_files_without_matching_receipts_have_explicit_decisions(
    language: str, family: str, filename: str, policy: str,
) -> None:
    from appsec_review.applicability import decision_from_mapping

    covered, missing = _file(f"built/{filename}"), _file(f"unbuilt/{filename}", H2)
    plan = build_codeql_plan(
        source_fingerprint="fp", files=(missing, covered),
        receipts=(_receipt("built-unit", family, root="built"),),
        supported_extractors=(language,), source_image_id=IMAGE,
        language_modes={language: policy},
    )
    decisions = [decision_from_mapping(item) for item in plan.decisions]
    unmatched = [item for item in decisions if any(source.path == missing["path"] for source in item.sources)]
    assert len(unmatched) == 1
    decision, = unmatched
    assert [(source.path, source.sha256) for source in decision.sources] == [(missing["path"], H2)]
    assert decision.resolved_policy == policy
    assert not any(missing["path"] == item["path"] for scope in plan.scopes for item in scope.files)
    if policy == "disabled":
        assert decision.disposition.value == "SKIPPED_POLICY"
        assert not plan.gaps
    else:
        assert decision.disposition.value == "GAP"
        assert any("no matching accepted build receipt" in gap for gap in plan.gaps)

    empty = build_codeql_plan(
        source_fingerprint="fp", files=(missing,), receipts=(), supported_extractors=(language,),
        source_image_id=IMAGE, language_modes={language: policy},
    )
    assert empty.scopes == ()
    assert len(empty.decisions) == 1
    assert empty.decisions[0]["disposition"] == decision.disposition.value


def test_failed_native_addon_is_decided_once_and_gradle_scripts_are_not_java_sources() -> None:
    plan = build_codeql_plan(
        source_fingerprint="fp",
        files=(_file("addon/index.js"), _file("addon/binding.cc"), _file("build.gradle.kts")),
        receipts=(_receipt("node-unit", "node", root="addon", status="FAILED", workspace=None),),
        supported_extractors=("cpp", "javascript", "java"), source_image_id=IMAGE,
    )
    native = [item for item in plan.decisions if item["language"] == "cpp"]
    assert len(native) == 1 and native[0]["project_id"] == "node-unit"
    assert not any(item["language"] == "java" for item in plan.decisions)
    assert not any("no matching accepted build receipt" in gap for gap in plan.gaps)


def test_path_files_rust_replay_scope_and_environment_validations() -> None:
    for bad in ("", "/abs/file.py", "../escape.py"):
        with pytest.raises(ValueError, match="invalid target-relative path"):
            _path(bad)

    with pytest.raises(ValueError, match="missing an accepted file hash"):
        _files_for([{"path": "a.py", "sha256": "short"}], ".", {".py"})

    rust_gaps = _rust_prerequisite_gaps([_file("src/lib.rs")], ".")
    assert rust_gaps == (
        "./rust: Cargo.toml prerequisite is absent",
        "./rust: Cargo.lock prerequisite is absent; dependency resolution is partial",
    )

    assert replay_commands({"recipe": "bad", "commands": []}) is None
    assert replay_commands({"recipe": {"configure_commands": [], "build_commands": []}, "commands": []}) is None
    unlabeled = replay_commands(
        {
            "recipe": {"configure_commands": [["cmake"]], "build_commands": [["make"]]},
            "commands": [{"role": None, "cmd": 1}, {"role": "", "cmd": 2}],
        }
    )
    assert unlabeled is not None and [r for _, r in unlabeled] == ["configure", "build"]
    assert replay_commands(
        {
            "recipe": {"configure_commands": [], "build_commands": [["make"]]},
            "commands": [{"role": "other"}],
        }
    ) is None

    with pytest.raises(ValueError, match="invalid CodeQL scope contract"):
        CodeQLScope("bad-schema", "s1", "python", ("Python",), "none", ".", (), None, None, H1, False)
    with pytest.raises(ValueError, match="cannot permit commands"):
        CodeQLScope(SCOPE_SCHEMA, "s1", "python", ("Python",), "none", ".", (), None, None, H1, True)
    with pytest.raises(ValueError, match="Rust extractor requires source/no-build mode"):
        CodeQLScope(SCOPE_SCHEMA, "s1", "rust", ("Rust",), "manual", ".", (), "u1", "fp", H1, True)
    with pytest.raises(ValueError, match="manual scopes require an accepted build unit"):
        CodeQLScope(SCOPE_SCHEMA, "s1", "cpp", ("C++",), "manual", ".", (), None, None, H1, True)

    kt_scope = CodeQLScope(
        SCOPE_SCHEMA, "s-kt", "java", ("Kotlin",), "manual", ".", (), "u-kt", "fp", H1, True
    )
    assert kt_scope.source_languages == ("Kotlin",)

    with pytest.raises(ValueError, match="no image identity"):
        _environment_identity({})
    with pytest.raises(ValueError, match="environment image identity is invalid"):
        _environment_identity({"image": {"image_id": "unpinned-tag"}})


def test_build_codeql_plan_input_and_duplicate_unit_guards() -> None:
    with pytest.raises(ValueError, match="requires an accepted snapshot"):
        build_codeql_plan(source_fingerprint="", files=(), receipts=(), supported_extractors=(), source_image_id=IMAGE)
    with pytest.raises(ValueError, match="source image identity is invalid"):
        build_codeql_plan(source_fingerprint="fp", files=(), receipts=(), supported_extractors=(), source_image_id="bad")

    with pytest.raises(ValueError, match="duplicate CodeQL build unit"):
        build_codeql_plan(
            source_fingerprint="fp",
            files=(_file("main.go"),),
            receipts=(_receipt("dup", "go"), _receipt("dup", "go")),
            supported_extractors=("go",),
            source_image_id=IMAGE,
        )

    with pytest.raises(ValueError, match="command inventory is invalid"):
        build_codeql_plan(
            source_fingerprint="fp",
            files=(_file("main.go"),),
            receipts=(_receipt("u-go", "go", commands="not-a-list"),),
            supported_extractors=("go",),
            source_image_id=IMAGE,
        )


def test_build_codeql_plan_covers_node_native_addons_and_decision_branches() -> None:
    files = (
        _file("addon/index.js"),
        _file("addon/binding.cc"),
    )
    # 1) Native C++ addon skipped when cpp=disabled; JS skipped when javascript=disabled; unknown family ignored; empty selected ignored.
    plan_skip = build_codeql_plan(
        source_fingerprint="fp",
        files=files,
        receipts=(
            _receipt("u-unknown", "terraform"),
            _receipt("u-empty", "go", root="empty-go"),
            _receipt("u-node", "node", root="addon"),
        ),
        supported_extractors=("javascript", "cpp"),
        source_image_id=IMAGE,
        language_modes={"cpp": "disabled", "javascript": "disabled"},
    )
    assert plan_skip.scopes == ()
    assert {item["language"] for item in plan_skip.non_applicable} == {"cpp", "javascript"}

    # 2) Native C++ addon GAP when cpp=source (unsupported capability on native compiled addon) and JS GAP when javascript=build.
    plan_mode_gap = build_codeql_plan(
        source_fingerprint="fp",
        files=files,
        receipts=(_receipt("u-node", "node", root="addon"),),
        supported_extractors=("javascript", "cpp"),
        source_image_id=IMAGE,
        language_modes={"cpp": "source", "javascript": "build"},
    )
    assert any("u-node/cpp:" in g for g in plan_mode_gap.gaps)
    assert any("u-node/javascript:" in g for g in plan_mode_gap.gaps)

    # 3) Missing cpp extractor on native addon.
    plan_no_cpp = build_codeql_plan(
        source_fingerprint="fp",
        files=files,
        receipts=(_receipt("u-node", "node", root="addon"),),
        supported_extractors=("javascript",),
        source_image_id=IMAGE,
    )
    assert any("u-node/cpp: pinned runtime did not report the required extractor" in g for g in plan_no_cpp.gaps)

    # 4) Failed receipt on native addon & main receipt.
    plan_failed = build_codeql_plan(
        source_fingerprint="fp",
        files=files,
        receipts=(_receipt("u-node", "node", root="addon", status="FAILED", workspace=None),),
        supported_extractors=("javascript", "cpp"),
        source_image_id=IMAGE,
    )
    assert "u-node/cpp: no successful accepted materialized environment" in plan_failed.gaps
    assert "u-node/javascript: no successful accepted materialized environment" in plan_failed.gaps

    # 5) Missing replayable commands on native addon & compiled go receipt.
    plan_no_replay = build_codeql_plan(
        source_fingerprint="fp",
        files=(*files, _file("svc/main.go")),
        receipts=(
            _receipt("u-node", "node", root="addon", commands=[]),
            _receipt("u-go", "go", root="svc", commands=[]),
        ),
        supported_extractors=("javascript", "cpp", "go"),
        source_image_id=IMAGE,
    )
    assert "u-node/cpp: accepted compiled build has no exact replayable command set" in plan_no_replay.gaps
    assert "u-go/go: accepted compiled build has no exact replayable command set" in plan_no_replay.gaps

    # 6) Valid native addon produces both cpp manual scope and javascript source scope.
    plan_ok = build_codeql_plan(
        source_fingerprint="fp",
        files=files,
        receipts=(_receipt("u-node", "node", root="addon"),),
        supported_extractors=("javascript", "cpp"),
        source_image_id=IMAGE,
    )
    assert [(s.language, s.mode) for s in plan_ok.scopes] == [("cpp", "manual"), ("javascript", "none")]


def test_build_codeql_plan_covers_rust_source_actions_dotnet_swift_php_wasm_and_export_helpers() -> None:
    files = (
        _file("crate/src/lib.rs"),
        _file("loose_rust/lib.rs"),
        _file("scripts/tool.rb"),
        _file(".github/workflows/ci.yml"),
        _file("legacy/Mod.vb"),
        _file("ios/App.swift"),
        _file("web/index.php"),
        _file("mod/filter.wat"),
    )
    plan = build_codeql_plan(
        source_fingerprint="fp",
        files=files,
        receipts=(_receipt("u-rust", "rust", root="crate", commands=[]),),
        supported_extractors=("rust", "actions", "swift"),
        source_image_id=IMAGE,
        projects=({"root": "loose_rust"},),
        language_modes={"ruby": "build", "actions": "disabled"},
        enable_swift=True,
    )
    assert any("crate/rust: Cargo.toml prerequisite is absent" in g for g in plan.gaps)
    assert any("loose_rust/rust: Cargo.toml prerequisite is absent" in g for g in plan.gaps)
    assert any("ruby:" in g for g in plan.gaps)
    assert any("Visual Basic: 1 accepted source file(s)" in g for g in plan.gaps)
    assert any("Swift: 1 accepted source file(s); extractor is present" in g for g in plan.gaps)
    non_app_langs = {item["language"] for item in plan.non_applicable}
    assert {"actions", "php", "wasm"} <= non_app_langs

    # Actions GAP and missing-extractor branches, plus source SKIP and missing-extractor branches.
    plan_actions_gap = build_codeql_plan(
        source_fingerprint="fp",
        files=(_file(".github/workflows/ci.yml"), _file("app.py"), _file("gem.rb")),
        receipts=(),
        supported_extractors=(),
        source_image_id=IMAGE,
        language_modes={"actions": "build", "python": "disabled", "ruby": "source"},
    )
    assert any("actions:" in g for g in plan_actions_gap.gaps)
    assert any("ruby: accepted source exists but the runtime reported no extractor" in g for g in plan_actions_gap.gaps)
    assert any(item["language"] == "python" for item in plan_actions_gap.non_applicable)

    plan_actions_no_ext = build_codeql_plan(
        source_fingerprint="fp",
        files=(_file(".github/workflows/ci.yml"),),
        receipts=(),
        supported_extractors=(),
        source_image_id=IMAGE,
    )
    assert "actions: accepted GitHub Actions workflows exist but the runtime reported no extractor" in plan_actions_no_ext.gaps

    # Export lock mismatches when export_query_packs is non-mapping, and plan_graph_exports disabled/enabled.
    assert export_lock_mismatches({"cpp": [{"id": 1}], "python": []}, {"export_query_packs": "corrupt"}) == (
        "cpp",
        "python",
    )
    scope_cpp = CodeQLScope(SCOPE_SCHEMA, "s-cpp", "cpp", ("C++",), "manual", ".", (), "u1", "fp", H1, True)
    scope_py = CodeQLScope(SCOPE_SCHEMA, "s-py", "python", ("Python",), "none", ".", (), None, None, H1, False)
    disabled = plan_graph_exports((scope_cpp,), enabled=False, export_languages=("cpp",))
    assert disabled[0]["disposition"] == "NOT_APPLICABLE"
    enabled = plan_graph_exports((scope_cpp, scope_py), enabled=True, export_languages=("cpp",))
    assert [e["disposition"] for e in enabled] == ["PLANNED", "NOT_APPLICABLE"]
