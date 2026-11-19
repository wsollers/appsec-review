"""Unit tests for scope routing, first-party ordering, bounds, grammar locks and fingerprinting."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_tree_sitter_ast import (
    GrammarLock,
    Scope,
    partition_scopes,
    plan_scopes,
    scope_fingerprint,
)
from appsec_review.jobs.job_tree_sitter_ast.model import SUPPORTED_LANGUAGES, _slug
from appsec_review.jobs.job_tree_sitter_ast.normalize import NORMALIZER_SCHEMA, node_identity
from appsec_review.review.dispositions import SourceDispositions

ROOT = Path(__file__).resolve().parents[3]


def _lock(language: str = "Python", grammar: str = "python") -> GrammarLock:
    return GrammarLock(
        language, grammar, f"https://example.invalid/tree-sitter-{grammar}",
        "a" * 40, "MIT", f"libtree_sitter_{grammar}.so", "b" * 64,
    )


def _scope(language: str = "Python", digest: str = "c" * 64) -> Scope:
    return Scope(
        "scope-python", "component:0001", "python", "source:component:0001",
        "python", language,
        ({"path": "python/app.py", "sha256": digest, "size_bytes": 10, "language": language},),
    )


def _node(*, ordinal=(), kind="module", error=False, missing=False, end=10):
    return {
        "ordinal_path": list(ordinal), "field": None, "type": kind, "named": True,
        "error": error, "missing": missing, "extra": False, "has_error": error or missing,
        "start_byte": 0, "end_byte": end, "start_point": [0, 0], "end_point": [0, end],
    }


def test_scope_routing_is_project_translation_and_language_specific() -> None:
    files = [
        {"path": "native/main.c", "sha256": "1" * 64, "language": "C", "generated": False},
        {"path": "python/app.py", "sha256": "2" * 64, "language": "Python", "generated": False},
        {"path": "web/src/index.ts", "sha256": "3" * 64, "language": "TypeScript", "generated": False},
        {"path": "web/src/view.tsx", "sha256": "4" * 64, "language": "TypeScript", "generated": False},
    ]
    catalog = {
        "files": files,
        "components": [
            {"component_id": "native", "root": "native"},
            {"component_id": "python", "root": "python"},
            {"component_id": "web", "root": "web"},
        ],
        "build_units": [
            {"build_unit_id": "native-build", "root": "native"},
            {"build_unit_id": "web-build", "root": "web"},
        ],
        "gaps": [{"path": "web/vendor", "reason": "excluded_directory"}],
    }
    scopes = plan_scopes(catalog)
    assert {(value.project_id, value.translation_scope_id, value.language) for value in scopes} == {
        ("native", "native-build", "C"),
        ("python", "source:python", "Python"),
        ("web", "web-build", "TypeScript"),
        ("web", "web-build", "TSX"),
    }
    assert next(value for value in scopes if value.language == "TypeScript").exclusions[0]["path"] == "web/vendor"


def test_scope_routing_handles_default_component_generated_sources_and_invalid_entries() -> None:
    assert _slug("///") == "root"
    with pytest.raises(ValueError, match="scope chunk bounds must be positive"):
        plan_scopes({}, max_files_per_scope=0)
    with pytest.raises(ValueError, match="scope chunk bounds must be positive"):
        plan_scopes({}, max_source_bytes_per_scope=0)

    catalog = {
        "files": [
            {"path": "", "sha256": "1" * 64, "language": "Python"},
            {"path": "docs/readme.md", "sha256": "2" * 64, "language": None},
            {"path": "platform/skip.py", "sha256": "3" * 64, "language": "Python", "scope_role": "supplied_platform"},
            {"path": "api/plain.py", "sha256": "4" * 64, "language": "Python", "size_bytes": 12},
            {
                "path": "@generated/abc/gen_pb2.py",
                "workspace_path": "api/proto/gen_pb2.py",
                "sha256": "5" * 64,
                "language": "Python",
                "size_bytes": 20,
                "build_unit_id": "bu-proto",
                "build_root": "api",
                "source_backing": {
                    "path": f"data/treesitter/sources/{'5' * 64}.json",
                    "sha256": "5" * 64,
                    "size_bytes": 20,
                },
            },
        ],
    }
    scopes = plan_scopes(catalog)
    assert [(s.project_id, s.translation_scope_id, [f["path"] for f in s.files]) for s in scopes] == [
        ("component:0001", "generated:bu-proto", ["@generated/abc/gen_pb2.py"]),
        ("component:0001", "source:component:0001", ["api/plain.py"]),
    ]


def test_scope_routing_chunks_large_partitions_deterministically_by_count_and_bytes() -> None:
    files = [
        {"path": f"python/{index}.py", "sha256": f"{index:064x}", "language": "Python",
         "generated": False, "size_bytes": 10}
        for index in range(5)
    ]
    catalog = {"files": files, "components": [{"component_id": "python", "root": "python"}]}
    first = plan_scopes(catalog, max_files_per_scope=2, max_source_bytes_per_scope=100)
    assert [len(scope.files) for scope in first] == [2, 2, 1]
    assert first == plan_scopes(catalog, max_files_per_scope=2, max_source_bytes_per_scope=100)
    assert len({scope.scope_id for scope in first}) == 3

    by_bytes = plan_scopes(catalog, max_files_per_scope=10, max_source_bytes_per_scope=25)
    assert [len(scope.files) for scope in by_bytes] == [2, 2, 1]


def test_scope_files_are_ordered_first_party_first_and_chunked_in_that_order() -> None:
    files = [
        {"path": f"native/{name}", "sha256": f"{index:064x}", "language": "C", "generated": False, "size_bytes": 10}
        for index, name in enumerate(["third_party/bzip2/a.c", "third_party/bzip2/b.c", "util.c", "zz.c"])
    ]
    catalog = {"files": files, "components": [{"component_id": "native", "root": "native"}]}
    dispositions = SourceDispositions(vendored=("**/third_party/**",))
    scopes = plan_scopes(catalog, max_files_per_scope=2, dispositions=dispositions)
    assert [[item["path"] for item in scope.files] for scope in scopes] == [
        ["native/util.c", "native/zz.c"],
        ["native/third_party/bzip2/a.c", "native/third_party/bzip2/b.c"],
    ]
    assert {item["disposition"] for item in scopes[0].files} == {"first_party"}
    assert {item["disposition"] for item in scopes[1].files} == {"vendored"}

    plain = plan_scopes(catalog, max_files_per_scope=2)
    assert [item["path"] for scope in plain for item in scope.files] == sorted(item["path"] for item in files)
    assert {item["disposition"] for scope in plain for item in scope.files} == {"first_party"}


def test_unavailable_grammar_is_an_explicit_gap_with_exclusions() -> None:
    swift_scope = replace(_scope("Swift"), exclusions=({"path": "ios/Pods", "reason": "excluded_directory"},))
    runnable, gaps = partition_scopes((swift_scope,), {"Python": _lock()})
    assert runnable == ()
    assert gaps == ({
        "scope_id": "scope-python",
        "language": "Swift",
        "terminal_status": "UNAVAILABLE",
        "reason": "grammar unavailable",
        "gaps": ["ios/Pods: excluded_directory"],
    },)


def test_supported_languages_have_locked_offline_grammars_and_partition_cleanly() -> None:
    lock = json.loads((ROOT / "containers" / "tools" / "tree-sitter" / "assets.lock.json").read_text(encoding="utf-8"))
    locked = {item["language"] for item in lock["grammars"]} | {"C/C++"}
    assert locked == SUPPORTED_LANGUAGES
    expected = {
        "Kotlin": (
            "kotlin",
            "c8ac3d2627240160b999a2c100de3babbdb8f419",
            "4ba2c2f1b00fb74350a335aadc287e4bcd82f8cbec2848f644cc95279ad44a1c",
        ),
        "PowerShell": (
            "powershell",
            "d398441825243b00e317e87e1829b9d6a3e54ce0",
            "610c910b6fb4b265894cf8af035d597d87abef2838206bccaa204629034c09c8",
        ),
        "Shell": (
            "bash",
            "a06c2e4415e9bc0346c6b86d401879ffb44058f7",
            "0a3c99ddb5ba49f35fb890d893af8483049bf9d8d7b1261730acc2488e3d3379",
        ),
        "Ruby": (
            "ruby",
            "ad907a69da0c8a4f7a943a7fe012712208da6dee",
            "c1c22f6a62595422e154fabedae9218ee92bf1a307c42965b7272b2531503bf8",
        ),
    }
    identities = {item["language"]: item for item in lock["grammars"]}
    for language, (grammar, revision, digest) in expected.items():
        assert (identities[language]["grammar"], identities[language]["revision"], identities[language]["sha256"]) == (
            grammar,
            revision,
            digest,
        )
        assert identities[language]["license"] == "MIT"

    languages = ("Kotlin", "PowerShell", "Ruby", "Shell")
    scopes = tuple(replace(_scope(language), scope_id=f"scope-{language.lower()}") for language in languages)
    locks = {
        language: _lock(language, {"Kotlin": "kotlin", "PowerShell": "powershell", "Ruby": "ruby", "Shell": "bash"}[language])
        for language in languages
    }
    runnable, gaps = partition_scopes((*scopes, _scope("Swift")), locks)
    assert [scope.language for scope in runnable] == list(languages)
    assert len(gaps) == 1 and gaps[0]["language"] == "Swift"


def test_canonical_node_identity_and_scope_fingerprint_are_deterministic_and_partition_local() -> None:
    scope = _scope()
    grammar = _lock()
    node = _node(ordinal=(0, 1), kind="identifier", end=4)
    assert node_identity("snapshot", scope, grammar, "python/app.py", "c" * 64, node) == node_identity(
        "snapshot", scope, grammar, "python/app.py", "c" * 64, dict(reversed(list(node.items())))
    )
    first = scope_fingerprint(
        target_snapshot="snapshot",
        scope=scope,
        grammar=grammar,
        image_id="sha256:" + "d" * 64,
        normalizer_schema=NORMALIZER_SCHEMA,
        limits={"max_nodes": 10, "max_file_bytes": 100},
    )
    assert first == scope_fingerprint(
        target_snapshot="snapshot",
        scope=scope,
        grammar=grammar,
        image_id="sha256:" + "d" * 64,
        normalizer_schema=NORMALIZER_SCHEMA,
        limits={"max_file_bytes": 100, "max_nodes": 10},
    )
    changed = replace(scope, files=({**scope.files[0], "sha256": "e" * 64},))
    assert first != scope_fingerprint(
        target_snapshot="snapshot",
        scope=changed,
        grammar=grammar,
        image_id="sha256:" + "d" * 64,
        normalizer_schema=NORMALIZER_SCHEMA,
        limits={"max_file_bytes": 100, "max_nodes": 10},
    )


@pytest.mark.parametrize("change", ["legacy", "algorithm", "bound"])
def test_scope_fingerprint_binds_cfg_builder_semantics_and_actual_bound(monkeypatch, change):
    from appsec_review.jobs.job_tree_sitter_ast import cfg

    def fingerprint():
        return scope_fingerprint(
            target_snapshot="snapshot", scope=_scope(), grammar=_lock(),
            image_id="sha256:" + "d" * 64, normalizer_schema=NORMALIZER_SCHEMA,
            limits={"max_nodes": 10, "max_file_bytes": 100},
        )

    first = fingerprint()
    if change == "legacy":
        # Recorded from the same inputs before the CFG identity entered the key.
        assert first != "2670daac2dfa7ef464438807b0f8e6b37dbd82a66ed9a14d9e8bdc695b5c9aae"
    else:
        if change == "algorithm":
            monkeypatch.setattr(cfg, "CFG_BUILDER_IDENTITY", "test-cfg-builder/next", raising=False)
        else:
            monkeypatch.setattr(cfg, "MAX_CFG_NODES_PER_FUNCTION", cfg.MAX_CFG_NODES_PER_FUNCTION - 1)
        assert fingerprint() != first
