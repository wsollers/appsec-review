from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import tomllib

import pytest

from appsec_review.jobs.job_tree_sitter_ast import (
    GrammarLock, Scope, partition_scopes, plan_scopes, scope_fingerprint,
)
from appsec_review.jobs.job_tree_sitter_ast.model import SUPPORTED_LANGUAGES
from appsec_review.config import load_config
from appsec_review.container_runtime.identity import application_runtime_user
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_tree_sitter_ast import build_job
from appsec_review.jobs.job_tree_sitter_ast.normalize import (
    NORMALIZER_SCHEMA, node_identity, normalize_scope, reusable_shard,
)
from appsec_review.jobs.job_tree_sitter_ast.scope_execution import (
    _validate_container_output, _write_container_request,
)
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "tree_sitter_target"
DEFAULT_IMAGE = "appsec-review/tool-tree-sitter:1.0.0"
IMAGE = os.environ.get("APPSEC_TREE_SITTER_TEST_IMAGE", DEFAULT_IMAGE)


def _lock(language: str = "Python", grammar: str = "python") -> GrammarLock:
    return GrammarLock(language, grammar, f"https://example.invalid/tree-sitter-{grammar}",
                       "a" * 40, "MIT", f"libtree_sitter_{grammar}.so", "b" * 64)


def _scope(language: str = "Python", digest: str = "c" * 64) -> Scope:
    return Scope("scope-python", "component:0001", "python", "source:component:0001",
                 "python", language, ({"path": "python/app.py", "sha256": digest,
                                       "size_bytes": 10, "language": language},))


def _node(*, ordinal=(), kind="module", error=False, missing=False, end=10):
    return {"ordinal_path": list(ordinal), "field": None, "type": kind, "named": True,
            "error": error, "missing": missing, "extra": False, "has_error": error or missing,
            "start_byte": 0, "end_byte": end, "start_point": [0, 0], "end_point": [0, end]}


def test_scope_routing_is_project_translation_and_language_specific() -> None:
    files = [
        {"path": "native/main.c", "sha256": "1" * 64, "language": "C", "generated": False},
        {"path": "python/app.py", "sha256": "2" * 64, "language": "Python", "generated": False},
        {"path": "web/src/index.ts", "sha256": "3" * 64, "language": "TypeScript", "generated": False},
        {"path": "web/src/view.tsx", "sha256": "4" * 64, "language": "TypeScript", "generated": False},
    ]
    catalog = {"files": files, "components": [
        {"component_id": "native", "root": "native"}, {"component_id": "python", "root": "python"},
        {"component_id": "web", "root": "web"}], "build_units": [
        {"build_unit_id": "native-build", "root": "native"},
        {"build_unit_id": "web-build", "root": "web"}],
        "gaps": [{"path": "web/vendor", "reason": "excluded_directory"}]}
    scopes = plan_scopes(catalog)
    assert {(value.project_id, value.translation_scope_id, value.language) for value in scopes} == {
        ("native", "native-build", "C"), ("python", "source:python", "Python"),
        ("web", "web-build", "TypeScript"), ("web", "web-build", "TSX"),
    }
    assert next(value for value in scopes if value.language == "TypeScript").exclusions[0]["path"] == "web/vendor"


def test_scope_routing_chunks_large_partitions_deterministically() -> None:
    files = [{"path": f"python/{index}.py", "sha256": f"{index:064x}", "language": "Python",
              "generated": False, "size_bytes": 10} for index in range(5)]
    catalog = {"files": files, "components": [{"component_id": "python", "root": "python"}]}
    first = plan_scopes(catalog, max_files_per_scope=2, max_source_bytes_per_scope=100)
    assert [len(scope.files) for scope in first] == [2, 2, 1]
    assert first == plan_scopes(catalog, max_files_per_scope=2, max_source_bytes_per_scope=100)
    assert len({scope.scope_id for scope in first}) == 3


def test_canonical_node_identity_and_scope_fingerprint_are_deterministic_and_partition_local() -> None:
    scope = _scope()
    grammar = _lock()
    node = _node(ordinal=(0, 1), kind="identifier", end=4)
    assert node_identity("snapshot", scope, grammar, "python/app.py", "c" * 64, node) == node_identity(
        "snapshot", scope, grammar, "python/app.py", "c" * 64, dict(reversed(list(node.items()))))
    first = scope_fingerprint(target_snapshot="snapshot", scope=scope, grammar=grammar,
                              image_id="sha256:" + "d" * 64, normalizer_schema=NORMALIZER_SCHEMA,
                              limits={"max_nodes": 10, "max_file_bytes": 100})
    assert first == scope_fingerprint(target_snapshot="snapshot", scope=scope, grammar=grammar,
        image_id="sha256:" + "d" * 64, normalizer_schema=NORMALIZER_SCHEMA,
        limits={"max_file_bytes": 100, "max_nodes": 10})
    changed = replace(scope, files=({**scope.files[0], "sha256": "e" * 64},))
    assert first != scope_fingerprint(target_snapshot="snapshot", scope=changed, grammar=grammar,
        image_id="sha256:" + "d" * 64, normalizer_schema=NORMALIZER_SCHEMA,
        limits={"max_file_bytes": 100, "max_nodes": 10})


def test_normalization_preserves_spans_fields_malformed_flags_and_truncation(tmp_path: Path) -> None:
    scope, grammar = _scope(), _lock()
    output = {"schema": "appsec-review/tree-sitter-container-output/1", "scope_id": scope.scope_id,
              "language": scope.language, "records": [{"kind": "file", "path": "python/app.py",
              "status": "PARTIAL", "sha256": "c" * 64, "bytes": 10, "root_has_error": True,
              "truncated": True, "nodes": [_node(error=True), {**_node(ordinal=(0,), kind="ERROR", missing=True),
              "field": "body"}]}]}
    artifact, identity, counts = normalize_scope(run_root=tmp_path, target_snapshot="snapshot",
        scope=scope, grammar=grammar, fingerprint="f" * 64, container_output=output,
        producer={"job": "fixture"}, artifact_path=tmp_path / "ast.jsonl", index_path=tmp_path / "ast.sqlite")
    rows = [json.loads(line) for line in (tmp_path / artifact["path"]).read_text().splitlines()]
    child = next(row for row in rows if row["field"] == "body")
    assert child["location"]["start_line"] == 1 and child["location"]["start_column"] == 1
    assert child["grammar_native_type"] == "ERROR" and child["missing"] and child["syntax_only"]
    assert counts["diagnostic_count"] == 2 and counts["nodes_parsed"] == 2
    assert any("node limit" in gap for gap in identity.gaps)


def test_unavailable_grammar_is_an_explicit_gap() -> None:
    runnable, gaps = partition_scopes((_scope("Ruby"),), {"Python": _lock()})
    assert runnable == ()
    assert gaps == ({"scope_id": "scope-python", "language": "Ruby",
                     "terminal_status": "UNAVAILABLE", "reason": "grammar unavailable",
                     "gaps": []},)


def test_supported_languages_have_locked_offline_grammars_and_parser_routes() -> None:
    lock = json.loads((ROOT / "containers" / "tools" / "tree-sitter" /
                       "assets.lock.json").read_text(encoding="utf-8"))
    locked = {item["language"] for item in lock["grammars"]} | {"C/C++"}
    parser = runpy.run_path(str(ROOT / "containers" / "tools" / "tree-sitter" / "parser.py"))
    acquisition = runpy.run_path(str(ROOT / "containers" / "tools" / "tree-sitter" /
                                       "acquire_assets.py"))
    assert locked == SUPPORTED_LANGUAGES == set(parser["LANGUAGES"])
    assert set(parser["LANGUAGES"].values()) == set(acquisition["LANGUAGES"])
    expected = {
        "Kotlin": ("kotlin", "c8ac3d2627240160b999a2c100de3babbdb8f419",
                   "4ba2c2f1b00fb74350a335aadc287e4bcd82f8cbec2848f644cc95279ad44a1c"),
        "PowerShell": ("powershell", "d398441825243b00e317e87e1829b9d6a3e54ce0",
                       "610c910b6fb4b265894cf8af035d597d87abef2838206bccaa204629034c09c8"),
        "Shell": ("bash", "a06c2e4415e9bc0346c6b86d401879ffb44058f7",
                  "0a3c99ddb5ba49f35fb890d893af8483049bf9d8d7b1261730acc2488e3d3379"),
    }
    identities = {item["language"]: item for item in lock["grammars"]}
    for language, (grammar, revision, digest) in expected.items():
        assert parser["LANGUAGES"][language] == grammar
        assert (identities[language]["grammar"], identities[language]["revision"],
                identities[language]["sha256"]) == (grammar, revision, digest)
        assert identities[language]["license"] == "MIT"


def test_supported_run_grammars_are_runnable_but_unknown_languages_remain_gaps() -> None:
    languages = ("Kotlin", "PowerShell", "Shell")
    scopes = tuple(replace(_scope(language), scope_id=f"scope-{language.lower()}")
                   for language in languages)
    locks = {language: _lock(language, {"Kotlin": "kotlin", "PowerShell": "powershell",
                                       "Shell": "bash"}[language]) for language in languages}
    runnable, gaps = partition_scopes((*scopes, _scope("Ruby")), locks)
    assert [scope.language for scope in runnable] == list(languages)
    assert gaps == ({"scope_id": "scope-python", "language": "Ruby",
                     "terminal_status": "UNAVAILABLE", "reason": "grammar unavailable",
                     "gaps": []},)


def test_container_request_is_readable_and_scratch_is_writable_by_runtime_user(tmp_path: Path) -> None:
    request_path = _write_container_request(tmp_path / "scope", {"schema": "fixture"})
    request_mode = request_path.stat().st_mode
    scratch_mode = request_path.parent.stat().st_mode
    assert request_mode & stat.S_IROTH
    if os.name != "nt":
        assert not request_mode & stat.S_IWOTH
    assert scratch_mode & stat.S_IWOTH
    assert scratch_mode & stat.S_IXOTH


def test_resume_requires_matching_fingerprint_and_both_immutable_hashes(tmp_path: Path) -> None:
    artifact, index, metadata = tmp_path / "a.jsonl", tmp_path / "a.sqlite", tmp_path / "a.json"
    artifact.write_bytes(b"ast\n")
    index.write_bytes(b"index")
    atomic_json(metadata, {"fingerprint": "f" * 64,
                           "artifact": {"sha256": file_sha256(artifact)},
                           "index_identity": {"sha256": file_sha256(index)}})
    assert reusable_shard(metadata, artifact, index, "f" * 64) is not None
    assert reusable_shard(metadata, artifact, index, "0" * 64) is None
    index.write_bytes(b"changed")
    assert reusable_shard(metadata, artifact, index, "f" * 64) is None


def test_container_output_must_match_locked_tool_image_and_grammar_identity() -> None:
    lock = {"tool_version": "1.0.0", "tree_sitter": {"version": "0.26.0"},
            "language_pack": {"version": "1.12.5"},
            "normalizer_schema": NORMALIZER_SCHEMA}
    output = {"tool": {"id": "tool-tree-sitter", "version": "1.0.0",
        "tree_sitter": "0.26.0", "language_pack": "1.12.5",
        "normalizer_schema": NORMALIZER_SCHEMA, "architecture": "x86_64"},
        "records": [{"status": "SUCCEEDED", "grammar": "python"}]}
    _validate_container_output(output, scope=_scope(), grammar=_lock(), asset_lock=lock,
                               image_id="sha256:locked", execution_image_id="sha256:locked")
    output["tool"]["tree_sitter"] = "changed"
    with pytest.raises(ValueError, match="asset lock"):
        _validate_container_output(output, scope=_scope(), grammar=_lock(), asset_lock=lock,
                                   image_id="sha256:locked", execution_image_id="sha256:locked")


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True,
                          timeout=15).returncode != 0:
            return False
        lock = json.loads((ROOT / "containers" / "tools" / "tree-sitter" /
                           "assets.lock.json").read_text(encoding="utf-8"))
        expected = sorted(item["artifact"] for item in lock["grammars"])
        probe = subprocess.run(["docker", "run", "--rm", "--entrypoint", "python", IMAGE,
            "-c", "from pathlib import Path; print('\\n'.join(sorted(p.name for p in "
                  "Path('/opt/grammars').glob('*.so'))))"], capture_output=True, text=True,
            timeout=15)
        return probe.returncode == 0 and probe.stdout.splitlines() == expected
    except (OSError, subprocess.TimeoutExpired):
        return False


def _cataloged_docker_available() -> bool:
    return IMAGE == DEFAULT_IMAGE and _docker_available()


@pytest.mark.skipif(not _docker_available(), reason="locked Tree-sitter image is not locally available")
def test_live_container_parses_mult_project_multilanguage_fixture_and_proves_identity(tmp_path: Path) -> None:
    catalog = tomllib.loads((ROOT / "containers" / "catalog.toml").read_text(encoding="utf-8"))
    cataloged = next(item for item in catalog["images"] if item["id"] == "tool-tree-sitter")
    inspected = subprocess.run(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"],
                               capture_output=True, text=True, check=True).stdout.strip()
    if IMAGE == DEFAULT_IMAGE:
        assert inspected == cataloged["image_id"]
    cases = [("C", "native/main.c"), ("C++", "native/main.cpp"),
             ("Rust", "rust/src/main.rs"), ("Go", "go/main.go"),
             ("Java", "java/Main.java"), ("JavaScript", "web/src/index.js"),
             ("TypeScript", "web/src/index.ts"), ("TSX", "web/src/view.tsx"),
             ("C#", "dotnet/Program.cs"),
             ("Python", "python/app.py"), ("PHP", "php/index.php"),
             ("Kotlin", "kotlin/Main.kt"), ("PowerShell", "powershell/main.ps1"),
             ("Shell", "shell/main.sh")]
    for language, relative in cases:
        payload = (FIXTURE / relative).read_bytes()
        request = {"schema": "appsec-review/tree-sitter-request/1", "scope_id": language.lower(),
                   "language": language, "max_nodes": 1000, "max_scope_nodes": 1000,
                   "max_file_bytes": 1024 * 1024,
                   "files": [{"path": relative, "sha256": hashlib.sha256(payload).hexdigest()}]}
        scratch = tmp_path / language.lower()
        _write_container_request(scratch, request)
        subprocess.run(["docker", "run", "--rm", "--network", "none", "--read-only",
            "--user", application_runtime_user("10001:10001"), "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--cpus", "2", "--memory", "1g", "--pids-limit", "256",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m",
            "--mount", f"type=bind,src={FIXTURE},dst=/target,readonly",
            "--mount", f"type=bind,src={scratch},dst=/scratch", "--workdir", "/scratch", IMAGE,
            "parse", "--request", "/scratch/request.json", "--output", "/scratch/output.json"],
            capture_output=True, check=True, timeout=60)
        output = json.loads((scratch / "output.json").read_text(encoding="utf-8"))
        assert output["tool"] == {"architecture": "x86_64", "id": "tool-tree-sitter",
            "language_pack": "1.12.5", "normalizer_schema": NORMALIZER_SCHEMA,
            "tree_sitter": "0.26.0", "version": "1.0.0"}
        assert output["records"][0]["status"] == "SUCCEEDED"
        assert output["records"][0]["node_count"] > 1

    payload = (FIXTURE / "python/app.py").read_bytes()
    bounded = tmp_path / "bounded"
    _write_container_request(bounded, {
        "schema": "appsec-review/tree-sitter-request/1", "scope_id": "bounded",
        "language": "Python", "max_nodes": 1000, "max_scope_nodes": 1,
        "max_file_bytes": 1024 * 1024,
        "files": [{"path": "python/app.py", "sha256": hashlib.sha256(payload).hexdigest()}],
    })
    subprocess.run(["docker", "run", "--rm", "--network", "none", "--read-only",
        "--user", application_runtime_user("10001:10001"), "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--cpus", "2", "--memory", "1g", "--pids-limit", "256",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m",
        "--mount", f"type=bind,src={FIXTURE},dst=/target,readonly",
        "--mount", f"type=bind,src={bounded},dst=/scratch", "--workdir", "/scratch", IMAGE,
        "parse", "--request", "/scratch/request.json", "--output", "/scratch/output.json"],
        capture_output=True, check=True, timeout=60)
    bounded_output = json.loads((bounded / "output.json").read_text(encoding="utf-8"))
    assert bounded_output["records"][0]["status"] == "PARTIAL"
    assert bounded_output["records"][0]["node_count"] == 1


@pytest.mark.skipif(not _cataloged_docker_available(),
                    reason="cataloged Tree-sitter image is not locally available")
def test_real_graph_is_parallel_queryable_gapped_and_resumable(tmp_path: Path) -> None:
    base = load_config(ROOT / "appsec-review.toml")
    runtime = replace(base.runtime, runs_dir=tmp_path / "runs", data_dir=tmp_path / "data",
                      metadata_dir=tmp_path / "metadata")
    config = replace(base, runtime=runtime)
    fingerprint = source_fingerprint(FIXTURE)
    jobs = (build_intake(), build_catalog(), build_job())
    outcome = GraphRunner(config, jobs).run(target_root=FIXTURE, source_fingerprint=fingerprint)
    published = outcome["jobs"]["job_tree_sitter_ast"]["result"]["outputs"][
        "acceptance.publish_handoff"]
    assert published["terminal_status"] == "PARTIAL"
    assert any(value.get("language") == "Ruby" and value.get("terminal_status") == "UNAVAILABLE"
               for value in published["dispositions"])
    successful = [value for value in published["dispositions"] if "execution" in value]
    intervals = [(value["execution"]["started_at"], value["execution"]["completed_at"])
                 for value in successful if not value.get("index_reused")]
    assert any(start_a < end_b and start_b < end_a
               for index, (start_a, end_a) in enumerate(intervals)
               for start_b, end_b in intervals[index + 1:])
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    assert core.search(query="identifier", indexes=("analysis",), kinds=("ast_node",))["results"]
    assert any("grammar unavailable" in gap
               for gap in core.coverage(indexes=("analysis",))["coverage_gaps"])
    resumed = GraphRunner(config, jobs).run(target_root=FIXTURE, source_fingerprint=fingerprint,
                                            run_id=outcome["run_id"])
    assert [item["action"] for item in resumed["decisions"]] == ["REUSE", "REUSE", "REUSE"]
