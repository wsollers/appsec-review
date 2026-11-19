"""Unit tests for scope_execution.py: request permissions, container validation, reuse and failures."""

from __future__ import annotations

from dataclasses import asdict, replace
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import ExecutionResult, load_catalog
from appsec_review.jobs.job_tree_sitter_ast import GrammarLock, Scope
from appsec_review.jobs.job_tree_sitter_ast.datasets import DATASETS
from appsec_review.jobs.job_tree_sitter_ast.job import _grammar_locks
from appsec_review.jobs.job_tree_sitter_ast.normalize import NORMALIZER_SCHEMA
from appsec_review.jobs.job_tree_sitter_ast.scope_execution import (
    _validate_container_output,
    _write_container_request,
    parse_scope,
)
from appsec_review.observability import aggregate_run_metrics
from appsec_review.retrieval.source_resolution import publish_source
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner, reference

ROOT = Path(__file__).resolve().parents[3]


def _lock(language: str = "Python", grammar: str = "python") -> GrammarLock:
    return GrammarLock(
        language, grammar, f"https://example.invalid/tree-sitter-{grammar}",
        "a" * 40, "MIT", f"libtree_sitter_{grammar}.so", "b" * 64,
    )


def _scope(language: str = "Python", digest: str = "c" * 64, size: int = 10) -> Scope:
    return Scope(
        "scope-python", "component:0001", "python", "source:component:0001",
        "python", language,
        ({"path": "python/app.py", "sha256": digest, "size_bytes": size, "language": language},),
    )


class _FakeScopeExecutor:
    def __init__(
        self,
        *,
        image_id: str,
        asset_lock: dict[str, Any],
        exit_code: int = 0,
        timed_out: bool = False,
        oom_killed: bool = False,
        omit_output: bool = False,
        truncate_second: bool = False,
    ) -> None:
        self.image_id = image_id
        self.asset_lock = asset_lock
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.oom_killed = oom_killed
        self.omit_output = omit_output
        self.truncate_second = truncate_second
        self.calls = 0

    def execute(self, request: Any) -> ExecutionResult:
        self.calls += 1
        now = "2026-10-10T00:00:00+00:00"
        if not self.omit_output and self.exit_code == 0 and not self.timed_out and not self.oom_killed:
            payload = json.loads((request.scratch_root / "request.json").read_text(encoding="utf-8"))
            grammar_by_lang = {item["language"]: item["grammar"] for item in self.asset_lock["grammars"]}
            records = []
            for idx, item in enumerate(payload["files"]):
                if self.truncate_second and idx == 1:
                    records.append({
                        "kind": "file",
                        "path": item["path"],
                        "status": "TRUNCATED",
                        "reason": "file_byte_limit",
                        "sha256": item["sha256"],
                        "bytes": 100,
                    })
                    continue
                data = (request.target_root / item["path"]).read_bytes()
                records.append({
                    "kind": "file",
                    "path": item["path"],
                    "status": "SUCCEEDED",
                    "sha256": item["sha256"],
                    "bytes": len(data),
                    "grammar": grammar_by_lang[payload["language"]],
                    "root_has_error": False,
                    "truncated": False,
                    "node_count": 1,
                    "nodes": [{
                        "ordinal_path": [],
                        "field": None,
                        "type": "module",
                        "named": True,
                        "error": False,
                        "missing": False,
                        "extra": False,
                        "has_error": False,
                        "start_byte": 0,
                        "end_byte": len(data),
                        "start_point": [0, 0],
                        "end_point": [0, len(data)],
                    }],
                })
            output = {
                "schema": "appsec-review/tree-sitter-container-output/1",
                "tool": {
                    "id": "tool-tree-sitter",
                    "version": self.asset_lock["tool_version"],
                    "tree_sitter": self.asset_lock["tree_sitter"]["version"],
                    "language_pack": self.asset_lock["language_pack"]["version"],
                    "normalizer_schema": self.asset_lock["normalizer_schema"],
                    "architecture": "x86_64",
                },
                "scope_id": payload["scope_id"],
                "language": payload["language"],
                "records": records,
            }
            (request.scratch_root / "output.json").write_text(json.dumps(output), encoding="utf-8")
        return ExecutionResult(
            "appsec-review/container-execution/1", "tool-tree-sitter", "tool-tree-sitter:test",
            self.image_id, self.image_id, "fake", (), {}, now, now,
            self.exit_code, self.timed_out, self.oom_killed, False, False, "", "", "",
        )


def _make_unit(tmp_path: Path, target_root: Path, attempt_id: str = "attempt_0001") -> tuple[SimpleNamespace, SharedArtifacts, dict[str, Any], str]:
    run_root = tmp_path / "run-1"
    run_root.mkdir(parents=True, exist_ok=True)
    attempt_root = run_root / "data/jobs/job_tree_sitter_ast/attempts" / attempt_id
    actor = {
        "run_id": "run-1",
        "job_id": "job_tree_sitter_ast",
        "attempt_id": attempt_id,
        "orchestration": {"system": "fixture"},
    }
    atomic_json(attempt_root / "claim.json", {
        **actor,
        "attempt_path": attempt_root.relative_to(run_root).as_posix(),
        "dataset_contract": dataset_contract(
            "job_tree_sitter_ast", ("load", "plan", "parse", "acceptance"), DATASETS
        ),
    })
    owner = SharedArtifacts(run_root, attempt_root, {**actor, "claim": reference(run_root, attempt_root / "claim.json")})
    locks, asset_lock = _grammar_locks(ROOT)
    image_id = load_catalog(ROOT).tool("tool-tree-sitter").expected_image_id
    job_cfg = load_config(ROOT / "appsec-review.toml").job("job_tree_sitter_ast")
    job_ctx = SimpleNamespace(
        job_id="job_tree_sitter_ast",
        run_id="run-1",
        attempt_id=attempt_id,
        run_root=run_root,
        attempt_root=attempt_root,
        target_root=target_root,
        repository_root=ROOT,
        source_fingerprint="snap-1",
        config=job_cfg,
    )
    loaded = {
        "grammar_locks": {k: asdict(v) for k, v in locks.items()},
        "asset_lock": asset_lock,
        "image_id": image_id,
    }
    unit = SimpleNamespace(
        job=job_ctx,
        unit_id="parse.dynamic_scopes",
        step_id="parse",
        task_id="dynamic_scopes",
        unit_root=attempt_root / "steps/parse/tasks/dynamic_scopes",
        outputs=MappingProxyType({"load.accepted_inputs": loaded}),
        output=lambda name: loaded if name == "load.accepted_inputs" else None,
    )
    return unit, owner, asset_lock, image_id


def test_container_request_is_readable_and_scratch_is_writable_by_runtime_user(tmp_path: Path) -> None:
    request_path = _write_container_request(tmp_path / "scope", {"schema": "fixture"})
    request_mode = request_path.stat().st_mode
    scratch_mode = request_path.parent.stat().st_mode
    assert request_mode & stat.S_IROTH
    if os.name != "nt":
        assert not request_mode & stat.S_IWOTH
    assert scratch_mode & stat.S_IWOTH
    assert scratch_mode & stat.S_IXOTH


def test_container_output_must_match_locked_tool_image_and_grammar_identity() -> None:
    lock = {
        "tool_version": "1.0.0",
        "tree_sitter": {"version": "0.26.0"},
        "language_pack": {"version": "1.12.5"},
        "normalizer_schema": NORMALIZER_SCHEMA,
    }
    output: dict[str, Any] = {
        "tool": {
            "id": "tool-tree-sitter",
            "version": "1.0.0",
            "tree_sitter": "0.26.0",
            "language_pack": "1.12.5",
            "normalizer_schema": NORMALIZER_SCHEMA,
            "architecture": "x86_64",
        },
        "records": [
            {"status": "SUCCEEDED", "grammar": "python"},
            {"status": "TRUNCATED", "grammar": None},
        ],
    }
    _validate_container_output(
        output, scope=_scope(), grammar=_lock(), asset_lock=lock,
        image_id="sha256:locked", execution_image_id="sha256:locked",
    )
    with pytest.raises(ValueError, match="image identity changed"):
        _validate_container_output(
            output, scope=_scope(), grammar=_lock(), asset_lock=lock,
            image_id="sha256:locked", execution_image_id="sha256:other",
        )
    with pytest.raises(ValueError, match="omitted the locked tool identity"):
        _validate_container_output(
            {"records": []}, scope=_scope(), grammar=_lock(), asset_lock=lock,
            image_id="sha256:locked", execution_image_id="sha256:locked",
        )
    with pytest.raises(ValueError, match="asset lock"):
        _validate_container_output(
            {**output, "tool": {**output["tool"], "tree_sitter": "changed"}},
            scope=_scope(), grammar=_lock(), asset_lock=lock,
            image_id="sha256:locked", execution_image_id="sha256:locked",
        )
    with pytest.raises(ValueError, match="invalid file disposition"):
        _validate_container_output(
            {**output, "records": [{"status": "BOGUS", "grammar": "python"}]},
            scope=_scope(), grammar=_lock(), asset_lock=lock,
            image_id="sha256:locked", execution_image_id="sha256:locked",
        )
    with pytest.raises(ValueError, match="grammar identity does not match"):
        _validate_container_output(
            {**output, "records": [{"status": "SUCCEEDED", "grammar": "ruby"}]},
            scope=_scope(), grammar=_lock(), asset_lock=lock,
            image_id="sha256:locked", execution_image_id="sha256:locked",
        )


def test_parse_scope_executes_reuses_records_metrics_and_stages_generated_inputs(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "python").mkdir(parents=True)
    body = b"def check():\n    return 1\n"
    (target / "python/app.py").write_bytes(body)
    (target / "python/big.py").write_bytes(b"x = 1\n" * 20)

    unit1, owner1, asset_lock, image_id = _make_unit(tmp_path, target, "attempt_0001")
    scope = Scope(
        "scope-python", "component:0001", "python", "source:component:0001", "python", "Python",
        (
            {"path": "python/app.py", "sha256": file_sha256(target / "python/app.py"), "size_bytes": len(body), "language": "Python"},
            {"path": "python/big.py", "sha256": file_sha256(target / "python/big.py"), "size_bytes": 120, "language": "Python"},
        ),
    )
    fake = _FakeScopeExecutor(image_id=image_id, asset_lock=asset_lock, truncate_second=True)

    with publication_scope_for_owner(owner1):
        first = parse_scope(unit1, asdict(scope), lambda _: fake)  # type: ignore[arg-type]
    assert first["terminal_status"] == "PARTIAL"
    assert not first["index_reused"]
    assert fake.calls == 1

    unit2, owner2, _, _ = _make_unit(tmp_path, target, "attempt_0002")
    with publication_scope_for_owner(owner2):
        second = parse_scope(unit2, asdict(scope), lambda _: fake)  # type: ignore[arg-type]
    assert second["index_reused"] is True
    assert fake.calls == 1
    assert first["tree_sitter_invocation_id"] == second["tree_sitter_invocation_id"]

    summary = aggregate_run_metrics(unit1.job.run_root)["tree_sitter"]
    assert summary["invocation_count"] == 1
    assert summary["reused_scope_count"] == 1

    # Generated source scope stages 0o444 detached input outside writable /scratch
    from appsec_review.retrieval.model import EntityKind, LogicalIdentity
    from appsec_review.retrieval.source_resolution import generated_path
    gen_data = b"y = 2\n"
    gen_sha = hashlib.sha256(gen_data).hexdigest()
    canonical = LogicalIdentity.derive(
        EntityKind.BUILD_ARTIFACT,
        "snap-1",
        {"build_unit_id": "bu:1", "workspace_path": "gen.py", "sha256": gen_sha, "format": "generated-code"},
    )
    logical_path = generated_path(canonical.value, "gen.py")
    with publication_scope_for_owner(owner1):
        backing = publish_source(
            unit1.job.run_root,
            target_snapshot="snap-1",
            logical_path=logical_path,
            artifact={"path": "data/build/gen.py", "workspace_path": "gen.py", "sha256": gen_sha,
                      "size_bytes": len(gen_data), "canonical_identity": canonical.value,
                      "kind": "generated-code", "scope_role": "deliverable",
                      "artifact_origin": "build-output"},
            build_unit_id="bu:1",
            handoff_sha256="c" * 64,
            data=gen_data,
        )
        gen_scope = Scope(
            "scope-gen", "component:0001", ".", "generated:bu:1", ".", "Python",
            ({
                "path": logical_path,
                "sha256": gen_sha,
                "size_bytes": len(gen_data),
                "language": "Python",
                "generated": True,
                "source_domain": "generated",
                "source_backing": backing,
            },),
        )
        gen_exec = _FakeScopeExecutor(image_id=image_id, asset_lock=asset_lock)
        gen_res = parse_scope(unit1, asdict(gen_scope), lambda _: gen_exec)  # type: ignore[arg-type]
    assert gen_res["terminal_status"] == "SUCCEEDED"
    staged = unit1.job.run_root / "data/treesitter/inputs" / gen_res["fingerprint"] / logical_path
    assert staged.read_bytes() == gen_data
    if os.name != "nt":
        assert (staged.stat().st_mode & 0o777) == 0o444


@pytest.mark.parametrize("change", ["algorithm", "bound"])
def test_changed_cfg_identity_creates_new_checkpoint_and_preserves_old_bytes(tmp_path, monkeypatch, change):
    from appsec_review.jobs.job_tree_sitter_ast import cfg
    target = tmp_path / "target"
    (target / "python").mkdir(parents=True)
    data = b"x = 1\n"
    (target / "python/app.py").write_bytes(data)
    scope = _scope(digest=hashlib.sha256(data).hexdigest(), size=len(data))
    unit, owner, asset_lock, image_id = _make_unit(tmp_path, target)
    fake = _FakeScopeExecutor(image_id=image_id, asset_lock=asset_lock)
    with publication_scope_for_owner(owner):
        first = parse_scope(unit, asdict(scope), lambda _: fake)
    old_paths = [
        unit.job.run_root / first["artifact"]["path"],
        unit.job.run_root / first["index_identity"]["relative_path"],
        unit.job.run_root / f"data/treesitter/shards/{first['fingerprint']}.json",
        *(unit.job.run_root / ref["path"] for ref in first["cfg_artifacts"].values()),
    ]
    old_bytes = {p: p.read_bytes() for p in old_paths}
    if change == "algorithm":
        monkeypatch.setattr(cfg, "CFG_BUILDER_IDENTITY", "test-cfg-builder/next", raising=False)
    else:
        monkeypatch.setattr(cfg, "MAX_CFG_NODES_PER_FUNCTION", cfg.MAX_CFG_NODES_PER_FUNCTION - 1)
    next_unit, next_owner, _, _ = _make_unit(tmp_path, target, "attempt_0002")
    with publication_scope_for_owner(next_owner):
        second = parse_scope(next_unit, asdict(scope), lambda _: fake)
        reused = parse_scope(next_unit, asdict(scope), lambda _: fake)
    assert second["fingerprint"] != first["fingerprint"]
    assert second["artifact"]["path"] != first["artifact"]["path"]
    assert fake.calls == 2
    assert not second["index_reused"] and reused["index_reused"]
    assert second["cfg_builder"]["max_nodes_per_function"] == cfg.MAX_CFG_NODES_PER_FUNCTION
    assert second["cfg_builder"]["algorithm"] == cfg.CFG_BUILDER_IDENTITY
    assert {p: p.read_bytes() for p in old_paths} == old_bytes


def test_checkpoint_missing_cfg_builder_identity_is_not_relabelled_or_overwritten(tmp_path):
    target = tmp_path / "target"
    (target / "python").mkdir(parents=True)
    data = b"x = 1\n"
    (target / "python/app.py").write_bytes(data)
    scope = _scope(digest=hashlib.sha256(data).hexdigest(), size=len(data))
    unit, owner, asset_lock, image_id = _make_unit(tmp_path, target)
    fake = _FakeScopeExecutor(image_id=image_id, asset_lock=asset_lock)
    with publication_scope_for_owner(owner):
        first = parse_scope(unit, asdict(scope), lambda _: fake)
        metadata_path = unit.job.run_root / f"data/treesitter/shards/{first['fingerprint']}.json"
        metadata = json.loads(metadata_path.read_text())
        metadata.pop("cfg_builder", None)
        atomic_json(metadata_path, metadata)
        before = metadata_path.read_bytes()
        with pytest.raises(ValueError, match="CFG checkpoint builder identity mismatch"):
            parse_scope(unit, asdict(scope), lambda _: fake)
    assert fake.calls == 1
    assert metadata_path.read_bytes() == before


def test_recorded_unsupported_cfg_makes_successful_parser_scope_partial(tmp_path: Path) -> None:
    fixture = ROOT / "tests/fixtures/review_prioritization"
    path = "native/src/codec.c"
    record = json.loads(gzip.decompress((fixture / "ast-golden.json.gz").read_bytes()))["files"][path]
    source = (fixture / "target" / path).read_bytes()
    assert hashlib.sha256(source).hexdigest() == record["sha256"]
    assert not record["root_has_error"]
    target = tmp_path / "target"
    (target / path).parent.mkdir(parents=True)
    (target / path).write_bytes(source)
    unit, owner, asset_lock, image_id = _make_unit(tmp_path, target)
    language = next(lang for lang, lock in unit.outputs["load.accepted_inputs"]["grammar_locks"].items()
                    if lock["grammar"] == record["grammar"])
    scope = Scope("scope-cfg", "component", ".", "source:component", ".", language, ({
        "path": path, "sha256": record["sha256"], "size_bytes": len(source), "language": language,
    },))

    class RecordedExecutor(_FakeScopeExecutor):
        def execute(self, request: Any) -> ExecutionResult:
            result = super().execute(request)
            output_path = request.scratch_root / "output.json"
            output = json.loads(output_path.read_text())
            output["records"][0].update(
                nodes=record["nodes"], node_count=len(record["nodes"]), root_has_error=False,
            )
            output_path.write_text(json.dumps(output))
            return result

    fake = RecordedExecutor(image_id=image_id, asset_lock=asset_lock)
    with publication_scope_for_owner(owner):
        result = parse_scope(unit, asdict(scope), lambda _: fake)
    assert fake.calls == 1
    assert result["terminal_status"] == "PARTIAL"
    assert any("cfg_unmodeled_construct:goto_statement" in gap for gap in result["gaps"])
    assert result["gaps"] == list(result["index_identity"]["gaps"])
    assert result["counts"]["files_parsed"] == 1
    assert result["counts"]["cfg_partial_functions"] >= 1
    manifest = json.loads((unit.job.run_root / result["cfg_artifacts"]["manifest"]["path"]).read_text())
    assert manifest["counts"]["cfg_partial_functions"] == result["counts"]["cfg_partial_functions"]


def test_parse_scope_handles_container_failures_missing_output_and_guard_errors(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "python").mkdir(parents=True)
    (target / "python/app.py").write_bytes(b"x = 1\n")
    sha = file_sha256(target / "python/app.py")
    unit, owner, asset_lock, image_id = _make_unit(tmp_path, target)
    scope = _scope(digest=sha, size=6)

    # Non-zero container exit returns FAILED scope result without raising
    fail_exec = _FakeScopeExecutor(image_id=image_id, asset_lock=asset_lock, exit_code=137, oom_killed=True)
    with publication_scope_for_owner(owner):
        failed = parse_scope(unit, asdict(scope), lambda _: fail_exec)  # type: ignore[arg-type]
    assert failed["terminal_status"] == "FAILED"
    assert "exit 137" in failed["gaps"][0]

    # Zero exit with missing output.json raises ValueError
    omit_exec = _FakeScopeExecutor(image_id=image_id, asset_lock=asset_lock, omit_output=True)
    with publication_scope_for_owner(owner):
        with pytest.raises(ValueError, match="omitted its declared output"):
            parse_scope(unit, asdict(scope), lambda _: omit_exec)  # type: ignore[arg-type]

    # Out-of-scope file rejected
    bad_scope = replace(scope, files=({**scope.files[0], "scope_role": "supplied_platform"},))
    with pytest.raises(ValueError, match="out-of-scope source"):
        parse_scope(unit, asdict(bad_scope), lambda _: omit_exec)  # type: ignore[arg-type]

    # Mixed generated + target files rejected
    mixed = replace(scope, files=(scope.files[0], {**scope.files[0], "path": "g.py", "source_backing": {}}))
    with pytest.raises(ValueError, match="separate parser mounts"):
        parse_scope(unit, asdict(mixed), lambda _: omit_exec)  # type: ignore[arg-type]

    # Generated scope exceeding max_files_per_scope rejected
    small_cfg = replace(unit.job.config, settings={**unit.job.config.settings, "max_files_per_scope": 1})
    small_unit = SimpleNamespace(**{**unit.__dict__, "job": SimpleNamespace(**{**unit.job.__dict__, "config": small_cfg})})
    two_gen = replace(
        scope,
        files=(
            {**scope.files[0], "path": "g1.py", "source_backing": {}},
            {**scope.files[0], "path": "g2.py", "source_backing": {}},
        ),
    )
    with pytest.raises(ValueError, match="exceeds configured bounds"):
        parse_scope(small_unit, asdict(two_gen), lambda _: omit_exec)  # type: ignore[arg-type]
