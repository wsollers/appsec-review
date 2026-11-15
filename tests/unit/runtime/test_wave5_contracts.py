"""Wave 5 (T-055 + T-113 registered strictness) unit contract regressions."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.indexing.target_documents import DocumentResult, InventoryIntegrityError
from appsec_review.interchange import (
    GAP_SCHEMA, CoverageDisposition, GapCode, validate_unit_output,
)
from appsec_review.jobs.job_target_catalog import (
    CatalogConfigurationError, CatalogDocumentIntegrityError, CatalogError,
    CatalogIntegrityError, TargetCatalogFailed, build_job,
)
from appsec_review.jobs.job_target_catalog import job as catalog_mod
from appsec_review.runtime.handoff import build_outcomes
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.units import UnitContext
from tests.test_gap_contract import LEGACY_FREE_TEXT_GAPS

ROOT = Path(__file__).resolve().parents[3]
CONFIG = load_config(ROOT / "appsec-review.toml", profile="dev")


@dataclass
class _EventSink:
    rows: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def write(self, event_type: str, **kwargs: Any) -> None:
        self.rows.append((event_type, kwargs))


def _unit_context(
    tmp_path: Path,
    unit_id: str,
    outputs: dict[str, dict[str, Any]] | None = None,
    *,
    target_root: Path | None = ...,  # type: ignore[assignment]
) -> UnitContext:
    run_root = tmp_path / "run"
    attempt_root = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001"
    step_id, task_id = unit_id.split(".")
    unit_root = attempt_root / "steps" / step_id / "tasks" / task_id
    unit_root.mkdir(parents=True, exist_ok=True)
    if target_root is ...:
        resolved_target: Path | None = tmp_path / "target"
        resolved_target.mkdir(parents=True, exist_ok=True)
    else:
        resolved_target = target_root
    job_ctx = SimpleNamespace(
        run_id="run-wave5-unit",
        attempt_id="attempt_0001",
        run_root=run_root,
        attempt_root=attempt_root,
        target_root=resolved_target,
        source_fingerprint="f" * 64,
        config=CONFIG.jobs["job_target_catalog"],
        review_policy=CONFIG.review_policy,
        events=_EventSink(),
    )
    return UnitContext(
        job=job_ctx,  # type: ignore[arg-type]
        unit_id=unit_id,
        step_id=step_id,
        task_id=task_id,
        unit_root=unit_root,
        outputs=outputs if outputs is not None else {},
    )


def _handler(unit_id: str, *, fail_task: str | None = None):
    job = build_job(fail_task=fail_task)
    return next(unit.handler for unit in job.units if unit.unit_id == unit_id)


def _coverage_rows(sqlite_path: Path) -> list[tuple[str, str, str | None]]:
    with sqlite3.connect(sqlite_path) as conn:
        return list(conn.execute("SELECT area, status, gap FROM coverage ORDER BY area"))


def _write_unit_receipts(
    run_root: Path, job_id: str, attempt_id: str, outputs: dict[str, dict[str, Any]]
) -> None:
    for unit_id, payload in outputs.items():
        step_id, task_id = unit_id.split(".")
        task_dir = run_root / "data/jobs" / job_id / "attempts" / attempt_id / "steps" / step_id / "tasks" / task_id
        task_dir.mkdir(parents=True, exist_ok=True)
        raw_result = json.dumps(payload, sort_keys=True).encode("utf-8")
        (task_dir / "result.json").write_bytes(raw_result)
        receipt = {
            "status": "SUCCEEDED",
            "unit_id": unit_id,
            "step_id": step_id,
            "task_id": task_id,
            "result_sha256": hashlib.sha256(raw_result).hexdigest(),
        }
        (task_dir / "status.json").write_text(json.dumps(receipt), encoding="utf-8")


def _assert_strict_records(unit_id: str, result: dict[str, Any]) -> list[dict[str, Any]]:
    validate_unit_output(result, unit_id=unit_id, strict_gaps=True)
    records = list(result["gaps"])
    for record in records:
        assert record["schema"] == GAP_SCHEMA
        assert record["unit_id"] == unit_id
    return records


def test_target_catalog_is_strict_and_off_legacy_exemption_list() -> None:
    built = build_job()
    assert built.strict_gaps is True
    assert "job_target_catalog" not in LEGACY_FREE_TEXT_GAPS


def test_all_fourteen_catalog_units_emit_strict_producer_gaps_and_gap_id_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    (target / ".hg").mkdir(parents=True)
    (target / ".hg/ignored.py").write_text("x = 1\n", encoding="utf-8")
    (target / "src").mkdir(parents=True)
    (target / "src/orphan.c").write_text("int orphan(void) { return 0; }\n", encoding="utf-8")
    (target / "src/bad.py").write_bytes(b"def ok():\n    return 1\n\xff\n")
    (target / "pkg/package.json").parent.mkdir(parents=True)
    (target / "pkg/package.json").write_text(
        json.dumps({"name": "pkg", "dependencies": {"left-pad": "^1.0.0"}, "devDependencies": {"vitest": "^1.0.0"}}),
        encoding="utf-8",
    )
    (target / "broken/package.json").parent.mkdir(parents=True)
    (target / "broken/package.json").write_text("{not-json", encoding="utf-8")
    (target / "native/Cargo.toml").parent.mkdir(parents=True)
    (target / "native/Cargo.toml").write_text('[package]\nname = "demo"\n', encoding="utf-8")
    (target / "docs/broken.postman_collection.json").parent.mkdir(parents=True)
    (target / "docs/broken.postman_collection.json").write_text('{"item":{}}', encoding="utf-8")

    outputs: dict[str, dict[str, Any]] = {}
    job = build_job()
    assert len(job.units) == 14

    for unit in job.units:
        ctx = _unit_context(tmp_path, unit.unit_id, outputs, target_root=target)
        res = dict(unit.handler(ctx))
        records = _assert_strict_records(unit.unit_id, res)
        outputs[unit.unit_id] = res
        if unit.unit_id == "repository_discovery.partition_repository":
            assert any(r["scope_id"] == ".hg" and r["reason"] == ".hg: excluded_directory" for r in records)
            part_doc = json.loads((ctx.job.run_root / res["artifact"]["path"]).read_text(encoding="utf-8"))
            assert part_doc["gaps"] == [{"path": ".hg", "reason": "excluded_directory"}]
        elif unit.unit_id == "build_discovery.discover_compile_commands":
            assert [r["scope_id"] for r in records] == ["compile_commands.json"]
            assert [r["code"] for r in records] == [str(GapCode.PRODUCER_REPORTED_GAP)]
        elif unit.unit_id == "component_discovery.catalog_dependencies":
            codes = {r["scope_id"]: r["code"] for r in records}
            assert codes["pkg/package.json#dependencies.left-pad"] == str(GapCode.PRODUCER_REPORTED_GAP)
            assert codes["broken/package.json"] == str(GapCode.PARSER_ERROR)
            assert codes["native/Cargo.toml"] == str(GapCode.PRODUCER_REPORTED_GAP)

    # Verify all 5 SQLite indices store resolving gap_ids in coverage rows while preserving IndexIdentity.gaps strings.
    run_root = tmp_path / "run"
    _write_unit_receipts(run_root, job.job_id, "attempt_0001", outputs)
    outcomes = build_outcomes(
        run_root,
        run_id="run-wave5-unit",
        job_id=job.job_id,
        attempt_id="attempt_0001",
        target_snapshot="f" * 64,
        unit_ids=[unit.unit_id for unit in job.units],
        strict_gaps=True,
    )
    assert outcomes["coverage"]["disposition"] == str(CoverageDisposition.PARTIAL)
    all_gap_ids = {item["gap_id"] for item in outcomes["gaps"]}

    for index_unit in (
        "retrieval_indexes.build_path_index",
        "retrieval_indexes.build_symbol_index",
        "retrieval_indexes.build_component_index",
        "retrieval_indexes.build_target_documents",
    ):
        idx_out = outputs[index_unit]
        assert all(isinstance(reason, str) for reason in idx_out["index_identity"]["gaps"])
        sqlite_file = tmp_path / "run" / idx_out["artifact"]["path"]
        unit_gap_ids = {item["gap_id"] for item in idx_out["gaps"]}
        for _area, status, gap_col in _coverage_rows(sqlite_file):
            if status == "complete":
                assert gap_col is None
            else:
                assert gap_col is not None
                for gid in gap_col.split(","):
                    assert gid in unit_gap_ids and gid in all_gap_ids

    publish_out = outputs["publish_catalog.publish_handoff"]
    manifest = json.loads((tmp_path / "run" / publish_out["index_manifest"]["path"]).read_text(encoding="utf-8"))
    build_idx = next(item for item in manifest["indexes"] if item["name"] == "build")
    build_sqlite = tmp_path / "run" / build_idx["relative_path"]
    publish_gap_ids = {item["gap_id"] for item in publish_out["gaps"]}
    for _area, status, gap_col in _coverage_rows(build_sqlite):
        if status == "complete":
            assert gap_col is None
        else:
            assert gap_col is not None and gap_col in publish_gap_ids and gap_col in all_gap_ids


def test_empty_target_and_oversized_descriptor_emit_typed_codes(tmp_path: Path) -> None:
    # Empty target exercises empty build_systems, empty projects, no-manifest dependency, and empty build-actions.
    empty_target = tmp_path / "empty_target"
    empty_target.mkdir()
    outputs: dict[str, dict[str, Any]] = {}
    for unit in build_job().units:
        ctx = _unit_context(tmp_path / "empty_run", unit.unit_id, outputs, target_root=empty_target)
        res = dict(unit.handler(ctx))
        _assert_strict_records(unit.unit_id, res)
        outputs[unit.unit_id] = res

    assert outputs["build_discovery.discover_build_systems"]["gaps"][0]["code"] == str(GapCode.EMPTY_RESULT)
    assert outputs["repository_discovery.discover_projects"]["gaps"][0]["code"] == str(GapCode.EMPTY_RESULT)
    assert outputs["component_discovery.catalog_dependencies"]["gaps"][0]["scope_id"] == "component:0001"
    publish_scopes = {r["scope_id"]: r["code"] for r in outputs["publish_catalog.publish_handoff"]["gaps"]}
    assert publish_scopes["build-actions"] == str(GapCode.EMPTY_RESULT)
    assert publish_scopes["compile-units"] == str(GapCode.PRODUCER_REPORTED_GAP)

    # Oversized meson.build exercises GapCode.TRUNCATED scoped to the descriptor path.
    oversized_target = tmp_path / "oversized"
    oversized_target.mkdir()
    meson = oversized_target / "meson.build"
    raw = b"project('huge', 'c')\n"
    meson.write_bytes(raw)
    fake_size = catalog_mod.BUILD_DESCRIPTOR_READ_BYTES + 10
    ctx = _unit_context(
        tmp_path / "oversized_run",
        "build_discovery.discover_build_systems",
        {
            "repository_discovery.partition_repository": {
                "files": [{
                    "path": "meson.build",
                    "size_bytes": fake_size,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "language": None,
                }],
            }
        },
        target_root=oversized_target,
    )
    res = dict(_handler("build_discovery.discover_build_systems")(ctx))
    records = _assert_strict_records("build_discovery.discover_build_systems", res)
    truncated = next(r for r in records if r["scope_id"] == "meson.build")
    assert truncated["code"] == str(GapCode.TRUNCATED)
    assert f"{fake_size} bytes exceeds" in truncated["reason"]


def test_symbol_bounds_and_document_truncation_emit_typed_truncated_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _FastIndexBuilder:
        def __init__(self, path: Path, *, name: str, fingerprint: str, target_snapshot: str) -> None:
            self.path = path
            self.name = name
            self.entities = 0
            self.coverage: list[tuple[str, str, str | None]] = []

        def add_entity(self, _record: Any) -> None:
            self.entities += 1

        def add_relation(self, _record: Any) -> None:
            pass

        def add_coverage(self, area: str, status: str, gap: str | None = None) -> None:
            self.coverage.append((area, status, gap))

        def build(self) -> str:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_bytes(b"sqlite-stub")
            return hashlib.sha256(b"sqlite-stub").hexdigest()

    monkeypatch.setattr(catalog_mod, "IndexBuilder", _FastIndexBuilder)
    target = tmp_path / "target"
    target.mkdir()
    huge = target / "huge.py"
    huge.write_text("def skipped():\n    pass\n", encoding="utf-8")
    many = target / "many.py"
    many_bytes = b"def sym():\n" * 50_001
    many.write_bytes(many_bytes)

    part_artifact = {"path": "data/jobs/job_target_catalog/attempts/attempt_0001/artifacts/catalog/p.json",
                     "sha256": "a" * 64, "size_bytes": 2}
    sym_ctx = _unit_context(
        tmp_path / "sym",
        "retrieval_indexes.build_symbol_index",
        {
            "repository_discovery.partition_repository": {
                "artifact": part_artifact,
                "files": [
                    {"path": "huge.py", "size_bytes": 16 * 1024 * 1024 + 1,
                     "sha256": hashlib.sha256(huge.read_bytes()).hexdigest(),
                     "language": "Python", "scope_role": "target_source"},
                    {"path": "many.py", "size_bytes": len(many_bytes),
                     "sha256": hashlib.sha256(many_bytes).hexdigest(),
                     "language": "Python", "scope_role": "target_source"},
                ],
                "gaps": [],
            }
        },
        target_root=target,
    )
    sym_res = dict(_handler("retrieval_indexes.build_symbol_index")(sym_ctx))
    sym_records = _assert_strict_records("retrieval_indexes.build_symbol_index", sym_res)
    assert [(r["scope_id"], r["code"]) for r in sym_records] == [
        ("huge.py", str(GapCode.TRUNCATED)),
        ("symbols", str(GapCode.TRUNCATED)),
    ]

    # Document gap cap at 200 + 1 truncated record.
    monkeypatch.setattr(
        catalog_mod,
        "collect_target_documents",
        lambda *_args, **_kwargs: DocumentResult(
            records=(),
            links=(),
            gaps=tuple({"path": f"docs/doc_{i:03d}.md", "reason": "parse_error", "detail": "bad"} for i in range(205)),
        ),
    )
    doc_ctx = _unit_context(
        tmp_path / "doc",
        "retrieval_indexes.build_target_documents",
        {
            "repository_discovery.partition_repository": {
                "artifact": part_artifact,
                "files": [],
                "gaps": [],
            }
        },
        target_root=target,
    )
    doc_res = dict(_handler("retrieval_indexes.build_target_documents")(doc_ctx))
    doc_records = _assert_strict_records("retrieval_indexes.build_target_documents", doc_res)
    assert len(doc_records) == 201
    assert doc_records[-1]["code"] == str(GapCode.TRUNCATED)
    assert doc_records[-1]["scope_id"] == "target-documents"
    assert "additional gap(s)" in doc_records[-1]["reason"]


def test_typed_catalog_error_hierarchy_covers_config_integrity_document_and_failure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 1. Missing target root -> CatalogConfigurationError (CatalogError + ValueError).
    no_target_ctx = _unit_context(tmp_path / "no_target", "repository_discovery.partition_repository", target_root=None)
    with pytest.raises(CatalogConfigurationError) as cfg_exc:
        _handler("repository_discovery.partition_repository")(no_target_ctx)
    assert isinstance(cfg_exc.value, (CatalogError, ValueError))

    # 2. Config validator mismatch -> CatalogConfigurationError.
    bad_cfg = SimpleNamespace(config=SimpleNamespace(steps={}))
    with pytest.raises(CatalogConfigurationError):
        build_job().input_validators[0](bad_cfg, None)  # type: ignore[arg-type]

    # 3. Injected failure -> TargetCatalogFailed (CatalogError + RuntimeError).
    fail_ctx = _unit_context(tmp_path / "fail", "repository_discovery.partition_repository")
    with pytest.raises(TargetCatalogFailed) as fail_exc:
        _handler("repository_discovery.partition_repository", fail_task="repository_discovery.partition_repository")(fail_ctx)
    assert isinstance(fail_exc.value, (CatalogError, RuntimeError))

    # 4. descriptor_reader changed bytes & escaped symlink -> CatalogIntegrityError.
    target = tmp_path / "desc_target"
    target.mkdir()
    cmake = target / "CMakeLists.txt"
    cmake.write_bytes(b"project(demo)\n")
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"secret\n")
    (target / "escape.cmake").symlink_to(outside)
    accepted = {
        "CMakeLists.txt": {"size_bytes": 14, "sha256": "0" * 64},
        "escape.cmake": {"size_bytes": 7, "sha256": hashlib.sha256(b"secret\n").hexdigest()},
    }
    read_text, changed, _unread = catalog_mod.descriptor_reader(target, accepted)
    with pytest.raises(CatalogIntegrityError):
        read_text("CMakeLists.txt")
    assert changed == ["CMakeLists.txt"]
    with pytest.raises(CatalogIntegrityError):
        read_text("escape.cmake")

    # 5. Document integrity errors inherit both CatalogIntegrityError and InventoryIntegrityError.
    doc_target = tmp_path / "doc_target"
    doc_target.mkdir()
    doc_file = doc_target / "openapi.json"
    doc_file.write_text("{}\n", encoding="utf-8")
    part_artifact = {"path": "p.json", "sha256": "a" * 64, "size_bytes": 2}
    monkeypatch.setattr(
        catalog_mod,
        "collect_target_documents",
        lambda *_args, **_kwargs: DocumentResult(
            records=({
                "id": "rec-1", "path": "openapi.json", "file_sha256": "b" * 64,
                "line": 1, "end_line": 1, "kind": "openapi", "subtype": "spec",
                "text": "{}", "authority": "declared", "fields": {},
            },),
            links=(),
            gaps=(),
        ),
    )
    doc_ctx = _unit_context(
        tmp_path / "doc_err",
        "retrieval_indexes.build_target_documents",
        {"repository_discovery.partition_repository": {"artifact": part_artifact, "files": [], "gaps": []}},
        target_root=doc_target,
    )
    with pytest.raises(CatalogDocumentIntegrityError) as doc_exc:
        _handler("retrieval_indexes.build_target_documents")(doc_ctx)
    assert isinstance(doc_exc.value, (CatalogError, CatalogIntegrityError, InventoryIntegrityError, ValueError))

    # 6. validate_catalog tampered index -> CatalogIntegrityError.
    val_ctx = _unit_context(tmp_path / "val_err", "publish_catalog.validate_catalog")
    for idx_unit in (
        "retrieval_indexes.build_path_index",
        "retrieval_indexes.build_symbol_index",
        "retrieval_indexes.build_component_index",
        "retrieval_indexes.build_target_documents",
    ):
        val_ctx.outputs[idx_unit] = {"artifact": {"path": "missing.sqlite", "sha256": "a" * 64}, "gaps": []}  # type: ignore[index]
    with pytest.raises(CatalogIntegrityError):
        _handler("publish_catalog.validate_catalog")(val_ctx)


def test_registered_strict_gaps_contract_distinguishes_strict_and_legacy_normalization(
    tmp_path: Path,
) -> None:
    registry = builtin_registry()
    strict_job = registry.build("job_target_catalog")
    legacy_job = registry.build("job_language_build")
    assert strict_job.strict_gaps is True
    assert legacy_job.strict_gaps is False and "job_language_build" in LEGACY_FREE_TEXT_GAPS

    with pytest.raises(ValueError, match="producer-gap/1"):
        validate_unit_output({"gaps": ["free text gap"]}, unit_id="step.task", strict_gaps=strict_job.strict_gaps)

    # Registered lenient jobs validate unit output at strict_gaps=False and normalize on publication.
    validate_unit_output({"gaps": ["free text gap"]}, unit_id="step.task", strict_gaps=legacy_job.strict_gaps)
    run_root = tmp_path / "legacy_run"
    _write_unit_receipts(run_root, legacy_job.job_id, "attempt_0001", {"step.task": {"gaps": ["free text gap"]}})
    normalized = build_outcomes(
        run_root,
        run_id="run-legacy",
        job_id=legacy_job.job_id,
        attempt_id="attempt_0001",
        target_snapshot="f" * 64,
        unit_ids=("step.task",),
        strict_gaps=legacy_job.strict_gaps,
    )
    assert normalized["coverage"]["disposition"] == str(CoverageDisposition.PARTIAL)
    assert normalized["gaps"][0]["schema"] == GAP_SCHEMA
    assert normalized["gaps"][0]["reason"] == "free text gap"
