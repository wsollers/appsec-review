"""Helper and 16-unit handler unit tests for job_review_data_indexing."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import tomllib
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest

from appsec_review.config import ToolCapabilityConfig, load_config
from appsec_review.config.assurance import ReviewPolicy
from appsec_review.indexing import fts_worker
from appsec_review.indexing.store import AcceptedHandoff
from appsec_review.jobs.job_review_data_indexing.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_review_data_indexing.job import (
    FEED_INDEXES,
    FEED_STEPS,
    JOB_ID,
    PRODUCT_SETS,
    SCHEMA,
    TOPOLOGY,
    _artifact,
    _read,
    _resolved_document,
    _resolved_steps,
    _self_rows,
    _unit_statuses,
    build_job,
    feed_pins,
    graph_follow_up,
    owasp_status,
    reconcile_shards,
)
from appsec_review.jobs.job_third_party_data_sync.publication import publish_snapshot
from appsec_review.observability import EventLog
from appsec_review.retrieval import (
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RelationKind,
    RelationRecord,
    SourceLocation,
    index_fingerprint,
    write_manifest,
)
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import JobContext, UnitContext
from appsec_review.runtime.datasets import artifact_only, dataset_contract, indexed
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff


REPO_ROOT = Path(__file__).resolve().parents[3]
SNAPSHOT = "target-sha256:" + "9" * 64
CATALOG_FTS_IMAGE = "sha256:" + "4" * 64


def _make_pinned_repo(repo_root: Path) -> Path:
    (repo_root / "containers" / "tools" / "sqlite-fts").mkdir(parents=True, exist_ok=True)
    (repo_root / "containers" / "runtime-policy.toml").write_bytes(
        (REPO_ROOT / "containers" / "runtime-policy.toml").read_bytes()
    )
    (repo_root / "containers" / "tools" / "sqlite-fts" / "tool.toml").write_bytes(
        (REPO_ROOT / "containers" / "tools" / "sqlite-fts" / "tool.toml").read_bytes()
    )
    (repo_root / "containers" / "catalog.toml").write_text(
        'schema = "appsec-review/container-catalog/1"\n'
        'runtime_policy = "containers/runtime-policy.toml"\n'
        "[[images]]\n"
        f'id = "{fts_worker.TOOL_ID}"\n'
        'state = "enabled"\n'
        'kind = "tool"\n'
        'version = "1.0.0"\n'
        'tag = "appsec-review/tool-sqlite-fts:1.0.0"\n'
        'tool_manifest = "containers/tools/sqlite-fts/tool.toml"\n'
        f'image_id = "{CATALOG_FTS_IMAGE}"\n',
        encoding="utf-8",
    )
    return repo_root


@dataclass
class FakeFtsResult:
    exit_code: int | None
    timed_out: bool
    oom_killed: bool
    image_id: str
    stdout_path: str
    receipt_path: str


class InProcessSqliteFts:
    """In-memory/SQLite-only fake for tool-sqlite-fts container requests (no subprocess)."""

    def __init__(self, run_root: Path, image_id: str) -> None:
        self.run_root = run_root
        self.image_id = image_id
        self.calls: list[str] = []

    def execute(self, request: Any) -> FakeFtsResult:
        cmd = request.argv[1]
        self.calls.append(cmd)
        scratch: Path = request.scratch_root
        (scratch / "raw").mkdir(parents=True, exist_ok=True)
        stdout_path = scratch / "raw" / "stdout.bin"
        receipt_path = scratch / "execution.json"
        if cmd == "probe":
            stdout_path.write_text(f"FTS5 ready ({sqlite3.sqlite_version})\n", encoding="utf-8")
        elif cmd == "build":
            docs_path = request.target_root / "documents.jsonl"
            raw = docs_path.read_bytes()
            rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
            db_path = scratch / "search.sqlite"
            with sqlite3.connect(db_path) as conn:
                conn.execute(
                    "CREATE VIRTUAL TABLE search_fts USING fts5(identity UNINDEXED, name, path, text, tokenize='unicode61')"
                )
                conn.executemany(
                    "INSERT INTO search_fts(identity, name, path, text) VALUES (?, ?, ?, ?)",
                    [(row["identity"], row["name"], row["path"], row["text"]) for row in rows],
                )
            report = {
                "record_count": len(rows),
                "input_sha256": hashlib.sha256(raw).hexdigest(),
                "sqlite_version": sqlite3.sqlite_version,
            }
            stdout_path.write_text(json.dumps(report) + "\n", encoding="utf-8")
        elif cmd == "verify":
            db_path = request.target_root / "search.sqlite"
            with sqlite3.connect(db_path) as conn:
                count = int(conn.execute("SELECT count(*) FROM search_fts").fetchone()[0])
            stdout_path.write_text(json.dumps({"record_count": count, "status": "ok"}) + "\n", encoding="utf-8")
        else:
            raise ValueError(f"unexpected command: {cmd}")
        atomic_json(receipt_path, {"tool_id": request.tool_id, "exit_code": 0})
        return FakeFtsResult(
            0,
            False,
            False,
            self.image_id,
            stdout_path.relative_to(self.run_root).as_posix(),
            receipt_path.relative_to(self.run_root).as_posix(),
        )


def _write_resolved_config(run_root: Path, document: dict[str, Any]) -> None:
    cfg = run_root / "data" / "configuration"
    cfg.mkdir(parents=True, exist_ok=True)
    full_doc = dict(document)
    if "build_capture" not in full_doc:
        base_doc = json.loads(load_config(REPO_ROOT / "appsec-review.toml").resolved_json)
        full_doc["build_capture"] = base_doc["build_capture"]
    resolved_path = cfg / "resolved.json"
    atomic_json(resolved_path, full_doc)
    atomic_json(cfg / "manifest.json", {"resolved_sha256": file_sha256(resolved_path)})


def _build_shard(
    run_root: Path,
    *,
    name: str,
    shard_id: str,
    producer_job: str,
    entities: list[EntityRecord],
    unit_name: str = "s1.u1",
) -> IndexIdentity:
    fp = index_fingerprint(
        name=name,
        target_snapshot=SNAPSHOT,
        producer_artifacts=[{"shard": shard_id, "job": producer_job}],
        tool_identity={"job": producer_job},
        parser_identity="u/1",
        normalizer_identity="u/1",
        mapping_identity="u/1",
    )
    shard_path = run_root / "data" / "indices" / name / shard_id / f"{fp}.sqlite"
    builder = IndexBuilder(shard_path, name=name, fingerprint=fp, target_snapshot=SNAPSHOT, shard_id=shard_id)
    for ent in entities:
        builder.add_entity(ent)
    builder.add_coverage(shard_id, "complete", None)
    return IndexIdentity(
        name,
        "appsec-review/retrieval-index/2",
        builder.build(),
        fp,
        shard_path.relative_to(run_root).as_posix(),
        {"job": producer_job, "unit": unit_name},
        (),
        shard_id,
    )


def test_artifact_read_and_resolved_configuration_helpers(tmp_path: Path) -> None:
    run_root = tmp_path / "run_001"
    payload_path = run_root / "data" / "sample.json"
    atomic_json(payload_path, {"ok": True})
    ref = _artifact(run_root, payload_path)
    assert ref["path"] == "data/sample.json"
    assert _read(run_root, ref) == {"ok": True}

    outside = tmp_path / "outside.json"
    atomic_json(outside, {"escape": True})
    with pytest.raises(ValueError, match="changed after acceptance"):
        _read(run_root, {"path": "../outside.json", "sha256": file_sha256(outside)})
    with pytest.raises(ValueError, match="changed after acceptance"):
        _read(run_root, {"path": "data/sample.json", "sha256": "0" * 64})

    _write_resolved_config(
        run_root,
        {
            "jobs": {
                "job_target_catalog": {"settings": {"enabled": True}, "steps": {"discover": {}, "index": {}}},
                "job_cpg_analysis": {"settings": {"enabled": False}, "steps": {"cpg": {}}},
            }
        },
    )
    assert "jobs" in _resolved_document(run_root)
    assert _resolved_steps(run_root, include_disabled=False) == {"job_target_catalog": ["discover", "index"]}
    assert _resolved_steps(run_root, include_disabled=True) == {
        "job_cpg_analysis": ["cpg"],
        "job_target_catalog": ["discover", "index"],
    }

    # Corrupt resolved.json to verify both helpers reject hash mismatches.
    (run_root / "data" / "configuration" / "resolved.json").write_text('{"tampered": true}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="resolved configuration hash mismatch"):
        _resolved_document(run_root)
    with pytest.raises(ValueError, match="resolved configuration hash mismatch"):
        _resolved_steps(run_root)


def test_feed_pins_fresh_stale_missing_index_bad_timestamp_and_overrides(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    now = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)

    # 1. osv: relative feed_root, fresh valid snapshot with index/osv.sqlite
    osv_src = tmp_path / "src_osv.sqlite"
    osv_src.write_bytes(b"sqlite-osv")
    osv_root = repo / "feeds" / "osv"
    publish_snapshot(
        osv_root,
        feed_id="osv",
        schema="appsec-review/osv-feed/1",
        files={"index/osv.sqlite": osv_src},
        manifest_fields={"ecosystem_count": 1},
    )
    osv_pointer = json.loads((osv_root / "current.json").read_text(encoding="utf-8"))
    osv_pointer["published_at"] = "2026-10-19T12:00:00Z"
    atomic_json(osv_root / "current.json", osv_pointer)

    # 2. kev: absolute feed_root, valid snapshot but invalid published_at -> stale: True, plus override bound
    kev_src = tmp_path / "src_kev.sqlite"
    kev_src.write_bytes(b"sqlite-kev")
    kev_root = tmp_path / "abs_feeds" / "kev"
    publish_snapshot(
        kev_root,
        feed_id="kev",
        schema="appsec-review/kev-feed/1",
        files={"index/kev.sqlite": kev_src},
        manifest_fields={},
    )
    kev_pointer = json.loads((kev_root / "current.json").read_text(encoding="utf-8"))
    kev_pointer["published_at"] = "not-an-iso-timestamp"
    atomic_json(kev_root / "current.json", kev_pointer)

    # 3. mitre: published snapshot missing index/mitre.sqlite -> unavailable ("publishes no index/mitre.sqlite")
    mitre_other = tmp_path / "other.json"
    mitre_other.write_text("{}", encoding="utf-8")
    mitre_root = tmp_path / "abs_feeds" / "mitre"
    publish_snapshot(
        mitre_root,
        feed_id="mitre",
        schema="appsec-review/mitre-feed/1",
        files={"meta/summary.json": mitre_other},
        manifest_fields={},
    )

    # 4. cve-bin-tool: not in FEED_INDEXES -> pinned without requiring index/*.sqlite, older than bound -> stale
    cbt_db = tmp_path / "cve.db"
    cbt_db.write_bytes(b"cbt-data")
    cbt_root = tmp_path / "abs_feeds" / "cbt"
    publish_snapshot(
        cbt_root,
        feed_id="cve-bin-tool",
        schema="appsec-review/cbt-feed/1",
        files={"db/cve.db": cbt_db},
        manifest_fields={},
    )
    cbt_pointer = json.loads((cbt_root / "current.json").read_text(encoding="utf-8"))
    cbt_pointer["published_at"] = "2026-09-01T00:00:00Z"
    atomic_json(cbt_root / "current.json", cbt_pointer)

    # 5. nvd: configured root with no current.json -> verify_current raises -> unavailable
    nvd_missing_root = tmp_path / "abs_feeds" / "nvd_missing"
    nvd_missing_root.mkdir(parents=True)

    # 6. epss: unconfigured feed_root -> unavailable ("feed root is not configured")
    resolved = {
        "jobs": {
            "job_third_party_data_sync": {
                "steps": {
                    FEED_STEPS["osv"]: {"settings": {"feed_root": "feeds/osv"}},
                    FEED_STEPS["kev"]: {"settings": {"feed_root": str(kev_root)}},
                    FEED_STEPS["mitre"]: {"settings": {"feed_root": str(mitre_root)}},
                    FEED_STEPS["cve-bin-tool"]: {"settings": {"feed_root": str(cbt_root)}},
                    FEED_STEPS["nvd"]: {"settings": {"feed_root": str(nvd_missing_root)}},
                    FEED_STEPS["epss"]: {"settings": {}},
                }
            }
        }
    }
    pins = feed_pins(repo, resolved, max_age_days=7, now=now, max_age_overrides={"kev": 3})
    assert set(pins) == set(FEED_STEPS)
    assert set(FEED_INDEXES) < set(FEED_STEPS)
    assert pins["osv"]["status"] == "pinned" and pins["osv"]["stale"] is False
    assert pins["osv"]["files"]["index/osv.sqlite"] == file_sha256(osv_src)
    assert pins["kev"]["status"] == "pinned" and pins["kev"]["stale"] is True and pins["kev"]["max_age_days"] == 3
    assert pins["mitre"]["status"] == "unavailable" and "publishes no index/mitre.sqlite" in pins["mitre"]["reason"]
    assert pins["cve-bin-tool"]["status"] == "pinned" and pins["cve-bin-tool"]["stale"] is True
    assert pins["nvd"]["status"] == "unavailable" and "no verified current snapshot" in pins["nvd"]["reason"]
    assert pins["epss"] == {"feed_id": "epss", "status": "unavailable", "reason": "feed root is not configured"}


def test_owasp_status_unavailable_rejections_and_accepted(tmp_path: Path) -> None:
    run_id = "2026-10-10-0099"
    run_root = tmp_path / run_id
    run_root.mkdir()
    assert owasp_status(run_root)["status"] == "unavailable"

    pointer_path = run_root / "data" / "indexes" / "owasp" / "accepted.json"
    atomic_json(pointer_path, {"run_id": run_id, "manifest_path": "../escape.json", "manifest_sha256": "a" * 64})
    with pytest.raises(ValueError, match="manifest identity changed"):
        owasp_status(run_root)

    manifest_rel = "data/indexes/owasp/manifests/m1.json"
    manifest_path = run_root / manifest_rel
    manifest_doc: dict[str, Any] = {
        "schema": "appsec-review/owasp-index-manifest/1",
        "run_id": run_id,
        "assessment_mode": "assessment",
        "assessment_bounds": {"max_controls": 10},
        "accepted_upstream_manifest": {"path": "data/indices/manifests/u.json", "sha256": "1" * 64},
        "shards": [{"shard_id": "owasp-main"}],
    }
    atomic_json(manifest_path, manifest_doc)
    manifest_sha = file_sha256(manifest_path)
    atomic_json(pointer_path, {"run_id": run_id, "manifest_path": manifest_rel, "manifest_sha256": manifest_sha})

    # Unbound to job_owasp_control_assessment handoff -> rejected
    with pytest.raises(ValueError, match="not bound to its accepted producer handoff"):
        owasp_status(run_root)

    def bind_owasp_handoff(current_doc: dict[str, Any], pointer_run_id: str = run_id) -> None:
        atomic_json(manifest_path, current_doc)
        sha = file_sha256(manifest_path)
        atomic_json(pointer_path, {"run_id": pointer_run_id, "manifest_path": manifest_rel, "manifest_sha256": sha})
        handoff_path = run_root / "data/jobs/job_owasp_control_assessment/attempts/attempt_0001/handoff.json"
        write_fixture_handoff(
            run_root,
            handoff_path,
            {
                "job_id": "job_owasp_control_assessment",
                "attempt_id": "attempt_0001",
                "status": "ACCEPTED",
                "completion_status": "SUCCEEDED",
                "outputs": {},
                "artifacts": [{"path": manifest_rel, "sha256": sha}],
                "source_fingerprint": SNAPSHOT,
            },
        )
        atomic_json(
            handoff_path.parent.parent.parent / "latest.json",
            {
                "schema": "appsec-review/latest-handoff/1",
                "attempt_id": "attempt_0001",
                "handoff_path": handoff_path.relative_to(run_root).as_posix(),
                "handoff_sha256": file_sha256(handoff_path),
            },
        )

    bind_owasp_handoff({**manifest_doc, "run_id": "other-run"})
    with pytest.raises(ValueError, match="belongs to another run"):
        owasp_status(run_root)

    bind_owasp_handoff({**manifest_doc, "assessment_mode": "invalid-mode"})
    with pytest.raises(ValueError, match="invalid assessment mode"):
        owasp_status(run_root)

    bind_owasp_handoff(manifest_doc)
    accepted = owasp_status(run_root)
    assert accepted["status"] == "accepted"
    assert accepted["assessment_mode"] == "assessment"
    assert accepted["shards"] == [{"shard_id": "owasp-main"}]


def test_unit_statuses_reconcile_shards_graph_follow_up_and_self_rows(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    attempt = run_root / "data/jobs/job_a/attempts/attempt_0001"
    handoff_rel = "data/jobs/job_a/attempts/attempt_0001/handoff.json"
    atomic_json(attempt / "steps/s1/tasks/t_status_only/status.json", {"status": "SUCCEEDED"})
    atomic_json(attempt / "steps/s1/tasks/t_terminal/status.json", {"status": "SUCCEEDED"})
    atomic_json(attempt / "steps/s1/tasks/t_terminal/result.json", {"terminal_status": "COMPLETED_WITH_GAPS"})
    atomic_json(attempt / "steps/s1/tasks/t_bad_json/status.json", {"status": "FAILED"})
    (attempt / "steps/s1/tasks/t_bad_json/result.json").write_text("{corrupt", encoding="utf-8")
    atomic_json(attempt / "steps/s1/tasks/t_non_str/status.json", {"status": "SKIPPED"})
    atomic_json(attempt / "steps/s1/tasks/t_non_str/result.json", {"terminal_status": 123})

    handoff_obj = AcceptedHandoff("job_a", {"attempt_id": "attempt_0001"}, "a" * 64, handoff_rel)
    statuses = _unit_statuses(run_root, handoff_obj)
    assert statuses == {
        "s1.t_bad_json": "FAILED",
        "s1.t_non_str": "SKIPPED",
        "s1.t_status_only": "SUCCEEDED",
        "s1.t_terminal": "COMPLETED_WITH_GAPS",
    }

    # reconcile_shards: None handoff, foreign producer ignored, dropped shard restored, conflicting sha reported
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    kept_id = _build_shard(
        run_root,
        name="source",
        shard_id="s-kept",
        producer_job="job_a",
        entities=[EntityRecord(LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {"p": "1"}), "f1", "a.py", "x = 1", {})],
    )
    dropped_id = _build_shard(
        run_root,
        name="source",
        shard_id="s-drop",
        producer_job="job_a",
        entities=[EntityRecord(LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {"p": "2"}), "f2", "b.py", "y = 2", {})],
    )
    conflict_handoff_id = _build_shard(
        run_root,
        name="source",
        shard_id="s-conflict",
        producer_job="job_a",
        entities=[EntityRecord(LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {"p": "3"}), "f3", "c.py", "z = 3", {})],
    )
    foreign_id = _build_shard(
        run_root,
        name="source",
        shard_id="s-foreign",
        producer_job="job_other",
        entities=[EntityRecord(LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {"p": "4"}), "f4", "d.py", "w = 4", {})],
    )
    m_path = run_root / "data/indices/manifests/job_a.json"
    m_doc = write_manifest(
        m_path,
        run_id="2026-10-10-0001",
        target_snapshot=SNAPSHOT,
        target_root=target_dir,
        indexes=[kept_id, dropped_id, conflict_handoff_id, foreign_id],
    )
    m_ref = {"path": m_path.relative_to(run_root).as_posix(), "sha256": file_sha256(m_path)}
    handoff_with_manifests = AcceptedHandoff(
        "job_a",
        {
            "outputs": {
                "s1.u1": {"index_manifest": m_ref},
                "s1.u2": {"index_manifest": m_ref},
            }
        },
        "b" * 64,
        handoff_rel,
    )
    by_sid = {item["shard_id"]: item for item in m_doc["indexes"]}
    accepted_in = [by_sid["s-kept"], {**by_sid["s-conflict"], "sha256": "3" * 64}]
    acc, restored, conflicts = reconcile_shards(
        run_root, accepted_in, {"job_none": None, "job_a": handoff_with_manifests}
    )
    assert len(acc) == 2
    assert [item["shard_id"] for item in restored] == ["s-drop"]
    assert len(conflicts) == 1 and "source/s-conflict: job_a" in conflicts[0]

    # graph_follow_up with complete/partial vs unavailable languages
    follow_none = graph_follow_up([{"language": "python", "lanes": {"code_graph": {"state": "unavailable"}}}])
    assert "no language has accepted graph coverage" in follow_none[0]["missing_prerequisite"]
    follow_ok = graph_follow_up(
        [
            {"language": "python", "lanes": {"code_graph": {"state": "complete"}}},
            {"language": "go", "lanes": {"code_graph": {"state": "custom_state"}}},
        ]
    )
    assert follow_ok[0]["graph_coverage"]["complete"] == ["python"]
    assert follow_ok[0]["graph_coverage"]["custom_state"] == ["go"]
    assert "no language has accepted graph coverage" not in follow_ok[0]["missing_prerequisite"]

    # _self_rows unavailable vs partial vs complete
    ident = {
        "name": "precomputed",
        "shard_id": "qs-ci_trust",
        "sha256": "5" * 64,
        "fingerprint": "6" * 64,
        "schema": "appsec-review/retrieval-index/2",
    }
    rows = _self_rows(
        "2026-10-10-0001",
        SNAPSHOT,
        [
            {"query_set": "ci_trust", "index_identity": ident, "status": "unavailable", "gaps": ["missing ci"]},
            {"query_set": "symbol_links", "index_identity": ident, "status": "complete", "gaps": []},
        ],
        [
            {"rule": "representation", "index_identity": {**ident, "name": "links"}, "terminal_status": "UNAVAILABLE", "gaps": ["no build"]},
            {"rule": "advisory", "index_identity": {**ident, "name": "links"}, "terminal_status": "COMPLETED_WITH_GAPS", "gaps": ["bound"]},
        ],
        {"dataset_audit_report": {"path": "data/audit.json", "sha256": "7" * 64, "size_bytes": 42}},
    )
    by_scope = {(r["output_kind"], r["scope"]): r for r in rows}
    assert by_scope[("precomputed_products", "ci_trust")]["disposition"] == "unavailable"
    assert by_scope[("precomputed_products", "ci_trust")]["coverage"]["reason"] == "missing ci"
    assert by_scope[("cross_domain_links", "representation")]["disposition"] == "unavailable"
    assert by_scope[("cross_domain_links", "advisory")]["coverage"]["state"] == "partial"
    assert by_scope[("dataset_inventory", "self")]["index"]["hash_resolution"] == "accepted_manifest"


def _seed_unit_run(
    tmp_path: Path,
    *,
    settings_overrides: dict[str, Any] | None = None,
    include_dropped_shard: bool = False,
    snapshot_override: str | None = None,
    corrupt_restored_shard: bool = False,
    add_stray_file: bool = False,
    undeclared_provider: bool = False,
    mismatch_provider: bool = False,
    fts_catalog_mode: str = "valid",
) -> tuple[JobContext, tuple[Any, ...], InProcessSqliteFts]:
    run_id = "2026-10-10-0037"
    run_root = tmp_path / "runs" / run_id
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    src_file = target / "src" / "app.c"
    src_bytes = b"int main(void) {\n  return 0;\n}\n"
    src_file.write_bytes(src_bytes)

    repo_root = tmp_path / "repo"
    if fts_catalog_mode == "valid":
        _make_pinned_repo(repo_root)
    else:
        (repo_root / "containers").mkdir(parents=True, exist_ok=True)

    base_config = load_config(REPO_ROOT / "appsec-review.toml")
    base_job_cfg = base_config.job(JOB_ID)
    merged_settings = {
        **dict(base_job_cfg.settings),
        "osv_version_matching": "index",
        "feed_max_age_days_overrides": {"osv": 14},
        **(settings_overrides or {}),
    }
    job_cfg = replace(base_job_cfg, settings=MappingProxyType(merged_settings))

    # Build minimal source, observations, priority, and build shards.
    src_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {"path": "src/app.c"})
    loc = SourceLocation(
        SNAPSHOT, "src/app.c", hashlib.sha256(src_bytes).hexdigest(), 0, len(src_bytes), 1, 3, 1, 1, {}, "exact", 1.0
    )

    def make_shard(
        index_name: str,
        shard_id: str,
        producer_job: str,
        unit_name: str,
        entities: list[EntityRecord],
        relations: list[RelationRecord] = (),
    ) -> IndexIdentity:
        fp = index_fingerprint(
            name=index_name,
            target_snapshot=SNAPSHOT,
            producer_artifacts=[{"shard": shard_id}],
            tool_identity={"job": producer_job},
            parser_identity="u/1",
            normalizer_identity="u/1",
            mapping_identity="u/1",
        )
        shard_path = run_root / "data" / "indices" / index_name / shard_id / f"{fp}.sqlite"
        builder = IndexBuilder(shard_path, name=index_name, fingerprint=fp, target_snapshot=SNAPSHOT, shard_id=shard_id)
        for ent in entities:
            builder.add_entity(ent)
        for rel in relations:
            builder.add_relation(rel)
        builder.add_coverage(shard_id, "complete", None)
        return IndexIdentity(
            index_name,
            "appsec-review/retrieval-index/2",
            builder.build(),
            fp,
            shard_path.relative_to(run_root).as_posix(),
            {"job": producer_job, "unit": unit_name},
            (),
            shard_id,
        )

    obs_id = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"obs": 1})
    prio_id = LogicalIdentity.derive(EntityKind.PRIORITY_ITEM, SNAPSHOT, {"item": "src/app.c"})
    act_id = LogicalIdentity.derive(EntityKind.BUILD_ACTION, SNAPSHOT, {"cmd": "1"})

    s_source = make_shard(
        "source",
        "catalog-src",
        "job_target_catalog",
        "index.source",
        [EntityRecord(src_id, "src/app.c", "src/app.c", "source file app", {"language": "C"}, loc)],
    )
    s_obs = make_shard(
        "observations",
        "semgrep",
        "job_evidence_collection",
        "source_sast.semgrep",
        [
            EntityRecord(
                obs_id,
                "o1",
                "c.rule",
                "semgrep observation",
                {"tool_id": "tool-semgrep", "native_rule_id": "c.rule", "native_severity": "HIGH", "category": "source_sast", "language": "C"},
                loc,
            )
        ],
        [RelationRecord(RelationKind.OBSERVED_AT, obs_id.value, src_id.value, True, 1.0)],
    )
    s_prio = make_shard(
        "priority",
        "review-prioritization",
        "job_review_prioritization",
        "publish.index_priority",
        [
            EntityRecord(
                prio_id,
                "file:src/app.c",
                "src/app.c",
                "priority app",
                {"item_id": "file:src/app.c", "scope": "file", "path": "src/app.c", "language": "C", "rank": 1, "score": 50.0, "features": {}, "gaps": []},
                loc,
            )
        ],
    )
    s_build = make_shard(
        "build",
        "language-build",
        "job_language_build",
        "acceptance.publish",
        [
            EntityRecord(
                act_id,
                "cmd-1",
                "cc",
                "compile app",
                {"command_id": "cmd-1", "tool": "cc", "tool_kind": "compiler", "argv_sha256": "a" * 64, "build_unit_id": "u1"},
            )
        ],
    )
    all_shards = [s_source, s_obs, s_prio, s_build]
    dropped_shard = None
    if include_dropped_shard:
        dropped_shard = make_shard(
            "history",
            "git-history",
            "job_source_history_analysis",
            "history.git",
            [],
        )
        if corrupt_restored_shard:
            (run_root / dropped_shard.relative_path).write_bytes(b"corrupted")

    # Producer manifest includes dropped_shard if requested; accepted manifest omits it so load restores it.
    producer_manifest_path = run_root / "data" / "indices" / "manifests" / "upstream-full.json"
    write_manifest(
        producer_manifest_path,
        run_id=run_id,
        target_snapshot=SNAPSHOT,
        target_root=target,
        indexes=[*all_shards, *([dropped_shard] if dropped_shard else [])],
    )
    producer_manifest_ref = {
        "path": producer_manifest_path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(producer_manifest_path),
    }

    accepted_manifest_path = run_root / "data" / "indices" / "manifests" / "accepted-upstream.json"
    write_manifest(
        accepted_manifest_path,
        run_id=run_id,
        target_snapshot=SNAPSHOT,
        target_root=target,
        indexes=all_shards,
    )
    accepted_manifest_sha = file_sha256(accepted_manifest_path)
    accepted_manifest_ref = {
        "path": accepted_manifest_path.relative_to(run_root).as_posix(),
        "sha256": accepted_manifest_sha,
    }

    decls: dict[str, tuple[Any, ...]] = {
        "job_target_catalog": (
            indexed("source_files", "index", "catalog", "appsec-review/retrieval-index/2", "Sources", indexes=("source",), route="find"),
        ),
        "job_evidence_collection": (
            indexed("static_tool_observations", "source_sast", "scanner_findings", "appsec-review/retrieval-index/2", "SAST", indexes=("observations",), route="query_observations"),
        ),
        "job_review_prioritization": (
            indexed("priority_items", "publish", "priority", "appsec-review/retrieval-index/2", "Priority", indexes=("priority",), route="find"),
            artifact_only(
                "prioritization_documents",
                "extract",
                "priority",
                "appsec-review/review-prioritization/1",
                "Syntax",
                artifacts=("data/jobs/job_review_prioritization/attempts/*/steps/extract/tasks/syntax_metrics/syntax.json",),
                reason="attempt syntax artifact",
            ),
        ),
        "job_language_build": (
            indexed("build_actions", "acceptance", "build", "appsec-review/retrieval-index/2", "Build", indexes=("build",), route="find"),
        ),
        "job_source_history_analysis": (
            indexed("history_signals", "history", "history", "appsec-review/retrieval-index/2", "History", indexes=("history",), route="find"),
        ),
        "job_cpg_analysis": (
            artifact_only("cpg_summary", "cpg", "cpg", "application/json", "Disabled CPG", artifacts=("data/cpg/*.json",), reason="disabled"),
        ),
        "job_poc_generation": (
            artifact_only("poc_summary", "poc", "inference_review", "application/json", "Downstream PoC", artifacts=("data/poc/*.json",), reason="downstream"),
        ),
        JOB_ID: DATASETS,
    }
    if undeclared_provider:
        decls["job_undeclared_extra"] = ()

    steps_map: dict[str, dict[str, Any]] = {
        "job_target_catalog": {"settings": {"enabled": True}, "steps": {"index": {}}},
        "job_evidence_collection": {"settings": {"enabled": True}, "steps": {"source_sast": {}, "evidence_publication": {}}},
        "job_review_prioritization": {"settings": {"enabled": True}, "steps": {"extract": {}, "publish": {}}},
        "job_language_build": {"settings": {"enabled": True}, "steps": {"acceptance": {}}},
        "job_source_history_analysis": {"settings": {"enabled": True}, "steps": {"history": {}}},
        "job_cpg_analysis": {"settings": {"enabled": False}, "steps": {"cpg": {}}},
        "job_poc_generation": {"settings": {"enabled": True}, "steps": {"poc": {}}},
        JOB_ID: {"settings": {"enabled": True}, "steps": {step: {} for step in TOPOLOGY}},
    }
    if undeclared_provider:
        steps_map["job_undeclared_extra"] = {"settings": {"enabled": True}, "steps": {"work": {}}}
    if mismatch_provider:
        # Configured in resolved.json as enabled, but omitted from providers() -> registry_configuration_mismatch
        steps_map["job_configured_only"] = {"settings": {"enabled": True}, "steps": {"work": {}}}
    _write_resolved_config(run_root, {"jobs": steps_map})

    def write_upstream_handoff(
        producer: str, shard: IndexIdentity, extra_artifacts: list[dict[str, str]] = (), extra_outputs: dict[str, Any] | None = None, manifest_ref: dict[str, str] = accepted_manifest_ref
    ) -> tuple[Path, str]:
        att = run_root / "data" / "jobs" / producer / "attempts" / "attempt_0001"
        step_names = list(steps_map[producer]["steps"])
        atomic_json(
            att / "claim.json",
            {
                "schema": "appsec-review/attempt-claim/1",
                "run_id": run_id,
                "job_id": producer,
                "attempt_id": "attempt_0001",
                "attempt_path": att.relative_to(run_root).as_posix(),
                "source_fingerprint": SNAPSHOT,
                "orchestration": {"system": "unit", "run_id": "u-1"},
                "dataset_contract": dataset_contract(producer, step_names, decls[producer]),
            },
        )
        unit_key = shard.producer["unit"]
        step_n, task_n = unit_key.split(".", 1)
        atomic_json(att / "steps" / step_n / "tasks" / task_n / "status.json", {"status": "SUCCEEDED"})
        outputs = {
            unit_key: {"index_manifest": manifest_ref, "index_identity": asdict(shard)},
            **(extra_outputs or {}),
        }
        artifacts = [
            manifest_ref,
            {"path": shard.relative_path, "sha256": shard.sha256},
            *extra_artifacts,
        ]
        if manifest_ref != accepted_manifest_ref:
            artifacts.append(accepted_manifest_ref)
        h_path = att / "handoff.json"
        write_fixture_handoff(
            run_root,
            h_path,
            {
                "job_id": producer,
                "attempt_id": "attempt_0001",
                "status": "ACCEPTED",
                "completion_status": "SUCCEEDED",
                "outputs": outputs,
                "artifacts": artifacts,
                "source_fingerprint": SNAPSHOT,
            },
        )
        h_sha = file_sha256(h_path)
        atomic_json(
            att.parent.parent / "latest.json",
            {
                "schema": "appsec-review/latest-handoff/1",
                "attempt_id": "attempt_0001",
                "handoff_path": h_path.relative_to(run_root).as_posix(),
                "handoff_sha256": h_sha,
            },
        )
        return h_path, h_sha

    syntax_path = (
        run_root
        / "data/jobs/job_review_prioritization/attempts/attempt_0001/steps/extract/tasks/syntax_metrics/syntax.json"
    )
    atomic_json(
        syntax_path,
        {"files": {"src/app.c": {"component_id": "core", "language": "C", "suppression_count": 0, "suppressions": []}}},
    )
    syntax_ref = {"path": syntax_path.relative_to(run_root).as_posix(), "sha256": file_sha256(syntax_path)}

    write_upstream_handoff("job_target_catalog", s_source)
    write_upstream_handoff(
        "job_evidence_collection",
        s_obs,
        extra_outputs={
            "evidence_publication.assemble_manifest": {
                "dispositions": [{"tool_id": "tool-semgrep", "terminal_status": "SUCCEEDED"}]
            }
        },
    )
    prio_path, prio_sha = write_upstream_handoff(
        "job_review_prioritization",
        s_prio,
        extra_artifacts=[syntax_ref],
        extra_outputs={"extract.syntax_metrics": {"artifact": syntax_ref}},
    )
    write_upstream_handoff("job_language_build", s_build)
    if dropped_shard is not None:
        write_upstream_handoff("job_source_history_analysis", dropped_shard, manifest_ref=producer_manifest_ref)

    atomic_json(
        run_root / "data/indices/accepted.json",
        {
            "schema": "appsec-review/accepted-index-set/1",
            "run_id": run_id,
            "handoff_path": prio_path.relative_to(run_root).as_posix(),
            "handoff_sha256": prio_sha,
            "manifest_path": accepted_manifest_ref["path"],
            "manifest_sha256": accepted_manifest_sha,
        },
    )

    if add_stray_file:
        stray = run_root / "data" / "stray_unowned.bin"
        stray.write_bytes(b"unexpected")

    attempt_id = "attempt_0001"
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / attempt_id
    orchestration = {"system": "unit", "run_id": "idx-1"}
    atomic_json(
        attempt_root / "claim.json",
        {
            "schema": "appsec-review/attempt-claim/1",
            "run_id": run_id,
            "job_id": JOB_ID,
            "attempt_id": attempt_id,
            "attempt_path": attempt_root.relative_to(run_root).as_posix(),
            "source_fingerprint": SNAPSHOT,
            "orchestration": orchestration,
            "dataset_contract": dataset_contract(JOB_ID, tuple(TOPOLOGY), DATASETS),
        },
    )

    job_ids = tuple(decls.keys())
    consumes = {name: () for name in job_ids}
    consumes["job_evidence_collection"] = ("job_target_catalog",)
    consumes[JOB_ID] = ("job_target_catalog", "job_evidence_collection", "job_review_prioritization", "job_language_build")

    ctx = JobContext(
        run_id=run_id,
        attempt_id=attempt_id,
        trigger="unit",
        repository_root=repo_root,
        run_root=run_root,
        attempt_root=attempt_root,
        metadata_root=tmp_path / "runs" / "metadata",
        orchestration=orchestration,
        config=job_cfg,
        events=EventLog(attempt_root / "logs" / "events.jsonl"),
        tools=ToolCapabilityConfig(),
        target_root=target,
        source_fingerprint=snapshot_override or SNAPSHOT,
        input_manifest_path=accepted_manifest_path,
        input_manifest_sha256=accepted_manifest_sha,
        review_policy=ReviewPolicy(),
        contract=CONTRACT,
    )
    fts_exec = InProcessSqliteFts(run_root, CATALOG_FTS_IMAGE)
    return ctx, (job_ids, decls, consumes), fts_exec


def test_sixteen_units_execute_end_to_end_via_unit_executor_with_restored_shard(tmp_path: Path) -> None:
    ctx, provider_tuple, fts_exec = _seed_unit_run(tmp_path, include_dropped_shard=True)
    job = build_job(providers=lambda: provider_tuple, executor_factory=lambda _unit: fts_exec)

    result = job.handler(ctx)

    outputs = result["outputs"]
    assert outputs["load.accepted_inputs"]["restored"] == 1
    assert any("restored dropped shard history/git-history" in g for g in outputs["load.accepted_inputs"]["gaps"])
    assert outputs["links.cross_domain"]["terminal_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    for name in PRODUCT_SETS:
        assert outputs[f"precompute.{name}"]["query_set"] == name
    assert outputs["precompute.scanner_correlation"]["status"] == "complete"
    assert outputs["fts.image_validation"]["terminal_status"] == "SUCCEEDED"
    assert fts_exec.calls == ["probe", "build", "verify"]
    assert outputs["audit.inventory"]["audit_status"] == "PASSED"
    # Compact provider tuple omits several INPUT_SOURCES producers, exercising discrepancies -> COMPLETED_WITH_GAPS
    assert outputs["matrix.coverage"]["terminal_status"] == "COMPLETED_WITH_GAPS"
    pub = outputs["publish.inventory_index"]
    assert pub["schema"] == SCHEMA
    assert pub["summary"]["restored_shards"] == 1
    manifest_doc, _ = load_verified_manifest(
        ctx.run_root,
        ctx.run_root / pub["index_manifest"]["path"],
        pub["index_manifest"]["sha256"],
    )
    shard_names = {(item["name"], item["shard_id"]) for item in manifest_doc["indexes"]}
    assert ("inventory", "dataset-inventory") in shard_names
    assert ("history", "git-history") in shard_names


def test_load_rejects_snapshot_mismatch_and_corrupted_restored_shard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad_snap_ctx, providers_a, fts_a = _seed_unit_run(
        tmp_path / "snap", snapshot_override="target-sha256:" + "1" * 64
    )
    load_unit = build_job(providers=lambda: providers_a, executor_factory=lambda _u: fts_a).units[0]
    u_ctx_a = UnitContext(
        bad_snap_ctx,
        "load.accepted_inputs",
        "load",
        "accepted_inputs",
        bad_snap_ctx.attempt_root / "steps/load/tasks/accepted_inputs",
        {},
    )
    u_ctx_a.unit_root.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError, match="accepted index snapshot differs"):
        load_unit.handler(u_ctx_a)

    corrupt_ctx, providers_b, fts_b = _seed_unit_run(tmp_path / "corrupt")
    import appsec_review.jobs.job_review_data_indexing.job as job_mod

    monkeypatch.setattr(
        job_mod,
        "reconcile_shards",
        lambda _rr, accepted, _h: (
            list(accepted),
            [{"name": "history", "shard_id": "git-history", "relative_path": "../escape.sqlite", "sha256": "0" * 64}],
            [],
        ),
    )
    load_unit_b = build_job(providers=lambda: providers_b, executor_factory=lambda _u: fts_b).units[0]
    u_ctx_b = UnitContext(
        corrupt_ctx,
        "load.accepted_inputs",
        "load",
        "accepted_inputs",
        corrupt_ctx.attempt_root / "steps/load/tasks/accepted_inputs",
        {},
    )
    u_ctx_b.unit_root.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError, match="restored shard failed verification"):
        load_unit_b.handler(u_ctx_b)


def test_fts_disabled_unpinned_missing_catalog_and_default_container_executor_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Single seeded run reused across disabled, missing-catalog, unpinned-catalog, and default-executor checks
    ctx_base, prov, fts_exec = _seed_unit_run(
        tmp_path / "fts_modes", settings_overrides={"fts_image_validation": "disabled", "max_links_per_rule": 0}
    )
    job_dis = build_job(providers=lambda: prov, executor_factory=lambda _u: fts_exec)
    units_by_id = {u.unit_id: u for u in job_dis.units}
    prior: dict[str, Any] = {}
    for uid in ("load.accepted_inputs", "links.cross_domain", *(f"precompute.{n}" for n in PRODUCT_SETS), "fts.image_validation"):
        step, task = uid.split(".", 1)
        uc = UnitContext(ctx_base, uid, step, task, ctx_base.attempt_root / "steps" / step / "tasks" / task, prior)
        uc.unit_root.mkdir(parents=True, exist_ok=True)
        prior[uid] = units_by_id[uid].handler(uc)
    assert prior["fts.image_validation"]["summary"]["status"] == "disabled"
    assert prior["fts.image_validation"]["terminal_status"] == "COMPLETED_WITH_GAPS"

    # Switch config setting to mode="optional" on the same run_root
    opt_cfg = replace(
        ctx_base.config,
        settings=MappingProxyType({**dict(ctx_base.config.settings), "fts_image_validation": "optional"}),
    )

    # 2. mode="optional" with missing catalog -> catalog_gap raised inside factory -> unavailable
    missing_repo = tmp_path / "missing_repo"
    missing_repo.mkdir()
    ctx_missing = replace(ctx_base, config=opt_cfg, repository_root=missing_repo, attempt_id="attempt_0002")
    fts_unit_m = {u.unit_id: u for u in build_job(providers=lambda: prov, executor_factory=lambda _u: fts_exec).units}["fts.image_validation"]
    uc_m = UnitContext(
        ctx_missing,
        "fts.image_validation",
        "fts",
        "image_validation",
        ctx_base.attempt_root / "steps/fts/tasks/image_validation_m",
        prior,
    )
    uc_m.unit_root.mkdir(parents=True, exist_ok=True)
    res_m = fts_unit_m.handler(uc_m)
    assert res_m["summary"]["status"] == "unavailable"
    assert any("not an enabled catalog image" in g for g in res_m["gaps"])

    # 3. mode="optional" with unpinned image_id -> catalog_gap ("has no pinned image id")
    import appsec_review.container_runtime as cr_mod

    real_load_catalog = cr_mod.load_catalog
    monkeypatch.setattr(
        cr_mod,
        "load_catalog",
        lambda _root: SimpleNamespace(tool=lambda _id: SimpleNamespace(expected_image_id=None)),
    )
    ctx_unpin = replace(ctx_base, config=opt_cfg, attempt_id="attempt_0003")
    uc_u = UnitContext(
        ctx_unpin,
        "fts.image_validation",
        "fts",
        "image_validation",
        ctx_base.attempt_root / "steps/fts/tasks/image_validation_u",
        prior,
    )
    uc_u.unit_root.mkdir(parents=True, exist_ok=True)
    res_u = fts_unit_u = fts_unit_m.handler(uc_u)
    assert res_u["summary"]["status"] == "unavailable"
    assert any("no pinned image id" in g for g in res_u["gaps"])

    # 4. executor_factory=None exercises default ContainerExecutor(...) branch via lightweight stub
    monkeypatch.setattr(cr_mod, "load_catalog", real_load_catalog)
    monkeypatch.setattr(
        cr_mod, "ContainerExecutor", lambda _cat, run_root: InProcessSqliteFts(run_root, CATALOG_FTS_IMAGE)
    )
    ctx_def = replace(ctx_base, config=opt_cfg, attempt_id="attempt_0004")
    fts_unit_def = {u.unit_id: u for u in build_job(providers=lambda: prov, executor_factory=None).units}["fts.image_validation"]
    uc_def = UnitContext(
        ctx_def,
        "fts.image_validation",
        "fts",
        "image_validation",
        ctx_base.attempt_root / "steps/fts/tasks/image_validation_def",
        prior,
    )
    uc_def.unit_root.mkdir(parents=True, exist_ok=True)
    res_def = fts_unit_def.handler(uc_def)
    assert res_def["terminal_status"] == "SUCCEEDED"


def test_audit_reports_stray_undeclared_and_configuration_mismatch_violations(tmp_path: Path) -> None:
    ctx, prov, fts_exec = _seed_unit_run(
        tmp_path,
        add_stray_file=True,
        undeclared_provider=True,
        mismatch_provider=True,
        settings_overrides={"fts_image_validation": "disabled"},
    )
    job = build_job(providers=lambda: prov, executor_factory=lambda _u: fts_exec)
    units_by_id = {u.unit_id: u for u in job.units}
    prior: dict[str, Any] = {}
    for uid in ("load.accepted_inputs", "links.cross_domain", *(f"precompute.{n}" for n in PRODUCT_SETS), "fts.image_validation"):
        step, task = uid.split(".", 1)
        uc = UnitContext(ctx, uid, step, task, ctx.attempt_root / "steps" / step / "tasks" / task, prior)
        uc.unit_root.mkdir(parents=True, exist_ok=True)
        prior[uid] = units_by_id[uid].handler(uc)

    audit_uc = UnitContext(
        ctx,
        "audit.inventory",
        "audit",
        "inventory",
        ctx.attempt_root / "steps/audit/tasks/inventory",
        prior,
    )
    audit_uc.unit_root.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError, match="dataset publication audit failed"):
        units_by_id["audit.inventory"].handler(audit_uc)

    retained = json.loads((audit_uc.unit_root / "inventory.json").read_text(encoding="utf-8"))
    codes = {v["code"] for v in retained["audit"]["violations"]}
    assert {"unaccounted_file", "undeclared_job", "registry_configuration_mismatch"} <= codes
