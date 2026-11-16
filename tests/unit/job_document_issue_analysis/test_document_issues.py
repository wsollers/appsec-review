"""Fast unit tests for appsec_review.document_issues mapping, adjudication, and ledger verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.document_issues import (
    SCHEMA,
    _route_key,
    _source_lines,
    adjudicate,
    analyze_document_hunts,
    verify_document_issue_ledger,
)
from appsec_review.retrieval import (
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RetrievalCore,
    SourceLocation,
    index_fingerprint,
    write_manifest,
)
from appsec_review.retrieval.model import canonical_json
from appsec_review.retrieval.precomputed import FACT_SCHEMA
from appsec_review.review_packages import publish_review_packages
from appsec_review.storage import atomic_bytes, atomic_json
from appsec_review.storage.shared import put_bytes


def _build_core(
    tmp_path: Path,
    *,
    source_files: list[tuple[str, bytes, str | None]] | None = None,
    include_source_shard: bool = True,
) -> tuple[RetrievalCore, Path, str]:
    run_id = "2026-10-15-0139"
    run_root = tmp_path / "runs" / run_id
    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)
    snapshot = "target-sha256:" + "d" * 64

    doc_rel = "api/openapi.yaml"
    doc_path = target / doc_rel
    doc_path.parent.mkdir(parents=True, exist_ok=True)
    doc_bytes = b"paths:\n  /orders/{id}:\n    get: {}\n"
    doc_path.write_bytes(doc_bytes)
    doc_sha = hashlib.sha256(doc_bytes).hexdigest()
    doc_loc = SourceLocation(snapshot, doc_rel, doc_sha, 0, len(doc_bytes), 1, 3, 1, 1, {}, "exact", 1.0)
    doc_id = LogicalIdentity.derive(EntityKind.DOCUMENT_RECORD, snapshot, {"path": doc_rel})
    fact_id = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, snapshot, {"qs": "document_context", "k": "orders"})

    shards: list[IndexIdentity] = []

    def add_shard(name: str, shard_id: str, entities: list[EntityRecord], producer: dict[str, str]) -> None:
        fp = index_fingerprint(
            name=name,
            target_snapshot=snapshot,
            producer_artifacts=[{"shard": shard_id}],
            tool_identity={"job": producer["job"]},
            parser_identity="u/1",
            normalizer_identity="u/1",
            mapping_identity="u/1",
        )
        s_path = run_root / "data" / "indices" / name / shard_id / f"{fp}.sqlite"
        builder = IndexBuilder(s_path, name=name, fingerprint=fp, target_snapshot=snapshot, shard_id=shard_id)
        for ent in entities:
            builder.add_entity(ent)
        builder.add_coverage(f"{name}:{shard_id}", "complete", None)
        sha = builder.build()
        shards.append(
            IndexIdentity(
                name,
                "appsec-review/retrieval-index/2",
                sha,
                fp,
                s_path.relative_to(run_root).as_posix(),
                producer,
                (),
                shard_id,
            )
        )

    if include_source_shard:
        src_entities: list[EntityRecord] = []
        files = source_files if source_files is not None else [
            (
                "src/orders.ts",
                b"router.get('/orders/:id', (req, res) => {\n  res.send(req.params.id);\n});\n",
                "TypeScript",
            )
        ]
        for rel, raw, lang in files:
            p = target / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(raw)
            sha = hashlib.sha256(raw).hexdigest()
            sid = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, {"path": rel})
            loc = SourceLocation(snapshot, rel, sha, 0, max(1, len(raw)), 1, 3, 1, 1, {}, "exact", 1.0)
            src_entities.append(EntityRecord(sid, rel, Path(rel).name, rel, {"language": lang}, loc))
        add_shard("source", "source-files", src_entities, {"job": "job_target_catalog"})

    add_shard(
        "documents",
        "docs",
        [EntityRecord(doc_id, "d1", "GET /orders/{id}", "orders", {"authority": "declared"}, doc_loc)],
        {"job": "job_document_analysis"},
    )
    add_shard(
        "precomputed",
        "doc-ctx",
        [
            EntityRecord(
                fact_id,
                "f1",
                "GET /orders/{id}",
                "orders route",
                {
                    "schema": FACT_SCHEMA,
                    "query_set": "document_context",
                    "fact_type": "route_context",
                    "subject_identity": doc_id.value,
                    "gaps": [],
                    "result": {
                        "subject_type": "route",
                        "key": "GET /orders/{id}",
                        "members": {"openapi": [doc_id.value]},
                    },
                },
            )
        ],
        {"job": "job_review_data_indexing", "query_set": "document_context"},
    )

    m_path = run_root / "data" / "indices" / "manifest.json"
    write_manifest(m_path, run_id=run_id, target_snapshot=snapshot, target_root=target, indexes=shards)
    m_sha = hashlib.sha256(m_path.read_bytes()).hexdigest()
    return RetrievalCore(run_root.parent, run_id, manifest_sha256=m_sha, manifest_path=m_path), target, snapshot


def test_route_key_normalization() -> None:
    assert _route_key("/orders/:id/") == "/orders/{id}"
    assert _route_key("/orders/{id}") == "/orders/{id}"
    assert _route_key("/") == "/"


def test_source_lines_bounds_skips_and_tamper_guards(tmp_path: Path) -> None:
    no_src_core, _, _ = _build_core(tmp_path / "no-src", include_source_shard=False)
    assert _source_lines(no_src_core, 10, 1024) == ([], ["accepted source index is unavailable"])

    core, target, _ = _build_core(
        tmp_path / "mixed",
        source_files=[
            ("src/a.ts", b"app.get('/orders/:id', handler);\n", "TypeScript"),
            ("src/b_big.ts", b"x" * 200, "TypeScript"),
            ("src/c_bin.ts", b"\xff\xfe\xfd", "TypeScript"),
            ("tests/orders.test.ts", b"app.get('/orders/:id', handler);\n", "TypeScript"),
            ("src/readme.txt", b"app.get('/orders/:id', handler);\n", None),
        ],
    )
    routes, gaps = _source_lines(core, max_files=4, max_file_bytes=100)
    assert any("exceeded bound" in g for g in gaps)
    routes_all, gaps_all = _source_lines(core, max_files=20, max_file_bytes=100)
    assert len(routes_all) == 1
    assert routes_all[0]["path"] == "src/a.ts"
    assert any("oversized file: src/b_big.ts" in g for g in gaps_all)
    assert any("undecodable file: src/c_bin.ts" in g for g in gaps_all)

    (target / "src/a.ts").write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="accepted source bytes changed"):
        _source_lines(core, max_files=20, max_file_bytes=100)

    (target / "src/a.ts").unlink()
    with pytest.raises(ValueError, match="accepted source path is missing or escaped"):
        _source_lines(core, max_files=20, max_file_bytes=100)


def test_analyze_ambiguous_mapping_and_adjudicate_gates(tmp_path: Path) -> None:
    amb_core, _, _ = _build_core(
        tmp_path / "amb",
        source_files=[
            ("src/v1.ts", b"app.get('/orders/:id', h1);\n", "TypeScript"),
            ("src/v2.ts", b"router.get('/orders/{id}', h2);\n", "TypeScript"),
        ],
    )
    amb_ledger = analyze_document_hunts(amb_core, publish_review_packages(amb_core))
    assert amb_ledger["counts"]["ambiguous"] == 1
    assert amb_ledger["candidates"][0]["mapping_status"] == "ambiguous"

    core, target, _ = _build_core(
        tmp_path / "uniq",
        source_files=[
            (
                "src/orders.ts",
                b"router.get('/orders/:id', (req, res) => {\n\n  return res.json(req.params.id);\n});\n",
                "TypeScript",
            )
        ],
    )
    pkg_dir = publish_review_packages(core)
    ledger = analyze_document_hunts(core, pkg_dir)
    cand = ledger["candidates"][0]
    assert cand["mapping_status"] == "unique"
    impl = cand["implementation_evidence"][0]
    proof = {**impl, "line": 3}
    ref = f"{proof['entity_id']}:3"
    red = {"decision": "supported", "security_claim": "IDOR in orders", "evidence_refs": [ref]}
    blue = {"decision": "not_refuted", "evidence_refs": [ref], "unresolved_refutations": []}
    verifier = {"decision": "independently_supported", "security_claim": "IDOR in orders", "evidence_refs": [ref]}

    ok = adjudicate({**cand, "proof_evidence": [proof]}, core=core, red=red, blue=blue, verifier=verifier)
    assert ok["state"] == "supported"
    assert ok["finding"]["claim"] == "IDOR in orders"

    # Empty line (line 2 is blank) rejected
    empty_proof = {**impl, "line": 2}
    empty_ref = f"{impl['entity_id']}:2"
    with pytest.raises(ValueError, match="empty source line"):
        adjudicate(
            {**cand, "proof_evidence": [empty_proof]},
            core=core,
            red={**red, "evidence_refs": [empty_ref]},
            blue={**blue, "evidence_refs": [empty_ref]},
            verifier={**verifier, "evidence_refs": [empty_ref]},
        )

    # Out-of-range line rejected
    oob_proof = {**impl, "line": 99}
    with pytest.raises(ValueError, match="outside accepted bytes"):
        adjudicate({**cand, "proof_evidence": [oob_proof]}, core=core, red=red, blue=blue, verifier=verifier)

    # Unaccepted entity rejected
    bad_ent = {**proof, "entity_id": "missing-entity"}
    with pytest.raises(ValueError, match="does not resolve to accepted source"):
        adjudicate({**cand, "proof_evidence": [bad_ent]}, core=core, red=red, blue=blue, verifier=verifier)

    # Changed source bytes rejected
    (target / "src/orders.ts").write_bytes(b"changed\n")
    with pytest.raises(ValueError, match="candidate source evidence bytes changed"):
        adjudicate({**cand, "proof_evidence": [proof]}, core=core, red=red, blue=blue, verifier=verifier)


def test_verify_document_issue_ledger_rejects_corrupt_or_unreviewed_findings(tmp_path: Path) -> None:
    core, _, _ = _build_core(tmp_path)
    ledger = analyze_document_hunts(core, publish_review_packages(core))
    assert ledger["schema"] == SCHEMA

    obj_ref = put_bytes(core.run_root, canonical_json(ledger) + b"\n")
    assert verify_document_issue_ledger(core, core.run_root / obj_ref["path"]) == ledger

    legacy_path = core.run_root / "data" / "document-issues" / ledger["content_sha256"] / "ledger.json"
    atomic_json(legacy_path, ledger)
    assert verify_document_issue_ledger(core, legacy_path) == ledger

    wrong_dir = core.run_root / "data" / "other" / "ledger.json"
    atomic_json(wrong_dir, ledger)
    with pytest.raises(ValueError, match="document issue ledger escapes its run"):
        verify_document_issue_ledger(core, wrong_dir)

    non_canonical = core.run_root / "data" / "document-issues" / ledger["content_sha256"] / "ledger.json"
    atomic_bytes(non_canonical, json.dumps(ledger, indent=2).encode("utf-8"))
    with pytest.raises(ValueError, match="byte integrity mismatch"):
        verify_document_issue_ledger(core, non_canonical)

    bad_id = {**ledger, "run_id": "other-run"}
    bad_id_ref = put_bytes(core.run_root, canonical_json(bad_id) + b"\n")
    with pytest.raises(ValueError, match="identity mismatch"):
        verify_document_issue_ledger(core, core.run_root / bad_id_ref["path"])

    bad_counts = dict(ledger)
    bad_counts.pop("content_sha256")
    bad_counts["counts"] = {**ledger["counts"], "candidates": 99}
    bad_counts["content_sha256"] = hashlib.sha256(canonical_json(bad_counts)).hexdigest()
    bad_counts_ref = put_bytes(core.run_root, canonical_json(bad_counts) + b"\n")
    with pytest.raises(ValueError, match="count mismatch"):
        verify_document_issue_ledger(core, core.run_root / bad_counts_ref["path"])

    bad_findings = dict(ledger)
    bad_findings.pop("content_sha256")
    bad_findings["findings"] = [{"claim": "unreviewed"}]
    bad_findings["content_sha256"] = hashlib.sha256(canonical_json(bad_findings)).hexdigest()
    bad_findings_ref = put_bytes(core.run_root, canonical_json(bad_findings) + b"\n")
    with pytest.raises(ValueError, match="unreviewed document issues cannot be published as findings"):
        verify_document_issue_ledger(core, core.run_root / bad_findings_ref["path"])
