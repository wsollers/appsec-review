"""Manual local publication/index/source join; never selected by the unit gate."""
from __future__ import annotations

from copy import deepcopy

import pytest

from appsec_review.config.owasp import AssessmentMode, OwaspSettings
from appsec_review.owasp_workbench.evidence import EvidenceResolver, accepted_inputs
from appsec_review.owasp_workbench.obligations import PROCEDURES, subjects
from appsec_review.owasp_workbench.standards import digest
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RetrievalCore,
    SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.review.scope import accept_manifest
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff


pytestmark = pytest.mark.time_budget(30, reason="Join a small local accepted publication to original source bytes")
RUN_ID = "2026-11-13-0001"
SOURCE = ("# earlier accepted context\n" * 200
          + "@audit('query')\ndef lookup(cursor):\n    return cursor.execute('SELECT 1')\n"
          + "# later accepted context\n" * 20)


@pytest.fixture
def publication(tmp_path):
    root, target = tmp_path / "runs" / RUN_ID, tmp_path / "target"
    target.mkdir()
    source = target / "app.py"
    source.write_bytes(SOURCE.encode())
    sha = file_sha256(source)
    snapshot = "target-sha256:" + digest({"source": sha})
    location = SourceLocation(snapshot, "app.py", sha, 0, source.stat().st_size,
                              1, len(SOURCE.splitlines()), 1, 1, {}, "fixture-exact", 1.0)
    file_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, {"path": "app.py", "sha256": sha})
    symbol_id = LogicalIdentity.derive(EntityKind.SYMBOL, snapshot, {"path": "app.py", "name": "lookup"})
    component_id = LogicalIdentity.derive(EntityKind.COMPONENT, snapshot, {"id": "api"})
    indexes = []
    for name, records in (
        ("source", [EntityRecord(file_id, "app.py", "app.py", "", {"language": "Python"}, location)]),
        ("components", [EntityRecord(component_id, "api", "api", "",
                                      {"root": ".", "component_id": "api"})]),
        ("analysis", [EntityRecord(symbol_id, "lookup", "lookup", "", {"component_id": "api"},
                                   SourceLocation(snapshot, "app.py", sha,
                                       len(("# earlier accepted context\n" * 200).encode()),
                                       len(SOURCE.rsplit("# later accepted context\n" * 20, 1)[0].encode()),
                                       201, 203, 1, 1, {}, "fixture-exact", 1.0))]),
    ):
        fingerprint = index_fingerprint(name=name, target_snapshot=snapshot,
            producer_artifacts=[{"sha256": sha}], tool_identity={"tool": "manual-source-fixture"},
            parser_identity="fixture/1", normalizer_identity="fixture/1", mapping_identity="fixture/1")
        path = root / "data" / "indices" / name / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name=name, fingerprint=fingerprint, target_snapshot=snapshot)
        for record in records:
            builder.add_entity(record)
        builder.add_coverage("source", "complete", None)
        indexes.append(IndexIdentity(name, "appsec-review/retrieval-index/2", builder.build(),
            fingerprint, path.relative_to(root).as_posix(), {"job": "job_target_catalog"}))
    manifest = root / "data" / "indices" / "manifests" / "fixture.json"
    write_manifest(manifest, run_id=RUN_ID, target_snapshot=snapshot, target_root=target, indexes=indexes)
    artifact = {"path": manifest.relative_to(root).as_posix(), "sha256": file_sha256(manifest),
                "size_bytes": manifest.stat().st_size}
    handoff = root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001" / "handoff.json"
    write_fixture_handoff(root, handoff, {"job_id": "fixture", "attempt_id": "attempt_0001",
                                         "artifacts": [artifact], "outputs": {}})
    atomic_json(root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff.relative_to(root).as_posix(), "handoff_sha256": file_sha256(handoff),
        "manifest_path": artifact["path"], "manifest_sha256": artifact["sha256"],
    })
    core = RetrievalCore(tmp_path / "runs", RUN_ID)
    settings = OwaspSettings(True, AssessmentMode.ASSESSMENT, "reviewer", 60, 120, 8, 10, 4, 8)
    return root, source, core, settings, manifest, file_id.value


def test_accepted_syntax_location_selects_complete_original_subject(publication):
    root, _, core, settings, manifest, identity = publication
    inputs = accepted_inputs(core, settings, manifest_path=manifest)
    [item] = inputs["evidence"]
    assert item["reference"]["source_identity"] == identity
    assert item["reference"]["publication"]["index"] == "source"
    assert item["reference"]["locator"]["lines"] == [201, 203]
    assert item["source_subject"]["outside_lines"] == 220
    assert not item["truncated"] and item["excerpt"].startswith("@audit")
    assert subjects(PROCEDURES[0], item)
    resolver = EvidenceResolver(core, accept_manifest(root))
    assert resolver.resolve(item["reference"], component_id="api")["source_subject"] == item["source_subject"]


@pytest.mark.parametrize("damage", ["target_bytes", "foreign_run", "forged_publication"])
def test_changed_or_foreign_original_evidence_never_becomes_a_subject(publication, damage):
    root, source, core, settings, manifest, _ = publication
    [item] = accepted_inputs(core, settings, manifest_path=manifest)["evidence"]
    ref = deepcopy(item["reference"])
    if damage == "target_bytes":
        source.write_bytes(SOURCE.replace("SELECT 1", "SELECT 2").encode())
    elif damage == "foreign_run":
        ref["run_id"] = "foreign"
    else:
        ref["publication"]["sha256"] = "f" * 64
    with pytest.raises(ValueError):
        EvidenceResolver(core, accept_manifest(root)).resolve(ref, component_id="api")
