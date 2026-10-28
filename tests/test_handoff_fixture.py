import json

import pytest

from appsec_review.interchange import HANDOFF_SCHEMA, decode_handoff
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff


def test_synthetic_fixture_publishes_actual_hash_bound_accounting(tmp_path):
    artifact = tmp_path / "manifest.json"
    atomic_json(artifact, {"target_snapshot": "snapshot"})
    handoff_path = tmp_path / "data" / "jobs" / "fixture" / "attempts" / "one" / "handoff.json"
    write_fixture_handoff(tmp_path, handoff_path, {
        "job_id": "fixture", "outputs": {"publish": {"index_manifest": {
            "path": "manifest.json", "sha256": file_sha256(artifact),
        }}},
    })
    handoff = decode_handoff(json.loads(handoff_path.read_text()), run_id=tmp_path.name)
    assert handoff["schema"] == HANDOFF_SCHEMA
    assert handoff["target_snapshot"] == "snapshot"
    for reference in handoff["artifacts"]:
        path = tmp_path / reference["path"]
        assert path.stat().st_size == reference["size_bytes"]
        assert file_sha256(path) == reference["sha256"]
    outcomes = json.loads((tmp_path / handoff["outcomes"]["path"]).read_text())
    assert outcomes["units"][0]["unit_id"] == "publish"
    assert outcomes["units"][0]["execution_status"] == "SUCCEEDED"


def test_synthetic_fixture_never_repairs_changed_artifact_identity(tmp_path):
    artifact = tmp_path / "evidence.json"
    atomic_json(artifact, {})
    with pytest.raises(ValueError, match="artifact changed"):
        write_fixture_handoff(tmp_path, tmp_path / "handoff.json", {
            "job_id": "fixture", "artifacts": [{"path": "evidence.json", "sha256": "0" * 64}],
        })
