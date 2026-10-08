import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_third_party_data_sync.publication import publish_snapshot, verify_current


def test_atomic_publication_preserves_last_good_pointer_and_detects_tampering(tmp_path: Path) -> None:
    root = tmp_path / "feed"
    source = tmp_path / "source.bin"
    source.write_bytes(b"verified")
    first = publish_snapshot(root, feed_id="fixture", schema="fixture/1", files={"data/source.bin": source},
                             manifest_fields={"source": "fixture"})

    missing = tmp_path / "missing.bin"
    with pytest.raises(ValueError, match="unsafe publication file"):
        publish_snapshot(root, feed_id="fixture", schema="fixture/1", files={"data/missing.bin": missing},
                         manifest_fields={"source": "broken"})
    assert json.loads((root / "current.json").read_text(encoding="utf-8"))["snapshot_id"] == first["snapshot_id"]

    published = root / "snapshots" / first["snapshot_id"] / "data" / "source.bin"
    published.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="integrity mismatch"):
        verify_current(root, "fixture")
