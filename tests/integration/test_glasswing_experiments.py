"""Manual offline publication/rebuild scenarios; never an automatic unit gate or live campaign."""
import json
from pathlib import Path

from appsec_review.observability.experiments import csv_exports, publish_snapshot, rebuild
from tests.fixtures.glasswing import experiment


def test_late_completion_and_label_revision_publish_coexisting_replayable_snapshots(tmp_path):
    final = experiment([["A"], ["B"], []], outcomes={"A": "fp"})
    pending = json.loads(json.dumps(final))
    pending["completions"].pop(1)
    old = publish_snapshot(tmp_path, rebuild(pending))
    completed = publish_snapshot(tmp_path, rebuild(final))
    final["adjudications"]["revision"] = "labels-2"
    final["adjudications"]["labels"][0].update(outcome="tp", is_real_bug=True)
    corrected = publish_snapshot(tmp_path, rebuild(final))
    assert len({receipt["snapshot_id"] for receipt in (old, completed, corrected)}) == 3
    for receipt in (old, completed, corrected):
        snapshot = json.loads(Path(receipt["path"]).read_text())
        assert rebuild(snapshot["source"]) == snapshot
        for name, content in csv_exports(snapshot).items():
            destination = tmp_path / f"{receipt['snapshot_id']}-{name}"
            destination.write_text(content)
            assert destination.read_text() == content
