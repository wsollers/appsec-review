"""Manual recorded quality and disposable retention acceptance; no live inference."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from appsec_review.observability.quality import compare_trends, evaluation_trend, publish_trend
from appsec_review.observability.retention import CATALOG, apply_retention, plan_retention
from appsec_review.review.evaluation import REPORT_SCHEMA
from appsec_review.review.identity import sha256_hex
from appsec_review.storage import atomic_json


def test_pinned_recorded_corpus_trends(tmp_path):
    fixture = Path(__file__).parents[1] / "fixtures/operations-quality.json"
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == "d7f98edbf8deb0458657ef4fb1f7fee264ee1ff7ee23afa76841955ba3331a33"
    document = json.loads(fixture.read_bytes())
    rows = [{**row, "guidance_sha256": "a" * 64} for row in document["rows"]]
    report = {"schema": REPORT_SCHEMA, "cases_sha256": sha256_hex(document["cases"]),
              "settings_sha256": "b" * 64, "role": "independent_verifier", "variants": {"full": {"rows": rows}}}
    baseline, candidate = [evaluation_trend(report, document["cases"], variant="full",
                                          implementation_sha=revision * 40, model_sha256="c" * 64)
                           for revision in ("1", "2")]
    assert publish_trend(tmp_path, baseline)["status"] == "published"
    assert publish_trend(tmp_path, candidate)["status"] == "published"
    assert compare_trends(baseline, candidate, thresholds=document["thresholds"])["status"] == "passed"


def test_disposable_multi_run_retention_with_reuse_and_holds(tmp_path):
    root = tmp_path / "sealed"
    root.mkdir(mode=0o700)
    paths = ["r1/data/receipt.json", "r2/data/shared.bin", "r2/data/obsolete.bin", "r3/data/held.bin"]
    objects = []
    for relative in paths:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(relative.encode())
        objects.append({"path": relative, "run_id": relative.split("/")[0], "retain": False,
                        "sha256": hashlib.sha256(relative.encode()).hexdigest(), "references": [],
                        "role": "accepted_receipt" if relative == paths[0] else "artifact"})
    objects[0]["references"] = [paths[1]]
    atomic_json(root / CATALOG, {"schema": "appsec-review/retention-catalog/1",
                                "custody": "sealed_offline", "owner": "acceptance-fixture", "objects": objects,
                                "runs": {run: {"state": "held" if run == "r3" else "terminal",
                                               "leases": [], "repair_hold": run == "r3"}
                                         for run in ("r1", "r2", "r3")}})
    plan = plan_retention(root)
    assert plan["delete"] == [paths[2]]
    assert apply_retention(root, plan)["status"] == "dry_run"
    assert apply_retention(root, plan, apply=True)["deleted"] == [paths[2]]
    assert all((root / path).is_file() for path in (paths[0], paths[1], paths[3]))
