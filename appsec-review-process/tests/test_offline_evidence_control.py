from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import automatic_evidence_inputs as automatic
import offline_evidence_control as control
from execution_state import Blocked


class OfflineEvidenceControlTests(unittest.TestCase):
    def test_stages_only_after_both_snapshots_and_table_validate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); run = root / "runs" / "run-one"; (run / "inputs").mkdir(parents=True)
            (run / "inputs" / "artifact-manifest.json").write_text("{}\n", encoding="utf-8")
            registry = root / "registry"; registry.mkdir()
            table = root / "table.json"; table.write_text(json.dumps({
                "schema": "appsec-review/dependency-lifecycle-reference-table/1.0",
                "table_id": "curated", "version": "1", "as_of": "2026-09-27",
                "rows": [{"row_id": "openssl-1.1.1", "ecosystem": "conan", "name": "openssl",
                          "cycle": "1.1.1", "status": "end-of-life", "eol_date": "2023-09-11"}]}) + "\n")
            now = datetime(2026, 9, 27, 12, tzinfo=timezone.utc)
            with mock.patch.object(control, "run_path", return_value=run), \
                 mock.patch.object(control, "data_path", return_value=run / "data/controls" / automatic.CONTROL), \
                 mock.patch.object(control.snapshots, "resolve", return_value={"snapshot_id": "verified"}) as resolve:
                path = control.stage_control("run-one", snapshot_registry=registry,
                    max_database_age_seconds=86400, reference_table=table,
                    max_reference_age_days=30, now=now)
                self.assertEqual(resolve.call_count, 2)
                self.assertEqual(json.loads(path.read_text())["offline_snapshots"]["registry_path"], str(registry.resolve()))

    def test_refuses_stale_table(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); run = root / "run"; (run / "inputs").mkdir(parents=True)
            (run / "inputs/artifact-manifest.json").write_text("{}\n")
            registry = root / "registry"; registry.mkdir()
            table = root / "table.json"; table.write_text(json.dumps({
                "schema": "appsec-review/dependency-lifecycle-reference-table/1.0",
                "table_id": "curated", "version": "1", "as_of": "2025-01-01",
                "rows": [{"row_id": "openssl-1.1.1", "ecosystem": "conan", "name": "openssl",
                          "cycle": "1.1.1", "status": "end-of-life", "eol_date": "2023-09-11"}]}) + "\n")
            with mock.patch.object(control, "run_path", return_value=run), \
                 mock.patch.object(control.snapshots, "resolve", return_value={"snapshot_id": "verified"}):
                with self.assertRaisesRegex(Blocked, "stale"):
                    control.stage_control("run-one", snapshot_registry=registry,
                        max_database_age_seconds=86400, reference_table=table,
                        max_reference_age_days=30,
                        now=datetime(2026, 9, 27, tzinfo=timezone.utc))


if __name__ == "__main__": unittest.main()
