"""02-binary-component-cve-match: cve-bin-tool against the NVD-derived database (recorded real output).

The scanner is replaced by recorded cve-bin-tool 3.4 output (tests/fixtures/cve-bin-tool-real/), and
the NVD and database roots are built by the real publishers (see test_cve_bin_tool_db). The produced
attempt is checked by the real `validate_job_output`.
"""
from __future__ import annotations

from datetime import timedelta
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import binary_component_cve_match as job  # noqa: E402
import cve_bin_tool_db as db  # noqa: E402
from test_cve_bin_tool_db import T0, TOOL, Publisher, fake_runner  # noqa: E402
import validate_job_output as validator  # noqa: E402

REAL = ROOT / "tests" / "fixtures" / "cve-bin-tool-real"
SOURCE_SHA = "sha256:" + "a" * 64
NOW = T0 + timedelta(hours=4)


def recorded_scanner(calls, report=None, detected=None, status="OK"):
    def scan(**kwargs):
        calls.append(kwargs)
        if status != "OK":
            return {"status": status, "cause": "container-exit-nonzero", "exit_code": 2}
        data = {"report": report if report is not None else (REAL / "cves-3.4.json").read_bytes(),
                "detected": detected if detected is not None else (REAL / "detected-3.4.cdx.json").read_bytes()}
        return {"status": "OK", **data,
                "evidence": {"image_id": "tool-cve-bin-tool", "image_digest": TOOL["image_digest"], "argv": ["x"],
                             "exit_code": 1, "request_sha256": "sha256:" + "1" * 64, "result_sha256": "sha256:" + "2" * 64,
                             "raw_outputs": []}}
    return scan


class BinaryComponentCveMatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.nvd_root, self.db_root = self.tmp / "nvd", self.tmp / "cve-bin-tool"
        publisher = Publisher(self.nvd_root)
        publisher.sync(T0)
        publisher.sync(T0 + timedelta(hours=2))
        db.build(self.db_root, self.nvd_root, clock=lambda: T0 + timedelta(hours=3), runner=fake_runner([]), tool=TOOL)
        self.run_root = self.tmp / "runs" / "run-1"
        self.source = self.tmp / "binaries"
        (self.source / "unit-a").mkdir(parents=True)
        # The recorded scan was over case001 and case030 in /workspace; the projection mirrors it.
        (self.source / "case001").write_bytes(b"\x7fELF\x02\x01\x01\x00case001")
        (self.source / "case030").write_bytes(b"\x7fELF\x02\x01\x01\x00case030")
        (self.source / "unit-a" / "notes.txt").write_bytes(b"not a binary")
        self.calls = []

    def build(self, scanner=None, source=None, now=NOW):
        return job.build("run-1", "native-1", source_root=source or self.source, source_sha=SOURCE_SHA, now=now,
                         execution_root=self.tmp / "execution", nvd_data_root=self.nvd_root, db_root=self.db_root,
                         tool=TOOL, scanner=scanner or recorded_scanner(self.calls))

    def publish(self, documents):
        attempt = self.run_root / "data" / "jobs" / job.JOB / "whole" / "attempts" / "native-1"
        envelope = job.materialize(documents, attempt, dagster_run_id="dagster-1",
                                   started_at="2026-09-30T16:00:00Z", finished_at="2026-09-30T16:00:00Z")
        errors = validator.validate_job_output(attempt, envelope, envelope["input_fingerprint"],
                                               expected_run_id="run-1", expected_job_id=job.JOB,
                                               consumer_job_id="02-evidence-assembly",
                                               orchestration=validator.NO_ORCHESTRATION_FACTS)
        return attempt, envelope, errors

    def test_real_output_publishes_matches_without_severity(self):
        documents = self.build()
        self.assertEqual(documents["status"], "OK_WITH_GAPS")
        result = documents["result"]
        self.assertEqual([b["path"] for b in result["scanned_binaries"]], ["case001", "case030"])
        self.assertEqual([(m["binary_path"], m["product"], m["version"], m["cve_id"]) for m in result["matches"]],
                         [("case030", "zlib", "1.2.11", "CVE-2018-25032"), ("case030", "zlib", "1.2.11", "CVE-2022-37434"),
                          ("case030", "zlib", "1.2.11", "CVE-2023-45853")])
        self.assertEqual(result["components"], [{"vendor": "zlib", "product": "zlib", "version": "1.2.11",
                                                 "cpe": "cpe:/a:zlib:zlib:1.2.11"}])
        text = json.dumps(result)
        for word in ("severity", "score", "cvss", "remarks", "NewFound"):
            self.assertNotIn(word, text)
        self.assertEqual({g["kind"] for g in result["gaps"]}, {"sources-limited", "checker-degraded"})
        pointer = json.loads((self.db_root / "current.json").read_text())
        self.assertEqual(result["database"]["db_manifest_sha256"], pointer["manifest_sha256"])
        (call,) = self.calls
        self.assertEqual(Path(call["database_dir"]).parent.parent, self.db_root.absolute())
        attempt, envelope, errors = self.publish(documents)
        self.assertEqual(errors, [])
        self.assertEqual(envelope["acceptance_status"], "CURRENT")
        self.assertTrue((attempt / "outputs" / "redaction-receipt.json").is_file())

    def test_nothing_detected_is_a_named_gap_not_a_clean_result(self):
        empty_bom = json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "CVEBINTOOL-workspace"}]}).encode()
        documents = self.build(recorded_scanner(self.calls, report=b"", detected=empty_bom))
        self.assertEqual(documents["result"]["matches"], [])
        self.assertIn("zero-detected-components", {g["kind"] for g in documents["result"]["gaps"]})
        self.assertEqual(self.publish(documents)[2], [])

    def test_no_binaries_is_skipped(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        documents = self.build(source=empty)
        self.assertEqual((documents["status"], documents["skip_reason"]), ("SKIPPED", job.SKIP))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.publish(documents)[2], [])

    def test_a_database_from_another_nvd_snapshot_blocks_and_an_old_nvd_snapshot_fails(self):
        Publisher(self.nvd_root).sync(T0 + timedelta(hours=5))
        documents = self.build(now=T0 + timedelta(hours=6))
        self.assertEqual((documents["status"], documents["cause"]), ("BLOCKED", "db_stale_for_nvd_snapshot"))
        self.assertEqual(self.calls, [])
        envelope = self.publish(documents)[1]
        self.assertEqual(envelope["acceptance_status"], "NOT_ACCEPTED")
        old = self.build(now=T0 + timedelta(days=30))
        self.assertEqual((old["status"], old["cause"]), ("FAILED", "nvd-snapshot_too_old"))

    def test_a_tool_failure_or_an_unknown_path_is_failed_never_empty_success(self):
        failed = self.build(recorded_scanner(self.calls, status="FAILED"))
        self.assertEqual(failed["status"], "FAILED")
        self.assertEqual(failed["result"]["matches"], [])
        self.assertTrue(any(g["kind"] == "tool-failed" for g in failed["result"]["gaps"]))
        stray = json.loads((REAL / "cves-3.4.json").read_text())
        stray[0]["paths"] = "/workspace/elsewhere"
        invalid = self.build(recorded_scanner(self.calls, report=json.dumps(stray).encode()))
        self.assertEqual((invalid["status"], invalid["cause"]), ("FAILED", "output-invalid"))

    def test_one_component_in_two_binaries_is_one_match_per_binary(self):
        # Real cve-bin-tool 3.4 shape when the same zlib is found in two files (recorded 2026-10-01).
        rows = json.loads((REAL / "cves-3.4.json").read_text())
        for row in rows:
            row["paths"] = "/workspace/case001, /workspace/case030"
        matches, _ = job.normalize(json.dumps(rows).encode(), (REAL / "detected-3.4.cdx.json").read_bytes(),
                                   {"case001", "case030"})
        self.assertEqual(len(matches), 6)
        self.assertEqual({m["binary_path"] for m in matches}, {"case001", "case030"})
        self.assertEqual([m["match_id"] for m in matches], [f"BCM-{n:06d}" for n in range(1, 7)])

    def test_no_docker_or_no_image_is_a_blocked_gap_not_a_crash(self):
        import vendor_evidence_b13 as b13
        def no_docker(source_sha, now):
            raise b13.VendorToolBlocked("docker-unavailable")
        database = json.loads((self.db_root / "current.json").read_text())["snapshot_id"]
        outcome = job.scan(run_id="run-1", attempt_id="native-1", source_root=self.source,
                           database_dir=self.db_root / "snapshots" / database, execution_root=self.tmp / "exec",
                           source_sha=SOURCE_SHA, now="2026-09-30T16:00:00Z", runtime_factory=no_docker)
        self.assertEqual(outcome["status"], "BLOCKED")
        self.assertIn(outcome["cause"], ("docker-unavailable", "image_unavailable"))

    def test_a_boundary_refusal_is_blocked_not_a_crash(self):
        import container_execution as ce
        def refuse(runtime, **kwargs):
            raise ce.ContainerRequestError("runtime.container_user must be a numeric non-root uid:gid")
        database = json.loads((self.db_root / "current.json").read_text())["snapshot_id"]
        try:
            job._request(run_id="run-1", attempt_id="x", source_root=self.source,
                         database_dir=self.db_root / "snapshots" / database, source_sha=SOURCE_SHA, now="2026-09-30T16:00:00Z")
        except db.DbUnavailable:
            self.skipTest("no tool-cve-bin-tool B16 record in this checkout")
        outcome = job.scan(run_id="run-1", attempt_id="native-1", source_root=self.source,
                           database_dir=self.db_root / "snapshots" / database, execution_root=self.tmp / "exec",
                           source_sha=SOURCE_SHA, now="2026-09-30T16:00:00Z",
                           runtime_factory=lambda sha, now: object(), run_container=refuse)
        self.assertEqual(outcome, {"status": "BLOCKED", "cause": "request-invalid"})

    def test_the_container_request_is_offline_and_mounts_the_database_read_only(self):
        database = json.loads((self.db_root / "current.json").read_text())["snapshot_id"]
        try:
            request = job._request(run_id="run-1", attempt_id="cve-bin-tool-x", source_root=self.source,
                                   database_dir=self.db_root / "snapshots" / database, source_sha=SOURCE_SHA,
                                   now="2026-09-30T16:00:00Z")
        except db.DbUnavailable as exc:
            self.assertEqual(exc.reason, "IMAGE_UNAVAILABLE")   # no B16 record in this checkout
            return
        self.assertEqual(request["network"], {"mode": "none", "destinations": []})
        self.assertIn("--offline", request["argv"])
        self.assertEqual({m["container_path"] for m in request["target_mounts"]},
                         {"/workspace", "/inputs/cvedb", "/inputs/launcher"})


if __name__ == "__main__":
    unittest.main()
