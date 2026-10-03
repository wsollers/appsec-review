"""Acceptance tests for gap punch list P42 (hello-autotools, 2026-10-03): the optional 02-native-build ->
02-sbom-inventory edge must not let a crashed or BLOCKED native build stop the SBOM.

The SBOM runs whenever the target source is available and records ``native-build-not-published`` as a gap;
required consumers of 02-native-build stay held as before; full-review input assembly binds the accepted
native build into the SBOM request when present. The Dagster wiring test needs Dagster (the code location's
venv) and is skipped without it; the worker and assembly tests are pure Python.

See docs/TODO/gap-punchlist-hello-autotools-2026-10-03.md.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import registry_paths  # noqa: E402,F401

import execution_state  # noqa: E402
from execution_state import Blocked, atomic_json, file_hash  # noqa: E402
import full_review_input_assembly as assembly  # noqa: E402
from publish_job_output import ACCEPTED_SCHEMA  # noqa: E402
from worker_result import artifact_records, terminal_envelope  # noqa: E402
import test_full_review_input_assembly as tfa  # noqa: E402  (modules, so their tests do not re-run here)
import test_gap_punchlist_builddeps as tbd  # noqa: E402


class SbomGapTests(unittest.TestCase):
    def setUp(self):
        self.case = tbd.SbomBuildDependencyTests("test_p37_deb_rows_dedupe_with_syft")
        self.case.setUp()

    def tearDown(self):
        self.case.tearDown()

    def test_p42_sbom_without_a_published_native_build_records_the_gap(self):
        """P42: no accepted 02-native-build (crash or BLOCKED) -> the SBOM publishes with native-build-not-published."""
        envelope, result, _cdx = self.case.sbom(None)
        self.assertIn(envelope["execution_status"], {"OK_WITH_GAPS"})
        self.assertTrue(any(gap.startswith("native-build-not-published") for gap in envelope["gaps"]), envelope["gaps"])
        self.assertTrue(result["components"] is not None)


class AssemblyBindingTests(unittest.TestCase):
    def setUp(self):
        self.case = tfa.FullReviewInputAssemblyTests("test_component_map_derives_exact_first_wave_and_explicit_na_rows")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)  # the borrowed case's own patches (source_projection)
        self.addCleanup(self.case.tearDown)
        runs = patch.object(execution_state, "RUNS", self.case.runs)
        runs.start()
        self.addCleanup(runs.stop)

    def _accepted_native_build(self) -> Path:
        base = self.case.run / "data/jobs/02-native-build"
        attempt = base / "attempts/nb-1"
        attempt.mkdir(parents=True)
        atomic_json(attempt / "native-build.json", {"schema": "appsec-review/native-build/1", "run_id": "review-1",
            "source_revision": "x", "upstream": {}, "status": "OK", "units": [], "coverage_gaps": []})
        envelope = terminal_envelope(run_id="review-1", job_id="02-native-build", attempt_id="nb-1",
            worker_kind="pinned_container", execution_status="OK", acceptance_status="CURRENT",
            input_fingerprint="sha256:" + "7" * 64, output_contract="native-build", started_at=tfa.STAMP,
            finished_at=tfa.STAMP, summary="fixture native build", artifacts=artifact_records(attempt, ["native-build.json"]))
        atomic_json(attempt / "result.json", envelope)
        atomic_json(base / "accepted.json", {"schema": ACCEPTED_SCHEMA, "status": "OK", "run_id": "review-1",
            "job": "02-native-build", "attempt_id": "nb-1", "fingerprint": envelope["input_fingerprint"],
            "envelope_path": "result.json", "envelope_sha256": file_hash(attempt / "result.json")})
        return attempt / "native-build.json"

    def _sbom_request(self) -> dict:
        pointer = self.case._accepted_component()
        self.case._accepted_build_index()
        plan = self.case.run / "inputs/derived-full-review-plan.json"
        assembly.derive_plan(pointer, self.case.run.absolute(), plan, run_id="review-1", generated_at=tfa.STAMP)
        output, _ = self.case._assemble(plan)
        return json.loads((output / "attempts/assembly-1/requests/02-sbom-inventory.json").read_text())

    def test_p42_assembly_sbom_request_binds_the_accepted_native_build(self):
        """P42: the assembled SBOM request carries the exact accepted native-build binding."""
        native = self._accepted_native_build()
        binding = self._sbom_request()["payload"].get("native_build", "missing")
        self.assertIsInstance(binding, dict, binding)
        self.assertEqual((binding["attempt_id"], binding["path"], binding["sha256"]),
                         ("nb-1", str(native), "sha256:" + file_hash(native)))

    def test_p42_assembly_sbom_request_without_native_build_binds_the_gap(self):
        """P42: with no accepted native build the request says so (null), so the SBOM records the gap."""
        payload = self._sbom_request()["payload"]
        self.assertIn("native_build", payload)
        self.assertIsNone(payload["native_build"])


@unittest.skipUnless(importlib.util.find_spec("dagster"), "dagster is not installed")
class DagsterWiringTests(unittest.TestCase):
    def test_p42_raising_native_build_still_runs_the_sbom_and_holds_required_consumers(self):
        """P42: a raising native-build stub lets 02-sbom-inventory run; 02-native-sast is still held; the run fails."""
        from dagster import In, job, op
        import dagster_workflow as dw
        self.assertTrue(hasattr(dw, "wire_lifecycle"), "full_review's graph wiring is not reusable")
        ran = []

        @op
        def stub_config():
            return {"engagement_run_id": "review-1", "force": False}

        @op(ins={"configured": In(dict)})
        def seed(configured):
            return {"status": "OK"}

        @op(name="job_02_native_sast", ins={"configured": In(dict), "upstream": In(list)})
        def required_consumer(configured, upstream):
            ran.append("02-native-sast")
            return {}

        def sbom(context, configured, job_id):
            ran.append(job_id)
            return {"job_id": job_id, "status": "OK_WITH_GAPS"}

        ops = {name: dw.LIFECYCLE_OPS[name] for name in ("02-native-build", "02-sbom-inventory")}
        ops["02-native-sast"] = required_consumer

        @job
        def probe():
            configured = stub_config()
            outputs = {name: seed.alias("seed_" + name.replace("-", "_"))(configured)
                       for name in ("00-intake", "02-build-index", "02-build-configure",
                                    "02-iac-config-scan")}  # P43: the SBOM's other optional edge
            dw.wire_lifecycle(configured, outputs, ops)

        with patch.object(dw.native_build_worker, "run", side_effect=Blocked("stub native build crashed")), \
             patch.object(dw, "run_automatic_evidence_job", side_effect=sbom):
            result = probe.execute_in_process(raise_on_error=False)
        self.assertEqual(ran, ["02-sbom-inventory"])
        self.assertFalse(result.success)
        failed = {event.step_key for event in result.all_events if event.event_type_value == "STEP_FAILURE"}
        self.assertNotIn("job_02_native_build", failed)
        self.assertEqual(failed, {"job_02_native_build_published"}, "the gate still fails the run")


if __name__ == "__main__":
    unittest.main()
