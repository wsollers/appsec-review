"""Live compatibility qualification for T03 -> component routing -> T04 ... T14.

The chain currently stops at T03. The component producer uses the common accepted-worker-result
envelope, while T03 still requires the legacy top-level ``artifacts`` map. This test retains the
exact boundary and guards against describing the downstream chain as integrated before that
producer/consumer contract is reconciled.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest


PROCESS = Path(__file__).resolve().parents[1]
ROOT = PROCESS.parent
sys.path.insert(0, str(PROCESS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import execution_state  # noqa: E402
import owasp_component_routing as routing  # noqa: E402
import owasp_lane_in  # noqa: E402
import test_owasp_component_routing as routing_fixture  # noqa: E402

sha, write_json = routing_fixture.sha, routing_fixture.write_json


class OwaspChainQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.old_runs = execution_state.RUNS
        execution_state.RUNS = Path(self.temporary.name) / "runs"
        self.addCleanup(setattr, execution_state, "RUNS", self.old_runs)
        self.run_id = "freeciv-chain-qualification"
        self.run = execution_state.RUNS / self.run_id
        self.data = self.run / "data"
        write_json(self.run / "run-status.json", {"run_id": self.run_id, "status": "READY"})

        # Use the realistic four-component fixture, published through the common result helper.
        fixture = routing_fixture.OwaspComponentRoutingTests(methodName="runTest")
        fixture.run_id, fixture.run, fixture.data = self.run_id, self.run, self.data
        self.component_map = fixture._freeciv_like_map()
        self.component_pointer = fixture._publish_component(self.component_map)

        asvs_root = next((ROOT / "data/reference/owasp/owasp_asvs/5.0.0").iterdir())
        reference_path = asvs_root / "manifest.json"
        component_attempt = self.component_pointer["attempt_id"]
        component_path = (self.data / "jobs" / routing.COMPONENT_JOB / "attempts" /
                          component_attempt / "component-purpose-map.json")
        pointer_path = self.data / "jobs" / routing.COMPONENT_JOB / "accepted.json"
        self.request_path = self.run / "inputs" / "owasp-lane-in-request.json"
        write_json(self.request_path, {
            "schema": "appsec-review/owasp-intel-lane-in-request/1.0",
            "run_id": self.run_id,
            "selection": {
                "schema": "appsec-review/standard-selection/1.0",
                "selection_id": "selection-freeciv", "engagement_id": self.run_id,
                "selections": [{
                    "family": "owasp_asvs", "snapshot_id": asvs_root.name,
                    "manifest_sha256": sha(reference_path), "edition": "5.0.0",
                    "enabled_scope": ["server"], "profile_or_level": "L2", "tailoring": [],
                }],
                "approver": "engagement-lead", "approved_at": "2026-09-27T00:00:00Z",
            },
            "permissions": {"static_inspection": True, "dynamic_execution": False,
                            "manual_observation": False, "network_access": False,
                            "target_mutation": False},
            "entries": [{
                "input_id": "component-map", "evidence_class": "derived_intelligence",
                "kind": "component_map", "admission": "accepted_run_output",
                "artifact": {"path": component_path.relative_to(self.data).as_posix(),
                             "sha256": sha(component_path)},
                "producer": {"job_id": routing.COMPONENT_JOB, "attempt_id": component_attempt,
                             "accepted_pointer_path": pointer_path.relative_to(self.data).as_posix(),
                             "accepted_pointer_sha256": sha(pointer_path)},
                "source_artifacts": [{"path": component_path.relative_to(self.data).as_posix(),
                                      "sha256": sha(component_path)}],
                "source_snapshot": {"snapshot_id": self.component_map["source_snapshot_sha256"],
                                    "captured_at": "2026-09-27T00:00:00Z"},
                "derivation_status": "complete",
                "freshness": {"assessed_at": "2026-09-27T00:00:00Z", "status": "current"},
                "redaction_status": "not_required",
                "caveats": ["Classification is routing context, not proof."],
                "use": "locator_only",
            }],
            "nvd": {"requested": False, "snapshot_id": None, "manifest_sha256": None,
                    "advisory_freshness_seconds": 86400},
            "completeness_gaps": [],
        })

    def test_chain_stops_at_t03_common_envelope_compatibility_boundary(self):
        pointer = json.loads((self.data / "jobs" / routing.COMPONENT_JOB / "accepted.json").read_text())
        self.assertEqual(pointer["schema"], "appsec-review/accepted-worker-result/1.0")
        self.assertIn("hashes", pointer)
        self.assertIn("envelope_path", pointer)
        self.assertNotIn("artifacts", pointer)

        with self.assertRaisesRegex(
                execution_state.Blocked,
                "component-map: accepted pointer does not publish an artifact map"):
            owasp_lane_in.admit(
                self.run_id, self.request_path,
                clock=lambda: datetime(2026, 9, 27, tzinfo=timezone.utc),
            )

        # T03 fails before attempt allocation; no downstream publication can be claimed.
        self.assertFalse((self.data / "jobs" / owasp_lane_in.JOB_ID).exists())
        self.assertFalse((self.data / "jobs" / routing.JOB).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
