"""Live compatibility qualification for T03 -> component routing -> T04 ... T14."""
from __future__ import annotations

from datetime import datetime, timezone
from copy import deepcopy
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
import owasp_applicability  # noqa: E402
import owasp_batching  # noqa: E402
import owasp_component_routing as routing  # noqa: E402
import owasp_dispatch  # noqa: E402
import owasp_dispatch_support as dispatch_support  # noqa: E402
import owasp_join_publisher  # noqa: E402
import owasp_lane_in  # noqa: E402
import owasp_validator_handoff  # noqa: E402
import persona_invocation  # noqa: E402
import persona_invocation_support as invocation_support  # noqa: E402
import pool_rendezvous  # noqa: E402
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
        canonical_path = component_path.parent / "canonical" / "server-config.json"
        pointer_path = self.data / "jobs" / routing.COMPONENT_JOB / "accepted.json"
        component_binding = {
            "job_id": routing.COMPONENT_JOB, "attempt_id": component_attempt,
            "artifact_path": component_path.relative_to(self.data).as_posix(),
            "artifact_sha256": sha(component_path),
            "accepted_pointer_path": pointer_path.relative_to(self.data).as_posix(),
            "accepted_pointer_sha256": sha(pointer_path),
            "source_snapshot_sha256": self.component_map["source_snapshot_sha256"],
            "generation_sha256": self.component_map["evidence_manifest_lineage"]["generation_sha256"],
        }
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
                "component_scope": None,
            }, {
                "input_id": "freeciv-server-config", "evidence_class": "raw_evidence",
                "kind": "source_configuration", "admission": "accepted_run_output",
                "artifact": {"path": canonical_path.relative_to(self.data).as_posix(),
                             "sha256": sha(canonical_path)},
                "producer": {"job_id": routing.COMPONENT_JOB, "attempt_id": component_attempt,
                             "accepted_pointer_path": pointer_path.relative_to(self.data).as_posix(),
                             "accepted_pointer_sha256": sha(pointer_path)},
                "source_artifacts": [],
                "source_snapshot": {"snapshot_id": self.component_map["source_snapshot_sha256"],
                                    "captured_at": "2026-09-27T00:00:00Z"},
                "derivation_status": None,
                "freshness": {"assessed_at": "2026-09-27T00:00:00Z", "status": "current"},
                "redaction_status": "not_required", "caveats": [], "use": "canonical_evidence",
                "component_scope": {"component_ids": ["freeciv-server"],
                                    "component_map": component_binding},
            }],
            "nvd": {"requested": False, "snapshot_id": None, "manifest_sha256": None,
                    "advisory_freshness_seconds": 86400},
            "completeness_gaps": [],
        })

    def _through_t04(self):
        t03 = owasp_lane_in.admit(
            self.run_id, self.request_path,
            clock=lambda: datetime(2026, 9, 27, tzinfo=timezone.utc),
        )
        assembled = routing.run(self.run_id)
        applicability_request = routing.request_path(self.run_id, assembled)
        t04 = owasp_applicability.build(self.run_id, applicability_request)
        return t03, assembled, t04, applicability_request

    def _build_t05(self, t04: dict, applicability_request: Path) -> dict:
        t04_root = self.data / "jobs" / owasp_applicability.JOB_ID / "whole"
        model_path = (t04_root / "attempts" / t04["attempt_id"] / "outputs" /
                      "owasp-applicability-model.json")
        projected = json.loads(applicability_request.read_text(encoding="utf-8"))["components"]
        source = {row["component_id"]: row for row in self.component_map["functional_components"]}
        contexts = [{
            "component_id": row["component_id"],
            "component_group_id": source[row["component_id"]]["parallel_review_group"],
            "trust_role": source[row["component_id"]]["component_type"],
            "evidence_root_input_ids": row.get("evidence_input_ids", row["input_ids"]),
        } for row in sorted(projected, key=lambda value: value["component_id"])]
        config = json.loads((PROCESS / "config/owasp-batching/default-v1.json").read_text())
        request_path = self.run / "inputs" / "owasp-batch-request.json"
        write_json(request_path, {
            "schema": "appsec-review/owasp-batch-request/1.0", "run_id": self.run_id,
            "applicability": {
                "attempt_id": t04["attempt_id"],
                "accepted_pointer_path": f"jobs/{owasp_applicability.JOB_ID}/whole/accepted.json",
                "accepted_pointer_sha256": sha(t04_root / "accepted.json"),
                "model_path": model_path.relative_to(self.data).as_posix(),
                "model_sha256": sha(model_path),
            },
            "batch_config": {"path": "appsec-review-process/config/owasp-batching/default-v1.json",
                             "config_digest": execution_state.digest(config)},
            "component_contexts": contexts,
            "routing_rules": [{
                "route_id": "static-offline-all",
                "selector": {"standard_family": "owasp_asvs", "obligation_ids": [],
                             "control_ids": [], "domain_ids": [], "all_controls": True,
                             "component_ids": [], "all_components": True},
                "primary_evidence_mode": "static_source", "authorization_boundary": "static_offline",
                "tooling_profile_id": "read-only-source", "validator_role": "owasp-validator",
                "linked_test_ids": [],
            }],
        })
        return owasp_batching.build(self.run_id, request_path)

    def _build_t06(self, t05: dict) -> tuple[dict, Path]:
        base = self.data / "jobs" / owasp_batching.JOB_ID / "whole"
        attempt = base / "attempts" / t05["attempt_id"]
        batching = {"attempt_id": t05["attempt_id"],
                    "accepted_pointer_path": f"jobs/{owasp_batching.JOB_ID}/whole/accepted.json",
                    "accepted_pointer_sha256": sha(base / "accepted.json")}
        for key, name in {"worklist": "owasp-validation-worklist.json",
                          "batch_manifest": "owasp-batch-manifest.json",
                          "summary": "batch-summary.md"}.items():
            path = attempt / "outputs" / name
            batching[key + "_path"] = path.relative_to(self.data).as_posix()
            batching[key + "_sha256"] = sha(path)
        config = json.loads((PROCESS / "config/owasp-validator-handoff/default-v1.json").read_text())
        request_path = self.run / "inputs" / "owasp-validator-handoff-request.json"
        write_json(request_path, {
            "schema": "appsec-review/owasp-validator-handoff-request/1.0", "run_id": self.run_id,
            "batching": batching,
            "handoff_config": {
                "path": "appsec-review-process/config/owasp-validator-handoff/default-v1.json",
                "config_digest": execution_state.digest(config),
            },
            "budget": "standard", "operation": "build", "batch_id": None,
        })
        result = owasp_validator_handoff.build(self.run_id, request_path)
        handoff = (self.data / "jobs" / owasp_validator_handoff.JOB_ID / "whole" / "attempts" /
                   result["attempt_id"] / "outputs" / "owasp-validator-handoff-set.json")
        return result, handoff

    def test_canonical_evidence_reaches_t14_artifact_size_boundary(self):
        pointer = json.loads((self.data / "jobs" / routing.COMPONENT_JOB / "accepted.json").read_text())
        self.assertEqual(pointer["schema"], "appsec-review/accepted-worker-result/1.0")
        self.assertIn("hashes", pointer)
        self.assertIn("envelope_path", pointer)
        self.assertNotIn("artifacts", pointer)

        t03, assembled, t04, request_path = self._through_t04()
        model_path = (self.data / "jobs" / owasp_applicability.JOB_ID / "whole" / "attempts" /
                      t04["attempt_id"] / "outputs" / "owasp-applicability-model.json")
        model = json.loads(model_path.read_text(encoding="utf-8"))

        self.assertEqual(t03["status"], "OK")
        self.assertEqual(assembled["status"], "OK_WITH_GAPS")
        self.assertEqual(t04["status"], "OK_WITH_GAPS")
        self.assertEqual(model["counts"]["components"], 4)
        self.assertEqual(model["counts"]["not_applicable"], 0)
        self.assertGreater(model["counts"]["applicable"], 0)
        self.assertGreater(model["counts"]["cannot_determine"], 0)

        t05 = self._build_t05(t04, request_path)
        t06, handoff_path = self._build_t06(t05)
        handoff_set = json.loads(handoff_path.read_text(encoding="utf-8"))
        self.assertIn(t05["status"], {"OK", "OK_WITH_GAPS"})
        self.assertIn(t06["status"], {"OK", "OK_WITH_GAPS"})
        self.assertGreater(len(handoff_set["handoffs"]), 0)

        t06_root = self.data / "jobs" / owasp_validator_handoff.JOB_ID / "whole"
        config = json.loads((PROCESS / "config/owasp-dispatch/default-v1.json").read_text())
        request = {
            "schema": owasp_dispatch.REQUEST_ID, "run_id": self.run_id,
            "handoffs": {"attempt_id": t06["attempt_id"],
                         "accepted_pointer_path": f"jobs/{owasp_validator_handoff.JOB_ID}/whole/accepted.json",
                         "accepted_pointer_sha256": sha(t06_root / "accepted.json"),
                         "handoff_set_path": handoff_path.relative_to(self.data).as_posix(),
                         "handoff_set_sha256": sha(handoff_path)},
            "dispatch_config": {"path": "appsec-review-process/config/owasp-dispatch/default-v1.json",
                                "config_digest": execution_state.digest(config)},
            "model": deepcopy(invocation_support.MODEL),
        }
        facts = owasp_dispatch.DispatchFacts(
            registry_dir=PROCESS / "registry", allowed_models=(invocation_support.MODEL,),
            invoker_id=persona_invocation.FixtureInvoker.invoker_id,
            source_snapshot_sha256=invocation_support.SNAPSHOT, registry_ceiling=None,
        )
        dispatch_request = self.run / "inputs" / "owasp-dispatch-request.json"
        write_json(dispatch_request, request)
        invoker = dispatch_support.ValidatorInvoker()
        runtime = owasp_dispatch.DispatchRuntime(
            facts=facts, invoker=invoker,
            clock=lambda: dispatch_support.NOW, cancel=pool_rendezvous.PoolCancel(),
            stop_grace_seconds=2, max_parallel=pool_rendezvous.MAX_PARALLEL,
            wait_limit_seconds=dispatch_support.HANG_SECONDS, drain_seconds=5,
        )
        t10 = owasp_dispatch.dispatch(self.run_id, dispatch_request, runtime=runtime, force=False)
        accounting = owasp_dispatch.load_verified_accounting(self.run_id, facts=facts)
        self.assertIn(t10["status"], {"OK", "OK_WITH_GAPS"})
        self.assertTrue(accounting["cells"])
        dispatched = [cell for cell in accounting["cells"] if cell["disposition"] == "dispatched"]
        self.assertEqual(len(invoker.packages), len(dispatched))
        self.assertTrue(all(cell["state"] == "succeeded" for cell in dispatched))
        self.assertTrue(all(cell["valid_result"] and cell["not_assessed_reason"] is None
                            for cell in dispatched))

        with self.assertRaisesRegex(execution_state.Blocked,
                                    "declared result artifact exceeds 8388608 bytes"):
            owasp_join_publisher.run(self.run_id, "dagster-owasp-chain-qualification", facts)
        published = owasp_join_publisher.root(self.run_id) / "accepted.json"
        self.assertNotIn(json.loads(published.read_text(encoding="utf-8"))["status"],
                         {"OK", "OK_WITH_GAPS"})

    def test_t03_rejects_tampered_common_envelope_binding(self):
        pointer_path = self.data / "jobs" / routing.COMPONENT_JOB / "accepted.json"
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        pointer["envelope_sha256"] = "0" * 64
        write_json(pointer_path, pointer)
        request = json.loads(self.request_path.read_text(encoding="utf-8"))
        request["entries"][0]["producer"]["accepted_pointer_sha256"] = sha(pointer_path)
        write_json(self.request_path, request)
        with self.assertRaisesRegex(execution_state.Blocked, "common accepted publication is invalid"):
            owasp_lane_in.admit(
                self.run_id, self.request_path,
                clock=lambda: datetime(2026, 9, 27, tzinfo=timezone.utc),
            )

    def test_component_evidence_rejects_stale_mixed_and_unresolved_scope(self):
        request = json.loads(self.request_path.read_text(encoding="utf-8"))
        request["entries"][1]["freshness"]["status"] = "stale_accepted"
        request["entries"][1]["caveats"] = ["stale fixture"]
        write_json(self.request_path, request)
        with self.assertRaisesRegex(execution_state.Blocked, "must be current"):
            owasp_lane_in.admit(self.run_id, self.request_path)

        request["entries"][1]["freshness"]["status"] = "current"
        request["entries"][1]["component_scope"]["component_map"]["generation_sha256"] = "sha256:" + "0" * 64
        write_json(self.request_path, request)
        owasp_lane_in.admit(self.run_id, self.request_path)
        with self.assertRaisesRegex(execution_state.Blocked, "mixed or stale generation"):
            routing.assemble(self.run_id)

        request["entries"][1]["component_scope"]["component_map"]["generation_sha256"] = \
            self.component_map["evidence_manifest_lineage"]["generation_sha256"]
        request["entries"][1]["component_scope"]["component_ids"] = ["missing-component"]
        write_json(self.request_path, request)
        owasp_lane_in.admit(self.run_id, self.request_path)
        with self.assertRaisesRegex(execution_state.Blocked, "unresolved or duplicate scope"):
            routing.assemble(self.run_id)

    def test_validator_authority_is_separate_from_worklist_builder(self):
        registry = PROCESS / "registry"
        worklist_template = json.loads((registry / "job-templates/04-owasp-validation-worklist.json").read_text())
        validator_template = json.loads((registry / "job-templates/04-owasp-validator-cell.json").read_text())
        self.assertEqual(worklist_template["composition"]["tooling_profile_id"], "owasp-worklist-builder")
        self.assertEqual(validator_template["composition"]["tooling_profile_id"], "owasp-control-validator")

        worklist = json.loads((registry / "tooling-profiles/owasp-worklist-builder.json").read_text())
        validator = json.loads((registry / "tooling-profiles/owasp-control-validator.json").read_text())
        role = json.loads((registry / "roles/standards-control-validator.json").read_text())
        self.assertNotIn("control_verdict", persona_invocation.claim_ceiling(role, worklist)["allowed"])
        ceiling = persona_invocation.claim_ceiling(role, validator)
        self.assertEqual(set(ceiling["allowed"]), {
            "candidate_followup", "control_verdict", "coverage_gap", "dynamic_test_request",
        })
        self.assertTrue({"verified_finding", "verified_security_finding", "final_severity",
                         "observed_runtime_state", "compliance_verdict", "remediation_status"}
                        <= set(ceiling["prohibited"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
