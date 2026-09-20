"""Offline qualification for the T04 OWASP applicability model."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


PROCESS = Path(__file__).resolve().parents[1]
ROOT = PROCESS.parent
sys.path.insert(0, str(PROCESS))

import execution_state
import owasp_applicability
from schema_validate import validate_document


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class OwaspApplicabilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.old_runs = execution_state.RUNS
        execution_state.RUNS = Path(self.temporary.name) / "runs"
        self.addCleanup(setattr, execution_state, "RUNS", self.old_runs)
        self.run_id = "applicability-fixture"
        self.run = execution_state.RUNS / self.run_id
        self.data = self.run / "data"
        write_json(self.run / "run-status.json", {"run_id": self.run_id, "status": "READY"})

        raw = self.data / "imports" / "import-1" / "component.json"
        write_json(raw, {"component": "server", "kind": "web application"})
        self.raw = raw
        asvs_root = next((ROOT / "data" / "reference" / "owasp" / "owasp_asvs" / "5.0.0").iterdir())
        reference_manifest_path = asvs_root / "manifest.json"
        reference_manifest = json.loads(reference_manifest_path.read_text(encoding="utf-8"))
        selection = {
            "schema": "appsec-review/standard-selection/1.0", "selection_id": "selection-1",
            "engagement_id": self.run_id,
            "selections": [{"family": "owasp_asvs", "snapshot_id": asvs_root.name,
                            "manifest_sha256": sha(reference_manifest_path), "edition": "5.0.0",
                            "enabled_scope": ["server"], "profile_or_level": "L2", "tailoring": []}],
            "approver": "engagement-lead", "approved_at": "2026-09-20T00:00:00Z",
        }
        self.input_manifest = {
            "schema": "appsec-review/owasp-input-manifest/1.0", "run_id": self.run_id,
            "selection_id": "selection-1", "selection": selection, "input_fingerprint": "b" * 64,
            "admitted_at": "2026-09-20T00:00:00+00:00",
            "permissions": {"static_inspection": True, "dynamic_execution": False,
                            "manual_observation": False, "network_access": False,
                            "target_mutation": False},
            "reference_snapshots": [{"family": "owasp_asvs", "edition": "5.0.0",
                                     "profile_or_level": "L2", "snapshot_id": asvs_root.name,
                                     "manifest_path": reference_manifest_path.relative_to(ROOT).as_posix(),
                                     "manifest_sha256": sha(reference_manifest_path),
                                     "manifest": reference_manifest}],
            "entries": [{
                "input_id": "component-map", "evidence_class": "raw_evidence",
                "kind": "component_map", "admission": "explicit_import",
                "artifact": {"path": "imports/import-1/component.json", "sha256": sha(raw)},
                "producer": None, "source_artifacts": [], "source_snapshot": None,
                "derivation_status": None,
                "freshness": {"assessed_at": "2026-09-20T00:00:00Z", "status": "current"},
                "redaction_status": "not_required", "caveats": [], "use": "canonical_evidence",
                "admission_validated": True, "may_support_control_status": True,
            }],
            "nvd": None, "gaps": [],
            "claim_limits": ["Applicability input only."],
        }
        self.t03_attempt = "lane-in-1"
        self.t03_manifest = (self.data / "jobs" / owasp_applicability.UPSTREAM_JOB / "whole" /
                             "attempts" / self.t03_attempt / "outputs" / "owasp-input-manifest.json")
        write_json(self.t03_manifest, self.input_manifest)
        self.t03_pointer = self.data / "jobs" / owasp_applicability.UPSTREAM_JOB / "whole" / "accepted.json"
        write_json(self.t03_pointer, {"status": "OK", "run_id": self.run_id,
                                     "job_id": owasp_applicability.UPSTREAM_JOB,
                                     "attempt_id": self.t03_attempt, "input_fingerprint": "b" * 64,
                                     "selection_id": "selection-1",
                                     "artifacts": {"outputs/owasp-input-manifest.json": sha(self.t03_manifest)}})
        write_json(self.t03_pointer.with_name("latest.json"), {"attempt_id": self.t03_attempt})

        self.citation = {"input_id": "component-map", "artifact_path": "imports/import-1/component.json",
                         "sha256": sha(raw), "locator": "$.kind", "observed_fact": "Component is a web application."}
        self.signal = {"signal_type": "positive_presence", "fact": "Web application is present.",
                       "input_id": "component-map"}
        self.request = {
            "schema": "appsec-review/owasp-applicability-request/1.0", "run_id": self.run_id,
            "input_manifest": {"attempt_id": self.t03_attempt,
                               "accepted_pointer_path": f"jobs/{owasp_applicability.UPSTREAM_JOB}/whole/accepted.json",
                               "accepted_pointer_sha256": sha(self.t03_pointer),
                               "manifest_path": f"jobs/{owasp_applicability.UPSTREAM_JOB}/whole/attempts/{self.t03_attempt}/outputs/owasp-input-manifest.json",
                               "manifest_sha256": sha(self.t03_manifest)},
            "assigned_reviewer": {"reviewer_id": "reviewer-1", "role": "owasp-applicability-reviewer"},
            "components": [{"component_id": "server", "name": "Server application",
                            "classification_hash": "a" * 64, "input_ids": ["component-map"],
                            "scope_status": "in_scope", "scope_authority": None}],
            "rules": [{"rule_id": "server-asvs", "component_id": "server",
                       "selector": {"standard_family": "owasp_asvs", "control_ids": [],
                                    "domain_ids": [], "all_controls": True},
                       "decision": {"status": "applicable", "rationale": "ASVS governs the server application.",
                                    "signals": [self.signal], "citations": [self.citation],
                                    "source_completeness": "adequate", "conditional_expression": None}}],
            "overrides": [],
        }
        self.request_path = self.run / "inputs" / "owasp-applicability-request.json"

    def write_request(self):
        write_json(self.request_path, self.request)

    def output(self, result, name):
        return (self.data / "jobs" / owasp_applicability.JOB_ID / "whole" / "attempts" /
                result["attempt_id"] / "outputs" / name)

    def test_complete_cartesian_model_and_reuse(self):
        self.write_request()
        first = owasp_applicability.build(self.run_id, self.request_path)
        self.assertEqual(first["status"], "OK")
        model = json.loads(self.output(first, "owasp-applicability-model.json").read_text(encoding="utf-8"))
        self.assertEqual(validate_document(model, "owasp-applicability-model.schema.json"), [])
        self.assertEqual(model["counts"]["control_targets"], model["counts"]["selected_controls"])
        self.assertEqual(model["counts"]["applicable"], model["counts"]["control_targets"])
        self.assertEqual(len({row["target_id"] for row in model["rows"]}), model["counts"]["control_targets"])
        second = owasp_applicability.build(self.run_id, self.request_path)
        self.assertTrue(second["reused"])
        self.assertEqual(second["attempt_id"], first["attempt_id"])

    def test_justified_override_is_append_only_and_requests_rescope(self):
        self.request["overrides"] = [{
            "override_id": "override-1", "standard_family": "owasp_asvs",
            "control_id": "V1.1.1", "component_id": "server", "prior_status": "applicable",
            "decision": {"status": "conditional", "rationale": "Applicability depends on the decoding path.",
                         "signals": [{"signal_type": "unresolved_condition", "fact": "Decoder path is not classified.",
                                      "input_id": "component-map"}], "citations": [self.citation],
                         "source_completeness": "partial", "conditional_expression": "decoder path exists"},
            "reviewer": self.request["assigned_reviewer"], "decided_at": "2026-09-20T01:00:00Z",
            "invalidated_result_ids": ["assessment-old"], "rescope_actions": ["reassess V1.1.1 for server"],
        }]
        self.write_request()
        result = owasp_applicability.build(self.run_id, self.request_path)
        self.assertEqual(result["status"], "OK_WITH_GAPS")
        model = json.loads(self.output(result, "owasp-applicability-model.json").read_text(encoding="utf-8"))
        row = next(row for row in model["rows"] if row["control_id"] == "V1.1.1")
        self.assertEqual(row["applicability_status"], "conditional")
        self.assertEqual(row["decision_source"], "reviewer_override")
        self.assertEqual(row["rescope_state"], "required")
        lines = self.output(result, "applicability-overrides.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(validate_document(json.loads(lines[0]), "owasp-applicability-override.schema.json"), [])

    def test_technical_na_requires_positive_canonical_evidence(self):
        decision = self.request["rules"][0]["decision"]
        decision.update(status="not_applicable", rationale="No relevant surface.",
                        signals=[{"signal_type": "positive_exclusion", "fact": "Component is outside the control domain.",
                                  "input_id": "component-map"}], citations=[],
                        source_completeness="adequate", conditional_expression=None)
        self.write_request()
        with self.assertRaisesRegex(ValueError, "canonical evidence"):
            owasp_applicability.build(self.run_id, self.request_path)
        decision["signals"] = [{"signal_type": "absence", "fact": "No match found.", "input_id": "component-map"}]
        self.write_request()
        with self.assertRaisesRegex(ValueError, "signal_type"):
            owasp_applicability.build(self.run_id, self.request_path)

    def test_out_of_scope_is_distinct_from_technical_na(self):
        component = self.request["components"][0]
        component["scope_status"] = "out_of_scope"
        component["scope_authority"] = {"actor": "engagement-lead", "rationale": "Server excluded from this engagement.",
                                          "decided_at": "2026-09-20T00:30:00Z"}
        self.request["rules"] = []
        self.write_request()
        result = owasp_applicability.build(self.run_id, self.request_path)
        model = json.loads(self.output(result, "owasp-applicability-model.json").read_text(encoding="utf-8"))
        self.assertEqual(model["counts"]["out_of_scope"], model["counts"]["control_targets"])
        self.assertEqual(model["counts"]["not_applicable"], 0)
        self.assertTrue(all(row["decision_source"] == "scope_authority" for row in model["rows"]))

    def test_out_of_scope_requires_selection_owner(self):
        component = self.request["components"][0]
        component["scope_status"] = "out_of_scope"
        component["scope_authority"] = {"actor": "reviewer-1", "rationale": "Reviewer attempted scope change.",
                                          "decided_at": "2026-09-20T00:30:00Z"}
        self.request["rules"] = []
        self.write_request()
        with self.assertRaisesRegex(ValueError, "selection owner"):
            owasp_applicability.build(self.run_id, self.request_path)

    def test_equal_specificity_conflict_stays_visible(self):
        duplicate = json.loads(json.dumps(self.request["rules"][0]))
        duplicate["rule_id"] = "server-asvs-conflict"
        duplicate["decision"]["status"] = "cannot_determine"
        duplicate["decision"]["rationale"] = "Conflicting classification requires review."
        duplicate["decision"]["signals"] = []
        duplicate["decision"]["citations"] = []
        duplicate["decision"]["source_completeness"] = "partial"
        self.request["rules"].append(duplicate)
        self.write_request()
        result = owasp_applicability.build(self.run_id, self.request_path)
        model = json.loads(self.output(result, "owasp-applicability-model.json").read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "OK_WITH_GAPS")
        self.assertEqual(model["counts"]["cannot_determine"], model["counts"]["control_targets"])

    def test_pointer_tamper_and_wrong_reviewer_fail_closed(self):
        self.request["overrides"] = [{
            "override_id": "override-1", "standard_family": "owasp_asvs", "control_id": "V1.1.1",
            "component_id": "server", "prior_status": "applicable",
            "decision": self.request["rules"][0]["decision"],
            "reviewer": {"reviewer_id": "someone-else", "role": "owasp-applicability-reviewer"},
            "decided_at": "2026-09-20T01:00:00Z", "invalidated_result_ids": [], "rescope_actions": [],
        }]
        self.write_request()
        with self.assertRaisesRegex(ValueError, "not the assigned reviewer"):
            owasp_applicability.build(self.run_id, self.request_path)
        self.request["overrides"] = []
        write_json(self.t03_pointer, {"status": "FAILED", "run_id": self.run_id,
                                     "job_id": owasp_applicability.UPSTREAM_JOB,
                                     "attempt_id": self.t03_attempt, "artifacts": {}})
        self.request["input_manifest"]["accepted_pointer_sha256"] = sha(self.t03_pointer)
        self.write_request()
        with self.assertRaisesRegex(execution_state.Blocked, "identity/status mismatch"):
            owasp_applicability.build(self.run_id, self.request_path)

    def test_override_requires_citation_and_monotonic_chain(self):
        first = {
            "override_id": "override-1", "standard_family": "owasp_asvs",
            "control_id": "V1.1.1", "component_id": "server", "prior_status": "applicable",
            "decision": {"status": "cannot_determine", "rationale": "Classification needs review.",
                         "signals": [], "citations": [], "source_completeness": "partial",
                         "conditional_expression": None},
            "reviewer": self.request["assigned_reviewer"], "decided_at": "2026-09-20T02:00:00Z",
            "invalidated_result_ids": [], "rescope_actions": [],
        }
        self.request["overrides"] = [first]
        self.write_request()
        with self.assertRaisesRegex(ValueError, "requires a citation"):
            owasp_applicability.build(self.run_id, self.request_path)

        first["decision"]["citations"] = [self.citation]
        second = json.loads(json.dumps(first))
        second.update(override_id="override-2", prior_status="cannot_determine",
                      decided_at="2026-09-20T01:00:00Z")
        self.request["overrides"] = [first, second]
        self.write_request()
        with self.assertRaisesRegex(ValueError, "timestamps must advance"):
            owasp_applicability.build(self.run_id, self.request_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
