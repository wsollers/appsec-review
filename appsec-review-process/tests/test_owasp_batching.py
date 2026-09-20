"""Offline qualification for T05 OWASP control partitioning and batching."""
from __future__ import annotations

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
import owasp_batching
from schema_validate import validate_document


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class OwaspBatchingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.old_runs = execution_state.RUNS
        execution_state.RUNS = Path(self.temporary.name) / "runs"
        self.addCleanup(setattr, execution_state, "RUNS", self.old_runs)
        self.run_id = "batching-fixture"
        self.run = execution_state.RUNS / self.run_id
        self.data = self.run / "data"
        write_json(self.run / "run-status.json", {"run_id": self.run_id, "status": "READY"})

        self.snapshot_root = next((ROOT / "data" / "reference" / "owasp" / "owasp_asvs" / "5.0.0").iterdir())
        self.snapshot_manifest_path = self.snapshot_root / "manifest.json"
        catalog = json.loads((self.snapshot_root / "normalized" / "catalog.json").read_text(encoding="utf-8"))
        self.controls = [record for record in catalog["records"] if record["record_type"] == "control"]
        self.opencre_root = next((ROOT / "data" / "reference" / "opencre").iterdir())
        self.opencre_manifest_path = self.opencre_root / "manifest.json"
        self.opencre_manifest = json.loads(self.opencre_manifest_path.read_text(encoding="utf-8"))
        self.config = json.loads((PROCESS / "config" / "owasp-batching" / "default-v1.json").read_text(encoding="utf-8"))
        self.config_digest = execution_state.digest(self.config)
        self.attempt_id = "applicability-1"
        self.request_path = self.run / "inputs" / "owasp-batch-request.json"

    def row(self, control, component_id, status="applicable"):
        target_id = "target-" + execution_state.digest({"control": control["control_id"],
                                                          "component": component_id})[:20]
        scope_authority = ({"actor": "engagement-lead", "rationale": "Excluded by approved scope.",
                            "decided_at": "2026-09-20T00:00:00Z"}
                           if status == "out_of_scope" else None)
        return {
            "target_id": target_id, "selection_id": "selection-1",
            "standard_family": control["standard_family"], "standard_version": control["standard_version"],
            "profile_or_level": "L2", "control_id": control["control_id"],
            "control_title": control["title"],
            "domain_id": control["group"]["chapter_id"], "source_record_hash": execution_state.digest(control),
            "proof_obligations": control["proof_obligations"], "component_id": component_id,
            "component_name": component_id.title(), "classification_hash": "a" * 64,
            "classification_input_ids": ["component-map"], "applicability_status": status,
            "rationale": f"Fixture decision: {status}.", "signals": [], "citations": [],
            "source_completeness": "adequate" if status == "not_applicable" else "unknown",
            "conditional_expression": "feature enabled" if status == "conditional" else None,
            "decision_source": "scope_authority" if status == "out_of_scope" else (
                "unresolved" if status == "cannot_determine" else "deterministic_rule"),
            "rule_ids": [] if status in {"out_of_scope", "cannot_determine"} else ["fixture-rule"],
            "override_ids": [], "scope_authority": scope_authority, "rescope_state": "none",
            "invalidated_result_ids": [], "rescope_actions": [],
        }

    def publish_model(self, rows):
        statuses = ("applicable", "conditional", "not_applicable", "cannot_determine", "out_of_scope")
        components = {row["component_id"] for row in rows}
        model = {
            "schema": "appsec-review/owasp-applicability-model/1.0", "run_id": self.run_id,
            "selection_id": "selection-1", "input_fingerprint": "f" * 64,
            "generated_at": "2026-09-20T00:00:00+00:00",
            "assigned_reviewer": {"reviewer_id": "reviewer-1", "role": "owasp-applicability-reviewer"},
            "reference_snapshots": [
                {"family": "owasp_asvs", "edition": "5.0.0", "profile_or_level": "L2",
                 "snapshot_id": self.snapshot_root.name, "manifest_sha256": sha(self.snapshot_manifest_path)},
                {"family": "opencre", "edition": self.opencre_manifest["edition"],
                 "profile_or_level": None, "snapshot_id": self.opencre_root.name,
                 "manifest_sha256": sha(self.opencre_manifest_path)},
            ],
            "counts": {"selected_controls": len({row["control_id"] for row in rows}),
                       "components": len(components), "control_targets": len(rows),
                       **{status: sum(row["applicability_status"] == status for row in rows)
                          for status in statuses}},
            "rows": sorted(rows, key=lambda row: (row["standard_family"], row["control_id"], row["component_id"])),
            "claim_limits": ["Applicability only."],
        }
        attempt = (self.data / "jobs" / owasp_batching.UPSTREAM_JOB / "whole" / "attempts" /
                   self.attempt_id / "outputs")
        model_path = attempt / "owasp-applicability-model.json"
        applicable_path = attempt / "applicable-controls.json"
        gaps_path = attempt / "applicability-gaps.json"
        override_path = attempt / "applicability-overrides.jsonl"
        write_json(model_path, model)
        write_json(applicable_path, {"schema": "appsec-review/owasp-applicable-controls/1.0",
                                     "run_id": self.run_id, "selection_id": "selection-1",
                                     "rows": [row for row in model["rows"]
                                              if row["applicability_status"] in owasp_batching.ASSIGNED]})
        gaps = []
        for row in model["rows"]:
            if row["applicability_status"] in {"conditional", "cannot_determine"}:
                gaps.append({"gap_id": "gap-" + row["target_id"], "target_id": row["target_id"],
                             "kind": "conditional_applicability" if row["applicability_status"] == "conditional"
                             else "cannot_determine", "summary": row["rationale"]})
        write_json(gaps_path, {"schema": "appsec-review/owasp-applicability-gaps/1.0",
                               "run_id": self.run_id, "selection_id": "selection-1", "gaps": gaps})
        override_path.parent.mkdir(parents=True, exist_ok=True)
        override_path.write_bytes(b"")
        pointer_path = self.data / "jobs" / owasp_batching.UPSTREAM_JOB / "whole" / "accepted.json"
        artifacts = {path.relative_to(attempt.parent).as_posix(): sha(path)
                     for path in (model_path, applicable_path, gaps_path, override_path)}
        write_json(pointer_path, {"status": "OK_WITH_GAPS" if gaps else "OK", "run_id": self.run_id,
                                  "job_id": owasp_batching.UPSTREAM_JOB, "attempt_id": self.attempt_id,
                                  "input_fingerprint": "f" * 64, "selection_id": "selection-1",
                                  "artifacts": artifacts})
        write_json(pointer_path.with_name("latest.json"), {"attempt_id": self.attempt_id})
        return model, model_path, pointer_path

    def request(self, model, model_path, pointer_path, *, rules=None):
        component_ids = sorted({row["component_id"] for row in model["rows"]})
        request = {
            "schema": "appsec-review/owasp-batch-request/1.0", "run_id": self.run_id,
            "applicability": {"attempt_id": self.attempt_id,
                              "accepted_pointer_path": f"jobs/{owasp_batching.UPSTREAM_JOB}/whole/accepted.json",
                              "accepted_pointer_sha256": sha(pointer_path),
                              "model_path": model_path.relative_to(self.data).as_posix(),
                              "model_sha256": sha(model_path)},
            "batch_config": {"path": "appsec-review-process/config/owasp-batching/default-v1.json",
                             "config_digest": self.config_digest},
            "component_contexts": [{"component_id": component_id, "component_group_id": "application",
                                    "trust_role": "application-tier",
                                    "evidence_root_input_ids": ["component-map"]}
                                   for component_id in component_ids],
            "routing_rules": rules or [{
                "route_id": "asvs-static", "selector": {"standard_family": "owasp_asvs",
                    "obligation_ids": [], "control_ids": [], "domain_ids": [], "all_controls": True,
                    "component_ids": [], "all_components": True},
                "primary_evidence_mode": "static_source", "authorization_boundary": "static_offline",
                "tooling_profile_id": "read-only-source", "validator_role": "owasp-validator",
                "linked_test_ids": [],
            }],
        }
        write_json(self.request_path, request)
        return request

    def output(self, result, name):
        return (self.data / "jobs" / owasp_batching.JOB_ID / "whole" / "attempts" /
                result["attempt_id"] / "outputs" / name)

    def test_row_limit_determinism_and_reuse(self):
        records = [record for record in self.controls if record["group"]["chapter_id"] == "V1"][:13]
        self.assertEqual(len(records), 13)
        model, model_path, pointer = self.publish_model([self.row(record, "server") for record in records])
        self.request(model, model_path, pointer)
        first = owasp_batching.build(self.run_id, self.request_path)
        worklist = json.loads(self.output(first, "owasp-validation-worklist.json").read_text(encoding="utf-8"))
        batches = json.loads(self.output(first, "owasp-batch-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(validate_document(worklist, "owasp-validation-worklist.schema.json"), [])
        self.assertEqual(validate_document(batches, "owasp-batch-manifest.schema.json"), [])
        self.assertEqual(worklist["counts"]["control_targets"], 13)
        self.assertTrue(any(assignment["crosswalk_lineage"] for assignment in worklist["assignments"]))
        self.assertEqual([batch["control_target_count"] for batch in batches["batches"]], [12, 1])
        self.assertTrue(all(not batch["dispatch_ready"] and not batch["execution_authorized"]
                            for batch in batches["batches"]))
        second = owasp_batching.build(self.run_id, self.request_path)
        self.assertTrue(second["reused"])
        self.assertEqual(second["attempt_id"], first["attempt_id"])

    def test_component_limit_and_domain_separation(self):
        first = self.controls[0]
        other_domain = next(record for record in self.controls
                            if record["group"]["chapter_id"] != first["group"]["chapter_id"])
        rows = [self.row(first, f"component-{index}") for index in range(6)]
        rows.extend(self.row(other_domain, f"component-{index}") for index in range(6))
        model, model_path, pointer = self.publish_model(rows)
        self.request(model, model_path, pointer)
        result = owasp_batching.build(self.run_id, self.request_path)
        manifest = json.loads(self.output(result, "owasp-batch-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual({batch["domain_id"] for batch in manifest["batches"]},
                         {first["group"]["chapter_id"], other_domain["group"]["chapter_id"]})
        self.assertTrue(all(batch["component_count"] <= 5 for batch in manifest["batches"]))
        self.assertEqual(len(manifest["batches"]), 4)

    def test_every_applicability_disposition_is_accounted(self):
        statuses = ["applicable", "conditional", "not_applicable", "cannot_determine", "out_of_scope"]
        rows = [self.row(self.controls[index], "server", status) for index, status in enumerate(statuses)]
        model, model_path, pointer = self.publish_model(rows)
        self.request(model, model_path, pointer)
        result = owasp_batching.build(self.run_id, self.request_path)
        self.assertEqual(result["status"], "OK_WITH_GAPS")
        worklist = json.loads(self.output(result, "owasp-validation-worklist.json").read_text(encoding="utf-8"))
        self.assertEqual(len(worklist["assignments"]), 5)
        dispositions = {assignment["applicability_status"]: assignment["disposition"]
                        for assignment in worklist["assignments"]}
        self.assertEqual(dispositions["not_applicable"], "not_applicable_accounted")
        self.assertEqual(dispositions["out_of_scope"], "out_of_scope_accounted")
        self.assertEqual(dispositions["cannot_determine"], "unresolved_applicability_gap")
        self.assertEqual(sum(bool(assignment["batch_ids"]) for assignment in worklist["assignments"]), 2)

    def test_composite_obligations_split_and_require_join(self):
        record = self.controls[0]
        row = self.row(record, "server")
        row["proof_obligations"] = [
            {"obligation_id": "part-static", "text": "Inspect source.",
             "evidence_classification": "classified", "minimum_evidence_modes": ["static_source"]},
            {"obligation_id": "part-config", "text": "Inspect config.",
             "evidence_classification": "classified", "minimum_evidence_modes": ["static_config"]},
        ]
        model = {"run_id": self.run_id, "selection_id": "selection-1", "input_fingerprint": "f" * 64,
                 "rows": [row]}
        rules = []
        for obligation_id, mode in (("part-static", "static_source"), ("part-config", "static_config")):
            rules.append({"route_id": f"route-{mode}", "selector": {"standard_family": "owasp_asvs",
                "obligation_ids": [obligation_id], "control_ids": [], "domain_ids": [], "all_controls": False,
                "component_ids": [], "all_components": True}, "primary_evidence_mode": mode,
                "authorization_boundary": "static_offline", "tooling_profile_id": f"tool-{mode}",
                "validator_role": "owasp-validator", "linked_test_ids": []})
        request = {"run_id": self.run_id,
                   "component_contexts": [{"component_id": "server", "component_group_id": "application",
                                           "trust_role": "application-tier",
                                           "evidence_root_input_ids": ["component-map"]}],
                   "routing_rules": rules, "applicability": {"model_sha256": "a" * 64}}
        worklist, manifest, _, _ = owasp_batching._build_outputs(
            request, model, self.config, self.config_digest, {}, {})
        assignment = worklist["assignments"][0]
        self.assertTrue(assignment["join_required"])
        self.assertEqual(len(assignment["batch_ids"]), 2)
        self.assertTrue(all(fragment["final_control_status_authority"] == "obligation_fragment_only"
                            for batch in manifest["batches"] for fragment in batch["fragments"]))

    def test_dynamic_is_request_only_and_manual_is_blocked(self):
        model, model_path, pointer = self.publish_model([self.row(self.controls[0], "server")])
        dynamic = [{"route_id": "dynamic-request", "selector": {"standard_family": "owasp_asvs",
                    "obligation_ids": [], "control_ids": [], "domain_ids": [], "all_controls": True,
                    "component_ids": [], "all_components": True},
                    "primary_evidence_mode": "dynamic_runtime", "authorization_boundary": "dynamic_request_only",
                    "tooling_profile_id": "request-drafting-only", "validator_role": "dynamic-test-request-author",
                    "linked_test_ids": []}]
        request = self.request(model, model_path, pointer, rules=dynamic)
        result = owasp_batching.build(self.run_id, self.request_path)
        manifest = json.loads(self.output(result, "owasp-batch-manifest.json").read_text(encoding="utf-8"))
        self.assertFalse(manifest["dynamic_execution"])
        self.assertEqual(manifest["batches"][0]["authorization_boundary"], "dynamic_request_only")
        request["routing_rules"][0].update(primary_evidence_mode="manual_inspection",
                                            authorization_boundary="static_offline",
                                            validator_role="owasp-validator")
        write_json(self.request_path, request)
        with self.assertRaisesRegex(execution_state.Blocked, "manual observation"):
            owasp_batching.build(self.run_id, self.request_path, force=True)

    def test_tampered_pointer_and_unqualified_config_fail_closed(self):
        model, model_path, pointer = self.publish_model([self.row(self.controls[0], "server")])
        request = self.request(model, model_path, pointer)
        request["batch_config"]["config_digest"] = "0" * 64
        write_json(self.request_path, request)
        with self.assertRaisesRegex(execution_state.Blocked, "config digest mismatch"):
            owasp_batching.build(self.run_id, self.request_path)
        request["batch_config"]["config_digest"] = self.config_digest
        pointer_data = json.loads(pointer.read_text(encoding="utf-8"))
        pointer_data["status"] = "FAILED"
        write_json(pointer, pointer_data)
        request["applicability"]["accepted_pointer_sha256"] = sha(pointer)
        write_json(self.request_path, request)
        with self.assertRaisesRegex(execution_state.Blocked, "identity/status mismatch"):
            owasp_batching.build(self.run_id, self.request_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
