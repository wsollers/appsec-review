"""OWASP routing is a pure projection of the accepted 04-owasp-universe into T04 (ADR-0034).

The component-map helpers (``_freeciv_like_map``, ``_publish_component``, ``_publish_lane_in``) stay
for the chain tests that admit the map as report context; it no longer routes any OWASP work.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


PROCESS = Path(__file__).resolve().parents[1]
ROOT = PROCESS.parent
sys.path.insert(0, str(PROCESS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import execution_state
import owasp_applicability
import owasp_component_routing as routing
import owasp_lane_in
import owasp_universe
import owasp_workbench_lifecycle as workbench
from publish_job_output import mark_attempt_started, record_terminal_current
from schema_validate import validate_document
import test_owasp_universe as universe_fixture


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def admit_universe(case, run_id: str, *, component_map: bool = False) -> dict:
    """T03 over the accepted universe (and the component map as context when published)."""
    request = workbench.lane_in_request(run_id)
    if not component_map:
        request["entries"] = [row for row in request["entries"] if row["kind"] != "component_map"]
    return owasp_lane_in.admit(run_id, workbench._write_request(run_id, "owasp-lane-in-request.json", request))


class OwaspComponentRoutingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.old_runs = execution_state.RUNS
        execution_state.RUNS = Path(self.temporary.name) / "runs"
        self.addCleanup(setattr, execution_state, "RUNS", self.old_runs)
        self.run_id = "freeciv-routing"
        self.run = execution_state.RUNS / self.run_id
        self.data = self.run / "data"
        write_json(self.run / "run-status.json", {"run_id": self.run_id, "status": "READY"})
        self.component_map = self._freeciv_like_map()
        self.component_pointer = self._publish_component(self.component_map)
        self.manifest, self.manifest_path, self.t03_pointer = self._publish_lane_in()

    def _freeciv_like_map(self):
        value = json.loads((PROCESS / "tests/fixtures/component-characterization/hello-autotools.json").read_text())
        value["target"] = "freeciv-like"
        base = deepcopy(value["functional_components"][0])
        specs = [
            ("Freeciv Server", "server", "server", "network-game-server", "deployable", "src/server/**", "src/server/main.c"),
            ("Freeciv Client", "client", "client", "desktop-client", "deployable", "src/client/**", "src/client/main.c"),
            ("Ruleset Loader", "ruleset", "ruleset", "configuration-loader", "linked-runtime", "data/**", "data/default.ruleset"),
            ("Network Protocol", "protocol", "protocol", "network-protocol", "linked-runtime", "common/networking/**", "common/networking/packets.c"),
        ]
        components = []
        for name, alias, group, component_type, deployability, pattern, location in specs:
            row = deepcopy(base)
            row.update(component_id=name.lower().replace(" ", "-"), name=name,
                       coarse_group=group, component_type=component_type, aliases=[alias],
                       search_terms=[alias, name.lower()], path_patterns=[pattern],
                       representative_locations=[location], observed_purpose=f"Implements the {name} subsystem.",
                       trust_boundary_relevance=f"{name} participates in a distinct trust role.",
                       security_control_relevance=f"Review security controls for the {name} subsystem.",
                       deployability=deployability, downstream_lanes=["04-asvs-masvs"],
                       parallel_review_group=group)
            components.append(row)
        value["functional_components"] = components
        value["component_relationships"] = [{
            "relationship_id": "freeciv-client--calls--network-protocol",
            "from_component_id": "freeciv-client", "to_component_id": "network-protocol",
            "relationship_type": "calls", "basis": "Client uses the packet protocol.",
            "confidence": "high", "evidence_citations": deepcopy(base["evidence_citations"]),
        }, {
            "relationship_id": "freeciv-server--depends-on--ruleset-loader",
            "from_component_id": "freeciv-server", "to_component_id": "ruleset-loader",
            "relationship_type": "depends-on", "basis": "Server loads game rules.",
            "confidence": "high", "evidence_citations": deepcopy(base["evidence_citations"]),
        }]
        value["parallel_review_groups"] = [{
            "group_id": group, "component_ids": [component_id],
            "downstream_lanes": ["04-asvs-masvs"], "rationale": f"Independent {group} review partition."
        } for component_id, group in ((row["component_id"], row["parallel_review_group"]) for row in components)]
        citation = deepcopy(base["evidence_citations"])
        value["tag_cloud"] = [
            {"tag": "client", "weight": 50, "component_ids": ["freeciv-client"], "confidence": "high", "evidence_citations": citation},
            {"tag": "configuration", "weight": 40, "component_ids": ["ruleset-loader"], "confidence": "high", "evidence_citations": citation},
            {"tag": "network", "weight": 80, "component_ids": ["network-protocol"], "confidence": "high", "evidence_citations": citation},
            {"tag": "server", "weight": 100, "component_ids": ["freeciv-server"], "confidence": "high", "evidence_citations": citation},
        ]
        value["unknowns"] = [{
            "unknown_id": "client-runtime-surface", "subject": "Client service exposure",
            "question": "Does the client expose a local service?", "impact": "ASVS routing is ambiguous.",
            "affected_component_ids": ["freeciv-client"], "resolution_action": "Inspect runtime configuration.",
            "evidence_citations": citation,
        }]
        value["classification_gaps"] = [{
            "gap_id": "client-runtime-gap", "subject": "Client runtime surface",
            "reason": "Static characterization cannot resolve local service exposure.",
            "routing_impact": "Client control applicability remains cannot_determine.",
            "resolution_action": "Rescope after runtime configuration evidence is admitted."
        }]
        value["rescope_triggers"] = [{
            "trigger_id": "client-runtime-rescope", "condition": "Runtime configuration becomes available.",
            "affected_scope_ids": [], "affected_component_ids": ["freeciv-client"],
            "invalidation_scope": "affected-only", "max_reentry_rounds": 2,
            "required_evidence": ["runtime configuration"], "actions": ["reclassify client surface"]
        }]
        return value

    def _publish_component(self, value):
        base = self.data / "jobs" / routing.COMPONENT_JOB
        attempt_id, fingerprint = "component-1", "sha256:" + "9" * 64
        attempt = base / "attempts" / attempt_id
        attempt.mkdir(parents=True)
        write_json(attempt / "component-purpose-map.json", value)
        (attempt / "component-purpose-map.md").write_text("# Freeciv-like component map\n", encoding="utf-8")
        write_json(attempt / "canonical" / "server-config.json",
                   {"component_id": "freeciv-server", "setting": "static-fixture"})
        mark_attempt_started(base, attempt_id, fingerprint)
        return record_terminal_current(
            base, attempt, run_id=self.run_id, job_id=routing.COMPONENT_JOB,
            dagster_run_id="fixture", worker_kind="persona", output_contract="component-map",
            input_fingerprint=fingerprint, started_at="2026-09-27T00:00:00Z",
            execution_status="OK_WITH_GAPS", summary="fixture", status_record={
                "process": routing.COMPONENT_JOB, "status": "OK_WITH_GAPS", "budget": "fixture",
                "persona_id": "developer-engineer", "role_id": "component-characterizer",
                "domain_id": "component-characterization", "tooling_profile_id": "component-evidence-router",
                "artifacts_read": [], "classification_gaps": 1},
            artifact_paths=["component-purpose-map.json", "component-purpose-map.md",
                            "canonical/server-config.json", "status.json"],
            gaps=["client runtime surface unknown"])

    def _publish_lane_in(self):
        asvs_root = next((ROOT / "data/reference/owasp/owasp_asvs/5.0.0").iterdir())
        reference_path = asvs_root / "manifest.json"
        reference = json.loads(reference_path.read_text())
        component_attempt = self.component_pointer["attempt_id"]
        component_path = self.data / "jobs" / routing.COMPONENT_JOB / "attempts" / component_attempt / "component-purpose-map.json"
        pointer_path = self.data / "jobs" / routing.COMPONENT_JOB / "accepted.json"
        selection = {
            "schema": "appsec-review/standard-selection/1.0", "selection_id": "selection-freeciv",
            "engagement_id": self.run_id,
            "selections": [{"family": "owasp_asvs", "snapshot_id": asvs_root.name,
                            "manifest_sha256": sha(reference_path), "edition": "5.0.0",
                            "enabled_scope": ["server"], "profile_or_level": "L2", "tailoring": []}],
            "approver": "engagement-lead", "approved_at": "2026-09-27T00:00:00Z",
        }
        entry = {
            "input_id": "component-map", "evidence_class": "derived_intelligence", "kind": "component_map",
            "admission": "accepted_run_output", "artifact": {
                "path": component_path.relative_to(self.data).as_posix(), "sha256": sha(component_path)},
            "producer": {"job_id": routing.COMPONENT_JOB, "attempt_id": component_attempt,
                         "accepted_pointer_path": pointer_path.relative_to(self.data).as_posix(),
                         "accepted_pointer_sha256": sha(pointer_path)},
            "source_artifacts": [{"path": component_path.relative_to(self.data).as_posix(), "sha256": sha(component_path)}],
            "source_snapshot": {"snapshot_id": self.component_map["source_snapshot_sha256"],
                                "captured_at": "2026-09-27T00:00:00Z"},
            "derivation_status": "complete", "freshness": {"assessed_at": "2026-09-27T00:00:00Z", "status": "current"},
            "redaction_status": "not_required", "caveats": ["Classification is routing context, not proof."],
            "use": "locator_only", "admission_validated": True, "may_support_control_status": False,
        }
        manifest = {
            "schema": "appsec-review/owasp-input-manifest/1.0", "run_id": self.run_id,
            "selection_id": selection["selection_id"], "selection": selection, "input_fingerprint": "8" * 64,
            "admitted_at": "2026-09-27T00:00:00+00:00",
            "permissions": {"static_inspection": True, "dynamic_execution": False,
                            "manual_observation": False, "network_access": False, "target_mutation": False},
            "reference_snapshots": [{"family": "owasp_asvs", "edition": "5.0.0", "profile_or_level": "L2",
                                     "snapshot_id": asvs_root.name,
                                     "manifest_path": reference_path.relative_to(ROOT).as_posix(),
                                     "manifest_sha256": sha(reference_path), "manifest": reference}],
            "entries": [entry], "nvd": None, "gaps": [], "claim_limits": ["Applicability input only."],
        }
        base = self.data / "jobs" / routing.LANE_IN_JOB / "whole"
        attempt_id = "lane-in-1"
        manifest_path = base / "attempts" / attempt_id / "outputs" / "owasp-input-manifest.json"
        write_json(manifest_path, manifest)
        pointer = base / "accepted.json"
        write_json(pointer, {"status": "OK", "run_id": self.run_id, "job_id": routing.LANE_IN_JOB,
                             "attempt_id": attempt_id, "input_fingerprint": "8" * 64,
                             "selection_id": selection["selection_id"],
                             "artifacts": {"outputs/owasp-input-manifest.json": sha(manifest_path)}})
        write_json(base / "latest.json", {"attempt_id": attempt_id})
        return manifest, manifest_path, pointer

    def _republish(self, edit):
        edit(self.component_map)
        for path in (self.data / "jobs").iterdir():
            __import__("shutil").rmtree(path)
        self.component_pointer = self._publish_component(self.component_map)
        self.manifest, self.manifest_path, self.t03_pointer = self._publish_lane_in()
        pointer = routing.run(self.run_id)
        request_path = routing.request_path(self.run_id, pointer)
        result = owasp_applicability.build(self.run_id, request_path)
        model_path = (self.data / "jobs" / owasp_applicability.JOB_ID / "whole" / "attempts" /
                      result["attempt_id"] / "outputs" / "owasp-applicability-model.json")
        return json.loads(request_path.read_text()), json.loads(model_path.read_text())


class UniverseProjectionTests(unittest.TestCase):
    def setUp(self):
        universe_fixture.isolated_runs(self)
        self.run_id = "universe-routing"

    def project(self, **fixture):
        self.fixture = universe_fixture.UniverseRun(self, self.run_id, **fixture)
        self.fixture.publish()
        admit_universe(self, self.run_id)
        pointer = routing.run(self.run_id)
        request_path = routing.request_path(self.run_id, pointer)
        self.request_path = request_path
        return pointer, json.loads(request_path.read_text()), json.loads(request_path.with_name(routing.ROUTING).read_text())

    def model(self, request_path):
        result = owasp_applicability.build(self.run_id, request_path)
        path = (self.fixture.data / "jobs" / owasp_applicability.JOB_ID / "whole" / "attempts" / result["attempt_id"] /
                "outputs" / "owasp-applicability-model.json")
        return result, json.loads(path.read_text())

    def test_every_chapter_is_projected_once_and_t04_rows_follow_its_control_scope(self):
        pointer, request, route = self.project()
        self.assertEqual(pointer["status"], "OK")
        self.assertEqual(validate_document(request, "owasp-applicability-request.schema.json"), [])
        self.assertEqual(validate_document(route, "owasp-component-routing.schema.json"), [])
        ids = [f"asvs-V{n}" for n in range(1, 18)]
        self.assertEqual(route["component_ids"], ids)
        self.assertEqual([row["control_scope"] for row in request["components"]],
                         [{"domain_ids": [f"V{n}"]} for n in range(1, 18)])
        self.assertEqual((route["expected_target_count"], route["planned_validator_calls"]), (253, 4))
        self.assertNotIn("component_map", request)
        self.assertTrue(all(not rule["selector"]["all_controls"] and len(rule["selector"]["domain_ids"]) == 1
                            for rule in request["rules"]))

        _result, model = self.model(self.request_path)
        per_component = Counter(row["component_id"] for row in model["rows"])
        self.assertEqual({key.removeprefix("asvs-"): value for key, value in per_component.items()},
                         universe_fixture.PER_CHAPTER)
        self.assertEqual(model["counts"]["control_targets"], 253)
        self.assertTrue(all(row["domain_id"] == row["component_id"].removeprefix("asvs-") for row in model["rows"]))
        applicable = Counter(row["domain_id"] for row in model["rows"] if row["applicability_status"] == "applicable")
        self.assertEqual(applicable, {"V1": 27, "V2": 11, "V5": 9, "V16": 16})
        self.assertEqual(model["counts"]["not_applicable"], 253 - 63)
        self.assertEqual(model["counts"]["cannot_determine"], 0)
        participants = next(row for row in model["rows"] if row["domain_id"] == "V5")
        self.assertEqual(participants["component_evidence_input_ids"], ["asvs-participants-V5"])
        self.assertEqual(participants["component_evidence_roots"], ["src/hello.c"])

    def test_universe_gap_stays_cannot_determine_and_visible(self):
        _pointer, request, route = self.project(incomplete=("V3",))
        rule = next(row for row in request["rules"] if row["component_id"] == "asvs-V3")
        self.assertEqual(rule["decision"]["status"], "cannot_determine")
        self.assertEqual([gap["component_id"] for gap in route["gaps"]], ["asvs-V3"])
        _result, model = self.model(self.request_path)
        statuses = {row["applicability_status"] for row in model["rows"] if row["domain_id"] == "V3"}
        self.assertEqual(statuses, {"cannot_determine"})
        self.assertEqual(model["counts"]["cannot_determine"], universe_fixture.PER_CHAPTER["V3"])

    def test_not_applicable_chapter_rule_cites_the_universe_decision(self):
        _pointer, request, _route = self.project()
        rule = next(row for row in request["rules"] if row["component_id"] == "asvs-V3")["decision"]
        self.assertEqual((rule["status"], rule["source_completeness"]), ("not_applicable", "adequate"))
        self.assertEqual([signal["signal_type"] for signal in rule["signals"]], ["positive_exclusion"])
        self.assertEqual([citation["input_id"] for citation in rule["citations"]], ["asvs-universe"])
        applicable = next(row for row in request["rules"] if row["component_id"] == "asvs-V5")["decision"]
        self.assertEqual([citation["input_id"] for citation in applicable["citations"]],
                         ["asvs-participants-V5", "asvs-universe"])

    def test_t04_rejects_a_tampered_projection(self):
        _pointer, request, _route = self.project()
        request["components"][0]["control_scope"] = {"domain_ids": ["V1", "V6"]}
        tampered = self.fixture.run / "inputs" / "tampered-owasp-applicability-request.json"
        write_json(tampered, request)
        with self.assertRaisesRegex(execution_state.Blocked, "not the newest accepted assembler artifact"):
            owasp_applicability.build(self.run_id, tampered)
        manifest = owasp_applicability._load_input_manifest(self.run_id, request["input_manifest"])
        with self.assertRaisesRegex(execution_state.Blocked, "not the exact projection"):
            owasp_applicability._validate_component_binding(self.run_id, request, manifest)

    def test_routing_refuses_without_an_accepted_universe_or_its_admission(self):
        self.fixture = universe_fixture.UniverseRun(self, self.run_id)
        with self.assertRaisesRegex(execution_state.Blocked, "accepted 04-owasp-universe"):
            routing.assemble(self.run_id)
        self.fixture.publish()
        admit_universe(self, self.run_id)
        manifest, _binding = routing._accepted_lane_in(self.run_id)
        universe, binding = owasp_universe.accepted(self.run_id)
        dropped = deepcopy(manifest)
        dropped["entries"] = [row for row in dropped["entries"] if row["input_id"] != "asvs-participants-V5"]
        with self.assertRaisesRegex(execution_state.Blocked, "every participating chapter"):
            routing.admitted_universe(dropped, binding, universe)
        stale = dict(binding, artifact_sha256="0" * 64)
        with self.assertRaisesRegex(execution_state.Blocked, "exactly the newest accepted 04-owasp-universe"):
            routing.admitted_universe(manifest, stale, universe)

    def test_keyword_routing_is_gone(self):
        for name in ("_family_match", "_local_only", "_tokens", "NON_WEB_NA_DOMAINS", "LOCAL_KINDS", "NETWORK_TRAITS"):
            self.assertFalse(hasattr(routing, name), name)
        self.assertNotIn('"all_controls": True', Path(routing.__file__).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
