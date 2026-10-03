"""Acceptance tests for gap punch list items P39-P40 (docs/TODO/gap-punchlist-hello-autotools-2026-10-03.md)."""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import test_full_review_input_assembly as assembly_tests  # noqa: E402
import test_owasp_component_routing as routing_tests  # noqa: E402
import test_standards_lifecycle as standards_tests  # noqa: E402

import dependency_orchestration  # noqa: E402
import dependency_snapshot_registry  # noqa: E402
import execution_state  # noqa: E402
from execution_state import Blocked, atomic_json, file_hash, read_json  # noqa: E402
import full_review_input_assembly as assembly  # noqa: E402
import owasp_component_routing  # noqa: E402
import owasp_lane_in  # noqa: E402
import standards_lifecycle as lifecycle  # noqa: E402
import vendor_evidence_orchestration as vendor  # noqa: E402

H = standards_tests.H
STAMP = assembly_tests.STAMP
ROUTING_JOB = "04-owasp-component-routing"


def _record(control_id: str, chapter: str, family: str = "owasp_asvs"):
    record = {"standard_family": family, "control_id": control_id, "group": {"chapter_id": chapter},
              "proof_obligations": [{"minimum_evidence_modes": ["static_source"]}]}
    wrapper = {"family": family, "edition": "5.0.0", "record_type": "control", "record_id": control_id,
               "record": record}
    return dict(standards_tests.STANDARD["records"][0], family=family, record_id=control_id), wrapper


def _rule(rule_id, component_id, status, *, domains=(), expression=None):
    return {"rule_id": rule_id, "component_id": component_id,
            "selector": {"standard_family": "owasp_asvs", "control_ids": [], "domain_ids": list(domains),
                         "all_controls": not domains},
            "decision": {"status": status, "rationale": f"{status} by fixture rule.", "signals": [],
                         "citations": [], "source_completeness": "adequate",
                         "conditional_expression": expression}}


def routing_request(component_ids, rules, binding=standards_tests.COMPONENT_BIND):
    return {"component_map": {"attempt_id": binding["attempt_id"],
                              "artifact_sha256": binding["artifact_sha256"].removeprefix("sha256:")},
            "components": [{"component_id": value, "scope_status": "in_scope"} for value in component_ids],
            "rules": rules}


ROUTING_BIND = {"job_id": ROUTING_JOB, "attempt_id": "r1", "artifact_path": "owasp-applicability-request.json",
                "artifact_sha256": H, "accepted_pointer_sha256": H}


class OwaspWorklistRoutingTests(unittest.TestCase):
    """P39: the OWASP worklist takes its targets and applicability from the accepted T04 routing."""
    setup_paths = standards_tests.StandardsLifecycleTests.setup_paths

    def _prepare(self, job_id, component, routed, records):
        def load(_run, spec):
            if spec[0] == lifecycle.COMPONENT[0]: return component, standards_tests.COMPONENT_BIND
            if spec[0] == lifecycle.STANDARDS[0]: return standards_tests.STANDARD, standards_tests.STANDARDS_BIND
            if spec[0] == ROUTING_JOB: return routed, ROUTING_BIND
            raise AssertionError(spec)
        with tempfile.TemporaryDirectory() as folder:
            _run, p1, p2 = self.setup_paths(folder)
            with p1, p2, mock.patch.object(lifecycle, "_load", side_effect=load) as loader, \
                 mock.patch.object(lifecycle, "_record_documents", return_value=records):
                prepared = lifecycle.prepare_worklist("run-a", job_id)
                return prepared, read_json(prepared["request_path"]), [call.args[1][0] for call in loader.call_args_list]

    def _cli_lib(self):
        # Neither component's downstream_lanes names the OWASP lane; routing alone decides.
        component = {"source_snapshot_sha256": H, "functional_components": [
            {"component_id": "cli", "downstream_lanes": ["05-native-memory"]},
            {"component_id": "lib", "downstream_lanes": []}]}
        routed = routing_request(["cli", "lib"], [
            _rule("auto-cli-owasp-asvs-non-web-na", "cli", "not_applicable", domains=["V3"]),
            _rule("auto-lib-owasp-asvs", "lib", "conditional", expression="lib stays local")])
        return component, routed, [_record("V1.1.1", "V1"), _record("V3.1.1", "V3")]

    def test_p39_owasp_rows_carry_routed_applicability(self):
        """P39: CLI web chapters are N/A with their rule, partial is conditional, unmatched is cannot_determine."""
        prepared, request, _loads = self._prepare("04-owasp-validation-worklist", *self._cli_lib())
        rows = {(row["target_id"], row["control_id"]): row for row in request["payload"]["controls"]}
        self.assertEqual(sorted(rows), [("cli", "V1.1.1"), ("cli", "V3.1.1"), ("lib", "V1.1.1"), ("lib", "V3.1.1")],
                         "worklist targets did not come from the accepted OWASP routing")
        na = rows[("cli", "V3.1.1")]
        self.assertEqual(na["applicability"], "not_applicable")
        self.assertIn("auto-cli-owasp-asvs-non-web-na", na["citation_ids"])
        self.assertEqual(na["gaps"], [])
        self.assertEqual(rows[("lib", "V1.1.1")]["applicability"], "conditional")
        self.assertIn("lib stays local", rows[("lib", "V1.1.1")]["tailoring"])
        self.assertEqual(rows[("cli", "V1.1.1")]["applicability"], "cannot_determine")
        self.assertEqual(prepared["target_count"], 2)
        # An N/A row needs no assessment: three rows remain to assess.
        self.assertIn("Control-specific assessment has not been performed for 3 control x component work items.",
                      request["payload"]["gaps"])

    def test_p39_owasp_request_binds_the_accepted_routing(self):
        """P39: the bounded-transform request names the accepted routing so the worker re-verifies its hashes."""
        _prepared, request, loads = self._prepare("04-owasp-validation-worklist", *self._cli_lib())
        self.assertIn(ROUTING_JOB, loads)
        upstream = {row["job_id"]: row for row in request["upstream"]}
        self.assertIn(ROUTING_JOB, upstream, "worklist request does not bind the accepted routing")
        self.assertEqual((upstream[ROUTING_JOB]["contract"], upstream[ROUTING_JOB]["artifact"],
                          upstream[ROUTING_JOB]["schema"]),
                         ("owasp-applicability-request", "owasp-applicability-request.json",
                          "owasp-applicability-request.schema.json"))

    def test_p39_routing_for_another_component_map_is_refused(self):
        """P39: routing derived from a different component-map attempt cannot route this worklist."""
        component, routed, records = self._cli_lib()
        routed = deepcopy(routed); routed["component_map"]["attempt_id"] = "older"
        with self.assertRaisesRegex(Blocked, "different component map"):
            self._prepare("04-owasp-validation-worklist", component, routed, records)

    def test_p39_stig_keeps_downstream_lanes(self):
        """P39: STIG/SRG has no routing equivalent and still routes from downstream_lanes."""
        component = {"source_snapshot_sha256": H, "functional_components": [
            {"component_id": "cli", "downstream_lanes": ["15-deployment-hardening"]},
            {"component_id": "lib", "downstream_lanes": []}]}
        prepared, request, loads = self._prepare("15-stig-srg-validation-worklist", component, None,
                                                 [_record("SRG-APP-1", "V1", family="disa_srg")])
        self.assertNotIn(ROUTING_JOB, loads)
        self.assertEqual([row["target_id"] for row in request["payload"]["controls"]], ["cli"])
        self.assertEqual(prepared["target_count"], 1)

    def test_p39_run_produces_routing_before_the_owasp_worklist(self):
        """P39: the OWASP worklist stage produces (or reuses) T03 and routing before reading the routing."""
        order = []
        prepared = {"request_path": Path("request.json"), "attempt_id": "auto-a", "control_count": 1,
                    "target_count": 1, "generation": H}
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch.object(lifecycle, "data_path", return_value=Path(folder) / "job"), \
             mock.patch("owasp_workbench_lifecycle.lane_in_request", return_value={"fixture": True}), \
             mock.patch("owasp_workbench_lifecycle._write_request", return_value=Path("lane-in.json")), \
             mock.patch.object(owasp_lane_in, "admit", side_effect=lambda *a, **k: order.append("t03")), \
             mock.patch.object(owasp_component_routing, "run", side_effect=lambda *a, **k: order.append("routing")), \
             mock.patch.object(lifecycle, "prepare_worklist", side_effect=lambda *a: order.append("prepare") or prepared), \
             mock.patch("bounded_transform_orchestration.execute"), \
             mock.patch.object(lifecycle, "_publish_bounded", return_value={"attempt_id": "auto-a"}):
            lifecycle.run_worklist("run-a", "dagster-a", "04-owasp-validation-worklist")
        self.assertEqual(order, ["t03", "routing", "prepare"])


class PublishedRoutingTests(unittest.TestCase):
    """P39: the real accepted routing publication loads hash-verified and decides rows exactly as T04 does."""
    _cls = routing_tests.OwaspComponentRoutingTests
    setUp = _cls.setUp
    _freeciv_like_map = _cls._freeciv_like_map
    _publish_component = _cls._publish_component
    _publish_lane_in = _cls._publish_lane_in
    _republish = _cls._republish

    def test_p39_published_routing_matches_t04_rows(self):
        def edit(value):
            row = next(item for item in value["functional_components"] if item["component_id"] == "ruleset-loader")
            row.update(component_type="command-line application", aliases=["cli"], confidence="high")
        _request, model = self._republish(edit)
        _component, component_binding = lifecycle._load(self.run_id, lifecycle.COMPONENT)
        routed = lifecycle._owasp_routing(self.run_id, component_binding)
        observed = {}
        for row in model["rows"]:
            wrapper = {"family": row["standard_family"], "record_id": row["control_id"],
                       "record": {"group": {"chapter_id": row["domain_id"]}}}
            rule = lifecycle._routed_rule(routed, row["component_id"], wrapper)
            self.assertEqual(rule["decision"]["status"] if rule else "cannot_determine", row["applicability_status"])
            observed[row["applicability_status"]] = observed.get(row["applicability_status"], 0) + 1
        self.assertTrue(observed.get("not_applicable") and observed.get("applicable"), observed)


class _Reached(Exception):
    """The orchestrator accepted the request and reached its worker/tool seam."""


class AssembledRequestRoundTripTests(unittest.TestCase):
    """P40: standalone vendor and dependency requests from the assembly pass their orchestrators' validators."""
    _cls = assembly_tests.FullReviewInputAssemblyTests
    setUp = _cls.setUp
    tearDown = _cls.tearDown
    _accepted_fuzz = _cls._accepted_fuzz
    _accepted_component = _cls._accepted_component
    _accepted_build_index = _cls._accepted_build_index
    _plan = _cls._plan
    _assemble = _cls._assemble

    def _patches(self):
        return mock.patch.object(execution_state, "RUNS", self.runs)

    def _execute(self, call):
        try:
            call()
        except _Reached:
            return
        except Blocked as exc:
            self.fail(f"orchestrator refused the assembled request: {exc}")
        self.fail("orchestrator did not reach its worker seam")

    def test_p40_vendor_request_round_trips(self):
        """P40: the secrets request carries source_binding and the probe applicability the orchestrator re-derives."""
        output, _ = self._assemble()
        request = output / "attempts/assembly-1/requests/02-secrets-inventory.json"
        base = self.run / "data/jobs/02-secrets-inventory/whole"
        with self._patches(), mock.patch.object(vendor.WORKERS["02-secrets-inventory"], "build",
                                                side_effect=_Reached):
            self._execute(lambda: vendor.execute(job_id="02-secrets-inventory", run_id="review-1",
                dagster_run_id="dagster-1", input_path=str(request), output_root=str(base),
                attempt_root=str(base / "attempts/full-1"), execution_root=str(base / "executions/full-1")))

    def test_p40_dependency_request_round_trips(self):
        """P40: the SBOM request carries source_binding and targets the accepted source projection."""
        output, _ = self._assemble()
        request = output / "attempts/assembly-1/requests/02-sbom-inventory.json"
        with self._patches(), mock.patch.object(dependency_orchestration.b13, "execute", side_effect=_Reached):
            self._execute(lambda: dependency_orchestration.execute(job_id="02-sbom-inventory",
                run_id="review-1", input_path=str(request), output_root=str(self.run / "data/jobs"),
                attempt_root=str(self.run / "data/jobs/02-sbom-inventory/orchestration-attempts/full-1")))

    def test_p40_sca_request_carries_snapshot_identities_and_round_trips(self):
        """P40: a derived SCA launch binds the exact offline snapshot identities the orchestrator requires."""
        sbom_base = self.run / "data/jobs/02-sbom-inventory"
        sbom = sbom_base / "attempts/sbom-1/outputs/sbom-manifest.json"
        atomic_json(sbom, {"components": []})
        atomic_json(sbom_base / "accepted.json", {"fixture": True})
        registry = Path(self.temp.name) / "registry"; registry.mkdir()
        identity = {"vendor_build": "v", "schema_version": "1", "snapshot_id": "s", "sha256": H,
                    "data_timestamp": STAMP}

        def load(pointer, *, run_id, spec):
            if spec["job_id"] != "02-sbom-inventory": raise AssertionError(spec)
            return {"source_snapshot_sha256": self.generation}, {
                "job_id": spec["job_id"], "attempt_id": "sbom-1", "artifact_path": spec["artifact"],
                "artifact_sha256": "sha256:" + file_hash(sbom), "accepted_pointer_sha256": H}

        environment = {"APPSEC_REVIEW_VULN_SNAPSHOT_REGISTRY": str(registry),
                       "APPSEC_REVIEW_VULN_MAX_AGE_SECONDS": "86400"}
        with mock.patch.dict(os.environ, environment), \
             mock.patch.object(assembly, "_load_dependency_source", side_effect=load), \
             mock.patch.object(dependency_snapshot_registry, "resolve",
                               side_effect=lambda kind, *a, **k: {"database_kind": kind, **identity, "age_seconds": 1}):
            plan = assembly.derive_plan(self._accepted_component(), self.run.absolute(),
                self.run / "inputs/derived-full-review-plan.json", run_id="review-1", generated_at=STAMP)
            launch = next(row for row in plan["launches"] if row["job_id"] == "02-sca-vulnerability-match")
            self.assertEqual(sorted(row["database_kind"] for row in launch["tool"].get("snapshot_identities", [])),
                             ["grype-db", "osv"], "SCA launch lacks exact snapshot identities")
            self.assertEqual(set(launch["tool"]["snapshot_identities"][0]),
                             {"database_kind", "vendor_build", "schema_version", "snapshot_id", "sha256", "data_timestamp"})
            output, _ = self._assemble(self.run / "inputs/derived-full-review-plan.json")
        request = output / "attempts/assembly-1/requests/02-sca-vulnerability-match.json"
        self.assertIn("source_binding", read_json(request))
        with self._patches(), mock.patch.object(dependency_orchestration.b13, "execute_registered",
                                                side_effect=_Reached):
            self._execute(lambda: dependency_orchestration.execute(job_id="02-sca-vulnerability-match",
                run_id="review-1", input_path=str(request), output_root=str(self.run / "data/jobs"),
                attempt_root=str(self.run / "data/jobs/02-sca-vulnerability-match/orchestration-attempts/full-1")))


if __name__ == "__main__":
    unittest.main()
