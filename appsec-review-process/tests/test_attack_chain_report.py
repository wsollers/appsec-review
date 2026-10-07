"""Report projection of lane 14 (ADR-0016 decision 9): published, skipped, absent and tampered ledgers."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import attack_chain_composition as composition
import attack_chain_pool as chain_pool
import attack_chain_refutation as refutation
import attack_chain_refute as refute
import attack_chain_report as chain_report
import execution_state
from execution_state import Blocked
from tests.test_attack_chain_derive import CLAIM, two_link_chain
from tests.test_attack_chain_seeds import FIXTURE, claim, verification
from tests.test_attack_chain_workers import LAUNCHED, RUN, Harness, composition_inputs, merge_for, upstreams


def report(**changes) -> dict:
    value = {"run_id": RUN, "ledger_head_sha256": FIXTURE["verification"]["ledger_head_sha256"],
             "verified_findings": [{"claim_id": CLAIM, "title": "strcpy into a 16-byte stack buffer", "severity": "HIGH"}],
             "unresolved_candidates": []}
    value.update(changes)
    return value


class ReportTests(Harness):
    def run_root(self) -> Path:
        return execution_state.run_path(RUN)

    def publish(self, disposition="holds"):
        inputs = composition_inputs()
        first, _second, _dispatch = self.compose(inputs, self.composer_merge(inputs, {"chains": [two_link_chain()]}))
        chain_id = json.loads((composition.root(RUN) / "attempts" / first["attempt_id"] /
                               composition.RESULT).read_text())["chains"][0]["chain_id"]
        batch = refutation.prepare(RUN)["batches"][0]
        reply = {"chain_id": chain_id, "disposition": disposition}
        if disposition == "broken":
            reply.update(target={"kind": "edge", "index": 0}, mechanism="argv is length-checked",
                         citation_ids=["02-code-property-graph#cpg_a01000000000000000000000"])
        outcome, _ = refute.derive(batch, {"chains": [reply]}, refuter=None)
        merge = merge_for([("attack-chain-refuter", refute.candidates(outcome, "sha256:" + "b" * 64))])
        with mock.patch.object(chain_pool, "dispatch", return_value=(merge, LAUNCHED)):
            return refutation.run(RUN, "dagster-3")

    def test_published_chain_is_ranked_labelled_and_never_a_finding(self):
        self.publish()
        section = chain_report.build(report(), self.run_root())
        self.assertEqual((section["status"], section["refuted_count"]), ("PUBLISHED", 0))
        chain = section["chains"][0]
        self.assertEqual((chain["rank"], chain["state"], chain["impact_kind"]), (1, "supported", "code_execution"))
        self.assertEqual([link["stage"] for link in chain["links"]], ["entry", "impact"])
        self.assertEqual(chain["links"][1]["label"], "strcpy into a 16-byte stack buffer")
        self.assertEqual(chain["links"][1]["severity"], "HIGH")
        self.assertIn("argv read in main", chain["links"][0]["label"])
        self.assertEqual(chain["edges"][0]["basis"], "code_fact")
        self.assertIn("never a verified finding", section["note"])
        self.assertEqual(chain_report.build(report(), self.run_root(), reported_max=0)["appendix"][0]["chain_id"],
                         chain["chain_id"])

    def test_refuted_chain_is_counted_not_listed(self):
        self.publish("broken")
        section = chain_report.build(report(), self.run_root())
        self.assertEqual((section["chains"], section["refuted_count"]), ([], 1))
        self.assertEqual(section["reason"], "the lane published no surviving chain")

    def test_chain_citing_a_claim_the_report_lacks_is_a_gap(self):
        self.publish()
        section = chain_report.build(report(verified_findings=[]), self.run_root())
        self.assertEqual(section["chains"], [])
        self.assertTrue(any("the report does not carry" in gap for gap in section["gaps"]))

    def test_absent_and_skipped_lanes(self):
        section = chain_report.build(report(), self.run_root())
        self.assertEqual(section["status"], "ABSENT")
        self.assertTrue(section["gaps"])
        ups = upstreams(verification(claim("claim-p2", status="UNRESOLVED", tier="P2")))
        with mock.patch.object(composition, "prepare", return_value=composition_inputs(ups)):
            composition.run(RUN, "dagster-1")
        refutation.run(RUN, "dagster-2")
        section = chain_report.build(report(), self.run_root())
        self.assertEqual((section["status"], section["reason"]), ("SKIPPED", "not-applicable-no-chain-seeds"))
        self.assertEqual(section["gaps"], [])

    def test_tampered_ledger_blocks(self):
        published = self.publish()
        path = refutation.root(RUN) / "attempts" / published["attempt_id"] / refutation.RESULT
        value = json.loads(path.read_text())
        value["chains"][0]["state"] = "plausible"
        path.write_text(json.dumps(value))
        with self.assertRaises(Blocked):
            chain_report.build(report(), self.run_root())

    def test_other_claim_ledger_head_blocks(self):
        self.publish()
        with self.assertRaises(Blocked):
            chain_report.build(report(ledger_head_sha256="sha256:" + "0" * 64), self.run_root())


    def test_lifecycle_origin_head_is_accepted_beside_the_final_head(self):
        """Run 20261006T220018Z-7e69f0: lane 14 binds the L01 (lifecycle-origin) head because it runs before
        claim-ledger-final; the report's own head is the final one, so only the origin head matches."""
        self.publish()
        origin = FIXTURE["verification"]["ledger_head_sha256"]
        final = report(ledger_head_sha256="sha256:" + "0" * 64)
        section = chain_report.build(final, self.run_root(), origin_head_sha256=origin)
        self.assertEqual(section["status"], "PUBLISHED")
        with self.assertRaisesRegex(Blocked, "different claim-ledger head"):
            chain_report.build(final, self.run_root(), origin_head_sha256="sha256:" + "1" * 64)

class PresentationTests(unittest.TestCase):
    def test_renderer_section_projection(self):
        import synthesis_report_presentation as presentation
        self.assertEqual(presentation._attack_chains(None)["status"], "ABSENT")
        section = {"schema": chain_report.SCHEMA, "run_id": RUN, "status": "SKIPPED",
                   "reason": "not-applicable-no-chain-seeds", "binding": None, "chains": [], "appendix": [],
                   "refuted_count": 0, "coverage": {}, "gaps": [], "note": chain_report.NOTE}
        self.assertEqual(presentation._attack_chains(section),
                         {"status": "SKIPPED", "reason": "not-applicable-no-chain-seeds", "chains": [], "appendix": [],
                          "refuted_count": 0, "note": chain_report.NOTE})

    def test_worker_pins_the_lane_14_report_module(self):
        import synthesis_report_worker as worker
        self.assertIn("attack_chain_report.py", worker.CODE_FILES)
        self.assertIn(chain_report.RESULT, worker.ARTIFACTS)


if __name__ == "__main__":
    unittest.main()
