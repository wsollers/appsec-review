"""Lane 14 lifecycle workers: publish, reuse, skip and tamper, with canned pool merges (no model,
no Dagster, no container). The composer and refuter replies go through the real derive steps and
the real deterministic merge."""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import attack_chain_composition as composition
import attack_chain_derive as compose
import attack_chain_pool as chain_pool
import attack_chain_refutation as refutation
import attack_chain_refute as refute
import execution_state
from execution_state import Blocked
from review_control_loops import deterministic_merge
from schema_validate import validate_document
from tests.test_attack_chain_derive import COMPOSER, two_link_chain
from tests.test_attack_chain_pool import MODEL
from tests.test_attack_chain_seeds import FIXTURE, claim, verification

RUN = "r1"
SOURCE = "sha256:" + "2" * 64


def upstreams(doc=None, budget="standard", blue_status="SURVIVING") -> dict:
    doc = doc or FIXTURE["verification"]
    blue = {"reviews": [{"claim_id": row["claim_id"], "status": blue_status} for row in doc["verifications"]]}
    binding = {"job_id": "09-independent-verification", "attempt_id": "v1", "pointer_sha256": "sha256:" + "5" * 64,
               "artifact_path": "independent-verification.json", "artifact_sha256": "sha256:" + "4" * 64}
    other = {"attempt_id": "x1", "artifact_path": "a.json", "artifact_sha256": "sha256:" + "3" * 64,
             "accepted_pointer_sha256": "sha256:" + "3" * 64}
    return {"verification": doc, "blue": blue, "threat_model": {**FIXTURE["threat_model"], "budget_class": budget},
            "component_map": FIXTURE["component_map"],
            "bindings": {"verification": binding, "blue": {**binding, "job_id": "08-blue-team-refutation"},
                         "threat_model": {**other, "job_id": "03-threat-model-dfd-stride"},
                         "component_map": {**other, "job_id": "01-component-characterization"}},
            "accepted_at": "2026-09-29T00:00:00Z"}


def composition_inputs(ups=None) -> dict:
    ups = ups or upstreams()
    planned = composition.plan(RUN, ups, {}, FIXTURE["cpg_records"], FIXTURE["ir_facts"],
                               copy.deepcopy(FIXTURE["artifacts"]), composition.bound_values())
    return {"run_id": RUN, "source_generation": SOURCE, "bindings": ups["bindings"],
            "budget_class": planned["budget_class"], "seeds": planned["seeds"], "evidence_menu": {},
            "spec": {"schema": "test-spec"}, "accepted_at": "2026-09-29T00:00:00Z",
            "applicability": "APPLICABLE" if planned["seeds"]["clusters"] else "SKIPPED_NA_NO_CHAIN_SEEDS",
            "code": composition._code_hashes()}


def merge_for(rows: list[tuple[str, dict]]) -> dict:
    expected, results = [], []
    for index, (producer, document) in enumerate(rows):
        worker = f"w{index}"
        expected.append({"worker_id": worker, "producer_id": producer, "run_id": RUN})
        results.append({"worker_id": worker, "producer_id": producer, "run_id": RUN, "status": "OK",
                        "candidates": document["candidates"]})
    return deterministic_merge(RUN, expected, results)


LAUNCHED = SimpleNamespace(pool_directory="pool-1", outcome="COMPLETE", instance_count=1,
                           expansion_sha256="sha256:" + "6" * 64, terminal_manifest_sha256="sha256:" + "7" * 64)


class Harness(unittest.TestCase):
    """Temporary run root, pool/model stubs and the canned composition run (no tests of its own)."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        base = Path(self.folder.name).resolve()
        self.patches = [mock.patch.object(execution_state, "RUNS", base / "runs"),
                        mock.patch.object(chain_pool.pool_specification, "spec_sha256", return_value="sha256:" + "8" * 64),
                        mock.patch.object(chain_pool, "context", return_value=SimpleNamespace()),
                        mock.patch.object(chain_pool.model_versions, "model_identity_for", return_value=MODEL),
                        mock.patch.object(composition, "_budget_usd", return_value=2.0),
                        mock.patch.object(refutation, "_budget_usd", return_value=2.0)]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.folder.cleanup()

    def compose(self, inputs, merge):
        with mock.patch.object(composition, "prepare", return_value=inputs), \
                mock.patch.object(chain_pool, "dispatch", return_value=(merge, LAUNCHED)) as dispatch:
            first = composition.run(RUN, "dagster-1")
            second = composition.run(RUN, "dagster-2")
        return first, second, dispatch

    def composer_merge(self, inputs, reply):
        workspace = inputs["seeds"]["clusters"][0]
        document, _ = compose.derive(workspace, reply, composer=COMPOSER)
        return merge_for([("attack-chain-composer", compose.candidates(document, "sha256:" + "a" * 64))])


class WorkerTests(Harness):
    def test_composition_publishes_reuses_and_refutation_publishes_a_supported_chain(self):
        inputs = composition_inputs()
        merge = self.composer_merge(inputs, {"chains": [two_link_chain()]})
        first, second, dispatch = self.compose(inputs, merge)
        self.assertEqual(first["status"], "OK")
        self.assertEqual(second["attempt_id"], first["attempt_id"])
        self.assertEqual(dispatch.call_count, 1)
        attempt = composition.root(RUN) / "attempts" / first["attempt_id"]
        result = json.loads((attempt / composition.RESULT).read_text())
        self.assertEqual(validate_document(result, composition.RESULT_SCHEMA), [])
        self.assertEqual(len(result["chains"]), 1)
        self.assertEqual(result["chains"][0]["state"], "plausible")
        chain_id = result["chains"][0]["chain_id"]

        loaded = refutation.load_composition(RUN)
        self.assertEqual(loaded["result"], result)
        refuter_inputs = refutation.prepare(RUN)
        self.assertEqual([len(batch["chains"]) for batch in refuter_inputs["batches"]], [1])
        outcome, _ = refute.derive(refuter_inputs["batches"][0], {"chains": [{"chain_id": chain_id, "disposition": "holds"}]},
                                   refuter={"job_id": refutation.JOB, "attempt_id": "c", "persona_id": "attack-chain-refuter",
                                            "request_sha256": None})
        merge = merge_for([("attack-chain-refuter", refute.candidates(outcome, "sha256:" + "b" * 64))])
        with mock.patch.object(chain_pool, "dispatch", return_value=(merge, LAUNCHED)):
            published = refutation.run(RUN, "dagster-3")
        self.assertEqual(published["status"], "OK")
        ledger = json.loads((refutation.root(RUN) / "attempts" / published["attempt_id"] / refutation.RESULT).read_text())
        self.assertEqual([chain["state"] for chain in ledger["chains"]], ["supported"])
        self.assertEqual(ledger["verification_pointer_sha256"], "sha256:" + "5" * 64)
        self.assertEqual(ledger["claim_ledger_head_sha256"], FIXTURE["verification"]["ledger_head_sha256"])
        refute.verify_ledger(ledger)

    def test_failed_composer_cell_is_a_gap_and_the_job_still_publishes(self):
        inputs = composition_inputs()
        merge = deterministic_merge(RUN, [{"worker_id": "w0", "producer_id": "attack-chain-composer", "run_id": RUN}], [])
        first, _second, _dispatch = self.compose(inputs, merge)
        self.assertEqual(first["status"], "OK_WITH_GAPS")
        result = json.loads((composition.root(RUN) / "attempts" / first["attempt_id"] / composition.RESULT).read_text())
        self.assertEqual([gap["reason"] for gap in result["gaps"]], ["composer-failed"])

    def test_no_seeds_publishes_skipped_and_refutation_passes_it_through(self):
        ups = upstreams(verification(claim("claim-p2", status="UNRESOLVED", tier="P2")))
        inputs = composition_inputs(ups)
        self.assertEqual(inputs["seeds"]["skip_reason"], "not-applicable-no-chain-seeds")
        with mock.patch.object(composition, "prepare", return_value=inputs), \
                mock.patch.object(chain_pool, "dispatch") as dispatch:
            first = composition.run(RUN, "dagster-1")
        self.assertEqual(dispatch.call_count, 0)
        self.assertEqual((first["status"], first.get("reason")), ("SKIPPED", "not-applicable-no-chain-seeds"))
        pointer = json.loads((composition.root(RUN) / "accepted.json").read_text())
        self.assertEqual((pointer["status"], pointer["reason"]), ("SKIPPED", "not-applicable-no-chain-seeds"))
        with mock.patch.object(chain_pool, "dispatch") as dispatch:
            passed = refutation.run(RUN, "dagster-2")
        self.assertEqual(dispatch.call_count, 0)
        self.assertEqual(passed["status"], "SKIPPED")
        ledger = json.loads((refutation.root(RUN) / "attempts" / passed["attempt_id"] / refutation.RESULT).read_text())
        self.assertEqual(validate_document(ledger, refute.LEDGER_SCHEMA), [])
        self.assertEqual(ledger["chains"], [])

    def test_tampered_composition_blocks_refutation(self):
        inputs = composition_inputs()
        first, _second, _dispatch = self.compose(inputs, self.composer_merge(inputs, {"chains": [two_link_chain()]}))
        path = composition.root(RUN) / "attempts" / first["attempt_id"] / composition.RESULT
        value = json.loads(path.read_text())
        value["chains"][0]["state"] = "supported"
        path.write_text(json.dumps(value))
        with self.assertRaises(Blocked):
            refutation.prepare(RUN)
        with self.assertRaises(Blocked):
            refutation.run(RUN, "dagster-4")


class PlanTests(unittest.TestCase):
    def test_narrowed_comes_from_08_surviving_and_09_blocked(self):
        doc = verification(claim("claim-000000000000000000case01", status="BLOCKED"))
        self.assertEqual(composition.ledger_states(doc, upstreams(doc)["blue"]),
                         {"claim-000000000000000000case01": "narrowed"})
        self.assertEqual(composition.ledger_states(doc, upstreams(doc, blue_status="UNRESOLVED")["blue"]), {})

    def test_probe_budget_keeps_one_cluster(self):
        records, rows = [], []
        base = FIXTURE["cpg_records"][0]
        for index in range(3):
            path = f"projects/cpp/case-00{index + 2}/main.cpp"
            for kind, name, line, label in (("symbol", "main", 1, "METHOD"), ("identifier", "argv", 2, "IDENTIFIER")):
                rid = f"cpg_{kind[0]}{index}".ljust(28, "0")
                rows.append({**base, "record_id": rid, "kind": kind, "name": name, "full_name": name, "label": label,
                             "source_path": path, "start_line": line, "end_line": line,
                             "locator": {**base["locator"], "record_id": rid, "source_path": path, "line": line}})
            records.append(claim(f"claim-{index}", path=path, line=3))
        ups = upstreams(verification(*records), budget="probe")
        planned = composition.plan(RUN, ups, {}, rows, None, {}, composition.bound_values())
        self.assertEqual(len(planned["seeds"]["clusters"]), 1)
        self.assertEqual([gap["detail"] for gap in planned["seeds"]["gaps"] if gap["reason"] == "cluster-cap"],
                         ["probe budget: one composer cell per run"] * 2)

    def test_native_facts_are_read_from_the_pinned_menu_files_and_checked(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            with mock.patch.object(execution_state, "RUNS", base / "runs"):
                jobs = execution_state.data_path(RUN, "jobs")
                target = jobs / "02-code-property-graph/attempts/c1/code-property-graph.records.jsonl"
                target.parent.mkdir(parents=True)
                target.write_text("\n".join(json.dumps(row) for row in FIXTURE["cpg_records"]) + "\n")
                sha = "sha256:" + execution_state.file_hash(target)
                menu = {"items": [{"item_id": "02-code-property-graph", "status": "AVAILABLE", "files": [
                    {"path": "02-code-property-graph/attempts/c1/code-property-graph.records.jsonl", "sha256": sha}]}]}
                records, ir, artifacts = composition.native_facts(RUN, menu)
                self.assertEqual(records, FIXTURE["cpg_records"])
                self.assertIsNone(ir)
                self.assertEqual(artifacts["02-code-property-graph"]["sha256"], sha)
                target.write_text("tampered\n")
                with self.assertRaises(Blocked):
                    composition.native_facts(RUN, menu)


if __name__ == "__main__":
    unittest.main()
