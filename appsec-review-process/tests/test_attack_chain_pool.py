"""Lane 14 persona pools with a stub invoker (no live model call): request shape, one cell per
cluster, repair round-trip, cell failure as a gap, refuter batches."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import registry_paths

import attack_chain_derive as compose
import attack_chain_pool as pool
import attack_chain_refute as refute
import claude_cli_invoker as cli
import execution_state
import persona_dispatch
import supporting_evidence_menu as evidence_menu
from claude_cli_invoker import InvokerOutputError
from review_control_loops import deterministic_merge
from schema_validate import validate_document
from tests.test_attack_chain_derive import CLAIM, COMPOSER, run, two_link_chain, workspace
from tests.test_attack_chain_refute import REFUTER, batch_for

MODEL = {"provider": "anthropic", "family": "claude-sonnet-5", "model_id": "claude-sonnet-5-20260927",
         "snapshot": "claude-sonnet-5-20260927"}


def item(root: str, path: str, data: bytes) -> SimpleNamespace:
    return SimpleNamespace(root=root, path=path, sha256="sha256:" + hashlib.sha256(data).hexdigest(), data=data,
                           role="evidence")


def package(kind: str, document: dict) -> SimpleNamespace:
    template = pool.COMPOSER_TEMPLATE if kind == "compose" else pool.REFUTER_TEMPLATE
    root = compose.WORKSPACE_ROOT_ID if kind == "compose" else refute.BATCH_ROOT_ID
    key = "cluster_id" if kind == "compose" else "batch_id"
    contract = json.loads((registry_paths.contract("attack-chain-candidates")).read_text())
    job = "14-attack-chain-composition" if kind == "compose" else "14-attack-chain-refutation"
    persona = "attack-chain-composer" if kind == "compose" else "attack-chain-refuter"
    return SimpleNamespace(composition={"output_contract": contract}, prompt=b"OUTER",
        inputs=(item(root, document[key] + ".json", compose.workspace_bytes(document)),),
        request={"model": {"family": "claude-sonnet-5"}, "run_id": "r1", "job_id": job, "attempt_id": "a" * 32,
                 "persona": {"persona_id": persona}, "budget": {"input_unit_limit": 10 ** 9}},
        request_sha256="sha256:" + "4" * 64, allowed_claim_classes=("candidate_only",), template=template)


def invoke(kind: str, document: dict, replies: list[str]):
    prompts, written = [], {}

    def dispatch_fn(argv, prompt, timeout_seconds, transcript_path):
        prompts.append(prompt)
        return {"timed_out": False, "final_result": {"result": replies.pop(0)}}

    with tempfile.TemporaryDirectory() as out, \
            mock.patch.object(cli.cbr, "resolve_claude_binary", return_value="/usr/bin/claude"), \
            mock.patch.object(cli.rc, "load_model_config", return_value={"invocation": {"repair_attempts": 1}}), \
            mock.patch.object(cli.pi, "write_invoker_output", side_effect=lambda package, root, **kw: written.update(kw)):
        pool.ChainInvoker(kind, effort="high", budget_usd=2.0, dispatch_fn=dispatch_fn).invoke(
            package(kind, document), output_root=Path(out), cancel=threading.Event())
        published = json.loads((Path(out) / "candidates.json").read_text())
    return published, prompts, written


class InvokerTests(unittest.TestCase):
    def test_composer_repair_round_trip_on_an_unknown_claim_id(self):
        ws = workspace()
        bad = two_link_chain()
        bad["links"][1]["claim_id"] = "claim-invented"
        replies = [json.dumps({"candidates": {"chains": [bad]}}),
                   "```json\n" + json.dumps({"candidates": {"chains": [two_link_chain()]}}) + "\n```"]
        published, prompts, written = invoke("compose", ws, replies)
        self.assertEqual(len(prompts), 2)
        self.assertIn("is not a claim of this workspace", prompts[1])
        self.assertIn(compose.PERSONA_SCHEMA, prompts[0])
        self.assertIn("Trusted attack-chain runtime", prompts[0])
        self.assertEqual(validate_document(published, compose.CANDIDATES_SCHEMA), [])
        chain = json.loads(published["candidates"][0]["assertion"])
        self.assertEqual(chain["composer"]["persona_id"], "attack-chain-composer")
        self.assertEqual(chain["causal_claim_ids"], [CLAIM])
        self.assertEqual(written["claims"][0]["citations"][0]["root"], compose.WORKSPACE_ROOT_ID)

    def test_refuter_cell_derives_outcomes(self):
        ws = workspace()
        document, _ = run({"chains": [two_link_chain()]}, ws)
        batches, _ = batch_for(ws, document["chains"])
        reply = {"candidates": {"chains": [{"chain_id": document["chains"][0]["chain_id"], "disposition": "holds"}]}}
        published, prompts, _ = invoke("refute", batches[0], [json.dumps(reply)])
        self.assertIn("weakest", prompts[0])
        self.assertIn("the sink looks safe", prompts[0])
        outcome = json.loads(published["candidates"][0]["assertion"])
        self.assertEqual((outcome["disposition"], outcome["refuter"]["persona_id"]), ("holds", "attack-chain-refuter"))


class SpecTests(unittest.TestCase):
    def test_one_cell_per_cluster_with_the_workspace_as_input_zero(self):
        ws = workspace()
        second = copy.deepcopy(ws)
        second["cluster_id"] = "cluster-" + "f" * 16
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            with mock.patch.object(execution_state, "RUNS", base / "runs"), \
                    mock.patch.object(pool.model_versions, "model_identity_for", return_value=MODEL):
                menu = evidence_menu.build("r1", "14-attack-chain-composition", [], jobs_root=base / "nojobs")
                permission = persona_dispatch._permission_block("14-attack-chain-composition", run_id="r1",
                    source_snapshot_sha256="sha256:" + "2" * 64, now="2026-09-29T00:00:00Z")
                spec = pool.pool_spec("r1", "14-attack-chain-composition", "compose", [ws, second], menu=menu,
                                      permission=permission, binding={"x": 1}, rendezvous_timeout_seconds=5400)
                attempt = base / "attempt"; attempt.mkdir()
                context = pool.context("r1", "compose", [ws, second], menu=menu, spec=spec, attempt=attempt,
                                       source_snapshot_sha256="sha256:" + "2" * 64)
                plan = pool.pool_specification.plan_expansion(spec, context=context)
                empty = pool.pool_spec("r1", "14-attack-chain-refutation", "refute", [], menu=menu,
                                       permission=permission, binding={"x": 1}, rendezvous_timeout_seconds=5400)
        self.assertEqual(len(plan.instances), 2)
        readable = plan.instances[0].request.request["readable_inputs"]
        self.assertEqual(readable[0]["root"], compose.WORKSPACE_ROOT_ID)
        self.assertIn(readable[0]["path"], {ws["cluster_id"] + ".json", second["cluster_id"] + ".json"})
        self.assertEqual(plan.instances[0].request.request["persona"]["persona_id"], "attack-chain-composer")
        self.assertEqual(spec["pool_budget"]["max_instances"], 2)
        self.assertEqual((empty["worker_groups"][0]["count"], empty["empty_pool_reason"]), (0, "no_applicable_work"))
        self.assertEqual(empty["worker_groups"][0]["persona_request"]["persona"]["persona_id"], "attack-chain-refuter")


def merge_of(results: dict[str, list[dict]], missing=("w9",)) -> dict:
    expected = [{"worker_id": worker, "producer_id": "attack-chain-composer", "run_id": "r1"}
                for worker in list(results) + list(missing)]
    rows = [{"worker_id": worker, "producer_id": "attack-chain-composer", "run_id": "r1", "status": "OK",
             "candidates": candidates} for worker, candidates in results.items()]
    return deterministic_merge("r1", expected, rows)


class CollectTests(unittest.TestCase):
    def test_failed_cell_is_a_gap_not_an_exception_and_no_chain_is_recorded(self):
        ws = workspace()
        synthetic = two_link_chain()
        synthetic["edges"][0].update(basis_claimed="synthetic", fact_ref=None)
        document, _ = run({"chains": [synthetic]}, ws)
        other = copy.deepcopy(ws); other["cluster_id"] = "cluster-" + "e" * 16
        silent = copy.deepcopy(ws); silent["cluster_id"] = "cluster-" + "d" * 16
        none_doc, _ = compose.derive(other, {"chains": [], "no_chain_reason": "no path from argv"}, composer=COMPOSER)
        merge = merge_of({"w0": compose.candidates(document, "sha256:" + "a" * 64)["candidates"],
                          "w1": compose.candidates(none_doc, "sha256:" + "b" * 64)["candidates"]})
        seeds = {"clusters": [ws, other, silent]}
        chains, gaps, coverage = pool.collect_composition(seeds, merge)
        self.assertEqual([chain["chain_id"] for chain in chains], [document["chains"][0]["chain_id"]])
        self.assertEqual(sorted((gap["reason"], gap["id"]) for gap in gaps),
                         sorted([("composer-failed", silent["cluster_id"]),
                                 ("composer-no-chain", other["cluster_id"]),
                                 ("synthetic-edge", chains[0]["chain_id"])]))
        self.assertEqual(coverage, {"clusters_selected": 3, "clusters_answered": 2, "clusters_no_chain": 1,
                                    "clusters_failed": 1, "chains_composed": 1})

    def test_refuter_cell_failure_caps_the_chains(self):
        ws = workspace()
        document, _ = run({"chains": [two_link_chain()]}, ws)
        batches, _ = batch_for(ws, document["chains"])
        outcomes, reasons, gaps = pool.collect_refutation(batches, merge_of({}, missing=("w0",)))
        chain_id = document["chains"][0]["chain_id"]
        self.assertEqual((outcomes, list(reasons)), ({}, [chain_id]))
        self.assertEqual(gaps[0]["reason"], "refuter-failed")
        published, dropped = refute.apply(document["chains"], outcomes, reasons)
        self.assertEqual((published[0]["state"], dropped), ("plausible", []))

    def test_same_cluster_request_gives_the_same_request_bytes(self):
        # The persona result cache keys each cell on its request hash: an unchanged cluster reuses its reply.
        self.assertEqual(compose.workspace_bytes(workspace()), compose.workspace_bytes(workspace()))

    def test_code_hashes_cover_the_lane_files(self):
        hashes = pool.code_hashes()
        for path in ("attack_chain_seeds.py", "attack_chain_derive.py", "attack_chain_refute.py",
                     "personas/personas/attack-chain-refuter/persona.json", "14-attack-chain/task-attack-chain-refutation-cell.md",
                     "schemas/attack-chain-ledger.schema.json"):
            self.assertIn(path, hashes)


if __name__ == "__main__":
    unittest.main()
