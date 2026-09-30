"""Lane-12b pool: the real Claude CLI invoker repair loop with fake persona replies (a citation
outside the workspace goes back once and the repaired reply publishes), a denylisted reply is not
re-asked, and the pool specification builds one cell per request from the registry."""
from __future__ import annotations

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

import claude_cli_invoker as cli
import execution_state
import persona_dispatch
import poc_fix_derive as derive
import poc_fix_pool as pool
from schema_validate import validate_document
from tests.test_attack_chain_pool import MODEL
from tests.test_poc_fix_derive import REACH, good_reply, priority, scoring
from tests.test_report_finding_enrichment import write_run
import poc_fix_select as select


def request_workspace() -> dict:
    with tempfile.TemporaryDirectory() as folder:
        write_run(Path(folder))
        return select.select(scoring(priority(REACH, line=9)), Path(folder), findings_max=12, window=20)["requests"][0]


def package(document: dict) -> SimpleNamespace:
    data = derive.workspace_bytes(document)
    contract = json.loads((registry_paths.contract("poc-fix-candidates")).read_text())
    return SimpleNamespace(composition={"output_contract": contract}, prompt=b"OUTER",
        inputs=(SimpleNamespace(root=derive.WORKSPACE_ROOT_ID, path=document["request_id"] + ".json",
                                sha256="sha256:" + hashlib.sha256(data).hexdigest(), data=data, role="evidence"),),
        request={"model": {"family": "claude-sonnet-5"}, "run_id": "r1", "job_id": "12b-poc-and-fix",
                 "attempt_id": "a" * 32, "persona": {"persona_id": "poc-fix-author"},
                 "budget": {"input_unit_limit": 10 ** 9}},
        request_sha256="sha256:" + "4" * 64, allowed_claim_classes=("candidate_only",), template=pool.TEMPLATE)


def invoke(document: dict, replies: list[str]):
    prompts, written = [], {}

    def dispatch_fn(argv, prompt, timeout_seconds, transcript_path):
        prompts.append(prompt)
        return {"timed_out": False, "final_result": {"result": replies.pop(0)}}

    with tempfile.TemporaryDirectory() as out, \
            mock.patch.object(cli.cbr, "resolve_claude_binary", return_value="/usr/bin/claude"), \
            mock.patch.object(cli.rc, "load_model_config", return_value={"invocation": {"repair_attempts": 1}}), \
            mock.patch.object(cli.pi, "write_invoker_output", side_effect=lambda package, root, **kw: written.update(kw)):
        pool.PocFixInvoker(effort="high", budget_usd=2.0, dispatch_fn=dispatch_fn).invoke(
            package(document), output_root=Path(out), cancel=threading.Event())
        published = json.loads((Path(out) / "candidates.json").read_text())
    return published, prompts, written


class InvokerTests(unittest.TestCase):
    def test_citation_mismatch_is_repaired_once_then_published(self):
        document = request_workspace()
        bad = good_reply(cited_lines=[{"path": "app/elsewhere.cpp", "start_line": 9, "end_line": 9, "role": "sink"}])
        replies = [json.dumps({"candidates": bad}), "```json\n" + json.dumps({"candidates": good_reply()}) + "\n```"]
        published, prompts, written = invoke(document, replies)
        self.assertEqual(len(prompts), 2)
        self.assertIn("is not a citable workspace file", prompts[1])
        self.assertIn("Trusted PoC-and-fix runtime", prompts[0])
        self.assertIn(derive.PERSONA_SCHEMA, prompts[0])
        self.assertEqual(validate_document(published, derive.CANDIDATES_SCHEMA), [])
        record = json.loads(published["candidates"][0]["assertion"])
        self.assertEqual((record["label"], record["author"]["persona_id"]), ("UNVALIDATED", "poc-fix-author"))
        self.assertEqual(written["claims"][0]["citations"][0]["root"], derive.WORKSPACE_ROOT_ID)

    def test_denylisted_reply_is_accepted_withheld_and_never_re_asked(self):
        document = request_workspace()
        hostile = good_reply()
        hostile["poc"]["text"] = "cat input | sh"
        published, prompts, _ = invoke(document, [json.dumps({"candidates": hostile})])
        self.assertEqual(len(prompts), 1)
        record = json.loads(published["candidates"][0]["assertion"])
        self.assertEqual((record["poc"]["status"], record["poc"]["text"]), ("REJECTED_DENYLIST", None))
        self.assertNotIn("| sh", published["candidates"][0]["assertion"])


class SpecTests(unittest.TestCase):
    def test_one_cell_per_request_with_the_workspace_as_input_zero(self):
        first = request_workspace()
        second = {**first, "request_id": "pocreq-" + "f" * 16}
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            with mock.patch.object(execution_state, "RUNS", base / "runs"), \
                    mock.patch.object(pool.model_versions, "model_identity_for", return_value=MODEL):
                permission = persona_dispatch._permission_block("12b-poc-and-fix", run_id="r1",
                    source_snapshot_sha256="sha256:" + "2" * 64, now="2026-09-29T00:00:00Z")
                spec = pool.pool_spec("r1", "12b-poc-and-fix", [first, second], permission=permission,
                                      binding={"x": 1}, rendezvous_timeout_seconds=3600)
                attempt = base / "attempt"; attempt.mkdir()
                context = pool.context([first, second], spec=spec, attempt=attempt,
                                       source_snapshot_sha256="sha256:" + "2" * 64)
                plan = pool.pool_specification.plan_expansion(spec, context=context)
                empty = pool.pool_spec("r1", "12b-poc-and-fix", [], permission=permission, binding={"x": 1},
                                       rendezvous_timeout_seconds=3600)
        self.assertEqual(len(plan.instances), 2)
        readable = plan.instances[0].request.request["readable_inputs"]
        self.assertEqual([row["root"] for row in readable], [derive.WORKSPACE_ROOT_ID])
        self.assertEqual(plan.instances[0].request.request["persona"]["persona_id"], "poc-fix-author")
        self.assertEqual(spec["pool_budget"]["max_instances"], 2)
        self.assertEqual((empty["worker_groups"][0]["count"], empty["empty_pool_reason"]), (0, "no_applicable_work"))


if __name__ == "__main__":
    unittest.main()
