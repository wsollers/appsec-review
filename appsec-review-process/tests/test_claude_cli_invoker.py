"""Focused tests for claude_cli_invoker's llm-transcript persistence tunable
(``model-config.json``'s ``invocation.save_llm_transcripts``, added 2026-09-24)."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import registry_paths

import claude_cli_invoker as invoker
import execution_state as state


class TranscriptsEnabledTests(unittest.TestCase):
    def test_default_config_has_no_invocation_leaves_it_off(self):
        self.assertFalse(invoker._transcripts_enabled({}))

    def test_explicit_false_is_off(self):
        self.assertFalse(invoker._transcripts_enabled({"invocation": {"save_llm_transcripts": False}}))

    def test_explicit_true_is_on(self):
        self.assertTrue(invoker._transcripts_enabled({"invocation": {"save_llm_transcripts": True}}))

    def test_unset_key_defaults_off(self):
        self.assertFalse(invoker._transcripts_enabled({"invocation": {}}))


class PersistLlmTranscriptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.owner = Path(self.temporary.name)
        self.old_runs = state.RUNS
        state.RUNS = self.owner / "runs"
        (state.RUNS / "fixture-run" / "data").mkdir(parents=True)
        self.diagnostics_dir = self.owner / "diagnostics"
        self.diagnostics_dir.mkdir()
        (self.diagnostics_dir / "transcript.jsonl").write_text('{"turn": 1}\n', encoding="utf-8")
        (self.diagnostics_dir / "raw-response.json").write_text('{"result": "ok"}', encoding="utf-8")
        self.request = {"run_id": "fixture-run", "job_id": "02-repository-partition-discovery",
                         "attempt_id": "attempt-1"}

    def tearDown(self):
        state.RUNS = self.old_runs
        self.temporary.cleanup()

    def _dest(self):
        return state.data_path("fixture-run", "llm-transcripts", "02-repository-partition-discovery",
                                "attempt-1")

    def test_disabled_by_default_writes_nothing(self):
        invoker._persist_llm_transcript({}, self.request, self.diagnostics_dir)
        self.assertFalse(self._dest().exists())

    def test_repair_log_is_kept_even_when_transcripts_are_off(self):
        # B9 (2026-10-01): the rejection reasons survive a reboot; target-bearing files stay gated.
        (self.diagnostics_dir / "repair-log.json").write_text('[{"round": 0, "reason": "x"}]', encoding="utf-8")
        invoker._persist_llm_transcript({}, self.request, self.diagnostics_dir)
        self.assertEqual(sorted(p.name for p in self._dest().iterdir()), ["repair-log.json"])

    def test_dispatch_progress_lines_name_the_job_and_attempt(self):
        import io, subprocess
        from contextlib import redirect_stderr
        import review_cli as rc
        stderr = io.StringIO()
        token = rc.DISPATCH_LABEL.set("01-component-characterization#92dddfcdd022")
        try:
            with redirect_stderr(stderr), mock.patch.object(rc.pipeline_log, "log"):
                rc._dispatch_streaming(["/bin/echo", "--model", "m"], "prompt", 30,
                                       self.owner / "t" / "transcript.jsonl")
        finally:
            rc.DISPATCH_LABEL.reset(token)
        started = [line for line in stderr.getvalue().splitlines() if "dispatch started" in line]
        self.assertTrue(started and "for 01-component-characterization#92dddfcdd022" in started[0], stderr.getvalue())

    def test_enabled_copies_both_files_to_the_run_owned_path(self):
        cfg = {"invocation": {"save_llm_transcripts": True}}
        invoker._persist_llm_transcript(cfg, self.request, self.diagnostics_dir)
        dest = self._dest()
        self.assertEqual((dest / "transcript.jsonl").read_text(encoding="utf-8"), '{"turn": 1}\n')
        self.assertEqual((dest / "raw-response.json").read_text(encoding="utf-8"), '{"result": "ok"}')

    def test_enabled_but_missing_diagnostics_files_is_a_silent_no_op_per_file(self):
        cfg = {"invocation": {"save_llm_transcripts": True}}
        (self.diagnostics_dir / "raw-response.json").unlink()
        invoker._persist_llm_transcript(cfg, self.request, self.diagnostics_dir)
        dest = self._dest()
        self.assertTrue((dest / "transcript.jsonl").exists())
        self.assertFalse((dest / "raw-response.json").exists())

    def test_enabled_but_missing_run_identity_is_a_no_op_not_a_raise(self):
        cfg = {"invocation": {"save_llm_transcripts": True}}
        invoker._persist_llm_transcript(cfg, {"run_id": "fixture-run"}, self.diagnostics_dir)
        self.assertFalse(self._dest().exists())

    def test_never_raises_even_on_a_nonexistent_diagnostics_dir(self):
        cfg = {"invocation": {"save_llm_transcripts": True}}
        missing = self.owner / "does-not-exist"
        try:
            invoker._persist_llm_transcript(cfg, self.request, missing)
        except Exception as exc:  # pragma: no cover - the point of the test is that this never fires
            self.fail(f"_persist_llm_transcript raised {exc!r}")


class ToolingFeedbackTests(unittest.TestCase):
    """The optional envelope-level tooling_feedback block of a tool-granted reply: stripped before the
    result is validated or derived, persisted beside tool-usage.json, dropped (never a failure) when invalid."""

    FEEDBACK = {"useful_tools": ["input_read"], "unhelpful_tools": [{"tool": "input_grep", "reason": "slow"}],
                "wanted": [{"kind": "query", "what": "call graph", "why": "reach"}],
                "coverage_confidence": "medium", "would_change": "index the build files"}

    def run_invoke(self, feedback=None, *, profile=("query tool: code_symbol",), fill_result=None):
        from tests.test_dev_dispatch import inventory
        contract = json.loads((registry_paths.contract("project-discovery")).read_text())
        reply = {"project_inventory": inventory(), "project_discovery_summary": "# s"}
        if feedback is not None:
            reply["tooling_feedback"] = feedback
        prompts, written, keys = [], {}, []

        def dispatch_fn(argv, prompt, timeout_seconds, transcript_path):
            prompts.append(prompt)
            return {"timed_out": False, "final_result": {"result": json.dumps(reply)}}

        def item(path):
            return SimpleNamespace(root="target-repository", path=path, data=b"x\n", sha256="a" * 64)

        package = SimpleNamespace(
            composition={"output_contract": contract, "tooling_profile": {"allowed_actions": list(profile)}},
            prompt=b"OUTER", inputs=(item("configure.ac"), item("Makefile.am")),
            request={"model": {"family": "claude-sonnet-5"}, "run_id": "fb-run", "job_id": "d02", "attempt_id": "a1",
                     "budget": {"input_unit_limit": 10 ** 9}},
            allowed_claim_classes=("project_inventory", "safe_command_plan"))
        real_key = invoker.persona_cache_key
        with tempfile.TemporaryDirectory() as runs, tempfile.TemporaryDirectory() as out, \
                mock.patch.object(invoker.cbr, "resolve_claude_binary", return_value="/usr/bin/claude"), \
                mock.patch.object(invoker.rc, "load_model_config", return_value={"invocation": {"repair_attempts": 0}}), \
                mock.patch.object(invoker.pi, "write_invoker_output",
                                  side_effect=lambda package, root, **kw: written.update(kw)), \
                mock.patch.object(invoker, "persona_cache_key",
                                  side_effect=lambda pkg, text, *a: keys.append(text) or real_key(pkg, text, *a)), \
                mock.patch.object(invoker, "data_path", side_effect=lambda run, *parts: Path(runs, run, "data", *parts)):
            invoker.ClaudeCliInvoker(effort="medium", dispatch_fn=dispatch_fn, fill_result=fill_result).invoke(
                package, output_root=Path(out), cancel=threading.Event())
            published = json.loads((Path(out) / "project-inventory.json").read_text())
            dest = Path(runs, "fb-run", "data", "llm-transcripts", "d02", "a1")
            stored = {p.name: json.loads(p.read_text()) for p in dest.glob("*.json")} if dest.is_dir() else {}
        return published, written, stored, prompts, keys, reply

    def test_valid_feedback_is_stripped_persisted_and_the_result_is_unchanged(self):
        published, written, stored, prompts, _keys, reply = self.run_invoke(self.FEEDBACK)
        self.assertEqual(published, reply["project_inventory"])
        self.assertEqual(stored["tooling-feedback.json"], self.FEEDBACK)
        self.assertEqual(stored["tool-grant.json"]["tools"][-1], "evidence_derived")
        self.assertFalse(any("tooling feedback" in line for line in written["limitations"]))
        self.assertNotIn("tooling_feedback", json.dumps(written["claims"]))
        self.assertIn("tooling_feedback", prompts[0])   # a tool-granted job is asked for it

    def test_invalid_or_oversized_feedback_is_dropped_with_a_limitation(self):
        for bad in ({"coverage_confidence": "total"}, {"would_change": "x" * 301}, {"wanted": [{"kind": "query", "what": "y" * 10000}]}, "text"):
            published, written, stored, _p, _k, reply = self.run_invoke(bad)
            self.assertEqual(published, reply["project_inventory"])
            self.assertNotIn("tooling-feedback.json", stored)
            self.assertTrue(any(line.startswith("tooling feedback dropped:") for line in written["limitations"]), bad)

    def test_a_reply_without_feedback_is_unchanged(self):
        published, written, stored, _p, _k, reply = self.run_invoke(None)
        self.assertEqual(published, reply["project_inventory"])
        self.assertNotIn("tooling-feedback.json", stored)
        self.assertFalse(any("tooling feedback" in line for line in written["limitations"]))

    def test_feedback_never_reaches_the_derive_step(self):
        seen = []

        def fill(envelope, field):
            seen.append(sorted(envelope))
            return []
        self.run_invoke(self.FEEDBACK, fill_result=fill)
        self.assertEqual(seen, [["project_discovery_summary", "project_inventory"]])

    def test_untooled_job_is_not_asked_and_a_stray_block_is_dropped(self):
        published, written, stored, prompts, _k, reply = self.run_invoke(self.FEEDBACK, profile=())
        self.assertEqual(published, reply["project_inventory"])
        self.assertNotIn("tooling_feedback", prompts[0])
        self.assertNotIn("tooling-feedback.json", stored)
        self.assertIn("tooling feedback dropped: this invocation was granted no lookup tools", written["limitations"])

    def test_persona_cache_key_excludes_the_feedback_instruction(self):
        _pub, _w, _s, prompts, keys, _r = self.run_invoke(self.FEEDBACK)
        self.assertEqual(len(keys), 1)
        self.assertNotIn("tooling_feedback", keys[0])
        self.assertEqual(prompts[0], keys[0] + invoker.tooling_feedback_instructions())


if __name__ == "__main__":
    unittest.main()


import json
import threading
import time
from types import SimpleNamespace
from unittest import mock


class SplitEnvelopeTests(unittest.TestCase):
    """2026-10-01 (zarathustra, 01-component-characterization): the model sent the result object and the
    markdown in two fenced blocks after some prose; only the last block was kept, so the result object was
    lost and every repair round failed the same way."""

    def test_fenced_blocks_after_prose_are_merged(self):
        text = ('I have sufficient evidence now. Compiling the final JSON output.\n\n```json\n'
                '{"component_purpose_map": {"schema": "appsec-review/component-purpose-map/1.0"}}\n```\n\n'
                'Summary:\n\n```json\n{"component_purpose_map_markdown": "# Components"}\n```\n')
        self.assertEqual(sorted(invoker._parse_envelope(text)),
                         ["component_purpose_map", "component_purpose_map_markdown"])

    def test_single_block_and_bare_object_unchanged(self):
        self.assertEqual(invoker._parse_envelope('Prose.\n```json\n{"a": 1}\n```\n'), {"a": 1})
        self.assertEqual(invoker._parse_envelope('{"a": 1}'), {"a": 1})


class ControlCharacterEnvelopeTests(unittest.TestCase):
    """Run 20261001T032047Z-fd64eb (01-component-characterization): one fenced block holding both keys,
    with raw newlines inside the markdown string. Strict parsing failed, salvage filed the whole JSON
    text as the markdown key, and the repair prompt reported an envelope-key mismatch instead."""

    FIELDS = [("component-purpose-map.json", "component_purpose_map", "json"),
              ("component-purpose-map.md", "component_purpose_map_markdown", "md")]
    TEXT = ('I have sufficient evidence now. Compiling the final JSON output.\n\n```json\n'
            '{\n  "component_purpose_map": {"schema": "appsec-review/component-purpose-map/1.0"},\n'
            '  "component_purpose_map_markdown": "# Map\n\n- line one\n- line two"\n}\n```')

    def test_raw_newlines_inside_a_string_parse(self):
        envelope = invoker._parse_envelope(self.TEXT)
        self.assertEqual(sorted(envelope), ["component_purpose_map", "component_purpose_map_markdown"])
        self.assertEqual(envelope["component_purpose_map_markdown"], "# Map\n\n- line one\n- line two")

    def test_salvage_never_files_a_broken_json_object_as_markdown(self):
        broken = 'Prose.\n\n```json\n{"component_purpose_map": {"schema": "x"},\n```'
        self.assertEqual(invoker._salvage_envelope(broken, self.FIELDS),
                         {"component_purpose_map_markdown": "Prose."})
        self.assertEqual(invoker._salvage_envelope('{"component_purpose_map": ', self.FIELDS), {})


class RepairRetryTests(unittest.TestCase):
    """Bounded repair retry (William, 2026-09-26): a response that fails the mechanical checks is
    re-asked with its validation errors, at most ``repair_attempts`` times, within time/money/units."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.diag = Path(self.temporary.name)
        self.prompts: list[str] = []
        self.budgets: list = []

    def run_rounds(self, responses, *, repair_attempts=1, budget_usd=None, timeout=1800,
                   input_unit_limit=None, costs=None, repair_budget_usd=None):
        responses = list(responses)
        costs = list(costs or [0.0] * len(responses))

        def dispatch_fn(argv, prompt, timeout_seconds, transcript_path):
            self.prompts.append(prompt)
            self.budgets.append(argv[0])
            transcript_path.write_text("{}\n", encoding="utf-8")
            return {"timed_out": False, "final_result": {"result": responses.pop(0),
                    "total_cost_usd": costs.pop(0), "usage": {"input_tokens": 1000, "output_tokens": 10}}}

        def accept(dispatch):
            text = dispatch["final_result"]["result"]
            if text != "good":
                raise invoker.InvokerOutputError("rejected", [f"$: unexpected property {text!r}"])
            return {"k": 1}, [{"claim_id": "c"}]

        return invoker._dispatch_until_accepted(
            dispatch_fn=dispatch_fn, accept=accept, prompt_text="PROMPT", argv_for=lambda b: [b],
            budget_usd=budget_usd, timeout_seconds=timeout, repair_attempts=repair_attempts,
            input_unit_limit=input_unit_limit, diagnostics_dir=self.diag, cancel=threading.Event(),
            started=time.time(), repair_budget_usd=repair_budget_usd)

    def test_first_response_accepted_needs_no_repair(self):
        rounds = self.run_rounds(["good"])
        self.assertEqual(rounds["rejected"], 0)
        self.assertEqual(self.prompts, ["PROMPT"])
        self.assertFalse((self.diag / "repair-log.json").exists())

    def test_rejected_response_is_reasked_with_its_errors(self):
        rounds = self.run_rounds(["stray_placeholder", "good"])
        self.assertEqual(rounds["rejected"], 1)
        self.assertEqual(rounds["input_tokens"], 2000)
        self.assertTrue(self.prompts[1].startswith("PROMPT\n\n## Your previous response was rejected"))
        self.assertIn("unexpected property 'stray_placeholder'", self.prompts[1])
        log = json.loads((self.diag / "repair-log.json").read_text())
        self.assertEqual([entry["round"] for entry in log], [0])
        self.assertTrue((self.diag / "raw-response.json").exists())
        self.assertTrue((self.diag / "raw-response-repair-1.json").exists())
        self.assertTrue((self.diag / "transcript-repair-1.jsonl").exists())

    def test_repair_prompt_carries_the_rejected_response_for_correction(self):
        self.run_rounds(["stray_placeholder", "good"])
        self.assertIn("<<<REJECTED-RESPONSE\nstray_placeholder\nREJECTED-RESPONSE>>>", self.prompts[1])
        self.assertIn("do not\ninvestigate again", self.prompts[1])

    def test_oversized_rejected_response_is_not_sent_back(self):
        prompt = invoker._repair_prompt("P", invoker.InvokerOutputError("x", ["bad"]),
                                        "y" * (invoker.MAX_REPAIR_PREVIOUS_CHARS + 1))
        self.assertNotIn("REJECTED-RESPONSE", prompt)

    def test_retry_is_bounded_and_the_last_rejection_fails_closed(self):
        with self.assertRaises(invoker.InvokerOutputError) as caught:
            self.run_rounds(["bad", "still-bad", "good"], repair_attempts=1)
        self.assertEqual(len(self.prompts), 2)
        self.assertIn("after 2 response(s)", str(caught.exception))
        self.assertNotIn("still-bad", str(caught.exception))   # the model's text is never in the message

    def test_zero_repair_attempts_disables_the_retry(self):
        with self.assertRaises(invoker.InvokerOutputError):
            self.run_rounds(["bad", "good"], repair_attempts=0)
        self.assertEqual(len(self.prompts), 1)

    def test_retry_spends_only_what_is_left_of_the_dollar_cap(self):
        rounds = self.run_rounds(["bad", "good"], budget_usd=1.0, costs=[0.4, 0.3])
        self.assertEqual(rounds["rejected"], 1)
        self.assertEqual(self.budgets, [1.0, 0.6])
        with self.assertRaises(invoker.InvokerOutputError):
            self.run_rounds(["bad", "good"], budget_usd=1.0, costs=[0.98, 0.0])

    def test_repair_round_gets_its_own_cap_d31(self):
        """Run 20261001T032047Z-fd64eb: 01's round 0 cost $1.00 of $2.00; the repair got the remainder.
        With D-31 every repair round has a fixed cap, independent of what round 0 spent."""
        rounds = self.run_rounds(["bad", "still-bad", "good"], repair_attempts=2, budget_usd=2.0,
                                 costs=[1.9, 0.3, 0.2], repair_budget_usd=0.5)
        self.assertEqual(rounds["rejected"], 2)
        self.assertEqual(self.budgets, [2.0, 0.5, 0.5])
        self.assertEqual(invoker._repair_budget_fraction({}), 0.25)
        self.assertEqual(invoker._repair_budget_fraction({"invocation": {"repair_budget_fraction": 0.5}}), 0.5)
        self.assertEqual(invoker._repair_budget_fraction({"invocation": {"repair_budget_fraction": 3}}), 0.25)

    def test_no_retry_when_it_would_exceed_the_input_unit_ceiling(self):
        with self.assertRaises(invoker.InvokerOutputError):
            self.run_rounds(["bad", "good"], input_unit_limit=1500)
        self.assertEqual(len(self.prompts), 1)

    def test_timeout_is_never_retried(self):
        def dispatch_fn(argv, prompt, timeout_seconds, transcript_path):
            self.prompts.append(prompt)
            return {"timed_out": True}
        with self.assertRaises(TimeoutError):
            invoker._dispatch_until_accepted(
                dispatch_fn=dispatch_fn, accept=lambda d: None, prompt_text="P", argv_for=lambda b: [],
                budget_usd=None, timeout_seconds=1800, repair_attempts=2, input_unit_limit=None,
                diagnostics_dir=self.diag, cancel=threading.Event(), started=time.time())
        self.assertEqual(len(self.prompts), 1)

    def test_repair_attempts_config(self):
        self.assertEqual(invoker._repair_attempts({}), 1)
        self.assertEqual(invoker._repair_attempts({"invocation": {"repair_attempts": 0}}), 0)
        self.assertEqual(invoker._repair_attempts({"invocation": {"repair_attempts": 2}}), 2)
        self.assertEqual(invoker._repair_attempts({"invocation": {"repair_attempts": 9}}), 1)
        self.assertEqual(invoker._repair_attempts({"invocation": {"repair_attempts": True}}), 1)
        committed = json.loads((ROOT / "model-config.json").read_text())
        # Raised 1 -> 2 on 2026-09-30 (appsec-multi-vuln partition discovery; model-config.json note).
        self.assertEqual(invoker._repair_attempts(committed), 2)


class InvokeRepairEndToEndTests(unittest.TestCase):
    """The live stage 8 failure (SAT 20260926T164835Z): a stray property inside the project
    inventory. With the retry, the second (clean) response is the one published."""

    def test_stray_property_then_clean_response_publishes_the_clean_one(self):
        from tests.test_dev_dispatch import inventory
        from schema_validate import SchemaStore
        store = SchemaStore()
        contract = json.loads((registry_paths.contract("project-discovery")).read_text())
        clean = inventory()
        bad = dict(clean, project_discovery_summary_placeholder="x")
        responses = [json.dumps({"project_inventory": bad, "project_discovery_summary": "# s"}),
                     json.dumps({"project_inventory": clean, "project_discovery_summary": "# s"})]
        prompts = []

        def dispatch_fn(argv, prompt, timeout_seconds, transcript_path):
            prompts.append(prompt)
            return {"timed_out": False, "final_result": {"result": responses.pop(0)}}

        def item(path):
            data = b"x\n"
            return SimpleNamespace(root="target-repository", path=path, data=data, sha256="a" * 64)

        package = SimpleNamespace(
            composition={"output_contract": contract}, prompt=b"OUTER", inputs=(item("configure.ac"), item("Makefile.am")),
            request={"model": {"family": "claude-sonnet-5"}, "run_id": "r", "budget": {"input_unit_limit": 10 ** 9}},
            allowed_claim_classes=("project_inventory", "safe_command_plan"))
        written = {}
        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(invoker.cbr, "resolve_claude_binary", return_value="/usr/bin/claude"), \
                mock.patch.object(invoker.rc, "load_model_config", return_value={"invocation": {"repair_attempts": 1}}), \
                mock.patch.object(invoker.pi, "write_invoker_output",
                                  side_effect=lambda package, root, **kw: written.update(kw)):
            invoker.ClaudeCliInvoker(effort="medium", dispatch_fn=dispatch_fn).invoke(
                package, output_root=Path(out), cancel=threading.Event())
            published = json.loads((Path(out) / "project-inventory.json").read_text())
        self.assertEqual(len(prompts), 2)
        self.assertNotIn("project_discovery_summary_placeholder", published)
        self.assertEqual([c["claim_class"] for c in written["claims"]], ["project_inventory", "safe_command_plan"])
        self.assertTrue(any("schema repair retry: 1 rejected" in text for text in written["limitations"]))
        self.assertIn("project_discovery_summary_placeholder", prompts[1])
        del store

    def run_invoke(self, responses):
        from tests.test_dev_dispatch import inventory
        contract = json.loads((registry_paths.contract("project-discovery")).read_text())
        texts = [json.dumps({"project_inventory": dict(inventory(), **extra), "project_discovery_summary": "# s"})
                 for extra in responses]

        def dispatch_fn(argv, prompt, timeout_seconds, transcript_path):
            return {"timed_out": False, "final_result": {"result": texts.pop(0)}}

        def item(path):
            return SimpleNamespace(root="target-repository", path=path, data=b"x\n", sha256="a" * 64)

        package = SimpleNamespace(
            composition={"output_contract": contract}, prompt=b"OUTER", inputs=(item("configure.ac"), item("Makefile.am")),
            request={"model": {"family": "claude-sonnet-5"}, "run_id": "r", "budget": {"input_unit_limit": 10 ** 9}},
            allowed_claim_classes=("project_inventory", "safe_command_plan"))
        with tempfile.TemporaryDirectory() as out, tempfile.TemporaryDirectory() as scratch, \
                mock.patch.object(invoker.tempfile, "mkdtemp", return_value=str(Path(scratch) / "diag")) as mk, \
                mock.patch.object(invoker.cbr, "resolve_claude_binary", return_value="/usr/bin/claude"), \
                mock.patch.object(invoker.rc, "load_model_config", return_value={"invocation": {"repair_attempts": 1}}), \
                mock.patch.object(invoker.pi, "write_invoker_output"):
            (Path(scratch) / "diag").mkdir()
            invoker.ClaudeCliInvoker(effort="medium", dispatch_fn=dispatch_fn).invoke(
                package, output_root=Path(out), cancel=threading.Event())
            self.assertTrue(mk.called)
            return (Path(scratch) / "diag").exists()

    def test_clean_dispatch_removes_its_private_diagnostics_dir(self):
        self.assertFalse(self.run_invoke([{}]))

    def test_repaired_dispatch_keeps_its_diagnostics_dir(self):
        self.assertTrue(self.run_invoke([{"project_discovery_summary_placeholder": "x"}, {}]))

    def test_extra_validate_rejects_the_first_schema_valid_response_and_accepts_the_repair(self):
        """01-component-characterization, 2026-10-01: a response can be perfectly schema-valid and
        still semantically wrong (a model silently dropping 'first-party'). extra_validate is the
        hook that lets a caller's own check reject that and drive the same bounded repair loop a
        schema failure already uses."""
        from tests.test_dev_dispatch import inventory
        contract = json.loads((registry_paths.contract("project-discovery")).read_text())
        text = json.dumps({"project_inventory": inventory(), "project_discovery_summary": "# s"})
        responses = [text, text]  # schema-identical; only extra_validate tells them apart
        prompts = []

        def dispatch_fn(argv, prompt, timeout_seconds, transcript_path):
            prompts.append(prompt)
            return {"timed_out": False, "final_result": {"result": responses.pop(0)}}

        def item(path):
            return SimpleNamespace(root="target-repository", path=path, data=b"x\n", sha256="a" * 64)

        package = SimpleNamespace(
            composition={"output_contract": contract}, prompt=b"OUTER", inputs=(item("configure.ac"), item("Makefile.am")),
            request={"model": {"family": "claude-sonnet-5"}, "run_id": "r", "budget": {"input_unit_limit": 10 ** 9}},
            allowed_claim_classes=("project_inventory", "safe_command_plan"))
        calls: list[dict] = []

        def extra_validate(result):
            calls.append(result)
            return ["category_coverage is missing first-party"] if len(calls) == 1 else []

        written = {}
        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(invoker.cbr, "resolve_claude_binary", return_value="/usr/bin/claude"), \
                mock.patch.object(invoker.rc, "load_model_config", return_value={"invocation": {"repair_attempts": 1}}), \
                mock.patch.object(invoker.pi, "write_invoker_output",
                                  side_effect=lambda package, root, **kw: written.update(kw)):
            invoker.ClaudeCliInvoker(effort="medium", dispatch_fn=dispatch_fn,
                                     extra_validate=extra_validate).invoke(
                package, output_root=Path(out), cancel=threading.Event())
        self.assertEqual(len(prompts), 2)
        self.assertEqual(len(calls), 2)
        self.assertIn("category_coverage is missing first-party", prompts[1])
        self.assertTrue(any("schema repair retry: 1 rejected" in text for text in written["limitations"]))

    def test_extra_validate_that_never_passes_fails_closed_with_no_retry_budget(self):
        from tests.test_dev_dispatch import inventory
        contract = json.loads((registry_paths.contract("project-discovery")).read_text())
        text = json.dumps({"project_inventory": inventory(), "project_discovery_summary": "# s"})

        def dispatch_fn(argv, prompt, timeout_seconds, transcript_path):
            return {"timed_out": False, "final_result": {"result": text}}

        def item(path):
            return SimpleNamespace(root="target-repository", path=path, data=b"x\n", sha256="a" * 64)

        package = SimpleNamespace(
            composition={"output_contract": contract}, prompt=b"OUTER", inputs=(item("configure.ac"), item("Makefile.am")),
            request={"model": {"family": "claude-sonnet-5"}, "run_id": "r", "budget": {"input_unit_limit": 10 ** 9}},
            allowed_claim_classes=("project_inventory", "safe_command_plan"))
        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(invoker.cbr, "resolve_claude_binary", return_value="/usr/bin/claude"), \
                mock.patch.object(invoker.rc, "load_model_config", return_value={"invocation": {"repair_attempts": 0}}), \
                mock.patch.object(invoker.pi, "write_invoker_output"):
            with self.assertRaises(invoker.InvokerOutputError) as caught:
                invoker.ClaudeCliInvoker(effort="medium", dispatch_fn=dispatch_fn,
                                         extra_validate=lambda result: ["always wrong"]).invoke(
                    package, output_root=Path(out), cancel=threading.Event())
        self.assertIn("always wrong", str(caught.exception))


class PersonaResultCacheTests(unittest.TestCase):
    def test_identical_request_reuses_the_accepted_response_without_a_model_call(self):
        from tests.test_dev_dispatch import inventory
        contract = json.loads((registry_paths.contract("project-discovery")).read_text())
        response = json.dumps({"project_inventory": inventory(), "project_discovery_summary": "# s"})
        calls = []

        def dispatch_fn(argv, prompt, timeout_seconds, transcript_path):
            calls.append(prompt)
            return {"timed_out": False, "final_result": {"result": response}}

        def item(path):
            return SimpleNamespace(root="target-repository", path=path, data=b"x\n", sha256="a" * 64)

        def package(attempt):
            return SimpleNamespace(
                composition={"output_contract": contract}, prompt=b"OUTER", inputs=(item("configure.ac"), item("Makefile.am")),
                request=invoker.pi.freeze({"model": {"family": "claude-sonnet-5"}, "run_id": "cache-run",
                         "attempt_id": attempt, "job_id": "d02", "persona": {"persona_id": "p"},
                         "budget": {"input_unit_limit": 10 ** 9}}),
                allowed_claim_classes=("project_inventory", "safe_command_plan"))
        written = []
        with tempfile.TemporaryDirectory() as runs, \
                mock.patch.object(invoker.cbr, "resolve_claude_binary", return_value="/usr/bin/claude"), \
                mock.patch.object(invoker.rc, "load_model_config", return_value={"invocation": {"repair_attempts": 0}}), \
                mock.patch.object(invoker.pi, "write_invoker_output",
                                  side_effect=lambda package, root, **kw: written.append(kw)), \
                mock.patch.object(invoker, "data_path", side_effect=lambda run, *parts: Path(runs, run, "data", *parts)), \
                mock.patch("execution_state.run_path", side_effect=lambda run: Path(runs, run)):
            (Path(runs) / "cache-run" / "inputs").mkdir(parents=True)
            for attempt in ("a1", "a2"):
                with tempfile.TemporaryDirectory() as out:
                    invoker.ClaudeCliInvoker(effort="medium", dispatch_fn=dispatch_fn).invoke(
                        package(attempt), output_root=Path(out), cancel=threading.Event())
            # a different input is a different question
            other = package("a3"); other.inputs = other.inputs + (item("README"),)
            with tempfile.TemporaryDirectory() as out:
                invoker.ClaudeCliInvoker(effort="medium", dispatch_fn=dispatch_fn).invoke(
                    other, output_root=Path(out), cancel=threading.Event())
        self.assertEqual(len(calls), 2)
        self.assertTrue(any("persona cache" in text and "a1" in text for text in written[1]["limitations"]))

    def test_reused_response_reports_true_zero_usage_not_a_byte_estimate(self):
        """01-component-characterization, 2026-10-01, run 20261001T064759Z-4a8586: input_units on
        reuse was computed as `rounds["input_tokens"] or (read_bytes + 3) // 4`. A reuse sets
        input_tokens=0 deliberately (no new call made); `or` treated that honest 0 as 'missing' and
        substituted a bytes/4 estimate over the *entire* available input (31,044,251 bytes -> an
        estimated 7,761,063 units, against the real live call's actual 44), so a reused answer could
        fail BUDGET_EXCEEDED purely from being reused."""
        from tests.test_dev_dispatch import inventory
        contract = json.loads((registry_paths.contract("project-discovery")).read_text())
        response = json.dumps({"project_inventory": inventory(), "project_discovery_summary": "# s"})

        def dispatch_fn(argv, prompt, timeout_seconds, transcript_path):
            return {"timed_out": False, "final_result": {"result": response}}

        def item(path, size):
            return SimpleNamespace(root="target-repository", path=path, data=b"x" * size, sha256="a" * 64)

        def package(attempt):
            return SimpleNamespace(
                composition={"output_contract": contract}, prompt=b"OUTER",
                inputs=(item("configure.ac", 1_000_000), item("Makefile.am", 1_000_000)),
                request=invoker.pi.freeze({"model": {"family": "claude-sonnet-5"}, "run_id": "cache-run-2",
                         "attempt_id": attempt, "job_id": "d02", "persona": {"persona_id": "p"},
                         "budget": {"input_unit_limit": 10 ** 9}}),
                allowed_claim_classes=("project_inventory", "safe_command_plan"))
        written = []
        with tempfile.TemporaryDirectory() as runs, \
                mock.patch.object(invoker.cbr, "resolve_claude_binary", return_value="/usr/bin/claude"), \
                mock.patch.object(invoker.rc, "load_model_config", return_value={"invocation": {"repair_attempts": 0}}), \
                mock.patch.object(invoker.pi, "write_invoker_output",
                                  side_effect=lambda package, root, **kw: written.append(kw)), \
                mock.patch.object(invoker, "data_path", side_effect=lambda run, *parts: Path(runs, run, "data", *parts)), \
                mock.patch("execution_state.run_path", side_effect=lambda run: Path(runs, run)):
            (Path(runs) / "cache-run-2" / "inputs").mkdir(parents=True)
            for attempt in ("b1", "b2"):
                with tempfile.TemporaryDirectory() as out:
                    invoker.ClaudeCliInvoker(effort="medium", dispatch_fn=dispatch_fn).invoke(
                        package(attempt), output_root=Path(out), cancel=threading.Event())
        live, reused = written
        self.assertTrue(any("persona cache" in text for text in reused["limitations"]))
        self.assertGreater(live["usage"]["input_units"], 100_000)  # the real bytes/4 estimate for ~2MB
        self.assertEqual(reused["usage"]["input_units"], 0)
        self.assertEqual(reused["usage"]["output_units"], 0)

