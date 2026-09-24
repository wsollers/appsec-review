"""Focused tests for claude_cli_invoker's llm-transcript persistence tunable
(``model-config.json``'s ``invocation.save_llm_transcripts``, added 2026-09-24)."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

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


if __name__ == "__main__":
    unittest.main()
