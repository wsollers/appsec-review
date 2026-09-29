"""B3: the OWASP validator cell replies with reduced citations; Python derives the rest."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

PROCESS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROCESS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import owasp_validator_derive as derive
import owasp_validator_result
import test_owasp_validator_result as t07
from schema_validate import validate_document

BASE = t07.OwaspValidatorResultTests


class OwaspValidatorDeriveTests(unittest.TestCase):
    input_manifest = BASE.input_manifest
    row = BASE.row
    publish_upstream = BASE.publish_upstream
    tearDown_fixture_state = BASE.tearDown_fixture_state
    setUp = BASE.setUp
    prepare_handoff = BASE.prepare_handoff
    citation = BASE.citation
    make_candidate = BASE.make_candidate
    refresh_id = BASE.refresh_id
    write_candidate = BASE.write_candidate
    obligation = BASE.obligation
    result_path = BASE.result_path

    def read_pinned(self, path):
        target = self.data / path
        return target.read_bytes() if target.is_file() else None

    @staticmethod
    def reduce(citation):
        return {"ref": citation["input_id"], "locator": citation["locator"],
                "observed_fact": citation["observed_fact"], "evidence_mode": citation["evidence_mode"],
                "limitations": citation["limitations"],
                "affirmative_contrary_evidence": citation["affirmative_contrary_evidence"]}

    def reduced_candidate(self):
        reply = copy.deepcopy(self.candidate)
        for fragment in reply["fragment_results"]:
            for obligation in fragment["proof_obligation_results"]:
                for field in ("evidence_citations", "counterevidence_citations"):
                    obligation[field] = [self.reduce(item) for item in obligation[field]]
        reply["result_id"] = "pending"
        return reply

    def derive(self, reply):
        return derive.derive_candidate(reply, handoff=self.handoff, read_pinned=self.read_pinned)

    def test_resolvable_ref_derives_the_full_citation_and_the_real_hash(self):
        reply = self.reduced_candidate()
        self.assertTrue(validate_document(reply, "owasp-control-assessment-result.schema.json"))
        self.assertEqual(validate_document(reply, derive.PERSONA_SCHEMA), [])
        candidate, notes = self.derive(reply)
        self.assertEqual(notes, [])
        self.assertEqual(validate_document(candidate, derive.FINAL_SCHEMA), [])
        derived = self.obligation_of(candidate)["evidence_citations"][0]
        original = self.obligation()["evidence_citations"][0]
        expected = dict(original, citation_id=derived["citation_id"])
        self.assertEqual(derived, expected)
        self.assertEqual(derived["artifact_sha256"],
                         hashlib.sha256(self.read_pinned(original["artifact_path"])).hexdigest())
        self.assertRegex(derived["citation_id"], r"^citation-.+-evidence1$")

    def obligation_of(self, candidate):
        return candidate["fragment_results"][0]["proof_obligation_results"][0]

    def test_derived_candidate_is_admitted_by_the_unchanged_t07(self):
        candidate, _ = self.derive(self.reduced_candidate())
        self.candidate = candidate
        t07.write_json(self.candidate_path, candidate)
        self.request["candidate"]["sha256"] = t07.sha(self.candidate_path)
        t07.write_json(self.request_path, self.request)
        result = owasp_validator_result.publish(self.run_id, self.request_path)
        self.assertEqual(result["status"], "OK")
        published = json.loads(self.result_path(result).read_text(encoding="utf-8"))
        self.assertEqual(validate_document(published, derive.FINAL_SCHEMA), [])
        self.assertEqual(published["result_id"], candidate["result_id"])

    def test_ref_by_artifact_path_resolves(self):
        reply = self.reduced_candidate()
        entry = next(item for item in self.handoff["accepted_inputs"]
                     if item["input_id"] == self.obligation()["evidence_citations"][0]["input_id"])
        self.obligation_of(reply)["evidence_citations"][0]["ref"] = entry["artifact"]["path"]
        candidate, notes = self.derive(reply)
        if len(self.handoff_paths(entry["artifact"]["path"])) == 1:
            self.assertEqual(notes, [])
            self.assertEqual(self.obligation_of(candidate)["evidence_citations"][0]["input_id"], entry["input_id"])
        else:
            self.assertTrue(notes)

    def handoff_paths(self, path):
        return [item for item in self.handoff["accepted_inputs"] if item["artifact"]["path"] == path]

    def test_unresolvable_ref_is_rejected_as_a_gap_not_silently_dropped(self):
        reply = self.reduced_candidate()
        self.obligation_of(reply)["evidence_citations"][0]["ref"] = "not-an-input-this-cell-was-given"
        candidate, notes = self.derive(reply)
        obligation = self.obligation_of(candidate)
        self.assertEqual(obligation["evidence_citations"], [])
        self.assertEqual(obligation["evidence_gaps"], ["reduced-citation-rejected:evidence1:UNRESOLVED_REF"])
        self.assertEqual(len(notes), 1)
        self.assertNotIn("not-an-input", json.dumps(obligation["evidence_gaps"]))
        # and the unchanged T07 still refuses a satisfied verdict that has lost its evidence
        self.candidate = candidate
        self.write_candidate()
        with self.assertRaisesRegex(owasp_validator_result.CandidateRejected, "satisfied requires"):
            owasp_validator_result.publish(self.run_id, self.request_path)

    def test_hash_changed_on_disk_is_rejected(self):
        reply = self.reduced_candidate()
        candidate, notes = derive.derive_candidate(
            reply, handoff=self.handoff, read_pinned=lambda path: b"tampered bytes")
        self.assertEqual(self.obligation_of(candidate)["evidence_citations"], [])
        self.assertIn("reduced-citation-rejected:evidence1:PINNED_HASH_MISMATCH",
                      self.obligation_of(candidate)["evidence_gaps"])
        _, notes = derive.derive_candidate(reply, handoff=self.handoff, read_pinned=lambda path: None)
        self.assertTrue(notes)

    def test_model_supplied_mechanical_fields_are_ignored(self):
        reply = self.reduced_candidate()
        forged = self.obligation_of(reply)["evidence_citations"][0]
        forged.update({"artifact_sha256": "0" * 64, "citation_id": "forged", "input_id": "forged",
                       "artifact_path": "elsewhere.json", "freshness": {"status": "current", "assessed_at": "x"},
                       "accepted_pointer": None, "covered_scope": ["everything"],
                       "canonical_dereference_id": "forged", "derived_output_id": "forged"})
        candidate, notes = self.derive(reply)
        self.assertEqual(notes, [])
        derived = self.obligation_of(candidate)["evidence_citations"][0]
        original = self.obligation()["evidence_citations"][0]
        self.assertEqual(derived, dict(original, citation_id=derived["citation_id"]))
        self.assertNotEqual(derived["citation_id"], "forged")
        self.assertEqual(validate_document(candidate, derive.FINAL_SCHEMA), [])

    def test_model_cannot_widen_source_kind_or_smuggle_test_context(self):
        reply = self.reduced_candidate()
        item = self.obligation_of(reply)["evidence_citations"][0]
        item["source_kind"] = "crosswalk"
        item["test_context"] = {"test_definition": "x", "test_result": "y", "environment_identity": "z",
                                "production_equivalence": "equivalent", "production_equivalence_limitations": [],
                                "mocks_used": False}
        derived = self.obligation_of(self.derive(reply)[0])["evidence_citations"][0]
        self.assertEqual(derived["source_kind"], "canonical_evidence")
        self.assertIsNone(derived["test_context"])
        item["source_kind"] = "scanner"
        derived = self.obligation_of(self.derive(reply)[0])["evidence_citations"][0]
        self.assertEqual(derived["source_kind"], "scanner")

    def test_result_id_is_derived_not_model_supplied(self):
        candidate, _ = self.derive(self.reduced_candidate())
        self.assertEqual(candidate["result_id"], "assessment-" + t07.execution_state.digest(
            {k: v for k, v in candidate.items() if k != "result_id"})[:20])

    def test_fill_hook_uses_the_cells_own_pinned_bytes(self):
        handoff_bytes = self.handoff_path.read_bytes()
        inputs = [mock.Mock(role="handoff", path="h.json", data=handoff_bytes)]
        for entry in self.handoff["accepted_inputs"]:
            inputs.append(mock.Mock(role="evidence", path=entry["artifact"]["path"],
                                    data=self.read_pinned(entry["artifact"]["path"]) or b""))
        package = mock.Mock(inputs=tuple(inputs))
        envelope = {"result": self.reduced_candidate()}
        # canonical evidence in the handoff is a real file; other entries may be absent (b"" mismatches)
        notes = derive.make_fill(package)(envelope, "result")
        self.assertEqual(validate_document(envelope["result"], derive.FINAL_SCHEMA), [])
        self.assertEqual(notes, [])

    def test_cell_invoker_wires_reduced_schema_and_fill(self):
        import owasp_dispatch
        with mock.patch("claude_cli_invoker.ClaudeCliInvoker") as cli:
            invoker = owasp_dispatch.CellInvoker(effort="low", budget_usd=1.0)
            package = mock.Mock(inputs=(mock.Mock(role="handoff", path="h.json", data=self.handoff_path.read_bytes()),))
            invoker.invoke(package, output_root=Path("."), cancel=None)
        kwargs = cli.call_args.kwargs
        self.assertEqual(kwargs["persona_schema"], derive.PERSONA_SCHEMA)
        self.assertTrue(callable(kwargs["fill_result"]))
        self.assertEqual(invoker.invoker_id, "claude-cli")


del BASE  # keep the borrowed suite out of this module


if __name__ == "__main__":
    unittest.main()
