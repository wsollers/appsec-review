"""T10 publication tamper matrix.

The verifier re-derives a published dispatch attempt from the recorded request, the exact newest
accepted T06 publication, the tracked configuration, the registry and the disk, with the SAME
accounting rule the producer used. Every file of the attempt, every top-level position of every
T10 document, with and without a consistent reseal, is rejected; nothing read is echoed.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from owasp_dispatch_support import DispatchCase, MARKER, NoCandidate, Routed, od, write_json  # noqa: E402
import owasp_validator_result  # noqa: E402
import persona_invocation_support as b14  # noqa: E402
import pool_rendezvous as pr  # noqa: E402


def departures(value):
    """Plausible different values of the same JSON type, plus a marker."""
    if isinstance(value, bool):
        return [not value]
    if isinstance(value, int):
        return [value + 1]
    if isinstance(value, str):
        return [value + "x", MARKER]
    if isinstance(value, list):
        return [value + [deepcopy(value[0])] if value else [MARKER], value[:-1]] if value else [[MARKER]]
    if isinstance(value, dict):
        key = sorted(value)[0]
        return [{k: v for k, v in value.items() if k != key}, {**value, MARKER: 1}]
    return [MARKER]      # null


class Published(DispatchCase):
    """One accepted attempt with a valid cell, a failed cell, a cell without a candidate and a
    request-only handoff."""
    dynamic_chapters = ("V4",)

    def setUp(self):
        super().setUp()
        self.pointer = self.dispatch(Routed({2: b14.Raising(RuntimeError(MARKER)), 3: NoCandidate()}))
        self.attempt_root = self.attempt(self.pointer)
        self.assertEqual(self.verify(self.pointer), [])

    def rejected(self, label) -> None:
        errors = self.verify(self.pointer)
        self.assertNotEqual(errors, [], label)
        self.assertNotIn(MARKER, " ".join(errors), label)
        with self.assertRaises(od.DispatchRejected) as caught:
            self.load()
        self.assertNotIn(MARKER, str(caught.exception), label)

    def reseal(self, accounting: dict) -> None:
        """What a producer who controls every T10 file would do: every hash made consistent."""
        accounting["accounting_sha256"] = od.accounting_sha256(accounting)
        data = od._json_bytes(accounting)
        self.accounting_path(self.pointer).write_bytes(data)
        (self.job_root / "accepted.json").write_bytes(od._json_bytes(od._pointer(accounting, data)))
        (self.attempt_root / od.STATUS_FILE).write_bytes(od._json_bytes(od._status(
            accounting["input_fingerprint"], self.run_id, accounting["attempt_id"], accounting["status"],
            outcome=accounting["dispatch_outcome"], accounting=accounting["accounting_sha256"], refusal=None)))


class EveryFileTests(Published):
    def test_every_file_of_the_attempt_is_read_and_a_changed_byte_is_rejected(self):
        files = sorted(path for path in self.attempt_root.rglob("*") if path.is_file())
        self.assertGreater(len(files), 20)
        tolerated = []
        for path in files:
            original = path.read_bytes()
            path.write_bytes(original + b" ")
            if self.verify(self.pointer) == []:
                tolerated.append(path.relative_to(self.attempt_root).as_posix())
            path.write_bytes(original)
        self.assertEqual(tolerated, [])
        self.assertEqual(self.verify(self.pointer), [])

    def test_every_file_of_the_attempt_is_required(self):
        files = sorted(path for path in self.attempt_root.rglob("*") if path.is_file())
        tolerated = []
        for path in files:
            original = path.read_bytes()
            path.unlink()
            if self.verify(self.pointer) == []:
                tolerated.append(path.relative_to(self.attempt_root).as_posix())
            path.write_bytes(original)
        self.assertEqual(tolerated, [])

    def test_nothing_may_be_planted_in_a_directory_this_module_wrote(self):
        mine = [self.attempt_root, *(self.attempt_root / name for name in (
            od.OUTPUTS_DIR, od.WORK_DIR, od.POOLS_DIR, od.RENDEZVOUS_DIR)),
            self.attempt_root / od.POOLS_DIR / od.wave_name(0), self.attempt_root / od.RENDEZVOUS_DIR / od.wave_name(0)]
        for directory in mine:
            planted = directory / "planted.json"
            planted.write_bytes(b"{}")
            self.rejected(directory.name)
            planted.unlink()
        self.assertEqual(self.verify(self.pointer), [])

    def test_a_linked_accounting_file_is_refused(self):
        path = self.accounting_path(self.pointer)
        real = path.with_name("real.json")
        path.rename(real)
        path.symlink_to(real)        # POSIX never skips a link test
        self.rejected("symlink")


class EveryPositionTests(Published):
    def positions(self, document: dict, prefix: str = ""):
        for key in sorted(document):
            for value in departures(document[key]):
                yield prefix + key, key, value

    def test_every_top_level_position_of_the_accounting_with_and_without_a_reseal(self):
        original = self.accounting(self.pointer)
        saved = {path: path.read_bytes() for path in (
            self.accounting_path(self.pointer), self.job_root / "accepted.json", self.attempt_root / od.STATUS_FILE)}
        for label, key, value in self.positions(original):
            for resealed in (False, True):
                if resealed and key == "accounting_sha256":
                    continue            # resealing this position restores the file: there is nothing to refuse
                edited = deepcopy(original)
                edited[key] = value
                if resealed:
                    self.reseal(edited)
                else:
                    self.accounting_path(self.pointer).write_bytes(od._json_bytes(edited))
                self.rejected((label, resealed))
                for path, data in saved.items():
                    path.write_bytes(data)
        self.assertEqual(self.verify(self.pointer), [])

    def test_every_position_of_a_cell_a_row_a_fragment_and_a_pool_with_a_reseal(self):
        original = self.accounting(self.pointer)
        saved = {path: path.read_bytes() for path in (
            self.accounting_path(self.pointer), self.job_root / "accepted.json", self.attempt_root / od.STATUS_FILE)}
        targets = [("cells", 1, None), ("rows", 0, None), ("pools", 0, None), ("rows", 0, "fragments")]
        for collection, index, nested in targets:
            record = original[collection][index] if nested is None else original[collection][index][nested][0]
            for label, key, value in self.positions(record, f"{collection}."):
                edited = deepcopy(original)
                target = edited[collection][index] if nested is None else edited[collection][index][nested][0]
                target[key] = value
                self.reseal(edited)
                self.rejected(label)
                for path, data in saved.items():
                    path.write_bytes(data)
        self.assertEqual(self.verify(self.pointer), [])

    def test_a_failed_cell_cannot_be_rewritten_as_a_valid_result_of_another_cell(self):
        edited = self.accounting(self.pointer)
        good, bad = edited["cells"][0], edited["cells"][1]
        for name in ("state", "adapter_status", "adapter_cause", "result_file", "candidate", "validation",
                     "valid_result", "not_assessed_reason", "terminal_class"):
            bad[name] = deepcopy(good[name])
        for row in edited["rows"]:
            for fragment in row["fragments"]:
                if fragment["cell_ordinal"] == 2:
                    fragment.update(disposition="deferred_to_validated_result", not_assessed_reason=None,
                                    result_sha256=good["validation"]["result_sha256"],
                                    validation_attempt_id=good["validation"]["attempt_id"])
                    row["row_disposition"] = "deferred_to_validated_results"
        self.reseal(edited)
        self.rejected("upgrade")

    def test_every_position_of_attempt_status_inputs_pointer_and_latest(self):
        documents = [self.attempt_root / od.ATTEMPT_FILE, self.attempt_root / od.STATUS_FILE,
                     self.attempt_root / od.INPUTS_FILE, self.job_root / "accepted.json", self.job_root / "latest.json"]
        for path in documents:
            data = path.read_bytes()
            for label, key, value in self.positions(json.loads(data), path.name + "."):
                edited = json.loads(data)
                edited[key] = value
                path.write_bytes(od._json_bytes(edited))
                with self.assertRaises(od.DispatchRejected, msg=label) as caught:
                    self.load()
                self.assertNotIn(MARKER, str(caught.exception), label)
                path.write_bytes(data)
        self.assertEqual(od.thaw(self.load()), self.accounting(self.pointer))

    def test_a_repeated_key_in_any_t10_document_is_refused(self):
        for path in (self.attempt_root / od.ATTEMPT_FILE, self.attempt_root / od.INPUTS_FILE,
                     self.accounting_path(self.pointer), self.job_root / "accepted.json"):
            data = path.read_bytes()
            path.write_bytes(data.rstrip()[:-1] + b',\n  "run_id": "' + self.run_id.encode() + b'"\n}\n')
            with self.assertRaises(od.DispatchRejected, msg=path.name):
                self.load()
            path.write_bytes(data)

    def test_the_decision_instant_is_bound_through_the_specification(self):
        path = self.attempt_root / od.ATTEMPT_FILE
        record = json.loads(path.read_text(encoding="utf-8"))
        record["decided_at"] = "2026-09-20T12:00:01Z"
        path.write_bytes(od._json_bytes(record))
        self.rejected("decided_at")


class ValidationSideTests(Published):
    def result_root(self, ordinal: int) -> Path:
        batch = self.handoff_set["handoffs"][ordinal - 1]["batch_id"]
        return self.data / "jobs" / owasp_validator_result.JOB_ID / batch

    def test_a_tampered_t07_result_no_longer_backs_the_accounting(self):
        pointer = self.result_pointer(1)
        path = self.result_root(1) / "attempts" / pointer["attempt_id"] / "outputs" / "control-assessment-result.json"
        path.write_bytes(path.read_bytes() + b" ")
        self.rejected("t07 result")

    def test_a_resealed_t07_result_that_is_not_the_cell_s_candidate_is_refused(self):
        pointer = self.result_pointer(1)
        attempt = self.result_root(1) / "attempts" / pointer["attempt_id"]
        path = attempt / "outputs" / "control-assessment-result.json"
        result = json.loads(path.read_text(encoding="utf-8"))
        result["fragment_results"][0]["rationale"] = "Edited after validation."
        write_json(path, result)
        pointer["artifacts"]["outputs/control-assessment-result.json"] = od._sha_hex(path.read_bytes())
        write_json(self.result_root(1) / "accepted.json", pointer)
        edited = self.accounting(self.pointer)
        edited["cells"][0]["validation"].update(
            accepted_pointer_sha256=od._sha_hex((self.result_root(1) / "accepted.json").read_bytes()),
            result_sha256=pointer["artifacts"]["outputs/control-assessment-result.json"])
        for row in edited["rows"]:
            for fragment in row["fragments"]:
                if fragment["cell_ordinal"] == 1:
                    fragment["result_sha256"] = edited["cells"][0]["validation"]["result_sha256"]
        self.reseal(edited)
        self.rejected("resealed t07 result")

    def test_a_newer_t07_attempt_for_the_batch_supersedes_what_the_accounting_names(self):
        write_json(self.result_root(1) / "latest.json", {"attempt_id": "f" * 32})
        self.rejected("newer t07 attempt")

    def test_a_t07_pointer_cannot_be_planted_for_a_cell_that_never_had_a_candidate(self):
        """Cell 3 succeeded at the adapter and wrote no candidate. Copying cell 1's accepted T07
        publication under batch 3 changes nothing: the rule only reads T07 for a candidate."""
        import shutil
        shutil.copytree(self.result_root(1), self.result_root(3))
        self.assertEqual(self.verify(self.pointer), [])
        self.assertIs(self.cell(od.thaw(self.load()), 3)["valid_result"], False)


class OneRuleTests(DispatchCase):
    chapters = ("V1",)

    def test_the_producer_and_the_verifier_share_the_one_accounting_rule(self):
        with mock.patch.object(od, "derive_accounting", wraps=od.derive_accounting) as rule:
            pointer = self.dispatch()
            produced = rule.call_count
            self.assertEqual(self.verify(pointer), [])
        self.assertEqual(produced, 3)               # find the candidates, publish, verify what was written
        self.assertEqual(rule.call_count, produced + 1)

    def test_nothing_is_accepted_when_the_verifier_refuses_what_the_producer_wrote(self):
        with mock.patch.object(od, "verify_publication", return_value=["refused " + MARKER]):
            with self.assertRaises(od.DispatchRejected) as caught:
                self.dispatch()
        self.assertNotIn(MARKER, str(caught.exception))
        self.assertFalse((self.job_root / "accepted.json").exists())
        latest = json.loads((self.job_root / "latest.json").read_text("utf-8"))["attempt_id"]
        status = json.loads((self.job_root / "attempts" / latest / od.STATUS_FILE).read_text("utf-8"))
        self.assertEqual((status["status"], status["refusal"]), ("FAILED", "publication_failed"))
        with self.assertRaises(od.DispatchRejected):
            self.load()

    def test_verification_with_other_facts_than_the_dispatch_ran_under_is_refused(self):
        pointer = self.dispatch()
        self.assertNotEqual(self.verify(pointer, source_snapshot_sha256="sha256:" + "b" * 64), [])
        self.assertNotEqual(self.verify(pointer, invoker_id="another-invoker"), [])
        self.assertNotEqual(self.verify(pointer, allowed_models=(b14.OTHER_MODEL,)), [])
        self.assertEqual(self.verify(pointer), [])
        self.assertEqual(od.verify_publication(self.run_id, attempt_id="not-an-attempt", facts=self.facts()),
                         ["attempt_id is not a dispatch attempt id"])
        with self.assertRaises(TypeError):
            od.verify_publication(self.run_id, attempt_id=pointer["attempt_id"], facts=None)

    def test_the_returned_accounting_is_deeply_immutable(self):
        self.dispatch()
        accounting = self.load()
        with self.assertRaises(TypeError):
            accounting["status"] = "OK"
        with self.assertRaises(TypeError):
            accounting["cells"][0]["valid_result"] = False
        with self.assertRaises((TypeError, AttributeError)):
            accounting["rows"].append({})
        self.assertEqual(accounting["dispatch_outcome"], pr.COMPLETE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
