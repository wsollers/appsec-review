"""T10 lineage and binding checks a mutation probe found unobserved: each test edits ONLY the field
the check binds, and reseals every hash around it, so nothing but that check can refuse."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from owasp_dispatch_support import DispatchCase, MARKER, Routed, ValidatorInvoker, od, sha, write_json  # noqa: E402
import execution_state  # noqa: E402
import owasp_validator_result  # noqa: E402
import pool_rendezvous as pr  # noqa: E402


class Resealing(DispatchCase):
    chapters = ("V1", "V2")

    def reseal_publication(self, *, handoff_edit=None, ordinal: int = 1, pointer_edit=None) -> None:
        """Rewrites one handoff member (or the pointer) and makes every hash above it consistent:
        the member's composition hash, the set entry, the pointer artifacts and the request."""
        pointer_path = self.t06_root / "accepted.json"
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        if handoff_edit is not None:
            entry = self.handoff_set["handoffs"][ordinal - 1]
            path = self.t06_attempt / entry["path"]
            handoff = json.loads(path.read_text(encoding="utf-8"))
            handoff_edit(handoff)
            body = {key: value for key, value in handoff.items() if key not in ("schema", "handoff_id", "hashes")}
            handoff["hashes"]["composition_sha256"] = execution_state.digest(body)
            write_json(path, handoff)
            entry["sha256"] = sha(path)
            write_json(self.handoff_set_path, self.handoff_set)
            pointer["artifacts"][entry["path"]] = entry["sha256"]
            pointer["artifacts"]["outputs/owasp-validator-handoff-set.json"] = sha(self.handoff_set_path)
        if pointer_edit is not None:
            pointer_edit(pointer)
        write_json(pointer_path, pointer)
        self.request_path = self.write_request()

    def refused(self, code: str) -> None:
        invoker = Routed()
        with self.assertRaises(od.DispatchBlocked) as caught:
            self.dispatch(invoker)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(invoker.invoked, [])
        self.assertNotIn(MARKER, str(caught.exception))


class HandoffBoundaryTests(Resealing):
    def test_a_resealed_publication_without_any_edit_still_dispatches(self):
        self.reseal_publication(handoff_edit=lambda handoff: None)
        self.assertEqual(self.accounting(self.dispatch())["counts"]["valid_result"], 2)

    def test_a_resealed_handoff_that_widens_any_boundary_is_refused(self):
        edits = {
            "network": lambda h: h["authorization_boundaries"].update(network_access=True),
            "dynamic": lambda h: h["authorization_boundaries"].update(dynamic_execution=True),
            "manual": lambda h: h["authorization_boundaries"].update(manual_observation=True),
            "mutation": lambda h: h["authorization_boundaries"].update(target_mutation=True),
            "number for false": lambda h: h["authorization_boundaries"].update(network_access=0),
            "dispatch_ready": lambda h: h.update(dispatch_ready=True),
            "execution_authorized": lambda h: h.update(execution_authorized=True),
            "mode and boundary disagree": lambda h: h["authorization_boundaries"].update(declared="dynamic_request_only"),
        }
        original = (self.t06_attempt / self.handoff_set["handoffs"][0]["path"]).read_bytes()
        for label, edit in edits.items():
            with self.subTest(label=label):
                (self.t06_attempt / self.handoff_set["handoffs"][0]["path"]).write_bytes(original)
                self.reseal_publication(handoff_edit=edit)
                self.refused("lineage_refused")

    def test_a_resealed_handoff_whose_fragment_is_not_its_worklist_assignment_is_refused(self):
        self.reseal_publication(handoff_edit=lambda h: h["assigned_fragments"][0].update(target_id="target-" + MARKER))
        self.refused("lineage_refused")

    def test_a_resealed_handoff_that_names_one_evidence_path_with_two_hashes_is_refused(self):
        def twice(handoff):
            second = deepcopy(handoff["accepted_inputs"][0])
            second["artifact"]["sha256"] = "0" * 64
            handoff["accepted_inputs"].append(second)
        self.reseal_publication(handoff_edit=twice)
        self.refused("evidence_refused")

    def test_a_pointer_that_publishes_more_than_the_handoff_set_is_refused(self):
        extra = self.t06_attempt / "outputs" / "extra.json"
        extra.write_bytes(b"{}\n")
        self.reseal_publication(pointer_edit=lambda pointer: pointer["artifacts"].update({"outputs/extra.json": sha(extra)}))
        self.refused("lineage_refused")

    def edit_publication_request(self, edit) -> None:
        path = self.t06_attempt / "inputs.json"
        request = json.loads(path.read_text(encoding="utf-8"))
        edit(request)
        write_json(path, request)

    def test_the_recorded_budget_name_must_be_every_handoff_s(self):
        self.edit_publication_request(lambda request: request.update(budget="probe"))
        self.refused("lineage_refused")

    def test_the_recorded_worklist_must_be_the_one_every_handoff_pins(self):
        source = self.data / self.handoff(1)["worklist_identity"]["worklist_path"]
        copy = self.data / "imports" / "import-1" / "worklist-copy.json"
        copy.write_bytes(source.read_bytes() + b"\n")          # the same rows under another hash
        self.edit_publication_request(lambda request: request["batching"].update(
            worklist_path=copy.relative_to(self.data).as_posix(), worklist_sha256=sha(copy)))
        self.refused("lineage_refused")


class ConfigurationBindingTests(Resealing):
    chapters = ("V1",)

    def test_a_configuration_outside_the_tracked_directory_is_refused(self):
        config = json.loads((od.CONFIG_ROOT / "default-v1.json").read_text(encoding="utf-8"))
        self.relocate_config(deepcopy(config))
        nested = od.CONFIG_ROOT / "nested" / "default-v1.json"
        write_json(nested, config)
        self.request_path = self.write_request(dispatch_config={
            "path": "appsec-review-process/config/owasp-dispatch/nested/default-v1.json",
            "config_digest": execution_state.digest(config)})
        self.refused("config_refused")

    def test_a_configuration_that_names_another_persona_than_its_template_composes_is_refused(self):
        config = json.loads((od.CONFIG_ROOT / "default-v1.json").read_text(encoding="utf-8"))
        config["persona_id"] = "developer-engineer"
        self.config_reference = self.relocate_config(config)
        self.request_path = self.write_request()
        self.refused("registry_refused")


class RuntimeBindingTests(DispatchCase):
    chapters = ("V1",)

    def test_the_invoker_must_be_the_one_the_facts_name(self):
        class Other(ValidatorInvoker):
            invoker_id = "another-invoker"
        with self.assertRaises(od.DispatchBlocked) as caught:
            self.dispatch(Other())
        self.assertEqual(caught.exception.code, "runtime_refused")
        self.assertFalse(self.job_root.exists())

    def test_force_is_a_boolean_and_the_clock_returns_a_utc_instant(self):
        for force in (1, 0, None, "yes"):
            with self.assertRaises(TypeError):
                od.dispatch(self.run_id, self.request_path, runtime=self.runtime(), force=force)
        with self.assertRaises(od.DispatchBlocked) as caught:
            self.dispatch(clock=lambda: "yesterday " + MARKER)
        self.assertEqual(caught.exception.code, "runtime_refused")
        self.assertNotIn(MARKER, str(caught.exception))


class PublishedBindingTests(DispatchCase):
    chapters = ("V1",)

    def test_a_well_formed_but_wrong_input_fingerprint_is_refused(self):
        pointer = self.dispatch()
        path = self.attempt(pointer) / od.ATTEMPT_FILE
        record = json.loads(path.read_text(encoding="utf-8"))
        record["input_fingerprint"] = "0" * 64
        path.write_bytes(od._json_bytes(record))
        self.assertEqual(self.verify(pointer), ["attempt.json input_fingerprint is not what the recorded request derives"])

    def test_a_hard_linked_accounting_is_refused(self):
        pointer = self.dispatch()
        os.link(self.accounting_path(pointer), self.base / "second-name.json")
        self.assertNotEqual(self.verify(pointer), [])
        with self.assertRaises(od.DispatchRejected):
            self.load()

    def t07_root(self) -> Path:
        return self.data / "jobs" / owasp_validator_result.JOB_ID / self.handoff_set["handoffs"][0]["batch_id"]

    def test_a_later_t07_submission_of_another_request_supersedes_the_accounting(self):
        pointer = self.dispatch()
        cell = self.accounting(pointer)["cells"][0]
        request = json.loads((self.attempt(pointer) / od.WORK_DIR / "0001.json").read_text(encoding="utf-8"))
        copy = self.run / "inputs" / "the-same-candidate-elsewhere.json"
        copy.write_bytes((self.attempt(pointer) / cell["candidate"]["path"]).read_bytes())
        request["candidate"] = {"path": copy.relative_to(self.run).as_posix(), "sha256": sha(copy)}
        later = self.run / "inputs" / "later-request.json"
        write_json(later, request)
        accepted = owasp_validator_result.publish(self.run_id, later)      # T07 really accepts it
        self.assertEqual(accepted["status"], "OK")
        self.assertNotEqual(self.verify(pointer), [])                      # and it is not this cell's result
        with self.assertRaises(od.DispatchRejected):
            self.load()

    def test_a_t07_pointer_that_publishes_more_than_its_five_artifacts_is_not_a_valid_result(self):
        pointer = self.dispatch()
        t07_pointer_path = self.t07_root() / "accepted.json"
        t07_pointer = json.loads(t07_pointer_path.read_text(encoding="utf-8"))
        t07_pointer["artifacts"]["inputs.json"] = sha(self.t07_root() / "attempts" / t07_pointer["attempt_id"] / "inputs.json")
        write_json(t07_pointer_path, t07_pointer)
        edited = self.accounting(pointer)
        edited["cells"][0]["validation"]["accepted_pointer_sha256"] = sha(t07_pointer_path)
        edited["accounting_sha256"] = od.accounting_sha256(edited)
        data = od._json_bytes(edited)
        self.accounting_path(pointer).write_bytes(data)
        (self.job_root / "accepted.json").write_bytes(od._json_bytes(od._pointer(edited, data)))
        (self.attempt(pointer) / od.STATUS_FILE).write_bytes(od._json_bytes(od._status(
            edited["input_fingerprint"], self.run_id, edited["attempt_id"], edited["status"],
            outcome=edited["dispatch_outcome"], accounting=edited["accounting_sha256"], refusal=None)))
        self.assertNotEqual(self.verify(pointer), [])


class InterruptedWaveTests(DispatchCase):
    max_cells_per_pool = 1

    def test_an_interrupt_in_one_wave_launches_nothing_in_the_later_waves(self):
        # The first wave's REAL wait completes, then a KeyboardInterrupt reaches C02's coordinator.
        # C02 holds it (cancel, enter the resumable wait again, publish) and re-raises it after the
        # manifest is published; T10 must then launch nothing in the later waves.
        real, calls = pr._wait, []

        def wait(plan, pool_root, context, runtime, runtimes, interrupts):
            calls.append(1)
            waiting = real(plan, pool_root, context, runtime, runtimes, interrupts)
            run, first = waiting.run, len(calls) == 1

            def interrupted_run():
                observations = run()
                if first and not interrupts.caught:
                    raise KeyboardInterrupt
                return observations
            waiting.run = interrupted_run
            return waiting
        invoker = Routed()
        with mock.patch.object(pr, "_wait", side_effect=wait):
            with self.assertRaises(KeyboardInterrupt):
                self.dispatch(invoker)
        accounting = od.thaw(self.load())
        self.assertEqual(invoker.invoked, [1])
        self.assertEqual([cell["state"] for cell in accounting["cells"]],
                         [pr.SUCCEEDED, pr.NOT_LAUNCHED_CANCELED, pr.NOT_LAUNCHED_CANCELED])
        self.assertTrue(self.cancel.is_set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
