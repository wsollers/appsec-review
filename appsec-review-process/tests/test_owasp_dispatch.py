"""T10: OWASP validator dispatch, wait-all and failure accounting.

Real T05/T06 publications, the real C01 expansion, the real C02 rendezvous, the real B14 adapter
and the real T07 validator underneath; nothing of those layers is mocked. Every hostile case is the
honest path plus exactly one departure. Nothing sleeps to synchronize.
"""
from __future__ import annotations

from copy import deepcopy
import inspect
import json
from pathlib import Path
import shutil
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import owasp_dispatch_support as support  # noqa: E402
from owasp_dispatch_support import (  # noqa: E402
    DispatchCase, Gated, MARKER, NoCandidate, Routed, ValidatorInvoker, every_text, od, sha, write_json,
)
import execution_state  # noqa: E402
import owasp_validator_handoff  # noqa: E402
import owasp_validator_result  # noqa: E402
import persona_invocation as pi  # noqa: E402
import persona_invocation_support as b14  # noqa: E402
import pool_rendezvous as pr  # noqa: E402
import pool_specification as ps  # noqa: E402
from schema_validate import validate_document  # noqa: E402


def dispositions(accounting: dict) -> list:
    """Row dispositions in the order of the cells that carry them (the worklist itself is ordered by
    target id); rows without any fragment come last."""
    rows = sorted(accounting["rows"], key=lambda row: (not row["fragments"],
                                                       [f["cell_ordinal"] for f in row["fragments"]], row["row_index"]))
    return [row["row_disposition"] for row in rows]


def row_for(accounting: dict, ordinal: int) -> dict:
    return next(row for row in accounting["rows"] if any(f["cell_ordinal"] == ordinal for f in row["fragments"]))


def states(accounting: dict) -> list:
    return [cell["state"] for cell in accounting["cells"]]


class HonestDispatchTests(DispatchCase):
    dynamic_chapters = ("V4",)

    def test_every_cell_succeeds_and_every_row_defers_to_the_t07_result_of_its_own_cell(self):
        invoker = Routed()
        pointer = self.dispatch(invoker)
        accounting = self.accounting(pointer)
        self.assertEqual(validate_document(accounting, od.ACCOUNTING_SCHEMA), [])
        self.assertEqual(accounting["dispatch_outcome"], pr.COMPLETE)
        self.assertEqual(states(accounting), [pr.SUCCEEDED] * 3 + [None])
        self.assertEqual(sorted(invoker.invoked), [1, 2, 3])          # the request-only handoff never ran
        for ordinal in (1, 2, 3):
            cell, t07 = self.cell(accounting, ordinal), self.result_pointer(ordinal)
            self.assertTrue(cell["valid_result"])
            self.assertEqual(cell["terminal_class"], "valid_result")
            self.assertEqual(cell["validation"]["outcome"], "accepted")
            self.assertEqual(cell["validation"]["attempt_id"], t07["attempt_id"])
            self.assertEqual(cell["validation"]["result_sha256"],
                             t07["artifacts"]["outputs/control-assessment-result.json"])
            self.assertEqual(t07["handoff_id"], self.handoff_set["handoffs"][ordinal - 1]["handoff_id"])
            # the candidate T07 validated is the very file the cell wrote, in place
            request = json.loads((self.attempt(pointer) / od.WORK_DIR / f"{ordinal:04d}.json").read_text("utf-8"))
            self.assertEqual(self.run / request["candidate"]["path"], self.attempt(pointer) / cell["candidate"]["path"])
        self.assertEqual(dispositions(accounting), ["deferred_to_validated_results"] * 3 + ["request_only"])
        self.assertEqual(self.verify(pointer), [])
        self.assertEqual(od.thaw(self.load()), accounting)

    def test_a_request_only_handoff_keeps_the_publication_from_ever_being_ok(self):
        pointer = self.dispatch()
        self.assertEqual(pointer["status"], "OK_WITH_GAPS")
        self.assertEqual(self.cell(self.accounting(pointer), 4)["terminal_class"], "request_only")

    def test_t10_issues_no_status_and_every_boundary_flag_is_the_json_value_false(self):
        accounting = self.accounting(self.dispatch())
        for block in ("claims_boundary",):
            for name, value in accounting[block].items():
                self.assertIs(value, False, name)
        for name in ("network_access", "dynamic_execution", "manual_observation", "target_mutation"):
            self.assertIs(accounting["cell_boundary"][name], False)
        self.assertTrue(all(row["final_control_status_issued"] is False for row in accounting["rows"]))
        statuses = owasp_validator_result.ASSESSMENTS - {"not_assessed"}
        self.assertFalse(statuses & set(every_text(accounting)))        # no control status word anywhere

    def test_the_vocabulary_maps_every_c02_state_exactly_once(self):
        accounting = self.accounting(self.dispatch())
        mapped = [state for name in ("failed", "canceled", "timed_out", "skipped", "invalid")
                  for state in accounting["vocabulary"][name] if state in pr.STATES]
        self.assertEqual(sorted(mapped), sorted(set(pr.STATES) - {pr.SUCCEEDED}))
        self.assertEqual(accounting["vocabulary"]["degraded"], [pr.DEGRADED])
        self.assertIn(pr.EMPTY, accounting["vocabulary"]["skipped"])
        for state in pr.STATES:
            self.assertEqual(od.terminal_class(state, False) == "invalid", state in (pr.INVALID, pr.SUCCEEDED))
        self.assertEqual(od.terminal_class(pr.SUCCEEDED, True), "valid_result")


class CellMappingTests(DispatchCase):
    """What a cell is given comes from the registry, the tracked configuration and the trusted
    facts. A handoff contributes pinned bytes and limits that can only narrow."""
    dynamic_chapters = ("V4",)

    def specs(self, **over):
        plan = self.plan()
        return plan, od.build_specifications(plan, self.facts(), attempt_id="a" * 32, decided_at=support.NOW, **over)

    def test_one_persona_group_per_static_handoff_and_none_for_a_request_only_one(self):
        plan, (spec,) = self.specs()
        self.assertEqual([group["group_id"] for group in spec["worker_groups"]], ["cell-0001", "cell-0002", "cell-0003"])
        self.assertTrue(all(group["worker_kind"] == ps.PERSONA and group["count"] == 1 for group in spec["worker_groups"]))
        self.assertIs(spec["wait_all"], True)
        self.assertEqual(spec["lane"], od.LANE)
        self.assertEqual([cell.disposition for cell in plan.cells], [od.DISPATCHED] * 3 + [od.REQUEST_ONLY])

    def test_permission_is_default_deny_with_no_capability_and_no_grant(self):
        _, (spec,) = self.specs()
        for group in spec["worker_groups"]:
            permission = group["permission"]
            self.assertEqual(permission["requirement"]["capabilities"], [])
            self.assertEqual(permission["grants"], [])
            self.assertEqual(permission["decision"]["capabilities"], [])
        self.assertEqual(spec["resource_pool_policy"]["allowed_pools"], ["persona_llm"])

    def test_claims_and_tools_come_from_the_registry_and_are_only_narrowed(self):
        plan, (spec,) = self.specs()
        records = pi.load_composition(self.registry, od.thaw(plan.persona), pi.SchemaStore())
        ceiling = pi.claim_ceiling(records["role"], records["tooling_profile"])
        for group in spec["worker_groups"]:
            template = group["persona_request"]
            self.assertEqual(template["tools"], [])
            self.assertEqual(template["budget"]["tool_call_limit"], 0)
            self.assertLessEqual(set(template["allowed_claim_classes"]), set(ceiling["allowed"]))
            self.assertLessEqual(set(ceiling["prohibited"]), set(template["prohibited_claim_classes"]))
            self.assertIn("control_verdict", template["allowed_claim_classes"])
        mapping = {entry["handoff_class"]: entry["registry_classes"] for entry in plan.config["prohibited_claim_map"]}
        for name in self.handoff(1)["prohibited_claim_classes"]:
            self.assertLessEqual(set(mapping[name]), set(spec["worker_groups"][0]["persona_request"]["prohibited_claim_classes"]))

    def test_inputs_are_exactly_the_handoff_its_publication_and_the_evidence_it_names(self):
        _, (spec,) = self.specs()
        for ordinal, group in enumerate(spec["worker_groups"], 1):
            inputs = group["persona_request"]["readable_inputs"]
            entry, handoff = self.handoff_set["handoffs"][ordinal - 1], self.handoff(ordinal)
            self.assertEqual([item["role"] for item in inputs], ["handoff", "reference", "reference", "evidence"])
            self.assertEqual(inputs[0]["sha256"], "sha256:" + entry["sha256"])
            self.assertEqual(inputs[1]["sha256"], "sha256:" + sha(self.t06_root / "accepted.json"))
            self.assertEqual(inputs[2]["sha256"], "sha256:" + sha(self.handoff_set_path))
            self.assertEqual([item["path"] for item in inputs[3:]],
                             sorted({item["artifact"]["path"] for item in handoff["accepted_inputs"]}))
            self.assertTrue(all(item["root"] == od.READABLE_ROOT for item in inputs))

    def test_the_outer_prompt_is_the_bytes_every_handoff_pins(self):
        _, (spec,) = self.specs()
        prompt = spec["worker_groups"][0]["persona_request"]["outer_prompt"]
        self.assertEqual(prompt["sha256"], "sha256:" + self.handoff(1)["hashes"]["prompt_sha256"])
        self.assertEqual(prompt["path"], "config/owasp-validator-handoff/validator-instructions-v1.txt")
        self.assertEqual(sha(od.ROOT / prompt["path"]), self.handoff(1)["hashes"]["prompt_sha256"])

    def test_budget_class_pool_budget_and_timeouts_derive_from_the_handoff_s_versioned_limits(self):
        plan, (spec,) = self.specs()
        limits = plan.config["cell_budgets"]["standard"]
        self.assertEqual(spec["budget_class"], "standard")
        timeouts = [group["persona_request"]["budget"]["timeout_seconds"] for group in spec["worker_groups"]]
        self.assertEqual(timeouts, [self.handoff(1)["budget"]["timeout_seconds"]] * 3)
        self.assertEqual(spec["pool_budget"], {
            "max_instances": 3, "max_persona_input_units": 3 * limits["input_unit_limit"],
            "max_persona_output_units": 3 * limits["output_unit_limit"], "max_total_timeout_seconds": sum(timeouts)})
        self.assertEqual(spec["rendezvous_timeout_seconds"],
                         sum(timeouts) + plan.config["pool"]["rendezvous_margin_seconds"])

    def test_the_model_and_the_invoker_are_the_request_s_and_the_facts_never_the_handoff_s(self):
        _, (spec,) = self.specs()
        for group in spec["worker_groups"]:
            self.assertEqual(group["persona_request"]["model"], support.MODEL)
            self.assertEqual(group["persona_request"]["invoker_id"], pi.FixtureInvoker.invoker_id)
            self.assertEqual(group["persona_request"]["invocation_role"], "produce")
            self.assertEqual(group["persona_request"]["producers"], [])

    def test_a_model_outside_the_allow_list_is_refused_before_anything_runs(self):
        self.request_path = self.write_request(model={**support.MODEL, "model_id": "unlisted-model"})
        invoker = Routed()
        with self.assertRaises(od.DispatchBlocked) as caught:
            self.dispatch(invoker)
        self.assertEqual(caught.exception.code, "specification_refused")
        self.assertEqual(invoker.invoked, [])


class NarrowedLimitTests(DispatchCase):
    chapters = ("V1",)
    max_timeout_seconds = 7

    def test_the_cell_timeout_is_the_smaller_of_the_handoff_s_and_the_configuration_s(self):
        plan = self.plan()
        (spec,) = od.build_specifications(plan, self.facts(), attempt_id="a" * 32, decided_at=support.NOW)
        self.assertEqual(spec["worker_groups"][0]["persona_request"]["budget"]["timeout_seconds"], 7)
        self.assertGreater(self.handoff(1)["budget"]["timeout_seconds"], 7)


class PartialPoolFailureTests(DispatchCase):
    def test_succeeded_cells_defer_failed_cells_are_not_assessed_and_degraded_is_preserved(self):
        invoker = Routed({2: b14.Raising(RuntimeError(MARKER))})
        pointer = self.dispatch(invoker)
        accounting = self.accounting(pointer)
        self.assertEqual(accounting["dispatch_outcome"], pr.DEGRADED)
        self.assertIs(accounting["degraded"], True)
        self.assertIs(accounting["pools"][0]["degraded"], True)
        self.assertEqual(pointer["status"], "OK_WITH_GAPS")
        failed = self.cell(accounting, 2)
        self.assertEqual((failed["state"], failed["adapter_status"], failed["adapter_cause"], failed["terminal_class"]),
                         (pr.FAILED, "FAILED", "INVOKER_EXCEPTION", "failed"))
        self.assertEqual(failed["not_assessed_reason"], "cell_state")
        self.assertEqual(failed["validation"]["outcome"], "not_submitted")
        self.assertEqual(dispositions(accounting), ["deferred_to_validated_results", "not_assessed",
                                                    "deferred_to_validated_results"])
        fragment = row_for(accounting, 2)["fragments"][0]
        self.assertEqual((fragment["instance_id"], fragment["state"], fragment["adapter_cause"]),
                         (failed["instance_id"], pr.FAILED, "INVOKER_EXCEPTION"))
        self.assertIsNone(fragment["result_sha256"])
        self.assertEqual(self.verify(pointer), [])
        self.assertNotIn(MARKER, "".join(every_text(accounting)))

    def test_an_unavailable_invoker_is_a_blocked_cell_and_a_failed_pool(self):
        accounting = self.accounting(self.dispatch(b14.Raising(pi.InvokerUnavailable(MARKER))))
        self.assertEqual(accounting["dispatch_outcome"], pr.POOL_FAILED)
        self.assertEqual({cell["state"] for cell in accounting["cells"]}, {pr.BLOCKED})
        self.assertEqual({cell["terminal_class"] for cell in accounting["cells"]}, {"failed"})
        self.assertEqual(set(dispositions(accounting)), {"not_assessed"})


class InstanceTimeoutTests(DispatchCase):
    chapters = ("V1", "V2")
    max_timeout_seconds = 1

    def test_a_cell_that_exceeds_its_own_timeout_is_timed_out_and_its_rows_are_not_assessed(self):
        gate = Gated()
        accounting = self.accounting(self.dispatch(Routed({2: gate})))
        cell = self.cell(accounting, 2)
        self.assertEqual((cell["state"], cell["adapter_cause"], cell["terminal_class"]),
                         (pr.INSTANCE_TIMED_OUT, "TIMEOUT", "timed_out"))
        self.assertEqual(dispositions(accounting), ["deferred_to_validated_results", "not_assessed"])
        self.assertEqual(accounting["counts"]["timed_out"], 1)


class RendezvousTimeoutTests(DispatchCase):
    chapters = ("V1", "V2")

    def test_a_late_valid_output_is_never_adopted(self):
        gate = Gated(honor_cancel=False)
        pointer = self.dispatch(Routed({2: gate}), wait_limit_seconds=2.0, stop_grace_seconds=0, drain_seconds=0)
        before = self.accounting_path(pointer).read_bytes()
        accounting = self.accounting(pointer)
        late = self.cell(accounting, 2)
        self.assertEqual((late["state"], late["terminal_class"], late["result_file"], late["candidate"]),
                         (pr.RENDEZVOUS_TIMED_OUT, "timed_out", None, None))
        self.assertEqual(dispositions(accounting), ["deferred_to_validated_results", "not_assessed"])
        gate.release.set()                                   # now the cell writes a perfectly valid candidate
        self.assertTrue(gate.finished.wait(support.HANG_SECONDS))
        self.join_threads()
        written = list(self.attempt(pointer).rglob(od.CANDIDATE_FILE))
        self.assertEqual(len(written), 2)                    # it IS on disk, and it is valid
        self.assertEqual(self.verify(pointer), [])
        self.assertEqual(self.accounting_path(pointer).read_bytes(), before)
        self.assertEqual(self.cell(od.thaw(self.load()), 2)["state"], pr.RENDEZVOUS_TIMED_OUT)
        batch = self.handoff_set["handoffs"][1]["batch_id"]
        self.assertFalse((self.data / "jobs" / owasp_validator_result.JOB_ID / batch).exists())   # T07 never saw it


class WaveTests(DispatchCase):
    max_cells_per_pool = 1

    def test_one_wave_s_rendezvous_timeout_does_not_cancel_the_next_wave(self):
        gate = Gated()
        pointer = self.dispatch(Routed({1: gate}), wait_limit_seconds=1.5, drain_seconds=5)
        accounting = self.accounting(pointer)
        self.assertEqual([pool["wave"] for pool in accounting["pools"]], [0, 1, 2])
        self.assertEqual([cell["wave"] for cell in accounting["cells"]], [0, 1, 2])
        self.assertEqual(states(accounting), [pr.RENDEZVOUS_TIMED_OUT, pr.SUCCEEDED, pr.SUCCEEDED])
        self.assertEqual(accounting["dispatch_outcome"], pr.DEGRADED)
        self.assertFalse(self.cancel.is_set())
        self.assertEqual(self.verify(pointer), [])

    def test_a_dispatch_wide_cancel_reaches_every_later_wave(self):
        invoker = Routed({1: Gated(on_start=self.cancel.set)})
        accounting = self.accounting(self.dispatch(invoker))
        self.assertEqual(states(accounting), [pr.CANCELED, pr.NOT_LAUNCHED_CANCELED, pr.NOT_LAUNCHED_CANCELED])
        self.assertEqual(invoker.invoked, [1])


class CancellationTests(DispatchCase):
    def test_a_cancel_mid_flight_accounts_for_every_cell_and_records_the_never_launched_ones(self):
        invoker = Routed({1: Gated(on_start=self.cancel.set)})
        pointer = self.dispatch(invoker, max_parallel=1)
        accounting = self.accounting(pointer)
        self.assertEqual(accounting["dispatch_outcome"], pr.POOL_CANCELED)
        self.assertEqual(states(accounting), [pr.CANCELED, pr.NOT_LAUNCHED_CANCELED, pr.NOT_LAUNCHED_CANCELED])
        self.assertEqual([cell["terminal_class"] for cell in accounting["cells"]], ["canceled", "skipped", "skipped"])
        self.assertEqual(invoker.invoked, [1])
        self.assertEqual(set(dispositions(accounting)), {"not_assessed"})
        self.assertEqual(accounting["counts"]["cells"], 3)
        self.assertEqual(self.verify(pointer), [])

    def test_an_interrupt_is_accounted_for_and_then_re_raised(self):
        # The REAL C02 wait runs; the wrapper only adds what C02 itself does when a KeyboardInterrupt
        # reaches its coordinator thread (cancel, finish the wait, hand the interrupt back).
        with mock.patch.object(pr, "_wait", side_effect=self.interrupting_wait()):
            with self.assertRaises(KeyboardInterrupt):
                self.dispatch()
        accounting = od.thaw(self.load())
        self.assertEqual(accounting["dispatch_outcome"], pr.POOL_CANCELED)
        self.assertEqual(set(dispositions(accounting)), {"not_assessed"})

    def interrupting_wait(self):
        real = pr._wait

        def wait(plan, pool_root, context, runtime):
            runtime.cancel.set()                 # what C02 does for an interrupt in the coordinator
            observations, _ = real(plan, pool_root, context, runtime)
            return observations, KeyboardInterrupt()
        return wait


class InvalidOutputTests(DispatchCase):
    chapters = ("V1", "V2")

    def refused(self, invoker, reason, *, state=pr.SUCCEEDED, cause=None, outcome="not_submitted"):
        pointer = self.dispatch(Routed({1: invoker}))
        accounting = self.accounting(pointer)
        cell = self.cell(accounting, 1)
        self.assertEqual((cell["state"], cell["adapter_cause"], cell["not_assessed_reason"]), (state, cause, reason))
        self.assertEqual(cell["validation"]["outcome"], outcome)
        self.assertIs(cell["valid_result"], False)
        self.assertEqual(dispositions(accounting), ["not_assessed", "deferred_to_validated_results"])
        self.assertEqual(self.verify(pointer), [])
        self.assertNotIn(MARKER, "".join(every_text(accounting)))
        return accounting, cell

    def test_a_cell_that_succeeded_at_the_adapter_but_whose_candidate_t07_refuses(self):
        def unsupported(candidate, package):
            obligation = candidate["fragment_results"][0]["proof_obligation_results"][0]
            obligation["evidence_citations"] = []          # `satisfied` without admissible evidence
            obligation["rationale"] = MARKER
            support.refresh(candidate)
        _, cell = self.refused(ValidatorInvoker(unsupported), "validation_refused", outcome="refused")
        self.assertEqual((cell["terminal_class"], cell["validation"]["status"]), ("invalid", "INVALID"))
        self.assertIsNone(cell["validation"]["result_sha256"])
        self.assertEqual(self.result_pointer(1)["status"], "INVALID")     # T07 kept its own receipt

    def test_a_candidate_that_asserts_satisfaction_for_a_row_outside_its_handoff(self):
        def extra_row(candidate, package):
            foreign = deepcopy(candidate["fragment_results"][0])
            foreign.update(fragment_id="fragment-outside", target_id="target-outside", assessment_status="satisfied")
            candidate["fragment_results"].append(foreign)
            support.refresh(candidate)
        self.refused(ValidatorInvoker(extra_row), "validation_refused", outcome="refused")

    def test_a_candidate_for_another_batch_s_fragments(self):
        other = self.handoff(2)

        def other_fragments(candidate, package):
            for result, fragment in zip(candidate["fragment_results"], other["assigned_fragments"]):
                for name in ("fragment_id", "assignment_id", "target_id", "control_id"):
                    result[name] = fragment[name]
            support.refresh(candidate)
        self.refused(ValidatorInvoker(other_fragments), "validation_refused", outcome="refused")

    def test_a_whole_valid_candidate_of_another_batch_is_not_this_cell_s_result(self):
        def impersonate(candidate, package):
            builder = support._CandidateBuilder()
            builder.data, builder.run_id, builder.handoff = self.data, self.run_id, self.handoff(2)
            builder.t06_pointer, builder.handoff_set_path = self.t06_root / "accepted.json", self.handoff_set_path
            builder.handoff_path = self.t06_attempt / self.handoff_set["handoffs"][1]["path"]
            other = builder.make_candidate()
            other["producer"]["producer_id"] = package.request["attempt_id"]
            return support.refresh(other)
        accounting, _ = self.refused(ValidatorInvoker(impersonate), "validation_refused", outcome="refused")
        self.assertTrue(self.cell(accounting, 2)["valid_result"])       # batch 2's own cell is untouched

    def test_a_candidate_that_names_another_producer_is_never_submitted(self):
        def renamed(candidate, package):
            candidate["producer"]["producer_id"] = "another-instance"
            support.refresh(candidate)
        self.refused(ValidatorInvoker(renamed), "candidate_identity")
        batch = self.handoff_set["handoffs"][0]["batch_id"]
        self.assertFalse((self.data / "jobs" / owasp_validator_result.JOB_ID / batch).exists())

    def test_a_verified_adapter_result_without_a_candidate_file(self):
        self.refused(NoCandidate(), "candidate_missing")

    def test_adapter_level_malformed_prohibited_claim_and_identity(self):
        class WrongPersona(ValidatorInvoker):
            def invoke(inner, package, *, output_root, cancel):
                super().invoke(package, output_root=output_root, cancel=cancel)
                path = Path(output_root) / pi.MANIFEST_FILE
                manifest = json.loads(path.read_text(encoding="utf-8"))
                manifest["persona_id"] = "developer-engineer"
                path.write_bytes(pi.canonical_bytes(manifest))
        cases = {"MALFORMED_RESULT": ValidatorInvoker(lambda candidate, package: b"{" + MARKER.encode()),
                 "PROHIBITED_CLAIM": ValidatorInvoker(claim_class="verified_finding"),
                 "IDENTITY_MISMATCH": WrongPersona()}
        for cause, invoker in cases.items():
            with self.subTest(cause=cause):
                _, cell = self.refused(invoker, "cell_state", state=pr.FAILED, cause=cause)
                self.assertEqual(cell["terminal_class"], "failed")
                self.tearDown_fixture_state()

    def test_prohibited_text_in_the_candidate_itself_fails_at_the_adapter(self):
        def severity(candidate, package):
            candidate["fragment_results"][0]["rationale"] = "This is a critical severity problem."
            support.refresh(candidate)
        self.refused(ValidatorInvoker(severity), "cell_state", state=pr.FAILED, cause="PROHIBITED_CLAIM")

    def tearDown_fixture_state(self):
        shutil.rmtree(self.run)
        self.setUp_run()

    def setUp_run(self):
        write_json(self.run / "run-status.json", {"run_id": self.run_id, "status": "READY"})
        write_json(self.raw, {"component": "server", "kind": "web application", "comment": support.INJECTION})
        self.publish_handoffs()


class LowerLayerRefusalTests(DispatchCase):
    chapters = ("V1", "V2")

    def test_any_exception_from_the_rendezvous_verifier_is_not_assessed_never_a_crash(self):
        with mock.patch.object(pr, "load_verified_manifest", side_effect=TypeError(MARKER)):
            pointer = self.dispatch()               # accounted, published, and nothing is assessed
        accounting = self.accounting(pointer)
        self.assertEqual(pointer["status"], "OK_WITH_GAPS")
        # With the real verifier back the disk derives another accounting: the publication is refused.
        self.assertNotEqual(self.verify(pointer), [])
        with self.assertRaises(od.DispatchRejected):
            self.load()
        self.assertEqual({cell["not_assessed_reason"] for cell in accounting["cells"]}, {"pool_unverifiable"})
        self.assertEqual({cell["terminal_class"] for cell in accounting["cells"]}, {"invalid"})
        self.assertEqual(set(dispositions(accounting)), {"not_assessed"})
        self.assertIs(accounting["pools"][0]["manifest_verified"], False)
        self.assertNotIn(MARKER, "".join(every_text(accounting)))

    def test_any_exception_from_the_adapter_verifier_is_not_assessed(self):
        pointer = self.dispatch()
        plan, specifications = self.plan(), self.specifications(pointer)
        with mock.patch.object(od, "_adapter_result", side_effect=TypeError(MARKER)):
            accounting = od.derive_accounting(plan, self.facts(), attempt=self.attempt(pointer),
                                              attempt_id=pointer["attempt_id"], specifications=specifications)
        self.assertEqual({cell["not_assessed_reason"] for cell in accounting["cells"]}, {"adapter_result_unverifiable"})
        self.assertEqual(set(dispositions(accounting)), {"not_assessed"})

    def test_a_t07_that_raises_anything_at_all_is_a_refusal(self):
        with mock.patch.object(owasp_validator_result, "publish", side_effect=TypeError(MARKER)):
            accounting = self.accounting(self.dispatch())
        self.assertEqual({cell["not_assessed_reason"] for cell in accounting["cells"]}, {"validation_unavailable"})
        self.assertEqual({cell["validation"]["outcome"] for cell in accounting["cells"]}, {"unavailable"})
        self.assertEqual(set(dispositions(accounting)), {"not_assessed"})

    def test_a_value_t07_returned_is_never_the_authority(self):
        """T07 says OK and leaves nothing on disk: the rule reads T07's files, so nothing is valid."""
        with mock.patch.object(owasp_validator_result, "publish", return_value={"status": "OK", "reused": False}):
            accounting = self.accounting(self.dispatch())
        self.assertFalse(any(cell["valid_result"] for cell in accounting["cells"]))


class NewerAttemptTests(DispatchCase):
    def test_a_newer_degraded_attempt_blocks_the_older_success_for_the_affected_rows(self):
        first = self.dispatch()
        older = self.accounting(first)
        self.assertEqual(set(dispositions(older)), {"deferred_to_validated_results"})
        older_result = self.result_pointer(2)
        second = self.dispatch(Routed({2: b14.Raising(RuntimeError(MARKER))}), force=True)
        newest = self.accounting(second)
        self.assertNotEqual(first["attempt_id"], second["attempt_id"])
        self.assertEqual(dispositions(newest), ["deferred_to_validated_results", "not_assessed",
                                                "deferred_to_validated_results"])
        # The older, still OK, T07 result of batch 2 exists and is named nowhere in the newest accounting.
        self.assertEqual(self.result_pointer(2), older_result)
        self.assertEqual(older_result["status"], "OK")
        texts = set(every_text(newest))
        self.assertNotIn(older_result["attempt_id"], texts)
        self.assertNotIn(older_result["artifacts"]["outputs/control-assessment-result.json"], texts)
        self.assertNotIn(first["attempt_id"], texts)
        self.assertIs(newest["claims_boundary"]["older_attempt_consulted"], False)
        # the rows that did succeed defer to the NEW attempt's results, never to the older ones
        for ordinal in (1, 3):
            self.assertNotEqual(self.cell(newest, ordinal)["validation"]["attempt_id"],
                                self.cell(older, ordinal)["validation"]["attempt_id"])
        self.assertEqual(od.thaw(self.load()), newest)

    def test_deleting_the_older_attempt_and_its_results_changes_nothing(self):
        first = self.dispatch()
        second = self.dispatch(Routed({2: b14.Raising(RuntimeError(MARKER))}), force=True)
        before = self.accounting_path(second).read_bytes()
        batch = self.handoff_set["handoffs"][1]["batch_id"]
        shutil.rmtree(self.attempt(first))
        shutil.rmtree(self.data / "jobs" / owasp_validator_result.JOB_ID / batch)
        self.assertEqual(self.verify(second), [])
        self.assertEqual(self.accounting_path(second).read_bytes(), before)
        self.assertEqual(od.thaw(self.load())["attempt_id"], second["attempt_id"])

    def test_a_newer_blocked_attempt_blocks_the_older_accounting_and_never_replaces_the_pointer(self):
        self.dispatch()
        accepted = (self.job_root / "accepted.json").read_bytes()
        self.request_path = self.write_request(handoffs={**self.request["handoffs"], "handoff_set_sha256": "0" * 64})
        with self.assertRaises(od.DispatchBlocked) as caught:
            self.dispatch()
        self.assertEqual(caught.exception.code, "lineage_refused")
        self.assertEqual((self.job_root / "accepted.json").read_bytes(), accepted)
        latest = json.loads((self.job_root / "latest.json").read_text("utf-8"))["attempt_id"]
        status = json.loads((self.job_root / "attempts" / latest / od.STATUS_FILE).read_text("utf-8"))
        self.assertEqual(validate_document(status, od.STATUS_SCHEMA), [])
        self.assertEqual((status["status"], status["refusal"]), ("BLOCKED", "lineage_refused"))
        with self.assertRaisesRegex(od.DispatchRejected, "older accounting is never used"):
            self.load()
        # a good dispatch afterwards is a NEW attempt, never a reuse of the blocked-over one
        self.request_path = self.write_request()
        invoker = Routed()
        again = self.dispatch(invoker)
        self.assertIs(again["reused"], False)
        self.assertEqual(sorted(invoker.invoked), [1, 2, 3])
        self.assertEqual(od.thaw(self.load())["attempt_id"], again["attempt_id"])

    def test_a_superseded_handoff_publication_fails_closed(self):
        self.dispatch()
        stale = self.request_path.read_bytes()
        self.publish_handoffs(force=True)             # a newer T06 attempt: the old request is now stale
        self.request_path.write_bytes(stale)
        invoker = Routed()
        with self.assertRaises(od.DispatchBlocked) as caught:
            self.dispatch(invoker)
        self.assertEqual(caught.exception.code, "lineage_refused")
        self.assertEqual(invoker.invoked, [])
        with self.assertRaises(od.DispatchRejected):
            self.load()


class ReuseTests(DispatchCase):
    chapters = ("V1", "V2")

    def attempts(self) -> list:
        return sorted(path.name for path in (self.job_root / "attempts").iterdir())

    def test_an_exact_replay_of_a_fully_accepted_attempt_is_reused_after_full_revalidation(self):
        first = self.dispatch()
        invoker = Routed()
        with mock.patch.object(od, "_verify", wraps=od._verify) as verified:
            again = self.dispatch(invoker)
        self.assertIs(again["reused"], True)
        self.assertEqual(verified.call_count, 1)                   # the WHOLE publication was re-derived
        self.assertEqual(again["attempt_id"], first["attempt_id"])
        self.assertEqual(invoker.invoked, [])
        self.assertEqual(self.attempts(), [first["attempt_id"]])

    def test_a_replay_that_no_longer_verifies_is_dispatched_again(self):
        first = self.dispatch()
        path = self.accounting_path(first)
        path.write_bytes(path.read_bytes().replace(b'"degraded": false', b'"degraded": true', 1))
        invoker = Routed()
        again = self.dispatch(invoker)
        self.assertIs(again["reused"], False)
        self.assertEqual(sorted(invoker.invoked), [1, 2])

    def test_an_accepted_attempt_with_a_cell_to_retry_is_not_reused(self):
        self.dispatch(Routed({2: b14.Raising(RuntimeError(MARKER))}))
        invoker = Routed()
        again = self.dispatch(invoker)
        self.assertIs(again["reused"], False)
        self.assertEqual(sorted(invoker.invoked), [1, 2])
        self.assertEqual(set(dispositions(self.accounting(again))), {"deferred_to_validated_results"})

    def changed(self, expected_code=None):
        invoker = Routed()
        if expected_code is None:
            again = self.dispatch(invoker)
            self.assertIs(again["reused"], False)
            self.assertEqual(sorted(invoker.invoked), [1, 2])
            return again
        with self.assertRaises(od.DispatchBlocked) as caught:
            self.dispatch(invoker)
        self.assertEqual(caught.exception.code, expected_code)
        self.assertEqual(invoker.invoked, [])
        return None

    def test_a_changed_model_is_not_reused(self):
        first = self.dispatch()
        self.request_path = self.write_request(model=deepcopy(b14.OTHER_MODEL))
        self.assertNotEqual(self.changed()["input_fingerprint"], first["input_fingerprint"])

    def test_a_changed_registry_record_is_not_reused_and_the_older_attempt_stops_verifying(self):
        first = self.dispatch()
        path = self.registry / "personas" / "owasp-validator.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        record["display_name"] += " (edited)"
        path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        self.assertNotEqual(self.verify(first), [])
        self.assertNotEqual(self.changed()["input_fingerprint"], first["input_fingerprint"])

    def test_a_changed_evidence_byte_is_refused(self):
        first = self.dispatch()
        self.raw.write_bytes(self.raw.read_bytes() + b"\n")
        self.assertNotEqual(self.verify(first), [])
        self.changed("evidence_refused")

    def test_a_changed_prompt_byte_is_refused(self):
        self.dispatch()
        # A relocated tracked tree (repository root, process root, configuration) that differs from
        # the real one in exactly one prompt byte; it resolves the same way on a host checkout and
        # in the code-server layout, where the process tree is not called by its repository name.
        repo = self.base / "prompt-repo"
        relocated = repo / "appsec-review-process"
        for source in sorted((od.ROOT / "config").rglob("*")):       # by content: never a read-only mode
            if source.is_file():
                copy = relocated / source.relative_to(od.ROOT)
                copy.parent.mkdir(parents=True, exist_ok=True)
                copy.write_bytes(source.read_bytes())
        prompt =relocated / "config" / "owasp-validator-handoff" / "validator-instructions-v1.txt"
        prompt.write_bytes(prompt.read_bytes() + b"\n")
        with mock.patch.object(od, "ROOT", relocated), mock.patch.object(od, "REPO_ROOT", repo), \
                mock.patch.object(od, "CONFIG_ROOT", relocated / "config" / "owasp-dispatch"):
            self.changed("prompt_refused")

    def test_a_republished_handoff_is_a_new_dispatch(self):
        first = self.dispatch()
        self.publish_handoffs(force=True)
        self.assertNotEqual(self.changed()["input_fingerprint"], first["input_fingerprint"])


class ChangedLimitTests(DispatchCase):
    chapters = ("V1",)
    max_timeout_seconds = 900

    def test_a_changed_limit_is_a_new_configuration_digest_and_is_not_reused(self):
        first = self.dispatch()
        config = json.loads((od.CONFIG_ROOT / "default-v1.json").read_text(encoding="utf-8"))
        config["cell_budgets"]["standard"]["output_file_limit"] -= 1
        write_json(od.CONFIG_ROOT / "default-v1.json", config)
        invoker = Routed()
        with self.assertRaises(od.DispatchBlocked) as caught:       # the request still pins the old digest
            self.dispatch(invoker)
        self.assertEqual(caught.exception.code, "config_refused")
        self.request_path = self.write_request(dispatch_config={
            **self.request["dispatch_config"], "config_digest": execution_state.digest(config)})
        again = self.dispatch(invoker)
        self.assertIs(again["reused"], False)
        self.assertNotEqual(again["input_fingerprint"], first["input_fingerprint"])
        self.assertNotEqual(self.verify(first), [])

    def test_a_configuration_that_enables_a_disabled_capability_with_a_number_is_refused(self):
        config = json.loads((od.CONFIG_ROOT / "default-v1.json").read_text(encoding="utf-8"))
        for name in ("dynamic_execution", "manual_observation", "network_access"):
            with self.subTest(name=name):
                edited = {**config, name: 0}            # `const: false` in the schema subset admits 0
                self.assertEqual(validate_document(edited, od.CONFIG_SCHEMA), [])
                write_json(od.CONFIG_ROOT / "default-v1.json", edited)
                self.request_path = self.write_request(dispatch_config={
                    **self.request["dispatch_config"], "config_digest": execution_state.digest(edited)})
                with self.assertRaises(od.DispatchBlocked) as caught:
                    self.dispatch()
                self.assertEqual(caught.exception.code, "config_refused")


class ZeroCellTests(DispatchCase):
    chapters = ()
    dynamic_chapters = ("V1", "V2")

    def test_empty_is_a_coverage_statement_never_an_ok_set(self):
        invoker = Routed()
        pointer = self.dispatch(invoker)
        accounting = self.accounting(pointer)
        self.assertEqual(invoker.invoked, [])
        self.assertEqual((pointer["status"], accounting["status"]), ("OK_WITH_GAPS", "OK_WITH_GAPS"))
        self.assertEqual(accounting["dispatch_outcome"], pr.EMPTY)
        self.assertEqual(len(accounting["pools"]), 1)
        pool = accounting["pools"][0]
        self.assertEqual((pool["expansion_state"], pool["empty_pool_reason"], pool["outcome"], pool["cells"]),
                         (pr.EMPTY, "scope_excluded", pr.EMPTY, 0))
        self.assertEqual(accounting["counts"]["valid_result"], 0)
        self.assertEqual(set(dispositions(accounting)), {"request_only"})
        self.assertEqual({cell["disposition"] for cell in accounting["cells"]}, {od.REQUEST_ONLY})
        self.assertEqual(self.verify(pointer), [])
        self.assertIs(self.dispatch(invoker)["reused"], True)


class NotApplicableRowTests(DispatchCase):
    """A T06 publication without any handoff is not producible (T05 refuses a request whose rules route
    nothing), so ``upstream_produced_no_work`` has no test. Rows T05 accounted without a validator
    assignment are producible, and T10 reports each of them exactly once."""
    chapters = ("V1", "V2")

    def publish_handoffs(self, **kwargs):
        rows = [self.row(control) for control in self.selected_controls()]
        rows[1].update(applicability_status="not_applicable", rationale="The component has no such surface.")
        return super().publish_handoffs(rows=rows, **kwargs)

    def test_a_row_without_a_validator_assignment_is_reported_and_never_dispatched(self):
        self.assertEqual(len(self.handoff_set["handoffs"]), 1)
        invoker = Routed()
        accounting = self.accounting(self.dispatch(invoker))
        self.assertEqual(invoker.invoked, [1])
        self.assertEqual(dispositions(accounting), ["deferred_to_validated_results", "not_a_validator_assignment"])
        skipped = next(row for row in accounting["rows"] if not row["fragments"])
        self.assertEqual((skipped["applicability_status"], skipped["worklist_disposition"]),
                         ("not_applicable", "not_applicable_accounted"))
        self.assertEqual(accounting["counts"]["rows_not_validator_assignment"], 1)
        self.assertEqual(accounting["status"], "OK")          # every dispatched cell has a valid result


class RowAccountingInvariantTests(DispatchCase):
    """A multi-batch, mixed-mode publication of the real T03-T06 chain: two static batches of one
    domain (13 rows split 12 + 1), a static batch of another domain, a request-only batch and a row
    T05 accounted as not applicable."""
    chapters = ("V1", "V2")
    dynamic_chapters = ("V3",)

    def selected_controls(self) -> list:
        chapter = [control for control in self.controls if control["group"]["chapter_id"] == "V1"][:13]
        return chapter + super().selected_controls()[1:] + [
            next(control for control in self.controls if control["group"]["chapter_id"] == "V5")]

    def publish_handoffs(self, **kwargs):
        rows = [self.row(control) for control in self.selected_controls()]
        rows[-1].update(applicability_status="not_applicable", rationale="The component has no such surface.")
        return super().publish_handoffs(rows=rows, **kwargs)

    def check(self, accounting: dict) -> None:
        worklist = self.worklist["assignments"]
        handoffs = [self.handoff(n + 1) for n in range(len(self.handoff_set["handoffs"]))]
        self.assertEqual([row["assignment_digest"] for row in accounting["rows"]],
                         [od.id_digest("assignment", item["assignment_id"]) for item in worklist])
        self.assertEqual(len({row["assignment_digest"] for row in accounting["rows"]}), len(worklist))
        expected = sorted(od.id_digest("fragment", fragment["fragment_id"])
                          for handoff in handoffs for fragment in handoff["assigned_fragments"])
        found = sorted(fragment["fragment_digest"] for row in accounting["rows"] for fragment in row["fragments"])
        self.assertEqual(found, expected)                     # every fragment of every handoff, exactly once
        self.assertEqual(len(set(found)), len(found))
        self.assertEqual(sum(cell["fragments"] for cell in accounting["cells"]), len(found))
        cells = {cell["cell_ordinal"]: cell for cell in accounting["cells"]}
        self.assertEqual(sorted(cells), list(range(1, len(handoffs) + 1)))       # every expected cell, once
        for row, item in zip(accounting["rows"], worklist):
            found_states = {fragment["disposition"] for fragment in row["fragments"]}
            if item["disposition"] != "validator_assignment":
                self.assertEqual((row["row_disposition"], row["fragments"]), ("not_a_validator_assignment", []))
                continue
            self.assertEqual(len(row["fragments"]), len(item["batch_ids"]))
            for fragment in row["fragments"]:
                cell = cells[fragment["cell_ordinal"]]
                wanted = ("request_only" if cell["disposition"] == od.REQUEST_ONLY else
                          "deferred_to_validated_result" if cell["valid_result"] else "not_assessed")
                self.assertEqual(fragment["disposition"], wanted)
                self.assertEqual(fragment["result_sha256"],
                                 cell["validation"]["result_sha256"] if cell["valid_result"] else None)
                self.assertEqual((fragment["state"], fragment["adapter_cause"]), (cell["state"], cell["adapter_cause"]))
            self.assertEqual(row["row_disposition"] == "not_assessed", "not_assessed" in found_states)
            self.assertIs(row["final_control_status_issued"], False)
        counts = accounting["counts"]
        self.assertEqual(counts["rows"], sum(counts[name] for name in (
            "rows_deferred", "rows_deferred_with_request_only", "rows_not_assessed", "rows_request_only",
            "rows_not_validator_assignment")))
        self.assertEqual(counts["fragments"], counts["fragments_deferred"] + counts["fragments_not_assessed"]
                         + counts["fragments_request_only"])
        self.assertEqual(counts["cells"], counts["request_only"] + sum(counts[name] for name in (
            "valid_result", "failed", "canceled", "timed_out", "skipped", "invalid")))

    def test_every_row_of_every_handoff_is_accounted_exactly_once_whatever_the_cells_did(self):
        modes = [entry["handoff_mode"] for entry in self.handoff_set["handoffs"]]
        self.assertEqual((modes.count(od.STATIC_MODE), modes.count(od.REQUEST_MODE)), (3, 1))
        self.assertEqual(len(self.worklist["assignments"]), 16)
        honest = self.accounting(self.dispatch())
        self.check(honest)
        self.assertEqual(honest["counts"]["rows_deferred"], 14)
        static = [entry["ordinal"] for entry in self.handoff_set["handoffs"] if entry["handoff_mode"] == od.STATIC_MODE]
        mixed = self.accounting(self.dispatch(Routed({
            static[0]: b14.Raising(RuntimeError(MARKER)), static[1]: NoCandidate()}), force=True))
        self.check(mixed)
        self.assertEqual(mixed["dispatch_outcome"], pr.DEGRADED)
        self.assertEqual(mixed["counts"]["rows_not_assessed"] + mixed["counts"]["rows_deferred"], 14)
        self.assertGreater(mixed["counts"]["rows_not_assessed"], 0)
        self.assertEqual((mixed["counts"]["rows_request_only"], mixed["counts"]["rows_not_validator_assignment"]), (1, 1))

    def test_a_request_only_row_is_never_dispatched(self):
        invoker = Routed()
        accounting = self.accounting(self.dispatch(invoker))
        dynamic = [entry["ordinal"] for entry in self.handoff_set["handoffs"] if entry["handoff_mode"] == od.REQUEST_MODE]
        self.assertEqual(len(dynamic), 1)
        self.assertNotIn(dynamic[0], invoker.invoked)
        cell = self.cell(accounting, dynamic[0])
        self.assertEqual((cell["disposition"], cell["wave"], cell["group_id"], cell["instance_id"], cell["state"]),
                         (od.REQUEST_ONLY, None, None, None, None))
        self.assertEqual(cell["validation"]["outcome"], "not_submitted")
        pointer = json.loads((self.job_root / "accepted.json").read_text("utf-8"))
        for spec in self.specifications(pointer):
            self.assertNotIn(f"cell-{dynamic[0]:04d}", [group["group_id"] for group in spec["worker_groups"]])
        self.assertIs(accounting["claims_boundary"]["dynamic_or_manual_work_authorized"], False)


class MixedModeRowTests(unittest.TestCase):
    """ASVS 5.0.0 has one proof obligation per control, so the real chain cannot produce a row whose
    obligations sit in two batches. T05's own builder can; the pure row rule is applied to its output."""

    def rows(self, static_valid: bool) -> list:
        import owasp_batching
        import test_owasp_batching as t05
        case = t05.OwaspBatchingTests("test_composite_obligations_split_and_require_join")
        case.setUp()
        self.addCleanup(case.doCleanups)
        row = case.row(case.controls[0], "server")
        row["proof_obligations"] = [
            {"obligation_id": "part-static", "text": "Inspect source.", "evidence_classification": "classified",
             "minimum_evidence_modes": ["static_source"]},
            {"obligation_id": "part-dynamic", "text": "Observe.", "evidence_classification": "classified",
             "minimum_evidence_modes": ["dynamic_runtime"]}]
        rules = [{"route_id": f"route-{name}", "selector": {
            "standard_family": "owasp_asvs", "obligation_ids": [f"part-{name}"], "control_ids": [], "domain_ids": [],
            "all_controls": False, "component_ids": [], "all_components": True}, **fields, "linked_test_ids": []}
            for name, fields in (("static", support.STATIC), ("dynamic", support.DYNAMIC))]
        request = {"run_id": case.run_id, "routing_rules": rules, "applicability": {"model_sha256": "a" * 64},
                   "component_contexts": [{"component_id": "server", "component_group_id": "application",
                                           "trust_role": "application-tier",
                                           "evidence_root_input_ids": ["component-map"]}]}
        model = {"run_id": case.run_id, "selection_id": "selection-1", "input_fingerprint": "f" * 64, "rows": [row]}
        worklist, manifest, _, _ = owasp_batching._build_outputs(request, model, case.config, case.config_digest, {}, {})
        cells, entries = [], []
        for batch in manifest["batches"]:
            dynamic = batch["primary_evidence_mode"] == "dynamic_runtime"
            cells.append(od.Cell(
                ordinal=batch["ordinal"], handoff_id="h", batch_id=batch["batch_id"], member_relative="m",
                member_sha256="0" * 64, mode=od.REQUEST_MODE if dynamic else od.STATIC_MODE,
                disposition=od.REQUEST_ONLY if dynamic else od.DISPATCHED, wave=None if dynamic else 0,
                group_id=None, handoff={}, fragments=tuple(
                    (f["fragment_id"], f["assignment_id"], f["final_control_status_authority"])
                    for f in batch["fragments"])))
            valid = not dynamic and static_valid
            entries.append({"valid_result": valid, "not_assessed_reason": None if valid or dynamic else "cell_state",
                            "instance_id": None, "state": None, "adapter_status": None, "adapter_cause": None,
                            "validation": {"attempt_id": "a" * 32, "result_sha256": "b" * 64}})
        return od.account_rows(worklist, tuple(cells), entries)

    def test_a_mixed_mode_row_keeps_both_fragments_and_neither_issues_a_final_status(self):
        (row,) = self.rows(True)
        self.assertIs(row["join_required"], True)
        self.assertEqual(row["row_disposition"], "deferred_with_request_only_fragments")
        self.assertEqual(sorted(f["disposition"] for f in row["fragments"]),
                         ["deferred_to_validated_result", "request_only"])
        self.assertEqual({f["final_control_status_authority"] for f in row["fragments"]}, {"obligation_fragment_only"})
        self.assertIs(row["final_control_status_issued"], False)

    def test_a_mixed_mode_row_whose_static_cell_has_no_valid_result_is_not_assessed(self):
        (row,) = self.rows(False)
        self.assertEqual(row["row_disposition"], "not_assessed")
        self.assertEqual(sorted(f["disposition"] for f in row["fragments"]), ["not_assessed", "request_only"])


class HostileTextTests(DispatchCase):
    chapters = ("V1", "V2")
    caveats = [support.INJECTION.strip()]

    def test_hostile_handoff_and_evidence_text_changes_nothing_but_the_pinned_bytes(self):
        self.assertIn(MARKER, json.dumps(self.handoff(1)))              # the handoff really carries it
        self.assertIn(MARKER, self.raw.read_text(encoding="utf-8"))     # and so does the evidence
        hostile = od.build_specifications(self.plan(), self.facts(), attempt_id="a" * 32, decided_at=support.NOW)

        def neutral(spec):
            spec = deepcopy(spec)
            for group in spec["worker_groups"]:
                group["persona_request"]["readable_inputs"] = [
                    {key: value for key, value in item.items() if key in ("root", "role")}
                    for item in group["persona_request"]["readable_inputs"]]
            return spec
        self.caveats = None
        write_json(self.raw, {"component": "server", "kind": "web application"})
        self.publish_handoffs(force=True)
        self.assertNotIn(MARKER, json.dumps(self.handoff(1)))
        clean = od.build_specifications(self.plan(), self.facts(), attempt_id="a" * 32, decided_at=support.NOW)
        self.assertEqual([neutral(spec) for spec in hostile], [neutral(spec) for spec in clean])

    def test_the_marker_is_never_echoed_into_a_publication_or_a_message(self):
        pointer = self.dispatch()
        for name, data in self.published_files(pointer).items():
            self.assertNotIn(MARKER.encode(), data, name)
        self.assertEqual(set(dispositions(self.accounting(pointer))), {"deferred_to_validated_results"})
        self.request_path = self.write_request(handoffs={**self.request["handoffs"], "attempt_id": "zq-" + "x" * 9})
        with self.assertRaises(od.DispatchBlocked) as caught:
            self.dispatch()
        self.assertNotIn("zq-", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)


class TrackedRegistryTests(DispatchCase):
    chapters = ("V1",)

    def test_the_tracked_composition_may_not_issue_control_verdicts_so_nothing_is_dispatched(self):
        invoker = Routed()
        with self.assertRaises(od.DispatchBlocked) as caught:
            od.dispatch(self.run_id, self.request_path, force=False,
                        runtime=self.runtime(invoker, facts=self.facts(registry_dir=pi.REGISTRY_DIR)))
        self.assertEqual(caught.exception.code, "registry_refused")
        self.assertEqual(invoker.invoked, [])
        self.assertFalse((self.job_root / "accepted.json").exists())

    def test_a_handoff_prohibition_without_an_enforced_registry_class_is_refused(self):
        config = json.loads((od.CONFIG_ROOT / "default-v1.json").read_text(encoding="utf-8"))
        config["prohibited_claim_map"] = [entry for entry in config["prohibited_claim_map"]
                                          if entry["handoff_class"] != "severity"]
        self.config_reference = self.relocate_config(config)
        self.request_path = self.write_request()
        with self.assertRaises(od.DispatchBlocked) as caught:
            self.dispatch()
        self.assertEqual(caught.exception.code, "registry_refused")


class RequiredArgumentTests(unittest.TestCase):
    def test_no_safety_input_is_optional(self):
        for function in (od.dispatch, od.verify_publication, od.load_verified_accounting, od.load_plan,
                         od.build_specifications, od.derive_accounting, od.validation_outcome, od.pool_context):
            for name, parameter in inspect.signature(function).parameters.items():
                self.assertIs(parameter.default, inspect.Parameter.empty, f"{function.__name__}({name})")
        for record in (od.DispatchFacts, od.DispatchRuntime):
            with self.assertRaises(TypeError):
                record()
            for name, parameter in inspect.signature(record).parameters.items():
                self.assertIs(parameter.default, inspect.Parameter.empty, f"{record.__name__}.{name}")

    def test_force_is_a_json_boolean_and_the_runtime_is_a_runtime(self):
        with self.assertRaises(TypeError):
            od.dispatch("run", Path("request.json"), runtime=None, force=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
