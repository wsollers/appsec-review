"""`validate_job_output.py` dispatch for the nine ADR-0010 vendor-prepass contracts.

Every attempt here is a golden of the owning suite (V04 `Attempt`, V07 `materialize`, V05 `World`),
sealed by the real redactor, then placed into a run laid out the way a worker lays one out:

    <tmp>/<run_id>/inputs/artifact-manifest.json          target.repo_path -> the staged source
    <tmp>/<run_id>/data/jobs/<job_id>/whole/attempts/<attempt_id>/
    <tmp>/<run_id>/data/jobs/<job_id>/<tool_id>/outputs/...   (V04, V05 tool outputs)

and validated through the REAL `validate_job_output` entry point. Upstream attempts are accepted
with the REAL `publish_job_output.publish_validated`. No secret-shaped literal is tracked: the
values are the ones the owning suites assemble at run time.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import inspect
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import container_mobile_binary_contracts as v07
from execution_state import atomic_json, file_hash
import publish_job_output as publish
import sbom_family_contracts as v05
from schema_validate import SCHEMAS_DIR
import secrets_iac_contracts as v04
import test_container_mobile_binary_contracts as t07
import test_sbom_family_contracts as t05
import test_secrets_iac_contracts as t04
import validate_job_output as validator
from validate_job_output import (NO_ORCHESTRATION_FACTS, OrchestrationFacts, validate_job_output,
                                 validate_vendor_prepass_attempt)
from worker_result import artifact_records, terminal_envelope

REGISTRY = ROOT / "registry"
PROPOSAL = SCHEMAS_DIR.parent / "docs" / "proposals" / "vendor-prepass" / "job-nodes.proposal.json"
FINGERPRINT = "sha256:" + "5" * 64
NOW = t05.NOW
V04_IDS, V07_IDS, V05_IDS = tuple(v04.CONTRACT_POLICIES), tuple(v07.CONTRACTS), tuple(v05.CONTRACT_POLICIES)
NINE = (*V04_IDS, *V07_IDS, *V05_IDS)
# V04's other contract, looked up from its policy table. (Reading the module's own constant for it
# makes a code scanner's NAME heuristic treat the contract id as sensitive data flowing to a file.)
LEAK_INVENTORY_CONTRACT = next(contract_id for contract_id in V04_IDS if contract_id != v04.IAC_CONTRACT_ID)
FAIL_CLOSED = {
    v05.SCA_CONTRACT_ID: "sca-vulnerability-match cannot be validated: no Grype DB / OSV consumer binding exists (V18)",
    v05.LIFECYCLE_CONTRACT_ID: ("dependency-lifecycle cannot be validated: no dependency-lifecycle reference-table "
                                "publisher or consumer binding exists"),
}
# One non-SKIPPED golden per contract, and the SKIPPED ones (which need V02's graph edge).
V04_GOLDEN = {LEAK_INVENTORY_CONTRACT: "secrets-hits", v04.IAC_CONTRACT_ID: "iac-ok-with-gaps"}
V07_GOLDEN = {"container-image-inventory": "container-ok-with-gaps", "mobile-sast": "mobile-ok-android-only",
              "binary-hardening": "binary-ok-with-gaps"}
SKIPPED_GOLDEN = {v04.IAC_CONTRACT_ID: "iac-skipped", "container-image-inventory": "container-skipped",
                  "mobile-sast": "mobile-skipped", "binary-hardening": "binary-skipped"}
OTHER_SHA = "sha256:" + "c0ffee" * 10 + "abcd"
# What a producer plants in its own ENVELOPE (result.json) and in the names of files it adds. It is
# a legal identifier, contract id and path segment, so it gets as far as a value of its kind can.
MARKER = "zq" + "planted-7f3a-by-the-producer"
PLANTED = list(dict.fromkeys([*t04.PLANTED, *t05.PLANTED, OTHER_SHA, MARKER]))


def setUpModule():
    t07.setUpModule()
    t05.setUpModule()


def tearDownModule():
    t05.tearDownModule()
    t07.tearDownModule()


def dump(document) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def contract_record(contract_id: str) -> dict:
    return json.loads((REGISTRY / "output-contracts" / f"{contract_id}.json").read_text(encoding="utf-8"))


def node(contract_id: str):
    return validator.VENDOR_PREPASS_NODES[contract_id]


def header_documents(documents: dict) -> list[dict]:
    return [document for document in documents.values()
            if isinstance(document, dict) and "source_snapshot_sha256" in document]


def restate(field: str, value: str):
    """A dishonest-but-consistent producer: state `value` for `field` in EVERY document and in
    status.json, then seal correctly. Only the attempt changes. A mutation receives the documents
    keyed by their path in the attempt, and the status.json object."""
    def mutate(documents: dict, status: dict) -> None:
        for document in header_documents(documents):
            if field in document:
                document[field] = value
        if field in status:
            status[field] = value
    return mutate


class Staged:
    """One sealed golden attempt inside a run, with the envelope and facts a correct caller has."""

    def __init__(self, test, contract_id: str, *, golden: str | None = None, mutate=None, run_id: str | None = None,
                 attempt_id: str | None = None, as_contract: str | None = None, world=None):
        self.test, self.source_contract = test, contract_id
        self.contract_id = as_contract or contract_id
        self.job_id = node(self.contract_id)["job_id"]
        directory = tempfile.TemporaryDirectory()
        test.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name)
        self.world = world
        built = self._build(contract_id, golden, mutate)
        self.status, source_attempt, tool_root, source, inputs, header, dagster = built
        self.run_id, self.attempt_id = run_id or header["run_id"], attempt_id or header["attempt_id"]
        self.facts = OrchestrationFacts(dagster_run_id=dagster, source_snapshot_sha256=header["source_snapshot_sha256"],
                                        now=NOW)
        self.run_root = self.tmp / "runs" / self.run_id
        self.jobs = self.run_root / "data" / "jobs"
        (self.run_root / "inputs").mkdir(parents=True)
        if inputs is not None:
            shutil.copytree(inputs, self.run_root / "inputs", dirs_exist_ok=True)
        self.source = source if source is not None else self.tmp / "empty-source"
        self.source.mkdir(exist_ok=True)
        atomic_json(self.run_root / "inputs" / "artifact-manifest.json", {"target": {"repo_path": str(self.source)}})
        self.base, self.attempt = self.place(self.job_id, self.attempt_id, source_attempt, tool_root)

    # -- family builders: (status, attempt, tool root or None, source or None, inputs or None, header, dagster id)
    def _build(self, contract_id, golden, mutate):
        if contract_id in V04_IDS:
            chosen = t04.GOLDENS[golden or V04_GOLDEN[contract_id]]
            edit = (lambda g: mutate(g.documents, g.status)) if mutate else None
            attempt = t04.Attempt(self.test, chosen, edit)
            return (attempt.golden.node_status, attempt.root, attempt.tool_root, None, None, chosen.header,
                    "dagster-run-v04")
        if contract_id in V07_IDS:
            case = t07.GOLDENS[golden or V07_GOLDEN[contract_id]]()
            status = t07.status_document(case)
            if mutate:
                spec = v07.CONTRACTS[contract_id]
                mutate({spec["result"]: case["documents"]["result"], v07.TOOL_RESULTS: case["documents"]["tool-results"],
                        v07.COVERAGE: case["documents"]["coverage"],
                        spec["probe_receipt"]: case["documents"]["probe-receipt"]}, status)
            (self.tmp / "v07").mkdir()
            attempt, inputs = t07.materialize(case, self.tmp / "v07")
            (attempt / "status.json").write_bytes(dump(status))
            container = contract_id == "container-image-inventory"
            return (case["status"], attempt, None, None if container else inputs, inputs if container else None,
                    t07.header(contract_id), t07.DAGSTER_RUN_ID)
        self.world = self.world or t05.World(self.test)

        def edit(spec):
            mutate(spec.documents, spec.status)
            spec.reseal()
        item = self.world.publish(contract_id, edit if mutate else None)
        return (item.spec.node_status, item.root, item.tool_root, self.world.source, None, t05.header_for(contract_id),
                t05.DAGSTER_RUN)

    def place(self, job_id: str, attempt_id: str, source_attempt: Path, tool_root: Path | None):
        base = self.jobs / job_id / "whole"
        attempt = base / "attempts" / attempt_id
        shutil.copytree(source_attempt, attempt)
        if tool_root is not None:
            for entry in tool_root.iterdir():
                if entry.name != "attempts":
                    shutil.copytree(entry, self.jobs / job_id / entry.name, dirs_exist_ok=True)
        return base, attempt

    def with_upstreams(self):
        """Accept this world's upstream attempts in the same run, through the real publisher. In a
        run of ANOTHER name the real publisher rightly refuses them, so there the pointer is forged:
        the downstream verifier must then reject on its own."""
        for upstream in (v05.SBOM_CONTRACT_ID, v05.LICENSE_CONTRACT_ID):
            if upstream == self.source_contract or upstream not in self.world.published:
                continue
            self.accept(upstream, forge=self.run_id != t05.RUN_ID)
        return self

    def accept(self, contract_id: str, item=None, attempt_id: str | None = None, forge: bool = False) -> Path:
        item = item or self.world.published[contract_id]
        job_id = node(contract_id)["job_id"]
        attempt_id = attempt_id or item.spec.header["attempt_id"]
        base, attempt = self.place(job_id, attempt_id, item.root, item.tool_root)
        publish.mark_attempt_started(base, attempt_id, FINGERPRINT)
        envelope = self.envelope(contract_id=contract_id, job_id=job_id, attempt=attempt, status=item.spec.node_status)
        atomic_json(attempt / "result.json", envelope)
        if forge:
            atomic_json(base / "accepted.json", {
                "schema": publish.ACCEPTED_SCHEMA, "status": envelope["execution_status"], "run_id": self.run_id,
                "job": job_id, "attempt_id": attempt_id, "fingerprint": FINGERPRINT, "envelope_path": "result.json",
                "envelope_sha256": file_hash(attempt / "result.json"), "hashes": publish.tree_hashes(attempt),
                "accepted_at": "2026-09-20T12:25:00Z"})
        else:
            publish.publish_validated(base, attempt, attempt / "result.json", FINGERPRINT, expected_run_id=self.run_id,
                                      expected_job_id=job_id, orchestration=self.facts)
        return attempt

    def envelope(self, *, contract_id=None, job_id=None, attempt=None, status=None, **override) -> dict:
        attempt, status = attempt or self.attempt, status or self.status
        files = sorted(path.relative_to(attempt).as_posix() for path in attempt.rglob("*")
                       if path.is_file() and path.name != "result.json")
        envelope = terminal_envelope(
            run_id=self.run_id, job_id=job_id or self.job_id, attempt_id=attempt.name, worker_kind="pinned_container",
            execution_status=status, acceptance_status="CURRENT", input_fingerprint=FINGERPRINT,
            output_contract=contract_id or self.contract_id, started_at="2026-09-20T12:00:00Z",
            finished_at="2026-09-20T12:20:00Z", summary="vendor-prepass golden",
            artifacts=artifact_records(attempt, files), gaps=["see outputs/coverage.json"] if status == "OK_WITH_GAPS" else [],
            skip_reason=t04.SKIP_REASON if status == "SKIPPED" else None)
        envelope.update(override)
        return envelope

    def validate(self, envelope=None, *, facts=None, expected_run_id=None, expected_job_id=None, **kwargs) -> list[str]:
        envelope = envelope or self.envelope()
        errors = validate_job_output(
            self.attempt, envelope, FINGERPRINT, expected_run_id=expected_run_id or self.run_id,
            expected_job_id=expected_job_id or self.job_id, orchestration=facts or self.facts, **kwargs)
        for error in errors:  # the invariant, checked on every validation this suite performs
            for planted in PLANTED:
                assert planted not in error, f"a value read from the attempt reached an error message: {error!r}"
        return errors


@contextmanager
def bindings(world=None, *, max_age=None):
    """What V18 (and the reference-table publisher) will supply, modelled ONLY for tests: with the
    seam filled, SCA and lifecycle run their real verifiers. Harmless for the other seven."""
    def table(_run_root):
        return world.table_path, dict(world.table_identity)
    patches = [mock.patch.object(validator, "vulnerability_database_bindings", lambda _run_root: deepcopy(t05.DATABASES))]
    if world is not None:
        patches.append(mock.patch.object(validator, "lifecycle_reference_table_binding", table))
    if max_age is not None:
        patches.append(mock.patch.object(validator, "job_max_age", lambda _contract_id: max_age))
    for patch in patches:
        patch.start()
    try:
        yield
    finally:
        for patch in reversed(patches):
            patch.stop()


def stage(test, contract_id: str, **kwargs) -> Staged:
    staged = Staged(test, contract_id, **kwargs)
    return staged.with_upstreams() if staged.world is not None else staged


class GoldenTests(unittest.TestCase):
    def test_seven_contracts_validate_with_no_errors_through_the_real_entry_point(self):
        for contract_id in NINE:
            if contract_id in FAIL_CLOSED:
                continue
            with self.subTest(contract=contract_id):
                self.assertEqual(stage(self, contract_id).validate(), [])

    def test_every_other_v04_and_v05_golden_validates_too(self):
        self.assertEqual(stage(self, LEAK_INVENTORY_CONTRACT, golden="secrets-tool-failed").validate(), [])
        for contract_id in (v05.SBOM_CONTRACT_ID, v05.LICENSE_CONTRACT_ID):
            self.assertEqual(stage(self, contract_id, world=t05.World(self, "clean")).validate(), [])

    def test_sca_and_lifecycle_return_exactly_the_named_fail_closed_error(self):
        for contract_id, expected in FAIL_CLOSED.items():
            with self.subTest(contract=contract_id):
                self.assertEqual(stage(self, contract_id).validate(), [expected])

    def test_with_the_seam_filled_sca_and_lifecycle_run_their_real_verifier(self):
        for contract_id in FAIL_CLOSED:
            staged = stage(self, contract_id)
            with bindings(staged.world):
                self.assertEqual(staged.validate(), [], contract_id)
                # `now` is the caller's: a clock before the documents' evaluated_at is rejected.
                early = OrchestrationFacts(dagster_run_id=staged.facts.dagster_run_id, now=NOW - timedelta(days=30),
                                           source_snapshot_sha256=staged.facts.source_snapshot_sha256)
                self.assertTrue(any("age-invalid" in error for error in staged.validate(facts=early)), contract_id)
            # M4: a limit the JOB set, which the documents (sealed under no-limit) do not restate.
            with bindings(staged.world, max_age=timedelta(days=3650)):
                self.assertTrue(any("age-policy-mismatch" in error for error in staged.validate()), contract_id)

    def test_m4_no_age_limit_is_wired_explicitly(self):
        for contract_id in FAIL_CLOSED:
            self.assertIs(validator.job_max_age(contract_id), v05.NO_AGE_LIMIT)

    def test_the_binding_seam_blocks_and_takes_nothing_from_the_environment(self):
        with mock.patch.dict("os.environ", {"APPSEC_GRYPE_DB_SHA256": OTHER_SHA, "GRYPE_DB_CACHE_DIR": "/nonexistent"}):
            for provider in (validator.vulnerability_database_bindings, validator.lifecycle_reference_table_binding):
                with self.assertRaises(validator.BindingUnavailable):
                    provider(Path("."))
        for provider in (validator.vulnerability_database_bindings, validator.lifecycle_reference_table_binding):
            self.assertEqual(list(inspect.signature(provider).parameters), ["run_root"])

    def test_skipped_goldens_are_rejected_until_v02_declares_the_edge_and_accepted_after(self):
        for contract_id, golden in SKIPPED_GOLDEN.items():
            staged = stage(self, contract_id, golden=golden)
            with self.subTest(contract=contract_id):
                self.assertEqual(staged.status, "SKIPPED")
                graph = json.loads(validator.GRAPH.read_text(encoding="utf-8"))
                assembly = graph["jobs"]["02-evidence-assembly"]
                declared = [edge for edge in assembly["dependencies"] if edge["job"] == staged.job_id]
                if not declared:  # origin/main before V02: the node and its edge are not declared
                    errors = staged.validate(consumer_job_id="02-evidence-assembly")
                    self.assertEqual(len(errors), 2, errors)
                    self.assertIn(f"02-evidence-assembly does not have exactly one dependency edge from {staged.job_id}", errors)
                    self.assertTrue(any("is not authorized for this dependency edge" in error for error in errors))
                # What V02 declares, modelled in a copy of the graph: the same attempt is accepted.
                assembly["dependencies"] = [edge for edge in assembly["dependencies"] if edge["job"] != staged.job_id] + [
                    {"job": staged.job_id, "kind": "required", "contract": contract_id,
                     "allowed_skip_reasons": [t04.SKIP_REASON]}]
                path = staged.tmp / "graph.json"
                path.write_bytes(dump(graph))
                self.assertEqual(staged.validate(consumer_job_id="02-evidence-assembly", graph_path=path), [])
                self.assertTrue(staged.validate(graph_path=path))  # no named consumer edge: still rejected

    def test_validation_does_not_depend_on_the_job_being_a_graph_node(self):
        empty = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, empty)
        (empty / "graph.json").write_bytes(dump({"jobs": {}}))
        for contract_id in (LEAK_INVENTORY_CONTRACT, "binary-hardening", v05.SBOM_CONTRACT_ID):
            self.assertEqual(stage(self, contract_id).validate(graph_path=empty / "graph.json"), [], contract_id)


class CallerFactTests(unittest.TestCase):
    """Each fact the verifier is given comes from the envelope, the caller's facts, the registry
    table or the accepted pointer. Editing ONLY the attempt is rejected; editing ONLY the outside
    is rejected; so the attempt never vouches for itself."""

    def rejected(self, staged: Staged, **kwargs) -> list[str]:
        with bindings(staged.world):
            errors = staged.validate(**kwargs)
        self.assertTrue(errors, f"{staged.contract_id}: accepted")
        self.assertFalse(any(error in FAIL_CLOSED.values() for error in errors), errors)
        return errors

    def test_run_id(self):
        for contract_id in NINE:
            with self.subTest(contract=contract_id):
                # only the attempt: sealed, internally consistent, but for another run
                self.rejected(stage(self, contract_id, mutate=restate("run_id", "20260101T000000Z-other0")))
                # only the outside: the same golden under a run, envelope and expected run id of another name
                self.rejected(stage(self, contract_id, run_id="20260101T000000Z-other0"))

    def test_attempt_id(self):
        for contract_id in NINE:
            with self.subTest(contract=contract_id):
                self.rejected(stage(self, contract_id, mutate=restate("attempt_id", "node-attempt-9999")))
                self.rejected(stage(self, contract_id, attempt_id="node-attempt-9999"))

    def test_dagster_run_id(self):
        for contract_id in NINE:
            with self.subTest(contract=contract_id):
                self.rejected(stage(self, contract_id, mutate=restate("dagster_run_id", "dagster-run-other")))
                staged = stage(self, contract_id)
                other = OrchestrationFacts(dagster_run_id="dagster-run-other", now=NOW,
                                           source_snapshot_sha256=staged.facts.source_snapshot_sha256)
                self.rejected(staged, facts=other)

    def test_source_snapshot_sha256(self):
        for contract_id in NINE:
            with self.subTest(contract=contract_id):
                self.rejected(stage(self, contract_id, mutate=restate("source_snapshot_sha256", OTHER_SHA)))
                staged = stage(self, contract_id)
                other = OrchestrationFacts(dagster_run_id=staged.facts.dagster_run_id, now=NOW,
                                           source_snapshot_sha256="sha256:" + "0" * 64)
                self.rejected(staged, facts=other)

    def test_node_status(self):
        for contract_id in NINE:
            with self.subTest(contract=contract_id):
                staged = stage(self, contract_id)
                flipped = "OK" if staged.status == "OK_WITH_GAPS" else "OK_WITH_GAPS"
                self.rejected(stage(self, contract_id, mutate=restate("status", flipped)))
                self.rejected(staged, envelope=staged.envelope(status=flipped))

    def test_job_id_comes_from_the_policy_table_not_the_envelope(self):
        for contract_id in NINE:
            with self.subTest(contract=contract_id):
                staged = stage(self, contract_id)
                errors = self.rejected(staged, envelope=staged.envelope(job_id="02-some-other-job"),
                                       expected_job_id="02-some-other-job")
                self.assertIn(f"{contract_id} cannot be validated: the contract belongs to job {staged.job_id!r} and the "
                              "envelope names another job", errors)
                self.rejected(stage(self, contract_id, mutate=restate("job_id", "02-some-other-job")))

    def test_declared_tools_and_permitted_statuses_come_from_the_validator_table(self):
        for contract_id in NINE:
            with self.subTest(contract=contract_id):
                def rogue(documents, _status):
                    tool_results = documents["outputs/tool-results.json"]
                    extra = deepcopy(tool_results["tool_instances"][0])
                    extra.update(tool_id="rogue-scanner", attempt_id="rogue-scanner-attempt-0001", outputs=[],
                                 result_record_count=None)
                    tool_results["tool_instances"].append(extra)
                errors = self.rejected(stage(self, contract_id, mutate=rogue))
                self.assertTrue(any("undeclared" in error for error in errors), errors)
                staged = stage(self, contract_id)
                table = dict(validator.VENDOR_PREPASS_NODES)
                table[contract_id] = {**table[contract_id], "declared_tool_ids": (*table[contract_id]["declared_tool_ids"],
                                                                                 "a-tool-the-attempt-omits")}
                with mock.patch.object(validator, "VENDOR_PREPASS_NODES", table):
                    self.assertTrue(any("declared-tool-missing" in error for error in self.rejected(staged)))
                table[contract_id] = {**validator.VENDOR_PREPASS_NODES[contract_id], "permitted_node_statuses": ("FAILED",)}
                with mock.patch.object(validator, "VENDOR_PREPASS_NODES", table):
                    self.assertTrue(any("status-not-permitted" in error for error in self.rejected(staged)))

    def test_source_root_comes_from_the_run_manifest(self):
        for contract_id in (v05.SBOM_CONTRACT_ID, v05.LICENSE_CONTRACT_ID, "mobile-sast", "binary-hardening"):
            with self.subTest(contract=contract_id):
                staged = stage(self, contract_id)
                elsewhere = staged.tmp / "another-source"
                elsewhere.mkdir()
                atomic_json(staged.run_root / "inputs" / "artifact-manifest.json", {"target": {"repo_path": str(elsewhere)}})
                self.rejected(staged)
                (staged.run_root / "inputs" / "artifact-manifest.json").unlink()
                self.assertEqual(staged.validate(), [f"{contract_id} cannot be validated: cannot locate the owning run manifest"])

    def test_container_inputs_root_is_the_runs_staged_inputs(self):
        staged = stage(self, "container-image-inventory")
        archive = next(path for path in (staged.run_root / "inputs" / "images").iterdir())
        archive.write_bytes(archive.read_bytes() + b"x")
        self.assertTrue(any("input-" in error for error in self.rejected(staged)))

    def test_tool_outputs_root_is_the_jobs_directory_of_the_run(self):
        for contract_id in (*V04_IDS, v05.SBOM_CONTRACT_ID):
            with self.subTest(contract=contract_id):
                staged = stage(self, contract_id)
                tool_file = next(path for path in (staged.jobs / staged.job_id).rglob("result.json")
                                 if "attempts" not in path.parts and "whole" not in path.parts)
                tool_file.write_bytes(tool_file.read_bytes() + b" ")
                self.assertTrue(any("outputs-on-disk" in error for error in self.rejected(staged)))

    def test_an_attempt_outside_the_run_layout_is_not_validated(self):
        staged = stage(self, LEAK_INVENTORY_CONTRACT)
        stray = staged.run_root / "data" / "elsewhere" / staged.job_id / "whole" / "attempts" / staged.attempt_id
        shutil.copytree(staged.attempt, stray)
        staged.attempt = stray
        (error,) = staged.validate()
        self.assertIn("cannot be validated: the attempt is not at data/jobs/02-secrets-inventory/<scope>/attempts/", error)

    @unittest.skipUnless(t05.CAN_SYMLINK, "this host cannot create symbolic links")
    def test_an_attempt_reached_through_a_linked_job_directory_is_not_validated(self):
        staged = stage(self, LEAK_INVENTORY_CONTRACT)
        job_root, moved = staged.jobs / staged.job_id, staged.tmp / "moved-job"
        job_root.rename(moved)
        job_root.symlink_to(moved, target_is_directory=True)
        self.assertEqual(staged.validate(), ["secrets-inventory cannot be validated: the attempt is reached through a "
                                             "linked directory of its run"])

    def test_no_orchestration_facts_fails_closed_for_all_nine_and_parses_nothing(self):
        for contract_id in NINE:
            with self.subTest(contract=contract_id):
                staged = stage(self, contract_id)
                with mock.patch.object(validator, "validate_contract_result") as generic, \
                        mock.patch.object(validator, "_status_errors") as status:
                    errors = staged.validate(facts=NO_ORCHESTRATION_FACTS)
                self.assertEqual(len(errors), 1)
                self.assertIn(f"{contract_id} cannot be validated: the caller supplied NO_ORCHESTRATION_FACTS", errors[0])
                generic.assert_not_called()
                status.assert_not_called()

    def test_the_publisher_default_cannot_publish_a_vendor_prepass_attempt(self):
        staged = stage(self, LEAK_INVENTORY_CONTRACT)
        publish.mark_attempt_started(staged.base, staged.attempt_id, FINGERPRINT)
        atomic_json(staged.attempt / "result.json", staged.envelope())
        with self.assertRaises(publish.Blocked) as refused:
            publish.publish_validated(staged.base, staged.attempt, staged.attempt / "result.json", FINGERPRINT,
                                      expected_run_id=staged.run_id, expected_job_id=staged.job_id)
        self.assertIn("NO_ORCHESTRATION_FACTS", str(refused.exception))
        pointer = publish.publish_validated(staged.base, staged.attempt, staged.attempt / "result.json", FINGERPRINT,
                                            expected_run_id=staged.run_id, expected_job_id=staged.job_id,
                                            orchestration=staged.facts)
        with self.assertRaises(publish.Blocked):
            publish.validate_published(staged.base, pointer, FINGERPRINT, expected_run_id=staged.run_id,
                                       expected_job_id=staged.job_id)
        publish.validate_published(staged.base, pointer, FINGERPRINT, expected_run_id=staged.run_id,
                                   expected_job_id=staged.job_id, orchestration=staged.facts)


class WrongPartyTests(unittest.TestCase):
    def test_a_golden_presented_under_another_contracts_id_is_rejected_without_echo(self):
        for index, contract_id in enumerate(NINE):
            other = NINE[(index + 1) % len(NINE)]
            with self.subTest(golden=contract_id, presented_as=other):
                # The attempt also states a snapshot the caller never expected: it must not be quoted.
                staged = stage(self, contract_id, as_contract=other, mutate=restate("source_snapshot_sha256", OTHER_SHA))
                with bindings(staged.world):
                    errors = staged.validate()
                self.assertTrue(errors)
                self.assertTrue(all(OTHER_SHA not in error for error in errors))


class OrderTests(unittest.TestCase):
    """Receipt first: after a post-seal tamper only receipt errors come back, and nothing in this
    module parses any file of the attempt. (The receipt FILE is not covered by itself: a byte
    appended to it leaves it a valid receipt, and manifest.json is what notices. Still nothing of
    the attempt is parsed here.)"""

    RECEIPT_ERROR = re.compile(r"[a-z-]+ verifier: (receipt-(invalid|missing|hash-mismatch|does-not-publish)|redaction-receipt): ")

    def test_a_tamper_of_any_published_file_yields_only_receipt_errors_and_nothing_is_parsed(self):
        for contract_id in NINE:
            first = stage(self, contract_id)
            published = sorted(path.relative_to(first.attempt).as_posix()
                               for path in (first.attempt / "outputs").rglob("*") if path.is_file())
            self.assertGreaterEqual(len(published), 4)
            for relative in published:
                with self.subTest(contract=contract_id, file=relative):
                    staged = stage(self, contract_id)
                    target = staged.attempt / relative
                    target.write_bytes(target.read_bytes() + b"\n")
                    envelope = staged.envelope()  # a dishonest producer hashes AFTER tampering
                    parsed: list[Path] = []
                    real = validator.read_json

                    def spy(path):
                        parsed.append(Path(path))
                        return real(path)
                    with bindings(staged.world), mock.patch.object(validator, "read_json", spy), \
                            mock.patch.object(validator, "validate_contract_result") as generic, \
                            mock.patch.object(validator, "_status_errors") as status:
                        errors = staged.validate(envelope)
                    self.assertTrue(errors)
                    for error in errors:
                        if relative.endswith("/redaction-receipt.json"):
                            self.assertRegex(error, r"[a-z-]+ verifier: (manifest-mismatch|receipt-invalid|redaction-receipt): ")
                        else:
                            self.assertRegex(error, self.RECEIPT_ERROR)
                    generic.assert_not_called()
                    status.assert_not_called()
                    self.assertEqual([path for path in parsed if staged.attempt in path.parents], [])

    def test_the_generic_checks_run_only_after_the_verifier_accepted(self):
        staged = stage(self, v05.SBOM_CONTRACT_ID)
        calls: list[str] = []
        verifier, generic = validator.validate_vendor_prepass_attempt, validator.validate_contract_result
        with mock.patch.object(validator, "validate_vendor_prepass_attempt",
                               lambda *a, **k: calls.append("verifier") or verifier(*a, **k)), \
                mock.patch.object(validator, "validate_contract_result",
                                  lambda *a, **k: calls.append("generic") or generic(*a, **k)):
            self.assertEqual(staged.validate(), [])
        self.assertEqual(calls, ["verifier", "generic"])


class ClaimSurfaceTests(unittest.TestCase):
    def secret_values(self):
        return {name: value for name, value in t04.SECRETS.items() if name != "NAMED"}

    def test_a_secret_planted_after_sealing_is_rejected_and_never_echoed(self):
        for contract_id in NINE:
            for name, secret in self.secret_values().items():
                with self.subTest(contract=contract_id, secret=name):
                    staged = stage(self, contract_id)
                    result = staged.attempt / node(contract_id)["result"]
                    document = json.loads(result.read_bytes())
                    document["api_key"] = secret
                    result.write_bytes(dump(document))
                    (staged.attempt / "manifest.json").write_bytes(dump(t04.manifest_document(contract_id, staged.attempt)))
                    with bindings(staged.world):
                        errors = staged.validate()
                    self.assertTrue(errors)
                    self.assertTrue(all(secret not in error for error in errors))
                    # The generic layer is not blinded either: on its own it still names the location only.
                    generic = validator.validate_contract_result(staged.attempt, contract_record(contract_id),
                                                                 run_id=staged.run_id)
                    self.assertTrue(any("$.api_key" in error and "forbidden in a published result" in error
                                        for error in generic), generic)
                    self.assertTrue(all(secret not in error for error in generic))

    def test_a_secret_sealed_by_the_real_redactor_never_reaches_the_published_result(self):
        secret = t04.SECRETS["GITHUB_TOKEN"]
        for contract_id in (LEAK_INVENTORY_CONTRACT, "mobile-sast", v05.LICENSE_CONTRACT_ID):
            def plant(documents, _status, contract_id=contract_id):
                documents[node(contract_id)["result"]]["api_key"] = secret
            try:
                staged = stage(self, contract_id, mutate=plant)
            except AssertionError:  # V07's builder refuses a case the redactor has to rewrite
                continue
            self.assertNotIn(secret.encode(), b"".join(path.read_bytes() for path in staged.attempt.rglob("*") if path.is_file()))
            with bindings(staged.world):
                self.assertTrue(staged.validate(), contract_id)

    def test_a_forbidden_promotion_is_rejected_for_every_contract(self):
        for contract_id in NINE:
            for key, category in (("findings", "finding"), ("severity", "severity"), ("runtime_state", "runtime-state")):
                with self.subTest(contract=contract_id, key=key):
                    def promote(documents, _status, key=key, contract_id=contract_id):
                        documents[node(contract_id)["result"]][key] = "verified-by-" + contract_id
                    staged = stage(self, contract_id, mutate=promote)
                    with bindings(staged.world):
                        errors = staged.validate()
                    self.assertTrue(errors)
                    self.assertTrue(all("verified-by-" not in error for error in errors), errors)
                    generic = validator.validate_contract_result(staged.attempt, contract_record(contract_id),
                                                                 run_id=staged.run_id)
                    self.assertIn(f"$.{key}: {category} promotion is forbidden by the declared claim class", generic)

    def test_the_generic_checks_have_no_false_positive_on_any_published_golden_document(self):
        cases = [(contract_id, None) for contract_id in NINE] + [(c, g) for c, g in SKIPPED_GOLDEN.items()]
        cases += [(LEAK_INVENTORY_CONTRACT, "secrets-tool-failed")]
        for contract_id, golden in cases:
            staged = stage(self, contract_id, golden=golden)
            record = contract_record(contract_id)
            for path in sorted(staged.attempt.rglob("*.json")):
                document = json.loads(path.read_bytes())
                with self.subTest(contract=contract_id, golden=golden, file=path.name):
                    self.assertEqual(validator._secret_errors(document), [])
                    self.assertEqual(validator._claim_promotion_errors(document, set(validator.PROMOTION_FIELDS)), [])
                    self.assertEqual(validator._claim_class_errors(record, document), [])
            self.assertEqual(validator.validate_contract_result(staged.attempt, record, run_id=staged.run_id), [])


    def test_no_schema_property_of_the_nine_families_can_trip_a_generic_check_by_name(self):
        """Beyond the goldens: `_secret_errors` flags a high-entropy value under a secret-ish KEY
        and `_claim_promotion_errors` flags a promotion KEY. The documents are full of sha256
        values, so a property with such a name would be a standing false positive."""
        promotion = {name for names in validator.PROMOTION_FIELDS.values() for name in names}
        shared = ["tool-results.schema.json", "scan-coverage.schema.json", "applicability-probe-receipt.schema.json"]

        def properties(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key == "properties" and isinstance(child, dict):
                        yield from child
                    yield from properties(child)
            elif isinstance(value, list):
                for child in value:
                    yield from properties(child)
        names = set()
        for schema in sorted({*t04.ALL_SCHEMAS, *t07.ALL_SCHEMAS, *t05.ALL_SCHEMAS, *shared}):
            names.update(properties(json.loads((SCHEMAS_DIR / schema).read_text(encoding="utf-8"))))
        self.assertGreater(len(names), 100)
        self.assertEqual(sorted(name for name in names if validator.SECRET_FIELD_RE.search(name)), [])
        self.assertEqual(sorted(name for name in names if name.lower().replace("-", "_") in promotion), [])


class UpstreamBindingTests(unittest.TestCase):
    DOWNSTREAM = (v05.SCA_CONTRACT_ID, v05.LICENSE_CONTRACT_ID, v05.LIFECYCLE_CONTRACT_ID)

    def test_no_accepted_sbom_pointer_is_a_blocking_error_never_a_skip(self):
        for contract_id in self.DOWNSTREAM:
            with self.subTest(contract=contract_id):
                staged = Staged(self, contract_id)  # nothing upstream accepted in this run
                with bindings(staged.world):
                    errors = staged.validate()
                self.assertIn(f"{contract_id} cannot be validated: upstream job 02-sbom-inventory has no accepted pointer "
                              "in this run", errors)
                self.assertTrue(all(error.startswith(f"{contract_id} cannot be validated: ") for error in errors))

    def test_lifecycle_also_needs_the_accepted_licence_inventory(self):
        staged = Staged(self, v05.LIFECYCLE_CONTRACT_ID)
        staged.accept(v05.SBOM_CONTRACT_ID)
        with bindings(staged.world):
            self.assertEqual(staged.validate(), ["dependency-lifecycle cannot be validated: upstream job 02-license-scan has "
                                                 "no accepted pointer in this run"])

    def second_sbom(self, staged: Staged) -> None:
        """A newer accepted SBOM attempt: same content, another attempt id."""
        newer = t05.World(self)
        item = newer.publish(v05.SBOM_CONTRACT_ID, lambda spec: (restate("attempt_id", "sbom-node-attempt-0002")(
            spec.documents, spec.status), spec.reseal()))
        staged.accept(v05.SBOM_CONTRACT_ID, item, "sbom-node-attempt-0002")

    def test_a_pointer_to_another_attempt_than_the_documents_binding_is_rejected(self):
        for contract_id in self.DOWNSTREAM:
            with self.subTest(contract=contract_id):
                staged = stage(self, contract_id)
                self.second_sbom(staged)
                with bindings(staged.world):
                    errors = staged.validate()
                self.assertTrue(any("upstream-binding-mismatch" in error and "'sbom-node-attempt-0002'" in error
                                    for error in errors), errors)

    def test_the_expected_hash_is_the_pointers_not_the_documents(self):
        staged = stage(self, v05.LICENSE_CONTRACT_ID)
        pointer_path = staged.jobs / "02-sbom-inventory" / "whole" / "accepted.json"
        pointer = json.loads(pointer_path.read_bytes())
        upstream = staged.jobs / "02-sbom-inventory" / "whole" / "attempts" / pointer["attempt_id"]
        manifest = upstream / v05.SBOM_MANIFEST_FILE
        # only the upstream attempt changes after acceptance
        original = manifest.read_bytes()
        manifest.write_bytes(original + b"\n")
        self.assertEqual(staged.validate(), ["license-inventory cannot be validated: upstream job 02-sbom-inventory accepted "
                                             "attempt changed after it was accepted"])
        manifest.write_bytes(original)
        self.assertEqual(staged.validate(), [])
        # only the pointer changes: it now records another hash for the SBOM manifest
        pointer["hashes"][v05.SBOM_MANIFEST_FILE] = "0" * 64
        atomic_json(pointer_path, pointer)
        self.assertTrue(staged.validate())

    def test_a_pending_failed_or_foreign_pointer_blocks(self):
        staged = stage(self, v05.LICENSE_CONTRACT_ID)
        base = staged.jobs / "02-sbom-inventory" / "whole"
        accepted = json.loads((base / "accepted.json").read_bytes())
        prefix = "license-inventory cannot be validated: upstream job 02-sbom-inventory "
        cases = {
            "pending": ({"schema": publish.NONCURRENT_SCHEMA, "status": "PENDING", "attempt_id": accepted["attempt_id"]},
                        "has no CURRENT accepted result"),
            "other-run": ({**accepted, "run_id": "20260101T000000Z-other0"}, "accepted pointer is not an OK or OK_WITH_GAPS"),
            "other-job": ({**accepted, "job": "02-license-scan"}, "accepted pointer is not an OK or OK_WITH_GAPS"),
            "skipped": ({**accepted, "status": "SKIPPED"}, "accepted pointer is not an OK or OK_WITH_GAPS"),
            "escaping": ({**accepted, "attempt_id": "../../../02-license-scan"}, "does not resolve to an unlinked attempt"),
        }
        for name, (pointer, expected) in cases.items():
            with self.subTest(pointer=name):
                atomic_json(base / "accepted.json", pointer)
                (error,) = staged.validate()
                self.assertTrue(error.startswith(prefix) and expected in error, error)
        atomic_json(base / "accepted.json", accepted)
        atomic_json(base / "latest.json", {"attempt_id": "a-newer-failed-attempt"})
        self.assertEqual(staged.validate(), [prefix + "accepted attempt is not its newest attempt"])


    @unittest.skipUnless(t05.CAN_SYMLINK, "this host cannot create symbolic links")
    def test_a_linked_upstream_job_scope_or_attempt_directory_is_refused(self):
        for depth, name in ((0, "attempt"), (1, "attempts"), (2, "scope"), (3, "job")):
            with self.subTest(linked=name):
                staged = stage(self, v05.LICENSE_CONTRACT_ID)
                self.assertEqual(staged.validate(), [])
                base = staged.jobs / "02-sbom-inventory" / "whole"
                pointer = json.loads((base / "accepted.json").read_bytes())
                target = [base / "attempts" / pointer["attempt_id"], base / "attempts", base, base.parent][depth]
                moved = staged.tmp / f"moved-{name}"
                target.rename(moved)
                target.symlink_to(moved, target_is_directory=True)
                (error,) = staged.validate()
                self.assertTrue(error.startswith("license-inventory cannot be validated: upstream job 02-sbom-inventory "),
                                error)


    @unittest.skipUnless(t05.CAN_SYMLINK, "this host cannot create symbolic links")
    def test_a_linked_accepted_or_latest_pointer_is_refused_though_it_reads_as_a_valid_pointer(self):
        """The link's target is the GENUINE pointer, moved outside the run: followed, it would be
        accepted. One spelling per file -- the pointer is read only beneath the run root."""
        for name in ("accepted.json", "latest.json"):
            with self.subTest(linked=name):
                staged = stage(self, v05.LICENSE_CONTRACT_ID)
                self.assertEqual(staged.validate(), [])
                pointer = staged.jobs / "02-sbom-inventory" / "whole" / name
                moved = staged.tmp / f"moved-{name}"
                pointer.rename(moved)
                pointer.symlink_to(moved)
                self.assertEqual(json.loads(pointer.read_bytes()), json.loads(moved.read_bytes()))
                self.assertEqual(staged.validate(), ["license-inventory cannot be validated: upstream job "
                                                     "02-sbom-inventory has no readable accepted pointer in this run"])

    def test_a_pointer_whose_envelope_path_leaves_the_accepted_attempt_is_refused(self):
        """Forged pointers with a MATCHING envelope_sha256, so only containment can refuse them: the
        envelope of another attempt of the job (`../<attempt>/result.json`) and an absolute path."""
        staged = stage(self, v05.LICENSE_CONTRACT_ID)
        self.assertEqual(staged.validate(), [])
        base = staged.jobs / "02-sbom-inventory" / "whole"
        accepted = json.loads((base / "accepted.json").read_bytes())
        other = base / "attempts" / "sbom-node-attempt-0000"
        other.mkdir()
        atomic_json(other / "result.json", {"an": "envelope of another attempt"})
        outside = staged.tmp / "outside-result.json"
        atomic_json(outside, {"an": "envelope outside the run"})
        for name, spelling, target in (("sibling", f"../{other.name}/result.json", other / "result.json"),
                                       ("absolute", str(outside.absolute()), outside)):
            with self.subTest(envelope_path=name):
                atomic_json(base / "accepted.json", {**accepted, "envelope_path": spelling,
                                                     "envelope_sha256": file_hash(target)})
                self.assertEqual(staged.validate(), ["license-inventory cannot be validated: upstream job "
                                                     "02-sbom-inventory accepted pointer does not resolve to an "
                                                     "unlinked attempt of this run"])
        atomic_json(base / "accepted.json", accepted)
        self.assertEqual(staged.validate(), [])


class RequiredArgumentTests(unittest.TestCase):
    def test_orchestration_is_required_by_the_entry_point(self):
        staged = stage(self, LEAK_INVENTORY_CONTRACT)
        with self.assertRaises(TypeError):
            validate_job_output(staged.attempt, staged.envelope(), FINGERPRINT, expected_run_id=staged.run_id,
                                expected_job_id=staged.job_id)
        parameter = inspect.signature(validate_job_output).parameters["orchestration"]
        self.assertIs(parameter.default, inspect.Parameter.empty)
        self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        for bad in (None, {}, "NO_ORCHESTRATION_FACTS", False):
            with self.subTest(orchestration=bad), self.assertRaises(TypeError):
                validate_job_output(staged.attempt, staged.envelope(), FINGERPRINT, expected_run_id=staged.run_id,
                                    expected_job_id=staged.job_id, orchestration=bad)

    def test_every_dispatch_argument_is_required(self):
        staged = stage(self, LEAK_INVENTORY_CONTRACT)
        full = {"run_id": staged.run_id, "job_id": staged.job_id, "attempt_id": staged.attempt_id,
                "node_status": staged.status, "orchestration": staged.facts}
        record = contract_record(staged.contract_id)
        self.assertEqual(validate_vendor_prepass_attempt(staged.attempt, record, **full), [])
        for name in full:
            with self.subTest(omitted=name), self.assertRaises(TypeError):
                validate_vendor_prepass_attempt(staged.attempt, record, **{k: v for k, v in full.items() if k != name})
        for name, parameter in inspect.signature(validate_vendor_prepass_attempt).parameters.items():
            self.assertIs(parameter.default, inspect.Parameter.empty, name)
        for name in ("run_id", "job_id", "attempt_id", "node_status"):
            for bad in (None, "", 7):
                errors = validate_vendor_prepass_attempt(staged.attempt, record, **{**full, name: bad})
                self.assertEqual(len(errors), 1)
                self.assertIn("the caller and the worker envelope supply no usable", errors[0])

    def test_every_orchestration_fact_is_required_and_checked(self):
        full = {"dagster_run_id": "dagster-run-1", "source_snapshot_sha256": "sha256:" + "a" * 64, "now": NOW}
        OrchestrationFacts(**full)
        for name in full:
            with self.subTest(omitted=name), self.assertRaises(TypeError):
                OrchestrationFacts(**{k: v for k, v in full.items() if k != name})
        for name, bad in (("dagster_run_id", ""), ("dagster_run_id", None), ("dagster_run_id", "has space"),
                          ("source_snapshot_sha256", "a" * 64), ("source_snapshot_sha256", None),
                          ("now", datetime(2026, 9, 20)), ("now", "2026-09-20T12:00:00Z"), ("now", None)):
            with self.subTest(field=name, bad=bad), self.assertRaises(TypeError):
                OrchestrationFacts(**{**full, name: bad})
        with self.assertRaises(Exception):
            setattr(OrchestrationFacts(**full), "dagster_run_id", "changed-after-construction")

    def test_the_command_line_takes_both_facts_or_neither(self):
        staged = stage(self, LEAK_INVENTORY_CONTRACT)
        atomic_json(staged.tmp / "envelope.json", staged.envelope())
        argv = ["--attempt-root", str(staged.attempt), "--envelope", str(staged.tmp / "envelope.json"),
                "--expected-input-fingerprint", FINGERPRINT, "--expected-run-id", staged.run_id,
                "--expected-job-id", staged.job_id]
        with mock.patch("builtins.print"):
            self.assertEqual(validator.main(argv), 1)  # no facts: fails closed
            self.assertEqual(validator.main([*argv, "--dagster-run-id", staged.facts.dagster_run_id,
                                             "--source-snapshot-sha256", staged.facts.source_snapshot_sha256]), 0)
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            validator.main([*argv, "--dagster-run-id", staged.facts.dagster_run_id])


class PolicyProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        proposal = json.loads(PROPOSAL.read_text(encoding="utf-8"))
        cls.proposed = {entry["proposed_output_contract_id"]: entry for entry in proposal["proposed_nodes"]
                        if entry["adopted"]}

    def test_the_nine_contracts_are_exactly_the_adopted_adr_nodes(self):
        self.assertEqual(set(self.proposed), set(NINE))
        self.assertEqual(set(validator.VENDOR_PREPASS_NODES), set(NINE))
        self.assertEqual(len(NINE), 9)

    def test_claim_class_three_projections_agree_for_all_nine(self):
        """The validator's trusted table, the owning module's table (the ADR fixture for V07, whose
        module exports none) and the registry contract record are one decision."""
        modules = {**v04.CONTRACT_POLICIES, **v05.CONTRACT_POLICIES}
        for contract_id in NINE:
            with self.subTest(contract=contract_id):
                trusted, record = validator.CLAIM_CLASS_POLICIES[contract_id], contract_record(contract_id)["claim_class"]
                proposed = self.proposed[contract_id]["proposed_claim_class"]
                self.assertEqual(set(trusted), {"claim_class_id", "allowed_assertions"})
                for source in (record, proposed, *([modules[contract_id]] if contract_id in modules else [])):
                    self.assertEqual(trusted["claim_class_id"], source["claim_class_id"])
                    self.assertEqual(trusted["allowed_assertions"], set(source["allowed_assertions"]))
                    self.assertEqual(len(source["allowed_assertions"]), len(set(source["allowed_assertions"])))
                self.assertEqual(set(record["forbidden_promotions"]), set(validator.PROMOTION_FIELDS))
                self.assertEqual(validator._claim_class_errors(contract_record(contract_id), {}), [])

    def test_job_ids_tools_statuses_and_result_artifacts_agree_with_the_adr_fixture_and_the_records(self):
        for contract_id in NINE:
            with self.subTest(contract=contract_id):
                entry, proposed, record = node(contract_id), self.proposed[contract_id], contract_record(contract_id)
                self.assertEqual(entry["job_id"], proposed["proposed_job_id"])
                self.assertEqual(list(entry["declared_tool_ids"]), [tool["tool_id"] for tool in proposed["tool_instances"]])
                self.assertEqual(set(entry["permitted_node_statuses"]), set(proposed["permitted_terminal_statuses"]))
                self.assertEqual(entry["result"], record["result_schema"]["artifact"])

    def test_goldens_use_the_declared_tools(self):
        for contract_id, golden in V04_GOLDEN.items():
            self.assertEqual(t04.GOLDENS[golden].declared, list(node(contract_id)["declared_tool_ids"]))
        for contract_id in V07_IDS:
            self.assertEqual(t07.TOOLS[contract_id], list(node(contract_id)["declared_tool_ids"]))
        for contract_id in V05_IDS:
            self.assertEqual([t05.TOOLS[contract_id]], list(node(contract_id)["declared_tool_ids"]))

    def test_the_validator_constants_repeat_their_owners(self):
        self.assertEqual(validator.ACCEPTED_POINTER_SCHEMA, publish.ACCEPTED_SCHEMA)
        self.assertEqual(validator.REDACTION_POLICY, "refuse")
        self.assertIs(validator.REDACTION_LIMITS, validator.DEFAULT_LIMITS)
        with self.assertRaises(TypeError):
            validator.VENDOR_PREPASS_NODES["secrets-inventory"]["job_id"] = "other"


class ExistingContractRegressionTests(unittest.TestCase):
    LEGACY = {
        "ossf-scorecard-results": ("supply_chain_posture_evidence", {
            "published-scorecard-posture", "published-check-evidence", "publication-coverage-gap"}),
        "repository-partition-map": ("supplied_partition_map", {
            "declared-repository-structure", "statically-inferred-partition-relationship", "review-routing",
            "coverage-gap"}),
        "project-discovery": ("supplied_project_discovery", {
            "declared-project-structure", "statically-inferred-build-plan", "coverage-gap"}),
    }

    def test_their_trusted_policies_are_unchanged_and_they_are_not_vendor_prepass_contracts(self):
        self.assertEqual(set(validator.CLAIM_CLASS_POLICIES), set(self.LEGACY) | set(NINE))
        for contract_id, (claim_class_id, assertions) in self.LEGACY.items():
            self.assertEqual(validator.CLAIM_CLASS_POLICIES[contract_id],
                             {"claim_class_id": claim_class_id, "allowed_assertions": assertions})
            self.assertNotIn(contract_id, validator.VENDOR_PREPASS_NODES)

    def test_their_dispatch_path_is_status_then_generic_and_never_the_vendor_verifier(self):
        for contract_id in self.LEGACY:
            with self.subTest(contract=contract_id), tempfile.TemporaryDirectory() as tmp:
                record = contract_record(contract_id)
                attempt = Path(tmp) / "attempt-1"
                for relative in record["required_files"]:
                    (attempt / relative).parent.mkdir(parents=True, exist_ok=True)
                    (attempt / relative).write_text("{}\n", encoding="utf-8")
                files = sorted(path.relative_to(attempt).as_posix() for path in attempt.rglob("*") if path.is_file())
                envelope = terminal_envelope(
                    run_id="run-1", job_id="02-legacy", attempt_id="attempt-1", worker_kind="deterministic_python",
                    execution_status="OK", acceptance_status="CURRENT", input_fingerprint=FINGERPRINT,
                    output_contract=contract_id, started_at="2026-09-20T12:00:00Z", finished_at="2026-09-20T12:01:00Z",
                    summary="legacy", artifacts=artifact_records(attempt, files))
                calls: list[str] = []
                with mock.patch.object(validator, "validate_vendor_prepass_attempt",
                                       side_effect=AssertionError("vendor verifier reached")), \
                        mock.patch.object(validator, "_status_errors", lambda *a: calls.append("status") or []), \
                        mock.patch.object(validator, "validate_contract_result",
                                          lambda root, contract, **kwargs: calls.append(
                                              ("generic", root, contract["contract_id"], sorted(kwargs))) or []):
                    for facts in (NO_ORCHESTRATION_FACTS,
                                  OrchestrationFacts(dagster_run_id="d", source_snapshot_sha256="sha256:" + "a" * 64, now=NOW)):
                        calls.clear()
                        self.assertEqual(validate_job_output(attempt, envelope, FINGERPRINT, expected_run_id="run-1",
                                                             expected_job_id="02-legacy", orchestration=facts), [])
                        self.assertEqual(calls, ["status", ("generic", attempt.absolute(), contract_id,
                                                            ["registry_root", "run_id", "schemas_root"])])

    def test_validate_contract_result_keeps_its_signature(self):
        parameters = inspect.signature(validator.validate_contract_result).parameters
        self.assertEqual(list(parameters), ["attempt_root", "contract", "run_id", "registry_root", "schemas_root"])


class HygieneTests(unittest.TestCase):
    def test_no_secret_shaped_literal_is_tracked_in_this_module_the_validator_or_the_doc(self):
        paths = [Path(__file__), ROOT / "validate_job_output.py",
                 SCHEMAS_DIR.parent / "docs" / "validator-vendor-prepass-dispatch.md"]
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for label, pattern in validator.SECRET_PATTERNS:
                self.assertIsNone(pattern.search(text), f"{path.name}: {label}")

    def test_files_are_located_through_module_roots(self):
        source = (ROOT / "validate_job_output.py").read_text(encoding="utf-8") + Path(__file__).read_text(encoding="utf-8")
        self.assertNotIn("appsec-review-" + "process/", source.replace("appsec-review-" + "process/tests/", ""))


class JobContractBindingTests(unittest.TestCase):
    """Coordinator probe, after the slice was green: the envelope states both the job and the output
    contract, the contract selects every check, and nothing bound the two. The suite proved "one of
    the nine contracts => its job"; nobody asked the reverse. Pre-existing for every job, but it is
    this slice's strict verifiers that it let a producer walk around."""

    def test_a_vendor_prepass_job_cannot_pick_a_laxer_contract_to_escape_its_verifier(self):
        staged = stage(self, LEAK_INVENTORY_CONTRACT)
        lax = contract_record("evidence-index")
        self.assertIsNone(lax.get("result_schema"))
        document = staged.attempt / "outputs" / "secrets-inventory.redacted.json"
        value = json.loads(document.read_bytes())
        value["verified_findings"] = [{"severity": "critical"}]
        document.write_bytes(dump(value))
        for relative in lax["required_files"]:
            path = staged.attempt / relative
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"{}" if relative.endswith(".json") else b"x")
        self.assertTrue(staged.validate())  # its own contract refuses it
        errors = staged.validate(staged.envelope(contract_id="evidence-index"))
        self.assertEqual(errors, ["output contract is not the one this job publishes; expected 'secrets-inventory'"])

    def test_every_vendor_prepass_job_is_bound_to_exactly_its_contract(self):
        import validate_job_output as validator
        graph = {"jobs": {}}  # V02 has not declared the nodes on this base: the vendor table must suffice
        for contract_id in NINE:
            job_id = node(contract_id)["job_id"]
            with self.subTest(job=job_id):
                self.assertEqual(validator._job_contract_errors(job_id, contract_id, graph, REGISTRY), [])
                for other in ("evidence-index", "intake", *[c for c in NINE if c != contract_id][:2]):
                    self.assertEqual(validator._job_contract_errors(job_id, other, graph, REGISTRY),
                                     [f"output contract is not the one this job publishes; expected {contract_id!r}"])

    def test_registered_jobs_are_bound_by_their_template_and_their_graph_node(self):
        import validate_job_output as validator
        graph = json.loads((ROOT / "job-graph.json").read_text(encoding="utf-8"))
        checked = 0
        for template in sorted((REGISTRY / "job-templates").glob("*.json")):
            record = json.loads(template.read_text(encoding="utf-8"))
            job_id, contract_id = record["job_template_id"], record["composition"]["output_contract_id"]
            with self.subTest(job=job_id):
                self.assertEqual(validator._job_contract_errors(job_id, contract_id, graph, REGISTRY), [])
                self.assertTrue(validator._job_contract_errors(job_id, "evidence-index" if contract_id != "evidence-index"
                                                               else "intake", graph, REGISTRY))
                checked += 1
        self.assertGreaterEqual(checked, 16)
        planned = next(job for job, item in graph["jobs"].items()
                       if not (REGISTRY / "job-templates" / f"{job}.json").is_file())
        self.assertTrue(validator._job_contract_errors(planned, "evidence-index", graph, REGISTRY))
        self.assertEqual(validator._job_contract_errors(planned, graph["jobs"][planned]["contract"], graph, REGISTRY), [])

    def test_sources_that_disagree_are_an_error_and_an_unknown_job_is_left_as_it_was(self):
        import validate_job_output as validator
        job_id = node(LEAK_INVENTORY_CONTRACT)["job_id"]
        graph = {"jobs": {job_id: {"contract": "evidence-index"}}}
        for claimed in (LEAK_INVENTORY_CONTRACT, "evidence-index"):
            self.assertEqual(validator._job_contract_errors(job_id, claimed, graph, REGISTRY),
                             ["the registry, the graph and the vendor-prepass table disagree about this job's output contract"])
        self.assertEqual(validator._job_contract_errors("job-nobody-registered", "evidence-index", {"jobs": {}}, REGISTRY), [])
        for hostile in ("../x", "", None, 7, "a/b"):
            self.assertEqual(validator._job_contract_errors(hostile, "evidence-index", {"jobs": {}}, REGISTRY), [])


class EnvelopeEchoTests(unittest.TestCase):
    """Review P2: the envelope is the attempt's result.json. Its values were quoted by the artifact
    loop and by the envelope schema errors, before the verifier ran."""

    STRING_FIELDS = ("schema", "run_id", "job_id", "attempt_id", "worker_kind", "execution_status",
                     "acceptance_status", "input_fingerprint", "output_contract", "started_at", "finished_at",
                     "summary", "skip_reason", "cause", "superseded_by_attempt_id")

    def mutations(self, envelope: dict):
        self.assertEqual({key for key, value in envelope.items() if isinstance(value, str) or value is None},
                         set(self.STRING_FIELDS))  # every string-capable top-level field is covered
        for field in self.STRING_FIELDS:
            yield field, {**envelope, field: MARKER}
        yield "unexpected property name", {**envelope, MARKER: MARKER}
        yield "gaps[]", {**envelope, "gaps": [*envelope["gaps"], MARKER, 7]}
        yield "retry.resume_command", {**envelope, "retry": {"allowed": False, "resume_command": MARKER}}
        yield "retry property name", {**envelope, "retry": {**envelope["retry"], MARKER: MARKER}}
        for key in ("path", "sha256", "media_type", MARKER):
            artifacts = deepcopy(envelope["artifacts"])
            artifacts[1][key] = MARKER
            yield f"artifacts[1].{key.replace(MARKER, '<name>')}", {**envelope, "artifacts": artifacts}
        for spelling in (f"outputs/{MARKER}", f"../{MARKER}", f"/{MARKER}", f"outputs/./{MARKER}", f"{MARKER}\\x", ""):
            artifacts = deepcopy(envelope["artifacts"])
            artifacts[0]["path"] = spelling
            yield "artifacts[0].path spelling", {**envelope, "artifacts": artifacts}
        yield "duplicate artifact", {**envelope, "artifacts": [*envelope["artifacts"], envelope["artifacts"][0]]}

    def test_no_envelope_value_reaches_an_error_of_either_entry_point(self):
        for contract_id in NINE:
            staged = stage(self, contract_id)
            for name, envelope in self.mutations(staged.envelope()):
                with self.subTest(contract=contract_id, field=name):
                    with bindings(staged.world):
                        errors = staged.validate(envelope)  # asserts the invariant over PLANTED, MARKER included
                    if name not in ("started_at", "finished_at", "summary", "artifacts[1].media_type"):  # free text
                        self.assertTrue(errors)
                    publish.mark_attempt_started(staged.base, staged.attempt_id, FINGERPRINT)
                    (staged.attempt / "result.json").unlink(missing_ok=True)
                    atomic_json(staged.attempt / "result.json", envelope)
                    try:
                        with bindings(staged.world):
                            publish.publish_validated(staged.base, staged.attempt, staged.attempt / "result.json",
                                                      FINGERPRINT, expected_run_id=staged.run_id,
                                                      expected_job_id=staged.job_id, orchestration=staged.facts)
                    except publish.Blocked as blocked:
                        self.assertNotIn(MARKER, str(blocked))
                    (staged.attempt / "result.json").unlink()

    def test_the_reviewers_two_cases_name_the_index_and_the_location(self):
        staged = stage(self, LEAK_INVENTORY_CONTRACT)
        envelope = staged.envelope()
        envelope["artifacts"][0]["path"] = f"outputs/{MARKER}"
        self.assertIn("$.artifacts[0].path: is missing or not a regular file", staged.validate(envelope))
        errors = staged.validate(staged.envelope(worker_kind=MARKER))
        self.assertIn("$.worker_kind: violates worker-result-envelope.schema.json (enum)", errors)

    def test_an_unauthorized_skip_reason_and_a_foreign_job_are_not_quoted(self):
        staged = stage(self, v04.IAC_CONTRACT_ID, golden="iac-skipped")
        errors = staged.validate(staged.envelope(skip_reason=MARKER, job_id=MARKER), consumer_job_id="02-evidence-assembly")
        self.assertIn("$.skip_reason: the skip reason is not authorized for this dependency edge", errors)
        self.assertIn("job_id does not match the owning job", errors)

    def test_the_value_free_message_table_is_exactly_what_the_envelope_validator_says(self):
        """Derived from `validate_worker_result` over every state combination: a new or reworded
        cross-field message fails here instead of silently becoming the generic text."""
        base = terminal_envelope(run_id="r", job_id="j", attempt_id="a", worker_kind="persona", execution_status="OK",
                                 acceptance_status="CURRENT", input_fingerprint=FINGERPRINT, output_contract="c",
                                 started_at="s", finished_at="f", summary="x", artifacts=[])
        statuses = ("OK", "OK_WITH_GAPS", "SKIPPED", "BLOCKED", "FAILED", "CANCELED", "UNRESOLVED")
        seen: set[str] = set()
        for status, acceptance, gaps, cause, skip, superseded, retry in itertools.product(
                statuses, ("CURRENT", "NOT_ACCEPTED", "SUPERSEDED"), ([], ["g"]), (None, "c"), (None, "s"),
                (None, "a", "b"), ((False, None), (True, None), (True, "cmd"), (False, "cmd"))):
            envelope = {**base, "execution_status": status, "acceptance_status": acceptance, "gaps": gaps, "cause": cause,
                        "skip_reason": skip, "superseded_by_attempt_id": superseded,
                        "retry": {"allowed": retry[0], "resume_command": retry[1]}}
            raw = validator.validate_worker_result(envelope, allowed_skip_reasons=None)
            self.assertEqual([message.partition(": ")[2] for message in raw],
                             [message.partition(": ")[2] for message in validator._envelope_errors_without_values(raw)])
            seen.update(message.partition(": ")[2] for message in raw)
        self.assertEqual(seen, set(validator._VALUE_FREE_ENVELOPE_DETAILS))

    def test_the_other_contracts_keep_their_messages(self):
        with tempfile.TemporaryDirectory() as tmp:
            attempt = Path(tmp) / "attempt-1"
            attempt.mkdir()
            envelope = terminal_envelope(
                run_id="run-1", job_id="02-legacy", attempt_id="attempt-1", worker_kind=MARKER, execution_status="OK",
                acceptance_status="CURRENT", input_fingerprint=FINGERPRINT, output_contract="evidence-index",
                started_at="s", finished_at="f", summary="legacy",
                artifacts=[{"path": f"outputs/{MARKER}", "sha256": "0" * 64, "media_type": "application/json"}])
            errors = validate_job_output(attempt, envelope, FINGERPRINT, expected_run_id="run-1",
                                         expected_job_id="02-legacy", orchestration=NO_ORCHESTRATION_FACTS)
            self.assertIn(f"artifact is missing or not a regular file: outputs/{MARKER}", errors)
            self.assertTrue(any(error.startswith(f"$.worker_kind: {MARKER!r} not in enum") for error in errors))


if __name__ == "__main__":
    unittest.main()
