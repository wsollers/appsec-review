import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import registry_paths

import evidence_index_enrichment as enrichment
import evidence_store as store
import execution_state as state
import static_intelligence_core as static_core
from execution_state import Blocked, atomic_json, file_hash, tree_hashes
from schema_validate import validate_document
from worker_result import artifact_records, terminal_envelope


RUN_ID = "f01-test"
JOB = "02-doc-intelligence-ingest"
ATTEMPT = "attempt-0001"
FINGERPRINT = "sha256:" + "f" * 64
SOURCE = "a" * 64


class ProducerFixture:
    def __init__(self, root: Path):
        self.root = root
        self.target = root / "target"
        self.target.mkdir(parents=True)
        document = self.target / "docs" / "design.md"
        document.parent.mkdir()
        document.write_text(
            "# Service design\nThe reporting service must authenticate each actor.\n",
            encoding="utf-8",
        )
        self.base = root / RUN_ID / "data" / "jobs" / JOB
        self.attempt = self.base / "attempts" / ATTEMPT
        self.attempt.mkdir(parents=True)
        source_files = {
            "docs/design.md": {
                "kind": "file",
                "sha256": file_hash(document),
                "bytes": document.stat().st_size,
            }
        }
        binding = {
            "job_id": "00-intake",
            "attempt_id": "intake-1",
            "fingerprint": "intake-fingerprint",
            "source_fingerprint": SOURCE,
            "source_revision": "fixture",
            "pointer_sha256": "sha256:" + "b" * 64,
        }
        result = static_core.extract(
            JOB,
            run_id=RUN_ID,
            attempt_id=ATTEMPT,
            target=self.target,
            source=binding,
            source_files=source_files,
        )
        atomic_json(self.attempt / "doc-intelligence.json", result)
        atomic_json(
            self.attempt / "status.json",
            {
                "process": JOB,
                "status": result["status"],
                "sources": len(result["sources"]),
                "records": len(result["records"]),
                "static_only": True,
                "qualification": "implemented_not_qualified",
            },
        )
        atomic_json(
            self.attempt / "permission.json",
            {
                "schema": enrichment.PERMISSION_SCHEMA,
                "run_id": RUN_ID,
                "job_id": JOB,
                "source_snapshot_sha256": "sha256:" + SOURCE,
                "permissions": ["read-source", "read-run-data", "write-run-data"],
            },
        )
        atomic_json(
            self.attempt / "lineage.json",
            {
                "schema": enrichment.LINEAGE_SCHEMA,
                "run_id": RUN_ID,
                "job_id": JOB,
                "source_snapshot_sha256": "sha256:" + SOURCE,
                "build_lineage_sha256": None,
            },
        )
        self.reseal()

    def reseal(self):
        envelope = terminal_envelope(
            run_id=RUN_ID,
            job_id=JOB,
            attempt_id=ATTEMPT,
            worker_kind="deterministic_python",
            execution_status="OK",
            acceptance_status="CURRENT",
            input_fingerprint=FINGERPRINT,
            output_contract="doc-intelligence",
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:00:01+00:00",
            summary="fixture",
            artifacts=artifact_records(
                self.attempt,
                ["doc-intelligence.json", "status.json", "permission.json", "lineage.json"],
            ),
        )
        atomic_json(self.attempt / "result.json", envelope)
        atomic_json(
            self.base / "latest.json",
            {"attempt_id": ATTEMPT, "fingerprint": FINGERPRINT},
        )
        atomic_json(
            self.base / "accepted.json",
            {
                "schema": "appsec-review/accepted-worker-result/1.0",
                "status": "OK",
                "run_id": RUN_ID,
                "job": JOB,
                "attempt_id": ATTEMPT,
                "fingerprint": FINGERPRINT,
                "envelope_path": "result.json",
                "envelope_sha256": file_hash(self.attempt / "result.json"),
                "hashes": tree_hashes(self.attempt),
                "accepted_at": "2026-01-01T00:00:02+00:00",
            },
        )

    def selection(self):
        path = self.root / RUN_ID / "data" / "inputs" / enrichment.SELECTION
        atomic_json(path, json.loads(
            (ROOT / "tests/fixtures/evidence-index-enrichment/producer-selection.json").read_text()))
        return path


class EvidenceIndexEnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_runs = state.RUNS
        state.RUNS = Path(self.temp.name)
        self.fixture = ProducerFixture(state.RUNS)

    def tearDown(self):
        state.RUNS = self.old_runs
        self.temp.cleanup()

    def select(self):
        self.fixture.selection()
        return enrichment.selected_inputs(RUN_ID)

    def test_accepted_producer_builds_deterministic_redacted_bounded_locator_index(self):
        selected = self.select()
        one = enrichment.build(RUN_ID, selected)
        two = enrichment.build(RUN_ID, selected)
        self.assertEqual(one, two)
        self.assertEqual(validate_document(one, "evidence-index-enrichment.schema.json"), [])
        self.assertEqual(one["producer_count"], 1)
        self.assertGreater(one["record_count"], 0)
        record = one["records"][0]
        self.assertEqual(record["producer_job_id"], JOB)
        self.assertEqual(record["producer_attempt_id"], ATTEMPT)
        self.assertEqual(record["producer_contract"], "doc-intelligence")
        self.assertEqual(record["artifact_path"], "doc-intelligence.json")
        self.assertEqual(record["authority"], "untrusted_documented_intent")
        self.assertEqual(record["source_snapshot_sha256"], "sha256:" + SOURCE)
        self.assertNotIn("semantics", record)
        self.assertNotIn("source_sha256", record)
        matched = enrichment.query(one, text="reporting", limit=1)
        self.assertEqual(len(matched), 1)
        self.assertIn("reporting", matched[0]["search_text"].lower())
        self.assertEqual(enrichment.query(one, text="absent"), [])
        with self.assertRaises(ValueError):
            enrichment.query(one, limit=51)

    def test_no_selection_is_an_explicit_gap_and_preserves_empty_happy_path(self):
        selected = enrichment.selected_inputs(RUN_ID)
        self.assertEqual(selected, {"selection_sha256": None, "producers": []})
        result = enrichment.build(RUN_ID, selected, "sha256:" + SOURCE)
        self.assertEqual(result["records"], [])
        self.assertEqual(result["coverage_gaps"], ["no-derived-producers-selected"])

    def test_store_publishes_and_rederives_nonempty_sqlite_enrichment_and_receipts(self):
        selected = self.select()
        intake = Path(self.temp.name) / "intake" / "attempts" / "producer"
        source_file = self.fixture.target / "docs" / "design.md"
        atomic_json(
            intake / "evidence/source.json",
            {
                "target": str(self.fixture.target),
                "files": {
                    "docs/design.md": {
                        "kind": "file",
                        "sha256": file_hash(source_file),
                        "bytes": source_file.stat().st_size,
                    }
                },
                "fingerprint": SOURCE,
                "revision": "fixture",
            },
        )
        atomic_json(intake / "outputs/intake.json", {"scope": {"excluded_paths": []}})
        (intake / "outputs/build-discovery.md").write_text("static fixture\n", encoding="utf-8")
        plan = {
            "producers": [{"kind": "intake", "pointer": {"attempt_id": "producer"}}],
            "derived": selected,
            "template": json.loads((registry_paths.template("02-evidence-index")).read_text()),
        }
        attempt = Path(self.temp.name) / "index-attempt"
        attempt.mkdir()
        atomic_json(attempt / "inputs.json", plan)

        class FakeFuzzy:
            def hash(self, content):
                return "3:" + file_hash_bytes(content)[:32] + ":" + file_hash_bytes(content)[32:]

        def file_hash_bytes(content):
            import hashlib
            return hashlib.sha256(content).hexdigest()

        with patch.object(store.phase1, "job_root", return_value=Path(self.temp.name) / "intake"), \
                patch.object(store, "Fuzzy", FakeFuzzy):
            store.collect(RUN_ID, attempt)
            result = store.check_enrichment(RUN_ID, attempt, plan)
        self.assertGreater(result["record_count"], 0)
        import sqlite3
        with sqlite3.connect(attempt / "index.sqlite") as database:
            row = database.execute(
                "SELECT producer_job_id, producer_attempt_id, producer_contract, artifact_path, "
                "artifact_sha256, record_path, record_sha256, type_label, authority, redaction, "
                "source_snapshot_sha256, build_lineage_sha256 FROM derived_records"
            ).fetchone()
            fts = database.execute(
                "SELECT record_id FROM derived_chunks WHERE derived_chunks MATCH ?",
                ('"reporting"',),
            ).fetchall()
        self.assertEqual(row[0:4], (JOB, ATTEMPT, "doc-intelligence", "doc-intelligence.json"))
        self.assertEqual(row[8], "untrusted_documented_intent")
        self.assertEqual(row[10], "sha256:" + SOURCE)
        self.assertIsNone(row[11])
        self.assertTrue(fts)

    def test_stale_corrupt_and_wrong_shape_pointers_fail_closed(self):
        self.fixture.selection()
        pointer_path = self.fixture.base / "accepted.json"
        original = json.loads(pointer_path.read_text())
        cases = {
            "stale": lambda pointer: atomic_json(
                self.fixture.base / "latest.json",
                {"attempt_id": "attempt-newer", "fingerprint": FINGERPRINT},
            ),
            "wrong-shape": lambda pointer: pointer.update(extra="not-allowed"),
            "wrong-envelope-path": lambda pointer: pointer.update(envelope_path="status.json"),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                atomic_json(pointer_path, original)
                atomic_json(self.fixture.base / "latest.json", {"attempt_id": ATTEMPT, "fingerprint": FINGERPRINT})
                pointer = copy.deepcopy(original)
                mutate(pointer)
                if pointer != original:
                    atomic_json(pointer_path, pointer)
                with self.assertRaises(Blocked):
                    enrichment.selected_inputs(RUN_ID)
        atomic_json(pointer_path, original)
        atomic_json(self.fixture.base / "latest.json", {"attempt_id": ATTEMPT, "fingerprint": FINGERPRINT})
        (self.fixture.attempt / "doc-intelligence.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaises(Blocked):
            enrichment.selected_inputs(RUN_ID)

    def test_external_attempts_directory_symlink_fails_closed(self):
        self.fixture.selection()
        attempts = self.fixture.base / "attempts"
        external = Path(self.temp.name) / "external-attempts"
        attempts.rename(external)
        attempts.symlink_to(external, target_is_directory=True)
        with self.assertRaises(Blocked):
            enrichment.selected_inputs(RUN_ID)

    def test_nested_artifact_symlink_and_path_escape_fail_closed(self):
        self.fixture.selection()
        external = Path(self.temp.name) / "external-artifacts"
        external.mkdir()
        (external / "extra.json").write_text("{}\n", encoding="utf-8")
        nested = self.fixture.attempt / "nested"
        nested.symlink_to(external, target_is_directory=True)
        with self.assertRaises(Blocked):
            enrichment.selected_inputs(RUN_ID)

        nested.unlink()
        self.fixture.reseal()
        envelope_path = self.fixture.attempt / "result.json"
        envelope = json.loads(envelope_path.read_text())
        envelope["artifacts"][0]["path"] = "nested/../../doc-intelligence.json"
        atomic_json(envelope_path, envelope)
        pointer = json.loads((self.fixture.base / "accepted.json").read_text())
        pointer["envelope_sha256"] = file_hash(envelope_path)
        pointer["hashes"] = tree_hashes(self.fixture.attempt)
        atomic_json(self.fixture.base / "accepted.json", pointer)
        with self.assertRaises(Blocked):
            enrichment.selected_inputs(RUN_ID)

    def test_resealed_secret_payload_and_receipt_forgery_fail_contract_validation(self):
        self.fixture.selection()
        payload_path = self.fixture.attempt / "doc-intelligence.json"
        payload = json.loads(payload_path.read_text())
        payload["records"][0]["summary"] = "AKIA" + "A" * 16
        atomic_json(payload_path, payload)
        self.fixture.reseal()
        with self.assertRaises(Blocked):
            enrichment.selected_inputs(RUN_ID)

        self.fixture = ProducerFixture(state.RUNS / "second")
        # Retarget the second fixture into the test run root before exercising receipt checks.
        second_base = self.fixture.base
        original_root = state.RUNS
        state.RUNS = original_root / "second"
        try:
            self.fixture.selection()
            permission = json.loads((self.fixture.attempt / "permission.json").read_text())
            permission["permissions"] = ["read-source"]
            atomic_json(self.fixture.attempt / "permission.json", permission)
            self.fixture.reseal()
            with self.assertRaises(Blocked):
                enrichment.selected_inputs(RUN_ID)
        finally:
            state.RUNS = original_root

    def test_duplicate_selection_and_mixed_generation_fail_closed(self):
        path = self.fixture.selection()
        document = json.loads(path.read_text())
        document["producer_jobs"] = [JOB, JOB]
        atomic_json(path, document)
        with self.assertRaises(Blocked):
            enrichment.selected_inputs(RUN_ID)

        selected = {"selection_sha256": None, "producers": []}
        producer = enrichment.load_producer(RUN_ID, JOB)
        selected["producers"] = [producer, {**producer, "source_snapshot_sha256": "sha256:" + "c" * 64}]
        with self.assertRaises(Blocked):
            enrichment.build(RUN_ID, selected)


class ClosedSchemaTests(unittest.TestCase):
    def test_new_schemas_are_closed_and_selection_rejects_unknown_members(self):
        for name in (
            "evidence-index-producer-selection.schema.json",
            "evidence-index-derived-record.schema.json",
            "evidence-index-enrichment.schema.json",
        ):
            schema = json.loads((ROOT.parent / "schemas" / name).read_text())
            stack = [schema]
            while stack:
                value = stack.pop()
                if isinstance(value, dict):
                    if value.get("type") == "object":
                        self.assertIs(value.get("additionalProperties"), False, name)
                    stack.extend(value.values())
                elif isinstance(value, list):
                    stack.extend(value)
        selection = {
            "schema": "appsec-review/evidence-index-producer-selection/1.0",
            "run_id": RUN_ID,
            "producer_jobs": [],
            "authority": True,
        }
        self.assertTrue(validate_document(selection, "evidence-index-producer-selection.schema.json"))


if __name__ == "__main__":
    unittest.main()
