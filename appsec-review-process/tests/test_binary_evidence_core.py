"""Focused nominal and trust-boundary tests for E06--E08 binary evidence."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/binary-evidence/raw-records.json"
sys.path.insert(0, str(ROOT))

import binary_evidence_core as core  # noqa: E402
import evidence_assembly as assembly  # noqa: E402
from execution_state import Blocked, atomic_json, digest, file_hash, tree_hashes  # noqa: E402
from publish_job_output import ACCEPTED_SCHEMA  # noqa: E402
from schema_validate import validate_document  # noqa: E402
from validate_job_output import _claim_class_errors  # noqa: E402
from worker_result import artifact_records, terminal_envelope  # noqa: E402

H = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
H3 = "sha256:" + "3" * 64
BINARY = {"binary_id": "bin_1111111111111111", "unit_id": "dir:.",
          "source_path": "build/fixture", "artifact_path": "outputs/u/binaries/fixture",
          "sha256": H, "size_bytes": 128, "build_identity_sha256": H2}
NATIVE = {"job_id": "02-native-build", "attempt_id": "native-a", "result_sha256": H2,
          "fingerprint": "sha256:" + "6" * 64, "pointer_sha256": "sha256:" + "7" * 64,
          "envelope_sha256": H3, "source_revision": "a" * 40,
          "source_snapshot_sha256": "sha256:" + "4" * 64, "binaries": [BINARY]}
NATIVE["source_tree_sha256"] = "sha256:" + "8" * 64


def raw(job: str, record: dict) -> dict:
    return {"schema": core.RAW_SCHEMA, "job_id": job,
            "native_build": {key: NATIVE[key] for key in NATIVE if key != "binaries"},
            "image": {"image_id": "audit-binary-analysis", "image_digest": "sha256:" + "9" * 64,
                      "status": "PINNED"},
            "config": {"static_only": True, "adapter_id": "fixture-normalizer",
                       "adapter_version": "1"},
            "records": [{"binary_id": BINARY["binary_id"], "binary_sha256": H,
                         "build_identity_sha256": H2, **record}],
            "gaps": []}


def inputs(job: str, value: dict, upstream=None) -> dict:
    return {"run_id": "run-binary", "job_id": job, "native_build": copy.deepcopy(NATIVE),
            "upstream": upstream or {}, "raw": value,
            "raw_evidence_sha256": "sha256:" + "5" * 64,
            "config_sha256": "sha256:" + digest(value["config"]), "code": {}}


class BinaryEvidenceCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text())

    def test_happy_path_is_deterministic_schema_valid_and_hash_bound(self):
        debug_raw = raw("02-debug-symbol-index", self.fixture["debug"])
        triage_raw = raw("02-binary-triage", self.fixture["triage"])
        debug = core.normalize("02-debug-symbol-index", inputs("02-debug-symbol-index", debug_raw), "a-debug")
        triage = core.normalize("02-binary-triage", inputs("02-binary-triage", triage_raw), "a-triage")
        upstream = {
            "02-debug-symbol-index": {"attempt_id": "a-debug", "contract_id": "debug-symbol-index",
                "result_sha256": H2, "envelope_sha256": H3, "result": debug},
            "02-binary-triage": {"attempt_id": "a-triage", "contract_id": "binary-triage",
                "result_sha256": H3, "envelope_sha256": H2, "result": triage},
        }
        cfg_raw = raw("02-binary-cfg", self.fixture["cfg"])
        symbols = {item["name"]: item["symbol_id"] for item in debug["records"][0]["symbols"]}
        for function in cfg_raw["records"][0]["functions"]:
            function["symbol_id"] = symbols[function["name"]]
        cfg_inputs = inputs("02-binary-cfg", cfg_raw, upstream)
        cfg = core.normalize("02-binary-cfg", cfg_inputs, "a-cfg")
        intel_record = copy.deepcopy(self.fixture["intelligence"])
        intel_record["citations"] = [
            {"job_id": "02-binary-triage", "result_sha256": H3,
             "binary_id": BINARY["binary_id"], "record_identity": triage["records"][0]["triage_id"]},
            {"job_id": "02-binary-cfg", "result_sha256": H2,
             "binary_id": BINARY["binary_id"], "record_identity": cfg["records"][0]["functions"][0]["function_id"]},
        ]
        intel_upstream = {
            "02-binary-triage": upstream["02-binary-triage"],
            "02-binary-cfg": {"attempt_id": "a-cfg", "contract_id": "binary-cfg",
                "result_sha256": H2, "envelope_sha256": H3, "result": cfg},
        }
        intel_raw = raw("02-binary-intelligence-ingest", intel_record)
        intel_inputs = inputs("02-binary-intelligence-ingest", intel_raw, intel_upstream)
        intel = core.normalize("02-binary-intelligence-ingest", intel_inputs, "a-intel")
        self.assertEqual(intel, core.normalize("02-binary-intelligence-ingest", intel_inputs, "a-intel"))
        for value, schema in ((debug, "debug-symbol-index.schema.json"),
                              (triage, "binary-triage.schema.json"),
                              (cfg, "binary-cfg.schema.json"),
                              (intel, "binary-intelligence.schema.json")):
            self.assertEqual(validate_document(value, schema), [])
            self.assertEqual(value["tool"]["raw_evidence_sha256"], "sha256:" + "5" * 64)
        self.assertEqual([x["name"] for x in debug["records"][0]["symbols"]], ["main", "helper"])
        self.assertEqual(triage["records"][0]["imports"], ["libc.so.6", "puts"])
        self.assertRegex(cfg["records"][0]["functions"][0]["function_id"], r"^fn_[0-9a-f]{16}$")
        self.assertNotIn("severity", json.dumps(intel).lower())
        self.assertNotIn("verdict", json.dumps(intel).lower())
        self.assertFalse(any(key in {"finding", "findings"} for key in intel))

    def test_malformed_cross_identity_and_path_escape_fail_closed(self):
        value = raw("02-debug-symbol-index", self.fixture["debug"])
        malformed = copy.deepcopy(value); malformed["extra"] = True
        with self.assertRaises(Blocked): core._validate_raw(malformed, "02-debug-symbol-index")
        cross = copy.deepcopy(value); cross["records"][0]["binary_sha256"] = H3
        with self.assertRaises(Blocked): core.normalize("02-debug-symbol-index", inputs("02-debug-symbol-index", cross), "a")
        escape = copy.deepcopy(value); escape["records"][0]["symbols"][0]["source_path"] = "../secret.c"
        with self.assertRaises(Blocked): core.normalize("02-debug-symbol-index", inputs("02-debug-symbol-index", escape), "a")

    def test_stale_native_build_binding_and_m02_claim_are_rejected(self):
        value = raw("02-binary-triage", self.fixture["triage"])
        value["job_id"] = "02-binary-intelligence-ingest"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "raw.json"); atomic_json(path, value)
            stale = copy.deepcopy(NATIVE); stale["result_sha256"] = "sha256:" + "9" * 64
            with mock.patch.object(core, "control_path", return_value=path), \
                 mock.patch.object(core, "_native", return_value=(Path(folder), stale)), \
                 mock.patch.object(core, "_upstream", return_value={}), \
                 mock.patch.object(core, "_code_hashes", return_value={}):
                with self.assertRaises(Blocked):
                    core.current_inputs("run-binary", "02-binary-intelligence-ingest")
        claimed = copy.deepcopy(value)
        claimed["image"] = {"image_id": "audit-binary-analysis", "image_digest": None,
                            "status": "M02_UNRESOLVED"}
        with self.assertRaises(Blocked): core._validate_raw(claimed, "02-binary-triage")

    def test_cfg_rejects_mixed_accepted_generations(self):
        debug = core.normalize("02-debug-symbol-index",
            inputs("02-debug-symbol-index", raw("02-debug-symbol-index", self.fixture["debug"])), "a-debug")
        triage = core.normalize("02-binary-triage",
            inputs("02-binary-triage", raw("02-binary-triage", self.fixture["triage"])), "a-triage")
        triage["native_build"]["attempt_id"] = "another-build"
        upstream = {
            "02-debug-symbol-index": {"attempt_id": "a-debug", "contract_id": "debug-symbol-index",
                "result_sha256": H2, "envelope_sha256": H3, "result": debug},
            "02-binary-triage": {"attempt_id": "a-triage", "contract_id": "binary-triage",
                "result_sha256": H3, "envelope_sha256": H2, "result": triage},
        }
        symbols = {item["name"]: item["symbol_id"] for item in debug["records"][0]["symbols"]}
        cfg_raw = raw("02-binary-cfg", self.fixture["cfg"])
        for function in cfg_raw["records"][0]["functions"]:
            function["symbol_id"] = symbols[function["name"]]
        with self.assertRaisesRegex(Blocked, "mixed native-build generation"):
            core.normalize("02-binary-cfg",
                inputs("02-binary-cfg", cfg_raw, upstream), "a-cfg")

    def test_stripped_packed_unknown_and_partial_are_explicit_gaps(self):
        debug_record = copy.deepcopy(self.fixture["debug"]); debug_record["symbol_status"] = "PARTIAL"
        debug = core.normalize("02-debug-symbol-index",
            inputs("02-debug-symbol-index", raw("02-debug-symbol-index", debug_record)), "a")
        self.assertIn("symbol-status:partial", debug["records"][0]["gaps"])
        triage_record = copy.deepcopy(self.fixture["triage"])
        triage_record.update(format="UNKNOWN", architecture="mips64", packed="YES", stripped="YES")
        triage = core.normalize("02-binary-triage",
            inputs("02-binary-triage", raw("02-binary-triage", triage_record)), "a")
        self.assertEqual(triage["records"][0]["gaps"], ["packed-state:yes", "stripped-state:yes",
            "unsupported-architecture", "unsupported-or-unknown-binary-format"])
        self.assertEqual(triage["status"], "OK_WITH_GAPS")
        self.assertEqual(triage["coverage_gaps"], [
            f"{BINARY['binary_id']}:packed-state:yes", f"{BINARY['binary_id']}:stripped-state:yes",
            f"{BINARY['binary_id']}:unsupported-architecture",
            f"{BINARY['binary_id']}:unsupported-or-unknown-binary-format"])

    def test_clean_records_publish_ok_with_empty_aggregate_gaps(self):
        result = core.normalize("02-binary-triage",
            inputs("02-binary-triage", raw("02-binary-triage", self.fixture["triage"])), "a")
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["coverage_gaps"], [])

    def test_registry_composition_is_pinned_static_and_not_target_executable(self):
        source = (ROOT / "binary_evidence_core.py").read_text()
        self.assertNotIn("subprocess", source)
        self.assertNotIn("run_container", source)
        for job, (contract_id, result_name, schema_name) in core.SPECS.items():
            template = json.loads((ROOT / f"registry/job-templates/{job}.json").read_text())
            contract = json.loads((ROOT / f"registry/output-contracts/{contract_id}.json").read_text())
            self.assertEqual(template["implemented"], job in core.adapter.SUPPORTED)
            self.assertEqual(template["composition"]["output_contract_id"], contract_id)
            self.assertEqual(contract["result_schema"], {"artifact": result_name,
                                                         "schema_file": schema_name})
            self.assertTrue({"permission.json", "lineage.json"}.issubset(contract["required_files"]))
            self.assertNotIn("claim_types", contract)

    def test_zero_accepted_binaries_normalizes_to_evidence_supported_skip(self):
        value = raw("02-binary-triage", self.fixture["triage"])
        value["records"] = []
        inp = inputs("02-binary-triage", value)
        inp["native_build"]["binaries"] = []
        result = core.normalize("02-binary-triage", inp, "skip-attempt")
        self.assertEqual(result["status"], "SKIPPED")
        self.assertEqual(result["records"], [])
        self.assertEqual(validate_document(result, "binary-triage.schema.json"), [])
        receipt = core._applicability("run-binary", "02-binary-triage", inp)
        self.assertEqual(receipt["decision"], "SKIPPED_NA")
        self.assertEqual(receipt["reason"], "not-applicable-no-native-binaries")
        self.assertEqual(receipt["evidence"]["artifact_sha256"], NATIVE["result_sha256"])
        self.assertEqual(validate_document(receipt, "analysis-applicability-receipt.schema.json"), [])

    def test_missing_accepted_native_build_blocks_before_container_execution(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(core, "root", return_value=Path(folder)):
            with self.assertRaisesRegex(Blocked, "accepted native-build"):
                core.run("run-binary", "dag", "02-binary-triage")
            attempts = list((Path(folder) / "attempts").iterdir())
            self.assertEqual(len(attempts), 1)
            envelope = json.loads((attempts[0] / "result.json").read_text())
            self.assertEqual(envelope["execution_status"], "BLOCKED")
            self.assertEqual(envelope["worker_kind"], "pinned_container")

    def test_claim_ceiling_and_schema_closure_matrix(self):
        for _job, (contract_id, _result, schema) in core.SPECS.items():
            contract = json.loads((ROOT / f"registry/output-contracts/{contract_id}.json").read_text())
            self.assertEqual(_claim_class_errors(contract, {"lead": "static evidence"}), [])
            for forbidden in ("finding", "severity", "runtime_state"):
                self.assertTrue(_claim_class_errors(contract, {forbidden: "high"}))
        value = raw("02-debug-symbol-index", self.fixture["debug"])
        result = core.normalize("02-debug-symbol-index", inputs("02-debug-symbol-index", value), "a")
        result["authority"]["extra"] = True
        self.assertTrue(validate_document(result, "debug-symbol-index.schema.json"))

    def test_duplicate_binary_ids_and_unresolved_citations_are_rejected(self):
        value = raw("02-debug-symbol-index", self.fixture["debug"])
        inp = inputs("02-debug-symbol-index", value)
        inp["native_build"]["binaries"].append(copy.deepcopy(BINARY))
        with self.assertRaisesRegex(Blocked, "repeats a binary identity"):
            core.normalize("02-debug-symbol-index", inp, "a")

    def test_f02_consumes_all_four_canonical_receipts(self):
        with tempfile.TemporaryDirectory() as folder:
            supply = Path(folder); source = "sha256:" + "a" * 64; build = "sha256:" + "b" * 64
            for index, (job, (contract, result_name, _schema)) in enumerate(core.SPECS.items()):
                producer = supply / "producers" / job; attempt_id = f"attempt-{index}"
                attempt = producer / "attempts" / attempt_id; attempt.mkdir(parents=True)
                atomic_json(attempt / "permission.json", {"schema": assembly.PERMISSION_SCHEMA,
                    "run_id": "run", "job_id": job, "source_snapshot_sha256": source,
                    "permissions": core._permissions(job)})
                atomic_json(attempt / "lineage.json", {"schema": assembly.LINEAGE_SCHEMA,
                    "run_id": "run", "job_id": job, "source_snapshot_sha256": source,
                    "build_lineage_sha256": build})
                atomic_json(attempt / result_name, {"fixture": True})
                fingerprint = "sha256:" + str(index + 1) * 64
                envelope = terminal_envelope(run_id="run", job_id=job, attempt_id=attempt_id,
                    worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
                    input_fingerprint=fingerprint, output_contract=contract,
                    started_at="2026-09-27T00:00:00Z", finished_at="2026-09-27T00:00:01Z",
                    summary="fixture", artifacts=artifact_records(attempt,
                        ["permission.json", "lineage.json", result_name]))
                atomic_json(attempt / "result.json", envelope)
                pointer = {"schema": ACCEPTED_SCHEMA, "status": "OK", "run_id": "run", "job": job,
                    "attempt_id": attempt_id, "fingerprint": fingerprint, "envelope_path": "result.json",
                    "envelope_sha256": file_hash(attempt / "result.json"), "hashes": tree_hashes(attempt),
                    "accepted_at": "2026-09-27T00:00:02Z"}
                atomic_json(producer / "accepted.json", pointer); atomic_json(producer / "latest.json", {"attempt_id": attempt_id})
                iid = f"{index + 1:032x}"
                entry, _ = assembly._producer(supply, "run", source,
                    {"job": job, "contract": contract, "allowed_skip_reasons": []},
                    {"source_snapshot_sha256": source, "build_lineage_sha256": build,
                     "permissions": core._permissions(job), "terminal_instance_ids": [iid]},
                    {iid: {"instance_id": iid, "state": "succeeded", "group_id": job[3:][:40]}})
                self.assertEqual(entry["disposition"], "accepted")


if __name__ == "__main__":
    unittest.main()
