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
from execution_state import Blocked, atomic_json, digest  # noqa: E402
from schema_validate import validate_document  # noqa: E402

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


def raw(job: str, record: dict) -> dict:
    return {"schema": core.RAW_SCHEMA, "job_id": job,
            "native_build": {key: NATIVE[key] for key in NATIVE if key != "binaries"},
            "image": {"image_id": "audit-binary-analysis", "image_digest": None,
                      "status": "M02_UNRESOLVED"},
            "config": {"static_only": True, "adapter_id": "fixture-normalizer",
                       "adapter_version": "1"},
            "records": [{"binary_id": BINARY["binary_id"], "binary_sha256": H,
                         "build_identity_sha256": H2, **record}],
            "gaps": [core.M02_GAP]}


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
        cfg_inputs = inputs("02-binary-cfg", cfg_raw, upstream)
        cfg = core.normalize("02-binary-cfg", cfg_inputs, "a-cfg")
        intel_record = copy.deepcopy(self.fixture["intelligence"])
        intel_record["citations"] = [
            {"job_id": "02-binary-triage", "result_sha256": H3,
             "binary_id": BINARY["binary_id"], "record_identity": "format:ELF"},
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
            self.assertIn(core.M02_GAP, value["coverage_gaps"])
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
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "raw.json"); atomic_json(path, value)
            stale = copy.deepcopy(NATIVE); stale["result_sha256"] = "sha256:" + "9" * 64
            with mock.patch.object(core, "control_path", return_value=path), \
                 mock.patch.object(core, "_native", return_value=(Path(folder), stale)), \
                 mock.patch.object(core, "_upstream", return_value={}), \
                 mock.patch.object(core, "_code_hashes", return_value={}):
                with self.assertRaises(Blocked): core.current_inputs("run-binary", "02-binary-triage")
        claimed = copy.deepcopy(value)
        claimed["image"] = {"image_id": "audit-binary-analysis", "image_digest": H,
                            "status": "PINNED"}
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
        with self.assertRaisesRegex(Blocked, "mixed native-build generation"):
            core.normalize("02-binary-cfg",
                inputs("02-binary-cfg", raw("02-binary-cfg", self.fixture["cfg"]), upstream), "a-cfg")

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

    def test_registry_composition_stays_nominal_static_and_not_executable(self):
        source = (ROOT / "binary_evidence_core.py").read_text()
        self.assertNotIn("subprocess", source)
        self.assertNotIn("run_container", source)
        for job, (contract_id, result_name, schema_name) in core.SPECS.items():
            template = json.loads((ROOT / f"registry/job-templates/{job}.json").read_text())
            contract = json.loads((ROOT / f"registry/output-contracts/{contract_id}.json").read_text())
            self.assertFalse(template["implemented"])
            self.assertEqual(template["composition"]["output_contract_id"], contract_id)
            self.assertEqual(contract["result_schema"], {"artifact": result_name,
                                                         "schema_file": schema_name})
            self.assertTrue({"permission.json", "lineage.json"}.issubset(contract["required_files"]))
            self.assertNotIn("claim_types", contract)


if __name__ == "__main__":
    unittest.main()
