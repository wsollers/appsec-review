"""Live-adapter seam tests for the M02 static binary container boundary."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import binary_evidence_adapter as adapter  # noqa: E402
import container_execution as ce  # noqa: E402
from execution_state import atomic_json, file_hash  # noqa: E402
from schema_validate import validate_document  # noqa: E402

SHA = "sha256:" + "1" * 64


def native(binary: bool = True):
    value = {"job_id":"02-native-build","attempt_id":"native-1","fingerprint":SHA,
        "pointer_sha256":SHA,"result_sha256":SHA,"envelope_sha256":SHA,
        "source_revision":"a" * 40,"source_snapshot_sha256":SHA,"source_tree_sha256":SHA,
        "binaries":[]}
    if binary:
        value["binaries"] = [{"binary_id":"bin_1111111111111111","unit_id":"unit",
            "source_path":"hello.cpp","artifact_path":"outputs/unit/binaries/hello",
            "sha256":SHA,"size_bytes":4,"build_identity_sha256":SHA}]
    return value


class Runtime:
    host_flavor="linux"; docker_host=None; docker_executable="docker"; container_user="10001:10001"
    images_dir=Path("registry")


class BinaryEvidenceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        self.accepted = self.root / "native"; self.accepted.mkdir()
        binary = self.accepted / "outputs/unit/binaries/hello"; binary.parent.mkdir(parents=True)
        binary.write_bytes(b"ELF!")
        self.image = {"record":{"schema":"appsec-review/container-image/1.0",
            "image_id":"audit-binary-analysis","repository":"audit-binary-analysis",
            "digest":"sha256:" + "2" * 64,"digest_kind":"image-id",
            "dockerfile_sha256":SHA,"build_fingerprint_sha256":SHA,
            "build_attempt_id":"build-1","purpose":"static analysis","provenance":"test"},
            "record_sha256":"sha256:" + "3" * 64,
            "boundary_sha256":ce.boundary_sha256()}
        self.requests = []

    def tearDown(self): self.folder.cleanup()

    def run_container(self, runtime, **kwargs):
        request, trial = kwargs["request"], Path(kwargs["attempt_root"])
        self.requests.append(request)
        logs = trial / "logs/container"; logs.mkdir(parents=True)
        atomic_json(logs / ce.REQUEST_FILE, request)
        if request["argv"][0].endswith("analyze-binary"):
            out = trial / "scratch/evidence"; out.mkdir(parents=True)
            atomic_json(out / "summary.json", {"format":"elf","machine":"EM_X86_64",
                "sections":[".text",".debug_info"],"symbol_count":2,
                "has_debug_sections":True,"lief":{"libraries":["libc.so.6"]}})
            (out / "nm-symbols.txt").write_text("0000000000001000 T main\n", encoding="utf-8")
            (out / "checksec.txt").write_text("Full RELRO Canary found NX enabled PIE enabled\n", encoding="utf-8")
        else:
            (logs / "stdout.log").write_text(json.dumps({"architecture":"AMD64",
                "functions":[{"address":"0x1000","name":"main","block_count":2}],
                "call_edges":[]}), encoding="utf-8")
        return {"execution_status":"OK","result_sha256":"sha256:" + "4" * 64}

    @staticmethod
    def verify(*args, **kwargs): return {}

    def inputs(self, job, *, binary=True, upstream=None):
        return {"run_id":"run","job_id":job,"native_build":native(binary),
                "upstream":upstream or {},"image":self.image,"code":{}}

    def test_debug_and_triage_use_only_pinned_static_container_outputs(self):
        for job in ("02-debug-symbol-index", "02-binary-triage"):
            attempt = self.root / job; attempt.mkdir()
            raw = adapter.materialize("run", job, attempt, self.accepted, self.inputs(job),
                runtime_factory=lambda _source: Runtime(), run_container=self.run_container,
                verify=self.verify)
            self.assertEqual(validate_document(raw, "binary-static-evidence-input.schema.json"), [])
            receipt = json.loads((attempt / adapter.RECEIPT_FILE).read_text())
            self.assertEqual(validate_document(receipt, "binary-evidence-b13-receipts.schema.json"), [])
            request = self.requests[-1]
            self.assertEqual(request["network"], {"mode":"none","destinations":[]})
            self.assertEqual(request["image"], {"image_id":"audit-binary-analysis",
                                                 "digest":"sha256:" + "2" * 64})
            self.assertEqual(request["target_mounts"], [{"host_path":str(self.accepted),
                                                          "container_path":"/workspace"}])
            self.assertTrue(request["argv"][0].startswith("/usr/local/bin/"))
            self.assertFalse(receipt["target_execution"])
        self.assertEqual(self.requests[0]["argv"][0], "/usr/local/bin/analyze-binary")

    def test_cfg_joins_accepted_symbols_without_executing_binary(self):
        debug = {"result":{"records":[{"binary_id":"bin_1111111111111111",
            "symbols":[{"address":"0x1000","name":"main","symbol_id":"sym_aaaaaaaaaaaaaaaa"}]}]}}
        triage = {"result":{"records":[{"binary_id":"bin_1111111111111111",
            "architecture":"x86_64"}]}}
        attempt = self.root / "cfg"; attempt.mkdir()
        raw = adapter.materialize("run", "02-binary-cfg", attempt, self.accepted,
            self.inputs("02-binary-cfg", upstream={"02-debug-symbol-index":debug,
                                                   "02-binary-triage":triage}),
            runtime_factory=lambda _source: Runtime(), run_container=self.run_container,
            verify=self.verify)
        self.assertEqual(self.requests[-1]["argv"][0], "/usr/local/bin/angr-summary")
        self.assertEqual(raw["records"][0]["functions"][0]["symbol_id"], "sym_aaaaaaaaaaaaaaaa")

    def test_zero_accepted_binaries_is_evidence_supported_skip_input(self):
        attempt = self.root / "skip"; attempt.mkdir()
        raw = adapter.materialize("run", "02-binary-triage", attempt, self.accepted,
            self.inputs("02-binary-triage", binary=False),
            runtime_factory=lambda _source: self.fail("runtime must not start"),
            run_container=lambda *a, **k: self.fail("container must not start"), verify=self.verify)
        self.assertEqual(raw["records"], [])
        receipt = json.loads((attempt / adapter.RECEIPT_FILE).read_text())
        self.assertEqual(receipt["operations"], [])
        self.assertEqual(receipt["native_build"], {k:v for k,v in native(False).items() if k != "binaries"})

    def test_missing_or_oversized_raw_output_fails_closed(self):
        missing = self.root / "missing"; missing.mkdir()
        with self.assertRaisesRegex(Exception, "absent or exceeds"):
            adapter._bounded_text(missing / "summary.json")
        huge = missing / "summary.json"; huge.write_bytes(b"x" * (adapter.MAX_RAW_BYTES + 1))
        with self.assertRaisesRegex(Exception, "absent or exceeds"):
            adapter._bounded_text(huge)


if __name__ == "__main__": unittest.main()
