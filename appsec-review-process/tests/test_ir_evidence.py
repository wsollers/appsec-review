from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import execution_state as state
import ir_evidence as ir
from schema_validate import validate_document
from worker_result import artifact_records, terminal_envelope


@unittest.skipUnless(shutil.which("clang") and shutil.which("llvm-link-18") and
                     shutil.which("llvm-dis-18"), "LLVM 18 toolchain required")
class IrEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.owner = Path(self.temp.name)
        self.old_runs = state.RUNS; state.RUNS = self.owner / "runs"
        self.run_id = "ir-fixture"; self.run = state.RUNS / self.run_id
        self.target = self.owner / "target"; self.target.mkdir()
        shutil.copyfile(ROOT / "tests/fixtures/ir-evidence/pointer.c", self.target / "pointer.c")
        (self.run / "inputs").mkdir(parents=True)
        state.atomic_json(self.run / "inputs/artifact-manifest.json",
                          {"target": {"repo_path": str(self.target)}})
        self.snapshot = "sha256:" + state.file_hash(self.run / "inputs/artifact-manifest.json")
        self._native()

    def tearDown(self):
        state.RUNS = self.old_runs; self.temp.cleanup()

    def _publish(self, job, attempt_id, artifact, schema, extras=()):
        base = self.run / "data/jobs" / job; attempt = base / "attempts" / attempt_id
        envelope = terminal_envelope(run_id=self.run_id, job_id=job, attempt_id=attempt_id,
            worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
            input_fingerprint="sha256:" + state.digest({"job": job, "attempt": attempt_id}),
            output_contract=job.removeprefix("02-"), started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z", summary="fixture",
            artifacts=artifact_records(attempt, [artifact, *extras]))
        state.atomic_json(attempt / "result.json", envelope)
        state.atomic_json(base / "accepted.json", {"schema":"appsec-review/accepted-worker-result/1.0",
            "status":"OK", "run_id":self.run_id, "job":job, "attempt_id":attempt_id,
            "fingerprint":envelope["input_fingerprint"], "envelope_path":"result.json",
            "envelope_sha256":state.file_hash(attempt / "result.json"), "hashes":{}})

    def _native(self):
        attempt = self.run / "data/jobs/02-native-build/attempts/native-1"; attempt.mkdir(parents=True)
        db = attempt / "outputs/u/compile_commands.json"; db.parent.mkdir(parents=True)
        state.atomic_json(db, [{"directory":"/scratch/src", "file":"/scratch/src/pointer.c",
                                "arguments":["/usr/bin/clang","-g","-O0","-c","/scratch/src/pointer.c"]}])
        binary = attempt / "outputs/u/binaries/app"; binary.parent.mkdir(parents=True); binary.write_bytes(b"\x7fELFfixture")
        native = {"schema":"appsec-review/native-build/1", "run_id":self.run_id,
          "source_revision":"fixture-revision", "upstream":{"resolution":{"job":"02-build-resolution","attempt_id":"r1","lock_sha256":"sha256:"+"1"*64},
          "configured":{"job":"02-build-configure","attempt_id":"c1","result_sha256":"sha256:"+"2"*64,"envelope_sha256":"sha256:"+"3"*64}},
          "status":"OK", "units":[{"unit_id":"root","status":"OK","image_id":"image_build_aaaaaaaaaaaa",
          "image_digest":"sha256:"+"4"*64,"commands":[{},{}],"compile_database":{"path":"outputs/u/compile_commands.json","sha256":"sha256:"+state.file_hash(db),"entries":1},
          "binaries":[{"source_path":"app","artifact_path":"outputs/u/binaries/app","sha256":"sha256:"+state.file_hash(binary),"size_bytes":binary.stat().st_size}]}],"coverage_gaps":[]}
        state.atomic_json(attempt / "native-build.json", native)
        state.atomic_json(attempt / "inputs.json", {"source_snapshot_sha256":self.snapshot})
        self._publish("02-native-build", "native-1", "native-build.json", "native-build.schema.json",
                      ("outputs/u/compile_commands.json", "outputs/u/binaries/app", "inputs.json"))

    def test_nominal_capture_link_facts_are_deterministic_and_non_verdict(self):
        cap_attempt = self.run / "data/jobs/02-ir-capture/attempts/capture-1"; cap_attempt.mkdir(parents=True)
        first = ir.capture(self.run_id, cap_attempt); second_root = self.owner / "capture-repeat"; second_root.mkdir()
        second = ir.capture(self.run_id, second_root)
        self.assertEqual([{k:v for k,v in item.items() if k != "path"} for item in first["modules"]],
                         [{k:v for k,v in item.items() if k != "path"} for item in second["modules"]])
        self.assertEqual(validate_document(first, "ir-capture.schema.json"), [])
        state.atomic_json(cap_attempt / "ir-capture.json", first)
        self._publish("02-ir-capture", "capture-1", "ir-capture.json", "ir-capture.schema.json",
                      tuple(item["path"] for item in first["modules"]))

        link_attempt = self.run / "data/jobs/02-ir-link/attempts/link-1"; link_attempt.mkdir(parents=True)
        linked = ir.link(self.run_id, link_attempt); self.assertEqual(validate_document(linked, "ir-link.schema.json"), [])
        state.atomic_json(link_attempt / "ir-link.json", linked)
        self._publish("02-ir-link", "link-1", "ir-link.json", "ir-link.schema.json",
                      (linked["linked_module"]["path"],))
        fact_root = self.owner / "facts"; fact_root.mkdir()
        facts = ir.facts(self.run_id, fact_root)
        self.assertEqual(validate_document(facts, "ir-facts.schema.json"), [])
        self.assertTrue(facts["debug_locations"])
        self.assertTrue({"pointer-arithmetic", "memory-read"} & {x["kind"] for x in facts["facts"]})
        encoded = json.dumps(facts).lower()
        self.assertNotIn("severity", encoded); self.assertNotIn("vulnerability", encoded)
        malformed_facts = deepcopy(facts); malformed_facts["facts"][0]["kind"] = "vulnerability-verdict"
        self.assertTrue(validate_document(malformed_facts, "ir-facts.schema.json"))

    def test_stale_variant_and_malformed_bitcode_facts_fail_closed(self):
        manifest = self.run / "inputs/artifact-manifest.json"
        staged = state.read_json(manifest); staged["stale_variant_probe"] = True; state.atomic_json(manifest, staged)
        with self.assertRaisesRegex(state.Blocked, "source snapshot is stale"):
            ir.capture(self.run_id, self.owner / "stale")

        malformed = self.owner / "malformed"; malformed.mkdir(); bad = malformed / "bad.bc"; bad.write_bytes(b"not bitcode")
        with self.assertRaisesRegex(state.Blocked, "malformed"):
            ir._verify_artifact(malformed, {"path":"bad.bc","sha256":"sha256:"+state.file_hash(bad)}, b"BC\xc0\xde")
        with self.assertRaisesRegex(RuntimeError, "cannot be decoded"):
            # A file with only the bitcode magic passes the boundary check but not LLVM decoding.
            bad.write_bytes(b"BC\xc0\xdegarbage")
            import unittest.mock as mock
            with mock.patch.object(ir, "_accepted", return_value=(malformed,
                    {"source_revision":"r","source_snapshot_sha256":self.snapshot,"variant_sha256":"sha256:"+"1"*64,
                     "status":"OK","coverage_gaps":[],"linked_module":{"path":"bad.bc","sha256":"sha256:"+state.file_hash(bad)}}, {})):
                ir.facts(self.run_id, self.owner / "unused")


if __name__ == "__main__": unittest.main()
