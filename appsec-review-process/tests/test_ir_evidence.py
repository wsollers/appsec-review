from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import execution_state as state
from execution_state import tree_hashes
import evidence_assembly as assembly
import ir_evidence as ir
import intake
import validate_job_output as output_validator
from schema_validate import validate_document
from worker_result import artifact_records, terminal_envelope

class FixtureToolchain:
    image_id="image_build_aaaaaaaaaaaa"; image_digest="sha256:"+"4"*64
    toolchain_sha256="sha256:"+"d"*64
    def compile(self,argv,source,destination):
        actual=["clang",*argv[1:]]
        actual[actual.index(source.name)]=str(source)
        actual[actual.index("modules/"+destination.name)]=str(destination)
        return subprocess.run(actual,capture_output=True,check=False).returncode
    def link(self,modules,destination):
        return subprocess.run(["llvm-link-18",*map(str,modules),"-o",str(destination)],capture_output=True,check=False).returncode
    def disassemble(self,module):
        done=subprocess.run(["llvm-dis-18",str(module),"-o","-"],capture_output=True,check=True,text=True)
        return done.stdout


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
        self.toolchain=FixtureToolchain()

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
            "envelope_sha256":state.file_hash(attempt / "result.json"), "hashes":tree_hashes(attempt),
            "accepted_at":"2026-01-01T00:00:02Z"})
        state.atomic_json(base / "latest.json", {"attempt_id":attempt_id,
                                                  "updated_at":"2026-01-01T00:00:02Z"})

    def _native(self):
        attempt = self.run / "data/jobs/02-native-build/attempts/native-1"; attempt.mkdir(parents=True)
        db = attempt / "outputs/u/compile_commands.json"; db.parent.mkdir(parents=True)
        state.atomic_json(db, [{"directory":"/scratch/src", "file":"/scratch/src/pointer.c",
                                "arguments":["/usr/bin/clang","-g","-O0","-c","/scratch/src/pointer.c"]}])
        binary = attempt / "outputs/u/binaries/app"; binary.parent.mkdir(parents=True); binary.write_bytes(b"\x7fELFfixture")
        native = {"schema":"appsec-review/native-build/1", "run_id":self.run_id,
          "source_revision":intake.source_identity(str(self.target))["revision"], "upstream":{"resolution":{"job":"02-build-resolution","attempt_id":"r1","lock_sha256":"sha256:"+"1"*64},
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
        first = ir.capture(self.run_id, cap_attempt,toolchain=self.toolchain); second_root = self.owner / "capture-repeat"; second_root.mkdir()
        second = ir.capture(self.run_id, second_root,toolchain=self.toolchain)
        self.assertEqual([{k:v for k,v in item.items() if k != "path"} for item in first["modules"]],
                         [{k:v for k,v in item.items() if k != "path"} for item in second["modules"]])
        self.assertEqual(validate_document(first, "ir-capture.schema.json"), [])
        self.assertIn("-O0", first["modules"][0]["compiler_argv"])
        self.assertEqual(first["modules"][0]["toolchain_sha256"], self.toolchain.toolchain_sha256)
        state.atomic_json(cap_attempt / "ir-capture.json", first)
        self._publish("02-ir-capture", "capture-1", "ir-capture.json", "ir-capture.schema.json",
                      tuple(item["path"] for item in first["modules"]))

        link_attempt = self.run / "data/jobs/02-ir-link/attempts/link-1"; link_attempt.mkdir(parents=True)
        linked = ir.link(self.run_id, link_attempt,toolchain=self.toolchain); self.assertEqual(validate_document(linked, "ir-link.schema.json"), [])
        state.atomic_json(link_attempt / "ir-link.json", linked)
        self._publish("02-ir-link", "link-1", "ir-link.json", "ir-link.schema.json",
                      (linked["linked_module"]["path"],))
        fact_root = self.owner / "facts"; fact_root.mkdir()
        facts = ir.facts(self.run_id, fact_root,toolchain=self.toolchain)
        self.assertEqual(validate_document(facts, "ir-facts.schema.json"), [])
        self.assertTrue(facts["debug_locations"])
        self.assertTrue({"pointer-arithmetic", "memory-read"} & {x["kind"] for x in facts["facts"]})
        self.assertTrue({"greet","main"} <= {x["function"] for x in facts["facts"]})
        encoded = json.dumps(facts).lower()
        self.assertNotIn("severity", encoded); self.assertNotIn("vulnerability", encoded)
        malformed_facts = deepcopy(facts); malformed_facts["facts"][0]["kind"] = "vulnerability-verdict"
        self.assertTrue(validate_document(malformed_facts, "ir-facts.schema.json"))

    def test_current_envelope_mixed_variant_and_f02_receipts_fail_closed(self):
        native_base = self.run / "data/jobs/02-native-build"
        pointer = state.read_json(native_base / "accepted.json")
        envelope_path = native_base / "attempts/native-1/result.json"
        envelope = state.read_json(envelope_path); envelope["acceptance_status"] = "SUPERSEDED"
        state.atomic_json(envelope_path, envelope); pointer["envelope_sha256"] = state.file_hash(envelope_path)
        pointer["hashes"] = tree_hashes(envelope_path.parent)
        state.atomic_json(native_base / "accepted.json", pointer)
        with self.assertRaisesRegex(state.Blocked, "terminal envelope"):
            ir._accepted(self.run_id, "02-native-build", "native-build.json",
                         "native-build.schema.json", "native-build")

        capture = {"modules":[{"variant_sha256":"sha256:"+"1"*64,"toolchain_sha256":self.toolchain.toolchain_sha256},
                              {"variant_sha256":"sha256:"+"2"*64,"toolchain_sha256":self.toolchain.toolchain_sha256}],
                   "variants":[{"image_id":self.toolchain.image_id,"image_digest":self.toolchain.image_digest}],
                   "source_snapshot_sha256":self.snapshot,
                   "checkout_identity_sha256":"sha256:"+intake.source_identity(str(self.target))["fingerprint"],
                   "source_revision":intake.source_identity(str(self.target))["revision"]}
        with mock.patch.object(ir,"_accepted",return_value=(self.owner,capture,{})):
            with self.assertRaisesRegex(state.Blocked,"mixed variants"):
                ir.link(self.run_id,self.owner/"mixed",toolchain=self.toolchain)

        inputs={"run_id":self.run_id,"source_snapshot_sha256":self.snapshot,
                "build_lineage_sha256":"sha256:"+"9"*64}
        permission,lineage=ir._producer_receipts(self.run_id,"02-ir-capture",inputs)
        self.assertEqual(permission["schema"],"appsec-review/producer-permission-receipt/1.0")
        self.assertEqual(permission["permissions"],["read-source","write-run-data"])
        self.assertEqual(lineage["build_lineage_sha256"],"sha256:"+"9"*64)
        for contract in ("ir-capture","ir-link","ir-facts"):
            declared=json.loads((ROOT/"registry/output-contracts"/(contract+".json")).read_text())
            policy=output_validator.CLAIM_CLASS_POLICIES[contract]
            self.assertEqual(policy["claim_class_id"],declared["claim_class"]["claim_class_id"])
            self.assertEqual(policy["allowed_assertions"],set(declared["claim_class"]["allowed_assertions"]))

    def test_resealed_capture_source_and_pointer_forgery_is_independently_rejected(self):
        attempt=self.run/"data/jobs/02-ir-capture/attempts/capture-forged"; attempt.mkdir(parents=True)
        captured=ir.capture(self.run_id,attempt,toolchain=self.toolchain)
        state.atomic_json(attempt/"ir-capture.json",captured)
        self._publish("02-ir-capture","capture-forged","ir-capture.json","ir-capture.schema.json",
                      tuple(item["path"] for item in captured["modules"]))
        captured["source_snapshot_sha256"]="sha256:"+"8"*64
        captured["checkout_identity_sha256"]="sha256:"+"9"*64
        state.atomic_json(attempt/"ir-capture.json",captured)
        envelope=state.read_json(attempt/"result.json")
        next(item for item in envelope["artifacts"] if item["path"]=="ir-capture.json")["sha256"]=state.file_hash(attempt/"ir-capture.json")
        state.atomic_json(attempt/"result.json",envelope)
        pointer_path=self.run/"data/jobs/02-ir-capture/accepted.json"; pointer=state.read_json(pointer_path)
        pointer["envelope_sha256"]=state.file_hash(attempt/"result.json"); pointer["hashes"]=tree_hashes(attempt)
        state.atomic_json(pointer_path,pointer)
        with self.assertRaisesRegex(state.Blocked,"source/checkout generation is stale"):
            ir.link(self.run_id,self.owner/"forged-link",toolchain=self.toolchain)

    def test_f02_actual_producer_consumer_accepts_ir_receipts_and_artifacts(self):
        supply=self.owner/"f02-supply"; producer=supply/"producers/02-ir-facts"; attempt=producer/"attempts/ir-facts-1"
        attempt.mkdir(parents=True); source=self.snapshot; build="sha256:"+"9"*64
        inputs={"run_id":self.run_id,"source_snapshot_sha256":source,"build_lineage_sha256":build}
        permission,lineage=ir._producer_receipts(self.run_id,"02-ir-facts",inputs)
        state.atomic_json(attempt/"permission.json",permission); state.atomic_json(attempt/"lineage.json",lineage)
        state.atomic_json(attempt/"ir-facts.json",{"schema":"fixture/ir-facts","facts":[]})
        artifacts=artifact_records(attempt,["permission.json","lineage.json","ir-facts.json"])
        envelope=terminal_envelope(run_id=self.run_id,job_id="02-ir-facts",attempt_id="ir-facts-1",
          worker_kind="deterministic_python",execution_status="OK",acceptance_status="CURRENT",
          input_fingerprint="sha256:"+"8"*64,output_contract="ir-facts",started_at="2026-01-01T00:00:00Z",
          finished_at="2026-01-01T00:00:01Z",summary="fixture",artifacts=artifacts)
        state.atomic_json(attempt/"result.json",envelope)
        pointer={"schema":"appsec-review/accepted-worker-result/1.0","status":"OK","run_id":self.run_id,
          "job":"02-ir-facts","attempt_id":"ir-facts-1","fingerprint":envelope["input_fingerprint"],
          "envelope_path":"result.json","envelope_sha256":state.file_hash(attempt/"result.json"),
          "hashes":tree_hashes(attempt),"accepted_at":"2026-01-01T00:00:02Z"}
        state.atomic_json(producer/"accepted.json",pointer); state.atomic_json(producer/"latest.json",{"attempt_id":"ir-facts-1"})
        instance="a"*32; binding={"source_snapshot_sha256":source,"build_lineage_sha256":build,
          "permissions":ir.PERMISSIONS["02-ir-facts"],"terminal_instance_ids":[instance]}
        entry,copies=assembly._producer(supply,self.run_id,source,
          {"job":"02-ir-facts","contract":"ir-facts","allowed_skip_reasons":[]},binding,
          {instance:{"state":"succeeded","group_id":"ir-facts"}})
        self.assertEqual(entry["disposition"],"accepted"); self.assertEqual(len(copies),3)

    def test_stale_variant_and_malformed_bitcode_facts_fail_closed(self):
        manifest = self.run / "inputs/artifact-manifest.json"
        staged = state.read_json(manifest); staged["stale_variant_probe"] = True; state.atomic_json(manifest, staged)
        with self.assertRaisesRegex(state.Blocked, "source snapshot is stale"):
            ir.capture(self.run_id, self.owner / "stale",toolchain=self.toolchain)
        staged.pop("stale_variant_probe"); state.atomic_json(manifest, staged)

        malformed = self.owner / "malformed"; malformed.mkdir(); bad = malformed / "bad.bc"; bad.write_bytes(b"not bitcode")
        with self.assertRaisesRegex(state.Blocked, "malformed"):
            ir._verify_artifact(malformed, {"path":"bad.bc","sha256":"sha256:"+state.file_hash(bad)}, b"BC\xc0\xde")
        with self.assertRaisesRegex(RuntimeError, "cannot be decoded"):
            # A file with only the bitcode magic passes the boundary check but not LLVM decoding.
            bad.write_bytes(b"BC\xc0\xdegarbage")
            with mock.patch.object(ir, "_accepted", return_value=(malformed,
                    {"source_revision":intake.source_identity(str(self.target))["revision"],
                     "source_snapshot_sha256":self.snapshot,
                     "checkout_identity_sha256":"sha256:"+intake.source_identity(str(self.target))["fingerprint"],
                     "variant_sha256":"sha256:"+"1"*64,"toolchain_sha256":self.toolchain.toolchain_sha256,
                     "image_id":self.toolchain.image_id,"image_digest":self.toolchain.image_digest,
                     "sources":[{"module_id":"m","path":"pointer.c","sha256":"sha256:"+state.file_hash(self.target/"pointer.c")}],
                     "status":"OK","coverage_gaps":[],"linked_module":{"path":"bad.bc","sha256":"sha256:"+state.file_hash(bad)}}, {})):
                ir.facts(self.run_id, self.owner / "unused",toolchain=self.toolchain)


if __name__ == "__main__": unittest.main()
