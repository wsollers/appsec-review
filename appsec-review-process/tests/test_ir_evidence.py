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

    def _native(self, extra=()):
        attempt = self.run / "data/jobs/02-native-build/attempts/native-1"; attempt.mkdir(parents=True)
        db = attempt / "outputs/u/compile_commands.json"; db.parent.mkdir(parents=True)
        entries = [{"directory":"/scratch/src", "file":"/scratch/src/pointer.c",
                    "arguments":["/usr/bin/clang","-g","-O0","-c","/scratch/src/pointer.c"]}, *extra]
        state.atomic_json(db, entries)
        binary = attempt / "outputs/u/binaries/app"; binary.parent.mkdir(parents=True); binary.write_bytes(b"\x7fELFfixture")
        native = {"schema":"appsec-review/native-build/1", "run_id":self.run_id,
          "source_revision":intake.source_identity(str(self.target))["revision"], "upstream":{"resolution":{"job":"02-build-resolution","attempt_id":"r1","lock_sha256":"sha256:"+"1"*64},
          "configured":{"job":"02-build-configure","attempt_id":"c1","result_sha256":"sha256:"+"2"*64,"envelope_sha256":"sha256:"+"3"*64}},
          "status":"OK", "units":[{"unit_id":"root","status":"OK","image_id":"image_build_aaaaaaaaaaaa",
          "image_digest":"sha256:"+"4"*64,"commands":[{},{}],"compile_database":{"path":"outputs/u/compile_commands.json","sha256":"sha256:"+state.file_hash(db),"entries":len(entries)},
          "binaries":[{"source_path":"app","artifact_path":"outputs/u/binaries/app","sha256":"sha256:"+state.file_hash(binary),"size_bytes":binary.stat().st_size}]}],"coverage_gaps":[]}
        state.atomic_json(attempt / "native-build.json", native)
        state.atomic_json(attempt / "inputs.json", {"source_snapshot_sha256":self.snapshot,
            "source_tree_sha256":ir._source_tree_identity(self.target),
            "image_records":{"image_build_aaaaaaaaaaaa":{"sha256":FixtureToolchain.toolchain_sha256,
              "value":{"digest":FixtureToolchain.image_digest}}}})
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
        sources={item["module_id"]:item for item in facts["sources"]}
        for item in facts["facts"]:
            if item["module_id"] is not None:
                self.assertIn(item["module_id"],sources)
                self.assertEqual((item["source_path"],item["source_sha256"]),
                                 (sources[item["module_id"]]["path"],sources[item["module_id"]]["sha256"]))
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

        # ADR-0014 slice 1: several variants link the largest one and gap the rest; one variant
        # built with two toolchains still fails closed.
        capture = {"modules":[{"variant_sha256":"sha256:"+"1"*64,"toolchain_sha256":self.toolchain.toolchain_sha256},
                              {"variant_sha256":"sha256:"+"1"*64,"toolchain_sha256":"sha256:"+"8"*64}],
                   "variants":[{"unit_id":"u1","variant_sha256":"sha256:"+"1"*64,
                                "image_id":self.toolchain.image_id,"image_digest":self.toolchain.image_digest}],
                   "source_snapshot_sha256":self.snapshot,
                   "source_tree_sha256":ir._source_tree_identity(self.target),
                   "checkout_identity_sha256":ir._source_tree_identity(self.target),
                   "source_revision":intake.source_identity(str(self.target))["revision"]}
        with mock.patch.object(ir,"_accepted",return_value=(self.owner,capture,{})):
            with self.assertRaisesRegex(state.Blocked,"mixed toolchains"):
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

    GENERATED = {"directory":"/scratch/src/build", "file":"/scratch/src/build/app_autogen/mocs_compilation.cpp",
                 "arguments":["/usr/bin/clang++","-c","/scratch/src/build/app_autogen/mocs_compilation.cpp"]}

    def _republish_native(self, extra):
        shutil.rmtree(self.run / "data/jobs/02-native-build"); self._native(extra)

    def test_generated_source_absent_from_checkout_is_a_capture_gap(self):
        self._republish_native([self.GENERATED])
        attempt=self.owner/"generated"; attempt.mkdir()
        inputs=ir.current_inputs(self.run_id,"02-ir-capture")
        captured=ir.capture(self.run_id,attempt,toolchain=self.toolchain)
        self.assertEqual(len(captured["modules"]),1)
        self.assertEqual(captured["status"],"OK_WITH_GAPS")
        self.assertEqual(captured["coverage_gaps"],[{"unit_id":"root","compile_index":1,
            "source_path":"build/app_autogen/mocs_compilation.cpp","reason":"generated-source-not-in-checkout"}])
        state.atomic_json(attempt/"inputs.json",inputs); state.atomic_json(attempt/"ir-capture.json",captured)
        permission,lineage=ir._producer_receipts(self.run_id,"02-ir-capture",inputs)
        state.atomic_json(attempt/"permission.json",permission); state.atomic_json(attempt/"lineage.json",lineage)
        ir._validate_attempt("02-ir-capture",attempt,inputs)
        forged=deepcopy(captured); forged["coverage_gaps"]=[]
        forged["status"]="OK"; state.atomic_json(attempt/"ir-capture.json",forged)
        with self.assertRaises(state.Blocked):
            ir._validate_attempt("02-ir-capture",attempt,inputs)

    def test_generated_path_through_symlink_still_fails_closed(self):
        outside=self.owner/"outside"; outside.mkdir(); (self.target/"build").symlink_to(outside)
        self._republish_native([self.GENERATED])
        with self.assertRaises(state.Blocked):
            ir.capture(self.run_id,self.owner/"escape",toolchain=self.toolchain)

    def test_e02_attested_tree_rejects_post_acceptance_checkout_mutation(self):
        (self.target/"pointer.c").write_text("int main(void) { return 7; }\n",encoding="utf-8")
        with self.assertRaisesRegex(state.Blocked,"source_tree_sha256 attestation"):
            ir.capture(self.run_id,self.owner/"mutated",toolchain=self.toolchain)

    def test_resealed_capture_semantics_fail_attempt_validation(self):
        attempt=self.owner/"validate-forgery"; attempt.mkdir()
        inputs=ir.current_inputs(self.run_id,"02-ir-capture")
        captured=ir.capture(self.run_id,attempt,toolchain=self.toolchain)
        state.atomic_json(attempt/"inputs.json",inputs)
        state.atomic_json(attempt/"ir-capture.json",captured)
        permission,lineage=ir._producer_receipts(self.run_id,"02-ir-capture",inputs)
        state.atomic_json(attempt/"permission.json",permission); state.atomic_json(attempt/"lineage.json",lineage)
        ir._validate_attempt("02-ir-capture",attempt,inputs)
        for field,value in (("native_build",captured["native_build"]|{"attempt_id":"forged"}),
                            ("source_tree_sha256","sha256:"+"9"*64)):
            forged=deepcopy(captured); forged[field]=value; state.atomic_json(attempt/"ir-capture.json",forged)
            with self.subTest(field=field), self.assertRaises(state.Blocked):
                ir._validate_attempt("02-ir-capture",attempt,inputs)
        forged=deepcopy(captured); forged["modules"][0]["source_path"]="forged.c"
        state.atomic_json(attempt/"ir-capture.json",forged)
        with self.assertRaisesRegex(state.Blocked,"module lineage"):
            ir._validate_attempt("02-ir-capture",attempt,inputs)

    def test_f02_actual_producer_consumer_accepts_ir_receipts_and_artifacts(self):
        supply=self.owner/"f02-supply"; source=self.snapshot; build="sha256:"+"9"*64
        for index,(job,(artifact,_schema,contract)) in enumerate(ir.JOBS.items()):
            attempt_id=f"{contract}-1"; producer=supply/"producers"/job; attempt=producer/"attempts"/attempt_id
            attempt.mkdir(parents=True); inputs={"run_id":self.run_id,"source_snapshot_sha256":source,
                                                "build_lineage_sha256":build}
            permission,lineage=ir._producer_receipts(self.run_id,job,inputs)
            state.atomic_json(attempt/"permission.json",permission); state.atomic_json(attempt/"lineage.json",lineage)
            state.atomic_json(attempt/artifact,{"schema":f"fixture/{contract}"})
            artifacts=artifact_records(attempt,["permission.json","lineage.json",artifact])
            envelope=terminal_envelope(run_id=self.run_id,job_id=job,attempt_id=attempt_id,
              worker_kind="deterministic_python",execution_status="OK",acceptance_status="CURRENT",
              input_fingerprint="sha256:"+str(index+1)*64,output_contract=contract,started_at="2026-01-01T00:00:00Z",
              finished_at="2026-01-01T00:00:01Z",summary="fixture",artifacts=artifacts)
            state.atomic_json(attempt/"result.json",envelope)
            pointer={"schema":"appsec-review/accepted-worker-result/1.0","status":"OK","run_id":self.run_id,
              "job":job,"attempt_id":attempt_id,"fingerprint":envelope["input_fingerprint"],
              "envelope_path":"result.json","envelope_sha256":state.file_hash(attempt/"result.json"),
              "hashes":tree_hashes(attempt),"accepted_at":"2026-01-01T00:00:02Z"}
            state.atomic_json(producer/"accepted.json",pointer); state.atomic_json(producer/"latest.json",{"attempt_id":attempt_id})
            instance=chr(ord('a')+index)*32; binding={"source_snapshot_sha256":source,"build_lineage_sha256":build,
              "permissions":ir.PERMISSIONS[job],"terminal_instance_ids":[instance]}
            entry,copies=assembly._producer(supply,self.run_id,source,
              {"job":job,"contract":contract,"allowed_skip_reasons":[]},binding,
              {instance:{"state":"succeeded","group_id":job.removeprefix("02-")[:40]}})
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
                     "source_tree_sha256":ir._source_tree_identity(self.target),
                     "checkout_identity_sha256":ir._source_tree_identity(self.target),
                     "variant_sha256":"sha256:"+"1"*64,"toolchain_sha256":self.toolchain.toolchain_sha256,
                     "image_id":self.toolchain.image_id,"image_digest":self.toolchain.image_digest,
                     "sources":[{"module_id":"m","path":"pointer.c","sha256":"sha256:"+state.file_hash(self.target/"pointer.c")}],
                     "status":"OK","coverage_gaps":[],"linked_module":{"path":"bad.bc","sha256":"sha256:"+state.file_hash(bad)}}, {})):
                ir.facts(self.run_id, self.owner / "unused",toolchain=self.toolchain)


class ProhibitedKeysTest(unittest.TestCase):
    def test_words_in_data_are_not_verdicts(self):
        import ir_evidence
        self.assertFalse(ir_evidence._prohibited_keys({"facts": [{"function": "pf_finding_severity_cb", "source_path": "src/vulnerability.c"}]}))
        self.assertTrue(ir_evidence._prohibited_keys({"facts": [{"severity": "high"}]}))


if __name__ == "__main__": unittest.main()


class LinkSelectionTests(unittest.TestCase):
    def test_largest_variant_is_linked_and_others_are_named_gaps(self):
        a, b = "sha256:" + "1" * 64, "sha256:" + "2" * 64
        captured = {"modules": [{"variant_sha256": a, "module_id": "m1"},
                                {"variant_sha256": b, "module_id": "m2"},
                                {"variant_sha256": b, "module_id": "m3"}],
                    "variants": [{"unit_id": "dir:a", "variant_sha256": a},
                                 {"unit_id": "dir:b", "variant_sha256": b}]}
        primary, selected, gaps = ir.link_selection(captured)
        self.assertEqual(primary, b)
        self.assertEqual([m["module_id"] for m in selected], ["m2", "m3"])
        self.assertEqual(gaps, [{"unit_id": "dir:a", "reason": ir.LINK_GAP, "modules": 1}])

    def test_zero_is_a_skip(self):
        self.assertTrue(ir.should_skip("02-ir-capture", {"upstream_result": {"units": []}}))
        self.assertTrue(ir.should_skip("02-ir-link", {"upstream_result": {"status": "OK_WITH_GAPS", "modules": []}}))
        self.assertTrue(ir.should_skip("02-ir-facts", {"upstream_result": {"status": "SKIPPED"}}))
        self.assertFalse(ir.should_skip("02-ir-link", {"upstream_result": {"status": "OK", "modules": [{}]}}))
