from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))
import registry_paths

import execution_state as state
from execution_state import tree_hashes
import intake
import ir_capture
import ir_evidence as ir
import ir_facts
import ir_link
import container_execution as ce
from worker_result import artifact_records, terminal_envelope


class IrB13ToolchainTests(unittest.TestCase):
    def test_capture_rejects_a_registry_record_other_than_the_native_generation(self):
        from ir_b13_toolchain import _image

        record = {"digest": "sha256:" + "4" * 64}
        inputs = {"upstream_result": {"units": [{"unit_id": "root", "image_id": "fixture",
                                                   "image_digest": record["digest"]}]},
                  "toolchain_bindings": [["root", "sha256:" + "a" * 64]],
                  "toolchain_records": [["fixture", {"sha256": "sha256:" + "a" * 64,
                                                        "value": {"digest": "sha256:" + "5" * 64}}]]}
        with mock.patch("container_execution.load_image_registry", return_value={"fixture": record}), \
             mock.patch("ir_b13_toolchain._record_path", return_value=Path("/fixture.json")), \
             mock.patch("ir_b13_toolchain.read_json", return_value=record), \
             mock.patch("ir_b13_toolchain.file_hash", return_value="a" * 64):
            with self.assertRaisesRegex(state.Blocked, "accepted native-build generation"):
                _image(inputs, "02-ir-capture")

    def test_receipt_trial_path_traversal_is_rejected_before_dereference(self):
        from ir_b13_toolchain import validate_receipts

        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            state.atomic_json(attempt / "b13-receipts.json", {
                "schema":"appsec-review/ir-b13-receipts/1.0", "run_id":"fixture",
                "job_id":"02-ir-facts", "image_id":"fixture", "image_digest":"sha256:"+"4"*64,
                "toolchain_sha256":"sha256:"+"a"*64, "operations":[{
                    "operation":"disassemble","adapter_attempt_id":"facts-0001-fixture",
                    "trial_path":"../outside","expected_result_sha256":"sha256:"+"b"*64,
                    "output_path":"scratch/module.ll","output_sha256":"sha256:"+"c"*64,
                    "execution_status":"OK"}]})
            inputs = {"run_id":"fixture", "source_snapshot_sha256":"sha256:"+"d"*64}
            with mock.patch("ir_b13_toolchain._image",
                            return_value=("fixture","sha256:"+"4"*64,"sha256:"+"a"*64,{})), \
                 mock.patch("ir_b13_toolchain._runtime", return_value=SimpleNamespace()):
                with self.assertRaisesRegex(state.Blocked, "trial path is unsafe"):
                    validate_receipts("02-ir-facts", inputs, attempt)

    @unittest.skipUnless(os.environ.get("APPSEC_RUN_LIVE_IR_B13") == "1",
                         "set APPSEC_RUN_LIVE_IR_B13=1 for the bounded Docker qualification")
    def test_live_source_to_accepted_ir_facts(self):
        image_path = registry_paths.record(registry_paths.CONTAINER_IMAGES, "audit-buildenv-cpp")
        self.assertTrue(image_path.is_file(), "generate the host-local audit-buildenv-cpp record first")
        image = state.read_json(image_path)
        image_id = "image_build_" + image["digest"].removeprefix("sha256:")[:12]
        dynamic_path = ce.BUILD_IMAGES_DIR / f"{image_id}.json"
        dynamic = {**image, "image_id":image_id,
                   "purpose":"Live IR B13 qualification image; aliases the exact accepted build image."}
        state.atomic_json(dynamic_path, dynamic)
        with tempfile.TemporaryDirectory(prefix="appsec-ir-b13-") as temporary:
            owner = Path(temporary); old_runs = state.RUNS; state.RUNS = owner / "runs"
            try:
                run_id = "ir-b13-live"; run = state.RUNS / run_id
                target = owner / "target"; target.mkdir()
                source = target / "pointer.c"
                source.write_text(
                    "#include <stddef.h>\n"
                    "static int sum(const int *p, size_t n) { int r=0; for(size_t i=0;i<n;i++) r += p[i]; return r; }\n"
                    "int main(void) { int values[3]={1,2,3}; return sum(values,3)==6 ? 0 : 1; }\n",
                    encoding="utf-8")
                (run / "inputs").mkdir(parents=True)
                state.atomic_json(run / "inputs/artifact-manifest.json",
                                  {"target": {"repo_path": str(target)}})
                snapshot = "sha256:" + state.file_hash(run / "inputs/artifact-manifest.json")
                native = run / "data/jobs/02-native-build/attempts/native-live"
                database = native / "outputs/root/compile_commands.json"; database.parent.mkdir(parents=True)
                state.atomic_json(database, [{"directory": "/scratch/src", "file": "/scratch/src/pointer.c",
                    "arguments": ["/opt/llvm/bin/clang", "-g", "-O0", "-c", "/scratch/src/pointer.c"]}])
                binary = native / "outputs/root/binaries/app"; binary.parent.mkdir(parents=True)
                binary.write_bytes(b"\x7fELFqualification")
                result = {"schema":"appsec-review/native-build/1", "run_id":run_id,
                    "source_revision":intake.source_identity(str(target))["revision"],
                    "upstream":{"resolution":{"job":"02-build-resolution","attempt_id":"resolution-live",
                        "lock_sha256":"sha256:"+"1"*64},"configured":{"job":"02-build-configure",
                        "attempt_id":"configure-live","result_sha256":"sha256:"+"2"*64,
                        "envelope_sha256":"sha256:"+"3"*64}}, "status":"OK", "units":[{
                        "unit_id":"root","status":"OK","image_id":image_id,
                        "image_digest":image["digest"],"commands":[{},{}],"compile_database":{
                        "path":"outputs/root/compile_commands.json","sha256":"sha256:"+state.file_hash(database),
                        "entries":1},"binaries":[{"source_path":"app","artifact_path":"outputs/root/binaries/app",
                        "sha256":"sha256:"+state.file_hash(binary),"size_bytes":binary.stat().st_size}]}],
                    "coverage_gaps":[]}
                state.atomic_json(native / "native-build.json", result)
                state.atomic_json(native / "inputs.json", {"source_snapshot_sha256":snapshot,
                    "source_tree_sha256":ir._source_tree_identity(target), "image_records":{
                    image_id:{"value":dynamic,"sha256":"sha256:"+state.file_hash(dynamic_path)}}})
                envelope = terminal_envelope(run_id=run_id, job_id="02-native-build", attempt_id="native-live",
                    worker_kind="pinned_container", execution_status="OK", acceptance_status="CURRENT",
                    input_fingerprint="sha256:"+"6"*64, output_contract="native-build",
                    started_at="2026-09-27T00:00:00Z", finished_at="2026-09-27T00:00:01Z",
                    summary="qualification fixture", artifacts=artifact_records(native,
                    ["native-build.json","inputs.json","outputs/root/compile_commands.json",
                     "outputs/root/binaries/app"]))
                state.atomic_json(native / "result.json", envelope)
                base = native.parents[1]
                state.atomic_json(base / "accepted.json", {"schema":"appsec-review/accepted-worker-result/1.0",
                    "status":"OK","run_id":run_id,"job":"02-native-build","attempt_id":"native-live",
                    "fingerprint":envelope["input_fingerprint"],"envelope_path":"result.json",
                    "envelope_sha256":state.file_hash(native/"result.json"),"hashes":tree_hashes(native),
                    "accepted_at":"2026-09-27T00:00:02Z"})
                state.atomic_json(base / "latest.json", {"attempt_id":"native-live",
                    "updated_at":"2026-09-27T00:00:02Z"})

                pointers = [ir_capture.run(run_id,"qualification-capture"),
                            ir_link.run(run_id,"qualification-link"),
                            ir_facts.run(run_id,"qualification-facts")]
                attempts = [ir_capture.validate(run_id), ir_link.validate(run_id), ir_facts.validate(run_id)]
                facts = state.read_json(attempts[-1] / "ir-facts.json")
                self.assertTrue(facts["facts"]); self.assertTrue(facts["debug_locations"])
                self.assertTrue({"memory-read", "pointer-arithmetic"} & {item["kind"] for item in facts["facts"]})
                output = os.environ.get("APPSEC_IR_B13_QUALIFICATION_OUT")
                if output:
                    state.atomic_json(Path(output), {"schema":"appsec-review/ir-b13-qualification/1.0",
                        "run_id":run_id,"image_id":image_id,"image_digest":image["digest"],
                        "source_tree_sha256":ir._source_tree_identity(target),
                        "accepted_attempts":[{"job":job,"attempt_id":pointer["attempt_id"],
                            "envelope_sha256":"sha256:"+state.file_hash(attempt/"result.json"),
                            "b13_receipts_sha256":"sha256:"+state.file_hash(attempt/"b13-receipts.json")}
                            for job,pointer,attempt in zip(("02-ir-capture","02-ir-link","02-ir-facts"),pointers,attempts)],
                        "modules":len(state.read_json(attempts[0]/"ir-capture.json")["modules"]),
                        "facts":len(facts["facts"]),"debug_locations":len(facts["debug_locations"]),
                        "fact_kinds":sorted({item["kind"] for item in facts["facts"]}),
                        "network_mode":"none","limits":{"timeout_seconds_by_job":{
                            "02-ir-capture":900,"02-ir-link":300,"02-ir-facts":300},
                            "memory_bytes":4*1024*1024*1024,"cpu_millis":4000,
                            "pids":512,"tmpfs_bytes":512*1024*1024}})
            finally:
                state.RUNS = old_runs
                dynamic_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
