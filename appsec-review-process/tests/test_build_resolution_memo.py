"""Brief N: per-unit memo for 02-build-resolution (hit, miss, tamper, image gone, prod default).

The unit's copy-on-write install is stubbed; its trial is a real B13 attempt produced through the
scripted docker, so a memo hit exercises the real independent re-verification.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_resolution as worker  # noqa: E402
import container_execution as ce  # noqa: E402
import container_execution_support as support  # noqa: E402
import execution_state as state  # noqa: E402
from test_container_execution import ScriptedDocker  # noqa: E402

RUN = "run-br-memo"
CLANG = ["/opt/llvm/bin/clang", "/opt/llvm/bin/clang++"]


class BuildResolutionMemoTests(unittest.TestCase):
    PLAN = {"unit_id": "dir:.", "root": ".", "class": "compiled-native", "build_system": "make",
            "feasibility": {"tier": "A", "reasons": ["Makefile"]},
            "image": {"base": "audit-buildenv-cpp", "apt_packages": [{"name": "make"}]},
            "commands": [{"phase": "build", "argv": ["make"], "cwd": "."}],
            "compile_database": {"method": "bear"}}

    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.target = self.root / "target"; self.target.mkdir()
        (self.target / "Makefile").write_text("all:\n\tcc -c a.c\n")
        (self.target / "a.c").write_text("int a;\n")
        self.calls = 0
        self.plan = json.loads(json.dumps(self.PLAN))
        defaults = {**ce.host_defaults()}
        defaults["docker_executable"] = defaults["docker_executable"] or Path(sys.executable).resolve()
        if not ce._USER_RE.match(defaults["container_user"]):
            defaults["container_user"] = "10001:10001"
        patches = [mock.patch.object(state, "RUNS", self.root / "runs"),
                   mock.patch.dict(os.environ, {"APPSEC_CACHE_ROOT": str(self.root / "cache"),
                                                "APPSEC_RUN_MODE": "dev",
                                                "APPSEC_BUILD_IMAGES_ROOT": str(self.root / "build-images")}),
                   mock.patch.object(ce, "host_defaults", return_value=defaults),
                   mock.patch.object(worker, "current_inputs", side_effect=self.inputs),
                   mock.patch.object(worker, "_resolve_unit_cow", side_effect=self.resolve),
                   mock.patch.object(worker, "_inspect", side_effect=lambda reference: reference)]
        for patch in patches:
            patch.start(); self.addCleanup(patch.stop)
        state.run_path(RUN).mkdir(parents=True)

    def control(self):
        issued = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=1)
        caps = [worker._cap("package-restore", origin="staged-run-config"),
                worker._cap("target-execution", origin="staged-run-config")]
        grant = {"schema": "appsec-review/permission-grant/1.0", "grant_id": "g", "effect": "ALLOW",
                 "authority": {"name": "Owner", "role": "engagement-owner"},
                 "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "expires_at": (issued + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "binding": {"run_id": RUN, "source_snapshot_sha256": "sha256:" + "a" * 64, "job_id": worker.JOB},
                 "justification": "Stage 13", "capabilities": caps}
        return {"schema": worker.CONTROL_SCHEMA, "mode": "success", "build_resolution_attempts": 3,
                "build_image_reuse": "auto", "build_command_timeout_seconds": 600,
                "image_build_timeout_seconds": 1800, "apt_mirror": worker.APT_MIRROR,
                "permission": {"requirement": {"schema": "appsec-review/permission-requirement/1.0",
                                               "job_id": worker.JOB, "capabilities": caps}, "grants": [grant]}}

    def inputs(self, run_id):
        control = self.control()
        plan_value = {"source_revision": "1" * 40, "plans": [self.plan],
                      "toolchain": {"compile_database_compilers": CLANG}}
        digest = support.fixture_record()["digest"]
        return {"job": worker.JOB, "run_id": run_id, "source_snapshot_sha256": "sha256:" + "a" * 64,
                "source_revision": "1" * 40, "target_path": str(self.target),
                "control": {"path": "data/controls/build-resolution.json", "sha256": "0" * 64, "value": control},
                "plan": {"attempt_id": "plan-1", "sha256": state.digest(plan_value), "value": plan_value},
                "base_images": {"audit-buildenv-cpp": {"digest": digest, "build_reference": "audit-buildenv-cpp:local",
                                                       "reference": digest, "record_sha256": "sha256:" + "b" * 64}},
                "permission_fingerprint_sha256": "sha256:" + "c" * 64,
                "boundary_sha256": ce.boundary_sha256(), "code": worker._code_hashes()}

    def resolve(self, run_id, attempt, plan, number, unit_key, inputs, control, gaps, defer_conflict=False, label=""):
        """The real function's success tuple, with a real B13 trial and no apt."""
        self.calls += 1
        unit_attempt = attempt / "units" / (unit_key + label) / "resolution-attempts" / f"{number:03d}-r1"
        unit_attempt.mkdir(parents=True)
        dockerfile = "FROM audit-buildenv-cpp:local\n"
        fingerprint = "sha256:" + state.digest({"unit": unit_key, "run": run_id})
        image_id = "image_build_" + fingerprint.split(":", 1)[1][:12]
        record = worker._cow_record(image_id, support.fixture_record()["digest"], dockerfile, fingerprint, unit_attempt)
        registry = unit_attempt / "image-registry"; registry.mkdir()
        state.atomic_json(registry / f"{image_id}.json", record)
        trial = unit_attempt / "trial"; trial.mkdir()
        adapter_id = "u" + unit_key + "r1"
        request = worker._request(run_id, adapter_id, unit_attempt, record, plan, inputs)
        scripted = ScriptedDocker()
        original = scripted.child
        commands = [{"argv": ["make"], "exit_code": 0}]

        def child(spec, **kwargs):
            result = original(spec, **kwargs)
            scratch = Path(spec.owner_root) / "scratch"
            (scratch / "src").mkdir(parents=True, exist_ok=True)
            state.atomic_json(scratch / "trial-result.json", {"runner": worker.RUNNER_VERSION, "commands": commands})
            state.atomic_json(scratch / "src" / "compile_commands.json", [
                {"directory": "/scratch/src", "file": "/scratch/src/a.c", "arguments": [CLANG[0], "-c", "a.c"]}])
            return result
        scripted.child = child
        first, second = scripted.patches()
        runtime = worker._runtime(inputs["source_snapshot_sha256"], registry)
        with first, second:
            terminal = ce.run_container(runtime, run_id=run_id, job_id=worker.JOB, attempt_id=adapter_id,
                                        attempt_root=trial, request=request)
        installs = {"base": plan["image"]["base"], "planned": ["make"], "packages": ["make"],
                    "rounds": [{"round": 0}, {"round": 1, "trial": "OK"}], "dropped_unknown": [], "unresolved": []}
        return (unit_attempt, record, image_id, fingerprint, dockerfile, trial, registry, adapter_id,
                terminal["result_sha256"], commands, trial / "scratch" / "src" / "compile_commands.json", installs)

    def run_job(self, dagster, force=False):
        return worker.run(RUN, dagster, force=force)

    def attempt(self, pointer):
        return worker.root(RUN) / "attempts" / pointer["attempt_id"]

    # --- tests ---------------------------------------------------------------------------------

    def test_unchanged_unit_is_reused_and_revalidated_in_its_owner_attempt(self):
        first = self.run_job("d1")
        self.assertEqual((first["status"], self.calls), ("OK", 1))
        second = self.run_job("d2", force=True)
        self.assertEqual(second["status"], "OK")
        self.assertNotEqual(first["attempt_id"], second["attempt_id"])
        self.assertEqual(self.calls, 1, "a memo hit must not resolve the unit again")
        attempt = self.attempt(second)
        [receipt] = state.read_json(attempt / worker.RECEIPTS)
        self.assertEqual(receipt["owner_attempt_id"], first["attempt_id"])
        [lock] = state.read_json(attempt / worker.LOCK_FILE)["locks"]
        self.assertTrue(lock["successful_attempt"]["image_reused"])
        self.assertEqual(lock["successful_attempt"]["reused_from"]["owner_attempt_id"], first["attempt_id"])
        self.assertTrue((attempt / receipt["compile_commands_path"]).is_file())
        self.assertEqual(worker.validate(RUN), attempt)   # end-to-end re-validation with the owner trial

    def test_tampered_owner_trial_is_resolved_fresh(self):
        first = self.run_job("d1")
        [receipt] = state.read_json(self.attempt(first) / worker.RECEIPTS)
        (self.attempt(first) / receipt["trial_path"] / "logs" / "container" / "stdout.log").write_bytes(b"tampered\n")
        self.run_job("d2", force=True)
        self.assertEqual(self.calls, 2)
        events = (self.root / "cache" / "item-memo" / "events.jsonl").read_text().splitlines()
        reasons = [json.loads(line).get("reason", "") for line in events]
        self.assertTrue(any("ContainerRequestError" in reason for reason in reasons), reasons)

    def test_tampered_owner_compile_database_is_resolved_fresh(self):
        first = self.run_job("d1")
        [receipt] = state.read_json(self.attempt(first) / worker.RECEIPTS)
        state.atomic_json(self.attempt(first) / receipt["compile_commands_path"], [
            {"directory": "/scratch/src", "file": "/scratch/src/b.c", "arguments": [CLANG[0], "-c", "b.c"]}])
        self.run_job("d2", force=True)
        self.assertEqual(self.calls, 2)

    def test_image_no_longer_present_is_resolved_fresh(self):
        self.run_job("d1")
        with mock.patch.object(worker, "_inspect", return_value=None):
            self.run_job("d2", force=True)
        self.assertEqual(self.calls, 2)

    def test_changed_plan_or_source_is_a_miss(self):
        self.run_job("d1")
        self.plan["commands"][0]["argv"] = ["make", "-j2"]
        self.run_job("d2")
        self.assertEqual(self.calls, 2)
        (self.target / "a.c").write_text("int a = 1;\n")
        self.run_job("d3", force=True)
        self.assertEqual(self.calls, 3)

    def test_prod_default_resolves_every_unit(self):
        with mock.patch.dict(os.environ, {"APPSEC_RUN_MODE": "prod"}):
            self.run_job("d1")
            self.run_job("d2", force=True)
        self.assertEqual(self.calls, 2)

    def test_memo_key_ignores_grant_timestamps_and_manifest_hash(self):
        inputs = self.inputs(RUN)
        later = json.loads(json.dumps(inputs))
        later["control"]["value"]["permission"]["grants"][0]["issued_at"] = "2026-09-30T00:00:00Z"
        later["source_snapshot_sha256"] = "sha256:" + "f" * 64
        self.assertEqual(worker.unit_memo_material(RUN, self.plan, inputs, "fp"),
                         worker.unit_memo_material(RUN, self.plan, later, "fp"))
        self.assertNotEqual(worker.unit_memo_material(RUN, self.plan, inputs, "fp"),
                            worker.unit_memo_material(RUN, self.plan, inputs, "other"))


if __name__ == "__main__":
    unittest.main()
