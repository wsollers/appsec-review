from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

PROCESS = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(PROCESS))
import registry_paths

import binary_hardening_input
import execution_state as state
import vendor_evidence_orchestration


@unittest.skipUnless(os.environ.get("APPSEC_RUN_LIVE_BINARY_HARDENING") == "1",
                     "set APPSEC_RUN_LIVE_BINARY_HARDENING=1 for the bounded Docker qualification")
class BinaryHardeningLiveTests(unittest.TestCase):
    def test_real_elf_from_native_projection_reaches_accepted_checksec_evidence(self):
        build_image = state.read_json(
            registry_paths.record(registry_paths.CONTAINER_IMAGES, "audit-buildenv-cpp"))
        scanner_image = state.read_json(
            registry_paths.record(registry_paths.CONTAINER_IMAGES, "audit-binary-analysis"))
        self.assertEqual(build_image["digest_kind"], "image-id")
        self.assertEqual(scanner_image["digest_kind"], "image-id")

        with tempfile.TemporaryDirectory(prefix="appsec-binary-hardening-") as temporary:
            owner = Path(temporary)
            old_runs = state.RUNS
            state.RUNS = owner / "runs"
            try:
                run_id = "binary-hardening-live"
                run = state.run_path(run_id)
                target = owner / "target"
                target.mkdir()
                (target / "main.c").write_text(
                    "#include <stdio.h>\nint main(void) { puts(\"qualified\"); return 0; }\n",
                    encoding="utf-8")
                (run / "inputs").mkdir(parents=True)
                state.atomic_json(run / "inputs/artifact-manifest.json",
                                  {"target": {"repo_path": str(target)}})

                native_root = state.data_path(run_id, "jobs", "02-native-build")
                native = native_root / "attempts/native-live"
                binary = native / "outputs/root/binaries/app"
                binary.parent.mkdir(parents=True)
                subprocess.run([
                    "docker", "run", "--rm", "--network", "none",
                    "--user", f"{os.getuid()}:{os.getgid()}",
                    "--mount", f"type=bind,src={target},dst=/src,readonly",
                    "--mount", f"type=bind,src={binary.parent},dst=/out",
                    build_image["digest"], "/usr/bin/gcc", "-O2", "-fPIE", "-pie",
                    "-fstack-protector-strong", "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack",
                    "/src/main.c", "-o", "/out/app",
                ], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, timeout=120)
                self.assertEqual(binary.read_bytes()[:4], b"\x7fELF")

                binary_sha = "sha256:" + state.file_hash(binary)
                result = {
                    "schema": "appsec-review/native-build/1", "run_id": run_id,
                    "source_revision": "qualification-fixture", "upstream": {}, "status": "OK",
                    "coverage_gaps": [], "units": [{
                        "unit_id": "root", "status": "OK",
                        "image_id": build_image["image_id"],
                        "image_digest": build_image["digest"], "commands": [{}, {}],
                        "compile_database": {"path": "outputs/root/compile_commands.json",
                                             "sha256": "sha256:" + "2" * 64, "entries": 1},
                        "binaries": [{"source_path": "app",
                                      "artifact_path": "outputs/root/binaries/app",
                                      "sha256": binary_sha,
                                      "size_bytes": binary.stat().st_size}],
                    }],
                }
                state.atomic_json(native / "native-build.json", result)
                state.atomic_json(native / "result.json", {"status": "CURRENT"})
                state.atomic_json(native_root / "accepted.json", {"attempt_id": "native-live"})

                with mock.patch.object(binary_hardening_input.native_build, "validate",
                                       return_value=native), \
                     mock.patch.object(binary_hardening_input.native_build, "root",
                                       return_value=native_root):
                    pointer = vendor_evidence_orchestration.execute_binary_from_native(
                        run_id=run_id, dagster_run_id="qualification")

                accepted = state.data_path(
                    run_id, "jobs", "02-binary-hardening", "whole", "attempts",
                    pointer["attempt_id"])
                evidence = state.read_json(accepted / "outputs/binary-hardening.json")
                tools = state.read_json(accepted / "outputs/tool-results.json")
                self.assertEqual(pointer["status"], "OK")
                self.assertEqual(evidence["binaries"][0]["format"], "elf")
                self.assertEqual(tools["tool_instances"][0]["terminal_status"], "OK")
                self.assertEqual(tools["tool_instances"][0]["identity"]["tool_name"], "checksec")
                self.assertEqual(tools["tool_instances"][0]["identity"]["image_digest"],
                                 scanner_image["digest"])

                output = os.environ.get("APPSEC_BINARY_HARDENING_QUALIFICATION_OUT")
                if output:
                    instance = tools["tool_instances"][0]
                    state.atomic_json(Path(output), {
                        "schema": "appsec-review/binary-hardening-qualification/1.0",
                        "run_id": run_id,
                        "native_build": {"attempt_id": "native-live",
                                         "build_image_digest": build_image["digest"],
                                         "binary_sha256": binary_sha,
                                         "binary_bytes": binary.stat().st_size},
                        "binary_hardening": {
                            "attempt_id": pointer["attempt_id"],
                            "scanner_image_digest": scanner_image["digest"],
                            "tool_name": instance["identity"]["tool_name"],
                            "tool_version": instance["identity"]["tool_version"],
                            "execution_status": instance["terminal_status"],
                            "network_mode": "none",
                            "checks": evidence["binaries"][0]["checks"],
                            "rule_hits": evidence["binaries"][0]["rule_hits"],
                            "envelope_sha256": "sha256:" + state.file_hash(accepted / "result.json"),
                        },
                    })
            finally:
                state.RUNS = old_runs


if __name__ == "__main__":
    unittest.main()
