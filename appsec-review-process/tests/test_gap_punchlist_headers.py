"""Acceptance tests for gap punch list P35 (hello-autotools, 2026-10-03): configure-generated headers
(``config.h``, gnulib replacements) exist only in the native build copy, so native SAST and the traced
CodeQL replay compiled against the pristine checkout without them.

See docs/TODO/gap-punchlist-hello-autotools-2026-10-03.md.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import registry_paths  # noqa: E402,F401

import build_replay  # noqa: E402
import codeql_sast  # noqa: E402
import native_sast  # noqa: E402
from execution_state import Blocked, file_hash  # noqa: E402
from schema_validate import validate_document  # noqa: E402
from test_codeql_sast import _inputs, _traced  # noqa: E402
from test_native_sast import FIXTURE, VARIANT, accepted_native_build, trial_tree  # noqa: E402

HEADERS = {"config.h": b"#define HAVE_STDIO_H 1\n", "include/version.h": b"#define V 1\n",
           "src/local.h": b"#define L 1\n"}
MOUNT = "/inputs/generated-headers"


def _collector():
    source = getattr(build_replay, "HEADER_COLLECTOR", None)
    if source is None:
        return None
    namespace: dict = {}
    exec(source, namespace)  # the exact text the in-container runner executes
    return namespace["generated_headers"]


class GeneratedHeaderTests(unittest.TestCase):
    def load(self, folder, **kwargs):
        base, attempt, target, fingerprint = accepted_native_build(Path(folder), **kwargs)
        try:
            return native_sast.load_native_build(base, run_id="run-e03", expected_fingerprint=fingerprint), attempt
        except Blocked as exc:
            self.fail(f"native SAST refused a native build that publishes generated headers: {exc}")

    def test_p35_runner_collects_bounded_headers_absent_from_the_checkout(self):
        """P35: the replay runner lists header files the build created that the checkout lacks."""
        collect = _collector()
        self.assertIsNotNone(collect, "build_replay has no generated-header collector")
        with tempfile.TemporaryDirectory() as folder:
            pristine, src = Path(folder, "workspace"), Path(folder, "src")
            for root in (pristine, src):
                (root / "include").mkdir(parents=True)
                (root / "include/api.h").write_text("int api(void);\n")
                (root / "main.c").write_text("int main(void) { return 0; }\n")
            (src / "config.h").write_text("#define HAVE_X 1\n")
            (src / "lib").mkdir(); (src / "lib/stdio.h").write_text("#include_next <stdio.h>\n")
            (src / "lib/big.h").write_bytes(b"x" * 64)
            (src / "main.o").write_bytes(b"\0")
            (src / "CMakeFiles").mkdir(); (src / "CMakeFiles/probe.h").write_text("\n")
            found, omitted = collect(str(src), str(pristine), 8, 32, [".h", ".hh", ".hpp", ".hxx", ".inc"])
        self.assertEqual([item["path"] for item in found], ["config.h", "lib/stdio.h"])
        self.assertEqual(found[0]["sha256"], "sha256:" + __import__("hashlib").sha256(b"#define HAVE_X 1\n").hexdigest())
        self.assertEqual(omitted, 1, "an over-size generated header must be counted, not silently dropped")

    def test_p35_native_build_schema_binds_generated_headers(self):
        """P35: the native-build result carries hash-bound generated headers per unit."""
        unit = {"unit_id": "dir:.", "status": "OK", "image_id": "image_build_123456789abc",
                "image_digest": "sha256:" + "5" * 64, "commands": [{}],
                "compile_database": {"path": "db", "sha256": "sha256:" + "1" * 64, "entries": 1},
                "binaries": [{"source_path": "a", "artifact_path": "b", "sha256": "sha256:" + "2" * 64,
                              "size_bytes": 1}],
                "generated_headers": {"root": "outputs/u/generated-headers", "omitted": 0,
                                      "headers": [{"path": "config.h", "sha256": "sha256:" + "3" * 64,
                                                   "size_bytes": 0}]}}
        result = {"schema": "appsec-review/native-build/1", "run_id": "r", "source_revision": "x",
                  "upstream": {"resolution": {"job": "02-build-resolution", "attempt_id": "a",
                                              "lock_sha256": "sha256:" + "4" * 64},
                               "configured": {"job": "02-build-configure", "attempt_id": "c",
                                              "result_sha256": "sha256:" + "4" * 64,
                                              "envelope_sha256": "sha256:" + "4" * 64}},
                  "status": "OK", "units": [unit], "coverage_gaps": []}
        self.assertEqual(validate_document(result, "native-build.schema.json"), [])

    def test_p35_native_sast_prepends_verified_generated_include_dirs(self):
        """P35: entries whose include dir or source dir holds a generated header search the mount first."""
        with tempfile.TemporaryDirectory() as folder:
            loaded, attempt = self.load(folder, headers=HEADERS)
            unit = loaded["units"][0]
            args = unit["adapted"][0]["arguments"]
            self.assertEqual(args[:4], ["/opt/llvm/bin/clang", "-iquote", MOUNT + "/src", "-I" + MOUNT + "/include"])
            self.assertNotIn("-I" + MOUNT, args, "config.h's directory is not on this entry's include path")
            headers = unit["generated_headers"]
            self.assertEqual(headers["host_path"], str((attempt / "outputs/u/generated-headers").resolve()))
            inputs = {"target_path": str(loaded["target"]), "source_snapshot_sha256": "sha256:" + "1" * 64,
                      "image": {"image_id": "audit-native", "digest": "sha256:" + "7" * 64},
                      "config": json.loads(native_sast.CONFIG.read_text())}
            with mock.patch.object(native_sast, "_permission", return_value={"requirement": {}, "grants": [], "decision": {}}):
                request = native_sast._request("run", "a", inputs, unit, Path(folder), "clang-cppcheck")
        self.assertIn({"host_path": headers["host_path"], "container_path": MOUNT}, request["target_mounts"])

    def test_p35_tampered_generated_header_fails_closed(self):
        """P35: a generated header whose bytes differ from its recorded hash is never used."""
        with tempfile.TemporaryDirectory() as folder:
            base, attempt, _target, fingerprint = accepted_native_build(Path(folder), headers=HEADERS)
            loaded = None
            try:
                loaded = native_sast.load_native_build(base, run_id="run-e03", expected_fingerprint=fingerprint)
            except Blocked:
                pass
            self.assertIsNotNone(loaded, "untampered generated headers were refused")
            (attempt / "outputs/u/generated-headers/config.h").write_bytes(b"#define EVIL 1\n")
            with self.assertRaises(Blocked):
                native_sast.load_native_build(base, run_id="run-e03", expected_fingerprint=fingerprint)

    def test_p35_missing_or_omitted_generated_headers_stay_explicit_gaps(self):
        """P35: an unpublished header set or headers omitted by the bound are coverage gaps."""
        with tempfile.TemporaryDirectory() as folder:
            omitted, _ = self.load(Path(folder, "a"), headers=HEADERS, omitted=3)
            absent, _ = self.load(Path(folder, "b"), publish_headers=False)
            attempt = Path(folder, "attempt"); attempt.mkdir()
            clang, csa = trial_tree(attempt)
            inputs = {"image": {"image_id": "audit-native", "digest": "sha256:" + "7" * 64},
                      "config": json.loads(native_sast.CONFIG.read_text()),
                      "config_sha256": "sha256:" + file_hash(native_sast.CONFIG)}
            gaps = {}
            for name, loaded in (("omitted", omitted), ("absent", absent)):
                unit = {**loaded["units"][0], "build_variant": VARIANT}
                gaps[name] = native_sast.normalize_unit(unit, target=Path(FIXTURE / "target"), attempt=attempt,
                                                        clang_trial=clang, csa_trial=csa, inputs=inputs)["coverage_gaps"]
        self.assertIn("generated-headers-omitted:3", gaps["omitted"])
        self.assertIn("generated-headers-not-published", gaps["absent"])

    def test_p35_traced_codeql_mounts_the_generated_headers(self):
        """P35: the traced CodeQL replay compiles the same adapted entries, so it mounts the same headers."""
        with tempfile.TemporaryDirectory() as folder:
            headers = Path(folder, "generated-headers"); headers.mkdir()
            db = Path(folder, "db"); db.mkdir()
            units = [{"unit_id": "unit-a", "key": "0123456789abcdef", "adapted_sha256": "sha256:" + "c" * 64,
                      "adapted": [{"file": "/workspace/vuln.c", "directory": "/workspace",
                                   "arguments": ["/opt/llvm/bin/clang", "-I" + MOUNT, "-c", "/workspace/vuln.c"]}],
                      "generated_headers_root": str(headers)}]
            row = _traced(units=units)[0]
            inputs = {**_inputs([row]), "target_path": folder, "native_units": units, "limits": {}}
            with mock.patch.object(codeql_sast, "_permission", return_value={"requirement": {}, "grants": [], "decision": {}}):
                request = codeql_sast._request("run", "a", inputs, row, db)
        self.assertIn({"host_path": str(headers), "container_path": MOUNT}, request["target_mounts"])


if __name__ == "__main__":
    unittest.main()
