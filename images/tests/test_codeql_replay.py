"""images/audit-codeql/scripts/replay_compile_commands.py: what the CodeQL tracer is allowed to run.

    python3 -B -m unittest images.tests.test_codeql_replay
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "audit-codeql" / "scripts" / "replay_compile_commands.py"
LANE = SCRIPT.with_name("codeql-sast-lane.sh")
spec = importlib.util.spec_from_file_location("replay_compile_commands", SCRIPT)
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)


class BundlePermissions(unittest.TestCase):
    """The lanes run as a non-root uid; the bundle's precompiled query plans must be readable, or every
    query is recompiled from source and CodeQL runs out of memory (2026-09-30)."""

    def test_both_images_make_the_bundle_world_readable_after_unpacking(self):
        for name in ("Dockerfile", "Dockerfile.native"):
            text = (Path(__file__).resolve().parents[1] / "audit-codeql" / name).read_text(encoding="utf-8")
            unpack = text.index("tar --zstd -xf bundle.tar.zst")
            self.assertIn("chmod -R a+rX /opt/codeql", text[unpack:unpack + 300], name)


class Refusal(unittest.TestCase):
    def test_only_plain_in_image_compiler_invocations_run(self):
        ok = ["/opt/llvm/bin/clang++", "-std=c++17", "-I/workspace/include", "-c", "/workspace/a.cpp"]
        self.assertIsNone(replay.refused(ok))
        for argv, reason in (
                (["/usr/bin/gcc", "-c", "a.c"], "compiler"),
                (["/workspace/tools/clang", "-c", "a.c"], "compiler"),
                (["/opt/llvm/bin/clang", "@/workspace/flags.rsp"], "response file"),
                (["/opt/llvm/bin/clang", "-Xclang", "-load", "-Xclang", "/workspace/p.so"], "load or wrap"),
                (["/opt/llvm/bin/clang", "-fplugin=/workspace/p.so"], "load or wrap"),
                (["/opt/llvm/bin/clang", "-fpass-plugin=/workspace/p.so"], "load or wrap"),
                (["/opt/llvm/bin/clang", "--config=/workspace/c.cfg"], "load or wrap"),
                (["/opt/llvm/bin/clang", "-B/workspace/bin"], "search path"),
                (["/opt/llvm/bin/clang", "-B", "tools"], "search path"),
                (["/opt/llvm/bin/clang", "--gcc-toolchain=/workspace/gcc"], "load or wrap"),
                ([], "compiler")):
            with self.subTest(argv=argv):
                self.assertIn(reason, replay.refused(argv))

    def test_gnu_argv_redirects_objects_and_drops_depfiles(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(replay, "OBJ_DIR", temp):
            entry = {"file": "/workspace/a.c", "directory": "/workspace"}
            argv = replay.gnu_argv(entry, ["/opt/llvm/bin/clang", "-MD", "-MF", "/workspace/a.d", "-MTa.o",
                                           "-o", "/workspace/a.o", "/workspace/a.c"])
        self.assertEqual(argv[:2], ["/opt/llvm/bin/clang", "-c"])
        self.assertNotIn("-MD", argv)
        self.assertNotIn("/workspace/a.d", argv)
        self.assertNotIn("-MTa.o", argv)
        self.assertTrue(argv[argv.index("-o") + 1].startswith(temp))


@unittest.skipUnless(shutil.which("clang"), "clang not installed")
class LiveReplay(unittest.TestCase):
    def test_counts_ok_failed_and_refused_and_writes_stats(self):
        clang = "clang"  # bare name: allowed, resolved on PATH (in the image, /opt/llvm/bin first)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "good.c").write_text("int good(void) { return 1; }\n")
            (root / "bad.c").write_text("int bad(void) { return }\n")
            database = [
                {"file": str(root / "good.c"), "directory": str(root), "arguments": [clang, "-c", str(root / "good.c")]},
                {"file": str(root / "bad.c"), "directory": str(root), "arguments": [clang, "-c", str(root / "bad.c")]},
                {"file": str(root / "x.c"), "directory": str(root),
                 "arguments": [clang, "-fplugin=/tmp/x.so", "-c", str(root / "x.c")]},
            ]
            (root / "cc.json").write_text(json.dumps(database))
            env = {**os.environ, "REPLAY_OBJ_DIR": str(root / "obj")}
            code = subprocess.run([sys.executable, str(SCRIPT), str(root / "cc.json"),
                                   "--stats", str(root / "stats.json")],
                                  env=env, capture_output=True, text=True, timeout=120).returncode
            stats = json.loads((root / "stats.json").read_text())
            objects = list((root / "obj").iterdir())
        self.assertEqual(code, 0)
        self.assertEqual(stats, {"total": 3, "ok": 1, "failed": 1, "refused": 1})
        self.assertEqual(len(objects), 1)


class Lane(unittest.TestCase):
    def test_lane_script_modes_and_usage(self):
        text = LANE.read_text(encoding="utf-8")
        self.assertIn("--build-mode=none", text)
        self.assertIn('--command="python3 /opt/scripts/replay_compile_commands.py $compile_commands '
                      '--stats /scratch/replay.json"', text)
        for query in ("CallEdges", "EntryPoints", "FlowSources"):
            self.assertIn(query, text)
        for argv in (["cpp", "bogus", "s", "1", "1", "keep-db"], ["cpp", "none", "s", "1", "1"],
                     ["cpp", "none", "s", "1", "1", "keep-maybe"], ["python", "traced", "s", "1", "1", "keep-db", "c"]):
            with self.subTest(argv=argv):
                completed = subprocess.run(["bash", str(LANE), *argv], capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 2)
        self.assertIn('if [ "$keep" = drop-db ]; then rm -rf /scratch/db; fi', text)

    def test_reachability_lane_usage_and_offline_shape(self):
        script = LANE.with_name("codeql-reachability-lane.sh")
        text = script.read_text(encoding="utf-8")
        self.assertIn("--model-packs=\"appsec/$language-reachability-symbols\"", text)
        self.assertIn("cp -R /inputs/codeql-db /scratch/db", text)
        self.assertNotIn("--download", text)
        for argv in (["ruby", "1", "1"], ["python", "1"], ["cpp", "1", "1"]):
            with self.subTest(argv=argv):
                completed = subprocess.run(["bash", str(script), *argv], capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 2)


if __name__ == "__main__":
    unittest.main()
