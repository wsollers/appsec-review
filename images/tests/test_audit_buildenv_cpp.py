"""Contract and live smoke tests for the ADR-0012 Revision 3 C/C++ build image.

    python3 -B -m unittest images.tests.test_audit_buildenv_cpp
    APPSEC_LIVE_DOCKER_TESTS=1 python3 -B -m unittest \
      images.tests.test_audit_buildenv_cpp.LiveDocker
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
IMAGE = ROOT / "images" / "audit-buildenv-cpp"
TAG = "audit-buildenv-cpp:local"


class DeclaredContract(unittest.TestCase):
    def test_image_extends_audit_native_and_declares_the_required_base(self):
        dockerfile = (IMAGE / "Dockerfile").read_text(encoding="utf-8")
        build = json.loads((IMAGE / "image.json").read_text(encoding="utf-8"))["builds"][0]
        self.assertIn("FROM audit-native:local", dockerfile)
        self.assertEqual(build["requires_images"], ["audit-native:local", "audit-lsp-vendor:local"])

    def test_compiler_and_autotools_contract_is_fail_closed(self):
        dockerfile = (IMAGE / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("ENV CC=/opt/llvm/bin/clang", dockerfile)
        self.assertIn("CXX=/opt/llvm/bin/clang++", dockerfile)
        self.assertIn("clang version 21.1.0", dockerfile)
        versions = {
            "autoconf": "${AUTOCONF_VERSION}", "automake": "${AUTOMAKE_VERSION}",
            "libtool": "${LIBTOOL_VERSION}", "make": "${MAKE_VERSION}",
            "bear": "${BEAR_VERSION}", "pkg-config": "${PKG_CONFIG_VERSION}",
        }
        for package, version in versions.items():
            with self.subTest(package=package):
                self.assertIn(f"{package}={version}", dockerfile)
        self.assertIn("command -v autoconf automake libtoolize make bear pkg-config", dockerfile)


@unittest.skipUnless(os.environ.get("APPSEC_LIVE_DOCKER_TESTS") == "1",
                     "set APPSEC_LIVE_DOCKER_TESTS=1 for the image smoke test")
class LiveDocker(unittest.TestCase):
    def test_versions_and_fixed_compilers_inside_the_runtime_boundary(self):
        if not shutil.which("docker"):
            self.skipTest("docker CLI not installed")
        script = "\n".join((
            "set -eu",
            "test \"$CC\" = /opt/llvm/bin/clang",
            "test \"$CXX\" = /opt/llvm/bin/clang++",
            "test \"$(command -v clang)\" = /opt/llvm/bin/clang",
            "test \"$(command -v clang++)\" = /opt/llvm/bin/clang++",
            "clang --version | grep -F 'clang version 21.1.0 '",
            "for tool in autoconf automake libtoolize make bear pkg-config; do command -v \"$tool\"; done",
            "printf 'int c(void) { return 0; }\\n' > /scratch/smoke.c",
            "printf 'int cpp() { return 0; }\\n' > /scratch/smoke.cpp",
            "\"$CC\" -fsyntax-only /scratch/smoke.c",
            "\"$CXX\" -fsyntax-only /scratch/smoke.cpp",
            "autoconf --version | head -1",
            "automake --version | head -1",
            "libtoolize --version | head -1",
            "make --version | head -1",
            "bear --version | head -1",
            "pkg-config --version",
        ))
        with tempfile.TemporaryDirectory() as scratch:
            os.chmod(scratch, 0o777)
            completed = subprocess.run([
                "docker", "run", "--rm", "--network", "none", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", "10001:10001", "--mount", f"type=bind,src={scratch},dst=/scratch",
                "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m", TAG,
                "/bin/bash", "-lc", script,
            ], capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        for expected in (
            "clang version 21.1.0", "autoconf (GNU Autoconf) 2.71",
            "automake (GNU automake) 1.16.5", "libtoolize (GNU libtool) 2.4.7",
            "GNU Make 4.3", "bear 3.1.3", "\n1.8.1\n",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, completed.stdout)


if __name__ == "__main__":
    unittest.main()
