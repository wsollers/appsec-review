"""Offline tests for images/tool_pins.py (no network, no docker).

    cd images && python -B -m unittest tests.test_tool_pins
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

IMAGES = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(IMAGES))

import tool_pins as tp  # noqa: E402


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class CommittedTools(unittest.TestCase):
    def test_every_tool_folder_is_consistent(self):
        folders = tp.tool_dirs()
        self.assertGreaterEqual(len(folders), 13)
        for folder in folders:
            with self.subTest(folder.name):
                self.assertEqual(tp.check(folder), [])

    def test_one_tool_per_image_and_unique_ids(self):
        ids = [json.loads((f / "tool.json").read_text())["image_id"] for f in tp.tool_dirs()]
        self.assertEqual(len(ids), len(set(ids)))
        for folder in tp.tool_dirs():
            builds = json.loads((folder / "image.json").read_text())["builds"]
            self.assertEqual(len(builds), 1)
            self.assertEqual(builds[0]["tag"], f"{folder.name}:local")

    def test_hash_bound_text_inputs_are_checkout_stable(self):
        attributes = (IMAGES / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("tool-*/requirements.txt text eol=lf", attributes.splitlines())
        self.assertIn("tool-*/keys/*.pub text eol=lf", attributes.splitlines())
        paths = [folder / "requirements.txt" for folder in tp.tool_dirs()
                 if (folder / "requirements.txt").is_file()]
        paths.extend(IMAGES.glob("tool-*/keys/*.pub"))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=path.relative_to(IMAGES).as_posix()):
                self.assertNotIn(b"\r\n", path.read_bytes())


class Checksums(unittest.TestCase):
    def test_entry_found_exactly(self):
        text = f"{'a' * 64}  tool_1.0_linux_x64.tar.gz\n{'b' * 64} *tool_1.0_darwin.tar.gz\n"
        self.assertEqual(tp.checksum_entry(text, "tool_1.0_linux_x64.tar.gz"), "a" * 64)
        self.assertEqual(tp.checksum_entry(text, "tool_1.0_darwin.tar.gz"), "b" * 64)

    def test_missing_or_conflicting_entry_fails(self):
        with self.assertRaises(tp.PinError):
            tp.checksum_entry(f"{'a' * 64}  other\n", "tool")
        with self.assertRaises(tp.PinError):
            tp.checksum_entry(f"{'a' * 64}  tool\n{'c' * 64}  tool\n", "tool")

    def test_single_hash_file(self):
        self.assertEqual(tp.single_hash(("d" * 64) + "  go.tar.gz\n"), "d" * 64)
        with self.assertRaises(tp.PinError):
            tp.single_hash("not a hash\n")

    def test_spdx_file_hash(self):
        document = json.dumps({"files": [{
            "fileName": "./bin/tool",
            "checksums": [{"algorithm": "SHA1", "checksumValue": "1" * 40},
                          {"algorithm": "SHA256", "checksumValue": "E" * 64}],
        }]})
        self.assertEqual(tp.spdx_sha256(document, "./bin/tool"), "e" * 64)
        with self.assertRaises(tp.PinError):
            tp.spdx_sha256(document, "./bin/other")
        with self.assertRaises(tp.PinError):
            tp.spdx_sha256("not json", "./bin/tool")


class VerifyAsset(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.asset = self.tmp / "tool.tar.gz"
        self.asset.write_bytes(b"release bytes")

    def work(self, name):
        path = self.tmp / name
        path.mkdir()
        return path

    def test_vendor_checksums_match_and_mismatch(self):
        good = self.tmp / "checksums.txt"
        good.write_text(f"{sha(b'release bytes')}  tool.tar.gz\n")
        asset = {"name": "tool", "verify": {"kind": "vendor-checksums", "checksums_url": good.as_uri(),
                                            "entry": "tool.tar.gz"}}
        evidence = tp.verify_asset(asset, "1.0", self.asset, sha(b"release bytes"), self.tmp, self.work("a"))
        self.assertEqual(evidence["kind"], "vendor-checksums")
        with self.assertRaises(tp.PinError):
            tp.verify_asset(asset, "1.0", self.asset, sha(b"tampered"), self.tmp, self.work("b"))

    @unittest.skipUnless(shutil.which("gpg"), "gpg not installed")
    def test_pgp_accepts_only_the_pinned_key(self):
        home = self.tmp / "signer"
        home.mkdir(mode=0o700)
        gpg = ["gpg", "--batch", "--homedir", str(home), "--pinentry-mode", "loopback", "--passphrase", ""]
        for uid in ("Pinned <pinned@example.invalid>", "Other <other@example.invalid>"):
            subprocess.run(gpg + ["--quick-gen-key", uid, "ed25519", "sign", "never"], check=True,
                           capture_output=True)
        listing = subprocess.run(["gpg", "--batch", "--homedir", str(home), "--with-colons", "--fingerprint"],
                                 check=True, capture_output=True, text=True).stdout
        fprs = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr")]
        pinned, other = fprs[0], fprs[1]
        keys = self.tmp / "keys"
        keys.mkdir()
        for fpr in (pinned, other):
            (keys / f"{fpr}.asc").write_bytes(subprocess.run(
                ["gpg", "--batch", "--homedir", str(home), "--armor", "--export", fpr],
                check=True, capture_output=True).stdout)
        signature = self.tmp / "tool.tar.gz.asc"
        subprocess.run(gpg + ["--local-user", other, "--armor", "--detach-sign", "--output", str(signature),
                              str(self.asset)], check=True, capture_output=True)
        asset = {"name": "tool", "verify": {"kind": "pgp", "signature_url": signature.as_uri(), "fingerprint": pinned}}
        with self.assertRaises(tp.PinError):
            tp.verify_asset(asset, "1.0", self.asset, sha(b"release bytes"), self.tmp, self.work("c"))
        signature.unlink()
        subprocess.run(gpg + ["--local-user", pinned, "--armor", "--detach-sign", "--output", str(signature),
                              str(self.asset)], check=True, capture_output=True)
        evidence = tp.verify_asset(asset, "1.0", self.asset, sha(b"release bytes"), self.tmp, self.work("d"))
        self.assertEqual(evidence["fingerprint"], pinned)


class CheckRejects(unittest.TestCase):
    """check() on a copy of a real tool folder, broken one rule at a time."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.folder = self.tmp / "tool-gitleaks"
        shutil.copytree(IMAGES / "tool-gitleaks", self.folder, ignore=shutil.ignore_patterns("downloads"))
        self.assertEqual(tp.check(self.folder), [])

    def edit(self, name, old, new):
        path = self.folder / name
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1))

    def assertRejected(self, needle):
        errors = tp.check(self.folder)
        self.assertTrue(any(needle in e for e in errors), errors)

    def test_unpinned_base(self):
        self.edit("Dockerfile", "ubuntu:24.04@sha256:", "ubuntu:24.04#")
        self.assertRejected("not pinned by digest")

    def test_entrypoint(self):
        self.edit("Dockerfile", "USER 10001", 'ENTRYPOINT ["/opt/tool/bin/gitleaks"]\nUSER 10001')
        self.assertRejected("ENTRYPOINT")

    def test_download_in_build(self):
        self.edit("Dockerfile", "USER 10001", "RUN curl -fsSL https://example.invalid/x\nUSER 10001")
        self.assertRejected("may not download")

    def test_copy_of_repo_file(self):
        self.edit("Dockerfile", "USER 10001", "COPY tool.json /tmp/tool.json\nUSER 10001")
        self.assertRejected("only verified downloads")

    def test_root_user(self):
        self.edit("Dockerfile", "USER 10001", "USER root")
        self.assertRejected("USER 10001")

    def test_version_bump_without_pin(self):
        tool = json.loads((self.folder / "tool.json").read_text())
        tool["version"] = "99.0.0"
        (self.folder / "tool.json").write_text(json.dumps(tool))
        self.assertRejected("run pin")

    def test_hand_edited_hash(self):
        document = json.loads((self.folder / "image.json").read_text())
        document["builds"][0]["prebuild"][0]["sha256"] = "0" * 64
        (self.folder / "image.json").write_text(json.dumps(document))
        self.assertRejected("not the verified pin")

    def test_http_asset(self):
        tool = json.loads((self.folder / "tool.json").read_text())
        tool["assets"][0]["url"] = tool["assets"][0]["url"].replace("https://", "http://")
        (self.folder / "tool.json").write_text(json.dumps(tool))
        self.assertRejected("must be https")

    def test_relative_executable(self):
        tool = json.loads((self.folder / "tool.json").read_text())
        tool["executable"] = "gitleaks"
        (self.folder / "tool.json").write_text(json.dumps(tool))
        self.assertRejected("absolute")


class PipLock(unittest.TestCase):
    def test_pip_tools_install_hash_locked_wheels_offline(self):
        for name in ("tool-semgrep", "tool-checkov", "tool-mobsfscan"):
            with self.subTest(name):
                folder = IMAGES / name
                dockerfile = (folder / "Dockerfile").read_text()
                self.assertIn("--no-index", dockerfile)
                self.assertIn("--require-hashes", dockerfile)
                record = json.loads((folder / "pin-record.json").read_text())
                lock = (folder / "requirements.txt").read_text()
                pinned = [line.split("==")[0].lower().replace("_", "-") for line in lock.splitlines()
                          if line[:1].isalnum()]
                self.assertEqual(len(record["pip_lock"]["wheels"]), len(pinned))


if __name__ == "__main__":
    unittest.main()


class ImageBuildFetch(unittest.TestCase):
    """images/image_build.py fetch step on a fresh checkout (downloads/ is gitignored, so absent)."""

    def test_nested_download_dest_is_created_and_verified(self):
        import image_build
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        source = tmp / "wheel.whl"
        source.write_bytes(b"wheel bytes")
        folder = tmp / "tool-x"
        folder.mkdir()
        step = {"kind": "download", "url": source.as_uri(), "dest": "downloads/wheels/wheel.whl",
                "sha256": sha(b"wheel bytes"), "bytes": len(b"wheel bytes")}
        image_build._fetch(step, folder, lambda message: None)
        self.assertEqual((folder / "downloads" / "wheels" / "wheel.whl").read_bytes(), b"wheel bytes")
        bad = dict(step, dest="downloads/other/wheel.whl", sha256="0" * 64)
        with self.assertRaises(image_build.BuildFailed):
            image_build._fetch(bad, folder, lambda message: None)
        self.assertFalse((folder / "downloads" / "other" / "wheel.whl").exists())
