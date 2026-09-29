"""Declared contract for language servers and tree-sitter on the compiler images (brief C).

    python3 -B -m unittest images.tests.test_language_tooling

Static checks only; the images themselves are proven by scripts/smoke_lang_servers.sh in WSL.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
IMAGES = ROOT / "images"
VENDOR = IMAGES / "audit-lsp-vendor"
BUILDENVS = ("cpp", "cpp-resolute", "dotnet", "go", "java", "php", "python", "rust", "typescript")
CONSUMERS = tuple(f"audit-buildenv-{name}" for name in BUILDENVS) + ("audit-codeql", "audit-codeql-native")
FOLDERS = {"audit-codeql-native": "audit-codeql"}
DOCKERFILES = {"audit-codeql-native": "Dockerfile.native"}
# Pinned server evidence each Dockerfile must carry (docs/language-servers.md §2).
SERVER_PINS = {
    "audit-buildenv-cpp": ("clangd version ${CLANGD_VERSION}", "ARG CLANGD_VERSION=21.1.0",
                           "requirements/clangd.txt"),
    "audit-buildenv-cpp-resolute": ("clangd version 21.1.0", "requirements/clangd.txt"),
    "audit-buildenv-dotnet": ("ARG CSHARP_LS_VERSION=0.20.0", "--version ${CSHARP_LS_VERSION}"),
    "audit-buildenv-go": ("ARG GOPLS_VERSION=v0.18.1", "gopls@${GOPLS_VERSION}"),
    "audit-buildenv-java": ("ARG JDTLS_VERSION=1.61.0-202609031315",
                            "338e7e73d61836651ba2453919a0d34fa763eb4e7c03342092309bffb8934c64"),
    "audit-buildenv-php": ("ARG PHPACTOR_VERSION=2026.07.22.0", "composer create-project"),
    "audit-buildenv-python": ("--require-hashes -r /opt/python-lsp/requirements-lsp.txt",),
    "audit-buildenv-rust": ("rustc 1.90.0", "rustup component add rust-analyzer"),
    "audit-buildenv-typescript": ("npm ci", "lsp/package-lock.json"),
}
HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}")


def dockerfile(image: str) -> str:
    return (IMAGES / FOLDERS.get(image, image) / DOCKERFILES.get(image, "Dockerfile")).read_text(encoding="utf-8")


def build(image: str) -> dict:
    document = json.loads((IMAGES / FOLDERS.get(image, image) / "image.json").read_text(encoding="utf-8"))
    return next(row for row in document["builds"] if row["image_id"] == image)


class VendorImage(unittest.TestCase):
    def test_vendor_build_pins_cli_and_downloads_only_hash_locked_wheels(self):
        text = (VENDOR / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("cargo install --locked tree-sitter-cli --version", text)
        self.assertIn("ARG TREE_SITTER_CLI_VERSION=0.26.13", text)
        self.assertEqual(text.count("pip download"), 2)
        self.assertEqual(text.count("--require-hashes"), 4)  # header note, two downloads, probe install
        self.assertEqual(build("audit-lsp-vendor")["requires_images"], [])

    def test_every_locked_requirement_is_exact_and_hashed(self):
        for name in ("requirements-treesitter.txt", "requirements-clangd.txt"):
            with self.subTest(lock=name):
                text = (VENDOR / name).read_text(encoding="utf-8")
                requirements = re.findall(r"^([A-Za-z0-9_.-]+)==(\S+) \\$", text, re.M)
                self.assertTrue(requirements)
                blocks = re.split(r"^(?=[A-Za-z0-9_.-]+==)", text, flags=re.M)[1:]
                self.assertEqual(len(blocks), len(requirements))
                for block in blocks:
                    self.assertTrue(HASH.search(block), block.splitlines()[0])
        names = {name for name, _ in re.findall(
            r"^([a-z0-9-]+)==(\S+)", (VENDOR / "requirements-treesitter.txt").read_text(), re.M)}
        self.assertEqual(names, {"tree-sitter", "tree-sitter-bash", "tree-sitter-c", "tree-sitter-c-sharp",
                                 "tree-sitter-cpp", "tree-sitter-go", "tree-sitter-java",
                                 "tree-sitter-javascript", "tree-sitter-json", "tree-sitter-php",
                                 "tree-sitter-python", "tree-sitter-ruby", "tree-sitter-rust",
                                 "tree-sitter-typescript"})


class ConsumerImages(unittest.TestCase):
    def test_every_compiler_image_installs_vendored_tree_sitter_offline(self):
        for image in CONSUMERS:
            with self.subTest(image=image):
                text = dockerfile(image)
                self.assertIn("--mount=type=bind,from=audit-lsp-vendor:local,source=/opt/lsp-vendor", text)
                self.assertIn("--no-index --find-links /mnt/lsp-vendor/wheels", text)
                self.assertIn("--require-hashes -r /mnt/lsp-vendor/requirements/treesitter.txt", text)
                self.assertIn('tree-sitter --version | grep -F "tree-sitter 0.26.13"', text)
                self.assertIn("audit-lsp-vendor:local", build(image)["requires_images"])

    def test_external_base_images_are_digest_pinned(self):
        for image in CONSUMERS + ("audit-lsp-vendor",):
            text = dockerfile(image)
            for match in re.finditer(r"^FROM\s+(\S+)", text, re.M):
                reference = match.group(1)
                with self.subTest(image=image, reference=reference):
                    if reference.endswith(":local"):
                        continue
                    self.assertRegex(reference, r"@sha256:[0-9a-f]{64}\Z")
            for match in re.finditer(r"--from=(\S+)", text):
                reference = match.group(1)
                if "/" in reference or ":" in reference and not reference.endswith(":local"):
                    with self.subTest(image=image, copy_from=reference):
                        self.assertRegex(reference, r"@sha256:[0-9a-f]{64}\Z")

    def test_no_floating_server_downloads_remain(self):
        for image in CONSUMERS:
            text = dockerfile(image)
            with self.subTest(image=image):
                self.assertNotIn("latest", text.replace("MCP", ""))
                self.assertNotIn("composer global require", text)
                self.assertNotIn("apt-get install -y --no-install-recommends clangd", text)
                self.assertNotRegex(text, r"npm install -g\s+\\?\s*typescript")

    def test_each_language_server_is_pinned(self):
        for image, needles in SERVER_PINS.items():
            text = dockerfile(image)
            for needle in needles:
                with self.subTest(image=image, needle=needle):
                    self.assertIn(needle, text)

    def test_jdtls_is_vendored_by_a_checksummed_prebuild_download(self):
        steps = build("audit-buildenv-java")["prebuild"]
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["dest"], "jdtls.tar.gz")
        self.assertTrue(steps[0]["url"].startswith("https://download.eclipse.org/jdtls/milestones/1.61.0/"))
        self.assertIn(f'echo "{steps[0]["sha256"]}  /tmp/jdtls.tar.gz" | sha256sum -c -',
                      dockerfile("audit-buildenv-java"))
        ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("images/audit-buildenv-java/jdtls.tar.gz", ignored)

    def test_python_and_node_server_locks_are_complete(self):
        text = (IMAGES / "audit-buildenv-python/lsp/requirements-lsp.txt").read_text(encoding="utf-8")
        blocks = re.split(r"^(?=[A-Za-z0-9_.-]+==)", text, flags=re.M)[1:]
        self.assertTrue(any(block.startswith("python-lsp-server==1.15.0") for block in blocks))
        self.assertTrue(any(block.startswith("basedpyright==1.40.1") for block in blocks))
        for block in blocks:
            self.assertTrue(HASH.search(block), block.splitlines()[0])
        lock = json.loads((IMAGES / "audit-buildenv-typescript/lsp/package-lock.json").read_text())
        manifest = json.loads((IMAGES / "audit-buildenv-typescript/lsp/package.json").read_text())
        self.assertEqual(lock["packages"][""]["dependencies"], manifest["dependencies"])
        for name, value in manifest["dependencies"].items():
            self.assertRegex(value, r"^\d+\.\d+\.\d+$", name)
        for path, entry in lock["packages"].items():
            if path:
                with self.subTest(package=path):
                    self.assertTrue(entry["resolved"].startswith("https://registry.npmjs.org/"))
                    self.assertTrue(entry["integrity"].startswith("sha512-"))


if __name__ == "__main__":
    unittest.main()
