"""Declared contract for Ghidra and x64dbg (under Wine) in audit-binary-analysis and audit-native.

    python3 -B -m unittest images.tests.test_reverse_tools

Static checks only; the images themselves are proven by scripts/smoke_reverse_tools.sh in WSL.
"""
from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
IMAGES = ("audit-binary-analysis", "audit-native")
SHARED_PINS = (
    "ARG GHIDRA_VERSION=12.1.3",
    "ARG GHIDRA_BUILD=20260817",
    "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54",  # Ghidra zip
    "releases/download/jdk-21.0.12%2B8/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12_8.tar.gz",
    "e4446ff06a276155697597cc0f1b15da004ff083f4964a35271ecee567177370",  # Temurin tarball
    "ARG X64DBG_TAG=2026.05.27",
    "ARG X64DBG_SNAPSHOT=snapshot_2026-05-27_12-11",
    "ARG X64DBG_SHA256=d41966dfc5b435a372798245300ca0ab7bb8e48bdbf48512c6fb20fcca427697",
)
WINE = {"audit-binary-analysis": "ARG WINE_VERSION=8.0~repack-4",
        "audit-native": "ARG WINE_VERSION=9.0~repack-4build3"}


def dockerfile(image: str) -> str:
    return (ROOT / "images" / image / "Dockerfile").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    return text[text.index(start):text.index(end, text.index(start))]


class ReverseToolsContract(unittest.TestCase):
    def test_pins_are_identical_in_both_images(self) -> None:
        for image in IMAGES:
            text = dockerfile(image)
            for pin in SHARED_PINS + (WINE[image],):
                self.assertIn(pin, text, f"{image}: missing {pin}")

    def test_every_new_download_is_checksummed(self) -> None:
        for image in IMAGES:
            text = dockerfile(image)
            self.assertNotIn("/latest/", text, f"{image}: an unpinned 'latest' download")
            checks = re.findall(r'echo "\$\{?(\w+_SHA256)\}?  [^"]+" \| sha256sum -c -', text)
            want = {"audit-binary-analysis": {"JAVA_SHA256", "GHIDRA_SHA256", "X64DBG_SHA256"},
                    "audit-native": {"GHIDRA_JDK_SHA256", "GHIDRA_SHA256", "X64DBG_SHA256"}}[image]
            self.assertEqual(set(checks), want, image)
            for pinned in ('"wine=${WINE_VERSION}"', '"wine64=${WINE_VERSION}"', '"wine32:i386=${WINE_VERSION}"'):
                self.assertIn(pinned, text, image)

    def test_x64dbg_blocks_are_the_same_text(self) -> None:
        blocks = {name: (between(dockerfile(name), "# --- Wine + Xvfb, then x64dbg", "WINEDLLOVERRIDES="),
                         between(dockerfile(name), "# --- Wine prefix, created at build time", "USER root"))
                  for name in IMAGES}
        self.assertEqual(blocks["audit-binary-analysis"], blocks["audit-native"])

    def test_wrapper_contract(self) -> None:
        wrapper = between(dockerfile("audit-native"), "<<'X64DBG_WRAPPER'", "\nX64DBG_WRAPPER\n")
        for needle in ("headless.exe", "-userdir", "xvfb-run -a", "--prepare", "--which", "stat -c %u",
                       "msvcp140,vcruntime140,vcruntime140_1=n,b", "mscoree,mshtml="):
            self.assertIn(needle, wrapper)
        self.assertNotRegex(wrapper, r"\b(curl|wget|--network)\b")
        text = dockerfile("audit-native")
        self.assertIn("for name in x96dbg x64dbg x32dbg", text)
        self.assertIn("JAVA_HOME_OVERRIDE=/opt/ghidra-jdk", text)
        for image in IMAGES:
            self.assertIn("-Duser.home=${HOME:-/tmp}", dockerfile(image), image)

    def test_smoke_script_matches_pins(self) -> None:
        smoke = (ROOT / "scripts" / "smoke_reverse_tools.sh").read_text(encoding="utf-8")
        self.assertIn("wine-8.0 (Debian 8.0~repack-4)", smoke)
        self.assertIn("wine-9.0 (Ubuntu 9.0~repack-4build3)", smoke)
        self.assertIn('"21.0.12"', smoke)
        self.assertIn('= 12.1.3 ]', smoke)


if __name__ == "__main__":
    unittest.main()
