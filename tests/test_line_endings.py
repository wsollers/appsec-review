from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is required for checkout conversion")
@pytest.mark.parametrize("autocrlf", ["true", "false", "input"])
def test_checkout_preserves_pinned_bytes_and_canonical_git_blobs(tmp_path, autocrlf):
    def git(*args):
        return subprocess.run(
            ["git", "-C", str(tmp_path), *args], check=True, capture_output=True,
        ).stdout

    git("init", "--quiet")
    git("config", "core.autocrlf", autocrlf)
    git("config", "core.safecrlf", "false")
    shutil.copyfile(ROOT / ".gitattributes", tmp_path / ".gitattributes")
    portable = b"first\nsecond\n"
    windows = b"@echo off\nexit /b\n"
    files = {
        "scripts/check.sh": portable,
        "scripts/check.ps1": portable,
        "src/example.py": portable,
        "tools/check.bat": windows,
        "tools/check.cmd": windows,
        "image.bin": b"\x00binary\r\npayload\n",
    }
    for root in ("rules", "data", "tests/fixtures", "test/acceptance"):
        for name, content in (
            ("lf.txt", portable), ("crlf.txt", b"first\r\nsecond\r\n"),
            ("mixed.txt", b"first\r\nsecond\n"),
        ):
            files[f"{root}/{name}"] = content
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    git("add", ".")

    output = tmp_path / "checkout"
    git("checkout-index", "--all", f"--prefix={output.as_posix()}/")
    for name, content in files.items():
        assert git("show", f":{name}") == content, name
        expected = content.replace(b"\n", b"\r\n") if name.endswith((".bat", ".cmd")) else content
        assert (output / name).read_bytes() == expected, name

    # Staging a Windows checkout again must not change its Git object identities.
    before = git("ls-files", "--stage")
    for name in files:
        shutil.copyfile(output / name, tmp_path / name)
    git("add", *files)
    assert git("ls-files", "--stage") == before


def test_portable_shell_launchers_are_lf():
    for directory in ("scripts", "containers", "deploy"):
        for path in (ROOT / directory).rglob("*.sh"):
            assert b"\r\n" not in path.read_bytes(), path.relative_to(ROOT).as_posix()
