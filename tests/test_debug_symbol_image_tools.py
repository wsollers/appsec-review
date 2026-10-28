from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
import tomllib

import pytest

from appsec_review.container_runtime.catalog import load_catalog


ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = ROOT / "containers" / "buildenv" / "native-toolchain"
FALLBACK = ROOT / "containers" / "tools" / "native-cpp"
LLVM_APT_VERSION = "1:18.1.3-1ubuntu1"
READERS = ("/usr/bin/llvm-dwarfdump-18", "/usr/bin/llvm-pdbutil-18")


def test_shared_toolchain_pins_reader_package_to_its_compiler_version() -> None:
    pins = [
        line.strip().split("=", 1)
        for line in (TOOLCHAIN / "packages.lock").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert len({name for name, _ in pins}) == len(pins)
    packages = dict(pins)
    assert packages["llvm-18"] == packages["clang-18"] == packages["lld-18"] == LLVM_APT_VERSION
    assert packages["python3"] == "3.12.3-0ubuntu2.1"
    dockerfile = (TOOLCHAIN / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY packages.lock check-toolchain.sh /opt/native-toolchain/" in dockerfile
    assert "$(grep -v '^#' /opt/native-toolchain/packages.lock)" in dockerfile
    assert "sh /opt/native-toolchain/check-toolchain.sh" in dockerfile


@pytest.mark.parametrize("reader", READERS)
def test_shared_toolchain_checks_absolute_reader_version_at_build_time(reader: str) -> None:
    script = (TOOLCHAIN / "check-toolchain.sh").read_text(encoding="utf-8")
    checks = [
        shlex.split(line)
        for line in script.splitlines()
        if line.startswith("expect ")
    ]
    assert ["expect", "18.1.3", reader, "--version"] in checks
    assert 'output=$("$@" 2>&1 | head -n 1)' in script
    assert "toolchain identity mismatch" in script
    assert "exit 1" in script


@pytest.mark.parametrize("family", ("cpp", "go", "php", "python", "rust-wasm", "typescript"))
def test_native_compiler_families_inherit_and_recheck_symbol_readers(family: str) -> None:
    dockerfile = (TOOLCHAIN.parent / family / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1" in dockerfile
    assert "sh /opt/native-toolchain/check-toolchain.sh" in dockerfile


def test_fallback_locked_closure_already_provisions_readers_and_python() -> None:
    manifest = (FALLBACK / "packages.manifest").read_text(encoding="utf-8")
    for package, version in (("llvm-18", LLVM_APT_VERSION), ("python3", "3.12.3-0ubuntu2.1")):
        assert re.search(
            rf"^{re.escape(package)}={re.escape(version)} [0-9a-f]{{64}} \S+\.deb$",
            manifest,
            re.MULTILINE,
        )
    lock = json.loads((FALLBACK / "assets.lock.json").read_text(encoding="utf-8"))
    artifact = next(item for item in lock["artifacts"] if item["name"] == "native-cpp-debs.tar")
    assert artifact["path"] == "downloads/native-cpp-debs.tar"
    assert re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])
    assert artifact["bytes"] > 0
    dockerfile = (FALLBACK / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY downloads/native-cpp-debs.tar /tmp/native-cpp-debs.tar" in dockerfile
    assert "apt-get install -y --no-download /tmp/debs/*.deb" in dockerfile


@pytest.mark.parametrize(
    ("executable", "version"),
    [(reader, "18.1.3") for reader in READERS] + [("/usr/bin/python3", "Python 3.12.3")],
)
def test_fallback_build_checks_reader_and_interpreter_versions(executable: str, version: str) -> None:
    dockerfile = (FALLBACK / "Dockerfile").read_text(encoding="utf-8")
    assert f"&& {executable} --version | grep -F '{version}'" in dockerfile


def test_fallback_allows_python_exporter_without_replacing_native_entrypoint() -> None:
    manifest = tomllib.loads((FALLBACK / "tool.toml").read_text(encoding="utf-8"))
    tool = load_catalog(ROOT).tool("tool-native-cpp")
    assert tool.executable == manifest["executable"] == "/opt/appsec/native.py"
    assert "/usr/bin/python3" in tool.additional_executables
    assert manifest["version_argv"] == ["/opt/appsec/native.py", "version"]
    assert manifest["network"] == "none"
    assert manifest["root_filesystem"] == manifest["target_mount"] == "read-only"
    assert manifest["capabilities"] == "drop-all"
    assert manifest["security_opt"] == "no-new-privileges"
    assert tool.user == "10001:10001"
