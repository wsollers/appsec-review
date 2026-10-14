"""Repository contract for the pinned Ghidra headless runtime closure.

These tests are static. They never download the release archive, reach the network, or invoke
Docker.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import sys
import tomllib

from appsec_review.container_runtime import load_catalog as load_runtime_catalog


ROOT = Path(__file__).resolve().parents[1]
CONTEXT = ROOT / "containers" / "tools" / "ghidra"
VERSION = "12.1.4"
PREFIX = f"ghidra_{VERSION}_PUBLIC/"
SHA256 = re.compile(r"[0-9a-f]{64}")


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


container_build = _module("container_build_ghidra", ROOT / "containers" / "build.py")


def _entry() -> dict:
    return container_build.load_catalog()["by_id"]["tool-ghidra"]


def _lock() -> dict:
    return json.loads((CONTEXT / "assets.lock.json").read_text(encoding="utf-8"))


def _manifest() -> dict:
    return tomllib.loads((CONTEXT / "tool.toml").read_text(encoding="utf-8"))


def _dockerfile() -> str:
    return (CONTEXT / "Dockerfile").read_text(encoding="utf-8")


def _inventory() -> dict:
    return json.loads((CONTEXT / "inventory.json").read_text(encoding="utf-8"))


def test_catalog_registers_a_pinned_enabled_ghidra_tool() -> None:
    entry = _entry()
    assert entry["state"] == "enabled" and entry["kind"] == "tool"
    assert entry["version"] == VERSION and entry["tag"] == f"appsec-review/tool-ghidra:{VERSION}"
    assert entry["build_args"] == {"TOOL_VERSION": VERSION}
    assert entry["architectures"] == ["linux/amd64"] and entry["dependencies"] == ["base-jre"]
    assert entry["build_contexts"] == {"shared": "containers/tools/shared"}
    assert "not source coverage" in entry["purpose"]
    rendered = json.dumps(entry).lower()
    for moving in ("latest", "master", "main", "nightly", "snapshot", "head"):
        assert not re.search(rf"(?<![a-z]){moving}(?![a-z])", rendered), moving
    catalog = container_build.load_catalog()
    assert container_build.validate(catalog) == []
    assert container_build.dependency_order(["tool-ghidra"], catalog) == ["base-jre", "tool-ghidra"]


def test_runtime_catalog_loads_ghidra_under_the_central_policy() -> None:
    tool = load_runtime_catalog(ROOT).tool("tool-ghidra")
    assert tool.version == VERSION and tool.network == "none" and tool.user == "10001:10001"
    assert tool.executable == "/opt/appsec/bin/ghidra-export"
    # Packaging limits equal the central policy; extra capacity comes only from configuration.
    assert (tool.memory, tool.cpus, tool.pids_limit, tool.timeout_seconds) == ("1g", "2", 256, 600)
    manifest = _manifest()
    assert manifest["static_adapter"] is False
    assert "managed code is a named gap" in manifest["coverage"]
    for key in ("inventory", "review", "export_script"):
        assert (ROOT / manifest[key]).is_file(), key


def test_asset_lock_pins_one_immutable_release_archive() -> None:
    lock = _lock()
    assert lock["image_id"] == "tool-ghidra" and lock["tool_version"] == VERSION
    assert lock["release"]["tag"] == f"Ghidra_{VERSION}_build"
    assert SHA256.fullmatch(lock["license_sha256"]) and lock["java"]["bundled"] is False
    (archive,) = lock["artifacts"]
    assert archive["role"] == "archive" and archive["version"] == VERSION
    assert archive["url"].startswith(
        f"https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_{VERSION}_build/")
    assert "/latest/" not in archive["url"]
    assert SHA256.fullmatch(archive["sha256"]) and re.fullmatch(r"[0-9a-f]{128}", archive["sha512"])
    assert archive["bytes"] > 100_000_000 and archive["path"].startswith("downloads/")
    assert archive["signature_verification"]["status"] == "not-published"
    # The JDK the manifest names is the one the Dockerfile and lock pin.
    assert _manifest()["jdk"] == lock["java"]["runtime"]
    assert f"FROM {lock['java']['runtime']} AS jdk" in _dockerfile()


def test_dockerfile_builds_offline_from_digest_pinned_stages() -> None:
    text = _dockerfile()
    stages = re.findall(r"(?m)^FROM\s+(\S+)", text)
    assert len(stages) == 3 and stages[-1] == "appsec-review/base-jre:21-noble"
    assert all(re.search(r"@sha256:[0-9a-f]{64}$", stage) for stage in stages[:-1])
    instructions = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert not re.search(r"(?i)\b(curl|wget|apt-get|apt|pip|gradle|mvn)\b", instructions)
    assert Path(_lock()["artifacts"][0]["path"]).name in text
    assert "--expect-inventory /opt/review/inventory.json" in text
    assert re.search(r"(?m)^USER 10001:10001$", text) and "ENTRYPOINT" not in text
    # The export script is compiled against the pinned Ghidra classes during the build.
    assert "javac" in text and "AppsecExportProgram.java" in text


def test_reviewed_closure_matches_the_committed_inventory() -> None:
    manifest, inventory, archive = _manifest(), _inventory(), _lock()["artifacts"][0]
    closure = manifest["closure"]
    assert inventory["schema"] == "appsec-review/tool-closure-inventory/1"
    assert inventory["archive"] == {"name": archive["name"], "sha256": archive["sha256"],
                                    "bytes": archive["bytes"]}
    assert inventory["include"] == sorted(closure["include"])
    assert all(item.startswith(PREFIX) for item in closure["include"])
    paths = {item["path"] for item in inventory["files"]}
    assert inventory["totals"]["files"] == len(paths) == 2799
    assert inventory["totals"]["bytes"] <= closure["max_expanded_bytes"]
    assert all(any(path == prefix or path.startswith(prefix + "/") for prefix in closure["include"])
               for path in paths)
    for required in ("support/analyzeHeadless", "support/launch.sh", "support/LaunchSupport.jar",
                     "Ghidra/application.properties", "LICENSE", "bom.json",
                     "Ghidra/Features/Decompiler/os/linux_x86_64/decompile",
                     "GPL/DemanglerGnu/os/linux_x86_64/demangler_gnu_v2_41"):
        assert PREFIX + required in paths, required
    for excluded in ("Ghidra/Debug/", "Extensions/", "docs/", "server/", "GPL/DMG/", "ghidraRun"):
        assert not any(path.startswith(PREFIX + excluded) for path in paths), excluded
    by_path = {item["path"]: item for item in inventory["files"]}
    decompiler = by_path[PREFIX + "Ghidra/Features/Decompiler/os/linux_x86_64/decompile"]
    assert decompiler["kind"] == "elf" and decompiler["executable"] is True
    assert by_path[PREFIX + "support/analyzeHeadless"]["executable"] is True
    # Only Linux native code is expected to run; the count of ELF files is part of the review.
    assert inventory["totals"]["elf"] == sum(item["kind"] == "elf" for item in inventory["files"])


def test_wrapper_confines_input_output_and_ghidra_state() -> None:
    wrapper = (CONTEXT / "ghidra-export").read_text(encoding="utf-8")
    assert wrapper.startswith("#!/usr/bin/env bash\n") and "set -euo pipefail" in wrapper
    assert '[[ "$input" =~ ^/target/[A-Za-z0-9._-]+$ ]]' in wrapper
    assert '"$output" =~ ^/scratch/' in wrapper and '"$work" =~ ^/scratch/' in wrapper
    for confined in ('HOME="$work/home"', 'XDG_CONFIG_HOME="$work/home/.config"',
                     "-Djava.io.tmpdir=$work/tmp"):
        assert confined in wrapper
    assert "-deleteProject" in wrapper and "-analysisTimeoutPerFile" in wrapper
    assert "eval" not in wrapper and "\r" not in wrapper
    version = (CONTEXT / "ghidra-version").read_text(encoding="utf-8")
    assert 'echo "ghidra $version"' in version and "\r" not in version


def test_export_script_writes_the_documented_tables_and_a_completion_marker() -> None:
    script = (CONTEXT / "scripts" / "AppsecExportProgram.java").read_text(encoding="utf-8")
    for table in ("functions.jsonl", "decompiled.jsonl", "pcode.jsonl", "calls.jsonl", "imports.jsonl",
                  "exports.jsonl", "strings.jsonl", "gaps.jsonl", "program.json", "complete.json"):
        assert f'"{table}"' in script, table
    assert 'SCHEMA = "appsec-review/ghidra-export/1"' in script
    assert "extends HeadlessScript" in script and "analysisTimeoutOccurred()" in script
    # The target is analyzed, never launched.
    assert not re.search(r"Runtime\.getRuntime|ProcessBuilder|\.exec\(", script)
