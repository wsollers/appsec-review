"""Repository contract for the pinned clangd-indexer runtime closure.

Static tests only: they never download the release archive, reach the network, or invoke Docker.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tomllib

from appsec_review.container_runtime import load_catalog as load_runtime_catalog


ROOT = Path(__file__).resolve().parents[1]
CONTEXT = ROOT / "containers" / "tools" / "clangd-indexer"
FIXTURE = ROOT / "containers" / "fixtures" / "clangd-indexer"
VERSION = "23.1.0"
SHA256 = re.compile(r"[0-9a-f]{64}")
SHA512 = re.compile(r"[0-9a-f]{128}")

_SPEC = importlib.util.spec_from_file_location("container_build_clangd", ROOT / "containers" / "build.py")
assert _SPEC and _SPEC.loader
container_build = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(container_build)


def _entry() -> dict:
    return container_build.load_catalog()["by_id"]["tool-clangd-indexer"]


def _lock() -> dict:
    return json.loads((CONTEXT / "assets.lock.json").read_text(encoding="utf-8"))


def _manifest() -> dict:
    return tomllib.loads((CONTEXT / "tool.toml").read_text(encoding="utf-8"))


def _archive() -> dict:
    (archive,) = _lock()["artifacts"]
    return archive


def test_catalog_pins_clangd_indexer_without_moving_references() -> None:
    entry = _entry()
    assert entry["state"] == "enabled" and entry["kind"] == "tool"
    assert entry["version"] == VERSION and entry["tag"] == f"appsec-review/tool-clangd-indexer:{VERSION}"
    assert entry["architectures"] == ["linux/amd64"] and entry["dependencies"] == ["base-ubuntu"]
    assert entry["build_args"] == {"TOOL_VERSION": VERSION, "CLANGD_SHA512": _archive()["sha512"]}
    assert entry["build_contexts"] == {"shared": "containers/tools/shared"}
    rendered = json.dumps(entry).lower()
    for moving in ("latest", "master", "main", "nightly", "snapshot", "head"):
        assert not re.search(rf"(?<![a-z]){moving}(?![a-z])", rendered), moving
    assert "not index coverage" in entry["purpose"]
    for path in (entry["context"], entry["tool_manifest"], entry["assets_lock"]):
        assert ROOT.resolve() in (ROOT / path).resolve(strict=True).parents


def test_catalog_and_runtime_loader_accept_clangd_indexer() -> None:
    catalog = container_build.load_catalog()
    assert container_build.validate(catalog) == []
    assert container_build.dependency_order(["tool-clangd-indexer"], catalog) == [
        "base-ubuntu", "tool-clangd-indexer"]
    tool = load_runtime_catalog(ROOT).tool("tool-clangd-indexer")
    assert tool.version == VERSION and tool.network == "none" and tool.user == "10001:10001"


def test_asset_lock_is_exact_unsigned_and_inside_context() -> None:
    lock = _lock()
    assert lock["schema"] == "appsec-review/assets-lock/1" and lock["image_id"] == "tool-clangd-indexer"
    assert lock["tool_version"] == VERSION and lock["architecture"] == "linux/amd64"
    assert lock["license"] == "Apache-2.0 WITH LLVM-exception" and SHA256.fullmatch(lock["license_sha256"])
    assert lock["release"]["tag"] == VERSION and lock["release"]["tag_signed"] is False
    assert "Unverified" in lock["release"]["source_ref"]
    archive = _archive()
    assert archive["role"] == "archive"
    assert archive["url"] == (f"https://github.com/clangd/clangd/releases/download/{VERSION}/"
                              f"clangd_indexing_tools-linux-{VERSION}.zip")
    assert "/latest/" not in archive["url"]
    assert SHA256.fullmatch(archive["sha256"]) and SHA512.fullmatch(archive["sha512"])
    assert type(archive["bytes"]) is int and archive["bytes"] == 159888487
    assert archive["signature_verification"]["status"] == "not-published"
    assert archive["version"] == VERSION and archive["license_source"] and archive["provenance"]
    target = (CONTEXT / archive["path"]).resolve()
    assert CONTEXT.resolve() in target.parents and PurePosixPath(archive["path"]).parts[0] == "downloads"
    ignored = subprocess.run(["git", "check-ignore", "-q", str(target)], cwd=ROOT)
    assert ignored.returncode == 0


def test_closure_installs_only_the_indexer_license_and_builtin_headers() -> None:
    closure = _manifest()["closure"]
    assert closure["root"] == "/opt/clangd"
    assert closure["include"] == [f"clangd_{VERSION}/LICENSE.TXT", f"clangd_{VERSION}/bin/clangd-indexer",
                                  "clangd_23.1.0/lib/clang/23/include"]
    inventory = json.loads((CONTEXT / "inventory.json").read_text(encoding="utf-8"))
    archive = _archive()
    assert inventory["archive"] == {"name": archive["name"], "sha256": archive["sha256"],
                                    "bytes": archive["bytes"]}
    paths = [item["path"] for item in inventory["files"]]
    assert paths == sorted(paths)
    assert [item["path"] for item in inventory["files"] if item["kind"] == "elf"] == [
        f"clangd_{VERSION}/bin/clangd-indexer"]
    assert not any("index-server" in path or "/lib/clang/23/lib/" in path for path in paths)
    assert all(path.startswith(f"clangd_{VERSION}/lib/clang/23/include/") for path in paths
               if path not in closure["include"])


def test_tool_manifest_enforces_the_non_root_offline_boundary() -> None:
    manifest = _manifest()
    assert manifest["id"] == "tool-clangd-indexer" and manifest["version"] == VERSION
    assert manifest["user"] == "10001:10001" and manifest["network"] == "none"
    assert manifest["root_filesystem"] == "read-only" and manifest["target_mount"] == "read-only"
    assert manifest["scratch_mount"] == "read-write" and manifest["capabilities"] == "drop-all"
    assert manifest["security_opt"] == "no-new-privileges"
    for key in ("pids_limit", "timeout_seconds", "output_bytes"):
        assert type(manifest[key]) is int and manifest[key] > 0
    root = PurePosixPath(manifest["closure"]["root"])
    for value in (manifest["executable"], *manifest["version_argv"][:1]):
        path = PurePosixPath(value)
        assert path.is_absolute() and root in path.parents
    assert manifest["version_expect"].format(version=VERSION) == f"LLVM version {VERSION}"
    assert manifest["coverage"].startswith("none")


def test_dockerfile_is_offline_pinned_verified_and_non_root() -> None:
    text = (CONTEXT / "Dockerfile").read_text(encoding="utf-8")
    instructions = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    for forbidden in (r"\bcurl\b", r"\bwget\b", r"\bapt(-get)?\b", r"\bpip\b", r"ADD\s+https?://",
                      r"\|\s*(ba)?sh\b", r"index-server"):
        assert not re.search(forbidden, instructions, re.IGNORECASE), forbidden
    for base in re.findall(r"(?m)^FROM\s+(\S+)", text):
        assert "@sha256:" in base or base == "appsec-review/base-ubuntu:24.04"
    assert f"COPY {_archive()['path']} /tmp/clangd.zip" in text
    assert "COPY --from=shared safe_extract.py /opt/review/" in text
    assert "sha512sum --check --strict" in text and "--expect-inventory /opt/review/inventory.json" in text
    assert 'grep -F "LLVM version ${TOOL_VERSION}"' in text
    assert re.findall(r"(?m)^USER\s+(\S+)", text)[-1] == "10001:10001"
    final_stage = text.split("FROM appsec-review/base-ubuntu:24.04", 1)[1]
    assert re.findall(r"(?m)^RUN\s+(.*)$", final_stage) == [
        '/opt/clangd/clangd_23.1.0/bin/clangd-indexer --version | grep -F "LLVM version ${TOOL_VERSION}"']


def test_functional_fixture_exercises_clang_and_clang_cl_commands() -> None:
    commands = json.loads((FIXTURE / "compile_commands.json").read_text(encoding="utf-8"))
    drivers = {row["arguments"][0] for row in commands}
    assert drivers == {"clang++", "clang-cl"}
    for row in commands:
        assert row["directory"].startswith("/workspace/") and row["file"].startswith("/workspace/")
        assert (FIXTURE / row["file"].removeprefix("/workspace/")).is_file()
    source = (ROOT / "containers" / "build.py").read_text(encoding="utf-8")
    assert '"tool-clangd-indexer": ("clangd-indexer"' in source
    assert '"Name:            clang_cl_entry"' in source


def test_readme_documents_the_build_commands() -> None:
    readme = (CONTEXT / "README.md").read_text(encoding="utf-8")
    for command in ("python3 containers/build.py validate",
                    "python3 containers/build.py build tool-clangd-indexer",
                    "python3 containers/build.py smoke tool-clangd-indexer --functional",
                    "python3 containers/build.py security tool-clangd-indexer",
                    "--build-context shared=containers/tools/shared"):
        assert command in readme, command
