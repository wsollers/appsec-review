"""Repository contract for the pinned Joern/c2cpg runtime closure.

These tests are static or fixture-based. They never download the release archive, reach the
network, or invoke Docker.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tomllib
import zipfile

import pytest

from appsec_review.container_runtime import load_catalog as load_runtime_catalog
from appsec_review.jobs.job_cpp_compiled_analysis import build_job as build_cpp
from appsec_review.jobs.job_cpp_compiled_analysis.job import JOERN_GAP
from appsec_review.jobs.job_language_build import build_job as build_language
from appsec_review.runtime import GraphRunner


ROOT = Path(__file__).resolve().parents[1]
CONTEXT = ROOT / "containers" / "tools" / "joern"
VERSION = "4.0.630"
TAG = f"v{VERSION}"
SHA256 = re.compile(r"[0-9a-f]{64}")
SHA512 = re.compile(r"[0-9a-f]{128}")


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve their defining module during execution
    spec.loader.exec_module(module)
    return module


container_build = _module("container_build_joern", ROOT / "containers" / "build.py")
safe_extract = _module("joern_safe_extract", CONTEXT / "safe_extract.py")


def _entry() -> dict:
    return container_build.load_catalog()["by_id"]["tool-joern"]


def _lock() -> dict:
    return json.loads((CONTEXT / "assets.lock.json").read_text(encoding="utf-8"))


def _manifest() -> dict:
    return tomllib.loads((CONTEXT / "tool.toml").read_text(encoding="utf-8"))


def _dockerfile() -> str:
    return (CONTEXT / "Dockerfile").read_text(encoding="utf-8")


def _archive_entry() -> dict:
    (archive,) = [item for item in _lock()["artifacts"] if item["role"] == "archive"]
    return archive


# Catalog contract


def test_catalog_pins_joern_without_moving_references() -> None:
    entry = _entry()
    assert entry["state"] == "enabled" and entry["kind"] == "tool"
    assert entry["version"] == VERSION
    assert entry["tag"] == f"appsec-review/tool-joern:{VERSION}"
    assert entry["build_args"]["TOOL_VERSION"] == VERSION
    assert entry["architectures"] == ["linux/amd64"]
    assert entry["dependencies"] == ["base-jre"]
    rendered = json.dumps(entry).lower()
    for moving in ("latest", "master", "main", "nightly", "snapshot", "head"):
        assert not re.search(rf"(?<![a-z]){moving}(?![a-z])", rendered), moving
    assert "cpg" in entry["purpose"].lower() and "not cpg coverage" in entry["purpose"].lower()


def test_catalog_paths_resolve_inside_repository() -> None:
    entry = _entry()
    root = ROOT.resolve()
    context = (ROOT / entry["context"]).resolve()
    for path in (context, context / entry["dockerfile"], ROOT / entry["tool_manifest"],
                 ROOT / entry["assets_lock"]):
        resolved = Path(path).resolve(strict=True)
        assert root in resolved.parents
    assert context == CONTEXT.resolve()


def test_catalog_validation_reports_no_joern_error() -> None:
    catalog = container_build.load_catalog()
    errors = container_build.validate(catalog)
    assert not [error for error in errors if "joern" in error]
    assert errors == []
    assert container_build.dependency_order(["tool-joern"], catalog) == ["base-jre", "tool-joern"]


def test_runtime_catalog_loads_joern_under_the_central_policy() -> None:
    tool = load_runtime_catalog(ROOT).tool("tool-joern")
    assert tool.version == VERSION and tool.network == "none" and tool.user == "10001:10001"
    assert tool.executable.startswith("/opt/joern/")


def test_catalog_validation_rejects_latest_asset_urls(tmp_path: Path, monkeypatch) -> None:
    lock = _lock()
    lock["artifacts"][0]["url"] = "https://github.com/joernio/joern/releases/latest/download/x.zip"
    lock_path = tmp_path / "assets.lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    catalog = container_build.load_catalog()
    catalog["by_id"]["tool-joern"]["assets_lock"] = str(lock_path)
    real_safe_path = container_build.safe_path
    monkeypatch.setattr(container_build, "safe_path",
                        lambda value: lock_path if value == str(lock_path) else real_safe_path(value))
    assert any("tool-joern" in error and "latest" in error for error in container_build.validate(catalog))


# Asset-lock contract


def test_asset_lock_records_identity_and_release_provenance() -> None:
    lock = _lock()
    assert lock["schema"] == "appsec-review/assets-lock/1"
    assert lock["image_id"] == "tool-joern" and lock["tool_version"] == VERSION
    assert lock["project"] == "https://github.com/joernio/joern"
    assert lock["license"] == "Apache-2.0"
    assert lock["license_source"].endswith(f"/blob/{TAG}/LICENSE")
    assert SHA256.fullmatch(lock["license_sha256"])
    assert lock["architecture"] == "linux/amd64"
    release = lock["release"]
    assert release["tag"] == TAG and release["version"] == VERSION
    assert re.fullmatch(r"[0-9a-f]{40}", release["commit"])
    assert re.fullmatch(r"[0-9a-f]{40}", release["tag_object"])
    assert release["tag_signed"] is False
    assert lock["java"]["bundled"] is False
    assert lock["java"]["runtime"] == "appsec-review/base-jre:21-noble"


def test_asset_lock_artifacts_are_exact_immutable_and_inside_context() -> None:
    artifacts = _lock()["artifacts"]
    assert sorted(item["role"] for item in artifacts) == ["archive", "checksum-sidecar"]
    for artifact in artifacts:
        url = artifact["url"]
        assert url.startswith("https://github.com/joernio/joern/releases/download/")
        assert f"/download/{TAG}/" in url
        assert "/latest/" not in url and "?" not in url
        assert SHA256.fullmatch(artifact["sha256"]), artifact["name"]
        assert type(artifact["bytes"]) is int and artifact["bytes"] > 0
        assert artifact["architecture"] == "linux/amd64"
        assert artifact["version"] == VERSION
        assert artifact["license"] and artifact["license_source"] and artifact["provenance"]
        assert artifact["signature_verification"]["status"] in {"verified", "not-performed", "not-published"}
        assert artifact["signature_verification"]["reason"]
        target = (CONTEXT / artifact["path"]).resolve()
        assert CONTEXT.resolve() in target.parents
        assert PurePosixPath(artifact["path"]).parts[0] == "downloads"
    archive = _archive_entry()
    assert archive["name"] == "joern-cli-linux-x86_64.zip"
    assert archive["url"].endswith(f"/{TAG}/joern-cli-linux-x86_64.zip")
    assert SHA512.fullmatch(archive["sha512"])
    assert archive["bytes"] == 1858333634


def test_checksum_sidecar_is_not_described_as_a_signature() -> None:
    lock = _lock()
    (sidecar,) = [item for item in lock["artifacts"] if item["role"] == "checksum-sidecar"]
    archive = _archive_entry()
    assert sidecar["is_signature"] is False
    assert sidecar["url"] == archive["url"] + ".sha512"
    assert archive["signature_verification"]["status"] == "not-published"
    assert sidecar["signature_verification"]["status"] == "not-published"
    assert "not a signature" in archive["signature_verification"]["reason"]
    assert archive["verification"]["sidecar_entry"].endswith("/joern-cli-linux-x86_64.zip")
    assert _entry()["build_args"]["JOERN_SHA512"] == archive["sha512"]


def test_downloaded_archives_are_not_tracked_by_git() -> None:
    tracked = subprocess.run(["git", "ls-files", "containers/tools/joern"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout.split()
    assert not [path for path in tracked if "/downloads/" in path or path.endswith((".zip", ".sha512"))]
    for artifact in _lock()["artifacts"]:
        ignored = subprocess.run(["git", "check-ignore", "-q", str(CONTEXT / artifact["path"])], cwd=ROOT)
        assert ignored.returncode == 0, artifact["path"]


def test_committed_inventory_matches_the_lock_and_closure_policy() -> None:
    inventory = json.loads((CONTEXT / "inventory.json").read_text(encoding="utf-8"))
    archive = _archive_entry()
    closure = _manifest()["closure"]
    assert inventory["schema"] == "appsec-review/tool-closure-inventory/1"
    assert inventory["archive"] == {"name": archive["name"], "sha256": archive["sha256"],
                                    "bytes": archive["bytes"]}
    assert inventory["include"] == sorted(closure["include"])
    paths = [item["path"] for item in inventory["files"]]
    assert paths == sorted(paths) and len(paths) == len(set(paths))
    assert all(safe_extract._selected(PurePosixPath(path), closure["include"]) for path in paths)
    assert not any(item["kind"] in {"elf", "symlink"} for item in inventory["files"])
    assert not any("/frontends/" in path and "/frontends/c2cpg/" not in path for path in paths)
    assert {path for path in paths if path in closure["version_jars"]} == set(closure["version_jars"])
    assert inventory["totals"]["files"] == len(paths)


# Tool-manifest security policy


def test_tool_manifest_enforces_the_non_root_offline_boundary() -> None:
    manifest = _manifest()
    assert manifest["schema"] == "appsec-review/tool/1" and manifest["id"] == "tool-joern"
    assert manifest["version"] == VERSION
    assert manifest["user"] == "10001:10001"
    assert manifest["network"] == "none"
    assert manifest["root_filesystem"] == "read-only"
    assert manifest["target_mount"] == "read-only"
    assert manifest["scratch_mount"] == "read-write"
    assert manifest["capabilities"] == "drop-all"
    assert manifest["security_opt"] == "no-new-privileges"
    assert re.fullmatch(r"[1-9][0-9]*[mg]", manifest["memory"])
    assert float(manifest["cpus"]) > 0
    for key in ("pids_limit", "timeout_seconds", "output_bytes"):
        assert type(manifest[key]) is int and manifest[key] > 0
    assert manifest["coverage"].startswith("none")


def test_version_probe_is_absolute_and_inside_the_installed_closure() -> None:
    manifest = _manifest()
    root = PurePosixPath(manifest["closure"]["root"])
    assert root == PurePosixPath("/opt/joern")
    for value in (manifest["executable"], *manifest["version_argv"]):
        path = PurePosixPath(value)
        assert path.is_absolute() and root in path.parents and ".." not in path.parts
    assert manifest["version_expect"].format(version=manifest["version"]) == f"c2cpg {VERSION}"
    assert (CONTEXT / "joern-version").is_file()
    assert f"COPY --chmod=0555 joern-version {manifest['version_argv'][0]}" in _dockerfile()


# Dockerfile policy


def test_dockerfile_uses_no_network_installers_or_moving_bases() -> None:
    text = _dockerfile()
    instructions = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    for forbidden in (r"\bcurl\b", r"\bwget\b", r"joern-install", r"\bapt(-get)?\b", r"\bapk\b",
                      r"\bdnf\b", r"\byum\b", r"\bpip\b", r"\bmvn\b", r"\bmaven\b", r"\bsbt\b",
                      r"\bcoursier\b", r"\bcs\s+(fetch|install)", r"\bgit\s+clone", r"ADD\s+https?://",
                      r"\|\s*(ba)?sh\b", r"--dep\b", r"--repo\b"):
        assert not re.search(forbidden, instructions, re.IGNORECASE), forbidden
    for line in re.findall(r"(?m)^FROM\s+(\S+)", text):
        assert "@sha256:" in line or line == "appsec-review/base-jre:21-noble", line
        assert not line.endswith(":latest")
    assert "# syntax=" not in text
    assert re.findall(r"(?m)^USER\s+(\S+)", text)[-1] == "10001:10001"


def test_dockerfile_verifies_and_probes_the_pinned_archive() -> None:
    text = _dockerfile()
    archive = _archive_entry()
    (sidecar,) = [item for item in _lock()["artifacts"] if item["role"] == "checksum-sidecar"]
    assert f"COPY {archive['path']} /tmp/joern.zip" in text
    assert f"COPY {sidecar['path']} /tmp/joern.zip.sha512" in text
    assert "ARG JOERN_SHA512" in text
    assert 'test "$sidecar_hash" = "$JOERN_SHA512"' in text
    assert "sha512sum --check --strict" in text
    assert "--expect-inventory /opt/review/inventory.json" in text
    assert 'grep -Fx "c2cpg ${TOOL_VERSION}"' in text
    assert "RUN /opt/joern/bin/joern-version" in text
    assert "extractall" not in text and "unzip" not in text


def test_runtime_image_never_executes_target_programs() -> None:
    final_stage = _dockerfile().split("FROM appsec-review/base-jre:21-noble", 1)[1]
    assert re.findall(r"(?m)^RUN\s+(.*)$", final_stage) == [
        '/opt/joern/bin/joern-version | grep -Fx "c2cpg ${TOOL_VERSION}"']
    probe = (CONTEXT / "joern-version").read_text(encoding="utf-8")
    assert "/workspace" not in probe and "/target" not in probe and "/scratch" not in probe
    assert '"$root/joern-cli/frontends/c2cpg/bin/c2cpg" --help' in probe


# Safe extraction


LIMITS = safe_extract.Limits(max_members=64, max_total_bytes=1 << 20, max_member_ratio=50.0,
                             max_archive_ratio=1000.0)


def _zip(path: Path, entries: list[tuple[str, bytes | None, int | None]]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if mode is not None:
                info.external_attr = mode << 16
            if name.endswith("/"):
                info.external_attr |= 0x10
            archive.writestr(info, data or b"")
    return path


def _tar(path: Path, entries: list[tarfile.TarInfo], data: dict[str, bytes] | None = None) -> Path:
    with tarfile.open(path, "w") as archive:
        for info in entries:
            payload = (data or {}).get(info.name)
            if payload is not None:
                info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload) if payload is not None else None)
    return path


def test_extraction_accepts_a_nested_archive_and_installs_only_the_closure(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "ok.zip", [
        ("joern-cli/", None, stat.S_IFDIR | 0o755),
        ("joern-cli/lib/a.jar", b"jar-bytes", stat.S_IFREG | 0o644),
        ("joern-cli/frontends/c2cpg/bin/c2cpg", b"#!/bin/sh\n", stat.S_IFREG | 0o755),
        ("joern-cli/frontends/other/bin/tool", b"\x7fELF", stat.S_IFREG | 0o755),
        ("joern-cli/link", b"lib/a.jar", stat.S_IFLNK | 0o777),
    ])
    out = tmp_path / "out"
    written = safe_extract.extract(archive, out, LIMITS,
                                   ("joern-cli/lib", "joern-cli/frontends/c2cpg", "joern-cli/link"))
    assert (out / "joern-cli" / "lib" / "a.jar").read_bytes() == b"jar-bytes"
    launcher = out / "joern-cli" / "frontends" / "c2cpg" / "bin" / "c2cpg"
    assert launcher.stat().st_mode & 0o111
    assert not (out / "joern-cli" / "frontends" / "other").exists()
    assert (out / "joern-cli" / "link").is_symlink()
    assert PurePosixPath("joern-cli/frontends/other/bin/tool") not in written


@pytest.mark.parametrize("name", ["../escape.txt", "joern-cli/../../escape.txt", "joern-cli/./x",
                                  "joern-cli//x"])
def test_extraction_rejects_traversal_and_non_canonical_names(tmp_path: Path, name: str) -> None:
    archive = _zip(tmp_path / "bad.zip", [(name, b"x", stat.S_IFREG | 0o644)])
    with pytest.raises(safe_extract.UnsafeArchive):
        safe_extract.extract(archive, tmp_path / "out", LIMITS)
    assert not (tmp_path / "escape.txt").exists()


@pytest.mark.parametrize("name", ["/etc/passwd", "C:/Windows/evil.dll", "c:evil", "joern-cli\\..\\x"])
def test_extraction_rejects_absolute_drive_and_backslash_names(tmp_path: Path, name: str) -> None:
    member = safe_extract.Member(name, "file", 1)
    with pytest.raises(safe_extract.UnsafeArchive):
        safe_extract.validate_members([member], LIMITS, 1)


@pytest.mark.parametrize("target", ["../../outside", "/etc/passwd", "../..", "C:/x"])
def test_extraction_rejects_escaping_symlinks(tmp_path: Path, target: str) -> None:
    archive = _zip(tmp_path / "link.zip", [("joern-cli/link", target.encode(), stat.S_IFLNK | 0o777)])
    with pytest.raises(safe_extract.UnsafeArchive, match="escapes"):
        safe_extract.extract(archive, tmp_path / "out", LIMITS)
    assert not (tmp_path / "out" / "joern-cli" / "link").exists()


def test_extraction_rejects_hard_links_including_escaping_ones(tmp_path: Path) -> None:
    escaping = tarfile.TarInfo("joern-cli/hard")
    escaping.type, escaping.linkname = tarfile.LNKTYPE, "../../etc/passwd"
    with pytest.raises(safe_extract.UnsafeArchive, match="escapes"):
        safe_extract.extract(_tar(tmp_path / "a.tar", [escaping]), tmp_path / "a", LIMITS)
    regular = tarfile.TarInfo("joern-cli/file")
    internal = tarfile.TarInfo("joern-cli/hard")
    internal.type, internal.linkname = tarfile.LNKTYPE, "joern-cli/file"
    with pytest.raises(safe_extract.UnsafeArchive, match="hard links"):
        safe_extract.extract(_tar(tmp_path / "b.tar", [regular, internal], {"joern-cli/file": b"x"}),
                             tmp_path / "b", LIMITS)


def test_extraction_rejects_special_and_setuid_members(tmp_path: Path) -> None:
    fifo = tarfile.TarInfo("joern-cli/pipe")
    fifo.type = tarfile.FIFOTYPE
    with pytest.raises(safe_extract.UnsafeArchive, match="special"):
        safe_extract.extract(_tar(tmp_path / "f.tar", [fifo]), tmp_path / "f", LIMITS)
    archive = _zip(tmp_path / "s.zip", [("joern-cli/su", b"x", stat.S_IFREG | stat.S_ISUID | 0o755)])
    with pytest.raises(safe_extract.UnsafeArchive, match="setuid"):
        safe_extract.extract(archive, tmp_path / "s", LIMITS)


@pytest.mark.parametrize("entries", [
    [("joern-cli/a", b"1", None), ("joern-cli/a", b"2", None)],
    [("joern-cli/a/", None, stat.S_IFDIR | 0o755), ("joern-cli/a", b"2", None)],
    [("joern-cli/a", b"file", None), ("joern-cli/a/b", b"nested", None)],
    [("joern-cli/l", b"d", stat.S_IFLNK | 0o777), ("joern-cli/d/", None, stat.S_IFDIR | 0o755),
     ("joern-cli/l/x", b"through-link", None)],
], ids=["duplicate", "dir-and-file", "file-as-parent", "through-symlink"])
def test_extraction_rejects_duplicate_or_conflicting_members(tmp_path: Path, entries) -> None:
    with pytest.warns(UserWarning) if entries[0][0] == entries[1][0] else _no_warning():
        archive = _zip(tmp_path / "dup.zip", entries)
    with pytest.raises(safe_extract.UnsafeArchive):
        safe_extract.extract(archive, tmp_path / "out", LIMITS)


class _no_warning:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_extraction_enforces_member_count_and_expanded_byte_limits(tmp_path: Path) -> None:
    many = _zip(tmp_path / "many.zip", [(f"joern-cli/{index}", b"x", None) for index in range(65)])
    with pytest.raises(safe_extract.UnsafeArchive, match="members"):
        safe_extract.extract(many, tmp_path / "many", LIMITS)
    large = _zip(tmp_path / "large.zip", [("joern-cli/big", bytes(range(256)) * 8193, None)])
    with pytest.raises(safe_extract.UnsafeArchive, match="expanded size"):
        safe_extract.extract(large, tmp_path / "large", LIMITS)


def test_extraction_enforces_compression_ratio_limits(tmp_path: Path) -> None:
    bomb = _zip(tmp_path / "bomb.zip", [("joern-cli/zeros", b"\0" * 500_000, None)])
    with pytest.raises(safe_extract.UnsafeArchive, match="compression ratio"):
        safe_extract.extract(bomb, tmp_path / "bomb", LIMITS)
    tight = safe_extract.Limits(64, 1 << 20, 1e9, 2.0)
    with pytest.raises(safe_extract.UnsafeArchive, match="expansion ratio"):
        safe_extract.validate_members([safe_extract.Member("joern-cli/x", "file", 300)], tight, 100)


def test_extraction_rejects_members_that_exceed_their_declared_size(tmp_path: Path) -> None:
    source = io.BytesIO(b"x" * 10)
    with pytest.raises(safe_extract.UnsafeArchive, match="declared size"):
        safe_extract._write_stream(source, tmp_path / "out", 4, 0o644)


def test_extraction_requires_every_reviewed_closure_prefix(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "partial.zip", [("joern-cli/lib/a.jar", b"x", None)])
    with pytest.raises(safe_extract.UnsafeArchive, match="frontends/c2cpg"):
        safe_extract.extract(archive, tmp_path / "out", LIMITS,
                             ("joern-cli/lib", "joern-cli/frontends/c2cpg"))


def test_helper_cli_reverifies_lock_and_compares_inventory(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "joern-cli-linux-x86_64.zip", [
        ("joern-cli/lib/io.joern.c2cpg-1.jar", _jar("c2cpg", "1"), None),
    ])
    data = archive.read_bytes()
    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps({"artifacts": [{
        "role": "archive", "name": archive.name, "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(), "sha512": hashlib.sha512(data).hexdigest(),
    }]}), encoding="utf-8")
    policy = tmp_path / "tool.toml"
    policy.write_text('[closure]\ninclude = ["joern-cli/lib"]\n'
                      'version_jars = ["joern-cli/lib/io.joern.c2cpg-1.jar"]\nmax_members = 8\n'
                      'max_expanded_bytes = 1048576\nmax_member_compression_ratio = 50.0\n'
                      'max_archive_expansion_ratio = 10.0\n', encoding="utf-8")
    inventory, version = tmp_path / "inventory.json", tmp_path / "VERSION"
    argv = [str(archive), str(tmp_path / "a"), "--policy", str(policy), "--lock", str(lock)]
    assert safe_extract.main(argv + ["--inventory", str(inventory), "--version-file", str(version)]) == 0
    assert version.read_text(encoding="utf-8") == "c2cpg 1\n"
    assert safe_extract.main([str(archive), str(tmp_path / "b"), "--policy", str(policy), "--lock",
                              str(lock), "--expect-inventory", str(inventory)]) == 0
    tampered = json.loads(inventory.read_text(encoding="utf-8"))
    tampered["files"][0]["sha256"] = "0" * 64
    inventory.write_text(json.dumps(tampered), encoding="utf-8")
    assert safe_extract.main([str(archive), str(tmp_path / "c"), "--policy", str(policy), "--lock",
                              str(lock), "--expect-inventory", str(inventory)]) == 2
    wrong = json.loads(lock.read_text(encoding="utf-8"))
    wrong["artifacts"][0]["sha512"] = "0" * 128
    lock.write_text(json.dumps(wrong), encoding="utf-8")
    assert safe_extract.main(argv[:1] + [str(tmp_path / "d")] + argv[2:]) == 2


def _jar(title: str, version: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as jar:
        jar.writestr("META-INF/MANIFEST.MF", f"Manifest-Version: 1.0\nImplementation-Title: {title}\n"
                                             f"Implementation-Version: {version}\n")
    return buffer.getvalue()


# Fetch integrity


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _artifact(payload: bytes, **overrides) -> dict:
    value = {"url": "https://example.invalid/joern.zip", "path": "downloads/joern.zip",
             "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
    value.update(overrides)
    return value


def _opener(payload: bytes, calls: list[str]):
    def opener(request, timeout):
        calls.append(request.full_url)
        return _Response(payload)
    return opener


def test_fetch_accepts_exact_size_and_sha256(tmp_path: Path) -> None:
    payload, calls, log = b"joern-archive-fixture", [], io.StringIO()
    status = container_build.fetch_artifact(_artifact(payload), tmp_path, log, _opener(payload, calls))
    assert status == "fetched" and calls == ["https://example.invalid/joern.zip"]
    assert (tmp_path / "downloads" / "joern.zip").read_bytes() == payload
    assert not list((tmp_path / "downloads").glob("*.partial"))


@pytest.mark.parametrize("served", [b"short", b"joern-archive-fixture-with-extra-bytes"],
                         ids=["truncated", "oversized"])
def test_fetch_rejects_wrong_size_and_removes_partial(tmp_path: Path, served: bytes) -> None:
    artifact = _artifact(b"joern-archive-fixture")
    with pytest.raises(RuntimeError, match="verification failed"):
        container_build.fetch_artifact(artifact, tmp_path, io.StringIO(), _opener(served, []))
    assert list((tmp_path / "downloads").iterdir()) == []


def test_fetch_rejects_wrong_sha256_and_removes_partial(tmp_path: Path) -> None:
    payload = b"joern-archive-fixture"
    artifact = _artifact(payload, sha256="f" * 64)
    with pytest.raises(RuntimeError, match="verification failed"):
        container_build.fetch_artifact(artifact, tmp_path, io.StringIO(), _opener(payload, []))
    assert list((tmp_path / "downloads").iterdir()) == []


def test_fetch_removes_partial_when_the_transfer_fails(tmp_path: Path) -> None:
    class Broken(_Response):
        def read(self, size=-1):
            raise ConnectionResetError("fixture reset")

    with pytest.raises(ConnectionResetError):
        container_build.fetch_artifact(_artifact(b"payload"), tmp_path, io.StringIO(),
                                       lambda request, timeout: Broken(b""))
    assert list((tmp_path / "downloads").iterdir()) == []


def test_fetch_reuses_a_verified_current_file_without_network(tmp_path: Path) -> None:
    payload, log = b"joern-archive-fixture", io.StringIO()
    (tmp_path / "downloads").mkdir()
    (tmp_path / "downloads" / "joern.zip").write_bytes(payload)

    def refuse(request, timeout):
        raise AssertionError("network must not be used for a current artifact")

    assert container_build.fetch_artifact(_artifact(payload), tmp_path, log, refuse) == "current"
    assert log.getvalue().startswith("CURRENT downloads/joern.zip")


def test_fetch_replaces_a_stale_file_of_the_same_size(tmp_path: Path) -> None:
    payload, calls = b"joern-archive-fixture", []
    (tmp_path / "downloads").mkdir()
    (tmp_path / "downloads" / "joern.zip").write_bytes(b"X" * len(payload))
    assert container_build.fetch_artifact(_artifact(payload), tmp_path, io.StringIO(),
                                          _opener(payload, calls)) == "fetched"
    assert calls and (tmp_path / "downloads" / "joern.zip").read_bytes() == payload


def test_fetch_rejects_paths_that_escape_the_context(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        container_build.fetch_artifact(_artifact(b"x", path="../escape.zip"), tmp_path / "ctx",
                                       io.StringIO(), _opener(b"x", []))


# Truthful blocked status


def test_joern_gap_states_runtime_availability_without_claiming_coverage() -> None:
    assert JOERN_GAP.startswith("BLOCKED:")
    assert "tool-joern" in JOERN_GAP and "is available" in JOERN_GAP
    assert "not available in the tool catalog" not in JOERN_GAP
    for pending in ("bounded CPG/PDG export", "source mapping", "functional fixtures",
                    "security acceptance"):
        assert pending in JOERN_GAP
    assert "no CPG coverage is claimed" in JOERN_GAP


def test_joern_branch_publishes_only_a_blocked_zero_observation_shard(tmp_path: Path) -> None:
    from tests.test_language_build import AnalysisExecutor, _accepted_project, _fixture
    from tests.test_language_build import native_language_executor

    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted_project(config, target, [])
    GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: native_language_executor(profile, []))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    outcome = GraphRunner(config, [build_cpp(
        executor_factory=lambda unit: AnalysisExecutor(unit.job.run_root))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    result_path = Path(outcome["jobs"]["job_cpp_compiled_analysis"]["attempt_root"]) / "result.json"
    joern = json.loads(result_path.read_text(encoding="utf-8"))["outputs"]["joern.projects"]
    assert joern["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert joern["project_count"] == 1 and joern["gaps"] == [JOERN_GAP]
    (project,) = joern["projects"].values()
    assert project["observation_count"] == 0
    assert project["terminal_status"] == "COMPLETED_WITH_GAPS" and project["gaps"] == [JOERN_GAP]
    shard = config.runtime.runs_dir / run_id / project["artifact"]["path"]
    with sqlite3.connect(shard) as database:
        coverage = database.execute("SELECT area, status, gap FROM coverage").fetchall()
        statuses = [json.loads(row[0])["status"] for row in
                    database.execute("SELECT payload_json FROM entities").fetchall()]
    assert coverage == [("joern", "unavailable", JOERN_GAP)]
    assert statuses == ["BLOCKED"]
