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
import subprocess
import sys
import tomllib

import pytest

from appsec_review.container_runtime import load_catalog as load_runtime_catalog
from appsec_review.jobs.job_cpg_analysis import JOERN_GAP


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
safe_extract = _module("joern_safe_extract", ROOT / "containers" / "tools" / "shared" / "safe_extract.py")


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
    assert "COPY --from=shared safe_extract.py /opt/review/" in text
    assert _entry()["build_contexts"] == {"shared": "containers/tools/shared"}


def test_runtime_image_never_executes_target_programs() -> None:
    final_stage = _dockerfile().split("FROM appsec-review/base-jre:21-noble", 1)[1]
    assert re.findall(r"(?m)^RUN\s+(.*)$", final_stage) == [
        '/opt/joern/bin/joern-version | grep -Fx "c2cpg ${TOOL_VERSION}"']
    probe = (CONTEXT / "joern-version").read_text(encoding="utf-8")
    assert "/workspace" not in probe and "/target" not in probe and "/scratch" not in probe
    assert '"$root/joern-cli/frontends/c2cpg/bin/c2cpg" --help' in probe


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


# Truthful blocked status (the job-level shard behaviour is covered in test_cpp_index_jobs.py)


def test_joern_gap_states_cpg_generation_without_claiming_coverage() -> None:
    assert JOERN_GAP.startswith("BLOCKED:")
    assert "tool-joern" in JOERN_GAP and "generated this scope's CPG" in JOERN_GAP
    assert "not available in the tool catalog" not in JOERN_GAP
    for pending in ("bounded CPG/PDG export", "source mapping", "functional fixtures",
                    "security acceptance"):
        assert pending in JOERN_GAP
    assert "no CPG coverage is claimed" in JOERN_GAP


def test_image_supplies_zstd_native_library_without_an_executable_tmp() -> None:
    text = _dockerfile()
    jar = "/opt/joern/joern-cli/lib/com.github.luben.zstd-jni-1.5.7-11.jar"
    assert jar.removeprefix("/opt/joern/") in [item["path"] for item in json.loads(
        (CONTEXT / "inventory.json").read_text(encoding="utf-8"))["files"]]
    assert f"zipfile.ZipFile('{jar}').open('linux/amd64/libzstd-jni-1.5.7-11.so')" in text
    assert 'JAVA_TOOL_OPTIONS="-Djava.library.path=/opt/joern/native"' in text
    # The fix never relocates the JVM temp directory or relaxes the runtime policy's noexec /tmp.
    assert "java.io.tmpdir" not in text and "--tmpfs" not in text
