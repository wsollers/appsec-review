from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
from typing import Any, Callable, Mapping

from appsec_review.jobs.job_third_party_data_sync.publication import publish_snapshot, require_beneath, verify_current
from appsec_review.storage import file_sha256


@dataclass(frozen=True, slots=True)
class CveBinToolSettings:
    feed_root: Path
    image: str
    tool_version: str
    build_context: Path
    build_timeout_seconds: int
    run_timeout_seconds: int

    @classmethod
    def from_mapping(cls, root: Path, value: Mapping[str, Any]) -> "CveBinToolSettings":
        feed = Path(str(value.get("feed_root", "")))
        context = Path(str(value.get("build_context", "")))
        if not str(feed) or not str(context):
            raise ValueError("cve-bin-tool feed_root and build_context are required")
        settings = cls(
            feed_root=(root / feed).resolve() if not feed.is_absolute() else feed.resolve(),
            image=str(value.get("image", "")),
            tool_version=str(value.get("tool_version", "")),
            build_context=(root / context).resolve() if not context.is_absolute() else context.resolve(),
            build_timeout_seconds=int(value.get("build_timeout_seconds", 1800)),
            run_timeout_seconds=int(value.get("run_timeout_seconds", 3600)),
        )
        if not settings.image or not settings.tool_version or min(settings.build_timeout_seconds, settings.run_timeout_seconds) < 1:
            raise ValueError("cve-bin-tool image, version, and positive timeouts are required")
        if not (settings.build_context / "Dockerfile").is_file() or not (settings.build_context / "build_db.py").is_file():
            raise ValueError("cve-bin-tool build context is incomplete")
        return settings


def resolve_nvd_snapshot(nvd_root: Path, expected_pointer: Mapping[str, Any]) -> dict[str, Any]:
    pointer = json.loads((nvd_root / "current.json").read_text(encoding="utf-8"))
    for field in ("snapshot_id", "manifest_sha256"):
        if pointer.get(field) != expected_pointer.get(field):
            raise ValueError("NVD current pointer changed after this execution bound it")
    snapshot_id = pointer["snapshot_id"]
    layers: list[dict[str, Any]] = []
    chain: list[str] = []
    while snapshot_id:
        if snapshot_id in chain:
            raise ValueError("NVD snapshot chain contains a cycle")
        chain.append(snapshot_id)
        manifest_path = require_beneath(nvd_root, nvd_root / "snapshots" / snapshot_id / "manifest.json", "NVD manifest")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("snapshot_id") != snapshot_id:
            raise ValueError("NVD snapshot manifest identity mismatch")
        if snapshot_id == pointer["snapshot_id"] and file_sha256(manifest_path) != pointer["manifest_sha256"]:
            raise ValueError("NVD bound manifest hash mismatch")
        snapshot_layers = []
        for layer in manifest.get("layers", []):
            for item in layer.get("pages", [layer]):
                blob = item["raw_blob"]
                path = require_beneath(nvd_root, nvd_root / blob["path"], "NVD raw blob")
                if not path.is_file() or path.stat().st_size != blob["size_bytes"] or file_sha256(path) != blob["sha256"]:
                    raise ValueError("NVD raw blob integrity mismatch")
                snapshot_layers.append({"path": str(path), "sha256": blob["sha256"], "size_bytes": blob["size_bytes"]})
        layers[0:0] = snapshot_layers
        snapshot_id = manifest.get("parent_snapshot_id")
    if not layers:
        raise ValueError("NVD snapshot has no replayable layers")
    return {"schema": "appsec-review/resolved-nvd-snapshot/1", "snapshot_id": pointer["snapshot_id"],
            "manifest_sha256": pointer["manifest_sha256"], "chain_snapshot_ids": chain,
            "layers": layers, "layer_count": len(layers)}


def _docker_builder(settings: CveBinToolSettings, input_dir: Path, output_dir: Path) -> dict[str, str]:
    inspect = subprocess.run(["docker", "image", "inspect", settings.image, "--format", "{{.Id}}"],
                             stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding="utf-8",
                             errors="replace", check=False)
    if inspect.returncode != 0:
        built = subprocess.run(["docker", "build", "--tag", settings.image, str(settings.build_context)],
                               stdin=subprocess.DEVNULL, capture_output=True, text=True,
                               encoding="utf-8", errors="replace",
                               timeout=settings.build_timeout_seconds, check=False)
        if built.returncode != 0:
            raise RuntimeError(f"cve-bin-tool image build failed: {built.stderr[-4000:]}")
        inspect = subprocess.run(["docker", "image", "inspect", settings.image, "--format", "{{.Id}}"],
                                 stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding="utf-8",
                                 errors="replace", check=True)
    image_id = inspect.stdout.strip()
    command = [
        "docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "128", "--user", "65532:65532",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m", "-v", f"{input_dir.resolve()}:/input:ro",
        "-v", f"{output_dir.resolve()}:/output:rw", "--entrypoint", "python", settings.image,
        "/opt/builder/build_db.py", "/input", "/output",
    ]
    completed = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                               encoding="utf-8", errors="replace",
                               timeout=settings.run_timeout_seconds, check=False)
    (output_dir / "builder.stderr.txt").write_text(completed.stderr[-1_000_000:], encoding="utf-8")
    if completed.returncode != 0:
        raise RuntimeError(f"cve-bin-tool database build failed with exit {completed.returncode}")
    return {"image": settings.image, "image_id": image_id, "tool_version": settings.tool_version}


def _check(directory: Path, tool_version: str) -> dict[str, Any]:
    build_record = json.loads((directory / "build.json").read_text(encoding="utf-8"))
    if build_record.get("tool_version") != tool_version or build_record.get("sources") != ["NVD"]:
        raise ValueError("cve-bin-tool build record does not match the configured tool")
    with sqlite3.connect(f"file:{directory / 'cve.db'}?mode=ro&immutable=1", uri=True) as connection:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("cve-bin-tool cve.db quick_check failed")
        count = connection.execute("SELECT COUNT(*) FROM cve_severity WHERE data_source = 'NVD'").fetchone()[0]
        others = connection.execute("SELECT COUNT(*) FROM cve_severity WHERE data_source != 'NVD'").fetchone()[0]
    with sqlite3.connect(f"file:{directory / 'version_map.db'}?mode=ro&immutable=1", uri=True) as connection:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("cve-bin-tool version_map.db quick_check failed")
    if count < 1 or others or count != build_record.get("cve_count"):
        raise ValueError("cve-bin-tool database is empty or contains an unexpected data source")
    return {"cve_count": count, "range_count": build_record.get("range_count"),
            "layer_records": build_record.get("layer_records")}


def build(settings: CveBinToolSettings, resolved: Mapping[str, Any], work: Path,
          runner: Callable[[CveBinToolSettings, Path, Path], Mapping[str, str]] | None = None) -> dict[str, Any]:
    input_dir = work / "input" / "layers"
    output_dir = work / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    for index, layer in enumerate(resolved["layers"]):
        source = Path(layer["path"])
        target = input_dir / f"{index:06d}.json.gz"
        shutil.copyfile(source, target)
        if target.stat().st_size != layer["size_bytes"] or file_sha256(target) != layer["sha256"]:
            raise ValueError("NVD layer changed while staging cve-bin-tool input")
    tool = dict((runner or _docker_builder)(settings, input_dir.parent, output_dir))
    facts = _check(output_dir, settings.tool_version)
    return {"schema": "appsec-review/cve-bin-tool-build/1", "directory": str(output_dir),
            "nvd_snapshot_id": resolved["snapshot_id"], "nvd_manifest_sha256": resolved["manifest_sha256"],
            "tool": tool, **facts}


def publish(settings: CveBinToolSettings, built: Mapping[str, Any]) -> dict[str, Any]:
    directory = Path(built["directory"])
    files = {name: directory / name for name in ("cve.db", "version_map.db", "build.json")}
    return publish_snapshot(settings.feed_root, feed_id="cve-bin-tool",
                            schema="appsec-review/cve-bin-tool-snapshot/1", files=files,
                            manifest_fields={key: built[key] for key in
                                             ("nvd_snapshot_id", "nvd_manifest_sha256", "tool", "cve_count",
                                              "range_count", "layer_records")})


def verify(settings: CveBinToolSettings, expected_nvd: Mapping[str, Any]) -> dict[str, Any]:
    identity = verify_current(settings.feed_root, "cve-bin-tool")
    directory = Path(identity["directory"])
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if (manifest.get("nvd_snapshot_id"), manifest.get("nvd_manifest_sha256")) != (
        expected_nvd.get("snapshot_id"), expected_nvd.get("manifest_sha256")
    ):
        raise ValueError("cve-bin-tool database was not built from this execution's NVD snapshot")
    return {**identity, **_check(directory, settings.tool_version), "nvd_snapshot_id": manifest["nvd_snapshot_id"]}
