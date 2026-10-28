"""Media and asset artifacts are never handed to package catalogers, and the skip is recorded."""

from __future__ import annotations

import io
import json
from pathlib import Path
import struct
import tarfile
import zipfile

import pytest

from appsec_review.jobs.job_artifact_security_analysis import (
    build_job, load_accepted_artifact_security_analysis)
from appsec_review.jobs.job_artifact_security_analysis.formats import classify
from appsec_review.media_assets import (
    AMBIGUOUS_SUFFIXES, ASSET_FORMATS, ASSET_FORMATS_BY_SUFFIX, MEDIA_ASSET_FORMATS, AssetCategory,
    AssetFormat, recognize)
from appsec_review.runtime import GraphRunner
from appsec_review.tool_inputs import InputSupport, partition_artifacts, support

from tests import test_artifact_security_analysis as asa_tests


CATALOGERS = ("artifact:tool-syft", "artifact:tool-grype")
ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 64
PE = b"MZ" + b"\0" * 62
WAVEFRONT = b"# Blender export\nmtllib cube.mtl\no Cube\nv 1.0 1.0 -1.0\nv 1.0 -1.0 -1.0\nvn 0 1 0\nf 1//1 2//1 3//1\n"


def _truetype() -> bytes:
    return b"\0\x01\0\0" + struct.pack(">HHHH", 12, 128, 3, 64) + b"\0" * 64


def _zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _targz() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("pkg/PKG-INFO")
        info.size = 4
        archive.addfile(info, io.BytesIO(b"x\n\n\n"))
    return buffer.getvalue()


MEDIA = {
    "flags/usa.png": (b"\x89PNG\r\n\x1a\n" + b"\0" * 32, "image-png"),
    "sound/intro.ogg": (b"OggS\0\x02" + b"\0" * 32, "audio-ogg"),
    "fonts/DejaVu.ttf": (_truetype(), "font-truetype"),
    "models/unit.fbx": (b"Kaydara FBX Binary  \0\x1a\0" + b"\0" * 16, "model-fbx"),
    "models/unit.gltf": (b'{"asset": {"version": "2.0"}, "meshes": []}', "model-gltf"),
    "models/unit.glb": (b"glTF\x02\0\0\0" + b"\0" * 16, "model-gltf-binary"),
    "models/cube.obj": (WAVEFRONT, "model-wavefront-obj"),
    "textures/rock.dds": (b"DDS |\0\0\0" + b"\0" * 16, "texture-dds"),
    "textures/rock.tga": (b"\0\0\x02\0\0\0\0\0" + b"\0" * 16, "texture-targa"),
    # Wrong suffix: the bytes decide.
    "data/sprite.bin": (b"GIF89a" + b"\0" * 16, "image-gif"),
}

SCANNED = {
    "bin/server": (ELF, "elf"),
    "bin/app.exe": (PE, "pe"),
    "obj/main.obj": (ELF, "elf"),                               # ELF object named .obj
    "obj/arm64.obj": (b"\x64\xaa" + b"\0" * 30, "unknown"),     # unrecognized COFF machine: not media
    "dist/pkg.tar.gz": (_targz(), "compressed-archive"),
    "dist/app.zip": (_zip({"README": b"x"}), "zip"),
    "web/package.json": (b'{"name": "x", "version": "1.0.0"}', "unknown"),
    "py/requirements.txt": (b"requests==2.0\n", "unknown"),
    "go/go.mod": (b"module example.com/x\n\ngo 1.22\n", "unknown"),
    "lib/fake.png": (ELF, "elf"),                               # executable named like an image
}


def _classified(tmp_path: Path, name: str, payload: bytes, kind: str = "resource") -> dict:
    path = tmp_path / "store" / name.replace("/", "_")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return classify(path, {"kind": kind}, name=_name(name))


def _name(value: str) -> str:
    return value.rsplit("/", 1)[-1]


@pytest.mark.parametrize("name", sorted(MEDIA))
def test_media_and_asset_artifacts_are_classified_from_bytes_or_unambiguous_suffix(tmp_path: Path, name: str) -> None:
    payload, expected = MEDIA[name]
    classification = _classified(tmp_path, name, payload)
    assert classification["format"] == expected
    assert classification["family"] == "media-asset" and not classification["container"]


@pytest.mark.parametrize("name", sorted(SCANNED))
def test_executables_archives_objects_and_manifests_are_not_media(tmp_path: Path, name: str) -> None:
    payload, expected = SCANNED[name]
    classification = _classified(tmp_path, name, payload)
    assert classification["format"] == expected
    assert classification["format"] not in MEDIA_ASSET_FORMATS


@pytest.mark.parametrize("key", CATALOGERS)
def test_catalogers_skip_media_with_a_recorded_reason_and_scan_everything_else(tmp_path: Path, key: str) -> None:
    items = [(name, _name(name), _classified(tmp_path, name, payload)["format"])
             for name, (payload, _) in {**MEDIA, **SCANNED}.items()]
    partition = partition_artifacts(key, items)
    assert set(partition.supported) == set(SCANNED)
    assert {item.path for item in partition.not_applicable} == set(MEDIA)
    for item in partition.not_applicable:
        record = item.as_dict()
        assert record["disposition"] == "SKIPPED_NA" and record["tool"] == key
        assert record["reason_code"] == "INPUT_FORMAT_UNSUPPORTED"
        assert "media and asset files" in record["reason"] and MEDIA[item.path][1] in record["reason"]


def test_producer_kind_does_not_hide_media_magic_and_suffix_never_overrides_producer_kind(tmp_path: Path) -> None:
    png = b"\x89PNG\r\n\x1a\n" + b"\0" * 16
    assert _classified(tmp_path, "out/icon.png", png, kind="generated-output")["format"] == "image-png"
    assert _classified(tmp_path, "out/tool.png", b"\0" * 32, kind="executable")["format"] == "unrecognized-native"


def test_wavefront_obj_needs_geometry_directives() -> None:
    assert recognize(WAVEFRONT, "cube.obj").format == "model-wavefront-obj"
    assert recognize(b"\x4c\x01\x03\0" + b"\0" * 32, "x.obj") is None
    assert recognize(b"int main(void) { return 0; }\n" * 3, "x.obj") is None


def test_declarations_reject_ambiguous_suffix_fallbacks() -> None:
    assert not set(ASSET_FORMATS_BY_SUFFIX) & AMBIGUOUS_SUFFIXES
    assert {".obj", ".mod", ".ts"} <= AMBIGUOUS_SUFFIXES
    with pytest.raises(ValueError, match="ambiguous suffix"):
        AssetFormat("bogus", AssetCategory.MODEL, suffixes=frozenset({".obj"}))
    assert len(MEDIA_ASSET_FORMATS) == len(ASSET_FORMATS)
    assert {value.category for value in ASSET_FORMATS} == set(AssetCategory)
    with pytest.raises(ValueError, match="excluded formats"):
        InputSupport("x", "y", suffixes=frozenset({".c"}), excluded_formats=frozenset({"image-png"}))


def test_media_exclusion_applies_to_package_catalogers_only() -> None:
    for key in CATALOGERS:
        assert support(key).excluded_formats == MEDIA_ASSET_FORMATS
    # Format- and name-declared artifact tools already accept no media format.
    for key in ("artifact:tool-blint", "artifact:tool-spotbugs"):
        assert not support(key).formats & MEDIA_ASSET_FORMATS
    assert not partition_artifacts("artifact:tool-osv-scanner", [("a", "usa.png", "image-png")]).supported


def test_job_never_launches_catalogers_on_media_and_records_each_artifact(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = asa_tests._fixture(
        tmp_path, payload=MEDIA["flags/usa.png"][0], name="usa.png", kind="resource")
    calls: list[str] = []

    def scanner(capability, path, artifact, timeout, limit):
        calls.append(capability)
        raise AssertionError(f"{capability} launched on a media artifact")

    GraphRunner(config, [build_job(scanner_runner=scanner)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert calls == []
    accepted = load_accepted_artifact_security_analysis(run_root)
    for capability in ("syft", "grype"):
        result = accepted["capabilities"][capability]
        # On some hosts the fixture lacks a delivery fact; that named scope gap is unrelated here.
        assert result["observation_count"] == 0
        assert all("delivery status is unknown" in gap for gap in result["gaps"]), result["gaps"]
        assert result["terminal_status"] == ("COMPLETED_WITH_GAPS" if result["gaps"] else "NOT_APPLICABLE")
        summary = result["not_applicable_inputs"]
        assert summary["count"] == 1 and summary["items"][0]["reason_code"] == "INPUT_FORMAT_UNSUPPORTED"
        [row] = result["scope_dispositions"]
        assert row["format"] == "image-png" and row["input_disposition"] == "SKIPPED_NA"
        assert row["input_reason_code"] == "INPUT_FORMAT_UNSUPPORTED"
        assert "media and asset files" in row["input_reason"]
    assert json.dumps(accepted)  # published document stays serializable
