"""Binary decompilation publications reach a review: intake freezing, indexing and citation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from appsec_review.binary_decompilation import decompile_binary
from appsec_review.config import BinaryDecompilationSettings, BinaryRequest, load_config
from appsec_review.guidance.skills import load_runtime_skill, select_review_procedures
from appsec_review.indexing.input_matrix import INPUT_SOURCES
from appsec_review.jobs.job_binary_evidence_indexing.job import managed_routing
from appsec_review.jobs.job_inference_security_review.job import review_index_names
from appsec_review.jobs.job_inference_security_review.teams import BINARY_ENTITY_PREFIXES
from appsec_review.jobs.job_review_intake.job import BINARY_UNAVAILABLE, resolve_binary_evidence
from appsec_review.retrieval import EntityKind
from appsec_review.runtime.registry import builtin_registry
from tests.binary_decompilation_fakes import FakeDocker, write_export


import pytest

ROOT = Path(__file__).resolve().parents[1]
BINARY = b"\x7fELF synthetic vendor library"
SHA256 = hashlib.sha256(BINARY).hexdigest()
PDB = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS synthetic"
PDB_SHA256 = hashlib.sha256(PDB).hexdigest()


def _binary(tmp_path: Path, payload: bytes = BINARY, name: str = "libvendor.so") -> Path:
    path = tmp_path / "inputs" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def _config(tmp_path: Path, binaries: str = "") -> object:
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    data = (tmp_path / "data").as_posix()
    text = text.replace('data_dir = "data"', f'data_dir = "{data}"', 1)
    assert data in text
    path = tmp_path / "appsec-review.toml"
    path.write_text(text + binaries, encoding="utf-8")
    return load_config(path)


def _table(binary_id: str, path: Path, sha256: str, *, required: bool = False, extra: str = "") -> str:
    return (f'\n[[binary_decompilation.binaries]]\nid = "{binary_id}"\npath = "{path.as_posix()}"\n'
            f'sha256 = "{sha256}"\nauthorization = "owned test input"\nrequired = {str(required).lower()}\n'
            + extra)


def _publish(tmp_path: Path, path: Path, docker: FakeDocker | None = None, **request) -> dict:
    return decompile_binary(repository_root=ROOT, data_dir=tmp_path / "data",
                            settings=BinaryDecompilationSettings(),
                            request=BinaryRequest("vendor", path, hashlib.sha256(path.read_bytes()).hexdigest(),
                                                  "owned test input", **request),
                            runner=docker or FakeDocker())


def _document(config_path: Path) -> dict:
    import tomllib
    return tomllib.loads(config_path.read_text(encoding="utf-8"))


# Intake freezes publications


def test_intake_freezes_each_configured_binary_or_names_why_it_is_absent(tmp_path: Path) -> None:
    published, missing = _binary(tmp_path), _binary(tmp_path, b"\x7fELF never decompiled", "other.so")
    result = _publish(tmp_path, published)
    _config(tmp_path, _table("vendor", published, SHA256)
            + _table("other", missing, hashlib.sha256(missing.read_bytes()).hexdigest()))
    document = _document(tmp_path / "appsec-review.toml")
    frozen = resolve_binary_evidence(document, tmp_path)
    vendor, other = frozen["binaries"]
    assert vendor["status"] == "resolved" and vendor["identity"] == result["identity"]
    assert vendor["manifest_sha256"] == result["manifest_sha256"] and vendor["required"] is False
    assert other["status"] == "unavailable"
    assert [gap["kind"] for gap in frozen["gaps"]] == [BINARY_UNAVAILABLE]
    assert frozen["gaps"][0]["binary_id"] == "other"


def test_a_required_binary_without_a_publication_fails_intake(tmp_path: Path) -> None:
    path = _binary(tmp_path)
    _config(tmp_path, _table("vendor", path, SHA256, required=True))
    with pytest.raises(ValueError, match="required binary vendor has no usable decompilation"):
        resolve_binary_evidence(_document(tmp_path / "appsec-review.toml"), tmp_path)


def test_a_publication_made_for_another_request_is_not_frozen(tmp_path: Path) -> None:
    path = _binary(tmp_path)
    _publish(tmp_path, path, processor="x86:LE:64:default")
    _config(tmp_path, _table("vendor", path, SHA256))
    (entry,) = resolve_binary_evidence(_document(tmp_path / "appsec-review.toml"), tmp_path)["binaries"]
    assert entry["status"] == "unavailable" and "processor" in entry["reason"]


def test_no_configured_binaries_resolve_to_an_empty_record(tmp_path: Path) -> None:
    _config(tmp_path)
    frozen = resolve_binary_evidence(_document(tmp_path / "appsec-review.toml"), tmp_path)
    assert frozen["binaries"] == [] and frozen["gaps"] == []


# PE, debug symbols and managed code


def _pe_export(*, debug_symbols_loaded: bool | None = None, compiler: str = "visualstudio"):
    program = {"executable_format": "Portable Executable (PE)", "compiler": compiler,
               "compiler_spec": "windows"}
    if debug_symbols_loaded is not None:
        program["debug_symbols_loaded"] = debug_symbols_loaded
    return lambda root, sha256: write_export(root, sha256, program=program)


def test_a_pe_without_debug_symbols_indexes_like_any_native_binary(tmp_path: Path) -> None:
    path = _binary(tmp_path, b"MZ synthetic PE", "vendor.dll")
    result = _publish(tmp_path, path, FakeDocker(export=_pe_export()))
    assert result["coverage"]["managed_code"] is False and "debug_symbols_not_applied" not in result["gaps"]


def test_a_pe_with_a_pdb_stages_it_and_records_whether_ghidra_applied_it(tmp_path: Path) -> None:
    path = _binary(tmp_path, b"MZ synthetic PE", "vendor.dll")
    pdb = _binary(tmp_path, PDB, "vendor.pdb")
    docker = FakeDocker(export=_pe_export(debug_symbols_loaded=True))
    applied = _publish(tmp_path, path, docker, debug_symbols_path=pdb, debug_symbols_sha256=PDB_SHA256)
    (run,) = docker.runs
    assert run[run.index("--debug-symbols") + 1] == "/target/vendor.pdb"
    manifest = json.loads((Path(applied["path"]) / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["request"]["debug_symbols_sha256"] == PDB_SHA256
    assert "debug_symbols_not_applied" not in applied["gaps"]

    tmp = tmp_path / "second"
    path2 = _binary(tmp, b"MZ another PE", "vendor.dll")
    pdb2 = _binary(tmp, PDB, "vendor.pdb")
    refused = decompile_binary(repository_root=ROOT, data_dir=tmp / "data", settings=BinaryDecompilationSettings(),
                               request=BinaryRequest("vendor", path2, hashlib.sha256(path2.read_bytes()).hexdigest(),
                                                     "owned test input", debug_symbols_path=pdb2,
                                                     debug_symbols_sha256=PDB_SHA256),
                               runner=FakeDocker(export=_pe_export(debug_symbols_loaded=False)))
    assert refused["gaps"].get("debug_symbols_not_applied") == 1


def test_a_debug_symbol_file_must_match_its_pinned_hash(tmp_path: Path) -> None:
    path = _binary(tmp_path, b"MZ synthetic PE", "vendor.dll")
    pdb = _binary(tmp_path, PDB, "vendor.pdb")
    with pytest.raises(ValueError, match="debug symbols"):
        _publish(tmp_path, path, FakeDocker(export=_pe_export(debug_symbols_loaded=True)),
                 debug_symbols_path=pdb, debug_symbols_sha256="0" * 64)


@pytest.mark.parametrize(("program", "tool"), [
    ({"compiler": "cli", "language": "x86:LE:32:default"}, "ILSpy"),
    ({"compiler": "unknown", "language": "JVM:BE:32:default"}, "jadx or CFR"),
    ({"compiler": "unknown", "language": "Dalvik:LE:32:default"}, "jadx"),
])
def test_managed_routing_names_the_decompiler_for_each_runtime(program: dict, tool: str) -> None:
    routed = managed_routing({"coverage": {"managed_code": True}, "program": program})
    assert routed is not None and tool in routed
    assert managed_routing({"coverage": {"managed_code": False}, "program": program}) is None


# Review wiring


def test_the_job_is_registered_configured_and_scheduled_before_review_data_indexing(tmp_path: Path) -> None:
    from appsec_review.cli import GRAPH_JOB_IDS
    from appsec_review.orchestration.topology import wave1_dependencies

    config = _config(tmp_path)
    registry = builtin_registry()
    assert registry.build("job_binary_evidence_indexing").job_id == "job_binary_evidence_indexing"
    assert list(config.job("job_binary_evidence_indexing").steps) == ["load", "index", "acceptance"]
    assert GRAPH_JOB_IDS.index("job_binary_evidence_indexing") < GRAPH_JOB_IDS.index("job_review_data_indexing")
    dependencies = wave1_dependencies(set(GRAPH_JOB_IDS))
    assert dependencies is not None
    assert dependencies["job_binary_evidence_indexing"] == ("job_target_catalog",)
    order = list(dependencies)
    assert order.index("job_binary_evidence_indexing") < order.index("job_review_data_indexing")
    assert ("binary_decompilation", ("job_binary_evidence_indexing",), "current", (), ("core", "coverage")) in INPUT_SOURCES


def test_binary_shards_attach_the_runtime_skill_and_grant_binary_kinds() -> None:
    plain = select_review_procedures(role="red_team_analyst", task="reachability")
    with_binary = select_review_procedures(role="red_team_analyst", task="reachability", binary_evidence=True)
    assert "binary-evidence" not in plain and with_binary[-1] == "binary-evidence"
    skill = load_runtime_skill(ROOT, "binary-evidence", job_id="job_inference_security_review")
    assert "pseudo-C" in skill.body and "function address" in skill.body
    assert {prefix.split(":")[1] for prefix in BINARY_ENTITY_PREFIXES} == {
        kind.value for kind in (EntityKind.BINARY_FUNCTION, EntityKind.BINARY_CALL_SITE,
                                EntityKind.BINARY_IMPORT, EntityKind.BINARY_STRING)}
    assert review_index_names([{"name": "binary", "producer": {"job": "x"}}, {"name": "analysis"}]) == ("analysis",)
