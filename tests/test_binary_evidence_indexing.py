"""Binary decompilation publications reach a review: intake freezing, indexing and citation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.binary_decompilation import decompile_binary
from appsec_review.config import BinaryDecompilationSettings, BinaryRequest, load_config
from appsec_review.guidance.skills import load_runtime_skill, select_review_procedures
from appsec_review.indexing.input_matrix import INPUT_SOURCES
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_binary_evidence_indexing import build_job as build_binary
from appsec_review.jobs.job_binary_evidence_indexing.job import managed_routing
from appsec_review.jobs.job_inference_security_review.job import review_index_names
from appsec_review.jobs.job_inference_security_review.teams import BINARY_ENTITY_PREFIXES
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_review_intake.job import BINARY_UNAVAILABLE, resolve_binary_evidence
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.retrieval import EntityKind, RetrievalCore
from appsec_review.review.evidence import BINARY_CITATION_GAP, binary_anchor, resolve_relation
from appsec_review.review.models import EvidenceRelation, Gap, Predicate, RelationKind
from appsec_review.runtime import GraphRunner
from appsec_review.runtime.registry import builtin_registry
from tests.binary_decompilation_fakes import FakeDocker, write_export


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


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    return target


def _review(config, target: Path) -> tuple[dict, Path]:
    outcome = GraphRunner(config, [build_intake(), build_catalog(), build_binary()]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    return outcome, config.runtime.runs_dir / outcome["run_id"]


def _outputs(outcome, job_id: str) -> dict:
    path = Path(outcome["jobs"][job_id]["attempt_root"]) / "result.json"
    return json.loads(path.read_text(encoding="utf-8"))["outputs"]


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


# Indexing


def test_a_review_indexes_the_frozen_publication_and_cites_pseudo_c_lines(tmp_path: Path) -> None:
    path = _binary(tmp_path)
    _publish(tmp_path, path)
    config = _config(tmp_path, _table("vendor", path, SHA256))
    outcome, run_root = _review(config, _target(tmp_path))
    assert outcome["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    published = _outputs(outcome, "job_binary_evidence_indexing")["acceptance.publish_handoff"]
    assert published["counts"] == {"functions": 3, "located_functions": 2, "call_sites": 3,
                                   "located_call_sites": 2, "imports": 2, "strings": 2,
                                   "relations": published["counts"]["relations"]}
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    function = core.find(kind=EntityKind.BINARY_FUNCTION.value, name="print_label", indexes=("binary",))["results"]
    assert len(function) == 1
    assert binary_anchor(function[0]) == (SHA256, "0x1011b0", 1, 6)
    assert function[0]["location"]["path"] == f"@binary/{SHA256}/0x1011b0.c"
    excerpt = core.read_excerpt(identity=function[0]["identity"], context_lines=0)["results"][0]
    assert "strcpy(label,input);" in excerpt["excerpt"]

    sites = core.find(kind=EntityKind.BINARY_CALL_SITE.value, indexes=("binary",), limit=10)["results"]
    strcpy_site = next(site for site in sites if site["payload"]["call_site"] == "0x1011c4")
    assert strcpy_site["payload"]["callee_name"] == "strcpy" and strcpy_site["payload"]["line_match"] == "unique"
    assert binary_anchor(strcpy_site) == (SHA256, "0x1011b0", 5, 5)
    line = core.read_excerpt(identity=strcpy_site["identity"], context_lines=0)["results"][0]["excerpt"]
    assert line.strip() == "strcpy(label,input);"

    with sqlite3.connect(run_root / next(
            item for item in json.loads((run_root / published["index_manifest"]["path"]).read_text())["indexes"]
            if item.get("producer", {}).get("binary_id") == "vendor")["relative_path"]) as database:
        relations = database.execute("select kind, count(*) from relations group by kind").fetchall()
    kinds = dict(relations)
    # Every call site resolves: two to the strcpy import (directly and through its thunk), one to print_label.
    assert kinds == {"CALLS": 6, "CONTAINS": 3, "REFERENCES": 3}

    relation = resolve_relation(core, claim_id="claim-" + "c" * 64, predicate=Predicate.AFFECTED_CONSTRUCT,
                                kind=RelationKind.SUPPORTS, entity_id=strcpy_site["identity"],
                                producing_cell_id="cell-" + "d" * 64, retrieval_receipt_sha256="e" * 64)
    assert isinstance(relation, EvidenceRelation)
    for kind in (EntityKind.BINARY_IMPORT, EntityKind.BINARY_STRING):
        entity = core.find(kind=kind.value, indexes=("binary",), limit=1)["results"][0]
        cited = resolve_relation(core, claim_id="claim-" + "c" * 64, predicate=Predicate.AFFECTED_CONSTRUCT,
                                 kind=RelationKind.SUPPORTS, entity_id=entity["identity"],
                                 producing_cell_id="cell-" + "d" * 64, retrieval_receipt_sha256="e" * 64)
        assert isinstance(cited, Gap) and cited.reason == BINARY_CITATION_GAP

    manifest = json.loads((run_root / published["index_manifest"]["path"]).read_text(encoding="utf-8"))
    assert "binary" in review_index_names(manifest["indexes"])


def test_without_configured_binaries_the_job_is_not_applicable_and_grants_nothing(tmp_path: Path) -> None:
    config = _config(tmp_path)
    outcome, run_root = _review(config, _target(tmp_path))
    published = _outputs(outcome, "job_binary_evidence_indexing")["acceptance.publish_handoff"]
    assert published["terminal_status"] == "NOT_APPLICABLE" and published["counts"]["functions"] == 0
    manifest = json.loads((run_root / published["index_manifest"]["path"]).read_text(encoding="utf-8"))
    assert any(item["name"] == "binary" for item in manifest["indexes"])
    assert "binary" not in review_index_names(manifest["indexes"])


def test_an_unavailable_binary_is_a_named_coverage_gap(tmp_path: Path) -> None:
    path = _binary(tmp_path)
    config = _config(tmp_path, _table("vendor", path, SHA256))
    outcome, _ = _review(config, _target(tmp_path))
    published = _outputs(outcome, "job_binary_evidence_indexing")["acceptance.publish_handoff"]
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any(gap.startswith("vendor: binary_decompilation_unavailable") for gap in published["gaps"])


def test_a_publication_changed_after_intake_froze_it_is_refused(tmp_path: Path) -> None:
    path = _binary(tmp_path)
    result = _publish(tmp_path, path)
    config = _config(tmp_path, _table("vendor", path, SHA256))
    target = _target(tmp_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog()]).run(
        target_root=target, source_fingerprint=fingerprint)
    pseudo_c = Path(result["path"]) / "pseudo-c" / "0x1011b0.c"
    pseudo_c.chmod(0o644)
    pseudo_c.write_text("void print_label(void) {}\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="function file does not match its row"):
        GraphRunner(config, [build_binary()]).run(target_root=target, source_fingerprint=fingerprint,
                                                  run_id=upstream["run_id"])


def test_bounds_truncate_into_named_gaps(tmp_path: Path) -> None:
    path = _binary(tmp_path)
    _publish(tmp_path, path)
    config = _config(tmp_path, _table("vendor", path, SHA256))
    text = (tmp_path / "appsec-review.toml").read_text(encoding="utf-8")
    text = text.replace("max_functions_per_binary = 200000", "max_functions_per_binary = 2", 1)
    text = text.replace("max_strings_per_binary = 200000", "max_strings_per_binary = 1", 1)
    (tmp_path / "appsec-review.toml").write_text(text, encoding="utf-8")
    config = load_config(tmp_path / "appsec-review.toml")
    outcome, _ = _review(config, _target(tmp_path))
    published = _outputs(outcome, "job_binary_evidence_indexing")["acceptance.publish_handoff"]
    assert published["counts"]["functions"] == 2 and published["counts"]["strings"] == 1
    assert "vendor: functions_truncated: indexed 2 of 3" in published["gaps"]
    assert "vendor: strings_truncated: indexed 1 of 2" in published["gaps"]


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


def test_managed_code_is_routed_and_not_located_as_evidence(tmp_path: Path) -> None:
    path = _binary(tmp_path, b"MZ synthetic .NET assembly", "vendor.dll")
    _publish(tmp_path, path, FakeDocker(export=_pe_export(compiler="cli")))
    config = _config(tmp_path, _table("vendor", path, hashlib.sha256(path.read_bytes()).hexdigest()))
    outcome, _ = _review(config, _target(tmp_path))
    published = _outputs(outcome, "job_binary_evidence_indexing")["acceptance.publish_handoff"]
    assert published["counts"]["functions"] == 3 and published["counts"]["located_functions"] == 0
    assert any("managed_code" in gap and "ILSpy" in gap for gap in published["gaps"])
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    function = core.find(kind=EntityKind.BINARY_FUNCTION.value, name="main", indexes=("binary",))["results"][0]
    assert function.get("location") is None and binary_anchor(function) is None


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
