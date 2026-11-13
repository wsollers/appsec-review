"""job_debug_symbol_indexing: the unit graph, the configuration validator, the reader identity
that binds the decision to the injected or production reader, and the hash-bound reference
helpers every handler relies on."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.debug_symbols.contract import JOB_ID
from appsec_review.jobs.job_debug_symbol_indexing.job import (
    _TOPOLOGY, READER_IDENTITY, SCHEMA, FrameworkIntegrityError, _digest, _reader_identity, _ref, _validate_config,
    _verify, build_job,
)
from appsec_review.retrieval.model import canonical_json
from appsec_review.runtime import active_job_ids, job_is_enabled
from appsec_review.runtime.registry import builtin_registry
from tests.unit.job_debug_symbol_indexing.support import extractor

ROOT = Path(__file__).resolve().parents[3]


# --- graph shape -----------------------------------------------------------------------------------

def test_graph_is_a_decision_fanning_out_to_two_lanes_joined_by_publication() -> None:
    job = build_job()
    units = {unit.unit_id: unit for unit in job.units}
    assert {unit_id: unit.dependencies for unit_id, unit in units.items()} == {
        "decide.target": (), "extract.clang_dwarf": ("decide.target",), "extract.msvc_pdb": ("decide.target",),
        "acceptance.publish_handoff": ("extract.clang_dwarf", "extract.msvc_pdb")}
    assert all(unit.input_validators == () and unit.output_validators == () for unit in units.values())
    assert _TOPOLOGY == {"decide": ("target",), "extract": ("clang_dwarf", "msvc_pdb"), "acceptance": ("publish_handoff",)}
    assert job.input_validators == (_validate_config,) and job.output_validators == ()
    assert (job.job_id, job.name, job.schema_identity) == (JOB_ID, "debug_symbol_indexing", SCHEMA)
    assert job.implementation_identity is None and job.validation_identity is None
    assert job.result_transform is None and job.input_identity is None and job.external_input_identity is None


def test_production_job_probes_the_run_frozen_execution_plan_and_an_injected_reader_does_not() -> None:
    assert callable(build_job().run_input_identity)
    assert build_job(extractor=extractor()).run_input_identity is None


@pytest.mark.parametrize("target", ("clang", "msvc"))
def test_the_shipped_configuration_registers_both_targets_and_enables_the_job(target, monkeypatch) -> None:
    monkeypatch.delenv("APPSEC_REVIEW_CONFIG_OVERLAY", raising=False)
    from appsec_review.cli import GRAPH_JOB_IDS
    config = load_config(ROOT / "appsec-review.toml", profile="dev", compiler_target=target)
    job = builtin_registry().build(JOB_ID)
    assert job.name == config.job(JOB_ID).name
    assert config.job(JOB_ID).settings["compiler_target"] == target
    assert config.job(JOB_ID).settings["enabled"] is True
    assert job_is_enabled(config, JOB_ID)
    assert JOB_ID in active_job_ids(config, GRAPH_JOB_IDS)
    assert tuple(config.job(JOB_ID).steps) == tuple(_TOPOLOGY)
    _validate_config(SimpleNamespace(config=config.job(JOB_ID)), None)


# --- _validate_config --------------------------------------------------------------------------------

def _job_config(steps: dict[str, tuple[str, ...]], settings: dict[str, object]) -> SimpleNamespace:
    configured = {step: SimpleNamespace(tasks={task: None for task in tasks}) for step, tasks in steps.items()}
    return SimpleNamespace(config=SimpleNamespace(steps=configured, settings=settings, step=lambda name: configured[name]))


def test_validation_refuses_a_changed_topology_task_set_or_invalid_settings() -> None:
    good = dict(_TOPOLOGY)
    _validate_config(_job_config(good, {"compiler_target": "msvc"}), None)
    with pytest.raises(ValueError, match="topology differs"):
        _validate_config(_job_config({"extract": good["extract"], "decide": good["decide"],
                                      "acceptance": good["acceptance"]}, {}), None)
    with pytest.raises(ValueError, match="topology differs"):
        _validate_config(_job_config({**good, "extra": ("x",)}, {}), None)
    with pytest.raises(ValueError, match="tasks differ"):
        _validate_config(_job_config({**good, "extract": ("msvc_pdb", "clang_dwarf")}, {}), None)
    with pytest.raises(ValueError, match="tasks differ"):
        _validate_config(_job_config({**good, "acceptance": ("publish_handoff", "extra")}, {}), None)
    with pytest.raises(ValueError, match="unknown debug-symbol settings"):
        _validate_config(_job_config(good, {"unknown": 1}), None)
    with pytest.raises(ValueError, match="clang or msvc"):
        _validate_config(_job_config(good, {"compiler_target": "gcc"}), None)


# --- reader identity ---------------------------------------------------------------------------------

def test_reader_identity_binds_the_production_contract_or_the_injected_reader_source() -> None:
    assert _reader_identity(None) == _digest({"contract": READER_IDENTITY})
    assert READER_IDENTITY == "appsec-review/offline-debug-symbol-readers/3"
    first, second = extractor(), extractor()
    assert _reader_identity(first) == _reader_identity(second), "same source, same identity"

    def other(binary, debug_file, *, target, settings):
        return None

    assert _reader_identity(other) != _reader_identity(first) != _reader_identity(None)
    assert len(_reader_identity(other)) == 64


def test_reader_identity_without_source_falls_back_to_the_type_name() -> None:
    class Reader:
        def __call__(self, *args, **kwargs):
            return None

    reader = Reader()
    expected = _digest({"module": Reader.__module__, "name": "", "implementation": Reader.__qualname__})
    assert Reader.__qualname__.endswith("<locals>.Reader")
    assert _reader_identity(reader) == expected
    assert _reader_identity(reader) != _reader_identity(None)


# --- hash-bound references ---------------------------------------------------------------------------

def test_digest_is_the_sha256_of_canonical_json() -> None:
    import hashlib
    assert _digest({"b": 1, "a": [2, 3]}) == hashlib.sha256(canonical_json({"a": [2, 3], "b": 1})).hexdigest()
    assert _digest({"a": 1}) != _digest({"a": 2})


def test_verify_accepts_an_exact_reference_and_names_every_integrity_failure(tmp_path: Path) -> None:
    path = tmp_path / "data" / "file.bin"
    path.parent.mkdir()
    path.write_bytes(b"fixture bytes")
    reference = _ref(tmp_path, path)
    assert reference == {"path": "data/file.bin", "sha256": reference["sha256"], "size_bytes": 13}
    assert _verify(tmp_path, reference, "fixture") == path
    assert _verify(tmp_path, reference, "fixture", maximum=13) == path
    for broken in ({**reference, "sha256": "0" * 64}, {**reference, "size_bytes": 1},
                   {**reference, "path": "data/missing.bin"}, {**reference, "path": "../outside"},
                   {"path": "data/file.bin"}, {**reference, "path": None}):
        with pytest.raises(FrameworkIntegrityError, match="fixture integrity verification failed"):
            _verify(tmp_path, broken, "fixture")
    with pytest.raises(FrameworkIntegrityError, match="fixture integrity verification failed"):
        _verify(tmp_path, reference, "fixture", maximum=12)
    (tmp_path / "data" / "dir").mkdir()
    with pytest.raises(FrameworkIntegrityError):
        _verify(tmp_path, {"path": "data/dir", "sha256": "0" * 64, "size_bytes": 0}, "fixture")
