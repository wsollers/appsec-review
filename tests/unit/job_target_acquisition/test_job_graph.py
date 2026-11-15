"""Graph declarations, validators and pure helpers, without executing a job graph."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
import tomllib

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_target_acquisition import build_job
from appsec_review.jobs.job_target_acquisition import job as acquisition_job
from appsec_review.runtime.launch import SYSTEM_ENVIRONMENT
from tests.unit.job_target_acquisition.support import (
    ACQUISITION, CONFIGURATION, PUBLICATION, SCHEMA, SELECTION, artifact_document,
    frozen_text, unit_context,
)

ROOT = Path(__file__).resolve().parents[3]


def test_job_graph_pins_ids_dependencies_validators_and_identity_transform():
    job = build_job(environ={})
    assert (job.job_id, job.name, job.schema_identity) == (
        "job_target_acquisition", "target_acquisition", SCHEMA,
    )
    assert acquisition_job.TOPOLOGY == {
        "selection": ("resolve_system",),
        "acquisition": ("acquire_components",),
        "publication": ("publish_handoff",),
    }
    assert [(unit.unit_id, unit.dependencies, unit.input_validators, unit.output_validators)
            for unit in job.units] == [
        (SELECTION, (), (), ()),
        (ACQUISITION, (SELECTION,), (), ()),
        (PUBLICATION, (ACQUISITION,), (), ()),
    ]
    assert job.input_validators == (acquisition_job._validate,)
    assert job.output_validators == ()
    assert job.result_transform is None
    result = {"schema": "appsec-review/job-result/1", "units": {"fixture": {"value": 7}}}
    assert job.finalize_result(SimpleNamespace(), result) is result
    assert job.strict_gaps is True
    assert job.always_execute is True and job.propagate_handoff is False


def config_context(*, steps=None, changed_step=None, settings=None):
    topology = acquisition_job.TOPOLOGY
    return SimpleNamespace(config=SimpleNamespace(
        steps=tuple(topology) if steps is None else steps,
        step=lambda name: SimpleNamespace(tasks=("wrong_task",) if name == changed_step else topology[name]),
        settings={} if settings is None else settings,
    ))


def test_validate_accepts_the_shipped_configuration_and_known_settings():
    config = load_config(ROOT / "appsec-review.toml").job("job_target_acquisition")
    acquisition_job._validate(SimpleNamespace(config=config), None)
    acquisition_job._validate(config_context(), None)
    acquisition_job._validate(config_context(settings={"enabled": False}), None)


@pytest.mark.parametrize("steps", [(), ("acquisition", "selection", "publication"),
                                  ("selection", "acquisition", "publication", "extra")],
                         ids=["missing", "reordered", "extra"])
def test_validate_refuses_topology_drift(steps):
    with pytest.raises(ValueError, match="target acquisition topology does not match configuration"):
        acquisition_job._validate(config_context(steps=steps), None)


@pytest.mark.parametrize("step", ["acquisition", "publication", "selection"])
def test_validate_refuses_task_drift_with_step_scope(step):
    with pytest.raises(ValueError, match=f"target acquisition task order mismatch: {step}$"):
        acquisition_job._validate(config_context(changed_step=step), None)


def test_validate_refuses_unknown_settings_in_sorted_order():
    with pytest.raises(ValueError, match=r"jobs\.job_target_acquisition\.settings has unknown keys: alpha, zeta$"):
        acquisition_job._validate(config_context(settings={"zeta": 1, "enabled": True, "alpha": 2}), None)


@pytest.mark.parametrize("value", ["0", "a", "a" * 64, "sys.service_1-2"],
                         ids=["digit", "letter", "max-length", "punctuation"])
def test_requested_system_accepts_exact_safe_ids(value):
    assert acquisition_job.requested_system({SYSTEM_ENVIRONMENT: value}) == value


@pytest.mark.parametrize("value", ["a" * 65, "Sys", "_sys", ".sys", "-sys", "a/b", "a\\b", " sys", "sys\n"],
                         ids=["too-long", "uppercase", "underscore-prefix", "dot-prefix", "dash-prefix",
                              "slash", "backslash", "space", "newline"])
def test_requested_system_refuses_invalid_ids_with_environment_scope(value):
    with pytest.raises(ValueError, match=f"{SYSTEM_ENVIRONMENT} is not a valid system id"):
        acquisition_job.requested_system({SYSTEM_ENVIRONMENT: value})


def test_requested_system_distinguishes_absence_empty_and_explicit_environment(monkeypatch):
    monkeypatch.setenv(SYSTEM_ENVIRONMENT, "host-system")
    assert acquisition_job.requested_system() == "host-system"
    assert acquisition_job.requested_system({}) is None
    assert acquisition_job.requested_system({SYSTEM_ENVIRONMENT: ""}) is None
    assert acquisition_job.requested_system({SYSTEM_ENVIRONMENT: "explicit"}) == "explicit"
    monkeypatch.delenv(SYSTEM_ENVIRONMENT)
    assert acquisition_job.requested_system() is None


def test_settings_reads_only_frozen_bytes_and_hashes_the_exact_configuration(tmp_path):
    frozen = frozen_text(parallel=3) + "# frozen identity includes this comment\n"
    unit, _ = unit_context(tmp_path, SELECTION, frozen=frozen)
    (tmp_path / "appsec-review.toml").write_text("not valid TOML", encoding="utf-8")
    settings, identity = acquisition_job._settings(unit)
    assert settings.targets_dir == "checkouts" and settings.records_dir == "acquisition-records"
    assert settings.max_parallel_components == 3
    assert [item.target_id for item in settings.system("sys").components] == ["service", "library"]
    assert identity == {"path": CONFIGURATION, "sha256": hashlib.sha256(frozen.encode()).hexdigest()}


def test_settings_missing_configuration_retains_the_frozen_path_in_the_error(tmp_path):
    unit, _ = unit_context(tmp_path, SELECTION)
    path = unit.job.run_root / CONFIGURATION
    path.unlink()
    with pytest.raises(FileNotFoundError) as caught:
        acquisition_job._settings(unit)
    assert caught.value.filename == str(path)


@pytest.mark.parametrize(("data", "error", "message"), [
    (b"\xff", UnicodeDecodeError, "utf-8"),
    (b"[target_acquisition", tomllib.TOMLDecodeError, "Expected"),
    (b"[target_acquisition]\nmax_parallel_components = 0\n", ValueError, "max_parallel_components"),
], ids=["encoding", "toml", "bound"])
def test_settings_preserves_typed_configuration_parse_failures(tmp_path, data, error, message):
    unit, _ = unit_context(tmp_path, SELECTION)
    (unit.job.run_root / CONFIGURATION).write_bytes(data)
    with pytest.raises(error, match=message):
        acquisition_job._settings(unit)


def test_settings_uses_defaults_when_the_acquisition_table_is_absent(tmp_path):
    unit, _ = unit_context(tmp_path, SELECTION, frozen="# no acquisition table\n")
    settings, identity = acquisition_job._settings(unit)
    assert settings.systems == () and settings.max_parallel_components == 4
    assert identity["sha256"] == hashlib.sha256(b"# no acquisition table\n").hexdigest()


def test_identity_writes_exact_json_and_returns_a_run_relative_hash_and_size(tmp_path):
    unit, _ = unit_context(tmp_path, SELECTION)
    path = unit.unit_root / "identity.json"
    document = {"schema": SCHEMA, "value": "caf\u00e9", "ordered": [2, 1]}
    identity = acquisition_job._identity(unit, path, document)
    assert identity["path"] == path.relative_to(unit.job.run_root).as_posix()
    assert set(identity) == {"path", "sha256", "size_bytes"}
    assert artifact_document(unit, identity) == document
