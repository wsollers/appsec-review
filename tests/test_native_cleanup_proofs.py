"""Fake process/custody controls, real retired-scope matching; no host operations."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from appsec_review.container_runtime import engine_broker as engine
from appsec_review.runtime.resources import ResourceAdmission
from appsec_review.storage import atomic_json
from tests.test_bounded_image_build_service import forbid_real_execution  # noqa: F401
from tests.test_native_engine_broker import native  # noqa: F401


@pytest.fixture
def absence(native, tmp_path, monkeypatch):
    containers = tmp_path / "private-docker" / "containers"
    containers.mkdir(parents=True)
    config = SimpleNamespace(**{
        **vars(native.config),
        "docker_helper_scope": SimpleNamespace(data_root=str(containers.parent)),
    })
    monkeypatch.setattr(engine, "service_contract", lambda value: {"release": "fixed"})
    state = {"records": [], "owners": 0, "live": None, "custody": []}
    monkeypatch.setattr(engine, "_operator_records", lambda value: (state["records"], state["owners"]))
    monkeypatch.setattr(engine, "process_token", lambda pid: state["live"])
    monkeypatch.setattr(engine, "private_path", lambda path: state["custody"].append(path))
    grant = config.native_engine.grants[0]
    scope = {key: getattr(grant, key) for key in (
        "tenant_id", "project_id", "run_id", "target_snapshot", "configuration_id")}
    scope.update({key: getattr(config.native_engine, key) for key in (
        "service_generation", "engine_id", "engine_generation")})
    scope.update(lease_id="a" * 32, resource_budget=config.resources.view())
    entry = {
        "pid": 4321, "process_identity": "old-generation", "owner_finished": True,
        "containers": ["appsec-" + "c" * 20], "container_cleanup": "removed",
        "native_engine_scope": scope, "quarantine": "container_death_unconfirmed",
        "limits": {key: getattr(config.resources, key) for key in ("cpu", "memory_mb", "io_slots")},
    }
    return config, containers, entry, state


def test_rejected_create_reconciles_only_after_proved_retirement(absence):
    config, containers, entry, state = absence
    live = engine.EngineCleanupConfirmation(config)
    assert not live.lease_matches(entry)
    assert not live.confirmed_removed(entry["containers"][0])
    assert not state["custody"]
    retired = engine.EngineCleanupConfirmation(config, retired=True)
    assert state["custody"] == [containers]
    assert retired.lease_matches(entry)
    assert retired.confirmed_removed(entry["containers"][0])
    assert retired.confirmed_cleanup(entry)


@pytest.mark.parametrize("change", ["container", "owner", "unresolved", "accepted-name", "live-client",
                                   "persistent", "builder", "stopped-only", "budget", "limits",
                                   "foreign-name", "empty-names", "invalid-pid", "invalid-lease",
                                   "extra-scope", "quarantine", "no-private-engine"])
def test_retired_absence_never_substitutes_for_missing_custody(absence, change):
    config, containers, original, state = absence
    entry = deepcopy(original)
    if change == "container":
        (containers / ("d" * 64)).mkdir()
    elif change == "owner":
        state["owners"] = 1
    elif change in {"unresolved", "accepted-name"}:
        state["records"] = [{
            "payload": {"name": entry["containers"][0]},
            "state": "CREATING" if change == "unresolved" else "REMOVED",
            "binding": {}, "peer": {}, "execution_id": "e" * 32, "execution_token": "f" * 32,
        }]
    elif change == "live-client":
        state["live"] = entry["process_identity"]
    elif change == "persistent":
        entry["persistent"] = {"other": True}
    elif change == "builder":
        entry["builds"] = [{}]
    elif change == "stopped-only":
        entry["container_cleanup"] = "stopped"
    elif change == "budget":
        entry["native_engine_scope"]["resource_budget"]["cpu"] += 1
    elif change == "limits":
        entry["limits"]["memory_mb"] += 1
    elif change == "foreign-name":
        entry["containers"] = ["foreign"]
    elif change == "empty-names":
        entry["containers"] = []
    elif change == "invalid-pid":
        entry["pid"] = True
    elif change == "invalid-lease":
        entry["native_engine_scope"]["lease_id"] = "invalid"
    elif change == "extra-scope":
        entry["native_engine_scope"]["foreign"] = "value"
    elif change == "quarantine":
        entry["quarantine"] = "unrelated_failure"
    elif change == "no-private-engine":
        config.docker_helper_scope = None
    proof = engine.EngineCleanupConfirmation(config, retired=True)
    assert not proof.confirmed_cleanup(entry)


@pytest.mark.parametrize("field", [
    "tenant_id", "project_id", "run_id", "target_snapshot", "configuration_id",
    "service_generation", "engine_id", "engine_generation",
])
def test_retired_absence_requires_exact_frozen_scope(absence, field):
    config, _, entry, _ = absence
    entry["native_engine_scope"][field] = "foreign"
    assert not engine.EngineCleanupConfirmation(config, retired=True).confirmed_cleanup(entry)


def test_reused_pid_does_not_keep_dead_client_generation_alive(absence):
    config, _, entry, state = absence
    state["live"] = "unrelated-new-generation"
    assert engine.EngineCleanupConfirmation(config, retired=True).confirmed_cleanup(entry)


def test_private_storage_custody_failure_is_not_an_empty_proof(absence, monkeypatch):
    config, _, _, _ = absence

    def deny(path):
        raise PermissionError("private storage custody changed")

    monkeypatch.setattr(engine, "private_path", deny)
    with pytest.raises(PermissionError, match="custody"):
        engine.EngineCleanupConfirmation(config, retired=True)


def test_real_ledger_keeps_quarantine_until_terminal_absence_and_preserves_other_leases(
        absence, native):
    config, _, entry, _ = absence
    admission = ResourceAdmission(native.context.metadata_root, config.resources)
    path = admission.root / "leases.json"
    state = json.loads(path.read_text())
    existing = deepcopy(state["leases"])
    state["leases"][entry["native_engine_scope"]["lease_id"]] = entry
    atomic_json(path, state)
    for retired in (False, True):
        proof = engine.EngineCleanupConfirmation(config, retired=retired)
        removed = admission.reconcile(
            lambda name: False, confirmed_removed=proof.confirmed_removed,
            confirmed_cleanup=proof.confirmed_cleanup, lease_filter=proof.lease_matches)
        assert removed == ([entry["native_engine_scope"]["lease_id"]] if retired else [])
    assert json.loads(path.read_text())["leases"] == existing


def test_lifetime_reconciliation_never_enables_absence_before_release(native, monkeypatch):
    enabled = []

    def confirmation(config, *, retired=False):
        enabled.append(retired)
        return SimpleNamespace(
            records={}, lease_matches=lambda entry: False, confirmed_removed=lambda name: False,
            confirmed_cleanup=lambda entry: False)

    monkeypatch.setattr(engine, "EngineCleanupConfirmation", confirmation)
    assert native.lifetime.reconcile() == []
    assert enabled == [False]
    native.service.close()
    native.lifetime.release()
    enabled.clear()
    assert native.lifetime.reconcile() == []
    assert enabled == [True]
    native.lifetime.proof.stopped_result = False
    enabled.clear()
    with pytest.raises(engine.EnforcementUnavailable, match="confirmed stopped"):
        native.lifetime.reconcile()
    assert enabled == []
