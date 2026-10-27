"""Fake host/process controls, real service journal and ResourceAdmission ledger.

Selector: tests/test_builder_admission.py. No subprocess, socket, privilege
transition, daemon, image operation or real cgroup operation is executed.
"""
from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.container_runtime import builder_admission as integration
from appsec_review.container_runtime import image_builder_service as services
from appsec_review.runtime import resources
from appsec_review.runtime.resources import (
    Reservation, ResourceAdmission, ResourceCapacityInfeasible, track_image_build, update_image_build,
)
from appsec_review.storage import atomic_json
from tests.test_bounded_image_build_service import Harness, forbid_real_execution  # noqa: F401


@pytest.fixture
def harness(tmp_path):
    value = Harness(tmp_path, require_worker_reservation=True)
    yield value
    value.service.close()


def ledger(harness):
    return ResourceAdmission(harness.context.metadata_root, harness.config.resources)


def read_leases(harness):
    return json.loads((ledger(harness).root / "leases.json").read_text())["leases"]


def change_leases(harness, change):
    path = ledger(harness).root / "leases.json"
    state = json.loads(path.read_text())
    change(state["leases"])
    atomic_json(path, state)


def abandoned_build(harness):
    path = harness.prepare_context()
    with ledger(harness).reserve(
            Reservation(2, 5120), events=harness.context.events, action="image.prepare", timeout_seconds=0):
        track_image_build({**harness.binding, "endpoint": harness.config.endpoint,
                           "resource_budget": harness.config.resources.view()},
                          max_concurrency=1, timeout_seconds=1)
        prepared = harness.prepare()
        assert prepared["state"] == "PREPARED"
        update_image_build(harness.binding["build_id"], worker=prepared["worker"])
        path.joinpath("Dockerfile").write_text("FROM base:release\n")
        assert harness.start()["state"] == "RUNNING"
    leases = read_leases(harness)
    build_lease = next(key for key in leases if key != harness.config.admission.lease_id)
    assert leases[build_lease]["owner_finished"]
    assert leases[build_lease]["quarantine"] == "image_builder_cleanup_unconfirmed"
    return build_lease, path


def test_lifetime_is_a_real_counted_persistent_reservation(harness):
    lease_id = harness.config.admission.lease_id
    entry = read_leases(harness)[lease_id]
    assert entry["reservation"] == {"cpu": 1, "memory_mb": 512, "io_slots": 0}
    assert entry["limits"] == {"cpu": 8, "memory_mb": 10240, "io_slots": 1}
    assert entry["persistent"]["service_contract"] == integration.service_contract(harness.config)
    with ledger(harness).reserve(
            Reservation(2, 5120), events=harness.context.events, action="fixture", timeout_seconds=0):
        entries = read_leases(harness).values()
        assert sum(item["reservation"]["cpu"] for item in entries) == 3
        assert sum(item["reservation"]["memory_mb"] for item in entries) == 5632
    with pytest.raises(ResourceCapacityInfeasible):
        with ledger(harness).reserve(
                Reservation(8, 10240), events=harness.context.events, action="too-large", timeout_seconds=0):
            pytest.fail("permanent headroom was not counted")
    assert set(read_leases(harness)) == {lease_id}


def test_eight_cpu_compiled_work_is_permanently_infeasible_not_a_queue_timeout(harness, monkeypatch):
    monkeypatch.setattr(resources.time, "sleep", lambda seconds: pytest.fail("infeasible work must not wait"))
    demand = Reservation(8, 9728)
    with pytest.raises(ResourceCapacityInfeasible) as raised:
        with ledger(harness).reserve(
                demand, events=harness.context.events, action="codeql.compiled_database", timeout_seconds=86400):
            pytest.fail("compiled work was incorrectly considered ready")
    error = raised.value
    assert error.requirement == "operator_capacity_resolution_required"
    assert error.reason == "persistent_service_capacity_infeasible"
    assert error.blocking_resources == ("cpu",)
    assert error.required_budget == {"cpu": 9, "memory_mb": 10240, "io_slots": 1}
    events = [json.loads(line) for line in (harness.context.run_root / "events.jsonl").read_text().splitlines()]
    assert any(event["event"] == "RESOURCE_INFEASIBLE" and event["reason"] == error.reason for event in events)
    assert not any(event["event"] in {"RESOURCE_TIMED_OUT", "RESOURCE_ADMITTED"} for event in events)


def test_separately_charged_daemon_or_proxy_cost_is_not_exempted(harness, monkeypatch):
    ledger(harness).reserve_persistent(
        "separate-proxy", Reservation(1, 1, io_slots=0), {"kind": "fixture-separately-charged-proxy"})
    monkeypatch.setattr(resources.time, "sleep", lambda seconds: pytest.fail("permanent excess must not wait"))
    with pytest.raises(ResourceCapacityInfeasible) as raised:
        with ledger(harness).reserve(
                Reservation(8, 9728), events=harness.context.events,
                action="codeql.compiled_database", timeout_seconds=86400):
            pytest.fail("extra permanent costs were ignored")
    assert raised.value.blocking_resources == ("cpu", "memory_mb")
    assert raised.value.required_budget["memory_mb"] == 10241
    assert raised.value.available_budget["memory_mb"] == 10240


def test_transient_queue_pressure_is_not_misclassified_as_permanent_infeasibility(harness):
    admission = ledger(harness)
    with admission.reserve(
            Reservation(7, 1024), events=harness.context.events, action="transient-fixture", timeout_seconds=0):
        with pytest.raises(TimeoutError):
            with admission.reserve(
                    Reservation(1, 1024), events=harness.context.events, action="queued-fixture", timeout_seconds=0):
                pytest.fail("transient reservation was not counted")
    with admission.reserve(
            Reservation(7, 1024), events=harness.context.events, action="synthetic-after-drain", timeout_seconds=0):
        pass
    events = [json.loads(line) for line in (harness.context.run_root / "events.jsonl").read_text().splitlines()]
    assert any(event["event"] == "RESOURCE_TIMED_OUT" for event in events)
    assert not any(event["event"] == "RESOURCE_INFEASIBLE" for event in events)
    # This synthetic admission proves only queue behavior, never compiled-review coverage.


def test_transient_stricter_limits_do_not_become_a_permanent_baseline(harness):
    admission = ledger(harness)
    narrower = ResourceAdmission(harness.context.metadata_root, replace(harness.config.resources, cpu=7))
    with narrower.reserve(
            Reservation(1, 1024, io_slots=0), events=harness.context.events,
            action="synthetic-narrower-budget", timeout_seconds=0):
        with pytest.raises(TimeoutError):
            with admission.reserve(
                    Reservation(6, 1024), events=harness.context.events,
                    action="synthetic-wait-for-narrower-budget", timeout_seconds=0):
                pytest.fail("transient narrower budget was ignored")
    with admission.reserve(
            Reservation(6, 1024), events=harness.context.events, action="synthetic-after-drain", timeout_seconds=0):
        pass


def test_service_exit_restart_and_permissive_reconcile_do_not_release_lifetime(harness, monkeypatch):
    lease_id = harness.config.admission.lease_id
    before = deepcopy(read_leases(harness)[lease_id])
    harness.service.close()
    monkeypatch.setattr(resources, "process_identity", lambda pid: None)
    assert ledger(harness).reconcile(
        lambda name: True, confirmed_cleanup=lambda entry: True,
        confirmed_build_stopped=lambda build: True) == []
    assert read_leases(harness)[lease_id] == before
    harness.service = harness.open()
    harness.lifetime.verify()
    assert harness.lifetime.reserve() == lease_id
    assert read_leases(harness)[lease_id] == before


@pytest.mark.parametrize("fault", ["missing", "binding", "reservation", "overcommitted"])
def test_preparation_requires_matching_real_admission_not_a_config_attestation(harness, fault):
    lease_id = harness.config.admission.lease_id
    if fault == "missing":
        change_leases(harness, lambda leases: leases.pop(lease_id))
    elif fault == "binding":
        change_leases(harness, lambda leases: leases[lease_id]["persistent"].update(kind="unrelated"))
    elif fault == "reservation":
        change_leases(harness, lambda leases: leases[lease_id]["reservation"].update(memory_mb=1))
    else:
        def overcommit(leases):
            other = deepcopy(leases[lease_id])
            other["reservation"]["memory_mb"] = 10240
            leases["other"] = other
        change_leases(harness, overcommit)
    harness.prepare_context()
    with pytest.raises((ValueError, OSError, integration.EnforcementUnavailable)):
        harness.prepare()
    assert harness.driver.calls == []
    assert harness.service.store.records() == []


def test_lifetime_configuration_or_cgroup_rebinding_is_not_adopted(harness):
    changed = replace(harness.config, endpoint=str(Path(harness.config.state_root) / "changed.sock"))
    with pytest.raises(integration.EnforcementUnavailable):
        integration.BuilderAdmission(changed, proof=harness.lifetime_proof).verify()
    harness.lifetime_proof.generation += 1
    with pytest.raises(integration.EnforcementUnavailable):
        harness.lifetime.verify()
    assert harness.config.admission.lease_id in read_leases(harness)


def test_lifetime_headroom_does_not_authorize_an_unreserved_worker(harness):
    harness.prepare_context()
    with pytest.raises(integration.EnforcementUnavailable, match="tracked client"):
        harness.prepare()
    assert harness.driver.calls == []
    assert harness.service.store.records() == []


@pytest.mark.parametrize("demand", [Reservation(1, 5120), Reservation(2, 5119)])
def test_worker_requires_full_tracked_cpu_memory_and_staging(harness, demand):
    harness.prepare_context()
    with ledger(harness).reserve(
            demand, events=harness.context.events, action="insufficient-worker", timeout_seconds=0):
        track_image_build({**harness.binding, "endpoint": harness.config.endpoint,
                           "resource_budget": harness.config.resources.view()},
                          max_concurrency=1, timeout_seconds=1)
        with pytest.raises(integration.EnforcementUnavailable, match="tracked client"):
            harness.prepare()
    assert harness.driver.calls == []


def test_worker_start_requires_the_exact_generation_in_the_real_client_lease(harness):
    path = harness.prepare_context()
    with ledger(harness).reserve(
            Reservation(2, 5120), events=harness.context.events, action="wrong-generation", timeout_seconds=0):
        track_image_build({**harness.binding, "endpoint": harness.config.endpoint,
                           "resource_budget": harness.config.resources.view()},
                          max_concurrency=1, timeout_seconds=1)
        prepared = harness.prepare()
        update_image_build(harness.binding["build_id"], worker={**prepared["worker"], "start_token": "wrong"})
        path.joinpath("Dockerfile").write_text("FROM base:release\n")
        with pytest.raises(integration.EnforcementUnavailable, match="tracked client"):
            harness.start()
        assert harness.request("cleanup")["state"] == "CLEANED"
    assert "start" not in harness.driver.calls
    assert harness.lifetime.reconcile() == []


def test_normal_and_container_repair_admission_semantics_remain_unchanged(harness):
    with ledger(harness).reserve(
            Reservation(1, 1024), events=harness.context.events, action="ordinary", timeout_seconds=0):
        pass
    assert set(read_leases(harness)) == {harness.config.admission.lease_id}
    with ledger(harness).reserve(
            Reservation(1, 1024), events=harness.context.events, action="container", timeout_seconds=0):
        resources.track_container("fixture-only-no-container")
    container_lease = next(key for key in read_leases(harness) if key != harness.config.admission.lease_id)
    assert read_leases(harness)[container_lease]["quarantine"] == "container_death_unconfirmed"
    assert harness.lifetime.reconcile() == []
    assert ledger(harness).reconcile(
        lambda name: name == "fixture-only-no-container",
        confirmed_cleanup=lambda entry: entry.get("quarantine") == "container_death_unconfirmed",
    ) == [container_lease]


def test_owner_death_uses_real_admission_reconcile_and_trusted_callbacks(harness, monkeypatch):
    build_lease, _ = abandoned_build(harness)
    assert harness.request("cleanup")["state"] == "CLEANED"
    change_leases(harness, lambda leases: leases[build_lease].update(
        pid=987654, process_identity="dead-owner-generation", owner_finished=False))
    original = resources.process_identity
    monkeypatch.setattr(resources, "process_identity", lambda pid: None if pid == 987654 else original(pid))
    confirmation = integration.JournalCleanupConfirmation(harness.config)
    removed = ledger(harness).reconcile(
        lambda name: False, confirmed_cleanup=confirmation.confirmed_cleanup,
        confirmed_build_stopped=confirmation.confirmed_build_stopped,
        lease_filter=lambda entry: bool(entry.get("builds")),
    )
    assert removed == [build_lease]
    assert set(read_leases(harness)) == {harness.config.admission.lease_id}


def test_service_restart_independently_cleans_and_reconciles_abandoned_client(harness):
    build_lease, path = abandoned_build(harness)
    harness.service.close()
    harness.service = harness.open()
    harness.service.reconcile(restart=True)
    assert harness.service.store.records()[0]["state"] == "CLEANED"
    assert not path.exists()
    assert build_lease not in read_leases(harness)
    assert harness.config.admission.lease_id in read_leases(harness)
    assert harness.lifetime.reconcile() == []


@pytest.mark.parametrize("fault", [
    "unknown", "missing-record", "missing-worker", "worker", "binding", "endpoint",
    "service-contract", "receipt", "context-rebound", "unrelated-quarantine",
])
def test_unknown_rebound_and_unrelated_outcomes_stay_reserved(harness, fault):
    build_lease, path = abandoned_build(harness)
    if fault == "unknown":
        harness.driver.confirmed = False
        assert harness.request("cleanup")["state"] == "UNKNOWN"
    else:
        assert harness.request("cleanup")["state"] == "CLEANED"
    if fault == "missing-record":
        harness.service.store.connection.execute("DELETE FROM builds")
        harness.service.store.connection.commit()
    elif fault in {"service-contract", "receipt"}:
        record = harness.service.store.records()[0]
        if fault == "service-contract":
            record["service_contract"]["release_id"] = "changed"
        else:
            record["cleanup"]["context_released"] = False
        harness.service.store.save(record)
    elif fault == "context-rebound":
        path.mkdir(mode=0o700)
    elif fault == "unrelated-quarantine":
        change_leases(harness, lambda leases: leases[build_lease].update(quarantine="image_builder_binding_mismatch"))
    elif fault in {"missing-worker", "worker", "binding", "endpoint"}:
        def corrupt(leases):
            build = leases[build_lease]["builds"][0]
            if fault == "missing-worker":
                build.pop("worker")
            elif fault == "worker":
                build["worker"]["start_token"] = "replaced"
            elif fault == "binding":
                build["recipe_identity"] = "changed"
            else:
                build["endpoint"] = "/wrong/builder.sock"
        change_leases(harness, corrupt)
    assert harness.lifetime.reconcile() == []
    assert build_lease in read_leases(harness)


def test_builder_reconciler_does_not_change_unrelated_dead_leases(harness):
    build_lease, _ = abandoned_build(harness)
    assert harness.request("cleanup")["state"] == "CLEANED"
    def add_other(leases):
        leases["unrelated"] = {
            "pid": 987654, "process_identity": "gone", "owner_finished": True,
            "containers": [], "reservation": {"cpu": 1, "memory_mb": 1, "io_slots": 0},
            "limits": {"cpu": 8, "memory_mb": 10240, "io_slots": 1}, "action": "unrelated",
        }
    change_leases(harness, add_other)
    assert harness.lifetime.reconcile() == [build_lease]
    assert "unrelated" in read_leases(harness)


def test_client_ledger_ownership_and_private_modes_survive_all_operations(harness):
    path = ledger(harness).root / "leases.json"
    before = path.stat()
    build_lease, _ = abandoned_build(harness)
    assert harness.request("cleanup")["state"] == "CLEANED"
    assert harness.lifetime.reconcile() == [build_lease]
    after = path.stat()
    assert before.st_uid == after.st_uid == harness.config.admission.uid
    assert before.st_gid == after.st_gid == harness.config.admission.gid
    assert before.st_mode & 0o777 == after.st_mode & 0o777 == 0o600


def test_missing_lifetime_capacity_keeps_even_a_cleaned_builder_reserved(harness):
    build_lease, _ = abandoned_build(harness)
    assert harness.request("cleanup")["state"] == "CLEANED"
    change_leases(harness, lambda leases: leases.pop(harness.config.admission.lease_id))
    with pytest.raises(ValueError, match="missing"):
        harness.lifetime.reconcile()
    assert build_lease in read_leases(harness)


def test_client_ledger_symlink_is_rejected_without_touching_its_destination(harness):
    root = ledger(harness).root
    original = root.with_name("original-admission")
    root.rename(original)
    root.symlink_to(original, target_is_directory=True)
    before = (original / "leases.json").read_bytes()
    with pytest.raises((OSError, integration.EnforcementUnavailable)):
        harness.lifetime.verify()
    assert (original / "leases.json").read_bytes() == before


def test_client_ledger_directory_replacement_is_not_adopted(harness):
    root = ledger(harness).root
    saved = root.with_name("saved-admission")
    root.rename(saved)
    root.mkdir(mode=0o700)
    (root / "admission.lock").write_bytes(b"\0")
    atomic_json(root / "leases.json", json.loads((saved / "leases.json").read_text()))
    with pytest.raises(integration.EnforcementUnavailable, match="rebound"):
        harness.lifetime.verify()


def test_lifetime_release_requires_stopped_service_and_independent_daemon_confirmation(harness):
    with pytest.raises(BlockingIOError):
        harness.lifetime.release()
    harness.service.close()
    harness.lifetime_proof.stopped_result = False
    with pytest.raises(integration.EnforcementUnavailable, match="termination"):
        harness.lifetime.release()
    assert harness.config.admission.lease_id in read_leases(harness)
    harness.lifetime_proof.stopped_result = True
    harness.lifetime.release()
    assert harness.config.admission.lease_id not in read_leases(harness)
    assert json.loads(harness.lifetime.path.read_text())["state"] == "RELEASED"
    with pytest.raises(integration.EnforcementUnavailable):
        harness.lifetime.verify()


def test_uncertain_worker_cleanup_prevents_lifetime_release_even_when_host_looks_empty(harness):
    abandoned_build(harness)
    harness.driver.confirmed = False
    harness.request("cleanup")
    harness.service.close()
    with pytest.raises(integration.EnforcementUnavailable, match="worker intents"):
        harness.lifetime.release()
    assert harness.config.admission.lease_id in read_leases(harness)


@pytest.mark.parametrize("empty,token,expected", [
    (False, None, False), (True, "recorded-generation", False), (True, None, True),
])
def test_lifetime_shutdown_proof_checks_cgroup_and_recorded_process_liveness(harness, monkeypatch, empty, token, expected):
    proof = integration.LifetimeProof(harness.config)
    monkeypatch.setattr(proof, "empty", lambda: empty)
    monkeypatch.setattr(integration, "process_token", lambda pid: token)
    assert proof.stopped([{"pid": 12345, "start_token": "recorded-generation"}]) is expected


@pytest.mark.parametrize("capacity_error", [False, True])
def test_broker_parent_does_not_execute_client_filesystem_operation_as_root(harness, monkeypatch, capacity_error):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "pipe", lambda: (31, 32))
    monkeypatch.setattr(os, "fork", lambda: 12345)
    monkeypatch.setattr(os, "close", lambda descriptor: None)
    monkeypatch.setattr(os, "set_blocking", lambda *args: None)
    reply = ({"ok": False, "error_type": "ResourceCapacityInfeasible", "capacity": {
        "request": {"cpu": 8, "memory_mb": 9728, "io_slots": 1},
        "permanent": {"cpu": 1, "memory_mb": 512, "io_slots": 0},
        "limits": {"cpu": 8, "memory_mb": 10240, "io_slots": 1},
    }} if capacity_error else {"ok": True, "value": "child-result"})
    chunks = iter([json.dumps(reply).encode(), b""])
    monkeypatch.setattr(os, "read", lambda *args: next(chunks))
    monkeypatch.setattr(os, "waitpid", lambda *args: (12345, 0))
    selector = SimpleNamespace(register=lambda *args: None, select=lambda *args: [True], close=lambda: None)
    monkeypatch.setattr(integration.selectors, "DefaultSelector", lambda: selector)
    def forbidden():
        pytest.fail("root parent touched client-controlled paths")
    if capacity_error:
        with pytest.raises(ResourceCapacityInfeasible) as raised:
            integration._as_client(harness.config, forbidden)
        assert raised.value.requirement == "operator_capacity_resolution_required"
        assert raised.value.blocking_resources == ("cpu",)
    else:
        assert integration._as_client(harness.config, forbidden) == "child-result"


@pytest.mark.parametrize("successful_drop", [True, False])
def test_broker_child_permanently_drops_privileges_before_client_operations(harness, monkeypatch, successful_drop):
    current = {"uid": 0, "gid": 0}
    calls, replies = [], []
    monkeypatch.setattr(os, "geteuid", lambda: current["uid"])
    monkeypatch.setattr(os, "getegid", lambda: current["gid"])
    monkeypatch.setattr(os, "pipe", lambda: (31, 32))
    monkeypatch.setattr(os, "fork", lambda: 0)
    monkeypatch.setattr(os, "closerange", lambda *args: None)
    monkeypatch.setattr(os, "setgroups", lambda groups: calls.append(("groups", groups)))
    monkeypatch.setattr(os, "setgid", lambda gid: current.update(gid=gid))
    monkeypatch.setattr(os, "setuid", lambda uid: current.update(uid=uid if successful_drop else 0))
    monkeypatch.setattr(os, "write", lambda descriptor, data: replies.append(json.loads(data)) or len(data))
    class ChildExit(BaseException):
        pass
    def exit_child(code):
        raise ChildExit()
    monkeypatch.setattr(os, "_exit", exit_child)
    def operation():
        assert current["uid"] == harness.config.admission.uid
        assert current["gid"] == harness.config.admission.gid
        calls.append(("operation", current["uid"]))
        return "safe"
    with pytest.raises(ChildExit):
        integration._as_client(harness.config, operation)
    assert replies[0]["ok"] is successful_drop
    if successful_drop:
        assert ("operation", harness.config.admission.uid) in calls
    else:
        assert calls == [("groups", [])]
