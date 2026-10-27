"""Typed budget wiring using real client/service/leases and fake host/worker controls."""
from contextlib import contextmanager
from dataclasses import replace
import json
from uuid import uuid4

import pytest

from appsec_review.config.assurance import ResourceBudget
from appsec_review.container_runtime import builder_admission as integration
from appsec_review.container_runtime import image_builder as clients
from appsec_review.container_runtime import image_builder_service as services
from appsec_review.runtime.resources import (
    Reservation, ResourceAdmission, ResourceCapacityInfeasible, review_resource_scope,
    track_image_build, update_image_build,
)
from appsec_review.storage import atomic_json
from tests import test_bounded_image_build_service as fixtures
from tests.test_bounded_image_build_service import forbid_real_execution  # noqa: F401


DEFAULT = ResourceBudget()
OPT_IN = ResourceBudget(cpu=9, memory_mb=12288)


@pytest.fixture
def make_harness(tmp_path, monkeypatch):
    original = fixtures.configuration
    opened = []

    def make(budget=DEFAULT):
        def configuration(root):
            config, context = original(root)
            config = replace(config, resources=budget)
            context.review_policy = replace(context.review_policy, resources=budget)
            return config, context
        monkeypatch.setattr(fixtures, "configuration", configuration)
        root = tmp_path / str(len(opened))
        root.mkdir(mode=0o700)
        harness = fixtures.Harness(root, require_worker_reservation=True)
        opened.append(harness)
        return harness

    yield make
    for harness in opened:
        harness.service.close()


def admission(harness, budget=None):
    return ResourceAdmission(harness.context.metadata_root, budget or harness.config.resources)


def state(harness):
    return json.loads((admission(harness).root / "leases.json").read_text())


@contextmanager
def client_scope(harness, *, budget=None, metadata_root=None):
    context = harness.context
    with review_resource_scope(
            metadata_root or context.metadata_root, budget or context.review_policy.resources, context.events), \
            clients.image_builder_scope(context):
        yield


def install_transport(harness, monkeypatch, *, corrupt_response=None):
    class Transport:
        def __init__(self, owner):
            pass

        def request(self, action, body, timeout):
            assert timeout > 0
            request = {"schema": services.SCHEMA, "request_id": uuid4().hex, "action": action, "body": body}
            response = json.loads(harness.service.dispatch(services.encoded(request), harness.peer))["body"]
            if action == corrupt_response:
                response["resource_budget"]["staging_memory_mb"] += 1
            return response

    monkeypatch.setattr(clients, "UnixBuilderClient", Transport)


def build(harness):
    tag = "derived:" + clients.builder_namespace()[:12] + "-budget"
    with clients.bounded_image_preparation(identity="budget-recipe", tag=tag, timeout_seconds=10) as session:
        (session.context / "Dockerfile").write_text("FROM base:release\n")
        session.build(network="none")
    clients.verify_builder_receipt(session.receipt(), identity="budget-recipe", tag=tag, image_id=fixtures.BUILT)
    return session


@pytest.mark.parametrize("budget,feasible", [(DEFAULT, False), (OPT_IN, True)])
def test_compiled_eight_cpu_demand_is_unchanged_and_default_never_silently_upgrades(
        make_harness, monkeypatch, budget, feasible):
    harness = make_harness(budget)
    monkeypatch.setattr(integration.time, "sleep", lambda _: pytest.fail("permanent excess must not queue"))
    entry = state(harness)["leases"][harness.config.admission.lease_id]
    assert entry["reservation"] == {"cpu": 1, "memory_mb": 512, "io_slots": 0}
    assert entry["persistent"]["service_contract"]["resources"] == budget.view()
    request = Reservation(8, 9728)
    if not feasible:
        with pytest.raises(ResourceCapacityInfeasible) as raised:
            with admission(harness).reserve(
                    request, events=harness.context.events, action="compiled-database", timeout_seconds=86400):
                pytest.fail("the default budget cannot fit compiled work beside the service")
        assert raised.value.blocking_resources == ("cpu",)
    else:
        with admission(harness).reserve(
                request, events=harness.context.events, action="compiled-database", timeout_seconds=0):
            entries = state(harness)["leases"].values()
            assert sum(item["reservation"]["cpu"] for item in entries) == 9
            assert sum(item["reservation"]["memory_mb"] for item in entries) == 10240
            assert sum(item["reservation"]["io_slots"] for item in entries) == 1
    # Synthetic admission is not commissioning or compiled-review coverage.


def test_opt_in_preserves_transient_headroom_and_minimum_across_other_leases(make_harness):
    harness = make_harness(OPT_IN)
    with admission(harness, DEFAULT).reserve(
            Reservation(1, 1, io_slots=0), events=harness.context.events, action="older-client", timeout_seconds=0):
        with pytest.raises(TimeoutError):
            with admission(harness).reserve(
                    Reservation(7, 1024), events=harness.context.events, action="queued", timeout_seconds=0):
                pytest.fail("an older lease's 8-CPU ceiling must still apply")
    with admission(harness).reserve(
            Reservation(8, 9728), events=harness.context.events, action="compiled-database", timeout_seconds=0):
        pass
    admission(harness).reserve_persistent(
        "separate-daemon", Reservation(1, 2049, io_slots=0), {"kind": "separately-charged-fixture"})
    with pytest.raises(ResourceCapacityInfeasible) as raised:
        with admission(harness).reserve(
                Reservation(8, 9728), events=harness.context.events, action="compiled-database", timeout_seconds=0):
            pytest.fail("separately charged daemon/proxy capacity must not disappear")
    assert raised.value.blocking_resources == ("cpu", "memory_mb")


@pytest.mark.parametrize("budget", [DEFAULT, OPT_IN, replace(OPT_IN, staging_memory_mb=768)])
def test_budget_is_frozen_through_real_client_service_journal_receipt_and_restart(make_harness, monkeypatch, budget):
    harness = make_harness(budget)
    install_transport(harness, monkeypatch)
    with client_scope(harness):
        session = build(harness)
    record = harness.service.store.get(session.build_id)
    assert record["resource_budget"] == record["service_contract"]["resources"] == budget.view()
    receipt = json.loads((session.root / "terminal.json").read_text())
    assert receipt["resource_budget"] == receipt["enforcement"]["resource_budget"] == budget.view()
    events = [json.loads(line) for line in harness.context.events.path.read_text().splitlines()]
    acquired = next(event["reservation"] for event in events if event["event"] == "RESOURCE_ADMITTED")
    assert acquired == {"cpu": 2, "memory_mb": 4608 + budget.staging_memory_mb, "io_slots": 1}
    before = state(harness)
    harness.service.close()
    harness.service = harness.open()
    harness.lifetime.verify()
    assert harness.lifetime.reserve() == harness.config.admission.lease_id
    assert state(harness) == before


@pytest.mark.parametrize("budget", [DEFAULT, OPT_IN])
def test_typed_lifetime_survives_service_exit_until_independent_shutdown_confirmation(make_harness, budget):
    harness = make_harness(budget)
    harness.service.close()
    harness.lifetime_proof.stopped_result = False
    with pytest.raises(integration.EnforcementUnavailable, match="termination"):
        harness.lifetime.release()
    assert harness.config.admission.lease_id in state(harness)["leases"]
    assert admission(harness).reconcile(
        lambda _: True, confirmed_cleanup=lambda _: True, confirmed_build_stopped=lambda _: True) == []
    harness.lifetime_proof.stopped_result = True
    harness.lifetime.release()
    assert state(harness)["leases"] == {}
    with pytest.raises(integration.EnforcementUnavailable):
        harness.lifetime.verify()


@pytest.mark.parametrize("field,value", [
    ("cpu", 9), ("memory_mb", 12288), ("io_slots", 2), ("staging_memory_mb", 768),
    ("cpu", True), ("io_slots", True),
])
def test_service_rejects_every_budget_dimension_and_boolean_equivalents_before_preparation(
        make_harness, field, value):
    harness = make_harness()
    harness.prepare_context()
    with pytest.raises((ValueError, integration.EnforcementUnavailable)):
        harness.request("prepare", {
            "limits": harness.config.requested_limits,
            "resource_budget": {**DEFAULT.view(), field: value},
        })
    assert harness.driver.calls == []
    assert harness.service.store.records() == []


@pytest.mark.parametrize("wire", [None, {}, {"cpu": 8}, {**DEFAULT.view(), "other": 1}])
def test_incomplete_budget_contract_is_not_defaulted_on_the_wire(make_harness, wire):
    harness = make_harness()
    harness.prepare_context()
    with pytest.raises(ValueError):
        harness.request("prepare", {"limits": harness.config.requested_limits, "resource_budget": wire})
    assert harness.driver.calls == []


def test_missing_wire_budget_cannot_use_operator_defaults(make_harness):
    harness = make_harness()
    harness.prepare_context()
    message = {"schema": services.SCHEMA, "request_id": uuid4().hex, "action": "prepare", "body": {
        "binding": harness.binding, "worker": None, "limits": harness.config.requested_limits,
    }}
    with pytest.raises(ValueError, match="action fields"):
        harness.service.dispatch(services.encoded(message), harness.peer)
    assert harness.driver.calls == []


@pytest.mark.parametrize("resources", [
    DEFAULT.view(), ResourceBudget(cpu=1), ResourceBudget(memory_mb=4608),
    ResourceBudget(staging_memory_mb=256),
])
def test_service_requires_typed_budget_and_bounds_worker_and_context_staging(make_harness, resources):
    harness = make_harness()
    with pytest.raises(ValueError):
        replace(harness.config, resources=resources)


@pytest.mark.parametrize("wrong_scope", ["budget", "staging", "store"])
def test_client_refuses_actual_admission_scope_different_from_frozen_policy(make_harness, monkeypatch, wrong_scope):
    harness = make_harness()
    install_transport(harness, monkeypatch)
    budget = OPT_IN if wrong_scope == "budget" else (
        replace(DEFAULT, staging_memory_mb=768) if wrong_scope == "staging" else DEFAULT)
    metadata = harness.context.metadata_root.parent / "other-store" if wrong_scope == "store" else None
    with client_scope(harness, budget=budget, metadata_root=metadata):
        with pytest.raises(ValueError, match="frozen budget or metadata store"):
            build(harness)
    assert harness.driver.calls == []


@pytest.mark.parametrize("phase", ["prepare", "start", "cleanup"])
def test_response_budget_drift_cannot_publish_receipt_or_clear_quarantine(make_harness, monkeypatch, phase):
    harness = make_harness()
    install_transport(harness, monkeypatch, corrupt_response=phase)
    with client_scope(harness), pytest.raises((ValueError, RuntimeError)):
        build(harness)
    retained = [entry for entry in state(harness)["leases"].values() if "persistent" not in entry]
    assert len(retained) == 1
    assert retained[0]["quarantine"] == "image_builder_budget_mismatch"
    assert harness.lifetime.reconcile() == []


@pytest.mark.parametrize("field", ["resource_budget", "enforcement", "execution", "cleanup"])
def test_cached_receipt_requires_the_same_budget_in_every_phase(make_harness, monkeypatch, field):
    harness = make_harness()
    install_transport(harness, monkeypatch)
    with client_scope(harness):
        session = build(harness)
        path = session.root / "terminal.json"
        receipt = json.loads(path.read_text())
        if field == "resource_budget":
            receipt[field] = OPT_IN.view()
        else:
            receipt[field]["resource_budget"] = OPT_IN.view()
        atomic_json(path, receipt)
        with pytest.raises(ValueError, match="receipt"):
            clients.verify_builder_receipt(
                session.receipt(), identity="budget-recipe",
                tag=session.binding["output_tag"], image_id=fixtures.BUILT)


@pytest.mark.parametrize("fault", ["budget", "staging", "key", "generation", "old-contract", "old-limits"])
def test_lifetime_cannot_adopt_changed_budget_old_lease_or_rebound_identity(make_harness, fault):
    harness = make_harness()
    config = harness.config
    if fault == "budget":
        config = replace(config, resources=OPT_IN)
    elif fault == "staging":
        config = replace(config, resources=replace(DEFAULT, staging_memory_mb=768))
    elif fault == "key":
        config = replace(config, admission=replace(config.admission, lease_id=uuid4().hex))
    elif fault == "generation":
        harness.lifetime_proof.generation += 1
    elif fault == "old-contract":
        anchor = json.loads(harness.lifetime.path.read_text())
        anchor["service_contract"].pop("resources")
        atomic_json(harness.lifetime.path, anchor)
    else:
        value = state(harness)
        value["leases"][config.admission.lease_id]["limits"]["cpu"] = 7
        atomic_json(admission(harness).root / "leases.json", value)
    before = state(harness)
    candidate = integration.BuilderAdmission(config, proof=harness.lifetime_proof)
    with pytest.raises((ValueError, integration.EnforcementUnavailable)):
        candidate.verify()
    with pytest.raises((ValueError, integration.EnforcementUnavailable)):
        candidate.reserve()
    assert state(harness) == before


@pytest.mark.parametrize("fault", ["missing", "staging", "limits"])
def test_legacy_or_incompatible_tracked_build_cannot_borrow_service_capacity(make_harness, fault):
    harness = make_harness()
    harness.prepare_context()
    tracked = {**harness.binding, "endpoint": harness.config.endpoint, "resource_budget": DEFAULT.view()}
    if fault == "missing":
        tracked.pop("resource_budget")
    elif fault == "staging":
        tracked["resource_budget"]["staging_memory_mb"] = 768
    budget = replace(DEFAULT, cpu=7) if fault == "limits" else DEFAULT
    with admission(harness, budget).reserve(
            Reservation(2, 5120), events=harness.context.events, action="legacy-builder", timeout_seconds=0):
        track_image_build(tracked, max_concurrency=1, timeout_seconds=1)
        with pytest.raises(integration.EnforcementUnavailable, match="tracked client"):
            harness.prepare()
    assert harness.driver.calls == []


def test_changed_tracked_staging_cannot_be_reconciled_even_after_confirmed_cleanup(make_harness):
    harness = make_harness()
    path = harness.prepare_context()
    with admission(harness).reserve(
            Reservation(2, 5120), events=harness.context.events, action="tracked", timeout_seconds=0):
        track_image_build(
            {**harness.binding, "endpoint": harness.config.endpoint, "resource_budget": DEFAULT.view()},
            max_concurrency=1, timeout_seconds=1)
        prepared = harness.prepare()
        update_image_build(harness.binding["build_id"], worker=prepared["worker"])
        path.joinpath("Dockerfile").write_text("FROM base:release\n")
        harness.start()
    assert harness.request("cleanup")["state"] == "CLEANED"
    value = state(harness)
    ordinary = next(entry for entry in value["leases"].values() if "persistent" not in entry)
    ordinary["builds"][0]["resource_budget"]["staging_memory_mb"] = 768
    atomic_json(admission(harness).root / "leases.json", value)
    assert harness.lifetime.reconcile() == []
