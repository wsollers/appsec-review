"""Builder and native execution share the actual durable interlock and client ledger."""
import json
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from appsec_review.container_runtime import image_builder as builders
from appsec_review.container_runtime import image_builder_service as service
from appsec_review.runtime import resources
from tests.test_native_engine_broker import native, create_payload, lease, request  # noqa: F401
from tests.test_bounded_image_build_service import BASE, BUILT, forbid_real_execution  # noqa: F401


@pytest.mark.parametrize("native", ["engine-domain"], indirect=True)
def test_counted_engine_lifetime_allows_real_eight_cpu_action_admission(native, monkeypatch):
    class Transport:
        def __init__(self, owner):
            pass

        def request(self, action, body, timeout):
            data = service.encoded({"schema": service.SCHEMA, "request_id": uuid4().hex,
                                    "action": action, "body": body})
            return json.loads(native.service.dispatch(data, native.peer))["body"]

    monkeypatch.setattr(builders, "UnixBuilderClient", Transport)
    monkeypatch.setattr(native.client, "request",
                        lambda action, payload, **kw: request(native, action, payload, kw.get("request_id")))
    context = native.context
    with resources.review_resource_scope(context.metadata_root, context.review_policy.resources, context.events), \
            builders.image_builder_scope(context):
        tag = "derived:" + builders.builder_namespace()[:12] + "-engine-domain"
        with builders.bounded_image_preparation(identity="engine-domain", tag=tag, timeout_seconds=30) as build:
            (build.context / "Dockerfile").write_text('FROM base:release\nRUN ["true"]\n')
            assert build.build(network="none")[0] == 0
        assert native.broker.interlock.owner() is None
        payload, argv = create_payload(native)
        argv[argv.index("--cpus") + 1] = "8"
        admission = resources.ResourceAdmission(
            context.metadata_root, context.review_policy.resources, require_container_removal=True)
        with admission.reserve(resources.Reservation(8, 9728), events=context.events, action="codeql-sized"):
            native.lifetime.verify()
            assert native.client.run(argv, 30)[0] == 0
            assert native.client.run(("docker", "rm", "--force", payload["name"]), 30)[0] == 0
            resources.container_stopped(payload["name"])
            actions = json.loads((admission.root / "leases.json").read_text())["leases"]
            assert len(actions) == 1 and not any("persistent" in item for item in actions.values())
        bank = native.lifetime.engine_admission._ledger()
        entries = json.loads((bank.root / "leases.json").read_text())["leases"]
        assert len(entries) == 2 and all("persistent" in item for item in entries.values())
        assert sum(item["reservation"]["cpu"] for item in entries.values()) == 2
        assert sum(item["reservation"]["memory_mb"] for item in entries.values()) == 2048
        with pytest.raises(resources.ResourceCapacityInfeasible):
            bank.reserve_persistent("overflow", resources.Reservation(1, 1, io_slots=0), {"kind": "overflow"})
        with pytest.raises(BlockingIOError):
            native.lifetime.release()
        native.service.close()
        native.lifetime.proof.stopped_result = False
        with pytest.raises(RuntimeError, match="termination"):
            native.lifetime.release()
        assert len(json.loads((bank.root / "leases.json").read_text())["leases"]) == 2
        native.lifetime.proof.stopped_result = True
        native.lifetime.release()
        remaining = json.loads((bank.root / "leases.json").read_text())["leases"]
        assert list(remaining) == ["existing-engine-services"]
        assert remaining["existing-engine-services"]["reservation"] == {
            "cpu": 1, "memory_mb": 1536, "io_slots": 0}
        assert Path(native.lifetime.path).exists()


@pytest.mark.parametrize("native", ["engine-domain"], indirect=True)
def test_engine_headroom_loss_preserves_lifetime_reservations(native):
    from appsec_review.container_runtime.builder_admission import BuilderAdmission

    bank = native.lifetime.engine_admission._ledger()
    before = (bank.root / "leases.json").read_bytes()
    native.lifetime.engine_admission.proof.enough = False
    with pytest.raises(RuntimeError, match="headroom"):
        native.lifetime.verify()
    assert (bank.root / "leases.json").read_bytes() == before
    native.lifetime.engine_admission.proof.enough = True
    recovered = BuilderAdmission(native.config, proof=native.lifetime.proof)
    recovered.engine_admission.proof = native.lifetime.engine_admission.proof
    assert recovered.reserve() == native.config.admission.lease_id
    assert (bank.root / "leases.json").read_bytes() == before
    changed = BuilderAdmission(
        replace(native.config, lifetime_domain="actions", engine_domain=None), proof=native.lifetime.proof)
    with pytest.raises(RuntimeError, match="configuration"):
        changed.reserve()
    assert (bank.root / "leases.json").read_bytes() == before


@pytest.mark.parametrize("unremoved", [False, True])
@pytest.mark.parametrize("native", [True], indirect=True)
def test_builder_derived_tool_and_next_builder_use_one_interlock(native, monkeypatch, unremoved):
    class Transport:
        def __init__(self, owner):
            pass

        def request(self, action, body, timeout):
            data = service.encoded({"schema": service.SCHEMA, "request_id": uuid4().hex,
                                    "action": action, "body": body})
            return json.loads(native.service.dispatch(data, native.peer))["body"]

    monkeypatch.setattr(builders, "UnixBuilderClient", Transport)
    monkeypatch.setattr(native.client, "request",
                        lambda action, payload, **kw: request(native, action, payload, kw.get("request_id")))
    context = native.context
    with resources.review_resource_scope(context.metadata_root, context.review_policy.resources, context.events), \
            builders.image_builder_scope(context):
        first_tag = "derived:" + builders.builder_namespace()[:12] + "-first"
        with builders.bounded_image_preparation(identity="first-recipe", tag=first_tag, timeout_seconds=30) as first:
            (first.context / "Dockerfile").write_text('FROM base:release\nRUN ["true"]\n')
            assert first.build(network="none")[0] == 0
            assert native.broker.interlock.owner()["kind"] == "builder"
        assert native.broker.interlock.owner() is None
        first_record, = native.service.store.records()
        assert first_record["start"]["image_inputs"] == {}
        assert first_record["start"]["authorized_inputs"]["base:release"] == BASE
        payload, argv = create_payload(native)
        argv[argv.index(BASE)] = BUILT
        with lease(native):
            assert request(native, "image.inspect", {"reference": first_tag})["image_id"] == BUILT
            assert native.client.run(argv, 30)[0] == 0
            assert native.broker.interlock.owner()["kind"] == "execution"
            candidate = {**first_record, "binding": {**first_record["binding"], "build_id": uuid4().hex}}
            # Stopped/EXITED is not removal; even a separately admitted builder cannot steal ownership.
            with pytest.raises(RuntimeError, match="retained owner"):
                native.broker.claim_builder(candidate)
            if unremoved:
                native.engine.confirmed = False
                response = request(native, "execution.remove", native.client._control(payload["name"]))
                assert response["state"] == "UNKNOWN"
                assert native.broker.interlock.owner()["kind"] == "execution"
                return
            assert native.client.run(("docker", "rm", "--force", payload["name"]), 30)[0] == 0
            resources.container_stopped(payload["name"])
        assert native.broker.interlock.owner() is None
        second_image = "sha256:" + "d" * 64
        native.service.driver.result["image_id"] = second_image
        second_tag = "derived:" + builders.builder_namespace()[:12] + "-second"
        with builders.bounded_image_preparation(identity="second-recipe", tag=second_tag, timeout_seconds=30) as second:
            (second.context / "Dockerfile").write_text(f'FROM {first_tag}\nRUN ["true"]\n')
            assert second.build(network="none", image_inputs={first_tag: BUILT})[0] == 0
        assert native.broker.interlock.owner() is None
        with lease(native):
            assert request(native, "image.inspect", {"reference": second_tag})["image_id"] == second_image
        assert native.service.driver.calls.count("start") == 2
        assert native.engine.calls.count("create") == 1
