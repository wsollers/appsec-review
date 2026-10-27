"""Builder and native execution share the actual durable interlock and client ledger."""
import json
from uuid import uuid4

import pytest

from appsec_review.container_runtime import image_builder as builders
from appsec_review.container_runtime import image_builder_service as service
from appsec_review.runtime import resources
from tests.test_native_engine_broker import native, create_payload, lease, request  # noqa: F401
from tests.test_bounded_image_build_service import BASE, BUILT, forbid_real_execution  # noqa: F401


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
