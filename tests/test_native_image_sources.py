from dataclasses import replace

import pytest

from appsec_review.config.native_engine import NativeImage, parse_native_engine
from appsec_review.container_runtime.builder_admission import service_contract
from appsec_review.container_runtime.build_executor import BuildContainerExecutor, BuildProfile
from appsec_review.container_runtime.native_contracts import client_contracts
from appsec_review.runtime import resources
from tests.test_native_engine_broker import BASE, create_payload, lease, native, request  # noqa: F401
from tests.test_bounded_image_build_service import forbid_real_execution  # noqa: F401

PIN = "sha256:" + "b" * 64
OTHER = "sha256:" + "c" * 64
OTHER_PIN = "sha256:" + "d" * 64


def sourced(native, *extra, source=PIN):
    images = (replace(native.config.native_engine.images[0], source_image_id=source), *extra)
    return replace(native.config.native_engine, images=images)


def mapped(native, sources=None):
    return replace(native.client.contract, image_ids=(BASE,),
                   image_sources={PIN: BASE} if sources is None else sources)


@pytest.mark.parametrize("source", ["sha256:" + "B" * 64, "sha256:abc", "b" * 64, BASE, 7])
def test_native_image_source_identity_must_be_distinct_immutable_id(native, source):
    with pytest.raises(ValueError, match="source identity"):
        replace(native.config.native_engine.images[0], source_image_id=source)


def test_native_image_source_parses_as_optional_operator_field(native):
    from dataclasses import asdict

    assert native.config.native_engine.images[0].source_image_id is None
    policy = sourced(native)
    assert parse_native_engine(asdict(policy)) == policy


@pytest.mark.parametrize("collision", ["duplicate", "image-id", "alias"])
def test_native_image_sources_are_unique_and_never_name_private_images(native, collision):
    other = NativeImage(OTHER, "image-2", native.config.native_engine.images[0].user, ("python",))
    if collision == "duplicate":
        other = replace(other, source_image_id=PIN)
    elif collision == "image-id":
        other = replace(other, source_image_id=OTHER_PIN)
        with pytest.raises(ValueError, match="source identities"):
            sourced(native, other, NativeImage(OTHER_PIN, "image-3", other.user, ("python",)))
        return
    else:
        other = replace(other, aliases=(PIN,))
    with pytest.raises(ValueError, match="source identities"):
        sourced(native, other)


def test_client_contract_maps_only_granted_sourced_images(native):
    other = NativeImage(OTHER, "image-2", native.config.native_engine.images[0].user, ("python",),
                        source_image_id=OTHER_PIN)
    config = replace(native.config, native_engine=sourced(native, other))
    contract, = client_contracts(config)
    assert contract.image_ids == (BASE,)
    assert contract.image_sources == {PIN: BASE}
    contract, = client_contracts(native.config)
    assert contract.image_sources == {}


@pytest.mark.parametrize("sources", [
    {PIN: OTHER}, {BASE: BASE}, {"sha256:short": BASE}, {PIN: BASE, OTHER_PIN: BASE}, [PIN],
])
def test_client_contract_rejects_non_bijective_source_maps(native, sources):
    with pytest.raises(ValueError, match="source map"):
        mapped(native, sources)


@pytest.fixture
def inspected(native, monkeypatch):
    sent = []

    def answer(action, payload, deadline):
        sent.append(payload["reference"])
        return {"state": "PRESENT", "image_id": answer.image_id}
    answer.image_id = BASE
    monkeypatch.setattr(native.client, "_until", answer)
    return native, sent, answer


def inspect(native, reference):
    return native.client.run(("docker", "image", "inspect", reference, "--format", "{{.Id}}"), 30)


def test_client_inspect_reports_pin_only_for_mapped_images(inspected):
    native, sent, answer = inspected
    assert inspect(native, "base:release")[1] == f"{BASE}\n".encode()
    native.client.contract = mapped(native)
    assert inspect(native, PIN)[1] == f"{PIN}\n".encode()
    assert inspect(native, "base:release")[1] == f"{PIN}\n".encode()
    assert inspect(native, BASE)[1] == f"{BASE}\n".encode()
    assert sent == ["base:release", BASE, "base:release", BASE]
    answer.image_id = OTHER
    assert inspect(native, "base:release")[1] == f"{OTHER}\n".encode()
    with pytest.raises(RuntimeError, match="commissioned source"):
        inspect(native, PIN)


def test_client_create_sends_commissioned_private_image_for_pin(native):
    from appsec_review.container_runtime.native_commands import parse_native_command

    _, argv = create_payload(native)
    argv[argv.index(BASE)] = PIN
    native.client.contract = mapped(native)
    assert native.client._create(parse_native_command(argv))["image_id"] == BASE
    native.client.contract = mapped(native, {})
    assert native.client._create(parse_native_command(argv))["image_id"] == PIN


def test_broker_still_rejects_a_source_pin_sent_directly(native):
    native.broker.native = sourced(native)
    payload, _ = create_payload(native)
    payload["image_id"] = PIN
    with lease(native):
        resources.track_container(payload["name"])
        with pytest.raises(PermissionError, match="one operator command"):
            request(native, "execution.create", payload)
        assert "create" not in native.engine.calls
        resources.container_stopped(payload["name"])


def test_build_executor_resolves_pinned_profile_through_mapped_client(inspected):
    native, sent, _ = inspected
    native.client.contract = mapped(native)
    executor = BuildContainerExecutor(
        BuildProfile("java", "base:release", PIN, "10001:10001"), timeout_seconds=60, output_bytes=1024,
        runner=lambda argv, timeout: native.client.run(argv, timeout))
    executor.resolve()
    assert sent == ["base:release"]


def test_service_contract_keeps_pre_mapping_shape_for_unmapped_images(native):
    image = native.config.native_engine.images[0]
    unmapped = service_contract(native.config)
    assert unmapped["native_engine"]["images"] == [{
        "image_id": BASE, "release_id": "image-1", "user": image.user, "command_ids": ["python"],
        "allow_isolated_network": False, "aliases": ["base:release"], "allow_derived": False}]
    mapped_contract = service_contract(replace(native.config, native_engine=sourced(native)))
    assert mapped_contract["native_engine"]["images"][0]["source_image_id"] == PIN
    assert mapped_contract != unmapped
    other = service_contract(replace(native.config, native_engine=sourced(native, source=OTHER_PIN)))
    assert other["native_engine"]["images"][0]["source_image_id"] == OTHER_PIN
    assert other != mapped_contract
    assert native.config.native_engine.images[0].source_image_id is None
