from dataclasses import asdict, replace
import os
from pathlib import Path

import pytest

from appsec_review.config.native_engine import NativeCommand, parse_native_engine
from appsec_review.container_runtime import engine_broker
from appsec_review.container_runtime.builder_admission import service_contract
from appsec_review.container_runtime.engine_broker import NativeProof, execution_seccomp
from tests.test_bounded_image_build_service import forbid_real_execution  # noqa: F401
from tests.test_native_engine_broker import (
    create_payload, lease, message, native,  # noqa: F401
)


@pytest.mark.parametrize("value", [1, 0, "true", None, [], {}])
def test_tracing_requires_a_boolean_operator_command_policy(value):
    with pytest.raises(ValueError, match="explicit operator"):
        NativeCommand("capture", "/bin/sh", allow_process_tree_trace=value)


def test_tracing_policy_round_trips_and_changes_the_sealed_contract(native):
    command = native.config.native_engine.commands[0]
    assert command.allow_process_tree_trace is False
    configured = replace(native.config, native_engine=replace(
        native.config.native_engine, commands=(replace(command, allow_process_tree_trace=True),)))
    parsed = parse_native_engine(asdict(configured.native_engine))
    assert parsed.commands[0].allow_process_tree_trace is True
    assert service_contract(configured) != service_contract(native.config)
    with pytest.raises(ValueError, match="syscall allowlist"):
        replace(configured.native_engine, syscall_allowlist=("read", "ptrace"))


@pytest.mark.parametrize("tracing", [False, True])
@pytest.mark.parametrize("network", ["none", "isolated"])
def test_seccomp_changes_only_ptrace_for_the_explicit_command(native, tracing, network):
    policy = replace(native.config.native_engine,
                     syscall_allowlist=("read", "write", "clone", "exit_group"))
    command = asdict(replace(policy.commands[0], allow_process_tree_trace=tracing))
    profile = execution_seccomp(policy, command, network)
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    assert profile["defaultErrnoRet"] == 1
    assert profile["architectures"] == ["SCMP_ARCH_X86_64"]
    allowed = {name for rule in profile["syscalls"] if rule["action"] == "SCMP_ACT_ALLOW"
               for name in rule["names"]}
    assert ("ptrace" in allowed) is tracing
    assert not allowed & {"process_vm_readv", "process_vm_writev", "pidfd_getfd",
                          "mount", "unshare", "setns", "bpf", "clone3"}
    clone, = (rule for rule in profile["syscalls"] if rule["names"] == ["clone"])
    assert clone["args"] == [
        {"index": 0, "value": 0x7E020000, "valueTwo": 0, "op": "SCMP_CMP_MASKED_EQ"}]
    clone3, = (rule for rule in profile["syscalls"] if rule["names"] == ["clone3"])
    assert clone3 == {"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38}
    sockets = [rule for rule in profile["syscalls"] if rule["names"] == ["socket"]]
    assert sockets == ([] if network == "none" else [
        {"names": ["socket"], "action": "SCMP_ACT_ALLOW",
         "args": [{"index": 0, "value": family, "op": "SCMP_CMP_EQ"}]} for family in (2, 10)])
    if tracing:
        ordinary = execution_seccomp(policy, asdict(policy.commands[0]), network)
        assert [rule for rule in profile["syscalls"] if rule["names"] != ["ptrace"]] == ordinary["syscalls"]


def test_tracing_is_selected_only_from_the_exact_operator_command(native):
    payload, _ = create_payload(native)
    for enabled in (False, True):
        native.broker.native = replace(native.config.native_engine, commands=(
            replace(native.config.native_engine.commands[0], allow_process_tree_trace=enabled),))
        (_, command), _ = native.broker._create_policy(payload, native.broker.native.grants[0])
        assert command.allow_process_tree_trace is enabled
        assert "allow_process_tree_trace" not in payload


def test_client_cannot_request_operator_only_tracing(native):
    payload, _ = create_payload(native)
    payload["allow_process_tree_trace"] = True
    with lease(native):
        with pytest.raises(ValueError, match="invalid exact"):
            native.broker.dispatch(message(native, "execution.create", payload), native.peer)
    assert "create" not in native.engine.calls


@pytest.fixture
def capture_proof(native, tmp_path, monkeypatch):
    proof = NativeProof(native.config)
    parent = tmp_path / "execution"
    group = parent / ("f" * 64)
    group.mkdir(parents=True)
    for path in (parent, group):
        (path / "pids.max").write_text("16")
    values = {
        "Uid": "10001 10001 10001 10001", "Gid": "10001 10001 10001 10001",
        "CapEff": "0", "CapPrm": "0", "CapBnd": "0",
        "NoNewPrivs": "1", "Seccomp": "2", "NSpid": "424242 1",
    }
    namespace = {"shared": None}
    original_read = Path.read_text

    def read(path, *args, **kwargs):
        if str(path) == "/proc/424242/status":
            return "\n".join(f"{key}:\t{value}" for key, value in values.items())
        return original_read(path, *args, **kwargs)

    def link(path):
        name = path.rsplit("/", 1)[-1]
        owner = "host" if "/self/" in path or namespace["shared"] == name else "execution"
        return f"{name}:[{owner}]"

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(os, "readlink", link)
    monkeypatch.setattr(proof, "process_cgroup", lambda pid: group)
    monkeypatch.setattr(proof, "limits", lambda *args: {"fixture": True})
    monkeypatch.setattr(engine_broker, "process_token", lambda pid: "fixture-generation")
    record = {
        "driver": {"cgroup": str(parent), "container_id": group.name, "mounts": []},
        "payload": {"cpu": 2, "memory_mb": 1024, "pids": 16, "fsize_bytes": None},
        "image_policy": {"user": "10001:10001"},
        "command_policy": {"allow_process_tree_trace": True},
    }
    return proof, {"State": {"Pid": 424242}}, record, values, namespace


def test_capture_gate_proof_records_private_namespace_and_unchanged_isolation(capture_proof):
    proof, inspection, record, _, _ = capture_proof
    observed = proof.execution(inspection, record)
    assert observed["process_tree_trace"] is True
    assert observed["pid_namespace"] == "pid:[execution]"
    assert observed["pid"] == 424242
    assert observed["start_token"] == "fixture-generation"


@pytest.mark.parametrize("value", ["", "424242", "424242 2", "42 1", "424242 bad 1"])
def test_capture_gate_requires_resolving_private_namespace_init(capture_proof, value):
    proof, inspection, record, values, _ = capture_proof
    values["NSpid"] = value
    with pytest.raises(RuntimeError, match="private PID namespace init"):
        proof.execution(inspection, record)


@pytest.mark.parametrize("name", ["pid", "mnt", "ipc", "uts", "net", "cgroup"])
def test_capture_gate_refuses_every_host_namespace(capture_proof, name):
    proof, inspection, record, _, namespace = capture_proof
    namespace["shared"] = name
    with pytest.raises(RuntimeError, match="host namespace"):
        proof.execution(inspection, record)


@pytest.mark.parametrize("name,value", [
    ("Uid", "0 0 0 0"), ("Gid", "0 0 0 0"), ("CapEff", "80000"),
    ("CapPrm", "80000"), ("CapBnd", "80000"), ("NoNewPrivs", "0"), ("Seccomp", "0"),
])
def test_capture_does_not_relax_uid_capabilities_nnp_or_seccomp(capture_proof, name, value):
    proof, inspection, record, values, _ = capture_proof
    values[name] = value
    with pytest.raises(RuntimeError, match="UID, capabilities, NNP or seccomp"):
        proof.execution(inspection, record)


def test_disabled_capture_keeps_default_namespace_contract(capture_proof):
    proof, inspection, record, values, _ = capture_proof
    record["command_policy"]["allow_process_tree_trace"] = False
    del values["NSpid"]
    assert proof.execution(inspection, record)["process_tree_trace"] is False
