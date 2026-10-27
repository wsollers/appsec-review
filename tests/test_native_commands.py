from dataclasses import replace

import pytest

from appsec_review.container_runtime.native_commands import (
    NativeControl, NativeMount, NativeRun, parse_native_command,
)


IMAGE = "sha256:" + "a" * 64


def command():
    return [
        "docker", "run", "--rm", "--name", "appsec-test", "--network", "none",
        "--read-only", "--user", "1000:1000", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "4g",
        "--pids-limit", "1024", "--tmpfs", "/tmp:rw,noexec,nosuid,size=1g",
        "--workdir", "/scratch", "--mount", "type=bind,src=/fixture/target,dst=/target,readonly",
        "--mount", "type=bind,src=/fixture/run/scratch,dst=/scratch",
        "--env", "HOME=/tmp", "--entrypoint", "python3", IMAGE, "worker.py",
    ]


def test_native_run_translation_preserves_application_intent():
    parsed = parse_native_command(command())
    assert parsed == NativeRun(
        "appsec-test", IMAGE, "python3", ("worker.py",), "1000:1000", "2", 4096, 1024,
        "none", (NativeMount("/fixture/target", "/target", True),
                 NativeMount("/fixture/run/scratch", "/scratch", False)),
        (("HOME", "/tmp"),), "/tmp:rw,noexec,nosuid,size=1g", "/scratch", None)
    argv = command()
    argv[argv.index("--workdir") + 1] = "/workspace/."
    argv[argv.index("--memory") + 1] = "512m"
    argv[argv.index("--cpus") + 1] = "0.5"
    argv[2:2] = ["--ulimit", "fsize=4096:4096"]
    assert parse_native_command(argv) == replace(
        parsed, working_directory="/workspace", memory_mb=512, cpu="0.5",
        file_size_limit_bytes=4096)


@pytest.mark.parametrize("argv,expected", [
    (["docker", "image", "inspect", "approved:local", "--format", "{{.Id}}"],
     NativeControl("image.inspect", "approved:local")),
    (["docker", "container", "inspect", "appsec-test", "--format", "{{.State.Running}}"],
     NativeControl("execution.status", "appsec-test")),
    (["docker", "rm", "--force", "appsec-test"], NativeControl("execution.remove", "appsec-test")),
    (["docker", "kill", "appsec-test"], NativeControl("execution.cancel", "appsec-test")),
])
def test_native_control_translation_is_enumerated(argv, expected):
    assert parse_native_command(argv) == expected


@pytest.mark.parametrize("extra", [
    ["--privileged"], ["--device", "/dev/kvm"], ["--pid", "host"], ["--userns", "host"],
    ["--cap-add", "SYS_ADMIN"], ["--security-opt", "seccomp=unconfined"],
    ["--label", "appsec-owner=forged"], ["--volume-from", "unowned"],
    ["--env", "DOCKER_HOST=unix:///run/docker.sock"], ["--env", "APPSEC_NATIVE_ENDPOINT=escape"],
    ["--mount", "type=volume,src=unowned,dst=/volume"],
    ["--mount", "type=bind,src=/host,dst=/escape,bind-propagation=rshared"],
    ["--mount", "type=bind,src=/host,src=/other,dst=/escape"],
    ["--mount", "type=bind,src=/host,dst=/scratch"], ["--ulimit", "nofile=100:100"],
    ["--ulimit", "fsize=100:200"], ["--tmpfs", "/run:rw,size=1g"],
])
def test_native_translation_rejects_unmodeled_options(extra):
    argv = command()
    argv[2:2] = extra
    with pytest.raises(ValueError):
        parse_native_command(argv)


@pytest.mark.parametrize("option,value", [
    ("--user", "0:0"), ("--network", "host"), ("--cap-drop", "NET_ADMIN"),
    ("--security-opt", "apparmor=unconfined"), ("--cpus", "NaN"), ("--cpus", "0"),
    ("--memory", "0m"), ("--pids-limit", "-1"), ("--tmpfs", "/tmp:rw,size=1g"),
    ("--workdir", "/scratch/../host"),
])
def test_native_translation_rejects_weakened_required_limits(option, value):
    argv = command()
    argv[argv.index(option) + 1] = value
    with pytest.raises(ValueError):
        parse_native_command(argv)


@pytest.mark.parametrize("argv", [
    ["docker", "--host", "unix:///run/docker.sock", "info"],
    ["docker", "build", "."], ["docker", "image", "tag", IMAGE, "new:tag"],
    ["docker", "volume", "create", "unowned"], ["docker", "exec", "unowned", "sh"],
    ["docker", "inspect", "host", "--format", "{{json .Mounts}}"],
    ["docker", "rm", "--force", "unowned"], ["docker", "kill", "appsec-test", "second"],
    ["curl", "http://daemon/containers/json"],
])
def test_native_translation_has_no_ambient_or_maintenance_fallback(argv):
    with pytest.raises(ValueError):
        parse_native_command(argv)


def test_native_translation_bounds_messages_and_requires_immutable_image():
    argv = command()
    argv[-2] = "mutable:tag"
    with pytest.raises(ValueError):
        parse_native_command(argv)
    argv = command()
    argv[-1] = "x" * 65537
    with pytest.raises(ValueError):
        parse_native_command(argv)
