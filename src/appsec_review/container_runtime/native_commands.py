"""Closed translation of application-generated Docker commands, never a CLI tunnel."""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from pathlib import PurePosixPath
import re
from typing import Sequence

from appsec_review.config.image_builder_service import IMAGE_ID, absolute


@dataclass(frozen=True)
class NativeMount:
    source: str
    target: str
    read_only: bool


@dataclass(frozen=True)
class NativeRun:
    name: str
    image_id: str
    executable: str
    arguments: tuple[str, ...]
    user: str
    cpu: str
    memory_mb: int
    pids: int
    network: str
    mounts: tuple[NativeMount, ...]
    environment: tuple[tuple[str, str], ...]
    tmpfs: str
    working_directory: str
    file_size_limit_bytes: int | None


@dataclass(frozen=True)
class NativeControl:
    operation: str
    reference: str


def _mount(value: str, *, volume_syntax: bool = False) -> NativeMount:
    if volume_syntax:
        parts = value.split(":")
        if len(parts) != 3 or parts[2] not in {"ro", "rw"}:
            raise ValueError("native bind volume syntax must specify an explicit access mode")
        return NativeMount(absolute(parts[0]), absolute(parts[1]), parts[2] == "ro")
    fields: dict[str, str] = {}
    for part in value.split(","):
        key, separator, item = part.partition("=")
        if key in fields or (not separator and key != "readonly"):
            raise ValueError("ambiguous native bind mount")
        fields[key] = item
    if (set(fields) not in ({"type", "src", "dst"}, {"type", "src", "dst", "readonly"})
            or fields["type"] != "bind" or fields.get("readonly", "") != ""):
        raise ValueError("native execution accepts only explicit bind mounts")
    return NativeMount(absolute(fields["src"]), absolute(fields["dst"]), "readonly" in fields)


def parse_native_command(argv: Sequence[str]) -> NativeRun | NativeControl:
    if (not argv or len(argv) > 2048 or any(not isinstance(value, str) or "\0" in value for value in argv)
            or sum(len(value.encode("utf-8")) for value in argv) > 65536 or argv[0] != "docker"):
        raise ValueError("invalid bounded native command")
    command = tuple(argv)
    if (len(command) == 6 and command[:3] == ("docker", "image", "inspect")
            and command[4:] == ("--format", "{{.Id}}")):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}", command[3]):
            raise ValueError("invalid native image reference")
        return NativeControl("image.inspect", command[3])
    if (len(command) == 6 and command[:3] == ("docker", "container", "inspect")
            and command[4:] == ("--format", "{{.State.Running}}")):
        operation, name = "execution.status", command[3]
    elif len(command) == 4 and command[:3] == ("docker", "rm", "--force"):
        operation, name = "execution.remove", command[3]
    elif len(command) == 3 and command[:2] == ("docker", "kill"):
        operation, name = "execution.cancel", command[2]
    else:
        operation, name = "", ""
    if operation:
        if not re.fullmatch(r"appsec[-a-z0-9]{1,100}", name):
            raise ValueError("native container name is not application-scoped")
        return NativeControl(operation, name)
    if command[:2] != ("docker", "run"):
        raise ValueError("unsupported native engine operation; ambient Docker fallback is prohibited")
    flags: set[str] = set()
    options: dict[str, str] = {}
    mounts: list[NativeMount] = []
    environment: dict[str, str] = {}
    single = {"--name", "--network", "--user", "--cap-drop", "--security-opt", "--cpus",
              "--memory", "--pids-limit", "--tmpfs", "--workdir", "--entrypoint", "--ulimit"}
    index = 2
    while index < len(command) and command[index].startswith("-"):
        option = command[index]
        index += 1
        if option in {"--rm", "--read-only"}:
            if option in flags:
                raise ValueError("duplicate native execution flag")
            flags.add(option)
            continue
        if option not in single | {"--mount", "-v", "--env"} or index == len(command):
            raise ValueError(f"unsupported native execution option: {option}")
        value = command[index]
        index += 1
        if option in {"--mount", "-v"}:
            mounts.append(_mount(value, volume_syntax=option == "-v"))
        elif option == "--env":
            key, separator, item = value.partition("=")
            if (not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key)
                    or key.startswith(("DOCKER_", "APPSEC_NATIVE_"))):
                raise ValueError("native worker environment cannot select or access an engine")
            environment[key] = item
        else:
            if option in options:
                raise ValueError("duplicate native execution option")
            options[option] = value
    required = single - {"--ulimit"}
    if (flags != {"--rm", "--read-only"} or not required <= options.keys()
            or index == len(command) or not IMAGE_ID.fullmatch(command[index])):
        raise ValueError("native execution requires complete isolation and an immutable image ID")
    if (options["--cap-drop"] != "ALL" or options["--security-opt"] != "no-new-privileges"
            or options["--network"] not in {"none", "bridge"}
            or not re.fullmatch(r"[1-9][0-9]{0,9}:[1-9][0-9]{0,9}", options["--user"])
            or not re.fullmatch(r"appsec[-a-z0-9]{1,100}", options["--name"])):
        raise ValueError("native isolation policy cannot be weakened")
    cpu = options["--cpus"]
    memory = options["--memory"]
    if (not re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3})?", cpu) or not 0 < Decimal(cpu) <= 128
            or not re.fullmatch(r"[1-9][0-9]{0,5}[mg]", memory)
            or not re.fullmatch(r"[1-9][0-9]{0,4}", options["--pids-limit"])):
        raise ValueError("native resource limits must be finite and positive")
    memory_mb = int(memory[:-1]) * (1024 if memory[-1] == "g" else 1)
    pids = int(options["--pids-limit"])
    if memory_mb > 524288 or pids > 65536:
        raise ValueError("native resource limits exceed the protocol bound")
    if not re.fullmatch(r"/tmp:rw,(?:noexec|exec),nosuid,(?:nodev,)?size=[1-9][0-9]{0,5}[mg]",
                        options["--tmpfs"]):
        raise ValueError("native tmpfs requires a bounded private /tmp")
    if (not mounts or len(mounts) > 64 or len({mount.target for mount in mounts}) != len(mounts)
            or len(environment) > 128):
        raise ValueError("native mounts or environment exceed their bounds or repeat destinations")
    executable = options["--entrypoint"]
    if not executable or len(executable) > 4096:
        raise ValueError("native execution requires an explicit executable")
    limit = None
    if "--ulimit" in options:
        match = re.fullmatch(r"fsize=([1-9][0-9]{0,18}):\1", options["--ulimit"])
        if match is None or int(match[1]) > 2**63 - 1:
            raise ValueError("native execution supports only equal bounded fsize limits")
        limit = int(match[1])
    return NativeRun(
        options["--name"], command[index], executable, command[index + 1:], options["--user"],
        cpu, memory_mb, pids, options["--network"], tuple(mounts), tuple(sorted(environment.items())),
        options["--tmpfs"], absolute(str(PurePosixPath(options["--workdir"]))), limit)
