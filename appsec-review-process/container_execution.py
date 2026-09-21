#!/usr/bin/env python3
"""Pinned-container argv adapter (backlog batch B13): ``appsec-review/pinned-container-adapter/1.0``.

One request, one registry-pinned image, one argv array, one container, one terminal result.

* The image is resolved from ``registry/container-images/`` to ``repository@sha256:digest``. The
  reference handed to docker is built from the registry record, never from the request.
* The docker command line is a list built by :func:`build_docker_argv` and executed without a
  shell through ``deterministic_child.execute_child`` (process gate, process-tree teardown,
  bounded stdout/stderr retention, timeout, cooperative cancellation).
* The boundary flags are the versioned constant :data:`BOUNDARY_FLAGS`
  (``appsec-review/container-boundary/1.0``), equivalent to ``images/audit-native/run.sh``. No
  request property can add, remove or reorder one of them.
* Targets are mounted read-only; exactly one run-owned scratch directory, created by the adapter
  beneath the attempt root, is writable. Path identity is decided by device and inode.
* The network is ``none``. A request may *ask* for fixed destinations, and the B11 permission gate
  is evaluated for every request, but boundary 1.0 has no egress filter, so a granted network
  request ends ``BLOCKED`` (``NETWORK_ENFORCEMENT_UNAVAILABLE``) instead of opening a bridge.
* The container is always removed by its run-owned name, and the result says so.

Order is part of the contract: every hostile request is rejected before a directory is created or
a process is started, and no value read from a request, the attempt or the container is echoed
into an error message. See ``docs/pinned-container-adapter.md``.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import deterministic_child  # noqa: E402
from execution_state import atomic_bytes, beneath  # noqa: E402
import permission_capabilities as pc  # noqa: E402
from schema_validate import SchemaStore, validate_document  # noqa: E402
from tool_instance_shapes import output_path_errors  # noqa: E402

ADAPTER_ID = "appsec-review/pinned-container-adapter/1.0"
BOUNDARY_ID = "appsec-review/container-boundary/1.0"
REQUEST_ID = "appsec-review/pinned-container-request/1.0"
RESULT_ID = "appsec-review/pinned-container-result/1.0"
IMAGE_RECORD_ID = "appsec-review/container-image/1.0"
FINGERPRINT_ID = "appsec-review/pinned-container-fingerprint/1.0"

REQUEST_SCHEMA = "pinned-container-request.schema.json"
RESULT_SCHEMA = "pinned-container-result.schema.json"
IMAGE_SCHEMA = "container-image.schema.json"

IMAGES_DIR = ROOT / "registry" / "container-images"
WORKER_KIND = "pinned_container"
RESULT_FILE = "container-result.json"
REQUEST_FILE = "request.json"
CHILD_FILES = ("command.json", "events.jsonl", "stderr.log", "stdout.log")

SCRATCH_TARGET = "/scratch"
CONTAINER_HOME = "/tmp"
CONTAINER_HOSTNAME = "appsec-worker"

# The hostile-execution boundary (design-v3 section 2.2). Order and content are fixed; the only
# values interpolated around it are validated integers, the run-owned name, the adapter-chosen
# non-root user, adapter-checked mount sources and allow-listed environment names.
BOUNDARY_FLAGS: tuple[str, ...] = (
    "--pull", "never",
    "--log-driver", "none",
    "--network", "none",
    "--hostname", CONTAINER_HOSTNAME, "--add-host", CONTAINER_HOSTNAME + ":127.0.0.1",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--workdir", SCRATCH_TARGET,
    "--env", "HOME=" + CONTAINER_HOME,
)
# Options that may appear before the image, each with how many times. Anything else is a defect.
_ALLOWED_OPTION_COUNTS = {
    "--name": 1, "--label": 2, "--pull": 1, "--log-driver": 1, "--network": 1, "--hostname": 1,
    "--add-host": 1, "--read-only": 1, "--cap-drop": 1, "--security-opt": 1, "--workdir": 1,
    "--user": 1, "--pids-limit": 1, "--memory": 1, "--memory-swap": 1, "--cpus": 1, "--tmpfs": 1,
}
_FLAG_OPTIONS = {"--read-only"}

ENVIRONMENT_NAMES = ("LANG", "LC_ALL", "NO_COLOR", "SOURCE_DATE_EPOCH", "TZ", "XDG_CACHE_HOME")
# Host variables the docker *client* may see. None of them reaches the container: the adapter
# never emits ``--env NAME`` without a value and never emits ``--env-file``.
CLIENT_ENVIRONMENT_NAMES = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "PROGRAMDATA",
                            "LOCALAPPDATA", "APPDATA")

LIMIT_BOUNDS: Mapping[str, tuple[int, int]] = MappingProxyType({
    "timeout_seconds": (1, 86_400),
    "memory_bytes": (16 * 1024 * 1024, 64 * 1024 * 1024 * 1024),
    "cpu_millis": (100, 64_000),
    "pids": (1, 8_192),
    "tmpfs_bytes": (1024 * 1024, 4 * 1024 * 1024 * 1024),
    "stdout_limit_bytes": (1, deterministic_child.MAX_CONFIGURED_LOG_BYTES),
    "stderr_limit_bytes": (1, deterministic_child.MAX_CONFIGURED_LOG_BYTES),
})
MAX_ARGV_MEMBERS = 256
MAX_ARGV_MEMBER_CHARS = 4_096
MAX_ARGV_TOTAL_CHARS = 65_536
MAX_MOUNTS = 16
MAX_DESTINATIONS = 16
MAX_PATH_CHARS = 1_024
MAX_RESULT_BYTES = 1024 * 1024
DOCKER_CONTROL_TIMEOUT_SECONDS = 60

BLOCKED_CAUSES = ("PERMISSION_DENIED", "NETWORK_NOT_GRANTED", "NETWORK_ENFORCEMENT_UNAVAILABLE",
                  "DOCKER_UNAVAILABLE", "IMAGE_NOT_PROVISIONED")
STATUS_BY_CAUSE: Mapping[str | None, str] = MappingProxyType({
    None: "OK",
    **{cause: "BLOCKED" for cause in BLOCKED_CAUSES},
    "CONTAINER_START_FAILED": "FAILED",
    "CONTAINER_EXIT_NONZERO": "FAILED",
    "TIMEOUT": "FAILED",
    "WORKER_LOST": "FAILED",
    "OOM_KILLED": "FAILED",
    "LOG_WRITE_FAILED": "FAILED",
    "CLEANUP_FAILED": "FAILED",
    "CANCELED": "CANCELED",
})
SUMMARIES: Mapping[str | None, str] = MappingProxyType({
    None: "pinned container exited 0 inside the boundary and was removed",
    "PERMISSION_DENIED": "the permission gate did not re-derive a GRANTED decision; no container was started",
    "NETWORK_NOT_GRANTED": "a requested network destination is not in the granted capability set; no container was started",
    "NETWORK_ENFORCEMENT_UNAVAILABLE": "container boundary 1.0 cannot restrict egress to fixed destinations; no container was started",
    "DOCKER_UNAVAILABLE": "no docker daemon answered the adapter; no container was started",
    "IMAGE_NOT_PROVISIONED": "the pinned image digest is not present on this host and the adapter never pulls; no container was started",
    "CONTAINER_START_FAILED": "docker could not start the container process",
    "CONTAINER_EXIT_NONZERO": "the container process exited non-zero",
    "TIMEOUT": "the container exceeded its required timeout and was removed",
    "WORKER_LOST": "the container or its docker client ended without the adapter asking",
    "OOM_KILLED": "the container exceeded its required memory limit",
    "LOG_WRITE_FAILED": "retained diagnostics could not be written; the run is not a success",
    "CLEANUP_FAILED": "the adapter could not prove that the container was removed",
    "CANCELED": "the container was canceled and removed",
})

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,119}\Z")
_SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_USER_RE = re.compile(r"[1-9][0-9]{0,9}:[0-9]{1,10}\Z")
_PATH_FORBIDDEN_RE = re.compile(r"[\x00-\x1f\x7f,\"]")
_WINDOWS_FORBIDDEN_RE = re.compile(r"[<>|?*:/]")
_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(10)],
                     *[f"LPT{i}" for i in range(10)]}
_ARGV_FORBIDDEN_RE = re.compile(r"[\x00\n\r]")
_EXECUTABLE_RE = re.compile(r"/[^\x00-\x1f\x7f]{1,1023}\Z")


class ContainerRequestError(ValueError):
    """The request, the runtime or a path is unacceptable. Raised before anything is created or
    started. Messages name positions and rules only; they never quote a request value."""


class ContainerExecutionError(RuntimeError):
    """The adapter could not persist its own terminal result. Never a success."""


@dataclass(frozen=True)
class ContainerRuntime:
    """Trusted, integrator-supplied side of one execution. Every field is required."""
    docker_executable: Path
    docker_host: str | None
    images_dir: Path
    host_flavor: str
    container_user: str
    source_snapshot_sha256: str
    registry_ceiling: list | None
    clock: Callable[[], str]
    cancel: threading.Event


# ---- small helpers -------------------------------------------------------------------------------

def _sha(value: Any) -> str:
    return "sha256:" + pc.digest(value)


def _bytes_sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def canonical_request_bytes(request: Mapping[str, Any]) -> bytes:
    return (json.dumps(request, indent=2, sort_keys=True) + "\n").encode("utf-8")


def request_sha256(request: Mapping[str, Any]) -> str:
    return _sha(request)


def boundary_sha256() -> str:
    """Identity of everything the boundary fixes, for fingerprints and results."""
    return _sha({"schema": BOUNDARY_ID, "flags": list(BOUNDARY_FLAGS),
                 "environment_names": list(ENVIRONMENT_NAMES), "scratch_target": SCRATCH_TARGET,
                 "limit_bounds": {name: list(bounds) for name, bounds in LIMIT_BOUNDS.items()}})


def freeze(value: Any) -> Any:
    """Deeply immutable view, so a returned record cannot drift from what was verified."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(item) for item in value)
    return value


def thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [thaw(item) for item in value]
    return value


def container_name(run_id: str, job_id: str, attempt_id: str) -> str:
    """Run-owned, derivable name: one container per attempt, removable after a crash."""
    for value in (run_id, job_id, attempt_id):
        if not isinstance(value, str) or not _ID_RE.match(value):
            raise ContainerRequestError("run_id, job_id and attempt_id must be identifiers")
    return "appsec-" + pc.digest([ADAPTER_ID, run_id, job_id, attempt_id])[:32]


# ---- pure path translation (Windows-host / Linux-worker parity) ----------------------------------

def translate_host_path(path: Any, flavor: str) -> str:
    """One absolute, normalized spelling of a host directory, safe inside ``--mount``'s CSV.

    POSIX: ``/a/b``. Windows: ``C:\\a\\b`` (what Docker Desktop accepts as a bind source). UNC,
    device, drive-relative, forward-slash, relative and alias spellings are rejected, never
    normalized: two spellings of one directory must not both be acceptable.
    """
    if flavor not in ("posix", "windows"):
        raise ContainerRequestError("host flavor must be 'posix' or 'windows'")
    if not isinstance(path, str) or not path or len(path) > MAX_PATH_CHARS:
        raise ContainerRequestError("host path must be a non-empty bounded string")
    if _PATH_FORBIDDEN_RE.search(path) or path != path.strip():
        raise ContainerRequestError(
            "host path carries a control character, a comma, a double quote or outer whitespace")
    if flavor == "posix":
        if not path.startswith("/") or path.startswith("//"):
            raise ContainerRequestError("POSIX host path must be absolute with a single leading '/'")
        segments = path[1:].split("/")
    else:
        if path.startswith(("\\\\", "//")):
            raise ContainerRequestError("UNC and device host paths are not supported")
        if not re.match(r"[A-Za-z]:\\", path):
            raise ContainerRequestError("Windows host path must start with a drive letter and '\\'")
        segments = path[3:].split("\\")
        for segment in segments:
            if (_WINDOWS_FORBIDDEN_RE.search(segment) or segment.endswith((" ", "."))
                    or segment.split(".")[0].upper() in _WINDOWS_RESERVED) and segment not in (".", ".."):
                raise ContainerRequestError(
                    "Windows host path segment carries a forbidden character, a trailing dot or "
                    "space, or a reserved device name")
    if any(segment in ("", ".", "..") for segment in segments):
        raise ContainerRequestError(
            "host path must not be a filesystem root and must not contain '.', '..' or empty segments")
    return path


def docker_client_environment(host_environment: Mapping[str, str], docker_host: str | None
                              ) -> dict[str, str]:
    """Explicit environment for the docker client. Host DOCKER_* variables never pass through."""
    env = {name: host_environment[name] for name in CLIENT_ENVIRONMENT_NAMES
           if isinstance(host_environment.get(name), str) and "\x00" not in host_environment[name]}
    env.setdefault("PATH", os.defpath)
    if docker_host is not None:
        env["DOCKER_HOST"] = docker_host
    return env


# ---- request validation (pure) -------------------------------------------------------------------

def _argv_errors(argv: list) -> list[str]:
    errors: list[str] = []
    if len(argv) > MAX_ARGV_MEMBERS:
        errors.append(f"argv has more than {MAX_ARGV_MEMBERS} members")
    total = 0
    for index, member in enumerate(argv):
        if not isinstance(member, str):
            errors.append(f"argv[{index}] is not a string")
            continue
        total += len(member)
        if len(member) > MAX_ARGV_MEMBER_CHARS:
            errors.append(f"argv[{index}] is longer than {MAX_ARGV_MEMBER_CHARS} characters")
        if _ARGV_FORBIDDEN_RE.search(member):
            errors.append(f"argv[{index}] contains a NUL, newline or carriage return")
    if total > MAX_ARGV_TOTAL_CHARS:
        errors.append(f"argv is longer than {MAX_ARGV_TOTAL_CHARS} characters in total")
    first = argv[0] if argv and isinstance(argv[0], str) else ""
    if not _EXECUTABLE_RE.match(first) or any(
            segment in ("", ".", "..") for segment in first[1:].split("/")):
        errors.append("argv[0] must be one normalized absolute path inside the container")
    elif first.rsplit("/", 1)[1].lower() in deterministic_child.SHELL_EXECUTABLES:
        errors.append("argv[0] is a shell executable; the adapter runs argv arrays, not shell strings")
    return errors


def request_errors(request: Any, *, run_id: str, job_id: str, attempt_id: str,
                   store: SchemaStore | None = None) -> list[str]:
    """Closed schema first, then every bound the schema subset cannot express. Pure."""
    if isinstance(request, Mapping) and isinstance(request.get("argv"), list):
        # Named before the schema so a non-string member is reported by position, not by value.
        bad = [f"argv[{i}] is not a string" for i, member in enumerate(request["argv"])
               if not isinstance(member, str)]
        if bad:
            return bad
    schema_errors = validate_document(request, REQUEST_SCHEMA, store or SchemaStore())
    if schema_errors:
        return [f"request fails its closed schema ({len(schema_errors)} errors)"]
    errors: list[str] = []
    for name, expected in (("run_id", run_id), ("job_id", job_id), ("attempt_id", attempt_id)):
        if request[name] != expected:
            errors.append(f"request.{name} is not the {name} of the worker request it arrived in")
    errors.extend(_argv_errors(request["argv"]))
    names = [entry["name"] for entry in request["environment"]]
    if len(names) != len(set(names)):
        errors.append("environment repeats a name")
    mounts = request["target_mounts"]
    if len(mounts) > MAX_MOUNTS:
        errors.append(f"more than {MAX_MOUNTS} target mounts")
    targets = [mount["container_path"] for mount in mounts]
    if len(targets) != len(set(targets)):
        errors.append("two target mounts share one container path")
    for label in ("scratch_path", "log_path"):
        if output_path_errors(request[label]):
            errors.append(f"{label} is not one normalized relative path inside the attempt")
    scratch, log = request["scratch_path"].split("/"), request["log_path"].split("/")
    shorter = min(len(scratch), len(log))
    if [part.lower() for part in scratch[:shorter]] == [part.lower() for part in log[:shorter]]:
        errors.append("scratch_path and log_path must not be equal or contain one another")
    for name, (low, high) in LIMIT_BOUNDS.items():
        value = request["limits"][name]
        if not _is_int(value) or not low <= value <= high:
            errors.append(f"limits.{name} must be an integer within {low}..{high}")
    network = request["network"]
    destinations = network["destinations"]
    if network["mode"] == "none" and destinations:
        errors.append("network mode 'none' cannot list destinations")
    if network["mode"] != "none" and not destinations:
        errors.append("network mode 'granted-fixed-destinations' must list at least one destination")
    if len(destinations) > MAX_DESTINATIONS:
        errors.append(f"more than {MAX_DESTINATIONS} network destinations")
    keys = []
    for index, destination in enumerate(destinations):
        if not _is_int(destination["port"]) or not 1 <= destination["port"] <= 65_535:
            errors.append(f"network.destinations[{index}].port must be an integer within 1..65535")
        keys.append(json.dumps(destination, sort_keys=True))
    if len(keys) != len(set(keys)):
        errors.append("network destinations repeat")
    return errors


def fingerprint_material(request: Mapping[str, Any], image_record: Mapping[str, Any]) -> dict[str, Any]:
    """What an integrator folds into a job input fingerprint for one container request.

    The permission block is represented by the B11 capability fingerprint, which deliberately
    excludes grant ids and timestamps, so re-issuing an identical approval does not change it.
    """
    decision = request["permission"]["decision"]
    body = {
        "schema": FINGERPRINT_ID,
        "adapter": ADAPTER_ID,
        "boundary_sha256": boundary_sha256(),
        "image_reference": image_reference(image_record),
        "image_record_sha256": _sha(image_record),
        "permission_fingerprint_sha256": pc.input_fingerprint_component(decision),
        "request_without_permission_sha256": _sha(
            {key: value for key, value in request.items() if key != "permission"}),
    }
    return {**body, "sha256": _sha(body)}


# ---- image registry ------------------------------------------------------------------------------

def load_image_registry(directory: Path, store: SchemaStore | None = None) -> dict[str, dict[str, Any]]:
    directory = Path(directory)
    store = store or SchemaStore()
    records: dict[str, dict[str, Any]] = {}
    paths = sorted(directory.glob("*.json")) if directory.is_dir() else []
    if not paths:
        raise ContainerRequestError("container image registry is missing or empty")
    for path in paths:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise ContainerRequestError(f"{path.name}: unreadable container image record") from None
        errors = validate_document(record, IMAGE_SCHEMA, store)
        if errors:
            raise ContainerRequestError(f"{path.name}: invalid container image record ({len(errors)} errors)")
        if record["image_id"] != path.stem:
            raise ContainerRequestError(f"{path.name}: image_id and file name must agree")
        records[record["image_id"]] = record
    return records


def image_reference(record: Mapping[str, Any]) -> str:
    return f"{record['repository']}@{record['digest']}"


def resolve_image(image: Mapping[str, Any], registry: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """The request names a registry id and repeats the digest it expects; both must agree with the
    registry. A digest, tag or name that the registry does not hold cannot be run."""
    record = registry.get(image["image_id"])
    if record is None:
        raise ContainerRequestError("image.image_id is not a registered container image")
    if image["digest"] != record["digest"]:
        raise ContainerRequestError("image.digest is not the digest registered for image.image_id")
    return dict(record)


# ---- docker argv (pure) --------------------------------------------------------------------------

def build_docker_argv(*, docker_executable: str, name: str, user: str, image_ref: str,
                      limits: Mapping[str, int], environment: Iterable[Mapping[str, str]],
                      mounts: Iterable[tuple[str, str]], scratch_source: str,
                      argv: Iterable[str]) -> tuple[str, ...]:
    """``docker run`` as a list. Every argument is required; nothing here reads the host."""
    argv = tuple(argv)
    if not re.match(r"appsec-[0-9a-f]{32}\Z", name):
        raise ContainerRequestError("container name is not run-owned")
    if not isinstance(user, str) or not _USER_RE.match(user):
        raise ContainerRequestError("container user must be a numeric non-root uid:gid")
    if not re.match(r"[a-z0-9][a-z0-9._:/-]{0,254}@sha256:[0-9a-f]{64}\Z", image_ref):
        raise ContainerRequestError("image reference is not repository@sha256:digest")
    command = [
        docker_executable, "run", "--name", name,
        "--label", "appsec-review.adapter=" + ADAPTER_ID,
        "--label", "appsec-review.container=" + name,
        *BOUNDARY_FLAGS,
        "--user", user,
        "--pids-limit", str(limits["pids"]),
        "--memory", str(limits["memory_bytes"]),
        "--memory-swap", str(limits["memory_bytes"]),
        "--cpus", f"{limits['cpu_millis'] // 1000}.{limits['cpu_millis'] % 1000:03d}",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={limits['tmpfs_bytes']}",
    ]
    for entry in environment:
        if entry["name"] not in ENVIRONMENT_NAMES:
            raise ContainerRequestError("environment name is not on the boundary allow-list")
        command += ["--env", f"{entry['name']}={entry['value']}"]
    for source, target in mounts:
        command += ["--mount", f"type=bind,source={source},target={target},readonly"]
    command += ["--mount", f"type=bind,source={scratch_source},target={SCRATCH_TARGET}"]
    command += ["--entrypoint=" + argv[0], image_ref, *argv[1:]]
    result = tuple(command)
    assert_boundary(result, image_ref)
    return result


def assert_boundary(command: tuple[str, ...], image_ref: str) -> None:
    """Defence in depth over the built list: exactly the boundary options, exactly once, before
    the image; one writable mount, at the scratch target; nothing else docker would parse."""
    if command[1] != "run" or image_ref not in command:
        raise ContainerRequestError("docker argv is not a run of the pinned image")
    options = command[2:command.index(image_ref)]
    counts: dict[str, int] = {}
    writable = 0
    index = 0
    while index < len(options):
        option = options[index]
        if option.startswith("--entrypoint=") and index == len(options) - 1:
            index += 1
            continue
        if option in ("--env", "--mount"):
            value = options[index + 1]
            if option == "--env" and "=" not in value:
                raise ContainerRequestError("docker argv would pass a host environment variable through")
            if option == "--mount":
                if not value.startswith("type=bind,source=") or value.count(",") not in (2, 3):
                    raise ContainerRequestError("docker argv carries a mount that is not a plain bind")
                if not value.endswith(",readonly"):
                    writable += 1
                    if not value.endswith(",target=" + SCRATCH_TARGET):
                        raise ContainerRequestError("docker argv carries a writable mount that is not scratch")
            index += 2
            continue
        if option not in _ALLOWED_OPTION_COUNTS:
            raise ContainerRequestError("docker argv carries an option outside the boundary")
        counts[option] = counts.get(option, 0) + 1
        index += 1 if option in _FLAG_OPTIONS else 2
    if counts != _ALLOWED_OPTION_COUNTS or writable != 1:
        raise ContainerRequestError("docker argv does not carry each boundary option exactly once")
    width = len(BOUNDARY_FLAGS)
    if not any(options[at:at + width] == BOUNDARY_FLAGS for at in range(len(options) - width + 1)):
        raise ContainerRequestError("docker argv does not carry the boundary flags verbatim and in order")


# ---- filesystem identity -------------------------------------------------------------------------

def _identity(path: Path) -> tuple[int, int] | None:
    try:
        status = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    return (status.st_dev, status.st_ino)


def _chain(path: Path) -> set[tuple[int, int]]:
    """Identities of a path and every existing ancestor."""
    found = set()
    for part in [path, *path.parents]:
        identity = _identity(part)
        if identity is not None:
            found.add(identity)
    return found


def sensitive_locations(*, home: Path | None, attempt_root: Path, docker_host: str | None
                        ) -> tuple[list[Path], list[Path]]:
    """(never expose, never enter). A mount may not be, or contain, anything in the first list,
    and may not be, or be inside, anything in the second."""
    sockets = [Path("/var/run/docker.sock"), Path("/run/docker.sock")]
    if docker_host and docker_host.startswith("unix://"):
        sockets.append(Path(docker_host[len("unix://"):]))
    expose = [attempt_root, *sockets]
    enter = [attempt_root, Path("/proc"), Path("/sys"), Path("/dev"), Path("/etc"), Path("/run"),
             Path("/var/run")]
    if home is not None:
        expose.append(home)
        enter += [home / name for name in (".ssh", ".aws", ".docker", ".gnupg", ".kube", ".config",
                                           ".azure", ".netrc")]
    return expose, enter


def checked_mount_sources(mounts: list[Mapping[str, str]], *, flavor: str, expose: list[Path],
                          enter: list[Path]) -> list[tuple[str, str]]:
    """Returns (docker source, container target) pairs, or raises. Identity is device+inode."""
    forbidden_exposed: set[tuple[int, int]] = set()
    for location in expose:
        forbidden_exposed |= _chain(Path(location))
    forbidden_entered = {identity for identity in (_identity(Path(p)) for p in enter) if identity}
    seen: set[tuple[int, int]] = set()
    pairs: list[tuple[str, str]] = []
    for index, mount in enumerate(mounts):
        label = f"target_mounts[{index}].host_path"
        try:
            source = translate_host_path(mount["host_path"], flavor)
        except ContainerRequestError as exc:
            raise ContainerRequestError(f"{label}: {exc}") from None
        path = Path(source)
        try:
            status = os.stat(path, follow_symlinks=False)
        except OSError:
            raise ContainerRequestError(f"{label}: does not exist") from None
        if not stat.S_ISDIR(status.st_mode):
            raise ContainerRequestError(f"{label}: is a link, a socket, a device or a file, not a directory")
        if os.path.normcase(os.path.realpath(path)) != os.path.normcase(source):
            raise ContainerRequestError(f"{label}: is reached through a link or is not its one real spelling")
        identity = (status.st_dev, status.st_ino)
        if identity in forbidden_exposed:
            raise ContainerRequestError(
                f"{label}: is or contains the attempt, the host home, the docker socket or a filesystem root")
        if _chain(path) & forbidden_entered:
            raise ContainerRequestError(
                f"{label}: is inside the attempt, a credential directory or a host system directory")
        if identity in seen:
            raise ContainerRequestError(f"{label}: is the same directory as an earlier target mount")
        seen.add(identity)
        pairs.append((source, mount["container_path"]))
    return pairs



def request_mount_sources(request: Mapping[str, Any], *, attempt_root: Path, host_flavor: str,
                          docker_host: str | None) -> list[tuple[str, str]]:
    """The ONE rule for which host directories a request may mount, used by the execution path and
    by the verification path alike. PR 29 review: ``run_container`` applied it and
    ``verify_container_result`` did not, so the verifier (and ``to_worker_envelope`` behind it)
    certified a self-consistent attempt whose request mounted ``/etc``, the host home, the attempt
    itself or the docker socket -- states the adapter can never produce. Two callers, one
    definition: they cannot drift. Identity is device+inode on THIS host at THIS moment; a mount
    source that has since vanished or become sensitive fails closed."""
    expose, enter = sensitive_locations(home=Path.home(), attempt_root=Path(attempt_root),
                                        docker_host=docker_host)
    return checked_mount_sources(request["target_mounts"], flavor=host_flavor, expose=expose, enter=enter)

# ---- runtime -------------------------------------------------------------------------------------

def host_defaults() -> dict[str, Any]:
    """Host-derived runtime fields. The integrator still supplies every permission-context field."""
    import shutil
    found = shutil.which("docker")
    user = "10001:10001"
    if hasattr(os, "getuid"):
        user = f"{os.getuid()}:{os.getgid()}"
    return {"docker_executable": Path(found).resolve() if found else None,
            "host_flavor": "windows" if os.name == "nt" else "posix", "container_user": user,
            "images_dir": IMAGES_DIR}


def validate_runtime(runtime: Any) -> None:
    if not isinstance(runtime, ContainerRuntime):
        raise TypeError("container execution requires a ContainerRuntime")
    docker = runtime.docker_executable
    if not isinstance(docker, Path) or not docker.is_absolute() or not docker.is_file() or docker.is_symlink():
        raise ContainerRequestError("runtime.docker_executable must be an absolute, existing, non-link file")
    if runtime.docker_host is not None and (
            not isinstance(runtime.docker_host, str)
            or not re.match(r"(unix|npipe|tcp|ssh)://[ -~]{1,512}\Z", runtime.docker_host)):
        raise ContainerRequestError("runtime.docker_host must be null or one docker endpoint URL")
    if runtime.host_flavor not in ("posix", "windows"):
        raise ContainerRequestError("runtime.host_flavor must be 'posix' or 'windows'")
    if not isinstance(runtime.container_user, str) or not _USER_RE.match(runtime.container_user):
        raise ContainerRequestError("runtime.container_user must be a numeric non-root uid:gid")
    if not isinstance(runtime.images_dir, Path):
        raise ContainerRequestError("runtime.images_dir must be a path")
    if not isinstance(runtime.source_snapshot_sha256, str) or not _SHA_RE.match(runtime.source_snapshot_sha256):
        raise ContainerRequestError("runtime.source_snapshot_sha256 must be sha256:<64 hex>")
    if runtime.registry_ceiling is not None and not isinstance(runtime.registry_ceiling, list):
        raise ContainerRequestError("runtime.registry_ceiling must be null or a list")
    if not callable(runtime.clock):
        raise ContainerRequestError("runtime.clock must be callable")
    if not isinstance(runtime.cancel, threading.Event):
        raise ContainerRequestError("runtime.cancel must be a threading.Event")


def _now(runtime: ContainerRuntime) -> str:
    value = runtime.clock()
    if not isinstance(value, str) or not _TS_RE.match(value):
        raise ContainerRequestError("runtime.clock must return a UTC timestamp like 2026-01-01T00:00:00Z")
    return value


def _docker(runtime: ContainerRuntime, arguments: list[str]) -> tuple[int | None, bytes]:
    """One short docker control call. Output is bounded and never reaches a message."""
    try:
        done = subprocess.run(
            [str(runtime.docker_executable), *arguments], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False,
            env=docker_client_environment(os.environ, runtime.docker_host),
            timeout=DOCKER_CONTROL_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return None, b""
    return done.returncode, done.stdout[:65_536]


def container_state(runtime: ContainerRuntime, name: str) -> dict[str, Any] | None:
    code, output = _docker(runtime, ["inspect", "--type", "container", "--format", "{{json .State}}", name])
    if code != 0:
        return None
    try:
        state = json.loads(output.decode("utf-8"))
    except ValueError:
        return None
    if not isinstance(state, dict):
        return None
    exit_code, status, oom = state.get("ExitCode"), state.get("Status"), state.get("OOMKilled")
    if not _is_int(exit_code) or not isinstance(status, str) or not isinstance(oom, bool):
        return None
    return {"exit_code": exit_code, "exited": status == "exited", "created": status == "created",
            "oom_killed": oom}


def remove_container(runtime: ContainerRuntime, name: str) -> bool:
    """Force-removes the run-owned container and proves it is gone. True only on proof."""
    _docker(runtime, ["rm", "--force", "--volumes", name])
    code, output = _docker(runtime, ["ps", "--all", "--quiet", "--no-trunc", "--filter", f"name=^/{name}$"])
    return code == 0 and output.strip() == b""


# ---- execution -----------------------------------------------------------------------------------

def _classify(metadata: Mapping[str, Any] | None, state: Mapping[str, Any] | None,
              interrupted: bool) -> tuple[str | None, int | None]:
    if interrupted:
        return "CANCELED", None
    if metadata is None:
        return "LOG_WRITE_FAILED", None
    error = metadata.get("error") or ""
    if error.startswith("diagnostic stream failure") or "diagnostic stream logging failed" in error:
        return "LOG_WRITE_FAILED", None
    if metadata.get("cancelled"):
        return "CANCELED", None
    if metadata.get("timed_out"):
        return "TIMEOUT", None
    client = metadata.get("exit_code")
    if error or not _is_int(client):
        return "WORKER_LOST", None
    if client in (125, 126, 127) and (state is None or state["created"]):
        return "CONTAINER_START_FAILED", None
    if state is None or not state["exited"]:
        return "WORKER_LOST", None
    if state["oom_killed"]:
        return "OOM_KILLED", state["exit_code"]
    if client != state["exit_code"] or state["exit_code"] == 137:
        return "WORKER_LOST", state["exit_code"]
    if state["exit_code"] == 0:
        return None, 0
    return "CONTAINER_EXIT_NONZERO", state["exit_code"]


def _log_files(log_dir: Path) -> list[dict[str, Any]]:
    records = []
    for name in sorted((REQUEST_FILE, *CHILD_FILES)):
        path = log_dir / name
        if path.is_file() and not path.is_symlink():
            data = beneath(log_dir, path).read_bytes()
            records.append({"path": name, "sha256": _bytes_sha(data), "bytes": len(data)})
    return records


def run_container(runtime: ContainerRuntime, *, run_id: str, job_id: str, attempt_id: str,
                  attempt_root: Path, request: Any) -> Mapping[str, Any]:
    """Validate, gate, run, remove, record. Returns a deeply immutable terminal result."""
    validate_runtime(runtime)
    try:
        request = json.loads(json.dumps(thaw(request), allow_nan=False))
    except (TypeError, ValueError):
        raise ContainerRequestError("request is not a JSON document") from None
    errors = request_errors(request, run_id=run_id, job_id=job_id, attempt_id=attempt_id)
    if errors:
        raise ContainerRequestError("container request rejected: " + "; ".join(errors))
    record = resolve_image(request["image"], load_image_registry(runtime.images_dir))
    image_ref = image_reference(record)
    name = container_name(run_id, job_id, attempt_id)

    attempt_root = Path(attempt_root)
    if not attempt_root.is_absolute() or not attempt_root.is_dir() or attempt_root.is_symlink():
        raise ContainerRequestError("attempt_root must be an absolute, existing, non-link directory")
    try:
        scratch = beneath(attempt_root, attempt_root.joinpath(*request["scratch_path"].split("/")))
        log_dir = beneath(attempt_root, attempt_root.joinpath(*request["log_path"].split("/")))
        scratch_source = translate_host_path(str(scratch), runtime.host_flavor)
    except ValueError:
        raise ContainerRequestError(
            "scratch_path or log_path leaves the attempt, crosses a link or is not mountable") from None
    if os.path.lexists(scratch) or os.path.lexists(log_dir):
        raise ContainerRequestError("scratch_path and log_path must not exist: the adapter creates them")
    mounts = request_mount_sources(request, attempt_root=attempt_root, host_flavor=runtime.host_flavor,
                                   docker_host=runtime.docker_host)
    command = build_docker_argv(
        docker_executable=str(runtime.docker_executable), name=name, user=runtime.container_user,
        image_ref=image_ref, limits=request["limits"], environment=request["environment"],
        mounts=mounts, scratch_source=scratch_source, argv=request["argv"])
    started_at = _now(runtime)
    decision = request["permission"]["decision"]
    permission_fingerprint = pc.fingerprint_material(decision["decision"], decision["capabilities"])["sha256"]

    # Nothing above created a file or started a process. From here on the attempt owns evidence.
    log_dir.parent.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(mode=0o700)
    atomic_bytes(log_dir / REQUEST_FILE, canonical_request_bytes(request))

    def finish(cause: str | None, exit_code: int | None, streams: Any, removed: bool) -> Mapping[str, Any]:
        result = {
            "schema": RESULT_ID, "adapter": ADAPTER_ID, "boundary": BOUNDARY_ID,
            "boundary_sha256": boundary_sha256(),
            "run_id": run_id, "job_id": job_id, "attempt_id": attempt_id,
            "request_sha256": request_sha256(request),
            "image_reference": image_ref, "image_record_sha256": _sha(record),
            "permission_fingerprint_sha256": permission_fingerprint,
            "container_name": name,
            "execution_status": STATUS_BY_CAUSE[cause], "cause": cause, "exit_code": exit_code,
            "started_at": started_at, "finished_at": max(started_at, _now(runtime)),
            "scratch_path": request["scratch_path"], "log_path": request["log_path"],
            "streams": streams, "files": _log_files(log_dir), "container_removed": removed,
        }
        result["result_sha256"] = result_sha256(result)
        try:
            atomic_bytes(log_dir / RESULT_FILE, canonical_request_bytes(result))
        except BaseException as exc:
            raise ContainerExecutionError("the container result could not be persisted") from exc
        return freeze(result)

    context = {"run_id": run_id, "job_id": job_id, "now": started_at,
               "source_snapshot_sha256": runtime.source_snapshot_sha256,
               "registry_ceiling": runtime.registry_ceiling}
    try:
        granted = pc.require_granted(decision, requirement=request["permission"]["requirement"],
                                     grants=request["permission"]["grants"], context=context)
    except pc.PermissionModelError:       # PermissionDenied, or a context the model refuses
        return finish("PERMISSION_DENIED", None, None, True)
    destinations = request["network"]["destinations"]
    if destinations:
        allowed = {(c["parameters"]["scheme"], c["parameters"]["host"], c["parameters"]["port"])
                   for c in granted if c["kind"] == "fixed-network-destination"}
        if any((d["scheme"], d["host"], d["port"]) not in allowed for d in destinations):
            return finish("NETWORK_NOT_GRANTED", None, None, True)
        return finish("NETWORK_ENFORCEMENT_UNAVAILABLE", None, None, True)
    if _docker(runtime, ["version", "--format", "{{.Server.Version}}"])[0] != 0:
        return finish("DOCKER_UNAVAILABLE", None, None, True)
    if _docker(runtime, ["image", "inspect", "--format", "{{.Id}}", image_ref])[0] != 0:
        return finish("IMAGE_NOT_PROVISIONED", None, None, True)
    if not remove_container(runtime, name):      # a crashed earlier owner of this exact attempt
        return finish("CLEANUP_FAILED", None, None, False)

    scratch.parent.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(mode=0o700)
    spec = deterministic_child.ChildExecutionSpec(
        argv=command, argv_prefix=command[:4], executable=runtime.docker_executable, cwd=log_dir,
        owner_root=attempt_root, log_dir=log_dir, timeout_seconds=request["limits"]["timeout_seconds"],
        stdout_limit_bytes=request["limits"]["stdout_limit_bytes"],
        stderr_limit_bytes=request["limits"]["stderr_limit_bytes"],
        env=docker_client_environment(os.environ, runtime.docker_host))
    metadata: dict | None = None
    interrupt: BaseException | None = None
    state = None
    removed = False
    try:
        try:
            metadata = deterministic_child.execute_child(spec, cancel=runtime.cancel)
        except (KeyboardInterrupt, SystemExit) as exc:
            interrupt = exc
        except BaseException:
            metadata = None
        if interrupt is None and metadata is not None:
            state = container_state(runtime, name)
    finally:
        removed = remove_container(runtime, name)
    cause, exit_code = _classify(metadata, state, interrupt is not None)
    if not removed:
        cause, exit_code = "CLEANUP_FAILED", None
    streams = None
    if metadata is not None and isinstance(metadata.get("streams"), dict):
        streams = {stream: {key: metadata["streams"][stream][key] for key in
                            ("observed_bytes", "written_bytes", "dropped_bytes", "truncated")}
                   for stream in ("stdout", "stderr")}
    result = finish(cause, exit_code, streams, removed)
    if interrupt is not None:
        raise interrupt
    return result


# ---- verification: a persisted result is a cache, never an authority -----------------------------

def result_sha256(result: Mapping[str, Any]) -> str:
    """Integrity hash over every other field. Not an authenticator: the verifier re-derives."""
    return _sha({key: value for key, value in thaw(result).items() if key != "result_sha256"})


def _command_record_errors(path: Path, *, request: Mapping[str, Any], image_ref: str, name: str,
                           cause: str | None, exit_code: int | None, streams: Any) -> list[str]:
    """``command.json`` is the child runner's own account of the docker client it ran. The result
    and that account are two projections of one run and must agree: the recorded docker argv is
    re-derived from the expected request (only the docker executable, the container user and the
    scratch source are host facts taken from the record, and each is re-validated), and the
    outcome the result claims must be one the recorded client exit allows."""
    from execution_state import redact_argv
    try:
        command = json.loads(path.read_bytes().decode("utf-8"))
        recorded = command["argv"]
        if not isinstance(recorded, list) or not all(isinstance(item, str) for item in recorded):
            raise ValueError
        user = recorded[recorded.index("--user") + 1]
        mounts = [recorded[at + 1] for at, item in enumerate(recorded[:-1]) if item == "--mount"]
        prefix, suffix = "type=bind,source=", ",target=" + SCRATCH_TARGET
        if not mounts or not mounts[-1].startswith(prefix) or not mounts[-1].endswith(suffix):
            raise ValueError
        scratch_source = mounts[-1][len(prefix):-len(suffix)]
        if re.split(r"[\\/]", scratch_source)[-len(request["scratch_path"].split("/")):] != \
                request["scratch_path"].split("/"):
            raise ValueError
        expected = build_docker_argv(
            docker_executable=recorded[0], name=name, user=user, image_ref=image_ref,
            limits=request["limits"], environment=request["environment"],
            mounts=[(mount["host_path"], mount["container_path"]) for mount in request["target_mounts"]],
            scratch_source=scratch_source, argv=request["argv"])
        client_exit, timed_out, cancelled = command["exit_code"], command["timed_out"], command["cancelled"]
        recorded_streams = {stream: {key: command["streams"][stream][key] for key in
                                     ("observed_bytes", "written_bytes", "dropped_bytes", "truncated")}
                            for stream in ("stdout", "stderr")}
        limits = (command["timeout_seconds"], command["log_limits"]["stdout"], command["log_limits"]["stderr"])
    except (OSError, ValueError, KeyError, IndexError, TypeError, ContainerRequestError):
        return ["command.json is not the child runner's record of a boundary docker run"]
    errors: list[str] = []
    if recorded != redact_argv(list(expected)):
        errors.append("command.json does not record the docker argv the expected request derives")
    if limits != (request["limits"]["timeout_seconds"], request["limits"]["stdout_limit_bytes"],
                  request["limits"]["stderr_limit_bytes"]):
        errors.append("command.json does not record the required timeout and retention limits")
    if cause != "LOG_WRITE_FAILED" and streams is not None and thaw(streams) != recorded_streams:
        errors.append("stream counts disagree with command.json")
    agrees = {
        None: client_exit == 0 and not timed_out and not cancelled,
        "CONTAINER_EXIT_NONZERO": client_exit == exit_code and not timed_out and not cancelled,
        "CONTAINER_START_FAILED": client_exit in (125, 126, 127) and not timed_out and not cancelled,
        "TIMEOUT": timed_out is True,
    }.get(cause, True)
    if not agrees:
        errors.append("the claimed outcome is not one the recorded docker client exit allows")
    return errors


def verify_container_result(attempt_root: Path, *, run_id: str, job_id: str, attempt_id: str,
                            request: Any, images_dir: Path, host_flavor: str,
                            docker_host: str | None) -> list[str]:
    """Re-derives the on-disk result from the expected request, the registry and the bytes.

    Every argument is required. Messages are fixed text: nothing read from the attempt is echoed.
    ``host_flavor`` and ``docker_host`` are the integrator's host facts (``ContainerRuntime``'s),
    needed to apply the same target-mount rule ``run_container`` applies: a request the adapter
    would refuse to run cannot have a verifiable result.
    """
    if host_flavor not in ("posix", "windows"):
        raise TypeError("host_flavor must be one of the adapter's host flavors")
    if docker_host is not None and not isinstance(docker_host, str):
        raise TypeError("docker_host must be a string or None")
    request = thaw(request)
    errors = request_errors(request, run_id=run_id, job_id=job_id, attempt_id=attempt_id)
    if errors:
        return ["the expected request is itself invalid: " + "; ".join(errors)]
    try:
        request_mount_sources(request, attempt_root=Path(attempt_root), host_flavor=host_flavor,
                              docker_host=docker_host)
    except ContainerRequestError:
        return ["the expected request mounts a host directory the adapter refuses to mount "
                "(missing, linked, sensitive, or the same directory twice): no run of it can exist"]
    try:
        record = resolve_image(request["image"], load_image_registry(Path(images_dir)))
    except ContainerRequestError:
        return ["the expected request names an image the registry does not hold at that digest"]
    attempt_root = Path(attempt_root)
    try:
        log_dir = beneath(attempt_root, attempt_root.joinpath(*request["log_path"].split("/")))
        present = set()
        for path in sorted(log_dir.iterdir()):
            beneath(log_dir, path)
            if not path.is_file():
                return ["the log directory holds something that is not a regular file"]
            present.add(path.name)
        raw = (log_dir / RESULT_FILE).read_bytes()
    except (OSError, ValueError):
        return ["the log directory or its container-result.json is missing, linked or unreadable"]
    if len(raw) > MAX_RESULT_BYTES:
        return ["container-result.json is larger than the adapter ever writes"]
    try:
        result = json.loads(raw.decode("utf-8"))
    except ValueError:
        return ["container-result.json is not UTF-8 JSON"]
    schema_errors = validate_document(result, RESULT_SCHEMA)
    if schema_errors:
        return [f"container-result.json fails its closed schema ({len(schema_errors)} errors)"]
    if raw != canonical_request_bytes(result):
        errors.append("container-result.json is not in the adapter's canonical byte form")
    if result["result_sha256"] != result_sha256(result):
        errors.append("result_sha256 does not match the result record")
    decision = request["permission"]["decision"]
    expected = {
        "boundary_sha256": boundary_sha256(),
        "run_id": run_id, "job_id": job_id, "attempt_id": attempt_id,
        "request_sha256": request_sha256(request),
        "image_reference": image_reference(record), "image_record_sha256": _sha(record),
        "permission_fingerprint_sha256": pc.fingerprint_material(
            decision["decision"], decision["capabilities"])["sha256"],
        "container_name": container_name(run_id, job_id, attempt_id),
        "scratch_path": request["scratch_path"], "log_path": request["log_path"],
    }
    for field, value in expected.items():
        if result[field] != value:
            errors.append(f"{field} is not what the expected request, registry and boundary derive")
    cause, status, exit_code, streams = (result["cause"], result["execution_status"],
                                         result["exit_code"], result["streams"])
    if STATUS_BY_CAUSE[cause] != status:
        errors.append("execution_status is not the status of this cause")
    if result["container_removed"] != (cause != "CLEANUP_FAILED"):
        errors.append("container_removed must be true for every cause except CLEANUP_FAILED")
    if cause is None and exit_code != 0:
        errors.append("an OK result must carry exit_code 0")
    if cause == "CONTAINER_EXIT_NONZERO" and exit_code in (None, 0):
        errors.append("CONTAINER_EXIT_NONZERO must carry a non-zero exit_code")
    if cause not in (None, "CONTAINER_EXIT_NONZERO", "OOM_KILLED", "WORKER_LOST") and exit_code is not None:
        errors.append("this cause cannot carry an exit_code")
    if result["finished_at"] < result["started_at"]:
        errors.append("finished_at is before started_at")
    names = [entry["path"] for entry in result["files"]]
    full = sorted((REQUEST_FILE, *CHILD_FILES))
    if cause in BLOCKED_CAUSES:
        shaped = names == [REQUEST_FILE] and streams is None
    elif cause in ("LOG_WRITE_FAILED", "CLEANUP_FAILED", "CANCELED"):
        # The only outcomes that may end without the child runner returning its counts (a
        # persistence failure, a pre-start cleanup failure, a re-raised interrupt).
        shaped = (REQUEST_FILE in names and names == sorted(set(names))
                  and (streams is None or names == full))
    else:
        shaped = names == full and streams is not None
    if not shaped:
        errors.append("files and streams are not the adapter's shape for this cause")
    if present != {*names, RESULT_FILE}:
        errors.append("the log directory does not hold exactly the listed files and the result")
    sizes = {}
    for entry in result["files"]:
        try:
            data = beneath(log_dir, log_dir / entry["path"]).read_bytes()
        except (OSError, ValueError):
            errors.append("a listed file is missing, linked or unreadable")
            continue
        sizes[entry["path"]] = len(data)
        if entry["bytes"] != len(data) or entry["sha256"] != _bytes_sha(data):
            errors.append("a listed file does not have its recorded size and hash")
        if entry["path"] == REQUEST_FILE and data != canonical_request_bytes(request):
            errors.append("request.json is not the expected request")
    if "command.json" in sizes:
        errors.extend(_command_record_errors(
            log_dir / "command.json", request=request, image_ref=image_reference(record),
            name=container_name(run_id, job_id, attempt_id), cause=cause, exit_code=exit_code,
            streams=streams))
    if streams is not None:
        for stream in ("stdout", "stderr"):
            counts = streams[stream]
            limit = request["limits"][f"{stream}_limit_bytes"]
            if (min(counts["observed_bytes"], counts["written_bytes"], counts["dropped_bytes"]) < 0
                    or counts["written_bytes"] > limit):
                errors.append(f"{stream} counts are negative or exceed the required retention limit")
            elif cause != "LOG_WRITE_FAILED" and (       # a failed write leaves honest but unequal counts
                    counts["written_bytes"] != sizes.get(f"{stream}.log")
                    or counts["dropped_bytes"] != counts["observed_bytes"] - counts["written_bytes"]
                    or counts["truncated"] != (counts["dropped_bytes"] > 0)):
                errors.append(f"{stream} counts disagree with the retained log")
    return errors


def load_verified_result(attempt_root: Path, *, run_id: str, job_id: str, attempt_id: str,
                         request: Any, images_dir: Path, host_flavor: str,
                         docker_host: str | None) -> Mapping[str, Any]:
    errors = verify_container_result(attempt_root, run_id=run_id, job_id=job_id,
                                     attempt_id=attempt_id, request=request, images_dir=images_dir,
                                     host_flavor=host_flavor, docker_host=docker_host)
    if errors:
        raise ContainerRequestError("container result rejected: " + "; ".join(errors))
    request = thaw(request)
    path = Path(attempt_root).joinpath(*request["log_path"].split("/")) / RESULT_FILE
    return freeze(json.loads(path.read_text(encoding="utf-8")))


# ---- common worker-result envelope ---------------------------------------------------------------

def to_worker_envelope(attempt_root: Path, *, run_id: str, job_id: str, attempt_id: str,
                       request: Any, images_dir: Path, host_flavor: str, docker_host: str | None,
                       input_fingerprint: str, output_contract: str, output_paths: list[str],
                       resume_command: str | None) -> dict[str, Any]:
    """Maps the verified on-disk result into ``worker-result-envelope/1.0``.

    It reads the result from the attempt, never from a caller's copy, and always reports
    ``NOT_ACCEPTED``: acceptance belongs to the publication boundary, not to an adapter.
    """
    from worker_result import artifact_records, terminal_envelope, validate_worker_result
    result = load_verified_result(attempt_root, run_id=run_id, job_id=job_id, attempt_id=attempt_id,
                                  request=request, images_dir=images_dir, host_flavor=host_flavor,
                                  docker_host=docker_host)
    attempt_root = Path(attempt_root)
    relative = [f"{result['log_path']}/{entry['path']}" for entry in result["files"]]
    relative.append(f"{result['log_path']}/{RESULT_FILE}")
    if not isinstance(output_paths, list):
        raise ContainerRequestError("output_paths must be a list")
    for index, path in enumerate(output_paths):
        if not isinstance(path, str) or output_path_errors(path):
            raise ContainerRequestError(f"output_paths[{index}] is not one normalized relative path")
        try:
            target = beneath(attempt_root, attempt_root.joinpath(*path.split("/")))
        except ValueError:
            raise ContainerRequestError(f"output_paths[{index}] leaves the attempt or crosses a link") from None
        if not target.is_file():
            raise ContainerRequestError(f"output_paths[{index}] is not a regular file")
        relative.append(path)
    if len(relative) != len(set(relative)):
        raise ContainerRequestError("output_paths repeats a path or names an adapter file")
    cause = result["cause"]
    retry = result["execution_status"] != "OK" and resume_command is not None
    envelope = terminal_envelope(
        run_id=run_id, job_id=job_id, attempt_id=attempt_id, worker_kind=WORKER_KIND,
        execution_status=result["execution_status"], acceptance_status="NOT_ACCEPTED",
        input_fingerprint=input_fingerprint, output_contract=output_contract,
        started_at=result["started_at"], finished_at=result["finished_at"],
        summary=SUMMARIES[cause], artifacts=artifact_records(attempt_root, relative),
        cause=cause, retry_allowed=retry, resume_command=resume_command)
    errors = validate_worker_result(envelope)
    if errors:
        raise ContainerRequestError(f"container result does not map to a valid envelope ({len(errors)} errors)")
    return envelope
