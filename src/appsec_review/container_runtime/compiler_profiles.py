"""Collect static compiler profiles from a pinned, signature-verified builder image.

One bounded probe container per image reports which compiler drivers the image ships, their
symlink chains, default targets and selected image environment, and copies each driver's real
executable into a fresh run-owned directory. The host hashes those copied bytes. The probe uses
only the isolated ``docker run`` form that the native engine protocol accepts. Its output is
untrusted data and is parsed strictly; any mismatch fails the whole image closed.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import uuid
from typing import Any

from appsec_review.signing.images import ImageSignatureVerifier
from .build_executor import BuildContainerExecutor, BuildProfile, Runner, _run, resolve_host_bind_path
from .identity import application_runtime_user, grant_runtime_user

SCHEMA = "appsec-review/static-compiler-profile/2"
SET_SCHEMA = "appsec-review/compiler-profile-set/1"
TRANSCRIPT_SCHEMA = "appsec-review/compiler-probe/1"
ORIGIN = "image-probe/1"
COLLECTOR_VERSION = "1"

ENV_KEYS = ("CC", "CXX", "AR", "LD", "PATH", "CARGO_BUILD_TARGET", "RUSTFLAGS", "GOFLAGS",
            "GOOS", "GOARCH", "CGO_ENABLED")
INVOCATION_NAMES = ("cc", "c++", "clang", "clang++", "gcc", "g++", "rustc", "cargo", "go")
DRIVER_SEMANTICS = {
    "cargo": "cargo-rustc/1", "clang": "clang-target/1", "gcc": "gcc-default/1",
    "go": "go-env/1", "rustc": "rustc-host/1",
}
PROBE_KEYS = {
    "cargo": ("cargo.version",), "clang": ("clang.dumpmachine", "clang.version"),
    "gcc": ("gcc.dumpmachine", "gcc.version"), "go": ("go.version", "go.env"),
    "rustc": ("rustc.version",),
}
_GO_ENV_KEYS = ("CC", "CGO_ENABLED", "CXX", "GOARCH", "GOOS", "GOROOT")

MAX_TRANSCRIPT_BYTES = 1 << 20
MAX_LINE_BYTES = 4096
MAX_LINES = 8192
MAX_PROBE_LINES = 256
MAX_EXECUTABLE_BYTES = 1 << 30
PROBE_TIMEOUT_SECONDS = 120

PROBE_SCRIPT = r"""set -u
umask 077
outdir=$1
found=" "
emit() { while IFS= read -r line || [ -n "$line" ]; do printf '|%s\n' "$line"; done; }
present() { case $found in *" $1 "*) return 0 ;; esac; return 1; }
probe() {
  key=$1; shift
  out=$("$@" 2>/dev/null); rc=$?
  printf '@@probe %s %s\n' "$key" "$rc"
  if [ -n "$out" ]; then printf '%s\n' "$out" | head -n 256 | emit; fi
}
printf '@@collector appsec-review/compiler-probe/1\n'
for key in CC CXX AR LD PATH CARGO_BUILD_TARGET RUSTFLAGS GOFLAGS GOOS GOARCH CGO_ENABLED; do
  if value=$(printenv "$key"); then printf '@@env %s\n' "$key"; printf '%s\n' "$value" | emit; fi
done
for name in cc c++ clang clang++ gcc g++ rustc cargo go; do
  path=$(command -v "$name" 2>/dev/null) || continue
  case $path in /*) ;; *) continue ;; esac
  found="$found$name "
  printf '@@tool %s\n' "$name"
  printf '%s\n' "$path" | emit
  hop=$path
  count=0
  while [ -L "$hop" ]; do
    if [ "$count" -ge 16 ]; then printf '@@unresolved %s\n' "$name"; break; fi
    target=$(readlink "$hop") || { printf '@@unresolved %s\n' "$name"; break; }
    printf '@@link %s\n' "$name"
    printf '%s\n%s\n' "$hop" "$target" | emit
    case $target in /*) hop=$target ;; *) hop=${hop%/*}/$target ;; esac
    count=$((count + 1))
  done
  printf '@@real %s\n' "$name"
  readlink -f "$path" | emit
done
if present clang; then probe clang.dumpmachine clang -dumpmachine; probe clang.version clang --version; fi
if present gcc; then probe gcc.dumpmachine gcc -dumpmachine; probe gcc.version gcc --version; fi
if present rustc; then
  probe rustc.version rustc -vV
  printf '@@targets\n'
  if sysroot=$(rustc --print sysroot 2>/dev/null); then
    for dir in "$sysroot"/lib/rustlib/*/lib; do
      [ -d "$dir" ] || continue
      triple=${dir%/lib}
      printf '%s\n' "${triple##*/}"
    done | emit
  fi
fi
if present cargo; then probe cargo.version cargo -V; fi
if present go; then
  probe go.version go version
  probe go.env go env -json GOOS GOARCH CGO_ENABLED CC CXX GOROOT
fi
for name in clang gcc rustc cargo go; do
  present "$name" || continue
  real=$(readlink -f "$(command -v "$name")") && cp "$real" "$outdir/$name"
  printf '@@copy %s %s\n' "$name" "$?"
done
printf '@@end\n'
"""

_HEX = re.compile(r"[0-9a-f]{64}")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_TRIPLE = re.compile(r"[a-z0-9_.]{1,32}(?:-[a-z0-9_.]{1,32}){1,4}")
_PATH = re.compile(r"/[^\x00-\x1f\x7f]{0,4095}")
_LINK_TARGET = re.compile(r"[^\x00-\x1f\x7f]{1,4096}")
_EXIT = re.compile(r"[0-9]{1,3}")
_HEADER = re.compile(
    r"@@(collector|env|tool|link|real|unresolved|probe|targets|copy|end)"
    r"(?: ([A-Za-z0-9_.+/-]{1,64}))?(?: ([0-9]{1,3}))?")
_VERSION_LINE = re.compile(r"[^\x00-\x1f\x7f]{1,256}")
_RUSTC_FIRST = re.compile(r"rustc [0-9][^ \x00-\x1f]{0,63}(?: [^\x00-\x1f\x7f]{0,192})?")
_CARGO_FIRST = re.compile(r"cargo [0-9][^ \x00-\x1f]{0,63}(?: [^\x00-\x1f\x7f]{0,192})?")
_GO_FIRST = re.compile(r"go version go[0-9][^ \x00-\x1f]{0,63} [a-z0-9]{1,16}/[a-z0-9]{1,16}")
_RUSTC_FIELD = re.compile(r"([A-Za-z][A-Za-z -]{0,31}): ([^\x00-\x1f\x7f]{0,256})")
_GO_WORD = re.compile(r"[a-z0-9]{1,16}")


class CompilerProfileError(ValueError):
    """The image probe or its evidence cannot support a compiler profile."""


@dataclass
class ProbeTranscript:
    env: dict[str, str] = field(default_factory=dict)
    tools: dict[str, dict[str, Any]] = field(default_factory=dict)
    probes: dict[str, tuple[int, tuple[str, ...]]] = field(default_factory=dict)
    rust_targets: tuple[str, ...] | None = None
    copies: dict[str, int] = field(default_factory=dict)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fail(message: str) -> None:
    raise CompilerProfileError(f"compiler probe: {message}")


def _next_hop(hop: str, target: str) -> str:
    # Mirrors the probe's ``${hop%/*}/$target`` join exactly.
    return target if target.startswith("/") else f"{hop.rsplit('/', 1)[0]}/{target}"


def parse_probe_transcript(data: bytes) -> ProbeTranscript:
    """Parse the probe's stdout strictly; any unexpected shape is an error, never a partial result."""
    if not isinstance(data, bytes) or len(data) > MAX_TRANSCRIPT_BYTES:
        _fail("transcript is missing or exceeds its size bound")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        _fail("transcript is not UTF-8")
    if not text.endswith("\n") or "\r" in text:
        _fail("transcript is truncated or not LF-delimited")
    lines = text[:-1].split("\n")
    if len(lines) > MAX_LINES or any(len(line.encode("utf-8")) > MAX_LINE_BYTES for line in lines):
        _fail("transcript exceeds its line bounds")
    sections: list[tuple[tuple[str, str | None, str | None], list[str]]] = []
    for line in lines:
        if line.startswith("|"):
            if not sections:
                _fail("payload precedes any section header")
            sections[-1][1].append(line[1:])
            continue
        match = _HEADER.fullmatch(line)
        if match is None:
            _fail("unrecognised transcript line")
        sections.append(((match[1], match[2], match[3]), []))
    if (not sections or sections[0] != (("collector", TRANSCRIPT_SCHEMA, None), [])
            or sections[-1] != (("end", None, None), [])):
        _fail("transcript lacks its collector header or end marker")
    result = ProbeTranscript()
    probe_keys = {key for keys in PROBE_KEYS.values() for key in keys}
    for (kind, name, code), payload in sections[1:-1]:
        if kind == "env":
            if name not in ENV_KEYS or code is not None or name in result.env or not payload:
                _fail("invalid or repeated environment section")
            result.env[name] = "\n".join(payload)
        elif kind == "tool":
            if (name not in INVOCATION_NAMES or code is not None or name in result.tools
                    or len(payload) != 1 or not _PATH.fullmatch(payload[0])):
                _fail("invalid or repeated tool section")
            result.tools[name] = {"path": payload[0], "links": [], "real": None}
        elif kind == "link":
            tool = result.tools.get(name)
            if (tool is None or code is not None or tool["real"] is not None or len(payload) != 2
                    or not _PATH.fullmatch(payload[0]) or not _LINK_TARGET.fullmatch(payload[1])):
                _fail("invalid symlink section")
            expected = (tool["path"] if not tool["links"]
                        else _next_hop(*tool["links"][-1]))
            if payload[0] != expected:
                _fail(f"symlink chain for {name} is discontinuous")
            tool["links"].append((payload[0], payload[1]))
        elif kind == "real":
            tool = result.tools.get(name)
            if (tool is None or code is not None or tool["real"] is not None or len(payload) != 1
                    or not _PATH.fullmatch(payload[0])):
                _fail("invalid real-path section")
            tool["real"] = payload[0]
        elif kind == "unresolved":
            _fail(f"symlink chain for {name} could not be resolved within its bound")
        elif kind == "probe":
            if (name not in probe_keys or code is None or name in result.probes
                    or len(payload) > MAX_PROBE_LINES):
                _fail("invalid or repeated probe section")
            result.probes[name] = (int(code), tuple(payload))
        elif kind == "targets":
            if name is not None or code is not None or result.rust_targets is not None:
                _fail("invalid or repeated rust target section")
            result.rust_targets = tuple(payload)
        elif kind == "copy":
            if name not in DRIVER_SEMANTICS or code is None or name in result.copies or payload:
                _fail("invalid or repeated copy section")
            result.copies[name] = int(code)
        else:
            _fail("repeated collector header or end marker")
    if any(tool["real"] is None for tool in result.tools.values()):
        _fail("a tool lacks its resolved real path")
    drivers = {driver for driver in DRIVER_SEMANTICS if driver in result.tools}
    expected_probes = {key for driver in drivers for key in PROBE_KEYS[driver]}
    if (set(result.probes) != expected_probes or set(result.copies) != drivers
            or (result.rust_targets is not None) != ("rustc" in drivers)):
        _fail("probe, copy or target sections do not match the drivers present")
    return result


def _probe_ok(transcript: ProbeTranscript, key: str) -> tuple[str, ...]:
    code, lines = transcript.probes[key]
    if code != 0 or not lines:
        _fail(f"{key} failed or produced no output")
    return lines


def _single_triple(transcript: ProbeTranscript, key: str) -> str:
    lines = _probe_ok(transcript, key)
    if len(lines) != 1 or not _TRIPLE.fullmatch(lines[0]):
        _fail(f"{key} did not report exactly one target triple")
    return lines[0]


def _first_line(transcript: ProbeTranscript, key: str, pattern: re.Pattern[str]) -> str:
    line = _probe_ok(transcript, key)[0]
    if not pattern.fullmatch(line):
        _fail(f"{key} reported an unexpected version line")
    return line


def _rustc_facts(transcript: ProbeTranscript) -> tuple[str, str, list[str], dict[str, str]]:
    lines = _probe_ok(transcript, "rustc.version")
    if not _RUSTC_FIRST.fullmatch(lines[0]):
        _fail("rustc.version reported an unexpected version line")
    fields: dict[str, str] = {}
    for line in lines[1:]:
        match = _RUSTC_FIELD.fullmatch(line)
        if match is None or match[1] in fields:
            _fail("rustc.version reported an unexpected field")
        fields[match[1]] = match[2]
    host, release = fields.get("host", ""), fields.get("release", "")
    if not _TRIPLE.fullmatch(host) or not release:
        _fail("rustc.version lacks a host triple or release")
    targets = transcript.rust_targets or ()
    if (len(set(targets)) != len(targets) or not all(_TRIPLE.fullmatch(item) for item in targets)
            or host not in targets):
        _fail("installed rust targets are invalid or exclude the host")
    return lines[0], host, sorted(targets), {"release": release}


def _go_facts(transcript: ProbeTranscript) -> tuple[str, str, str, dict[str, Any]]:
    version = _first_line(transcript, "go.version", _GO_FIRST)
    try:
        environment = json.loads("\n".join(_probe_ok(transcript, "go.env")))
    except json.JSONDecodeError:
        _fail("go.env is not JSON")
    if (not isinstance(environment, dict) or tuple(sorted(environment)) != _GO_ENV_KEYS
            or not all(isinstance(value, str) for value in environment.values())):
        _fail("go.env does not report exactly the requested string keys")
    goos, goarch = environment["GOOS"], environment["GOARCH"]
    if (not _GO_WORD.fullmatch(goos) or not _GO_WORD.fullmatch(goarch)
            or environment["CGO_ENABLED"] not in {"0", "1"}):
        _fail("go.env reports an invalid platform or cgo setting")
    facts = {"cgo_enabled": environment["CGO_ENABLED"] == "1", "cc": environment["CC"],
             "cxx": environment["CXX"], "goroot": environment["GOROOT"]}
    return version, f"{goos}/{goarch}", f"{goarch}-{goos}", facts


def build_profile_records(transcript: ProbeTranscript, *, image_digest: str,
                          executable_hashes: Mapping[str, str], transcript_sha256: str
                          ) -> dict[str, dict[str, Any]]:
    """Build one validated ``/2`` record per driver the image ships."""
    from appsec_review.jobs.build_topology import _compiler_axes

    records: dict[str, dict[str, Any]] = {}
    for driver in sorted(DRIVER_SEMANTICS):
        tool = transcript.tools.get(driver)
        if tool is None:
            continue
        if transcript.copies[driver] != 0:
            _fail(f"{driver} executable could not be copied from the image")
        facts: dict[str, Any] = {}
        if driver in {"clang", "gcc"}:
            default_target = _single_triple(transcript, f"{driver}.dumpmachine")
            version = _first_line(transcript, f"{driver}.version", _VERSION_LINE)
            supported, axes_target = [default_target], default_target
        elif driver == "rustc":
            version, default_target, supported, facts = _rustc_facts(transcript)
            axes_target = default_target
        elif driver == "cargo":
            if "rustc" not in transcript.tools:
                _fail("cargo is present without rustc")
            version = _first_line(transcript, "cargo.version", _CARGO_FIRST)
            _rustc_version, default_target, supported, _rustc = _rustc_facts(transcript)
            axes_target = default_target
        else:
            version, default_target, axes_target, facts = _go_facts(transcript)
            supported = [default_target]
        record = {
            "schema": SCHEMA, "image_digest": image_digest, "driver": driver,
            "executable": tool["real"],
            "invocation_names": sorted(name for name, other in transcript.tools.items()
                                       if other["real"] == tool["real"]),
            "compiler_sha256": executable_hashes.get(driver),
            "wrapper_closure": [{"path": path, "target": target} for path, target in tool["links"]],
            "driver_semantics": DRIVER_SEMANTICS[driver], "version": version,
            "default_target": default_target, "target_axes": _compiler_axes(axes_target),
            "supported_targets": supported, "driver_facts": facts,
            "image_env": dict(sorted(transcript.env.items())),
            "probe": {
                "transcript_schema": TRANSCRIPT_SCHEMA, "script_sha256": _sha256(PROBE_SCRIPT.encode()),
                "transcript_sha256": transcript_sha256,
                "outputs": {key: {"exit_code": transcript.probes[key][0],
                                  "sha256": _sha256("\n".join(transcript.probes[key][1]).encode())}
                            for key in PROBE_KEYS[driver]},
            },
            "provenance": {"origin": ORIGIN, "collector_version": COLLECTOR_VERSION},
        }
        validate_profile(record)
        records[driver] = record
    return records


_RECORD_KEYS = frozenset((
    "schema", "image_digest", "driver", "executable", "invocation_names", "compiler_sha256",
    "wrapper_closure", "driver_semantics", "version", "default_target", "target_axes",
    "supported_targets", "driver_facts", "image_env", "probe", "provenance"))


def validate_profile(record: Any) -> None:
    """Reject any ``/2`` record that is not exactly the shape the collector produces."""
    if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
        _fail("profile record has unexpected fields")
    driver = record["driver"]
    names = record["invocation_names"]
    closure = record["wrapper_closure"]
    supported = record["supported_targets"]
    probe = record["probe"]
    if (record["schema"] != SCHEMA or not isinstance(driver, str) or driver not in DRIVER_SEMANTICS
            or record["driver_semantics"] != DRIVER_SEMANTICS[driver]
            or not isinstance(record["image_digest"], str)
            or not _IMAGE_DIGEST.fullmatch(record["image_digest"])
            or not isinstance(record["executable"], str) or not _PATH.fullmatch(record["executable"])
            or not isinstance(record["compiler_sha256"], str)
            or not _HEX.fullmatch(record["compiler_sha256"])):
        _fail("profile record identity is invalid")
    if (not isinstance(names, list) or not names or names != sorted(set(names))
            or not set(names) <= set(INVOCATION_NAMES) or driver not in names):
        _fail("profile invocation names are invalid")
    if (not isinstance(closure, list) or len(closure) > 16
            or any(not isinstance(hop, dict) or set(hop) != {"path", "target"}
                   or not isinstance(hop["path"], str) or not _PATH.fullmatch(hop["path"])
                   or not isinstance(hop["target"], str) or not _LINK_TARGET.fullmatch(hop["target"])
                   for hop in closure)):
        _fail("profile wrapper closure is invalid")
    if (not isinstance(record["version"], str) or not _VERSION_LINE.fullmatch(record["version"])
            or not isinstance(record["default_target"], str)
            or not isinstance(supported, list) or supported != sorted(set(supported))
            or record["default_target"] not in supported
            or not isinstance(record["target_axes"], dict) or not isinstance(record["driver_facts"], dict)):
        _fail("profile target facts are invalid")
    environment = record["image_env"]
    if (not isinstance(environment, dict) or not set(environment) <= set(ENV_KEYS)
            or not all(isinstance(value, str) for value in environment.values())):
        _fail("profile image environment is invalid")
    if (not isinstance(probe, dict)
            or set(probe) != {"transcript_schema", "script_sha256", "transcript_sha256", "outputs"}
            or probe["transcript_schema"] != TRANSCRIPT_SCHEMA
            or not all(isinstance(probe[key], str) and _HEX.fullmatch(probe[key])
                       for key in ("script_sha256", "transcript_sha256"))
            or not isinstance(probe["outputs"], dict) or set(probe["outputs"]) != set(PROBE_KEYS[driver])):
        _fail("profile probe evidence is invalid")
    if record["provenance"] != {"origin": ORIGIN, "collector_version": COLLECTOR_VERSION}:
        _fail("profile provenance is invalid")


def profile_set(image_digest: str, records: Mapping[str, dict[str, Any]]) -> dict[str, Any]:
    """One image's profiles; an image with no compiler drivers has an empty, still-probed entry."""
    if not isinstance(image_digest, str) or not _IMAGE_DIGEST.fullmatch(image_digest):
        _fail("profile set image digest is invalid")
    for driver, record in records.items():
        validate_profile(record)
        if record["driver"] != driver or record["image_digest"] != image_digest:
            _fail("profile set entry does not match its image or driver key")
    return {"schema": SET_SCHEMA,
            "images": {image_digest: {driver: records[driver] for driver in sorted(records)}}}


def merge_profile_sets(sets: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Merge per-image sets; an image probed twice is ambiguous, never silently replaced."""
    images: dict[str, dict[str, Any]] = {}
    for value in sets:
        if not isinstance(value, Mapping) or set(value) != {"schema", "images"} or value["schema"] != SET_SCHEMA:
            _fail("profile set is invalid")
        for digest, records in value["images"].items():
            if digest in images:
                _fail(f"image {digest} appears in more than one profile set")
            images[digest] = profile_set(digest, records)["images"][digest]
    return {"schema": SET_SCHEMA, "images": {digest: images[digest] for digest in sorted(images)}}


def hash_copied_executables(directory: Path, drivers: Iterable[str]) -> dict[str, str]:
    """Hash exactly the expected copied executables; a script wrapper or non-ELF file is an error."""
    expected = set(drivers)
    present = set(os.listdir(directory))
    if present != expected:
        _fail("copied executables do not match the drivers present")
    hashes: dict[str, str] = {}
    for name in sorted(expected):
        path = directory / name
        if not stat.S_ISREG(os.lstat(path).st_mode):
            _fail(f"copied {name} is not a regular file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            status = os.fstat(handle.fileno())
            if not stat.S_ISREG(status.st_mode) or status.st_size > MAX_EXECUTABLE_BYTES:
                _fail(f"copied {name} is not a bounded regular file")
            digest = hashlib.sha256()
            head = handle.read(4)
            if head.startswith(b"#!"):
                _fail(f"{name} resolves to a script wrapper, not a compiler executable")
            if head != b"\x7fELF":
                _fail(f"{name} does not resolve to an ELF executable")
            digest.update(head)
            total = len(head)
            while chunk := handle.read(1 << 20):
                total += len(chunk)
                if total > MAX_EXECUTABLE_BYTES:
                    _fail(f"copied {name} exceeds its size bound")
                digest.update(chunk)
        hashes[name] = digest.hexdigest()
    return hashes


def probe_command(image_id: str, runtime_user: str, output_source: Path, name: str) -> list[str]:
    return [
        "docker", "run", "--rm", "--name", name, "--network", "none", "--read-only",
        "--user", runtime_user, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--cpus", "1", "--memory", "1g", "--pids-limit", "128",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--workdir", "/tmp",
        "--mount", f"type=bind,src={output_source},dst=/out",
        "--env", "HOME=/tmp", "--env", "LANG=C.UTF-8", "--env", "LC_ALL=C.UTF-8",
        "--entrypoint", "/bin/sh", image_id, "-c", PROBE_SCRIPT, "compiler-probe", "/out",
    ]


def _remove_container(name: str, runner: Runner) -> None:
    code, _stdout, stderr, timed_out = runner(("docker", "rm", "--force", name), 60)
    absent = code == 1 and any(text in stderr.decode("utf-8", "replace").lower()
                               for text in ("no such container", "no such object"))
    if timed_out or not (code == 0 or absent):
        raise RuntimeError(f"compiler probe container cleanup is unconfirmed: {name}")


def collect_compiler_profiles(profile: BuildProfile, *, scratch: Path, runner: Runner | None = None,
                              image_verifier: ImageSignatureVerifier | None = None,
                              timeout_seconds: int = PROBE_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Probe one pinned image and return its compiler profile set, failing closed on any doubt."""
    if type(timeout_seconds) is not int or not 0 < timeout_seconds <= 3600:
        raise ValueError("compiler probe timeout must be a bounded positive integer")
    runner = runner or _run
    # Identity and signature are checked before any container runs.
    BuildContainerExecutor(profile, timeout_seconds=timeout_seconds, output_bytes=MAX_TRANSCRIPT_BYTES,
                           runner=runner, network="none", image_verifier=image_verifier).resolve()
    root = scratch.resolve(strict=True)
    if scratch.is_symlink() or not root.is_dir():
        raise ValueError("compiler probe scratch must be a run-owned directory")
    output = root / f"compiler-probe-{uuid.uuid4().hex}"
    output.mkdir(mode=0o700)
    try:
        runtime_user = application_runtime_user(profile.user)
        grant_runtime_user(output, runtime_user)
        name = f"appsec-review-compiler-probe-{uuid.uuid4().hex}"
        command = probe_command(profile.image_id, runtime_user,
                                resolve_host_bind_path(output, runner), name)
        code, stdout, _stderr, timed_out = runner(command, timeout_seconds)
        if timed_out:
            _remove_container(name, runner)
            _fail(f"probe of {profile.name} timed out")
        if code != 0:
            _fail(f"probe of {profile.name} exited with {code}")
        transcript = parse_probe_transcript(stdout)
        failed = sorted(driver for driver, status in transcript.copies.items() if status != 0)
        if failed:
            _fail(f"executables could not be copied from the image: {', '.join(failed)}")
        hashes = hash_copied_executables(output, transcript.copies)
        records = build_profile_records(transcript, image_digest=profile.image_id,
                                        executable_hashes=hashes, transcript_sha256=_sha256(stdout))
        return profile_set(profile.image_id, records)
    finally:
        shutil.rmtree(output, ignore_errors=True)
