"""Simulated containers for the real build executor.

The fakes replace only the Docker CLI. A simulated build writes raw `strace` rows and PATH
tool-call records in the formats the in-container driver and wrapper produce, and a simulated
gitleaks writes a report. `BuildContainerExecutor.execute_captured` then normalizes, scans,
sanitizes, and records them exactly as it does for a live container.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
import hashlib
import json
from pathlib import Path
import struct

from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
from appsec_review.container_runtime.catalog import load_catalog


ROOT = Path(__file__).parents[1]
SYNTHETIC_SECRET = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"
Scanner = Callable[[Path, Path], tuple[int | None, bytes, bytes, bool]]


def build_capture_toml() -> str:
    """The repository's global `[build_capture]` table, which every loadable configuration needs."""
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    start = text.index("[build_capture]\n")
    return text[start:text.index("\n[", start + 1)].rstrip() + "\n"


def minimal_elf(needed: Sequence[str] = ("libc.so.6",), *, interpreter: str | None = None) -> bytes:
    """A little-endian ELF64 holding only the program headers and dynamic section a loader reads."""
    strings = b"\0" + b"".join(name.encode() + b"\0" for name in needed)
    offsets, cursor = [], 1
    for name in needed:
        offsets.append(cursor)
        cursor += len(name) + 1
    interp = interpreter.encode() + b"\0" if interpreter else b""
    header, program, count = 64, 56, 3 if interp else 2
    dynamic_offset = header + count * program
    string_offset = dynamic_offset + (len(offsets) + 3) * 16
    dynamic = b"".join(struct.pack("<qQ", 1, offset) for offset in offsets)
    dynamic += struct.pack("<qQ", 5, string_offset) + struct.pack("<qQ", 10, len(strings))
    dynamic += struct.pack("<qQ", 0, 0)
    interp_offset = string_offset + len(strings)
    size = interp_offset + len(interp)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    elf_header = ident + struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, header, 0, 0, header, program, count, 0, 0, 0)
    headers = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, size, size, 4096)
    headers += struct.pack("<IIQQQQQQ", 2, 6, dynamic_offset, dynamic_offset, dynamic_offset,
                           len(dynamic), len(dynamic), 8)
    if interp:
        headers += struct.pack("<IIQQQQQQ", 3, 4, interp_offset, interp_offset, interp_offset,
                               len(interp), len(interp), 1)
    return elf_header + headers + dynamic + strings + interp


GO_MODINFO_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
GO_MODINFO_END = bytes.fromhex("f932433186182072008242104116d8f2")
GO_BUILD_ID = "aB3dE6gH9jK2mN5pQ8sT/uV1xY4zA7cD0fG3iJ6lM/oP9rS2uV5xY8aB1dE4gH/jK7mN0pQ3sT6vW9yZ2bC"
GO_MODULE_SUM = "h1:" + "A" * 43 + "="


def _uvarint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append(value & 0x7F | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def go_build_info(version: str = "go1.23.12", module_text: str | None = None) -> bytes:
    """A `.go.buildinfo` section in the Go 1.18+ inline layout the linker writes."""
    text = module_text if module_text is not None else (
        "path\texample.test/app/cmd/app\nmod\texample.test/app\t(devel)\t\n"
        f"dep\tgithub.com/google/uuid\tv1.6.0\t{GO_MODULE_SUM}\n"
        "build\t-buildmode=exe\nbuild\t-compiler=gc\nbuild\t-ldflags=\"-X main.build=release\"\n"
        "build\tCGO_ENABLED=1\nbuild\tGOARCH=amd64\nbuild\tGOOS=linux\n")
    module = (GO_MODINFO_START + text.encode() + GO_MODINFO_END) if text else b""
    data = b"\xff Go buildinf:" + bytes([8, 2]) + bytes(16)
    data += _uvarint(len(version)) + version.encode() + _uvarint(len(module)) + module
    return data + bytes(-len(data) % 16)


def go_build_id_note(build_id: str = GO_BUILD_ID) -> bytes:
    description = build_id.encode()
    return struct.pack("<III", 4, len(description), 4) + b"Go\0\0" + description + bytes(-len(description) % 4)


def go_elf(*, note: bytes | None = None, build_info: bytes | None = None,
           dwarf: bool = True) -> tuple[bytes, dict[str, dict[str, int]]]:
    """A static little-endian ELF64 with the sections the Go build-facts reader consumes.

    Returns the file and, for each section, its file offset, size, and section-header offset so
    adversarial tests can corrupt one exact field.
    """
    contents = [(".note.go.buildid", 7, go_build_id_note() if note is None else note),
                (".go.buildinfo", 1, go_build_info() if build_info is None else build_info)]
    if dwarf:
        contents.append((".debug_info", 1, b"\x01\x02\x03\x04" * 4))
    contents.append((".gopclntab", 1, b"\xf1\xff\xff\xff" + bytes(12)))
    names = b"\0"
    name_offsets = {}
    for name in [item[0] for item in contents] + [".shstrtab"]:
        name_offsets[name] = len(names)
        names += name.encode() + b"\0"
    contents.append((".shstrtab", 3, names))
    cursor = 64 + 56
    body = b""
    layout: dict[str, dict[str, int]] = {}
    for name, _kind, data in contents:
        layout[name] = {"offset": cursor, "size": len(data)}
        body += data
        cursor += len(data)
    section_offset = cursor
    table = bytes(64)
    for index, (name, kind, data) in enumerate(contents, 1):
        layout[name]["header"] = section_offset + index * 64
        table += struct.pack("<IIQQQQIIQQ", name_offsets[name], kind, 0, 0,
                             layout[name]["offset"], len(data), 0, 0, 1, 0)
    size = section_offset + len(table)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 64, section_offset, 0, 64, 56, 1,
                                 64, len(contents) + 1, len(contents))
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, size, size, 4096)
    layout["section_table"] = {"offset": section_offset, "size": len(table), "header": 0}
    return header + load + body + table, layout


def minimal_go_elf() -> bytes:
    return go_elf()[0]


def _quoted(value: str) -> str:
    return json.dumps(value)


class ContainerSimulation:
    """Syscalls and wrapped tool calls observed inside one simulated captured build container."""

    def __init__(self, capture_root: Path, environment: dict[str, str], *, capture_envp: bool,
                 call_limit: int) -> None:
        self.root, self.environment = capture_root, dict(environment)
        self.capture_envp, self.call_limit = capture_envp, call_limit
        self._clock, self._pid = 1_700_000_000.0, 100

    def _write(self, pid: int, call: str, result: str) -> None:
        self._clock += 0.000001
        with (self.root / f"trace.{pid}").open("a", encoding="utf-8") as stream:
            stream.write(f"{self._clock:.6f} {call} = {result}\n")

    def exec(self, executable: str, argv: Sequence[str], *, envp: Iterable[str] | None = None,
             succeeded: bool = True) -> int:
        """Record one execve; a failed attempt mirrors a PATH search miss."""
        self._pid += 1
        entries = sorted(f"{key}={value}" for key, value in self.environment.items()) if envp is None else list(envp)
        rendered_envp = ("[" + ", ".join(_quoted(item) for item in entries) + "]" if self.capture_envp
                         else f"0x7ffd00000000 /* {len(entries)} vars */")
        call = f'execve({_quoted(executable)}, [{", ".join(_quoted(item) for item in argv)}], {rendered_envp})'
        self._write(self._pid, call, "0" if succeeded else "-1 ENOENT (No such file or directory)")
        if succeeded:
            self._write(self._pid, "exit_group(0)", "?")
        return self._pid

    def syscall(self, call: str, result: str, *, pid: int | None = None) -> None:
        """Record one raw syscall row exactly as ``strace -y`` prints it."""
        self._write(self._pid if pid is None else pid, call, result)

    def open(self, path: str) -> None:
        self._write(self._pid, f"openat(AT_FDCWD, {_quoted(path)}, O_RDONLY|O_CLOEXEC)", "3")

    def connect(self, address: str, port: int) -> None:
        self._write(self._pid, "connect(3, {sa_family=AF_INET, sin_port=htons(%d), "
                               'sin_addr=inet_addr("%s")}, 16)' % (port, address), "0")

    def tool_call(self, tool: str, arguments: Sequence[str], *, executable: str, stdout: bytes = b"",
                  stderr: bytes = b"", exit_code: int = 0) -> None:
        """Write the record `containers/build-capture/tool-wrapper.py` writes for a PATH tool."""
        counter = self.root / "tool-call-counter"
        ordinal = int(counter.read_text(encoding="utf-8") or "0") + 1 if counter.is_file() else 1
        counter.write_text(str(ordinal), encoding="utf-8")
        if ordinal > self.call_limit:
            return
        call_root = self.root / "tool-calls" / f"{ordinal:08d}-{tool}"
        call_root.mkdir(parents=True)
        (call_root / "stdout").write_bytes(stdout)
        (call_root / "stderr").write_bytes(stderr)
        redacted = set(json.loads((self.root / "envp-redact-names.json").read_text(encoding="utf-8")))
        environment = ({key: "<redacted>" if key in redacted else value
                        for key, value in sorted(self.environment.items())} if self.capture_envp else {})
        (call_root / "record.json").write_text(json.dumps({
            "schema": "appsec-review/build-tool-call/1", "ordinal": ordinal, "tool": tool,
            "executable": executable, "argv": [tool, *arguments], "environment": environment,
            "environment_captured": self.capture_envp,
            "environment_redacted_names": sorted(key for key in environment if key in redacted),
            "exit_code": exit_code,
            "stdout": {"uri": "stdout", "bytes": len(stdout), "retained_bytes": len(stdout),
                       "truncated": False, "sha256": hashlib.sha256(stdout).hexdigest()},
            "stderr": {"uri": "stderr", "bytes": len(stderr), "retained_bytes": len(stderr),
                       "truncated": False, "sha256": hashlib.sha256(stderr).hexdigest()},
        }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


Behavior = Callable[[tuple[str, ...], Path, str, dict[str, str], ContainerSimulation],
                    tuple[int | None, bytes, bytes]]


def secret_scanner(secrets: Sequence[str] = (SYNTHETIC_SECRET,)) -> Scanner:
    """A gitleaks stand-in that reports every scan-corpus line holding a known synthetic secret."""
    def scan(target: Path, scratch: Path) -> tuple[int | None, bytes, bytes, bool]:
        findings = []
        for path in sorted(item for item in target.rglob("*") if item.is_file()):
            relative = path.relative_to(target).as_posix()
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if any(secret in line for secret in secrets):
                    findings.append({"RuleID": "synthetic-secret", "Description": "synthetic secret",
                                     "File": f"/target/{relative}", "StartLine": number, "EndLine": number,
                                     "Match": "REDACTED", "Secret": "REDACTED",
                                     "Fingerprint": f"{relative}:synthetic-secret:{number}"})
        (scratch / "gitleaks.json").write_text(json.dumps(findings) + "\n", encoding="utf-8")
        return (1 if findings else 0), b"", b"", False
    return scan


def failing_scanner(_target: Path, _scratch: Path) -> tuple[int | None, bytes, bytes, bool]:
    return 2, b"", b"gitleaks crashed", False


def simulated_executor(profile: BuildProfile, behavior: Behavior, *, scanner: Scanner | None = None,
                       output_bytes: int = 8 * 1024 * 1024) -> BuildContainerExecutor:
    gitleaks = load_catalog(ROOT).tool("tool-gitleaks")
    scan = scanner or secret_scanner()

    def mounts(argv: Sequence[str]) -> dict[str, Path]:
        result = {}
        for index, value in enumerate(argv[:-1]):
            if value == "--mount":
                fields = dict(item.split("=", 1) for item in argv[index + 1].split(",") if "=" in item)
                result[fields["dst"]] = Path(fields["src"])
        return result

    def runner(argv: Sequence[str], _timeout: int) -> tuple[int | None, bytes, bytes, bool]:
        argv = tuple(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            resolved = (gitleaks.expected_image_id or "sha256:" + "9" * 64) if argv[3] == gitleaks.tag \
                else profile.image_id
            return 0, resolved.encode(), b"", False
        if argv[:2] == ("docker", "inspect"):
            return 0, json.dumps([{"Destination": "/", "Source": "/"}]).encode(), b"", False
        bound = mounts(argv)
        if "--report-path" in argv:
            return scan(bound["/target"], bound["/scratch"])
        entrypoint = argv.index("--entrypoint")
        if argv[entrypoint + 1] != "/bin/sh":
            raise AssertionError(f"build command ran without execution capture: {argv[entrypoint + 1]}")
        _image, _driver, logical_capture, _strings, call_limit, _wrappers, envp, *command = \
            argv[entrypoint + 2:]
        workspace = bound["/workspace"]
        capture_root = bound["/capture"] if logical_capture == "/capture" else \
            workspace / logical_capture.removeprefix("/workspace/")
        environment = dict(argv[index + 1].split("=", 1) for index, value in enumerate(argv[:-1])
                           if value == "--env")
        working_directory = argv[argv.index("--workdir") + 1].removeprefix("/workspace/")
        simulation = ContainerSimulation(capture_root, environment, capture_envp=envp == "1",
                                         call_limit=int(call_limit))
        code, stdout, stderr = behavior(tuple(command), workspace, working_directory, environment, simulation)
        return code, stdout, stderr, code is None

    return BuildContainerExecutor(profile, timeout_seconds=90, output_bytes=output_bytes, runner=runner)


_CONTAINER_DEFAULTS = {"HOME": "/tmp", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"}


class CapturingFake:
    """Give a family fake that only implements `execute` a real captured execution path.

    `execute_captured` runs the fake's `execute` as the simulated container, so the fake still
    decides outputs, streams, and exit status while the real executor normalizes, scans, and
    records the command. Uncaptured `execute` and every other attribute pass through unchanged
    for adapters that have not been migrated to captured execution.
    """

    def __init__(self, profile: BuildProfile, fake: object) -> None:
        self._fake = fake

        def behavior(argv, workspace, working_directory, environment, container):
            container.exec(f"/usr/bin/{argv[0]}", list(argv))
            accepted = {key: value for key, value in environment.items()
                        if _CONTAINER_DEFAULTS.get(key) != value}
            result = fake.execute(argv, workspace=workspace, working_directory=working_directory,
                                  environment=accepted)
            return (None if result.timed_out else result.exit_code), result.stdout, result.stderr

        self._captured = simulated_executor(profile, behavior)

    def execute_captured(self, argv, **options):
        return self._captured.execute_captured(argv, **options)

    def __getattr__(self, name: str):
        return getattr(self._fake, name)


def capturing_fake(profile: BuildProfile, fake: object) -> CapturingFake:
    return CapturingFake(profile, fake)
