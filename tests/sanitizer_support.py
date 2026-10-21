"""Test doubles for ``job_sanitizer_build``: tiny ELF files with symbol tables and a fake Docker CLI.

The fake replaces only the Docker CLI under the real ``BuildContainerExecutor``, so the tests
exercise the executor's actual ``docker run`` argument construction (environment, mounts,
capabilities). The simulated build tool writes ELF files whose symbol tables reflect whether the
sanitizer flags reached its environment, which is exactly the observable the job verifies. No
file written here is ever executed.
"""

from __future__ import annotations

from collections.abc import Sequence
import json
from pathlib import Path
import struct

from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile


ET_REL, ET_EXEC = 1, 2
ASAN_UNDEFINED = ("__asan_init", "__asan_report_load4", "__asan_memcpy")
UBSAN_UNDEFINED = ("__ubsan_handle_add_overflow", "__ubsan_handle_type_mismatch_v1")
MISSING_RUNTIME_STDERR = (b"/usr/bin/ld: cannot find /usr/lib/llvm-18/lib/clang/18/lib/linux/"
                          b"libclang_rt.asan-x86_64.a: No such file or directory\n")


def elf_with_symbols(kind: int = ET_EXEC, *, defined: Sequence[str] = ("main",),
                     undefined: Sequence[str] = (), symbol_tables: bool = True) -> bytes:
    """A little-endian ELF64 holding only a section header table with ``.symtab``/``.strtab``."""
    names = [*defined, *undefined]
    strtab = b"\0"
    offsets = {}
    for name in names:
        offsets[name] = len(strtab)
        strtab += name.encode() + b"\0"
    symtab = b"\0" * 24
    for name in names:
        section = 1 if name in defined else 0
        symtab += struct.pack("<IBBHQQ", offsets[name], 0x12, 0, section, 0, 0)
    shstrtab = b"\0.text\0.symtab\0.strtab\0.shstrtab\0"
    names_at = {".text": 1, ".symtab": 7, ".strtab": 15, ".shstrtab": 23}
    body = b""
    placed = {}
    cursor = 64

    def place(label: str, data: bytes) -> None:
        nonlocal body, cursor
        placed[label] = (cursor, len(data))
        body += data
        cursor += len(data)

    place(".text", b"\x90")
    if symbol_tables:
        place(".symtab", symtab)
        place(".strtab", strtab)
    place(".shstrtab", shstrtab)
    sections = [b"\0" * 64]
    for label in (".text", ".symtab", ".strtab", ".shstrtab"):
        if label not in placed:
            continue
        offset, size = placed[label]
        kind_id = {".text": 1, ".symtab": 2, ".strtab": 3, ".shstrtab": 3}[label]
        entry = 24 if label == ".symtab" else 0
        sections.append(struct.pack("<IIQQQQIIQQ", names_at[label], kind_id, 0, 0, offset, size, 0, 0, 1, entry))
    shoff = cursor
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack("<HHIQQQIHHHHHH", kind, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64,
                                 len(sections), len(sections) - 1)
    return header + body + b"".join(sections)


def instrumented_elf(kind: int = ET_EXEC, *, symbol_tables: bool = True) -> bytes:
    return elf_with_symbols(kind, undefined=(*ASAN_UNDEFINED, *UBSAN_UNDEFINED), symbol_tables=symbol_tables)


class DockerFake:
    """A recording Docker CLI whose simulated build honours (or ignores) the injected environment."""

    def __init__(self, profile: BuildProfile, *, mode: str = "honor_env", fail_ordinal: int | None = None):
        self.profile = profile
        self.mode = mode
        self.fail_ordinal = fail_ordinal
        self.runs: list[dict] = []

    def executor(self, timeout_seconds: int = 90, output_bytes: int = 1_000_000) -> BuildContainerExecutor:
        return BuildContainerExecutor(self.profile, timeout_seconds=timeout_seconds,
                                      output_bytes=output_bytes, runner=self)

    def __call__(self, argv: Sequence[str], _timeout: int):
        argv = tuple(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, self.profile.image_id.encode(), b"", False
        if argv[:2] == ("docker", "inspect"):
            return 0, json.dumps([{"Destination": "/", "Source": "/"}]).encode(), b"", False
        if argv[:3] == ("docker", "rm", "--force"):
            return 0, b"", b"", False
        entry = argv.index("--entrypoint")
        command = (argv[entry + 1], *argv[entry + 3:])
        environment = dict(argv[index + 1].split("=", 1) for index, value in enumerate(argv[:-1])
                           if value == "--env")
        mount = next(argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "--mount")
        fields = dict(item.split("=", 1) for item in mount.split(",") if "=" in item)
        workdir = argv[argv.index("--workdir") + 1].removeprefix("/workspace/")
        self.runs.append({"command": command, "environment": environment, "workdir": workdir,
                          "image_id": argv[entry + 2], "docker": argv})
        ordinal = len(self.runs)
        if self.fail_ordinal == ordinal:
            if self.mode == "missing_runtime":
                return 1, b"", MISSING_RUNTIME_STDERR, False
            return 2, b"", b"compile failed", False
        if "--build" in command:
            self._build(Path(fields["src"]) / workdir if workdir != "." else Path(fields["src"]), environment)
        return 0, b"ok", b"", False

    def _build(self, root: Path, environment: dict[str, str]) -> None:
        sanitized = "-fsanitize=address" in environment.get("CXXFLAGS", "") and self.mode != "ignore_env"
        tables = self.mode != "stripped"
        build = root / "build"
        objects = build / "CMakeFiles" / "sample.dir"
        objects.mkdir(parents=True, exist_ok=True)
        probe = build / "CMakeFiles" / "3.28.3" / "CompilerIdCXX"
        probe.mkdir(parents=True, exist_ok=True)
        if sanitized:
            (objects / "main.cpp.o").write_bytes(instrumented_elf(ET_REL, symbol_tables=tables))
            (build / "sample").write_bytes(instrumented_elf(symbol_tables=tables))
            (probe / "a.out").write_bytes(instrumented_elf())
        else:
            (objects / "main.cpp.o").write_bytes(elf_with_symbols(ET_REL, undefined=("puts",)))
            (build / "sample").write_bytes(elf_with_symbols(undefined=("puts",)))
            (probe / "a.out").write_bytes(elf_with_symbols(undefined=("puts",)))
        if self.mode == "no_binaries":
            for path in (objects / "main.cpp.o", build / "sample"):
                path.unlink()
