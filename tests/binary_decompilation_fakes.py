"""A fake Docker runner that stands in for the Ghidra container in unit tests.

It writes the same export tree ``AppsecExportProgram.java`` produces for the case-083 fixture, so
the normalizer, publication store, and efficacy evaluator are exercised without Docker.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_review.container_runtime.executor import CommandOutcome


IMAGE_ID = "sha256:" + "a" * 64
EXPORT_SCHEMA = "appsec-review/ghidra-export/1"

FUNCTIONS = [
    {"address": "0x101030", "name": "strcpy", "qualified_name": "<EXTERNAL>::strcpy",
     "is_thunk": True, "thunk_target": "<EXTERNAL>::strcpy", "thunk_target_external": True,
     "decompile_status": "skipped_thunk"},
    {"address": "0x101150", "name": "main", "qualified_name": "main", "is_thunk": False,
     "name_source": "IMPORTED", "decompile_status": "ok"},
    {"address": "0x1011b0", "name": "print_label", "qualified_name": "print_label",
     "is_thunk": False, "name_source": "IMPORTED", "decompile_status": "ok"},
]
DECOMPILED = [
    {"address": "0x101150", "truncated": False,
     "c": "\nint main(int argc,char **argv)\n\n{\n  print_label(argv[1]);\n  return 0;\n}\n\n"},
    {"address": "0x1011b0", "truncated": False,
     "c": "\nvoid print_label(char *input)\n\n{\n  char label [32];\n  strcpy(label,input);\n}\n\n"},
]
PCODE = [
    {"address": "0x101150", "truncated": False, "operations": [
        {"address": "0x101195", "order": 1, "mnemonic": "CALL", "output": None,
         "inputs": ["(ram, 0x1011b0, 8)"], "callee": "print_label"}]},
    {"address": "0x1011b0", "truncated": False, "operations": [
        {"address": "0x1011c4", "order": 1, "mnemonic": "CALL", "output": None,
         "inputs": ["(ram, 0x101030, 8)"], "callee": "<EXTERNAL>::strcpy"},
        {"address": "0x1011dc", "order": 2, "mnemonic": "RETURN", "output": None, "inputs": []}]},
]
CALLS = [
    {"from_function": "0x101030", "call_site": "0x101030", "to": "0x105010",
     "to_name": "<EXTERNAL>::strcpy", "resolved_name": "<EXTERNAL>::strcpy",
     "resolved_external": True, "kind": "call", "computed": True},
    {"from_function": "0x101150", "call_site": "0x101195", "to": "0x1011b0",
     "to_name": "print_label", "resolved_name": "print_label", "resolved_external": False,
     "kind": "call", "computed": False},
    {"from_function": "0x1011b0", "call_site": "0x1011c4", "to": "0x101030",
     "to_name": "<EXTERNAL>::strcpy", "resolved_name": "<EXTERNAL>::strcpy",
     "resolved_external": True, "kind": "call", "computed": False},
]
IMPORTS = [
    {"name": "strcpy", "library": "<EXTERNAL>", "kind": "function", "thunks": ["0x101030"]},
    {"name": "printf", "library": "<EXTERNAL>", "kind": "function", "thunks": ["0x101040"]},
]
EXPORTS = [{"address": "0x101150", "name": "main", "is_function": True}]
STRINGS = [
    {"address": "0x102004", "length": 4, "truncated": False, "value": "demo", "data_type": "char[5]",
     "xrefs": [{"from": "0x101181", "function": "0x101150"}], "xrefs_truncated": False},
    {"address": "0x102009", "length": 9, "truncated": False, "value": "label=%s\n",
     "data_type": "char[10]", "xrefs": [{"from": "0x1011cd", "function": "0x1011b0"}],
     "xrefs_truncated": False},
]


def _jsonl(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def write_export(root: Path, executable_sha256: str, *, program: dict[str, Any] | None = None,
                 gaps: Sequence[dict[str, Any]] = (), complete: bool = True) -> None:
    root.mkdir(parents=True, exist_ok=True)
    document = {"schema": EXPORT_SCHEMA, "ghidra_version": "12.1.4", "name": "case083-symbols",
                "executable_format": "Executable and Linking Format (ELF)",
                "executable_sha256": executable_sha256, "language": "x86:LE:64:default",
                "compiler_spec": "gcc", "compiler": "unknown", "big_endian": False,
                "pointer_size": 8, "image_base": "0x100000", "analysis_timed_out": False,
                **(program or {})}
    (root / "program.json").write_text(json.dumps(document) + "\n", encoding="utf-8")
    _jsonl(root / "functions.jsonl", FUNCTIONS)
    _jsonl(root / "decompiled.jsonl", DECOMPILED)
    _jsonl(root / "pcode.jsonl", PCODE)
    _jsonl(root / "calls.jsonl", CALLS)
    _jsonl(root / "imports.jsonl", IMPORTS)
    _jsonl(root / "exports.jsonl", EXPORTS)
    _jsonl(root / "strings.jsonl", STRINGS)
    _jsonl(root / "gaps.jsonl", list(gaps))
    if complete:
        (root / "complete.json").write_text(json.dumps({
            "schema": EXPORT_SCHEMA, "ghidra_version": "12.1.4", "executable_sha256": executable_sha256,
            "counts": {"functions": len(FUNCTIONS), "functions_not_exported": 0,
                       "strings": len(STRINGS), "strings_not_exported": 0}}) + "\n", encoding="utf-8")


def mount_source(argv: Sequence[str], target: str) -> Path:
    for index, value in enumerate(argv):
        if value == "--mount" and f",dst={target}" in argv[index + 1]:
            return Path(argv[index + 1].split("src=", 1)[1].split(",dst=", 1)[0])
    raise AssertionError(f"no mount for {target}")


class FakeDocker:
    """Records every command; ``export`` decides what a ``docker run`` leaves in scratch."""

    def __init__(self, *, image_id: str = IMAGE_ID, outcome: CommandOutcome | None = None,
                 export: Callable[[Path, str], None] | None = None):
        self.calls: list[list[str]] = []
        self.image_id = image_id
        self.outcome = outcome or CommandOutcome(0, b"INFO  REPORT: Import succeeded\n", b"")
        self.export = export or (lambda root, sha256: write_export(root, sha256))

    @property
    def runs(self) -> list[list[str]]:
        return [call for call in self.calls if call[:2] == ["docker", "run"]]

    def __call__(self, argv: Sequence[str], timeout: int) -> CommandOutcome:
        call = list(argv)
        self.calls.append(call)
        if call[:3] == ["docker", "image", "inspect"]:
            return CommandOutcome(0, (self.image_id + "\n").encode(), b"")
        if call[:2] == ["docker", "kill"]:
            return CommandOutcome(0, b"", b"")
        if call[:2] == ["docker", "run"] and "/opt/appsec/bin/ghidra-export" in call:
            name = call[call.index("--input") + 1].rsplit("/", 1)[1]
            staged = mount_source(call, "/target") / name
            if self.outcome.exit_code == 0 and not self.outcome.timed_out:
                self.export(mount_source(call, "/scratch") / "export",
                            hashlib.sha256(staged.read_bytes()).hexdigest())
            return self.outcome
        if call[:2] == ["docker", "run"]:  # fixture compile
            output = call[call.index("-o") + 1].rsplit("/", 1)[1]
            (mount_source(call, "/scratch") / output).write_bytes(b"\x7fELF fixture " + output.encode())
            return CommandOutcome(0, b"", b"")
        raise AssertionError(f"unexpected command: {call[:4]}")
