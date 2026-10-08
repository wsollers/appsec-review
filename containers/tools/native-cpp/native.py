#!/usr/bin/env python3
"""Bounded native build/AST/IR/symbol driver. Target inputs are data, never commands."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

ROOT = Path("/scratch")
SOURCE = ROOT / "source"
BUILD = ROOT / "build"
OUT = ROOT / "analysis"

_NAMESPACE = re.compile(r"\bnamespace\s+([A-Za-z_]\w*)\s*\{")
_FUNCTION = re.compile(
    r"(?m)^[\t ]*(?:[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*(?:<[^;{}]+>)?[\s*&]+)+"
    r"([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?\{"
)


def run(argv: list[str], *, cwd: Path, timeout: int = 540) -> int:
    completed = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=timeout, check=False, env={
                                   "PATH": os.environ["PATH"], "HOME": "/tmp", "LANG": "C.UTF-8",
                                   "LC_ALL": "C.UTF-8", "TZ": "UTC", "CC": "clang-18",
                                   "CXX": "clang++-18", "SOURCE_DATE_EPOCH": "0",
                               })
    sys.stdout.buffer.write(completed.stdout[:8 * 1024 * 1024])
    sys.stderr.buffer.write(completed.stderr[:8 * 1024 * 1024])
    return completed.returncode


def configure(profile: str) -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    if profile == "cmake":
        return run(["cmake", "-S", str(SOURCE), "-B", str(BUILD),
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
                    "-DCMAKE_C_COMPILER=clang-18", "-DCMAKE_CXX_COMPILER=clang++-18"], cwd=BUILD)
    if profile == "make":
        return 0
    if profile == "autotools":
        code = run(["autoreconf", "-fi"], cwd=SOURCE)
        if code:
            return code
        return run([str(SOURCE / "configure"), "--disable-dependency-tracking", "CC=clang-18",
                    "CXX=clang++-18", f"--prefix={ROOT / 'install'}"], cwd=BUILD)
    return 64


def compile_case(profile: str) -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    database = BUILD / "compile_commands.json"
    if profile == "cmake":
        code = run(["cmake", "--build", str(BUILD), "--parallel", "2"], cwd=BUILD)
        if code == 0:
            emit_link_commands()
        return code
    command = ["make", "-j2", "CC=clang-18", "CXX=clang++-18"]
    cwd = SOURCE if profile == "make" else BUILD
    if database.exists():
        database.unlink()
    run(["make", "clean"], cwd=cwd, timeout=60)
    code = run(["bear", "--output", str(database), "--", *command], cwd=cwd)
    if code == 0:
        emit_link_commands()
    return code


def build_path(value: str) -> str | None:
    path = Path(value)
    if not path.is_absolute():
        path = BUILD / path
    try:
        return "build/" + path.resolve().relative_to(BUILD.resolve()).as_posix()
    except ValueError:
        return None


def emit_link_commands() -> None:
    receipts = []
    for link_file in sorted(BUILD.rglob("link.txt")):
        try:
            text = link_file.read_text(encoding="utf-8", errors="replace")[:1024 * 1024]
            argv = shlex.split(text)
        except (OSError, ValueError):
            continue
        output = None
        if "-o" in argv and argv.index("-o") + 1 < len(argv):
            output = build_path(argv[argv.index("-o") + 1])
        elif argv and (Path(argv[0]).name in {"ar", "llvm-ar"}
                       or Path(argv[0]).name.startswith("llvm-ar-")):
            output = next((build_path(value) for value in argv[1:] if value.endswith(".a")), None)
        inputs = sorted({mapped for value in argv for mapped in [build_path(value)]
                         if mapped and mapped != output
                         and not value.startswith("-")
                         and Path(value).suffix in {".o", ".obj", ".a", ".so"}})
        if output and inputs:
            receipts.append({"output_path": output, "input_paths": inputs,
                             "receipt": link_file.relative_to(BUILD).as_posix(),
                             "command_sha256": hashlib.sha256(text.encode()).hexdigest()})
    (BUILD / "link-commands.json").write_text(json.dumps(receipts, sort_keys=True), encoding="utf-8")


def load_commands() -> list[dict]:
    path = ROOT / "normalized-compile-commands.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or len(value) > 4096:
        raise ValueError("invalid normalized compile database")
    return value


def ast_filter(source: str) -> str:
    """Derive a bounded declaration filter from the current source file."""
    try:
        text = Path(source).read_text(encoding="utf-8", errors="replace")[:1024 * 1024]
    except OSError:
        return Path(source).stem
    text = text.replace('extern "C"', "")
    namespaces = [name for name in _NAMESPACE.findall(text) if name not in {"std", "__gnu_cxx"}]
    if namespaces:
        return "|".join(sorted(set(namespaces)))
    functions = sorted(set(_FUNCTION.findall(text)))
    if "main" in functions:
        return "main"
    if functions:
        prefix = os.path.commonprefix(functions)
        return prefix if len(prefix) >= 3 else functions[0]
    return Path(source).stem


def replay(mode: str) -> int:
    commands = load_commands()
    destination = OUT / mode
    destination.mkdir(parents=True, exist_ok=True)
    results = []
    for index, row in enumerate(commands):
        arguments = list(row["arguments"])
        source = row["file"]
        stem = f"tu-{index:04d}"
        if mode == "ast":
            output = destination / f"{stem}.json"
            argv = [arguments[0], *arguments[1:], "-Xclang", "-ast-dump=json",
                    "-Xclang", "-ast-dump-filter", "-Xclang", ast_filter(source),
                    "-fsyntax-only"]
        else:
            output = destination / f"{stem}.ll"
            argv = [arguments[0], *arguments[1:], "-emit-llvm", "-S", "-g", "-O0", "-o", str(output)]
        try:
            completed = subprocess.run(argv, cwd=SOURCE, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       timeout=180, check=False, env={"PATH": os.environ["PATH"],
                                       "HOME": "/tmp", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                                       "TZ": "UTC"})
            if mode == "ast":
                output.write_bytes(completed.stdout[:64 * 1024 * 1024])
            results.append({"index": index, "source": source, "exit_code": completed.returncode,
                            "output": output.relative_to(ROOT).as_posix(),
                            "stderr": completed.stderr.decode("utf-8", "replace")[:8192]})
        except subprocess.TimeoutExpired:
            results.append({"index": index, "source": source, "exit_code": None,
                            "output": output.relative_to(ROOT).as_posix(), "timeout": True})
    (destination / "receipt.json").write_text(json.dumps(results, sort_keys=True), encoding="utf-8")
    return 0 if all(item.get("exit_code") == 0 for item in results) else 2


def symbols() -> int:
    destination = OUT / "binary"
    destination.mkdir(parents=True, exist_ok=True)
    records = []
    for path in sorted(BUILD.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        magic = path.read_bytes()[:4]
        if path.suffix not in {".o", ".a", ".so"} and magic != b"\x7fELF":
            continue
        kind = "object" if path.suffix == ".o" else "library" if path.suffix in {".a", ".so"} else "executable"
        nm = subprocess.run(["nm", "-P", "--defined-only", str(path)], capture_output=True, check=False)
        elf = subprocess.run(["readelf", "-h", "-l", "-d", str(path)], capture_output=True, check=False)
        records.append({"path": path.relative_to(ROOT).as_posix(), "kind": kind,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "symbols": nm.stdout.decode("utf-8", "replace")[:4 * 1024 * 1024].splitlines()[:10000],
                        "metadata": elf.stdout.decode("utf-8", "replace")[:1024 * 1024]})
    (destination / "records.json").write_text(json.dumps(records, sort_keys=True), encoding="utf-8")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        return 64
    mode = sys.argv[1]
    if mode == "version":
        print("appsec-native-cpp 1.0.0")
        return 0
    if mode == "configure" and len(sys.argv) == 3:
        return configure(sys.argv[2])
    if mode == "compile" and len(sys.argv) == 3:
        return compile_case(sys.argv[2])
    if mode in {"ast", "ir"}:
        return replay(mode)
    if mode == "symbols":
        return symbols()
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
