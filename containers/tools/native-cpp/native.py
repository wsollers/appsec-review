#!/usr/bin/env python3
"""Bounded native build/AST/IR/symbol driver. Target inputs are data, never commands."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

ROOT = Path("/scratch")
SOURCE = ROOT / "source"
BUILD = ROOT / "build"
OUT = ROOT / "analysis"


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


def load_commands(mode: str = "") -> list[dict]:
    """The rows to replay: a seeded run's selected subset when the job wrote one, else every row.

    ``replay-<mode>.json`` is written by the seeded job beside the normalized database; its rows are
    renumbered from zero, so the receipt and ``tu-NNNN`` outputs index the subset, never the whole
    program. An AST row may carry ``ast_filters``: one declaration name per entry.
    """
    path = ROOT / "normalized-compile-commands.json"
    if mode and (ROOT / f"replay-{mode}.json").is_file():
        path = ROOT / f"replay-{mode}.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or len(value) > 4096:
        raise ValueError("invalid normalized compile database")
    return value


def replay(mode: str) -> int:
    commands = load_commands(mode)
    destination = OUT / mode
    destination.mkdir(parents=True, exist_ok=True)
    results = []
    for index, row in enumerate(commands):
        arguments = list(row["arguments"])
        source = row["file"]
        stem = f"tu-{index:04d}"
        filters = [str(name) for name in row.get("ast_filters") or () if str(name)] if mode == "ast" else []
        filters_truncated = len(filters) > 400
        filters = filters[:400]
        if mode == "ast":
            output = destination / f"{stem}.json"
            argvs = [[*arguments, "-Xclang", "-ast-dump=json",
                      *(["-Xclang", "-ast-dump-filter", "-Xclang", name] if name else []),
                      "-fsyntax-only"] for name in (filters or [""])]
        elif mode == "cfg":
            # Source-level clang::CFG text (debug.DumpCFG) for the unit; the plist the analyzer writes
            # is discarded. The checker prints to stderr, which is what is retained.
            output = destination / f"{stem}.cfg.txt"
            argvs = [[arguments[0], *arguments[1:], "--analyze", "-Xanalyzer", "-analyzer-checker=debug.DumpCFG",
                      "-Xanalyzer", "-analyzer-output=text", "-o", str(destination / f"{stem}.plist")]]
        else:
            output = destination / f"{stem}.ll"
            argvs = [[arguments[0], *arguments[1:], "-emit-llvm", "-S", "-g", "-O0", "-o", str(output)]]
        try:
            code, stdout, stderr = 0, b"", b""
            for argv in argvs:
                completed = subprocess.run(argv, cwd=Path(row.get("directory", SOURCE)), stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           timeout=180, check=False, env={"PATH": os.environ["PATH"],
                                           "HOME": "/tmp", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                                           "TZ": "UTC"})
                code = code or completed.returncode
                stdout += completed.stdout
                stderr += completed.stderr
            if mode == "ast":
                output.write_bytes(stdout[:64 * 1024 * 1024])
            elif mode == "cfg":
                output.write_bytes(stderr[:16 * 1024 * 1024])
                (destination / f"{stem}.plist").unlink(missing_ok=True)
            results.append({"index": index, "source": source, "exit_code": code,
                            "output": output.relative_to(ROOT).as_posix(),
                            "output_truncated": filters_truncated or (
                                len(stdout) > 64 * 1024 * 1024 if mode == "ast" else
                                len(stderr) > 16 * 1024 * 1024 if mode == "cfg" else False),
                            "stderr": stderr.decode("utf-8", "replace")[:8192]})
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
        tools, streams = {}, {}
        for tool, args, limit in (("nm", ["-P", "--defined-only"], 4 * 1024 * 1024),
                                  ("readelf", ["-h", "-l", "-d"], 1024 * 1024)):
            try:
                completed = subprocess.run([tool, *args, str(path)], capture_output=True, check=False, timeout=180)
                stdout, stderr = completed.stdout, completed.stderr
                tools[tool] = {"exit_code": completed.returncode, "timeout": False,
                               "stderr": stderr.decode("utf-8", "replace")[:8192],
                               "stderr_truncated": len(stderr) > 8192,
                               "output_truncated": len(stdout) > limit or (
                                   tool == "nm" and len(stdout.splitlines()) > 10000)}
                streams[tool] = stdout[:limit].decode("utf-8", "replace")
            except (subprocess.TimeoutExpired, OSError) as exc:
                tools[tool] = {"exit_code": None, "timeout": isinstance(exc, subprocess.TimeoutExpired),
                               "stderr": str(exc)[:8192], "output_truncated": False}
                streams[tool] = ""
        records.append({"path": path.relative_to(ROOT).as_posix(), "kind": kind,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "symbols": streams["nm"].splitlines()[:10000],
                        "metadata": streams["readelf"], "tools": tools})
    (destination / "records.json").write_text(json.dumps(records, sort_keys=True), encoding="utf-8")
    return 2 if any(receipt["exit_code"] != 0 or receipt.get("output_truncated")
                    for record in records for receipt in record["tools"].values()) else 0


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
    if mode in {"ast", "ir", "cfg"}:
        return replay(mode)
    if mode == "symbols":
        return symbols()
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
