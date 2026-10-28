"""Offline, bounded DWARF/native-PDB extraction.

``settings`` is the central job's flat reader settings mapping. ``tools`` maps
``llvm_dwarfdump``/``llvm_pdbutil`` to an absolute ``path`` and lowercase ``sha256``.
The optional trusted runner accepts argv plus timeout_seconds/max_output_bytes
and returns stdout bytes (or UTF-8 text); it must not evaluate a shell.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import math
from pathlib import Path
import queue
import subprocess
import threading
import time
from typing import Any, Mapping

from appsec_review.config.compiler_target import CompilerTarget
from appsec_review.debug_symbols.contract import Extraction, selected_path
from appsec_review.debug_symbols._reader_binary import ReaderFailure, pdb_identity, pe, verify_elf


_DEFAULTS = {
    "max_input_bytes": 536_870_912,
    "max_output_bytes": 16_777_216,
    "max_records": 100_000,
    "max_depth": 128,
    "timeout_seconds": 120,
}


def _limits(settings: Mapping[str, Any]) -> dict[str, int | float]:
    result = {}
    for name, default in _DEFAULTS.items():
        value = settings.get(name, default)
        if (type(value) not in (int, float) or not math.isfinite(value) or value <= 0
                or (name != "timeout_seconds" and type(value) is not int)):
            raise ValueError(f"invalid debug-symbol reader setting: {name}")
        result[name] = value
    if result["max_depth"] > 256:
        raise ValueError("debug-symbol max_depth cannot exceed parser safety ceiling 256")
    return result


def _read(path: Path, maximum: int) -> bytes:
    try:
        if path.stat().st_size > maximum:
            raise ReaderFailure("input_limit")
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
    except OSError as error:
        raise ReaderFailure("input_unavailable") from error
    if len(data) > maximum:
        raise ReaderFailure("input_limit")
    return data


def _tool(settings: Mapping[str, Any], name: str) -> Path:
    tools = settings.get("tools", {})
    spec = tools.get(name) if isinstance(tools, Mapping) else None
    if not isinstance(spec, Mapping) or not spec.get("path"):
        raise ReaderFailure("tool_unavailable")
    if not isinstance(spec["path"], str):
        raise ReaderFailure("tool_identity_unpinned")
    digest, path = spec.get("sha256"), Path(spec["path"])
    if (not path.is_absolute() or not isinstance(digest, str) or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)):
        raise ReaderFailure("tool_identity_unpinned")
    try:
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as error:
        raise ReaderFailure("tool_unavailable") from error
    if actual != digest:
        raise ReaderFailure("tool_identity_mismatch")
    return path


def _run(argv: list[str], *, timeout_seconds: float, max_output_bytes: int) -> bytes:
    """Drain a bounded pipe without communicate()'s unbounded output allocation."""
    messages: queue.Queue[bytes | None] = queue.Queue(maxsize=4)
    stopped = threading.Event()
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            shell=False,
        )
    except OSError as error:
        raise ReaderFailure("tool_unavailable") from error

    def drain():
        try:
            while not stopped.is_set():
                chunk = process.stdout.read(65536)
                if not chunk:
                    break
                while not stopped.is_set():
                    try:
                        messages.put(chunk, timeout=0.05)
                        break
                    except queue.Full:
                        pass
        finally:
            while not stopped.is_set():
                try:
                    messages.put(None, timeout=0.05)
                    break
                except queue.Full:
                    pass

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    end = time.monotonic() + timeout_seconds
    output = bytearray()
    try:
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise ReaderFailure("tool_timeout")
            try:
                chunk = messages.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                continue
            if chunk is None:
                break
            if len(output) + len(chunk) > max_output_bytes:
                raise ReaderFailure("output_limit")
            output.extend(chunk)
        try:
            code = process.wait(timeout=max(0.001, end - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise ReaderFailure("tool_timeout") from error
        if code:
            raise ReaderFailure("tool_failed")
        return bytes(output)
    finally:
        stopped.set()
        if process.poll() is None:
            process.kill()
            process.wait()
        reader.join(timeout=1)
        process.stdout.close()


def extract_symbols(
    binary: Path, debug_file: Path | None, *, target: CompilerTarget,
    settings: Mapping[str, Any], runner=None,
) -> Extraction:
    """Verify content and pairing before extracting; failures never publish partial records."""
    selected_path(target)
    limits = _limits(settings)
    name = "llvm_dwarfdump" if target is CompilerTarget.CLANG else "llvm_pdbutil"
    started = time.monotonic()
    try:
        format_gaps = set()
        image = _read(Path(binary), limits["max_input_bytes"])
        debug = _read(Path(debug_file), limits["max_input_bytes"]) if debug_file is not None else None
        if target is CompilerTarget.CLANG:
            elf_image = verify_elf(image, debug, limits["max_records"])
            if ".debug_types" in elf_image.sections or ".zdebug_types" in elf_image.sections:
                format_gaps.add("dwarf_type_units_unavailable")
            exporter_input = Path(debug_file) if debug is not None else Path(binary)
            args = ["--debug-info", "--debug-line", "--debug-ranges", "--debug-rnglists"]
        else:
            pe_image = pe(image, limits["max_records"])
            if debug is None:
                raise ReaderFailure("pdb_missing")
            if pdb_identity(debug, limits["max_records"]) != (pe_image.guid, pe_image.age):
                raise ReaderFailure("pdb_identity_mismatch")
            exporter_input = Path(debug_file)
            args = ["pdb2yaml", "--all"]
        executable = _tool(settings, name)
        output = (runner or _run)(
            [str(executable), *args, str(exporter_input.resolve())],
            timeout_seconds=limits["timeout_seconds"],
            max_output_bytes=limits["max_output_bytes"],
        )
        if isinstance(output, str):
            output = output.encode("utf-8")
        if not isinstance(output, bytes):
            raise ReaderFailure("malformed_tool_output")
        if len(output) > limits["max_output_bytes"]:
            raise ReaderFailure("output_limit")
        if time.monotonic() - started > limits["timeout_seconds"]:
            raise ReaderFailure("tool_timeout")
        text = output.decode("utf-8", "strict")
        if target is CompilerTarget.CLANG:
            from appsec_review.debug_symbols._reader_dwarf import parse_dwarf
            records, gaps = parse_dwarf(text, limits)
        else:
            from appsec_review.debug_symbols._reader_pdb import parse_pdb
            records, gaps = parse_pdb(text, pe_image, limits)
        gaps.update(format_gaps)
        if time.monotonic() - started > limits["timeout_seconds"]:
            raise ReaderFailure("tool_timeout")
        if len(records) > limits["max_records"]:
            raise ReaderFailure("record_limit")
        encoded_bytes = 0
        for record in records:
            encoded_bytes += len(json.dumps(asdict(record), ensure_ascii=False,
                                            separators=(",", ":")).encode("utf-8")) + 1
            if encoded_bytes > limits["max_output_bytes"]:
                raise ReaderFailure("output_limit")
        # Reject observed input drift before publishing records.
        if _read(Path(binary), limits["max_input_bytes"]) != image:
            raise ReaderFailure("input_identity_changed")
        if debug_file is not None and _read(Path(debug_file), limits["max_input_bytes"]) != debug:
            raise ReaderFailure("input_identity_changed")
        _tool(settings, name)
        if time.monotonic() - started > limits["timeout_seconds"]:
            raise ReaderFailure("tool_timeout")
        return Extraction(tuple(records), tuple(sorted(set(gaps))), name)
    except ReaderFailure as error:
        return Extraction((), (error.gap,), name)
    except (UnicodeError, ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
        return Extraction((), ("malformed_tool_output",), name)
    except (subprocess.TimeoutExpired, TimeoutError):
        return Extraction((), ("tool_timeout",), name)
    except subprocess.CalledProcessError:
        return Extraction((), ("tool_failed",), name)
