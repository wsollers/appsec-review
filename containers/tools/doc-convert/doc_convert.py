#!/opt/tool/bin/python -I
"""Bounded offline text extraction for one design document.

The application supplies every argument. Input is read from the read-only target mount; the only
writes are text.txt and manifest.json under --output-dir. Document content is data: it is never
evaluated, and pandoc runs with --sandbox so readers cannot touch files or the network.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

VERSION = "1.0.0"
SCHEMA = "appsec-review/document-conversion-output/1"
PANDOC_FORMATS = {"docx": "docx", "odt": "odt", "rtf": "rtf", "epub": "epub"}


def _pandoc() -> str:
    return str(Path(sys.executable).with_name("pandoc"))


def _details() -> str:
    try:
        import pypdf
        pypdf_version = pypdf.__version__
    except ImportError:
        pypdf_version = "unavailable"
    try:
        first = subprocess.run([_pandoc(), "--version"], capture_output=True, text=True, timeout=30,
                               check=False).stdout.splitlines()[0]
    except (OSError, IndexError, subprocess.SubprocessError):
        first = "pandoc unavailable"
    return f"pypdf {pypdf_version}\n{first}"


def _pdf(path: Path, max_pages: int) -> tuple[list[tuple[str, str]], str, list[str]]:
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError

    gaps: list[str] = []
    try:
        reader = PdfReader(str(path), strict=False)
        if reader.is_encrypted:
            try:
                if not reader.decrypt(""):
                    return [], "ENCRYPTED", ["document is encrypted"]
            except Exception:  # pypdf raises varied errors for unsupported encryption
                return [], "ENCRYPTED", ["document encryption is unsupported offline"]
        pages = reader.pages
        total = len(pages)
    except (PdfReadError, OSError, ValueError) as exc:
        return [], "FAILED", [f"PDF could not be parsed ({type(exc).__name__})"]
    segments: list[tuple[str, str]] = []
    for index in range(min(total, max_pages)):
        try:
            text = pages[index].extract_text() or ""
        except Exception as exc:  # one unreadable page must not discard its siblings
            gaps.append(f"page {index + 1}: text extraction failed ({type(exc).__name__})")
            text = ""
        segments.append((f"page {index + 1}", text))
    if total > max_pages:
        gaps.append(f"page bound max_pages={max_pages} reached; {total - max_pages} pages not converted")
    if not any(text.strip() for _, text in segments):
        return segments, "NO_TEXT", [*gaps, "no extractable text; scanned or image-only pages need OCR"]
    return segments, "SUCCEEDED", gaps


def _pandoc_convert(path: Path, source_format: str, timeout: int) -> tuple[list[tuple[str, str]], str, list[str]]:
    argv = [_pandoc(), "--sandbox", "--from", PANDOC_FORMATS[source_format], "--to", "gfm",
            "--wrap=none", "--eol=lf", str(path)]
    try:
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                                   check=False, env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"})
    except subprocess.TimeoutExpired:
        return [], "TIMEOUT", [f"pandoc exceeded {timeout}s"]
    except OSError as exc:
        return [], "FAILED", [f"pandoc unavailable ({type(exc).__name__})"]
    if completed.returncode != 0:
        return [], "FAILED", [f"pandoc exited {completed.returncode}"]
    text = completed.stdout.decode("utf-8", "replace")
    if not text.strip():
        return [("document", text)], "NO_TEXT", ["no extractable text"]
    return [("document", text)], "SUCCEEDED", []


def convert(args: argparse.Namespace) -> int:
    source = Path(args.input)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    data = source.read_bytes()
    input_sha256 = hashlib.sha256(data).hexdigest()
    if args.format == "pdf":
        segments, status, gaps = _pdf(source, args.max_pages)
    elif args.format in PANDOC_FORMATS:
        segments, status, gaps = _pandoc_convert(source, args.format, args.pandoc_timeout)
    else:
        segments, status, gaps = [], "UNSUPPORTED", [f"format {args.format} is not supported"]
    parts: list[str] = []
    ranges = []
    offset = 0
    truncated = False
    for label, text in segments:
        text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\0", "")
        remaining = args.max_chars - offset
        if remaining <= 0:
            truncated = True
            break
        if len(text) > remaining:
            text = text[:remaining]
            truncated = True
        parts.append(text)
        ranges.append({"label": label, "start_char": offset, "end_char": offset + len(text)})
        offset += len(text)
        if not text.endswith("\n"):
            parts.append("\n")
            offset += 1
    if truncated:
        gaps.append(f"character bound max_chars={args.max_chars} reached")
    text_bytes = "".join(parts).encode("utf-8")
    (output / "text.txt").write_bytes(text_bytes)
    manifest = {"schema": SCHEMA, "converter": f"doc-convert {VERSION}", "details": _details().splitlines(),
                "input_sha256": input_sha256, "input_bytes": len(data), "format": args.format,
                "status": status, "segments": ranges, "char_count": offset,
                "text_sha256": hashlib.sha256(text_bytes).hexdigest(), "truncated": truncated, "gaps": gaps}
    (output / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="doc-convert")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--version-details", action="store_true")
    parser.add_argument("--input")
    parser.add_argument("--format", choices=("pdf", *PANDOC_FORMATS))
    parser.add_argument("--output-dir")
    parser.add_argument("--max-pages", type=int, default=500)
    parser.add_argument("--max-chars", type=int, default=2_000_000)
    parser.add_argument("--pandoc-timeout", type=int, default=120)
    args = parser.parse_args(argv)
    if args.version:
        print(f"doc-convert {VERSION}")
        return 0
    if args.version_details:
        print(_details())
        return 0
    if not (args.input and args.format and args.output_dir):
        parser.error("--input, --format, and --output-dir are required")
    if not (1 <= args.max_pages <= 10_000 and 1 <= args.max_chars <= 64 * 1024 * 1024
            and 1 <= args.pandoc_timeout <= 3600):
        parser.error("bounds are outside the supported range")
    os.umask(0o022)
    return convert(args)


if __name__ == "__main__":
    raise SystemExit(main())
