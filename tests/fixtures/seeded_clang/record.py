"""Re-record ``recorded/`` from the project with the real clang-18 (manual; needs clang++-18).

Usage: ``python record.py``. Each translation unit is replayed the way ``containers/tools/native-cpp``
replays it (``-emit-llvm -S -g -O0``; ``-ast-dump=json -ast-dump-filter <function>``;
``--analyze -Xanalyzer -analyzer-checker=debug.DumpCFG`` for the source CFG text), with the
checkout path rewritten to ``/scratch/source`` so the recordings do not depend on where it was made.
"""
from __future__ import annotations

from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
PROJECT = HERE / "project"
RECORDED = HERE / "recorded"
TARGETS = {"util": ("checked_len", "copy_field", "clamp_len"), "net": ("handle_packet", "log_event"),
           "parse": ("parse_record",), "main": ("main",),
           **{f"mod_{x}": (f"helper_{x}",) for x in "abcdefgh"}}


def run(extra: list[str], stem: str) -> subprocess.CompletedProcess[bytes]:
    source = PROJECT / "src" / f"{stem}.cpp"
    return subprocess.run(["clang++-18", f"-ffile-prefix-map={PROJECT}=/scratch/source",
                           f"-I{PROJECT}/include", "-std=c++17", *extra, str(source)],
                          capture_output=True, check=True, cwd=PROJECT)


def main() -> None:
    for stem, names in TARGETS.items():
        ir = RECORDED / "ir" / f"{stem}.ll"
        ir.parent.mkdir(parents=True, exist_ok=True)
        run(["-emit-llvm", "-S", "-g", "-O0", "-o", str(ir)], stem)
        ir.write_text(ir.read_text().replace(str(PROJECT), "/scratch/source"), encoding="utf-8")
        cfg = RECORDED / "cfg" / f"{stem}.cfg.txt"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        done = subprocess.run(["clang++-18", f"-I{PROJECT}/include", "-std=c++17", "--analyze", "-Xanalyzer",
                               "-analyzer-checker=debug.DumpCFG", "-Xanalyzer", "-analyzer-output=text",
                               "-o", "/dev/null", str(PROJECT / "src" / f"{stem}.cpp")],
                              capture_output=True, check=True, cwd=PROJECT)
        cfg.write_text(done.stderr.decode().replace(str(PROJECT), "/scratch/source"), encoding="utf-8")
        for name in names:
            out = RECORDED / "ast" / stem / f"{name}.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            done = run(["-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter", "-Xclang", name,
                        "-fsyntax-only"], stem)
            text = done.stdout.decode().replace(str(PROJECT), "/scratch/source")
            out.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
