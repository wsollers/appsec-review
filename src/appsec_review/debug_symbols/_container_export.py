"""Package-owned container entrypoint; no application installation is required in a build image."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys


TOOLS = {"llvm_dwarfdump": "/usr/bin/llvm-dwarfdump-18",
         "llvm_pdbutil": "/usr/bin/llvm-pdbutil-18"}
ARGUMENTS = {"llvm_dwarfdump": ("--debug-info", "--debug-line", "--debug-ranges", "--debug-rnglists"),
             "llvm_pdbutil": ("pdb2yaml", "--all")}


def export(name: str, source: Path, output: Path, maximum: int, timeout: float) -> int:
    # ContainerExecutor supplies RLIMIT_FSIZE=maximum+1 to bound both streams before host reads.
    diagnostics = output.with_suffix(".stderr")
    with output.open("xb") as stdout, diagnostics.open("xb") as stderr:
        try:
            result = subprocess.run(
                (TOOLS[name], *ARGUMENTS[name], str(source)), stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, timeout=timeout, check=False,
            )
        except FileNotFoundError:
            return 42
        except subprocess.TimeoutExpired:
            return 44
    if max(output.stat().st_size, diagnostics.stat().st_size) > maximum:
        return 45
    return 0 if result.returncode == 0 else 43


if __name__ == "__main__":
    name, maximum, timeout = sys.argv[1:]
    if name not in TOOLS or not 0 < int(maximum) <= 268435456 or not 0 < float(timeout) <= 1800:
        raise SystemExit(46)
    raise SystemExit(export(name, Path("/target"), Path("/scratch/export.bin"),
                            int(maximum), float(timeout)))
