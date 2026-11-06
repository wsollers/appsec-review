from __future__ import annotations

import os
from pathlib import Path
import subprocess

from .config import GateError


def run(
    argv: list[str], root: Path, timeout: int, *, allowed: tuple[int, ...] = (0,),
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv, cwd=root, env={**os.environ, **(environment or {})},
            text=True, encoding="utf-8", capture_output=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as error:
        raise GateError("missing-tool", f"{argv[0]} is not installed") from error
    except subprocess.TimeoutExpired as error:
        raise GateError("timeout", f"{argv[0]} exceeded {timeout}s") from error
    except (OSError, UnicodeError) as error:
        raise GateError("tool-error", f"{argv[0]} could not execute: {error}") from error
    if result.returncode not in allowed:
        raise GateError(
            "tool-failure",
            f"{argv[0]} exited {result.returncode}\n{result.stdout}\n{result.stderr}",
        )
    return result
