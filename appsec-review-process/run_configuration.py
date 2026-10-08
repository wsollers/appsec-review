#!/usr/bin/env python3
"""Allocate a run and materialize its immutable operational configuration."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import date
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Iterator

import configuration
from execution_state import RUNS, atomic_bytes, atomic_json
from job_runtime import JobContext, JobRuntime, JobSpec


JOB_ID = "00-run-configuration"
CONFIGURATION_NAMESPACE = "job_0000.run_configuration"
STATUS_SCHEMA = "appsec-review/bootstrap-job-status/1"
ARTIFACT_SCHEMA = "appsec-review/run-configuration/1"


@dataclass(frozen=True)
class Parameters:
    config_uri: str | None = None


@dataclass(frozen=True)
class Output:
    config_path: Path
    source_sha256: str
    effective_fingerprint: str


@contextmanager
def _blocking_file_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = path.open("a+b")
    stream.seek(0, 2)
    if stream.tell() == 0:
        stream.write(b"\0")
        stream.flush()
    stream.seek(0)
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()


def allocate_run_directory(runs_root: Path = RUNS, *, day: date | None = None) -> Path:
    """Allocate ``yyyy-mm-dd-####`` under the existing run root without serial reuse."""
    root = Path(runs_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    today = (day or date.today()).isoformat()
    pattern = re.compile(re.escape(today) + r"-(\d{4})\Z")
    sequence_dir = root / ".run-sequences"
    counter = sequence_dir / today
    with _blocking_file_lock(root / ".run-allocation.lock"):
        recorded = 0
        if counter.is_file():
            try:
                recorded = int(counter.read_text(encoding="ascii").strip())
            except (OSError, ValueError):
                raise RuntimeError(f"invalid run allocation counter: {counter}") from None
        existing = [int(match.group(1)) for item in root.iterdir()
                    if item.is_dir() and (match := pattern.fullmatch(item.name))]
        serial = max([recorded, *existing], default=0) + 1
        if serial > 9999:
            raise RuntimeError(f"daily run serial exhausted for {today}")
        run_root = root / f"{today}-{serial:04d}"
        run_root.mkdir(exist_ok=False)
        sequence_dir.mkdir(parents=True, exist_ok=True)
        atomic_bytes(counter, f"{serial}\n".encode("ascii"))
    return run_root


def _write_immutable(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o444)


def _handler(context: JobContext, parameters: Parameters) -> Output:
    source = configuration.resolve_config_uri(parameters.config_uri)
    if source.is_symlink() or not source.is_file():
        raise configuration.ConfigurationError(f"configuration source must be a regular non-linked file: {source}")
    document = configuration.load_document(source)
    raw = source.read_bytes()
    destination = context.run_root / configuration.RUN_CONFIG_RELATIVE
    _write_immutable(destination, raw)
    resolved = configuration.resolve_layered("job_0000", "run_configuration", run_config=document)
    effective = dict(resolved.redacted())
    effective["schema"] = ARTIFACT_SCHEMA
    effective["source_sha256"] = document.sha256
    effective_path = destination.with_name("effective-config.json")
    _write_immutable(effective_path, (json.dumps(effective, indent=2, sort_keys=True) + "\n").encode())
    return Output(destination, document.sha256, resolved.fingerprint)


def _validator(context: JobContext, output: Output) -> None:
    expected = context.run_root / configuration.RUN_CONFIG_RELATIVE
    if output.config_path != expected or not expected.is_file():
        raise RuntimeError("run-owned configuration artifact was not materialized at the canonical path")
    document = configuration.load_document(expected)
    if document.sha256 != output.source_sha256:
        raise RuntimeError("run-owned configuration bytes changed before validation")
    resolved = configuration.resolve_layered("job_0000", "run_configuration", run_config=document)
    if resolved.fingerprint != output.effective_fingerprint:
        raise RuntimeError("effective configuration fingerprint changed before validation")


SPEC = JobSpec(JOB_ID, CONFIGURATION_NAMESPACE, "bootstrap", _handler, _validator)
RUNTIME = JobRuntime({JOB_ID: SPEC})


def _status(context: JobContext, status: str, *, output: Output | None = None, error: str | None = None) -> dict:
    record = {
        "schema": STATUS_SCHEMA,
        "run_id": context.run_id,
        "job_id": JOB_ID,
        "status": status,
        "attempt_id": context.attempt_root.name,
        "config_artifact": configuration.RUN_CONFIG_RELATIVE.as_posix() if output else None,
        "source_sha256": output.source_sha256 if output else None,
        "effective_fingerprint": output.effective_fingerprint if output else None,
        "error": error,
    }
    atomic_json(context.attempt_root / "status.json", record)
    return record


def create_run(config_uri: str | None = None, *, runs_root: Path = RUNS, day: date | None = None) -> dict:
    """Run the bootstrap job. A failed first job leaves a diagnosed run but publishes no config."""
    run_root = allocate_run_directory(runs_root, day=day)
    context = JobContext(run_root.name, run_root,
                         run_root / "data" / "jobs" / JOB_ID / "whole" / "attempts" / "attempt-0001")
    context.attempt_root.mkdir(parents=True)
    result = RUNTIME.execute(JOB_ID, context, Parameters(config_uri))
    if result.status != "OK":
        return _status(context, "FAILED", error=result.error)
    return _status(context, "OK", output=result.output)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config_uri", nargs="?", help="optional local path or file URI; empty uses the tracked default")
    parser.add_argument("--runs-root", type=Path, default=RUNS)
    args = parser.parse_args(argv)
    status = create_run(args.config_uri, runs_root=args.runs_root)
    print(json.dumps(status, indent=2, sort_keys=True))
    return 0 if status["status"] == "OK" else 1


if __name__ == "__main__":
    raise SystemExit(_main())
