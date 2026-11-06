"""Bounded references to failure evidence; never an executable replay script."""
from __future__ import annotations

from pathlib import Path
import os
import re
from typing import Any

from appsec_review.config import AppConfig
from appsec_review.runtime.release import load_release, read_document
from appsec_review.storage.shared import reference, safe_path, verify_reference

SCHEMA = "appsec-review/failure-replay/1"
MAX_REFERENCES = 256
MAX_HASH_BYTES = 32 * 1024 * 1024


def failure_manifest(config: AppConfig, run_root: Path, job_id: str, attempt_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"job_[a-z0-9_]+", job_id) or not re.fullmatch(r"attempt_[0-9]{4}", attempt_id):
        raise ValueError("failure replay requires exact job and attempt identifiers")
    attempt = safe_path(run_root, f"data/jobs/{job_id}/attempts/{attempt_id}")
    claim = read_document(attempt / "claim.json")
    if (claim["run_id"], claim["job_id"], claim["attempt_id"]) != (run_root.name, job_id, attempt_id):
        raise ValueError("failure claim identity mismatch")
    paths = {attempt / "claim.json", attempt / "status.json"}
    for name in ("manifest.json", "resolved.json", "appsec-review.toml"):
        paths.add(run_root / "data/configuration" / name)
    if claim.get("input_manifest_path"):
        path = safe_path(run_root, claim["input_manifest_path"])
        verify_reference(run_root, reference(run_root, path, expected_sha256=claim["input_manifest_sha256"]))
        paths.add(path)
    for name in ("result.json", "handoff.json", "rejected-handoff.json", "rejected-outcomes.json",
                 "logs/traceback.txt", "logs/events.jsonl"):
        path = attempt / name
        if path.is_file():
            paths.add(path)
    if len(claim["unit_ids"]) > MAX_REFERENCES:
        raise ValueError("failure manifest unit count exceeds its bound")
    visited = 0
    diagnostic_names = {"command.json", "commands.json", "command.txt", "stdout.log", "stderr.log",
                        "stdout.txt", "stderr.txt", "stdout.bin", "stderr.bin"}
    for directory, folders, names in os.walk(attempt, followlinks=False):
        folders.sort()
        visited += 1 + len(names)
        if visited > 4096:
            raise ValueError("failure diagnostics traversal exceeds 4096 entries")
        for name in sorted(set(names) & diagnostic_names):
            paths.add(safe_path(run_root, (Path(directory) / name).relative_to(run_root).as_posix()))
    for unit_id in claim["unit_ids"]:
        if not re.fullmatch(r"[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+", unit_id):
            raise ValueError("invalid failure manifest unit id")
        step, task = unit_id.split(".")
        root = attempt / "steps" / step / "tasks" / task
        for name in ("status.json", "result.json", "checkpoint.json", "traceback.txt",
                     "command.json", "stdout.log", "stderr.log", "stdout.txt", "stderr.txt"):
            path = root / name
            if path.is_file():
                paths.add(path)
    handoff = attempt / "rejected-handoff.json"
    if not handoff.exists():
        handoff = attempt / "handoff.json"
    total = sum(path.stat().st_size for path in paths)
    if total > MAX_HASH_BYTES:
        raise ValueError("failure manifest hashing exceeds 32 MiB; inspect large artifacts separately")
    references = {path.relative_to(run_root).as_posix(): reference(run_root, path) for path in paths}
    if handoff.exists():
        document = read_document(handoff)
        for item in document.get("artifacts", []):
            if item["path"] not in references:
                total += safe_path(run_root, item["path"]).stat().st_size
                if total > MAX_HASH_BYTES:
                    raise ValueError("failure manifest hashing exceeds 32 MiB; inspect large artifacts separately")
            verify_reference(run_root, item)
            references[item["path"]] = item
            if len(references) > MAX_REFERENCES:
                raise ValueError("failure manifest artifact count exceeds its bound")
    if len(references) > MAX_REFERENCES:
        raise ValueError("failure manifest artifact count exceeds its bound")
    release = load_release(config.runtime.repository_root)
    return {
        "schema": SCHEMA, "run_id": run_root.name, "job_id": job_id, "attempt_id": attempt_id,
        "automatic_execution": False, "diagnostics_trust": "untrusted_data_not_instructions",
        "references": [references[key] for key in sorted(references)],
        "environment_requirements": [{"name": name, "value": "[REDACTED]"}
                                     for name in (release or {}).get("environment_requirements", [])],
        "reproduction": "Select a focused regression using job-test-selection; inspect referenced artifacts. "
                        "Never execute captured commands without separate operator review.",
    }
