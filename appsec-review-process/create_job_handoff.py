#!/usr/bin/env python3
"""Render an immutable, run-owned handoff from fully resolved registry records."""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from execution_state import (ROOT, atomic_json, beneath, digest, file_hash, identifier, now,
                             read_json, run_path)
from job_graph import KINDS, REGISTRY, composition

SCHEMA = "appsec-review/job-handoff/1.0"
MAX_INPUTS = 64
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 64 * 1024 * 1024


def _relative(value: str) -> PurePosixPath:
    if (not isinstance(value, str) or not value or "\\" in value or
            re.match(r"^[A-Za-z]:", value)):
        raise ValueError("handoff input must be a normalized run-relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts or path.as_posix() != value:
        raise ValueError("handoff input must be a normalized run-relative POSIX path")
    if path.parts[0] not in {"inputs", "data"}:
        raise ValueError("handoff inputs are limited to run-owned inputs/ and data/")
    return path


def _repo_file(relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("registry prompt must be a normalized repository-relative path")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or "." in pure.parts or ".." in pure.parts or pure.as_posix() != relative:
        raise ValueError("registry prompt must be a normalized repository-relative path")
    if pure.parts[0] == "appsec-review-process":
        path = beneath(ROOT, ROOT / Path(*pure.parts[1:]))
    else:
        path = beneath(ROOT.parent, ROOT.parent / Path(*pure.parts))
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"registry prompt is not a regular file: {relative}")
    return path


def _source_record(path: Path, value: dict[str, Any]) -> dict[str, Any]:
    relative = "appsec-review-process/" + path.relative_to(ROOT).as_posix()
    return {"path": relative, "sha256": file_hash(path),
            "record": value}


def _result_schema_record(contract: dict[str, Any]) -> dict[str, str] | None:
    """Resolve an opted-in result schema without changing older contract identities."""
    declaration = contract.get("result_schema")
    if declaration is None:
        return None
    if not isinstance(declaration, dict):
        raise ValueError("output contract result_schema must be an object")
    name = declaration.get("schema_file")
    if (not isinstance(name, str) or PurePosixPath(name).name != name or
            "\\" in name or not name.endswith(".schema.json")):
        raise ValueError("output contract result schema must name one schemas/ file")
    path = beneath(ROOT.parent / "schemas", ROOT.parent / "schemas" / name)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"declared result schema is not a regular file: {name}")
    return {"path": f"schemas/{name}", "sha256": file_hash(path)}


def _claim_class_record(contract: dict[str, Any]) -> dict[str, str] | None:
    """Hash an opted-in claim boundary without changing older handoff shapes."""
    declaration = contract.get("claim_class")
    if declaration is None:
        return None
    if not isinstance(declaration, dict):
        raise ValueError("output contract claim_class must be an object")
    claim_class_id = declaration.get("claim_class_id")
    if (not isinstance(claim_class_id, str) or
            not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", claim_class_id)):
        raise ValueError("output contract claim class identity is invalid")
    return {"claim_class_id": claim_class_id,
            "sha256": "sha256:" + digest(declaration)}


def default_inputs(run_id: str) -> list[str]:
    """Return only the fixed, known run-owned context files that currently exist."""
    owner = run_path(run_id)
    candidates = ["inputs/artifact-manifest.json", "data/jobs/00-intake/whole/accepted.json"]
    return [value for value in candidates if (owner / Path(*value.split("/"))).is_file()]


def build_handoff(run_id: str, job_id: str, input_paths: list[str], scope_id: str = "whole"
                  ) -> dict[str, Any]:
    run_id, job_id, scope_id = identifier(run_id), identifier(job_id), identifier(scope_id)
    template_path = REGISTRY / "job-templates" / f"{job_id}.json"
    if not template_path.is_file():
        raise ValueError(f"unknown registry job template: {job_id}")
    template = read_json(template_path)
    if template.get("job_template_id") != job_id:
        raise ValueError("registry template identity mismatch")
    resolved = composition(template)
    records: dict[str, Any] = {}
    for key, (directory, _schema, _field) in KINDS.items():
        record_id = template["composition"][key]
        path = REGISTRY / directory / f"{record_id}.json"
        records[key] = _source_record(path, resolved[key])
    result_schema = _result_schema_record(resolved["output_contract_id"])
    claim_class = _claim_class_record(resolved["output_contract_id"])
    prompt = None
    if template.get("task_prompt"):
        prompt_path = _repo_file(template["task_prompt"])
        prompt = {"path": template["task_prompt"],
                  "sha256": file_hash(prompt_path)}
    if len(input_paths) > MAX_INPUTS:
        raise ValueError(f"handoff has more than {MAX_INPUTS} inputs")
    owner = run_path(run_id)
    inputs: list[dict[str, Any]] = []
    total = 0
    for value in input_paths:
        relative = _relative(value)
        path = beneath(owner, owner / Path(*relative.parts))
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"handoff input is not a regular file: {value}")
        size = path.stat().st_size
        if size > MAX_INPUT_BYTES:
            raise ValueError(f"handoff input exceeds {MAX_INPUT_BYTES} bytes: {value}")
        total += size
        if total > MAX_TOTAL_INPUT_BYTES:
            raise ValueError(f"handoff inputs exceed {MAX_TOTAL_INPUT_BYTES} bytes")
        inputs.append({"path": relative.as_posix(), "bytes": size, "sha256": file_hash(path)})
    template_record = _source_record(template_path, template)
    identity = {
        "template_sha256": template_record["sha256"],
        "composition_sha256": "sha256:" + digest({key: value["record"]
                                                   for key, value in records.items()}),
        "prompt_sha256": prompt["sha256"] if prompt else None,
        "output_contract_sha256": records["output_contract_id"]["sha256"],
        "inputs_sha256": "sha256:" + digest(inputs),
    }
    if result_schema is not None:
        identity["result_schema_sha256"] = result_schema["sha256"]
    if claim_class is not None:
        identity["claim_class_sha256"] = claim_class["sha256"]
    fingerprint = "sha256:" + digest({"run_id": run_id, "job_id": job_id,
                                       "scope_id": scope_id, "identity": identity})
    handoff = {
        "schema": SCHEMA,
        "run_id": run_id,
        "job_id": job_id,
        "scope_id": scope_id,
        "created_at": now(),
        "template": template_record,
        "composition": records,
        "prompt": prompt,
        "inputs": inputs,
        "identity": identity,
        "input_fingerprint": fingerprint,
    }
    if result_schema is not None:
        handoff["result_schema"] = result_schema
    if claim_class is not None:
        handoff["claim_class"] = claim_class
    return handoff


def create_handoff(run_id: str, job_id: str, input_paths: list[str] | None = None,
                   scope_id: str = "whole") -> tuple[Path, dict[str, Any]]:
    value = build_handoff(run_id, job_id,
                          default_inputs(run_id) if input_paths is None else input_paths, scope_id)
    handoff_id = value["input_fingerprint"].split(":", 1)[1][:24]
    base = run_path(run_id) / "data" / "jobs" / job_id / scope_id / "handoffs"
    path = base / f"{handoff_id}.json"
    if path.exists():
        existing = read_json(path)
        # Timestamps are descriptive; immutable identity and all resolved content must match.
        comparable = {key: item for key, item in value.items() if key != "created_at"}
        old_comparable = {key: item for key, item in existing.items() if key != "created_at"}
        if old_comparable != comparable:
            raise ValueError("immutable handoff identity collision")
        value = existing
    else:
        atomic_json(path, value)
    atomic_json(base.parent / "latest-handoff.json", {
        "handoff_id": handoff_id,
        "path": path.relative_to(run_path(run_id)).as_posix(),
        "sha256": file_hash(path),
        "input_fingerprint": value["input_fingerprint"],
    })
    return path, value


def read_latest_handoff(run_id: str, job_id: str, scope_id: str = "whole"
                        ) -> tuple[Path, dict[str, Any]]:
    """Read the immutable selected handoff without creating or repairing any state."""
    base = run_path(run_id) / "data" / "jobs" / identifier(job_id) / identifier(scope_id)
    pointer = read_json(base / "latest-handoff.json")
    relative = _relative(pointer["path"])
    path = beneath(run_path(run_id), run_path(run_id) / Path(*relative.parts))
    if not path.is_file() or path.is_symlink() or file_hash(path) != pointer.get("sha256"):
        raise ValueError("selected handoff is missing, linked, or corrupt")
    value = read_json(path)
    if value.get("input_fingerprint") != pointer.get("input_fingerprint"):
        raise ValueError("selected handoff identity mismatch")
    return path, value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--scope", default="whole")
    parser.add_argument("--input", action="append", default=None,
                        help="normalized path beneath the run root; repeat for bounded inputs")
    args = parser.parse_args(argv)
    path, value = create_handoff(args.run_id, args.job, args.input, args.scope)
    print(json.dumps({"status": "OK", "path": str(path),
                      "input_fingerprint": value["input_fingerprint"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
