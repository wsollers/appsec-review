#!/usr/bin/env python3
"""Run-owned ingestion of published OpenSSF Scorecard JSON2 results.

This worker never scans a repository. It fetches only the fixed public results endpoint after the
run grants ``network:api.scorecard.dev``. Target-controlled input is parsed as data, redirects are
rejected, response sizes are bounded, and accepted artifacts retain raw bytes and provenance.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable

from execution_state import (ROOT, Blocked, Lock, atomic_bytes, atomic_json, data_path, digest,
                             event, execute, file_hash, identifier, now, read_json, run_path,
                             tree_hashes)
from job_graph import composition
from phase1 import config_for

JOB_ID = "02-ossf-scorecard"
INPUT_NAME = "ossf-scorecard-projects.json"
API_BASE = "https://api.scorecard.dev/projects"
NETWORK_PERMISSION = "network:api.scorecard.dev"
MAX_INPUT_BYTES = 256 * 1024
MAX_PROJECTS = 100
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
TIMEOUT_SECONDS = 600
REQUEST_TIMEOUT_SECONDS = 20
REPOSITORY_RE = re.compile(
    r"^(?P<host>github\.com|gitlab\.com)/(?P<owner>[A-Za-z0-9_.-]{1,100})/"
    r"(?P<repo>[A-Za-z0-9_.-]{1,100})$"
)
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SAFE_HEADERS = ("content-type", "etag", "last-modified", "cache-control", "age", "date")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB_ID, "whole")


def input_path(run_id: str) -> Path:
    return run_path(run_id) / "inputs" / INPUT_NAME


def template() -> dict[str, Any]:
    value = read_json(ROOT / "registry" / "job-templates" / f"{JOB_ID}.json")
    composition(value)
    return value


def parse_projects(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, dict) or value.get("schema") != "appsec-review/ossf-scorecard-projects/1":
        raise ValueError("input must use appsec-review/ossf-scorecard-projects/1")
    projects = value.get("projects")
    if not isinstance(projects, list) or not projects or len(projects) > MAX_PROJECTS:
        raise ValueError(f"projects must contain 1..{MAX_PROJECTS} entries")
    parsed: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(projects, 1):
        if not isinstance(item, dict) or set(item) - {"repository", "commit"}:
            raise ValueError(f"project {index} has unsupported fields")
        repository = item.get("repository")
        commit = item.get("commit", "")
        if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
            raise ValueError(f"project {index} repository must be host/owner/repo")
        if not isinstance(commit, str) or (commit and not COMMIT_RE.fullmatch(commit)):
            raise ValueError(f"project {index} commit must be a 40-hex SHA")
        key = (repository, commit.lower())
        if key in seen:
            raise ValueError(f"duplicate project request: {repository}")
        seen.add(key)
        parsed.append({"repository": repository, **({"commit": commit.lower()} if commit else {})})
    return parsed


def load_input(path: Path) -> tuple[list[dict[str, str]], int]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("input must be a regular file")
    raw = path.read_bytes()
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    return parse_projects(json.loads(raw.decode("utf-8"))), len(raw)


def validate_payload(payload: Any, requested: dict[str, str]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Scorecard response must be an object")
    repo = payload.get("repo")
    tool = payload.get("scorecard")
    checks = payload.get("checks")
    score = payload.get("score")
    if not isinstance(repo, dict) or repo.get("name") != requested["repository"]:
        raise ValueError("Scorecard response repository does not match request")
    commit = repo.get("commit")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise ValueError("Scorecard response lacks a valid repository commit")
    if requested.get("commit") and commit.lower() != requested["commit"]:
        raise ValueError("Scorecard response commit does not match pinned request")
    if not isinstance(tool, dict) or not isinstance(tool.get("version"), str):
        raise ValueError("Scorecard response lacks tool version provenance")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10:
        raise ValueError("Scorecard aggregate score must be between 0 and 10")
    if not isinstance(checks, list) or not checks:
        raise ValueError("Scorecard response lacks checks")
    names: set[str] = set()
    for check in checks:
        if not isinstance(check, dict) or not isinstance(check.get("name"), str):
            raise ValueError("Scorecard check lacks a name")
        name = check["name"]
        if name in names:
            raise ValueError("Scorecard check names must be unique")
        names.add(name)
        check_score = check.get("score")
        if (isinstance(check_score, bool) or not isinstance(check_score, (int, float)) or
                not -1 <= check_score <= 10):
            raise ValueError(f"Scorecard check {name} has invalid score")
    return payload


def request_url(project: dict[str, str], base_url: str = API_BASE) -> str:
    url = f"{base_url}/{project['repository']}"
    if project.get("commit"):
        url += "?" + urllib.parse.urlencode({"commit": project["commit"]})
    return url


def fetch_projects(projects: list[dict[str, str]], output: Path, *,
                   opener: Callable[..., Any] | None = None, base_url: str = API_BASE) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    if opener is None:
        opener = urllib.request.build_opener(NoRedirect()).open
    records: list[dict[str, Any]] = []
    for index, project in enumerate(projects, 1):
        url = request_url(project, base_url)
        request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                       "User-Agent": "appsec-review-ossf-scorecard/1"})
        try:
            response = opener(request, timeout=REQUEST_TIMEOUT_SECONDS)
            with response:
                status = int(getattr(response, "status", response.getcode()))
                final_url = response.geturl()
                if final_url != url or status != 200:
                    raise ValueError("unexpected redirect or HTTP status")
                length = response.headers.get("Content-Length")
                if length and int(length) > MAX_RESPONSE_BYTES:
                    raise ValueError("Scorecard response exceeds size limit")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ValueError("Scorecard response exceeds size limit")
                payload = validate_payload(json.loads(raw.decode("utf-8")), project)
                raw_name = f"response-{index:03d}.json"
                atomic_bytes(output / raw_name, raw)
                records.append({"repository": project["repository"],
                                "requested_commit": project.get("commit"), "status": "published",
                                "request_url": url, "retrieved_at": now(), "http_status": status,
                                "response_headers": {key: response.headers[key] for key in SAFE_HEADERS
                                                     if response.headers.get(key) is not None},
                                "raw_path": raw_name, "raw_sha256": file_hash(output / raw_name),
                                "result": payload})
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise RuntimeError(f"Scorecard API HTTP {exc.code} for {project['repository']}") from exc
            records.append({"repository": project["repository"],
                            "requested_commit": project.get("commit"), "status": "not-published",
                            "request_url": url, "retrieved_at": now(), "http_status": 404,
                            "coverage_gap": "No published result exists at the requested API path."})
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(f"Scorecard API transport failure for {project['repository']}") from exc
    result = {"schema": "appsec-review/ossf-scorecard-results/1", "source": API_BASE,
              "semantics": "published-results-ingest-not-live-scan", "projects": records,
              "published_count": sum(r["status"] == "published" for r in records),
              "not_published_count": sum(r["status"] == "not-published" for r in records)}
    atomic_json(output / "scorecard-results.json", result)
    lines = ["# OpenSSF Scorecard published results", "",
             "This is published API evidence, not a live repository scan or a verified finding.", ""]
    for record in records:
        if record["status"] == "published":
            lines.append(f"- `{record['repository']}`: score {record['result']['score']} at commit "
                         f"`{record['result']['repo']['commit']}`")
        else:
            lines.append(f"- `{record['repository']}`: no published result (coverage gap)")
    atomic_bytes(output / "summary.md", ("\n".join(lines) + "\n").encode("utf-8"))
    return result


def current_inputs(run_id: str) -> dict[str, Any]:
    config = config_for(run_id)
    source = input_path(run_id)
    job = template()
    common = {"composition": job["composition"], "timeout_seconds": job["timeout_seconds"],
              "endpoint": API_BASE, "network_permission": NETWORK_PERMISSION,
              "tool": {"name": "OpenSSF Scorecard Results API", "contract": "JSON2",
                       "python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION,
                       "executable": str(Path(sys.executable).resolve()),
                       "image": os.environ.get("APPSEC_WORKER_IMAGE", "appsec-review-dagster:local")},
              "code": {"ossf_scorecard.py": file_hash(Path(__file__)),
                       f"registry/job-templates/{JOB_ID}.json": file_hash(
                           ROOT / "registry" / "job-templates" / f"{JOB_ID}.json")}}
    if not source.exists():
        return {**common, "applicable": False, "skip_reason": "not-requested-no-scorecard-projects"}
    projects, size = load_input(source)
    if NETWORK_PERMISSION not in config.get("permissions", []):
        raise Blocked(f"stage the run with explicit {NETWORK_PERMISSION} permission")
    return {**common, "applicable": True,
            "source": {"path": f"inputs/{INPUT_NAME}", "sha256": file_hash(source),
                       "bytes": size, "projects": projects}}


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    if pointer.get("status") not in {"OK", "SKIPPED"}:
        raise Blocked("OpenSSF Scorecard attempt is not accepted")
    attempt = base / "attempts" / identifier(pointer["attempt_id"])
    if tree_hashes(attempt) != pointer.get("hashes"):
        raise Blocked("OpenSSF Scorecard attempt artifacts changed")
    record = read_json(attempt / "inputs.json")
    if current_inputs(run_id) != record:
        raise Blocked("OpenSSF Scorecard inputs, authorization, tooling or implementation are stale")
    status = read_json(attempt / "status.json")
    if status.get("status") != pointer["status"]:
        raise Blocked("OpenSSF Scorecard attempt status mismatch")
    results_path = attempt / "outputs" / "scorecard-results.json"
    results = read_json(results_path)
    if results.get("schema") != "appsec-review/ossf-scorecard-results/1":
        raise Blocked("invalid OpenSSF Scorecard results schema")
    if record["applicable"]:
        if len(results.get("projects", [])) != len(record["source"]["projects"]):
            raise Blocked("OpenSSF Scorecard result count mismatch")
        for requested, result in zip(record["source"]["projects"], results["projects"]):
            if result.get("repository") != requested["repository"]:
                raise Blocked("OpenSSF Scorecard result ordering mismatch")
            if result.get("status") == "published":
                validate_payload(result.get("result"), requested)
                raw_name = result.get("raw_path")
                if not isinstance(raw_name, str) or not re.fullmatch(r"response-[0-9]{3}\.json", raw_name):
                    raise Blocked("OpenSSF Scorecard raw response path is invalid")
                raw = attempt / "outputs" / raw_name
                if file_hash(raw) != result.get("raw_sha256"):
                    raise Blocked("OpenSSF Scorecard raw response hash mismatch")
            elif result.get("status") != "not-published":
                raise Blocked("unsupported OpenSSF Scorecard result status")
    manifest = read_json(attempt / "manifest.json")
    if manifest.get("results_sha256") != file_hash(results_path):
        raise Blocked("OpenSSF Scorecard manifest output hash mismatch")
    return attempt


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)
    with Lock(base / "job.lock"):
        record = current_inputs(run_id)
        fingerprint = digest(record)
        if not force and (base / "accepted.json").exists():
            candidate = read_json(base / "accepted.json")
            if candidate.get("fingerprint") == fingerprint:
                try:
                    validate(run_id, candidate)
                    atomic_json(data_path(run_id, "orchestration", "dagster", dagster_id,
                                          "ossf-scorecard-reuse.json"),
                                {"status": candidate["status"], "reused": True,
                                 "producer": candidate, "time": now()})
                    return candidate
                except (ValueError, Blocked, OSError, KeyError):
                    pass
        if (base / "latest.json").exists():
            previous = read_json(base / "latest.json")
            old = base / "attempts" / identifier(previous["attempt_id"]) / "status.json"
            if old.exists() and read_json(old).get("status") == "RUNNING":
                atomic_json(old, {**read_json(old), "status": "FAILED",
                                  "error": "INTERRUPTED_WORKER", "ended_at": now()})
        attempt_id = uuid.uuid4().hex
        attempt = base / "attempts" / attempt_id
        (attempt / "outputs").mkdir(parents=True)
        status = {"status": "RUNNING", "run_id": run_id, "attempt_id": attempt_id,
                  "dagster_run_id": dagster_id, "started_at": now(), "fingerprint": fingerprint}
        atomic_json(base / "accepted.json", {"status": "PENDING", "attempt_id": attempt_id})
        atomic_json(base / "latest.json", {"attempt_id": attempt_id})
        try:
            atomic_json(attempt / "status.json", status)
            atomic_json(attempt / "inputs.json", record)
            atomic_json(attempt / "pre.json", {"status": "OK", "network_authorized": record["applicable"],
                                                "endpoint": API_BASE})
            if record["applicable"]:
                environment = {key: value for key, value in os.environ.items()
                               if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL",
                                                  "SSL_CERT_FILE", "SSL_CERT_DIR"}}
                environment["PYTHONDONTWRITEBYTECODE"] = "1"
                argv = [sys.executable, "-B", str(Path(__file__)), "worker", str(input_path(run_id)),
                        str(attempt / "outputs")]
                result = execute(argv, ROOT, attempt / "logs", record["timeout_seconds"], env=environment)
                atomic_json(attempt / "command.json", result)
                if result.get("error") or result.get("exit_code") != 0:
                    raise Blocked("OpenSSF Scorecard fetch failed; inspect separate attempt logs")
                if file_hash(input_path(run_id)) != record["source"]["sha256"]:
                    raise Blocked("OpenSSF Scorecard input changed during fetch")
                final_status, reason = "OK", None
            else:
                (attempt / "logs").mkdir()
                atomic_bytes(attempt / "logs" / "stdout.log", b"")
                atomic_bytes(attempt / "logs" / "stderr.log", b"")
                event(attempt / "logs" / "events.jsonl", "SKIP", reason=record["skip_reason"])
                atomic_json(attempt / "command.json", {"argv": [], "exit_code": None,
                                                        "network_used": False})
                atomic_json(attempt / "outputs" / "scorecard-results.json",
                            {"schema": "appsec-review/ossf-scorecard-results/1", "source": API_BASE,
                             "semantics": "published-results-ingest-not-live-scan", "projects": [],
                             "published_count": 0, "not_published_count": 0})
                atomic_bytes(attempt / "outputs" / "summary.md",
                             b"# OpenSSF Scorecard published results\n\nNot requested; no project input was staged.\n")
                final_status, reason = "SKIPPED", record["skip_reason"]
            if record["code"] != current_inputs(run_id)["code"]:
                raise Blocked("OpenSSF Scorecard implementation changed during work")
            results_path = attempt / "outputs" / "scorecard-results.json"
            manifest = {"schema": "appsec-review/ossf-scorecard-manifest/1", "run_id": run_id,
                        "attempt_id": attempt_id, "source_endpoint": API_BASE,
                        "semantics": "published-results-ingest-not-live-scan",
                        "network_authorized": record["applicable"], "network_used": record["applicable"],
                        "input_sha256": record.get("source", {}).get("sha256"),
                        "results_sha256": file_hash(results_path), "tool": record["tool"],
                        "target_execution": False}
            atomic_json(attempt / "manifest.json", manifest)
            atomic_json(attempt / "post.json", {"status": "OK", "schema_validation": "PASS",
                                                 "freshness": "PASS", "hash_validation": "PASS"})
            status.update(status=final_status, ended_at=now())
            if reason:
                status["reason"] = reason
            atomic_json(attempt / "status.json", status)
            pointer = {"status": final_status, "run_id": run_id, "job": JOB_ID,
                       "attempt_id": attempt_id, "fingerprint": fingerprint,
                       "hashes": tree_hashes(attempt)}
            if reason:
                pointer["reason"] = reason
            atomic_json(base / "accepted.json", pointer)
            validate(run_id, pointer)
            return pointer
        except BaseException as exc:
            status.update(status="FAILED", error=f"{type(exc).__name__}: {exc}", ended_at=now())
            atomic_json(attempt / "status.json", status)
            atomic_json(base / "accepted.json", {"status": "FAILED", "attempt_id": attempt_id})
            raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    worker = sub.add_parser("worker")
    worker.add_argument("input", type=Path)
    worker.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    projects, _ = load_input(args.input)
    result = fetch_projects(projects, args.output)
    print(json.dumps({"status": "OK", "published": result["published_count"],
                      "not_published": result["not_published_count"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
