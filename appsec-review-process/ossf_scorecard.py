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
from typing import Any, Callable

from create_job_handoff import create_handoff, default_inputs, read_latest_handoff
from deterministic_child import CONTRACT as CHILD_CONTRACT, ChildExecutionSpec, execute_child
from execution_state import (ROOT, Blocked, atomic_bytes, atomic_json, data_path, digest,
                             event, file_hash, identifier, now, read_json, run_path,
                             tree_hashes)
from job_graph import composition
from phase1 import config_for
from publish_job_output import (common_pointer, coordinate_worker_lifecycle,
                                record_terminal_current, validate_published)
from validate_job_output import validate_contract_result

JOB_ID = "02-ossf-scorecard"
INPUT_NAME = "ossf-scorecard-projects.json"
API_BASE = "https://api.scorecard.dev/projects"
NETWORK_PERMISSION = "network:api.scorecard.dev"
MAX_INPUT_BYTES = 256 * 1024
MAX_PROJECTS = 100
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
TIMEOUT_SECONDS = 600
REQUEST_TIMEOUT_SECONDS = 20
STDOUT_LIMIT_BYTES = 1024 * 1024
STDERR_LIMIT_BYTES = 1024 * 1024
CONSUMER_JOB_ID = "02-evidence-assembly"
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


def current_inputs(run_id: str, persist_handoff: bool = True) -> dict[str, Any]:
    config = config_for(run_id)
    source = input_path(run_id)
    job = template()
    handoff_inputs = default_inputs(run_id)
    if source.exists() and f"inputs/{INPUT_NAME}" not in handoff_inputs:
        handoff_inputs.append(f"inputs/{INPUT_NAME}")
    handoff_path, handoff = (create_handoff(run_id, JOB_ID, handoff_inputs)
                             if persist_handoff else read_latest_handoff(run_id, JOB_ID))
    common = {"composition": job["composition"], "timeout_seconds": job["timeout_seconds"],
              "endpoint": API_BASE, "network_permission": NETWORK_PERMISSION,
              "handoff": {"path": handoff_path.relative_to(run_path(run_id)).as_posix(),
                          "sha256": file_hash(handoff_path),
                          "input_fingerprint": handoff["input_fingerprint"]},
              "tool": {"name": "OpenSSF Scorecard Results API", "contract": "JSON2",
                       "python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION,
                       "executable": str(Path(sys.executable).resolve()),
                       "image": os.environ.get("APPSEC_WORKER_IMAGE", "appsec-review-dagster:local")},
              "code": {"ossf_scorecard.py": file_hash(Path(__file__)),
                       "deterministic_child.py": file_hash(ROOT / "deterministic_child.py"),
                       "execution_state.py": file_hash(ROOT / "execution_state.py"),
                       "process_gate.py": file_hash(ROOT / "process_gate.py"),
                       "create_job_handoff.py": file_hash(ROOT / "create_job_handoff.py"),
                       "publish_job_output.py": file_hash(ROOT / "publish_job_output.py"),
                       "validate_job_output.py": file_hash(ROOT / "validate_job_output.py"),
                       f"registry/job-templates/{JOB_ID}.json": file_hash(
                           ROOT / "registry" / "job-templates" / f"{JOB_ID}.json")},
              "child_execution": {"contract": CHILD_CONTRACT, "argv_only": True,
                                  "shell_allowed": False,
                                  "stdout_limit_bytes": STDOUT_LIMIT_BYTES,
                                  "stderr_limit_bytes": STDERR_LIMIT_BYTES,
                                  "child_tree_cleanup": "always"}}
    if not source.exists():
        return {**common, "applicable": False, "skip_reason": "not-requested-no-scorecard-projects"}
    projects, size = load_input(source)
    if NETWORK_PERMISSION not in config.get("permissions", []):
        raise Blocked(f"stage the run with explicit {NETWORK_PERMISSION} permission")
    return {**common, "applicable": True,
            "source": {"path": f"inputs/{INPUT_NAME}", "sha256": file_hash(source),
                       "bytes": size, "projects": projects}}


def _validate_attempt_payload(attempt: Path, record: dict[str, Any]) -> None:
    del record  # inputs.json is the immutable source used by the contract validator.
    contract = read_json(ROOT / "registry" / "output-contracts" /
                         "ossf-scorecard-results.json")
    errors = validate_contract_result(
        attempt, contract, run_id=read_json(attempt / "status.json").get("run_id", ""))
    if errors:
        raise Blocked("invalid OpenSSF Scorecard result: " + "; ".join(errors))


def _validate_legacy(run_id: str, pointer: dict[str, Any]) -> Path:
    base = root(run_id)
    if pointer.get("status") not in {"OK", "SKIPPED"}:
        raise Blocked("OpenSSF Scorecard attempt is not accepted")
    attempt = base / "attempts" / identifier(pointer["attempt_id"])
    if tree_hashes(attempt) != pointer.get("hashes"):
        raise Blocked("OpenSSF Scorecard attempt artifacts changed")
    stored = read_json(attempt / "inputs.json")
    status = read_json(attempt / "status.json")
    if status.get("status") != pointer["status"]:
        raise Blocked("OpenSSF Scorecard attempt status mismatch")
    _validate_attempt_payload(attempt, stored)
    return attempt


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    if not common_pointer(pointer):
        # Historical pointers remain integrity-readable, but run() never reuses them as current.
        return _validate_legacy(run_id, pointer)
    record = current_inputs(run_id, persist_handoff=False)
    fingerprint = "sha256:" + digest(record)
    attempt, _envelope = validate_published(
        base, pointer, fingerprint, expected_run_id=run_id, expected_job_id=JOB_ID,
        consumer_job_id=CONSUMER_JOB_ID)
    if read_json(attempt / "inputs.json") != record:
        raise Blocked("OpenSSF Scorecard immutable attempt inputs changed")
    _validate_attempt_payload(attempt, record)
    return attempt


def _failure_record(run_id: str, source: Path, exc: BaseException) -> dict[str, Any]:
    descriptor: dict[str, Any] = {"run_id": run_id, "job": JOB_ID,
                                  "preflight_error": f"{type(exc).__name__}: {exc}",
                                  "code": file_hash(Path(__file__))}
    if source.is_file() and not source.is_symlink():
        descriptor["source"] = {"path": f"inputs/{INPUT_NAME}",
                                "sha256": file_hash(source), "bytes": source.stat().st_size}
    return descriptor


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)
    resume = (f"python -B appsec-review-process/launch_job.py --run-id {run_id} "
              "--job ossf_scorecard --wait")

    def post_validate(attempt: Path, _envelope: dict[str, Any],
                      record: dict[str, Any]) -> None:
        if read_json(attempt / "inputs.json") != record:
            raise Blocked("OpenSSF Scorecard immutable attempt inputs changed")
        _validate_attempt_payload(attempt, record)

    def on_reuse(admitted: dict[str, Any]) -> None:
        candidate, envelope = admitted["pointer"], admitted["envelope"]
        atomic_json(data_path(run_id, "orchestration", "dagster", dagster_id,
                              "ossf-scorecard-reuse.json"),
                    {"status": envelope["execution_status"], "reused": True,
                     "publication_recovered": admitted["recovered_publication"],
                     "producer": candidate, "time": now()})

    def execute_attempt(allocation: dict[str, Any], record: dict[str, Any],
                        fingerprint: str) -> dict[str, Any]:
        attempt_id = allocation["attempt_id"]
        attempt = allocation["attempt"]
        (attempt / "outputs").mkdir(parents=True)
        started = allocation["started_at"]
        status = {"status": "RUNNING", "run_id": run_id, "attempt_id": attempt_id,
                  "dagster_run_id": dagster_id, "started_at": started, "fingerprint": fingerprint}
        atomic_json(attempt / "status.json", status)
        atomic_json(attempt / "pre.json", {"status": "OK",
                                            "network_authorized": record["applicable"],
                                            "endpoint": API_BASE})
        if record["applicable"]:
            environment = {key: value for key, value in os.environ.items()
                           if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL",
                                              "SSL_CERT_FILE", "SSL_CERT_DIR"}}
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            python_executable = str(Path(sys.executable).resolve())
            argv = [python_executable, "-B", str(Path(__file__)), "worker",
                    str(input_path(run_id)), str(attempt / "outputs")]
            result = execute_child(ChildExecutionSpec(
                argv=tuple(argv), argv_prefix=tuple(argv[:4]), executable=Path(python_executable),
                cwd=ROOT.resolve(), owner_root=attempt.resolve(),
                log_dir=(attempt / "logs").resolve(),
                timeout_seconds=record["timeout_seconds"],
                stdout_limit_bytes=record["child_execution"]["stdout_limit_bytes"],
                stderr_limit_bytes=record["child_execution"]["stderr_limit_bytes"],
                env=environment))
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
            atomic_bytes(
                attempt / "outputs" / "summary.md",
                b"# OpenSSF Scorecard published results\n\n"
                b"Not requested; no project input was staged.\n")
            final_status, reason = "SKIPPED", record["skip_reason"]
        if record["code"] != current_inputs(run_id)["code"]:
            raise Blocked("OpenSSF Scorecard implementation changed during work")
        results_path = attempt / "outputs" / "scorecard-results.json"
        manifest = {"schema": "appsec-review/ossf-scorecard-manifest/1", "run_id": run_id,
                    "attempt_id": attempt_id, "source_endpoint": API_BASE,
                    "semantics": "published-results-ingest-not-live-scan",
                    "network_authorized": record["applicable"],
                    "network_used": record["applicable"],
                    "input_sha256": record.get("source", {}).get("sha256"),
                    "results_sha256": file_hash(results_path), "tool": record["tool"],
                    "target_execution": False}
        atomic_json(attempt / "manifest.json", manifest)
        atomic_json(attempt / "post.json", {"status": "OK", "schema_validation": "PASS",
                                             "freshness": "PASS", "hash_validation": "PASS"})
        declared = ["manifest.json", "outputs/scorecard-results.json",
                    "outputs/summary.md", "status.json"]
        declared += sorted(path.relative_to(attempt).as_posix()
                           for path in (attempt / "outputs").glob("response-*.json"))
        gaps = (["One or more requested repositories have no published Scorecard result."]
                if record["applicable"] and
                read_json(results_path).get("not_published_count", 0) else [])
        return record_terminal_current(
            base, attempt, run_id=run_id, job_id=JOB_ID,
            dagster_run_id=dagster_id, worker_kind="deterministic_python",
            output_contract="ossf-scorecard-results", input_fingerprint=fingerprint,
            started_at=started, execution_status=final_status,
            summary=("Published Scorecard results ingested." if final_status == "OK" else
                     "Scorecard ingestion was not requested."),
            status_record=status, artifact_paths=declared, gaps=gaps,
            skip_reason=reason, consumer_job_id=CONSUMER_JOB_ID,
            pre_envelope_validate=lambda path, _status: _validate_attempt_payload(path, record))

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=JOB_ID, dagster_run_id=dagster_id,
        worker_kind="deterministic_python", output_contract="ossf-scorecard-results",
        resume_command=resume, derive_inputs=lambda: current_inputs(run_id),
        fingerprint_inputs=lambda value: "sha256:" + digest(value),
        execute_attempt=execute_attempt,
        preflight_failure_inputs=lambda exc: _failure_record(run_id, input_path(run_id), exc),
        force=force, consumer_job_id=CONSUMER_JOB_ID, post_validate=post_validate,
        on_reuse=on_reuse,
        blocked_summary="OpenSSF Scorecard preflight did not complete.",
        failed_summary="OpenSSF Scorecard ingestion did not publish.")
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
