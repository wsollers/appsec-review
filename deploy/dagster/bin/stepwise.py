"""Walk wave1_review one Dagster job at a time against one application run, and build the answer key.

  init --target <container path>      launch the first job; it allocates the application run
  next [--app-run ID] [--relaunch]    launch the next job that is not accepted, wait, then check it
  check --job JOB [--app-run ID]      Dagster status, job status and gaps, permission/filesystem audit
  accept --job JOB --tag TAG          write the normalized output to test/acceptance/<TAG>/<job>.json
  compare --app-run ID --tag TAG      diff a full wave1_review run against the accepted outputs
  seed --tag TAG --after JOB          restore the known-good run tree taken when JOB was accepted
  verify-job --tag TAG --job JOB      seed JOB's predecessor, run JOB, check it, diff its accepted output
  system --tag TAG [--app-run ID]     run the whole wave1_review in Dagster (or take a finished run), then check
                                      every job, the final artifacts, the baselines and the answer key
  parity --tag TAG --job JOB          from JOB's predecessor seed, run JOB through Dagster and the local
                                      launcher, one after the other, and diff the two outputs

Every job runs as its own single-job Dagster job in the packaged code location (same uid/gid,
mounts and Docker socket as wave1_review). Upstream handoffs are named in the
``appsec/upstream_handoffs`` run tag and verified by the job's begin op against the run's accepted
pointers. Normalization, audit and diff logic lives in ``appsec_review.acceptance``.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib
from urllib.request import Request, urlopen
from uuid import uuid4

from host import read_environment
import review_run

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from appsec_review.acceptance.answer_key import collect_findings, evaluate, load_answer_key  # noqa: E402
from appsec_review.acceptance.audit import audit_job_writes, summarize  # noqa: E402
from appsec_review.acceptance.content import content_differences  # noqa: E402
from appsec_review.acceptance.diff import CLASSES, classify_environment, diff_job_outputs, failing  # noqa: E402
from appsec_review.acceptance.integrity import attempt_integrity  # noqa: E402
from appsec_review.acceptance.normalize import Masks, gap_summary, locate_attempt, normalize_job_output  # noqa: E402
from appsec_review.acceptance.seed import BlobStore, SeedError, resolve_chain, restore, scan, snapshot  # noqa: E402
from appsec_review.acceptance.state import StateError, StepwiseState, valid_corpus_tag  # noqa: E402
from appsec_review.acceptance.system import final_artifact_problems, run_problems  # noqa: E402

DEPLOYMENT = ROOT / "deploy" / "dagster"
COMPOSE = ["docker", "compose", "--env-file", str(DEPLOYMENT / ".env"), "-f", str(DEPLOYMENT / "compose.yaml")]
CONTAINER_ROOT = "/opt/app"
STATE_ROOT = ROOT / "runs" / "metadata" / "stepwise"
ACCEPTANCE_ROOT = ROOT / "test" / "acceptance"
UPSTREAM_TAG = "appsec/upstream_handoffs"
# Seed bytes stay out of git under data/ (ignored); manifests are committed beside the answer key.
SEED_STORE = ROOT / "data" / "acceptance-seeds"
SEED_EXCLUDE = ("runs/metadata/stepwise", "runs/metadata/dagster-error-state",
                "runs/metadata/dagster-recovery", "data/acceptance-seeds")
RUN_QUERY = """query StepwiseRun($runId: ID!) { runOrError(runId: $runId) { __typename
  ... on Run { runId status pipelineName startTime endTime tags { key value } stepStats { stepKey status } }
  ... on RunNotFoundError { message } ... on PythonError { message } } }"""
LOG_QUERY = """query StepwiseLogs($runId: ID!, $after: String) {
  logsForRun(runId: $runId, afterCursor: $after, limit: 1000) { __typename
    ... on EventConnection { cursor hasMore events { __typename
      ... on ExecutionStepFailureEvent { stepKey error { message causes { message } } }
      ... on RunFailureEvent { message } } }
    ... on PythonError { message } } }"""


# -- live deployment -----------------------------------------------------------------------------
def graphql(url: str, query: str, variables: dict) -> dict:
    request = Request(url, data=json.dumps({"query": query, "variables": variables}).encode(),
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=60) as response:
        payload = json.load(response)
    if payload.get("errors"):
        raise RuntimeError(str(payload["errors"]))
    return payload["data"]


def get_run(url: str, run_id: str) -> dict:
    run = graphql(url, RUN_QUERY, {"runId": run_id})["runOrError"]
    if run.get("__typename") != "Run":
        raise RuntimeError(run.get("message") or f"Dagster run query failed: {run}")
    run["tag_map"] = {item["key"]: item["value"] for item in run.get("tags", [])}
    return run


def failure_messages(url: str, run_id: str) -> list[str]:
    """Failed steps with their root-cause message, as the error-state file reports them."""
    lines, after = [], None
    while True:
        page = graphql(url, LOG_QUERY, {"runId": run_id, "after": after})["logsForRun"]
        if page.get("__typename") != "EventConnection":
            return [f"logs unavailable: {page.get('message')}"]
        for event in page["events"]:
            if event["__typename"] == "ExecutionStepFailureEvent":
                causes = [item["message"] for item in (event.get("error") or {}).get("causes") or []]
                message = causes[-1] if causes else (event.get("error") or {}).get("message", "")
                lines.append(f"step={event.get('stepKey')} message={' '.join(message.split())[:700]}")
            elif event["__typename"] == "RunFailureEvent":
                lines.append(f"run message={' '.join(str(event.get('message')).split())[:700]}")
        if not page.get("hasMore"):
            return lines
        after = page["cursor"]


def compose(*arguments: str, capture: bool = True) -> str:
    result = subprocess.run([*COMPOSE, *arguments], cwd=ROOT, text=True, capture_output=capture, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"docker compose {' '.join(arguments[:3])} failed: "
                           f"{(result.stderr or '').strip()[-800:]}")
    return result.stdout or ""


def packaged_topology() -> dict:
    try:
        output = compose("exec", "-T", "code-location", "python", "-m", "appsec_review.orchestration.topology")
    except RuntimeError as exc:
        raise RuntimeError("the code-location image cannot describe wave1_review; rebuild it from a checkout "
                           f"that contains appsec_review.orchestration.topology ({exc})") from exc
    return json.loads(output)


def launch(job_name: str, dagster_run_id: str, tags: dict[str, str]) -> None:
    document = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    review_run.verify_build_profile_images(document)
    compose("exec", "-T", "webserver", "dagster", "job", "launch", "-w", "/opt/dagster/home/workspace.yaml",
            "-l", "appsec_review", "-j", job_name, "--run-id", dagster_run_id, "--tags", json.dumps(tags),
            capture=False)
    print(f"launched job={job_name} dagster_run_id={dagster_run_id}", flush=True)


def wait(url: str, dagster_run_id: str, interval: int) -> dict:
    while True:
        run = get_run(url, dagster_run_id)
        active = [item["stepKey"] for item in run.get("stepStats", [])
                  if item.get("status") in {"IN_PROGRESS", "STARTING"}]
        print(f"dagster_run_id={dagster_run_id} status={run['status']} "
              f"active_steps={','.join(active[:5]) or '-'}", flush=True)
        if run["status"] in review_run.TERMINAL:
            return run
        time.sleep(interval)


# -- local state ------------------------------------------------------------------------------
def host_path(container_path: str) -> Path:
    if container_path == CONTAINER_ROOT or container_path.startswith(CONTAINER_ROOT + "/"):
        return ROOT / container_path[len(CONTAINER_ROOT):].lstrip("/")
    raise RuntimeError(f"{container_path} is not under the code location's {CONTAINER_ROOT}")


def masks_for(app_run_id: str, target: str) -> Masks:
    return Masks.for_run(app_run_id, runs_roots=[f"{CONTAINER_ROOT}/runs", str(ROOT / "runs")],
                         repository_roots=[CONTAINER_ROOT, str(ROOT)],
                         target_roots=[target, str(host_path(target))])


def state_path(app_run: str | None) -> Path:
    if app_run:
        return StepwiseState.path_for(STATE_ROOT, app_run)
    candidates = sorted(STATE_ROOT.glob("*/state.json")) if STATE_ROOT.is_dir() else []
    if len(candidates) != 1:
        raise StateError("pass --app-run; "
                         f"{len(candidates)} stepwise walks exist under {STATE_ROOT.relative_to(ROOT)}")
    return candidates[0]


def relative(path: str | Path) -> str:
    path = Path(path)
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


def git(*arguments: str, cwd: Path) -> str:
    result = subprocess.run(["git", *arguments], cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(arguments)} failed in {cwd}: {result.stderr.strip()}")
    return result.stdout.strip()


# -- commands ---------------------------------------------------------------------------------
def check(args, state: StepwiseState, path: Path, job_key: str) -> bool:
    item = state.job(job_key)
    if not item["dagster_run_ids"]:
        raise StateError(f"{item['job_id']} has not been launched")
    dagster_run_id = item["dagster_run_ids"][-1]
    run = get_run(args.url, dagster_run_id)
    run_root = ROOT / "runs" / state.app_run_id
    print(f"== check {item['job_id']} dagster_run_id={dagster_run_id} status={run['status']}")
    failures = failure_messages(args.url, dagster_run_id) if run["status"] in {"FAILURE", "CANCELED"} else []
    for line in failures:
        print(f"   dagster failure {line}")
    attempt = locate_attempt(run_root, item["job_id"], dagster_run_id)
    document = normalize_job_output(run_root, item["job_id"], masks_for(state.app_run_id, state.target),
                                    attempt_root=attempt)
    gaps = gap_summary(document)
    partial = sorted(unit for unit, receipt in document["units"].items()
                     if {str(receipt.get(key)) for key in ("status", "disposition", "terminal_status")}
                     & {"PARTIAL", "FAILED"})
    print(f"   job status={document['status']} attempt={attempt.name if attempt else '-'} "
          f"unique_gaps={len(gaps)} gap_occurrences={sum(count for _, count in gaps)} "
          f"findings={sum(item['count'] for item in document['findings'])}")
    for gap, count in gaps[:args.show]:
        print(f"   gap x{count}: {gap[:240]}")
    if len(gaps) > args.show:
        print(f"   ... {len(gaps) - args.show} more unique gaps in the check report")
    for unit in partial:
        print(f"   partial/failed unit: {unit}")
    if document["failed_units"] or document["skipped_units"]:
        print(f"   failed_units={document['failed_units']} skipped_units={document['skipped_units']}")
    environment = read_environment(DEPLOYMENT / ".env")
    since = float(run["startTime"]) - 2 if run.get("startTime") else None
    findings = audit_job_writes(
        run_root, item["job_id"], attempt, expected_uid=int(environment.get("APPSEC_UID", "0")),
        expected_gid=int(environment.get("APPSEC_GID", "0")), since=since,
        extra_roots=[ROOT / "runs" / "metadata", ROOT / "data"], exclude=[STATE_ROOT, SEED_STORE],
        dagster_status=run["status"])
    print(f"   audit findings={len(findings)} {json.dumps(summarize(findings))}")
    shown: Counter = Counter()
    for finding in findings:
        if shown[finding.kind] < args.show:
            shown[finding.kind] += 1
            print(f"   {finding.kind}: {relative(finding.path)} {finding.detail}")
    passed = run["status"] == "SUCCESS" and not findings
    report = {"job_id": item["job_id"], "dagster_run_id": dagster_run_id, "dagster_status": run["status"],
              "dagster_failures": failures, "job_status": document["status"],
              "attempt": attempt.name if attempt else None, "gaps": [{"gap": gap, "count": count} for gap, count in gaps],
              "partial_units": partial, "failed_units": document["failed_units"],
              "skipped_units": document["skipped_units"], "audit": [finding.as_dict() for finding in findings],
              "passed": passed}
    report_path = path.parent / "checks" / f"{item['job_id']}-{dagster_run_id}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    state.record_check(item["job_id"], passed=passed, summary={
        "dagster_run_id": dagster_run_id, "dagster_status": run["status"], "job_status": document["status"],
        "audit": summarize(findings), "report": str(report_path.relative_to(ROOT))})
    state.save(path)
    print(f"   check {'PASSED' if passed else 'FAILED'}; report {report_path.relative_to(ROOT)}")
    return passed


def command_init(args) -> int:
    configured = compose("exec", "-T", "code-location", "printenv", "APPSEC_REVIEW_TARGET").strip()
    if args.target != configured:
        raise RuntimeError(f"the code location reviews {configured}; set APPSEC_REVIEW_TARGET={args.target} "
                           "in deploy/dagster/.env and recreate the stack to review another target")
    topology = packaged_topology()
    first = topology["jobs"][0]
    dagster_run_id = str(uuid4())
    launch(first["name"], dagster_run_id, {})
    run = wait(args.url, dagster_run_id, args.interval_seconds)
    app_run_id = run["tag_map"].get("appsec/application_run_id")
    if not app_run_id:
        for line in failure_messages(args.url, dagster_run_id):
            print(f"   dagster failure {line}")
        raise RuntimeError(f"{first['name']} did not allocate an application run")
    state = StepwiseState.create(app_run_id, target=args.target, topology=topology)
    state.record_launch(first["job_id"], dagster_run_id)
    path = StepwiseState.path_for(STATE_ROOT, app_run_id)
    state.save(path)
    print(f"application_run_id={app_run_id} state={path.relative_to(ROOT)} jobs={len(state.jobs)}")
    return 0 if check(args, state, path, first["job_id"]) else 1


def command_next(args) -> int:
    path = state_path(args.app_run)
    return launch_next(args, StepwiseState.load(path), path)


def launch_next(args, state: StepwiseState, path: Path) -> int:
    item = state.next_job()
    if item is None:
        print(f"every {state.graph} job is accepted for {state.app_run_id}; run a full wave1 and compare")
        return 0
    topology = packaged_topology()
    if topology["jobs"] != state.topology:
        raise StateError("the packaged wave1_review topology changed since init; start a new walk")
    run_root = ROOT / "runs" / state.app_run_id
    upstream = {}
    accepted = state.accepted_handoffs()
    for job_id in state.upstream_of(item["job_id"]):
        pointer = run_root / "data" / "jobs" / job_id / "latest.json"
        if not pointer.is_file():
            raise StateError(f"upstream {job_id} has no accepted handoff in {state.app_run_id}")
        digest = json.loads(pointer.read_text(encoding="utf-8"))["handoff_sha256"]
        if accepted.get(job_id) not in {None, digest}:
            raise StateError(f"upstream {job_id} changed after it was accepted")
        upstream[job_id] = digest
    dagster_run_id = str(uuid4())
    state.record_launch(item["job_id"], dagster_run_id, relaunch=getattr(args, "relaunch", False))
    state.save(path)
    launch(item["name"], dagster_run_id, {"appsec/application_run_id": state.app_run_id,
                                          UPSTREAM_TAG: json.dumps(upstream, sort_keys=True)})
    wait(args.url, dagster_run_id, args.interval_seconds)
    return 0 if check(args, state, path, item["job_id"]) else 1


def command_check(args) -> int:
    path = state_path(args.app_run)
    return 0 if check(args, StepwiseState.load(path), path, args.job) else 1


def command_accept(args) -> int:
    tag = valid_corpus_tag(args.tag)
    path = state_path(args.app_run)
    state = StepwiseState.load(path)
    item = state.job(args.job)
    if not check(args, state, path, item["job_id"]):
        raise StateError(f"{item['job_id']} fails its check; it cannot be accepted")
    state.validate_accept(item["job_id"], corpus_tag=tag)
    target = host_path(state.target)
    target_commit = git("rev-parse", "HEAD", cwd=target)
    tag_commit = git("rev-parse", "--verify", f"{tag}^{{commit}}", cwd=target)
    if tag_commit != target_commit:
        raise StateError(f"target {target} is at {target_commit}, but {tag} is {tag_commit}")
    run_root = ROOT / "runs" / state.app_run_id
    pointer = run_root / "data" / "jobs" / item["job_id"] / "latest.json"
    handoff_sha256 = json.loads(pointer.read_text(encoding="utf-8"))["handoff_sha256"]
    attempt = locate_attempt(run_root, item["job_id"], item["dagster_run_ids"][-1])
    document = normalize_job_output(run_root, item["job_id"], masks_for(state.app_run_id, state.target),
                                    attempt_root=attempt)
    destination = ACCEPTANCE_ROOT / tag
    destination.mkdir(parents=True, exist_ok=True)
    (destination / f"{item['job_id']}.json").write_text(
        json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    provenance = {
        "schema": "appsec-review/acceptance-provenance/1", "job_id": item["job_id"], "corpus_tag": tag,
        "target": state.target, "target_commit": target_commit,
        "repository_commit": git("rev-parse", "HEAD", cwd=ROOT),
        "repository_dirty": bool(git("status", "--porcelain", "--untracked-files=no", cwd=ROOT)),
        "application_run_id": state.app_run_id, "dagster_run_id": item["dagster_run_ids"][-1],
        "attempt": attempt.name if attempt else None, "handoff_sha256": handoff_sha256,
        "accepted_at": datetime.now(timezone.utc).isoformat(),
    }
    (destination / f"{item['job_id']}.provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    ids = [job["job_id"] for job in state.jobs]
    position = ids.index(item["job_id"])
    environment = read_environment(DEPLOYMENT / ".env")
    seed = snapshot(
        ROOT, BlobStore(SEED_STORE), destination / "seeds", tag=tag, job_id=item["job_id"],
        app_run_id=state.app_run_id, base_job=ids[position - 1] if position else None,
        expected_uid=int(environment.get("APPSEC_UID", "0")), expected_gid=int(environment.get("APPSEC_GID", "0")),
        exclude=SEED_EXCLUDE, extra={"target": state.target, "target_commit": target_commit,
                                     "repository_commit": provenance["repository_commit"],
                                     "topology": state.topology})
    print(f"seed after-{item['job_id']}: {seed['totals']['files']} files, {seed['totals']['bytes']} bytes "
          f"({seed['totals']['added_blob_bytes']} new blob bytes), {len(seed['entries'])} changed entries")
    state.record_accept(item["job_id"], corpus_tag=tag, handoff_sha256=handoff_sha256)
    state.save(path)
    print(f"accepted {item['job_id']} -> {(destination / (item['job_id'] + '.json')).relative_to(ROOT)}")
    return 0


def command_compare(args) -> int:
    tag = valid_corpus_tag(args.tag)
    key_root = ACCEPTANCE_ROOT / tag
    expected_files = sorted(path for path in key_root.glob("job_*.json") if not path.name.endswith(".provenance.json"))
    if not expected_files:
        raise StateError(f"no accepted outputs under {key_root.relative_to(ROOT)}")
    run_root = ROOT / "runs" / args.app_run
    provenance = json.loads(expected_files[0].with_suffix(".provenance.json").read_text(encoding="utf-8"))
    masks = masks_for(args.app_run, provenance["target"])
    differences = []
    accepted_jobs = set()
    for path in expected_files:
        expected = json.loads(path.read_text(encoding="utf-8"))
        accepted_jobs.add(expected["job_id"])
        actual = normalize_job_output(run_root, expected["job_id"], masks)
        differences += diff_job_outputs(expected, None if actual["status"] == "MISSING" else actual,
                                        expected["job_id"])
    jobs_root = run_root / "data" / "jobs"
    for job_root in sorted(jobs_root.iterdir()) if jobs_root.is_dir() else []:
        if job_root.name not in accepted_jobs:
            differences += diff_job_outputs(None, normalize_job_output(run_root, job_root.name, masks), job_root.name)
    counts = Counter(item.kind for item in differences)
    print(f"compare app_run={args.app_run} tag={tag} jobs={len(accepted_jobs)} "
          + " ".join(f"{kind}={counts.get(kind, 0)}" for kind in CLASSES))
    for difference in failing(differences)[:args.show * 5]:
        print(f"   {difference.kind} {difference.job_id} {difference.path}: "
              f"{difference.expected[:160]} -> {difference.actual[:160]}")
    report = run_root.parent / "metadata" / "stepwise" / "compare" / f"{args.app_run}-{tag}.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps([item.as_dict() for item in differences], indent=1) + "\n", encoding="utf-8")
    print(f"   report {report.relative_to(ROOT)}")
    return 1 if failing(differences) else 0


def command_system(args) -> int:
    """System acceptance: one complete wave1_review run, end to end, against the accepted corpus."""

    tag = valid_corpus_tag(args.tag)
    key_root = ACCEPTANCE_ROOT / tag
    accepted = sorted(path for path in key_root.glob("job_*.json") if not path.name.endswith(".provenance.json"))
    if not accepted:
        raise StateError(f"no accepted outputs under {key_root.relative_to(ROOT)}")
    provenance = json.loads(accepted[0].with_suffix(".provenance.json").read_text(encoding="utf-8"))
    topology = packaged_topology()
    job_ids = [item["job_id"] for item in topology["jobs"]]
    app_run_id = args.app_run
    if app_run_id is None:
        configured = compose("exec", "-T", "code-location", "printenv", "APPSEC_REVIEW_TARGET").strip()
        if configured != provenance["target"]:
            raise RuntimeError(f"the code location reviews {configured}, but {tag} was accepted on "
                               f"{provenance['target']}")
        dagster_run_id = str(uuid4())
        review_run.submit(dagster_run_id)
        run = wait(args.url, dagster_run_id, args.interval_seconds)
        app_run_id = run["tag_map"].get("appsec/application_run_id")
        if run["status"] != "SUCCESS" or not app_run_id:
            for line in failure_messages(args.url, dagster_run_id):
                print(f"   dagster failure {line}")
            print(f"system FAILED: the Dagster run ended {run['status']}"
                  f"{'' if app_run_id else ' without an application run'}")
            return 1
    run_root = ROOT / "runs" / app_run_id
    if not run_root.is_dir():
        raise StateError(f"no run tree at runs/{app_run_id}")

    problems = run_problems(run_root, app_run_id, job_ids, host_path(provenance["target"]))
    problems += final_artifact_problems(run_root, ROOT)
    for item in failing(problems)[:args.show * 5]:
        print(f"   {item.kind} {item.job_id} {item.path}: {item.expected[:120]} -> {item.actual[:120]}")
    print(f"system run={app_run_id} jobs={len(job_ids)} integrity_problems={len(failing(problems))}")

    compared = command_compare(argparse.Namespace(tag=tag, app_run=app_run_id, show=args.show))

    masks = masks_for(app_run_id, provenance["target"])
    outputs = [normalize_job_output(run_root, job_id, masks) for job_id in job_ids]
    _corpus, defects = load_answer_key(key_root / "expectations.toml")
    matrix = evaluate(defects, collect_findings(outputs))
    for defect in defects:
        state = "found " if defect.id in matrix.found else "MISSED"
        seen = ",".join(matrix.producers_seen.get(defect.id, ())) or "-"
        print(f"   answer-key {state} {defect.id} {defect.path}:{defect.line} producers_seen={seen}")
    print(f"answer key found={len(matrix.found)} missed={len(matrix.missed)} spurious={matrix.spurious}")

    verdict = "SYSTEM OK" if not failing(problems) and compared == 0 and not matrix.failed else "SYSTEM FAILED"
    report = run_root.parent / "metadata" / "stepwise" / "system" / f"{app_run_id}-{tag}.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({
        "verdict": verdict, "application_run_id": app_run_id, "corpus_tag": tag,
        "repository_commit": git("rev-parse", "HEAD", cwd=ROOT), "integrity": [item.as_dict() for item in problems],
        "baseline_compare_exit": compared, "answer_key": matrix.as_dict()}, indent=1) + "\n", encoding="utf-8")
    print(f"== {verdict}; report {report.relative_to(ROOT)}")
    return 0 if verdict == "SYSTEM OK" else 1


def seed_run(args, tag: str, after_job: str) -> tuple[StepwiseState, Path]:
    """Restore the known-good seed after ``after_job`` and open a walk that resumes after it."""
    header, entries = resolve_chain(ACCEPTANCE_ROOT / tag / "seeds", after_job)
    app_run_id = header["application_run_id"]
    if getattr(args, "run_id", None) and args.run_id != app_run_id:
        raise SeedError(
            f"a seed restores under its original run id {app_run_id}: the id is inside hashed artifacts "
            "(retrieval manifests carry run_id), so another id would change handoff identities, and a "
            "different runtime.runs_dir changes the configuration the run is bound to")
    topology = packaged_topology()
    if topology["jobs"] != header.get("topology"):
        raise SeedError("the packaged wave1_review topology differs from the one the seed was taken with")
    run_root = ROOT / "runs" / app_run_id
    state_dir = STATE_ROOT / app_run_id
    if run_root.exists() or state_dir.exists():
        if not args.replace:
            raise SeedError(f"runs/{app_run_id} or its walk state exists; pass --replace to move them aside")
        displaced = STATE_ROOT / "displaced" / f"{app_run_id}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
        displaced.mkdir(parents=True)
        if run_root.exists():
            run_root.rename(displaced / "run")
        if state_dir.exists():
            state_dir.rename(displaced / "state")
        print(f"moved the existing run and walk state to {relative(displaced)}")
    environment = read_environment(DEPLOYMENT / ".env")
    issues = restore(ROOT, BlobStore(SEED_STORE), header, entries,
                     expected_uid=int(environment.get("APPSEC_UID", "0")),
                     expected_gid=int(environment.get("APPSEC_GID", "0")),
                     restore_shared=args.restore_shared)
    run_prefix = header["run_root"] + "/"
    run_issues = [issue for issue in issues if issue.path.startswith(run_prefix) or issue.path == header["run_root"]]
    shared_issues = [issue for issue in issues if issue not in run_issues]
    for issue in [*run_issues, *shared_issues][:args.show * 5]:
        print(f"   seed {issue.kind}: {issue.path} {issue.detail}")
    if run_issues:
        raise SeedError(f"restored run tree differs from seed after-{after_job} in {len(run_issues)} entries")
    if shared_issues and not args.allow_shared_drift:
        raise SeedError(f"{len(shared_issues)} shared inputs (runs/metadata, data) drifted from the seed; "
                        "pass --restore-shared to restore stored ones or --allow-shared-drift to proceed")
    state = StepwiseState.create(app_run_id, target=header["target"], topology=topology)
    handoffs = {}
    for job in state.jobs:
        pointer = run_root / "data" / "jobs" / job["job_id"] / "latest.json"
        if pointer.is_file():
            handoffs[job["job_id"]] = json.loads(pointer.read_text(encoding="utf-8"))["handoff_sha256"]
    state.mark_seeded(after_job, corpus_tag=tag, handoffs=handoffs)
    path = StepwiseState.path_for(STATE_ROOT, app_run_id)
    state.save(path)
    print(f"seeded runs/{app_run_id} after {after_job}: {len(entries)} entries verified; "
          f"next job {(state.next_job() or {}).get('job_id', '-')}")
    return state, path


def command_seed(args) -> int:
    seed_run(args, valid_corpus_tag(args.tag), args.after)
    return 0


def command_verify_job(args) -> int:
    tag = valid_corpus_tag(args.tag)
    topology = packaged_topology()
    ids = [item["job_id"] for item in topology["jobs"]]
    job_id = next((item["job_id"] for item in topology["jobs"] if args.job in {item["job_id"], item["name"]}), None)
    if job_id is None:
        raise StateError(f"job is not in wave1_review: {args.job}")
    if ids.index(job_id) == 0:
        raise StateError(f"{job_id} has no predecessor seed; verify it with init, check and compare")
    expected_path = ACCEPTANCE_ROOT / tag / f"{job_id}.json"
    if not expected_path.is_file():
        raise StateError(f"no accepted output for {job_id} under {relative(expected_path.parent)}")
    state, path = seed_run(args, tag, ids[ids.index(job_id) - 1])
    status = launch_next(args, state, path)
    state = StepwiseState.load(path)
    run_root = ROOT / "runs" / state.app_run_id
    attempt = locate_attempt(run_root, job_id, state.job(job_id)["dagster_run_ids"][-1])
    actual = normalize_job_output(run_root, job_id, masks_for(state.app_run_id, state.target), attempt_root=attempt)
    differences = diff_job_outputs(json.loads(expected_path.read_text(encoding="utf-8")), actual, job_id)
    counts = Counter(item.kind for item in differences)
    print(f"verify-job {job_id} tag={tag} check={'passed' if status == 0 else 'FAILED'} "
          + " ".join(f"{kind}={counts.get(kind, 0)}" for kind in CLASSES))
    for difference in failing(differences)[:args.show * 5]:
        print(f"   {difference.kind} {difference.path}: {difference.expected[:160]} -> {difference.actual[:160]}")
    return 1 if status or failing(differences) else 0


# -- parity: the same job through Dagster and through the local launcher ------------------------
# docs/processes/local-dagster-parity.md. Both sides start from the same restored state, one after
# the other; the Dagster tree is the one kept for acceptance.
PARITY_ROOT = STATE_ROOT / "parity"
SHARED_ROOTS = ("runs/metadata", "data")
MODEL_RECORDING = "APPSEC_REVIEW_MODEL_RECORDING"
MODEL_REPLAY_DIR = "APPSEC_REVIEW_MODEL_REPLAY_DIR"
IDENTITY_KEYS = ("implementation_identity", "schema_identity", "validation_identity", "resolved_config_sha256",
                 "job_config_sha256", "source_fingerprint", "input_identity", "upstream_handoff_sha256")


_DAEMON_SOURCES: dict[str, str] = {}


def daemon_sources() -> dict[str, str]:
    """Code-location mount destinations mapped to the source paths the Docker daemon mounts them from.

    A tool container started from the code location is mounted from these sources, so the paths a
    Dagster run records for its tool mounts are spelled this way (Docker Desktop may report its own
    staging path rather than the host path).
    """
    if not _DAEMON_SOURCES:
        container = compose("ps", "-q", "code-location").strip()
        inspected = subprocess.run(["docker", "inspect", container, "--format", "{{json .Mounts}}"],
                                   text=True, capture_output=True, check=True)
        _DAEMON_SOURCES.update({str(item["Destination"]): str(item["Source"])
                                for item in json.loads(inspected.stdout)})
    return _DAEMON_SOURCES


def side_masks(app_run_id: str, target: str, side: str) -> Masks:
    """Masks for one driver's output, built from that driver's own roots only.

    Dagster output is masked with the code location's paths, and with the daemon-visible sources of
    its run and target mounts; local output with the host's. A path written in the other
    environment's spelling survives masking and shows as a difference.
    """
    if side == "dagster":
        sources = daemon_sources()
        runs = [f"{CONTAINER_ROOT}/runs"]
        targets = [target]
        if f"{CONTAINER_ROOT}/runs" in sources:
            runs.append(sources[f"{CONTAINER_ROOT}/runs"])
        targets_mount = f"{CONTAINER_ROOT}/targets"
        if targets_mount in sources and target.startswith(targets_mount + "/"):
            targets.append(sources[targets_mount] + target[len(targets_mount):])
        return Masks.for_run(app_run_id, runs_roots=runs, repository_roots=[CONTAINER_ROOT], target_roots=targets)
    return Masks.for_run(app_run_id, runs_roots=[str(ROOT / "runs")], repository_roots=[str(ROOT)],
                         target_roots=[str(host_path(target))])


def _ids() -> tuple[int, int]:
    environment = read_environment(DEPLOYMENT / ".env")
    return int(environment.get("APPSEC_UID", "0")), int(environment.get("APPSEC_GID", "0"))


_SCAN_CACHE: dict[str, dict] = {}


def _shared_scan() -> dict[str, dict]:
    """Listing of the shared roots; files whose size, mtime and inode are unchanged are not rehashed."""
    uid, gid = _ids()
    if not _SCAN_CACHE:
        cache_path = SEED_STORE / "stat-cache.json"
        if cache_path.is_file():
            _SCAN_CACHE.update(json.loads(cache_path.read_text(encoding="utf-8")))
    entries, cache = scan(ROOT, SHARED_ROOTS, expected_uid=uid, expected_gid=gid, exclude=SEED_EXCLUDE,
                          cache=_SCAN_CACHE)
    _SCAN_CACHE.update(cache)
    return entries


def _shared_delta(before: dict[str, dict], after: dict[str, dict]) -> tuple[list[str], list[str]]:
    """Top-level shared paths a run added, and shared files it changed."""
    added = sorted(path for path in set(after) - set(before) if path.rsplit("/", 1)[0] in before)
    changed = sorted(path for path in set(after) & set(before)
                     if after[path]["type"] == "file" and after[path] != before[path])
    return added, changed


def _move(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source.rename(destination)


def _park(app_run_id: str, destination: Path, added: list[str]) -> None:
    """Move one side's run tree, walk state and added shared paths out of the way."""
    for source, name in ((ROOT / "runs" / app_run_id, "run"), (STATE_ROOT / app_run_id, "state")):
        if source.exists():
            _move(source, destination / name)
    for path in added:
        if (ROOT / path).exists() or (ROOT / path).is_symlink():
            _move(ROOT / path, destination / "shared" / path)


def _unpark(app_run_id: str, source: Path, added: list[str]) -> None:
    for name, target in (("run", ROOT / "runs" / app_run_id), ("state", STATE_ROOT / app_run_id)):
        if (source / name).exists():
            _move(source / name, target)
    for path in added:
        if (source / "shared" / path).exists() or (source / "shared" / path).is_symlink():
            _move(source / "shared" / path, ROOT / path)


def _save_files(paths: list[str], destination: Path) -> None:
    for path in paths:
        (destination / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / path, destination / path)


def _restore_files(paths: list[str], source: Path) -> None:
    for path in paths:
        shutil.copy2(source / path, ROOT / path)


def _handoff(attempt: Path | None) -> dict | None:
    path = attempt / "handoff.json" if attempt else None
    return json.loads(path.read_text(encoding="utf-8")) if path and path.is_file() else None


def _identity_mismatches(dagster: dict | None, local: dict | None) -> list[dict]:
    if dagster is None or local is None:
        return [{"key": "handoff", "dagster": dagster is not None, "local": local is not None}]
    return [{"key": key, "dagster": dagster.get(key), "local": local.get(key)}
            for key in IDENTITY_KEYS if dagster.get(key) != local.get(key)]


CONTAINER_ROOT = "/opt/app"
# Runs the command with the checkout bind-mounted at the code location's /opt/app, in a rootless
# mount namespace (no sudo): paths then resolve to the same spelling as under Dagster, so hashes
# of artifacts that embed the target or run root (the retrieval manifest) agree across drivers.
_NAMESPACE = ('mount -t tmpfs tmpfs /opt && mkdir /opt/app && mount --bind "$1" /opt/app && shift && '
              'cd /opt/app && exec "$@"')


def local_command(job_id: str, app_run_id: str, target: str, *, container_paths: bool,
                  root: Path = ROOT) -> list[str]:
    """The argv of the local launcher for one job; ``target`` is spelled for the environment it runs in."""

    python = f"{CONTAINER_ROOT}/.venv/bin/python" if container_paths else str(root / ".venv" / "bin" / "python")
    command = [python, "-m", "appsec_review", "run", job_id, "--run-id", app_run_id, "--target", target,
               "--upstream-from-run"]
    if container_paths:
        return ["unshare", "-Urm", "sh", "-c", _NAMESPACE, "sh", str(root), *command]
    return command


def _run_local(job_id: str, app_run_id: str, target: Path, replay: Path, log: Path, *,
               container_paths: bool = False) -> int:
    spelled = str(target)
    environment = {**os.environ, MODEL_RECORDING: "replay", MODEL_REPLAY_DIR: str(replay),
                   "APPSEC_REVIEW_TARGET": spelled}
    command = local_command(job_id, app_run_id, spelled, container_paths=container_paths)
    print(f"local: {' '.join(command[-9 if container_paths else 2:])}", flush=True)
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as handle:
        result = subprocess.run(command, cwd=ROOT, env=environment, stdout=handle, stderr=subprocess.STDOUT,
                                check=False)
    print(f"local exit={result.returncode} log={relative(log)}", flush=True)
    return result.returncode


def _dagster_first(args, topology: dict) -> tuple[StepwiseState, Path]:
    """Launch the first wave job; it allocates the application run the walk then follows."""
    if not args.target:
        raise StateError(f"{topology['jobs'][0]['job_id']} starts a walk; pass --target <container path>")
    first = topology["jobs"][0]
    dagster_run_id = str(uuid4())
    launch(first["name"], dagster_run_id, {})
    run = wait(args.url, dagster_run_id, args.interval_seconds)
    app_run_id = run["tag_map"].get("appsec/application_run_id")
    if not app_run_id:
        raise RuntimeError(f"{first['name']} did not allocate an application run")
    state = StepwiseState.create(app_run_id, target=args.target, topology=topology)
    state.record_launch(first["job_id"], dagster_run_id)
    path = StepwiseState.path_for(STATE_ROOT, app_run_id)
    state.save(path)
    check(args, state, path, first["job_id"])
    return StepwiseState.load(path), path


def command_parity(args) -> int:
    tag = valid_corpus_tag(args.tag)
    topology = packaged_topology()
    ids = [item["job_id"] for item in topology["jobs"]]
    job_id = next((item["job_id"] for item in topology["jobs"] if args.job in {item["job_id"], item["name"]}), None)
    if job_id is None:
        raise StateError(f"job is not in wave1_review: {args.job}")
    position = ids.index(job_id)
    recording = compose("exec", "-T", "code-location", "sh", "-c", f"printenv {MODEL_RECORDING} || true").strip()
    if recording != "record":
        raise RuntimeError(f"the code location must run with {MODEL_RECORDING}=record for a parity walk; "
                           "set it in deploy/dagster/.env and recreate the stack")
    configured = compose("exec", "-T", "code-location", "printenv", "APPSEC_REVIEW_TARGET").strip()

    # 1-2. Dagster from the previous job's seed (or a new run for the first job).
    if position == 0:
        if args.target != configured:
            raise RuntimeError(f"the code location reviews {configured}, not {args.target}")
        shared_before = _shared_scan()
        state, path = _dagster_first(args, topology)
    else:
        state, path = seed_run(args, tag, ids[position - 1])
        if state.target != configured:
            raise RuntimeError(f"the code location reviews {configured}, but the seed reviews {state.target}")
        shared_before = _shared_scan()
        launch_next(args, state, path)
        state = StepwiseState.load(path)
    app_run_id = state.app_run_id
    run_root = ROOT / "runs" / app_run_id
    dagster_run_id = state.job(job_id)["dagster_run_ids"][-1]
    dagster_status = get_run(args.url, dagster_run_id)["status"]
    dagster_attempt = locate_attempt(run_root, job_id, dagster_run_id)
    dagster_output = normalize_job_output(run_root, job_id, side_masks(app_run_id, state.target, "dagster"),
                                          attempt_root=dagster_attempt)
    dagster_handoff = _handoff(dagster_attempt)
    walk = PARITY_ROOT / app_run_id / job_id / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    walk.mkdir(parents=True)
    (walk / "dagster.json").write_text(json.dumps(dagster_output, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    recordings = walk / "recordings"
    if (run_root / "data" / "inference-recordings").is_dir():
        shutil.copytree(run_root / "data" / "inference-recordings", recordings)
    else:
        recordings.mkdir()

    # 3. Put the starting state back: park Dagster's tree, additions and changed shared files.
    added, changed = _shared_delta(shared_before, _shared_scan())
    _save_files(changed, walk / "dagster" / "changed")
    _park(app_run_id, walk / "dagster", added)
    local_added: list[str] = []
    try:
        if position == 0:
            # The first job starts from an empty run bound to the same configuration.
            (run_root / "data" / "jobs").mkdir(parents=True)
            shutil.copytree(walk / "dagster" / "run" / "data" / "configuration", run_root / "data" / "configuration")
            if changed:
                raise StateError(f"{job_id} changed {len(changed)} shared files and has no seed to restore them")
        else:
            seed_args = argparse.Namespace(**{**vars(args), "replace": False, "restore_shared": args.restore_shared or bool(changed),
                                              "run_id": None})
            seed_run(seed_args, tag, ids[position - 1])
        # 4. The local launcher, replaying the Dagster run's model responses.
        local_before = _shared_scan()
        started = time.time()
        container_paths = bool(getattr(args, "container_paths", False))
        local_side = "dagster" if container_paths else "local"
        exit_code = _run_local(job_id, app_run_id, Path(state.target) if container_paths else host_path(state.target),
                               recordings, walk / "local.log", **({"container_paths": True} if container_paths else {}))
        local_attempt = locate_attempt(run_root, job_id)
        local_output = normalize_job_output(run_root, job_id, side_masks(app_run_id, state.target, local_side),
                                            attempt_root=local_attempt)
        local_handoff = _handoff(local_attempt)
        uid, gid = _ids()
        audit = audit_job_writes(run_root, job_id, local_attempt, expected_uid=uid, expected_gid=gid,
                                 since=started - 2, extra_roots=[ROOT / "runs" / "metadata", ROOT / "data"],
                                 exclude=[STATE_ROOT, SEED_STORE],
                                 dagster_status="SUCCESS" if exit_code == 0 else "FAILURE")
        (walk / "local.json").write_text(json.dumps(local_output, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        # Raw bytes may differ by environment; the content each side published must not.
        content = content_differences(job_id, walk / "dagster" / "run", dagster_handoff,
                                      side_masks(app_run_id, state.target, "dagster"), run_root, local_handoff,
                                      side_masks(app_run_id, state.target, local_side))
        # Ids, hashes and paths may differ between the sides; on each side they must be populated and
        # consistent with the run they belong to.
        parked_attempt = (walk / "dagster" / "run" / dagster_attempt.relative_to(run_root)
                          if dagster_attempt is not None else None)
        target_checkout = host_path(state.target)
        integrity = (attempt_integrity(job_id, walk / "dagster" / "run", app_run_id, parked_attempt, "dagster",
                                       target_checkout) +
                     attempt_integrity(job_id, run_root, app_run_id, local_attempt, "local", target_checkout))
        local_added, local_changed = _shared_delta(local_before, _shared_scan())
        _save_files(local_changed, walk / "local" / "changed")
    finally:
        # 7. Keep the Dagster side in place for acceptance.
        _park(app_run_id, walk / "local", local_added)
        _restore_files(changed, walk / "dagster" / "changed")
        _unpark(app_run_id, walk / "dagster", added)

    # 5-6. Same inputs and code on both sides, then the same output.
    mismatches = _identity_mismatches(dagster_handoff, local_handoff)
    differences = classify_environment(diff_job_outputs(dagster_output, local_output, job_id) + content) + integrity
    failures = failing(differences)
    both_succeeded = dagster_status == "SUCCESS" and exit_code == 0 and not audit
    verdict = ("PARITY OK" if both_succeeded and not mismatches and not failures else
               "RUN FAILED" if not both_succeeded else
               "INVALID COMPARISON" if mismatches else "DIFFERENT")
    counts = Counter(item.kind for item in differences)
    summary = {side: {"status": document["status"], "findings": sum(item["count"] for item in document["findings"]),
                      "gaps": sum(item["count"] for item in document["gaps"]), "units": len(document["units"])}
               for side, document in (("dagster", dagster_output), ("local", local_output))}
    report = {"schema": "appsec-review/parity-report/1", "verdict": verdict, "job_id": job_id, "corpus_tag": tag,
              "application_run_id": app_run_id, "repository_commit": git("rev-parse", "HEAD", cwd=ROOT),
              "dagster": {"dagster_run_id": dagster_run_id, "status": dagster_status, **summary["dagster"],
                          "tool_identity": (dagster_handoff or {}).get("tool_identity")},
              "local": {"exit_code": exit_code, **summary["local"], "audit": summarize(audit), "audit_findings": [finding.as_dict() for finding in audit],
                        "tool_identity": (local_handoff or {}).get("tool_identity")},
              "identity_mismatches": mismatches, "shared_added": {"dagster": added, "local": local_added},
              "differences": [item.as_dict() for item in differences]}
    (walk / "report.json").write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    print(f"== parity {job_id} {verdict}")
    for side in ("dagster", "local"):
        print(f"   {side}: " + " ".join(f"{key}={value}" for key, value in report[side].items()
                                         if key not in {"tool_identity", "dagster_run_id"}))
    for item in mismatches:
        print(f"   identity {item['key']}: dagster={str(item['dagster'])[:120]} local={str(item['local'])[:120]}")
    print("   differences " + " ".join(f"{kind}={counts.get(kind, 0)}" for kind in CLASSES))
    for item in failures[:args.show * 5]:
        print(f"   {item.kind} {item.path}: dagster={item.expected[:160]} local={item.actual[:160]}")
    if len(failures) > args.show * 5:
        print(f"   ... {len(failures) - args.show * 5} more in the report")
    print(f"   report {relative(walk / 'report.json')}")
    if verdict == "PARITY OK":
        print(f"   review it, then: stepwise.py accept --job {job_id} --tag {tag} --app-run {app_run_id}")
    return {"PARITY OK": 0, "RUN FAILED": 1}.get(verdict, 3)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="http://127.0.0.1:3000/graphql")
    parser.add_argument("--interval-seconds", type=int, default=30)
    parser.add_argument("--show", type=int, default=10, help="examples printed per gap list and audit kind")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--target", required=True, help="target path inside the code location")
    nxt = commands.add_parser("next")
    nxt.add_argument("--app-run")
    nxt.add_argument("--relaunch", action="store_true", help="relaunch a job whose check passed")
    for name in ("check", "accept"):
        sub = commands.add_parser(name)
        sub.add_argument("--job", required=True)
        sub.add_argument("--app-run")
        if name == "accept":
            sub.add_argument("--tag", required=True, help="corpus tag the target checkout is pinned at")
    compare = commands.add_parser("compare")
    compare.add_argument("--app-run", required=True)
    compare.add_argument("--tag", required=True)
    for name in ("seed", "verify-job"):
        sub = commands.add_parser(name)
        sub.add_argument("--tag", required=True)
        if name == "seed":
            sub.add_argument("--after", required=True, help="restore the seed taken after this job")
            sub.add_argument("--run-id", help="must equal the seed's run id; rewriting ids is refused")
        else:
            sub.add_argument("--job", required=True, help="job to verify from its predecessor's seed")
        sub.add_argument("--replace", action="store_true", help="move an existing run tree and walk aside")
        sub.add_argument("--restore-shared", action="store_true",
                         help="also restore stored runs/metadata and data inputs that drifted")
        sub.add_argument("--allow-shared-drift", action="store_true",
                         help="proceed although shared inputs differ from the seed")
    parity = commands.add_parser("parity", help="run one job through Dagster and the local launcher and diff them")
    parity.add_argument("--tag", required=True)
    parity.add_argument("--job", required=True)
    parity.add_argument("--target", help="target path inside the code location (first job only)")
    parity.add_argument("--replace", action="store_true", help="move an existing run tree and walk aside")
    parity.add_argument("--restore-shared", action="store_true",
                        help="also restore stored runs/metadata and data inputs that drifted")
    parity.add_argument("--allow-shared-drift", action="store_true",
                        help="proceed although shared inputs differ from the seed")
    parity.add_argument("--container-paths", action="store_true",
                        help="run the local side with the checkout mounted at /opt/app (rootless namespace) so "
                             "hashes that embed the target or run root match the Dagster side; no docker group")
    system = commands.add_parser("system", help="run or take a whole wave1_review and check it end to end")
    system.add_argument("--tag", required=True)
    system.add_argument("--app-run", help="evaluate this finished application run instead of starting one")
    args = parser.parse_args(argv)
    if args.interval_seconds < 1:
        parser.error("--interval-seconds must be positive")
    handlers = {"init": command_init, "next": command_next, "check": command_check,
                "accept": command_accept, "compare": command_compare, "seed": command_seed,
                "verify-job": command_verify_job, "parity": command_parity, "system": command_system}
    try:
        return handlers[args.command](args)
    except (StateError, SeedError, RuntimeError) as exc:
        print(f"stepwise: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
