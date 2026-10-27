"""Operator commands for the local Dagster stack and the reviews it runs.

The shell and PowerShell scripts under ``scripts/`` are thin wrappers around the subcommands here.
Stack changes go through ``lifecycle.py`` (it adds the selected provider's overlay compose file), never
through ``docker compose`` on ``compose.yaml`` alone. Reviews are launched with the same
``dagster job launch`` call the documentation uses and ended with ``recover_runs.py``.
Every state-changing command refuses to disturb a non-terminal Dagster run unless ``--force`` is given.

Exit codes: 0 success, 1 failed, 2 usage error, 3 refused by a safety rule, 4 nothing matched.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from host import actual_platform, deployment_profile, project_name, provider_overlay, read_environment, reject_native_environment


DEPLOYMENT = Path(__file__).resolve().parents[1]
ROOT = DEPLOYMENT.parents[1]
BIN = Path(__file__).resolve().parent
DEFAULT_URL = os.environ.get("APPSEC_DAGSTER_URL", "http://127.0.0.1:3000/graphql")
SERVICES = ("postgres", "code-location", "daemon", "webserver")
TERMINAL = frozenset({"SUCCESS", "FAILURE", "CANCELED"})
FAILED_FINAL = frozenset({"FAILURE", "CANCELED"})
JOB_NAME = "wave1_review"
CONTAINER_TARGETS = "/opt/app/targets"
CONTAINER_ACCEPTANCE = "/opt/app/test/acceptance"
TARGET_VARIABLE = "APPSEC_REVIEW_TARGET"
OVERLAY_VARIABLE = "APPSEC_REVIEW_CONFIG_OVERLAY"
RECORDING_VARIABLE = "APPSEC_REVIEW_MODEL_RECORDING"
PROFILE_VARIABLE = "APPSEC_REVIEW_PROFILE"
DEFAULT_PROFILE = "dev"
DEPLOY_VARIABLES = (TARGET_VARIABLE, OVERLAY_VARIABLE, RECORDING_VARIABLE, PROFILE_VARIABLE)
PROFILE_NOTICE = ("profile {profile} uses the more capable models (Sonnet 5.5, Opus 5.5 verifier) and larger token limits; "
                  "see docs/operations/model-profiles.md")
OK, FAILED, USAGE, REFUSED, NOT_FOUND = 0, 1, 2, 3, 4
APP_RUN_ID = re.compile(r"^\d{4}-\d{2}-\d{2}-\d{4}$")
DAGSTER_RUN_ID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
EXPIRED_TOKEN = re.compile(r"oauth|token.{0,40}(expired|invalid|revoked)|expired.{0,40}token|401|authentication_error|"
                           r"/login|not logged in|invalid api key", re.IGNORECASE)
SECRET = re.compile(r"(sk-ant-[A-Za-z0-9_\-]+|Bearer\s+[A-Za-z0-9._\-]+|[A-Za-z0-9_\-]{40,})")

RUNS_QUERY = """query OpsRuns($limit: Int!) { runsOrError(limit: $limit) {
  __typename ... on Runs { results { runId status pipelineName startTime endTime tags { key value } } }
  ... on PythonError { message } } }"""
RUN_QUERY = """query OpsRun($runId: ID!) { runOrError(runId: $runId) {
  __typename ... on Run { runId status pipelineName startTime endTime tags { key value }
    stepStats { stepKey status startTime endTime } }
  ... on RunNotFoundError { message } ... on PythonError { message } } }"""
PLAN_QUERY = """query OpsPlan($runId: ID!) { runOrError(runId: $runId) {
  __typename ... on Run { executionPlan { steps { key } } } } }"""


class OpsError(Exception):
    """A failure the operator should read about; ``code`` becomes the exit status."""

    def __init__(self, message: str, code: int = FAILED) -> None:
        super().__init__(message)
        self.code = code


def say(message: str = "") -> None:
    print(message, flush=True)


def redact(text: str, limit: int = 400) -> str:
    """Return a short, secret-free excerpt of tool output."""
    return SECRET.sub("[redacted]", " ".join(text.split()))[-limit:]


# -- docker ---------------------------------------------------------------------------------------
def docker(*arguments: str, timeout: float = 60) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["docker", *arguments], capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as error:
        raise OpsError("docker is not installed or not on PATH") from error
    except subprocess.TimeoutExpired as error:
        raise OpsError(f"docker {arguments[0]} timed out after {timeout:.0f}s") from error


@dataclass(frozen=True)
class Container:
    id: str
    name: str
    service: str
    state: str
    health: str
    image: str
    config_files: tuple[str, ...]
    settings: dict[str, str] = field(default_factory=dict)
    image_id: str = ""

    @property
    def healthy(self) -> bool:
        return self.state == "running" and self.health in {"healthy", "none"}


def deployment_project() -> str:
    environment = DEPLOYMENT / ".env"
    if environment.is_file():
        value = read_environment(environment).get("APPSEC_COMPOSE_PROJECT")
        if value:
            return value
    return project_name(actual_platform())


def stack_containers(project: str) -> list[Container]:
    listed = docker("ps", "-a", "-q", "--filter", f"label=com.docker.compose.project={project}")
    ids = listed.stdout.split()
    if listed.returncode != 0:
        raise OpsError(f"docker ps failed: {redact(listed.stderr)}")
    if not ids:
        return []
    inspected = docker("inspect", *ids)
    if inspected.returncode != 0:
        raise OpsError(f"docker inspect failed: {redact(inspected.stderr)}")
    containers = []
    for item in json.loads(inspected.stdout):
        labels = item.get("Config", {}).get("Labels") or {}
        environment = dict(entry.split("=", 1) for entry in item.get("Config", {}).get("Env") or [] if "=" in entry)
        state = item.get("State", {})
        containers.append(Container(
            id=item["Id"][:12], name=item.get("Name", "").lstrip("/"),
            service=labels.get("com.docker.compose.service", "?"), state=state.get("Status", "unknown"),
            health=(state.get("Health") or {}).get("Status", "none"), image=item.get("Config", {}).get("Image", "?"),
            config_files=tuple(part for part in labels.get("com.docker.compose.project.config_files", "").split(",") if part),
            # Only the three non-secret deployment settings are kept; the rest of the environment is never read.
            settings={key: environment[key] for key in DEPLOY_VARIABLES if key in environment},
            image_id=item.get("Image", "")))
    return sorted(containers, key=lambda item: (SERVICES.index(item.service) if item.service in SERVICES else 99))


def by_service(containers: list[Container]) -> dict[str, Container]:
    return {item.service: item for item in containers}


def overlay_name(profile: str = "dev") -> str:
    return provider_overlay(actual_platform(), profile)


def image_tag(profile: str = "dev") -> str:
    suffix = "-copilot" if profile in {"copilot-dev", "copilot-prod"} else ""
    return f"appsec-review-dagster:{actual_platform()}{suffix}"


# -- Dagster GraphQL ------------------------------------------------------------------------------
def graphql(url: str, query: str, variables: dict | None = None, timeout: float = 30) -> dict:
    request = Request(url, data=json.dumps({"query": query, "variables": variables or {}}).encode(),
                      headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except (URLError, OSError, ValueError) as error:
        raise OpsError(f"Dagster GraphQL at {url} is unreachable: {error}") from error
    if payload.get("errors"):
        raise OpsError(f"Dagster GraphQL error: {redact(str(payload['errors']))}")
    return payload["data"]


def tag_map(run: dict) -> dict[str, str]:
    return {item["key"]: item["value"] for item in run.get("tags", [])}


def list_runs(url: str, limit: int = 500) -> list[dict]:
    value = graphql(url, RUNS_QUERY, {"limit": limit})["runsOrError"]
    if value.get("__typename") != "Runs":
        raise OpsError(value.get("message") or "Dagster run listing failed")
    return list(value["results"])


def get_run(url: str, run_id: str) -> dict:
    value = graphql(url, RUN_QUERY, {"runId": run_id})["runOrError"]
    if value.get("__typename") != "Run":
        raise OpsError(value.get("message") or f"Dagster run {run_id} not found", NOT_FOUND)
    return value


def total_jobs(url: str, run_id: str) -> int:
    value = graphql(url, PLAN_QUERY, {"runId": run_id})["runOrError"]
    steps = (value.get("executionPlan") or {}).get("steps") or []
    return sum(1 for step in steps if step["key"].endswith("__begin"))


def active_only(runs: list[dict]) -> list[dict]:
    return [run for run in runs if run["status"] not in TERMINAL]


def stack_running(containers: list[Container]) -> bool:
    return any(item.state == "running" for item in containers)


def require_own_stack(containers: list[Container]) -> None:
    """Refuse to manage a stack that another checkout created: lifecycle.py would recreate it from this tree."""
    code = by_service(containers).get("code-location")
    if code is None or not code.config_files:
        return
    here = DEPLOYMENT.resolve().as_posix().lower().rstrip("/")
    there = code.config_files[0].replace("\\", "/").lower().rsplit("/", 1)[0].rstrip("/")
    if there != here:
        raise OpsError(f"the running stack was created from {there}, not from this checkout ({here}); "
                       "run the scripts from the checkout that owns it (managing it from here would recreate it "
                       "with this checkout's mounts)", REFUSED)


def guard_active_runs(url: str, containers: list[Container], force: bool, action: str) -> None:
    """Refuse to disturb a non-terminal run (multi-session-coordination: do not move what others use)."""
    if not stack_running(containers):
        return
    try:
        active = active_only(list_runs(url))
    except OpsError as error:
        if force:
            say(f"warning: cannot verify active runs ({error}); continuing because of --force")
            return
        raise OpsError(f"refusing to {action}: cannot verify that no run is active ({error}). "
                       "Use --force only if you know nothing is running.", REFUSED) from error
    if not active:
        return
    listing = "; ".join(f"{run['runId']} {run['status']} {run['pipelineName']} "
                        f"app={tag_map(run).get('appsec/application_run_id', 'unallocated')}" for run in active)
    if not force:
        raise OpsError(f"refusing to {action}: {len(active)} non-terminal Dagster run(s): {listing}. "
                       "Wait for them (review-watch), end them (review-stop), or use --force.", REFUSED)
    say(f"warning: {action} with --force while {len(active)} run(s) are active: {listing}")


# -- lifecycle ------------------------------------------------------------------------------------
def lifecycle(action: str, settings: dict[str, str], dry_run: bool) -> int:
    argv = [sys.executable, str(BIN / "lifecycle.py"), action]
    shown = " ".join(f"{key}={shlex.quote(value)}" for key, value in settings.items())
    say(f"+ {(shown + ' ') if shown else ''}{shlex.join(argv)}")
    if dry_run:
        return OK
    return subprocess.run(argv, cwd=ROOT, env={**os.environ, **settings}, check=False).returncode


def resolve_target(value: str) -> str:
    """A target name under ``targets/`` or an absolute container path, as a container path."""
    if value.startswith("/"):
        return value.rstrip("/") or "/"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._\-]*", value):
        raise OpsError(f"--target {value!r} is neither a name under targets/ nor an absolute container path", USAGE)
    if not (ROOT / "targets" / value).is_dir():
        raise OpsError(f"no target checkout targets/{value} (use an absolute container path for another mount)", NOT_FOUND)
    return f"{CONTAINER_TARGETS}/{value}"


def resolve_overlay(value: str) -> str:
    if value.lower() in {"none", "off", ""}:
        return ""
    acceptance = (ROOT / "test" / "acceptance").resolve()
    for candidate in (Path(value), ROOT / value, acceptance / value):
        if candidate.is_file():
            resolved = candidate.resolve()
            if not resolved.is_relative_to(acceptance):
                raise OpsError(f"--overlay must live under test/acceptance (the only tree mounted for it): {resolved}", USAGE)
            return f"{CONTAINER_ACCEPTANCE}/{resolved.relative_to(acceptance).as_posix()}"
    raise OpsError(f"overlay file not found: {value}", NOT_FOUND)


def resolve_recording(value: str) -> str:
    return "" if value == "off" else value


def requested_settings(args: argparse.Namespace) -> dict[str, str]:
    requested: dict[str, str] = {}
    if getattr(args, "target", None) is not None:
        requested[TARGET_VARIABLE] = resolve_target(args.target)
    if getattr(args, "overlay", None) is not None:
        requested[OVERLAY_VARIABLE] = resolve_overlay(args.overlay)
    if getattr(args, "recording", None) is not None:
        requested[RECORDING_VARIABLE] = resolve_recording(args.recording)
    if getattr(args, "profile", None) is not None:
        requested[PROFILE_VARIABLE] = args.profile
    return requested


def running_value(container: Container, key: str) -> str:
    """The container's setting; an unset profile is the default profile."""
    return container.settings.get(key, "") or (DEFAULT_PROFILE if key == PROFILE_VARIABLE else "")


def effective_settings(containers: list[Container], requested: dict[str, str]) -> tuple[dict[str, str], bool]:
    """Settings to export to compose: the running stack's non-empty values, then the requested ones.

    Compose lets the shell override ``.env``; carrying the running values over means a restart never
    silently reverts a ``--target``/``--overlay``/``--recording`` choice. Returns (settings, changes_running).
    """
    current = by_service(containers).get("code-location")
    carried = {key: value for key, value in (current.settings if current else {}).items() if value}
    changes = bool(current) and any(running_value(current, key) != value for key, value in requested.items())
    return {**carried, **requested}, changes


def add_deploy_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target", help="review target: a name under targets/ or a container path")
    parser.add_argument("--overlay", help="capacity overlay file under test/acceptance, or 'none'")
    parser.add_argument("--recording", choices=("record", "replay", "off"), help="model recording mode")
    parser.add_argument("--profile", choices=("dev", "prod", "copilot-dev", "copilot-prod"),
                        help="runtime profile (Copilot profiles use a separate login; prod profiles use production limits)")


# -- stack checks ---------------------------------------------------------------------------------
def check_health(project: str) -> tuple[bool, list[Container]]:
    containers = stack_containers(project)
    services = by_service(containers)
    ok = True
    for name in SERVICES:
        item = services.get(name)
        if item is None:
            say(f"  {name:<14} MISSING")
            ok = False
            continue
        say(f"  {name:<14} {item.state} ({item.health})")
        ok = ok and item.healthy
    return ok, containers


def check_overlay(containers: list[Container]) -> bool:
    code = by_service(containers).get("code-location")
    expected = overlay_name(running_value(code, PROFILE_VARIABLE) if code else "dev")
    if code is None:
        say("  overlay        cannot check: no code-location container")
        return False
    if not any(Path(path.replace("\\", "/")).name == expected for path in code.config_files):
        say(f"  overlay        MISSING: {expected} is not in the running project's compose files "
            f"({', '.join(code.config_files) or 'none recorded'})")
        say("                 the stack was created without the provider overlay; recreate it with "
            "scripts/stack-restart (lifecycle.py adds the overlay)")
        return False
    say(f"  overlay        ok ({expected} in compose config files)")
    return True


def refresh_advice() -> str:
    if actual_platform() == "windows":
        return ("sign in again inside the container: docker compose --env-file deploy/dagster/.env "
                "-f deploy/dagster/compose.yaml -f deploy/dagster/compose.windows.yaml exec code-location claude auth login")
    return ("run `claude -p \"ok\"` on the host (WSL/Linux shell, same user): that refreshes the shared token under "
            "~/.claude, which the stack mounts read-only; then re-run the probe")


def probe_model(containers: list[Container], timeout: float = 180) -> bool:
    code = by_service(containers).get("code-location")
    if code is None or code.state != "running":
        say("  model probe    skipped: code-location is not running")
        return False
    if running_value(code, PROFILE_VARIABLE) in {"copilot-dev", "copilot-prod"}:
        result = docker("exec", code.id, "python", "-c",
                        "from appsec_review.inference.copilot_sdk import verify; verify()", timeout=timeout)
        if result.returncode == 0:
            say("  model catalog  ok (dedicated Copilot login; configured models enabled)")
            return True
        say(f"  model catalog  FAILED: {redact(result.stderr or result.stdout)}")
        return False
    try:
        result = docker("exec", code.id, "claude", "-p", "Reply with the single word: ok", timeout=timeout)
    except OpsError as error:
        say(f"  model probe    FAILED: {error}")
        return False
    output = (result.stdout or "") + " " + (result.stderr or "")
    if result.returncode == 0 and (result.stdout or "").strip():
        say(f"  model probe    ok (replied {redact(result.stdout, 40)!r})")
        return True
    if EXPIRED_TOKEN.search(output):
        say("  model probe    FAILED: the Claude OAuth token looks expired or missing")
        say(f"                 fix: {refresh_advice()}")
    else:
        say(f"  model probe    FAILED (exit {result.returncode}): {redact(output)}")
    return False


def bring_up(args: argparse.Namespace, project: str, containers: list[Container], *, build: bool, action: str) -> int:
    requested = requested_settings(args)
    settings, changes = effective_settings(containers, requested)
    url = args.url
    if stack_running(containers) and (build or changes):
        guard_active_runs(url, containers, args.force, action)
    profile = settings.get(PROFILE_VARIABLE) or deployment_profile(DEPLOYMENT / ".env")
    say(f"profile: {profile}")
    if profile in {"prod", "copilot-prod"}:
        say(PROFILE_NOTICE.format(profile=profile))
    for key, value in settings.items():
        say(f"setting {key}={value or '(empty)'}{'' if key in requested else '  (carried over from the running stack)'}")
    image_missing = docker("image", "inspect", image_tag(profile), "--format", "{{.Id}}").returncode != 0
    if build or image_missing:
        reason = "--build" if build else f"image {image_tag(profile)} is missing"
        say(f"building the image ({reason})")
        if lifecycle("build", settings, args.dry_run) != 0:
            raise OpsError("lifecycle build failed")
    if lifecycle("start", settings, args.dry_run) != 0:
        raise OpsError("lifecycle start failed")
    if args.dry_run:
        say("dry run: not checking health, overlay or model connectivity")
        return OK
    say("health:")
    healthy, containers = check_health(project)
    overlay_ok = check_overlay(containers)
    probe_ok = True
    if not args.no_probe:
        probe_ok = probe_model(containers)
    say(f"Dagster UI: {args.url.removesuffix('/graphql')}")
    return OK if healthy and overlay_ok and probe_ok else FAILED


def cmd_stack_start(args: argparse.Namespace) -> int:
    project = deployment_project()
    say(f"stack-start: project {project}" + (" (dry run)" if args.dry_run else ""))
    require_own_stack(stack_containers(project))
    return bring_up(args, project, stack_containers(project), build=args.build, action="start/recreate the stack")


def cmd_stack_restart(args: argparse.Namespace) -> int:
    project = deployment_project()
    containers = stack_containers(project)
    say(f"stack-restart: project {project}" + (" (dry run)" if args.dry_run else ""))
    require_own_stack(containers)
    guard_active_runs(args.url, containers, args.force, "restart the stack")
    settings, _ = effective_settings(containers, requested_settings(args))
    if args.code_location_only:
        if lifecycle("reload", settings, args.dry_run) != 0:
            raise OpsError("lifecycle reload failed")
        if args.dry_run:
            return OK
        say("health:")
        healthy, containers = check_health(project)
        return OK if healthy and check_overlay(containers) else FAILED
    if stack_running(containers) and lifecycle("stop", settings, args.dry_run) != 0:
        raise OpsError("lifecycle stop failed")
    return bring_up(args, project, stack_containers(project), build=False, action="restart the stack")


def cmd_stack_rebuild(args: argparse.Namespace) -> int:
    project = deployment_project()
    containers = stack_containers(project)
    say(f"stack-rebuild: project {project}" + (" (dry run)" if args.dry_run else ""))
    require_own_stack(containers)
    guard_active_runs(args.url, containers, args.force, "rebuild the stack")
    return bring_up(args, project, containers, build=True, action="rebuild the stack")


def cmd_stack_stop(args: argparse.Namespace) -> int:
    project = deployment_project()
    containers = stack_containers(project)
    say(f"stack-stop: project {project}" + (" (dry run)" if args.dry_run else ""))
    require_own_stack(containers)
    if not containers:
        say("no containers exist for this project; nothing to stop")
        return OK
    purge: list[str] = []
    if args.purge_volumes:
        listed = docker("volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}")
        volumes = listed.stdout.split()
        say(f"--purge-volumes will REMOVE {len(containers)} container(s): {', '.join(item.name for item in containers)}")
        say(f"--purge-volumes will REMOVE {len(volumes)} volume(s) with all data in them: {', '.join(volumes) or '(none)'}")
        if not args.yes:
            raise OpsError("--purge-volumes deletes the Dagster database and storage; add --yes to confirm", REFUSED)
        purge = volumes
    guard_active_runs(args.url, containers, args.force, "stop the stack")
    settings, _ = effective_settings(containers, {})
    if lifecycle("stop", settings, args.dry_run) != 0:
        raise OpsError("lifecycle stop failed")
    if args.purge_volumes:
        for command in (["rm", *[item.id for item in containers]], ["volume", "rm", *purge] if purge else None):
            if command is None:
                continue
            say("+ docker " + shlex.join(command))
            if not args.dry_run and docker(*command).returncode != 0:
                raise OpsError(f"docker {command[0]} failed")
    else:
        say("containers stopped; volumes and images are kept (stack-start brings them back)")
    return OK


def disk_line(label: str, path: Path) -> str:
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    usage = shutil.disk_usage(probe)
    return f"  {label:<10} {usage.free / 2**30:7.1f} GiB free of {usage.total / 2**30:.1f} GiB  ({path})"


def clock(timestamp: float | None) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "-"


def age_text(timestamp: float) -> str:
    seconds = max(0, time.time() - timestamp)
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{seconds / size:.1f}{unit}"
    return f"{seconds:.0f}s"


def cmd_stack_status(args: argparse.Namespace) -> int:
    project = deployment_project()
    containers = stack_containers(project)
    say(f"stack-status: project {project}")
    say("containers:")
    healthy, containers = check_health(project)
    code = by_service(containers).get("code-location")
    if code:
        say("compose config files:")
        for path in code.config_files:
            say(f"  {path}")
        check_overlay(containers)
        for key in DEPLOY_VARIABLES:
            say(f"  {key}={code.settings.get(key) or '(unset)'}")
        say(f"  profile: {running_value(code, PROFILE_VARIABLE)}")
        created = docker("image", "inspect", code.image, "--format", "{{.Created}}")
        stamp = created.stdout.strip() if created.returncode == 0 else ""
        say(f"image: {code.image} created {stamp or 'unknown'}" + (f" ({_iso_age(stamp)} ago)" if stamp else ""))
    say("Dagster:")
    say(f"  URL        {args.url.removesuffix('/graphql')}")
    try:
        runs = list_runs(args.url, 200)
    except OpsError as error:
        say(f"  runs       unavailable: {error}")
    else:
        active = active_only(runs)
        say(f"  active     {len(active)} non-terminal run(s)")
        for run in active:
            say(f"    {run['runId']} {run['status']} {run['pipelineName']} "
                f"app={tag_map(run).get('appsec/application_run_id', 'unallocated')}")
        applied = [run for run in runs if "appsec/application_run_id" in tag_map(run)]
        if applied:
            last = applied[0]
            say(f"  last app   {tag_map(last)['appsec/application_run_id']} {last['status']} "
                f"{last['pipelineName']} started {clock(last.get('startTime'))}")
        else:
            say("  last app   none")
    say("disk:")
    say(disk_line("runs/", ROOT / "runs"))
    say(disk_line("test/tmp", ROOT / "test" / "tmp"))
    return OK if healthy else FAILED


def _iso_age(stamp: str) -> str:
    try:
        parsed = datetime.fromisoformat(re.sub(r"\.\d+", "", stamp).replace("Z", "+00:00"))
    except ValueError:
        return "unknown"
    return age_text(parsed.timestamp())


def cmd_stack_logs(args: argparse.Namespace) -> int:
    containers = stack_containers(deployment_project())
    wanted = [item for item in containers if args.service in {None, item.service}]
    if not wanted:
        raise OpsError(f"no container for {args.service or 'the stack'}; is the stack created?", NOT_FOUND)
    if args.follow and len(wanted) != 1:
        raise OpsError("--follow needs a single service", USAGE)
    status = OK
    for item in wanted:
        command = ["docker", "logs", "--tail", str(args.tail), *(["--follow"] if args.follow else []), item.id]
        say(f"==> {item.service} ({item.name}) <==")
        status = max(status, subprocess.run(command, check=False).returncode)
    return status


# -- reviews --------------------------------------------------------------------------------------
def webserver_and_code(containers: list[Container]) -> tuple[Container, Container]:
    services = by_service(containers)
    down = [name for name in ("code-location", "webserver", "daemon") if name not in services or services[name].state != "running"]
    if down:
        raise OpsError(f"the stack is not running ({', '.join(down)} down); run scripts/stack-start first", REFUSED)
    return services["webserver"], services["code-location"]


def cmd_review_start(args: argparse.Namespace) -> int:
    import review_run

    try:
        if args.dry_run:
            return _review_start(args)
        with review_run.submission_lock(ROOT):
            return _review_start(args)
    except (OSError, ValueError, RuntimeError) as error:
        raise OpsError(f"submission refused: {error}", REFUSED) from error


def _review_start(args: argparse.Namespace) -> int:
    project = deployment_project()
    containers = stack_containers(project)
    say(f"review-start: project {project}" + (" (dry run)" if args.dry_run else ""))
    webserver, code = webserver_and_code(containers)
    require_own_stack(containers)
    requested = requested_settings(args)
    for key, wanted in requested.items():
        actual = running_value(code, key)
        if actual != wanted:
            flag = {TARGET_VARIABLE: "--target", OVERLAY_VARIABLE: "--overlay", RECORDING_VARIABLE: "--recording",
                    PROFILE_VARIABLE: "--profile"}[key]
            raise OpsError(f"the running code-location has {key}={actual or '(unset)'}, not {wanted or '(unset)'}. "
                           f"The container fixes it at creation: run scripts/stack-restart {flag} <value> first.", REFUSED)
    if args.run_id:
        if not APP_RUN_ID.fullmatch(args.run_id):
            raise OpsError(f"--run-id {args.run_id!r} is not an application run id like 2026-10-21-0007", USAGE)
        if not (ROOT / "runs" / args.run_id).is_dir():
            raise OpsError(f"no application run runs/{args.run_id} to resume", NOT_FOUND)
    guard_active_runs(args.url, containers, args.force, "start another review")
    configuration = ROOT / "appsec-review.toml"
    if configuration.is_file():
        import review_run  # the documented helper: the image pin preflight stepwise.py also runs
        import tomllib
        try:
            review_run.verify_build_profile_images(tomllib.loads(configuration.read_text(encoding="utf-8")))
        except RuntimeError as error:
            raise OpsError(str(error), REFUSED) from error
    else:
        say("warning: appsec-review.toml not found; skipping the image pin preflight")
    import review_run

    dagster_run_id = getattr(args, "dagster_run_id", None) or str(uuid4())
    identity = review_run.submission_identity(
        ROOT, target=code.settings.get(TARGET_VARIABLE) or f"{CONTAINER_TARGETS}/appsec-multi-vuln",
        profile=running_value(code, PROFILE_VARIABLE), overlay=code.settings.get(OVERLAY_VARIABLE, ""),
        recording=code.settings.get(RECORDING_VARIABLE, ""), image_id=code.image_id,
        project=project, url=args.url, application_run_id=args.run_id)
    review_run.check_submission(ROOT, identity, dagster_run_id)
    tags = {"appsec/application_run_id": args.run_id} if args.run_id else {}
    tags["appsec/submission_identity"] = review_run.submission_identity_sha256(identity)
    command = ["exec", webserver.id, "dagster", "job", "launch", "-w",
               "/opt/dagster/home/workspace.yaml", "-l", "appsec_review", "-j", JOB_NAME, "--run-id", dagster_run_id]
    command += ["--tags", json.dumps(tags, sort_keys=True)]
    profile = running_value(code, PROFILE_VARIABLE)
    say(f"profile:   {profile}")
    if profile in {"prod", "copilot-prod"}:
        say(PROFILE_NOTICE.format(profile=profile))
    say(f"target:    {code.settings.get(TARGET_VARIABLE) or '(default)'}")
    say(f"overlay:   {code.settings.get(OVERLAY_VARIABLE) or '(none)'}")
    say(f"recording: {code.settings.get(RECORDING_VARIABLE) or 'off'}")
    say("+ docker " + shlex.join(command))
    if args.dry_run:
        say("dry run: nothing launched")
        return OK
    record = review_run.begin_submission(ROOT, identity, dagster_run_id)
    say(f"submission intent:  {review_run.submission_directory(ROOT) / 'active.json'}")
    try:
        launched = docker(*command, timeout=180)
    except OpsError as error:
        raise OpsError(f"{error}; submission {dagster_run_id} is UNCERTAIN; do not resubmit") from error
    if launched.returncode != 0:
        raise OpsError(f"dagster job launch failed: {redact(launched.stderr or launched.stdout, 800)}; "
                       f"submission {dagster_run_id} is UNCERTAIN; do not resubmit")
    record["state"] = "SUBMITTED"
    review_run.write_submission(ROOT, record)
    say(f"dagster run id:      {dagster_run_id}")
    allocated = args.run_id or ""
    deadline = time.monotonic() + args.id_wait
    while not allocated and time.monotonic() < deadline:
        try:
            allocated = tag_map(get_run(args.url, dagster_run_id)).get("appsec/application_run_id", "")
        except OpsError:
            allocated = ""
        if not allocated:
            time.sleep(min(2.0, max(0.05, args.id_wait / 10)))
    say(f"application run id:  {allocated or 'pending (allocated when the first job starts)'}")
    say(f"watch it:            {args.url.removesuffix('/graphql')}/runs/{dagster_run_id}")
    say(f"                     scripts/review-watch.sh --run {dagster_run_id}")
    return OK


@dataclass
class Watch:
    """Turn successive snapshots of one run into the lines the operator should read."""

    total: int = 0
    seen: set[str] = field(default_factory=set)
    failed: set[str] = field(default_factory=set)

    def update(self, run: dict) -> list[str]:
        lines = []
        started = sorted((step for step in run.get("stepStats", []) if step["stepKey"].endswith("__begin")
                          and step.get("startTime") is not None), key=lambda step: step["startTime"])
        origin = run.get("startTime") or (started[0]["startTime"] if started else 0)
        for step in started:
            job = step["stepKey"].removesuffix("__begin")
            if job in self.seen:
                continue
            self.seen.add(job)
            lines.append(f"[{(step['startTime'] - origin) / 60:6.1f} min] started {job} "
                         f"({len(self.seen)}/{self.total or '?'} jobs)")
        for step in run.get("stepStats", []):
            if step.get("status") == "FAILURE" and step["stepKey"] not in self.failed:
                self.failed.add(step["stepKey"])
                lines.append(f"FAILED step {step['stepKey']}")
        if run["status"] in TERMINAL:
            end = run.get("endTime") or time.time()
            lines.append(f"FINAL {run['status']} after {(end - origin) / 60:.1f} min, "
                         f"{len(self.seen)}/{self.total or '?'} jobs started "
                         f"(application run {tag_map(run).get('appsec/application_run_id', 'unallocated')})")
        return lines


def pick_run(url: str, wanted: str | None) -> dict:
    if wanted:
        return resolve_runs(url, wanted)[0]
    runs = list_runs(url, 200)
    if not runs:
        raise OpsError("Dagster has no runs", NOT_FOUND)
    active = active_only(runs)
    if not active:
        say(f"no active run; showing the latest ({runs[0]['runId']})")
    elif len(active) > 1:
        say(f"warning: {len(active)} active runs; watching the newest ({active[0]['runId']})")
    return (active or runs)[0]


def cmd_review_watch(args: argparse.Namespace) -> int:
    summary = pick_run(args.url, args.run)
    run_id = summary["runId"]
    watch = Watch()
    say(f"watching dagster run {run_id} ({summary['pipelineName']}) {args.url.removesuffix('/graphql')}/runs/{run_id}")
    errors = 0
    while True:
        try:
            run = get_run(args.url, run_id)
            if not watch.total:
                watch.total = total_jobs(args.url, run_id)
            errors = 0
        except OpsError as error:
            errors += 1
            if errors == 1:
                say(f"warning: {error}")
            if errors >= 5:
                say("giving up: Dagster stayed unreachable")
                return FAILED
            time.sleep(args.interval)
            continue
        for line in watch.update(run):
            say(line)
        if run["status"] in TERMINAL:
            return FAILED if run["status"] in FAILED_FINAL else OK
        if args.once:
            say(f"status {run['status']}; running steps: " + (", ".join(
                step["stepKey"] for step in run.get("stepStats", []) if step.get("status") == "IN_PROGRESS")[:300] or "-"))
            return OK
        time.sleep(args.interval)


def cmd_review_status(args: argparse.Namespace) -> int:
    runs = list_runs(args.url, max(args.limit, 50))
    say(f"{'STATUS':<10} {'JOB':<22} {'APP RUN':<16} {'STARTED':<19} {'DURATION':<9} DAGSTER RUN")
    for run in runs[:args.limit]:
        end = run.get("endTime") or (time.time() if run["status"] not in TERMINAL else None)
        duration = f"{(end - run['startTime']) / 60:.1f}m" if run.get("startTime") and end else "-"
        say(f"{run['status']:<10} {run['pipelineName'][:22]:<22} "
            f"{tag_map(run).get('appsec/application_run_id', '-'):<16} {clock(run.get('startTime')):<19} "
            f"{duration:<9} {run['runId']}")
    active = active_only(runs)
    if not active:
        say("no active run")
    for run in active:
        detail = get_run(args.url, run["runId"])
        watch = Watch(total=total_jobs(args.url, run["runId"]))
        watch.update({**detail, "status": "STARTED"})
        finished = [step for step in detail.get("stepStats", []) if step["stepKey"].endswith("__finalize")
                    and step.get("status") == "SUCCESS"]
        current = [step["stepKey"] for step in detail.get("stepStats", []) if step.get("status") == "IN_PROGRESS"]
        say(f"active {run['runId']}: {len(watch.seen)}/{watch.total or '?'} jobs started, {len(finished)} finished; "
            f"current steps: {', '.join(current[:8]) or '-'}")
    return OK


def resolve_runs(url: str, identifier: str) -> list[dict]:
    """Dagster runs for a Dagster uuid or an application run id; raises NOT_FOUND when nothing matches."""
    if DAGSTER_RUN_ID.fullmatch(identifier):
        return [get_run(url, identifier)]
    if APP_RUN_ID.fullmatch(identifier):
        matches = [run for run in list_runs(url, 1000) if tag_map(run).get("appsec/application_run_id") == identifier]
        if matches:
            return matches
        hint = (" (runs/ has it, but no Dagster run carries that tag; a local-CLI run cannot be stopped here)"
                if (ROOT / "runs" / identifier).is_dir() else "")
        raise OpsError(f"no Dagster run belongs to application run {identifier}{hint}", NOT_FOUND)
    raise OpsError(f"{identifier!r} is neither a Dagster run id (uuid) nor an application run id like 2026-10-21-0007", USAGE)


def terminate(args: argparse.Namespace, runs: list[dict], reason: str) -> int:
    policy = "MARK_AS_CANCELED_IMMEDIATELY" if args.now else "SAFE_TERMINATE"
    say(f"policy {policy}" + (" (marks runs canceled at once; their containers may keep running)" if args.now else
                              " (asks the run to stop and waits)"))
    command = [sys.executable, str(BIN / "recover_runs.py"), "--url", args.url, "--reason", reason, "--policy", policy]
    for run in runs:
        command += ["--run-id", run["runId"]]
    say("+ " + shlex.join(command))
    if args.dry_run:
        say("dry run: nothing terminated")
        return OK
    return subprocess.run(command, cwd=ROOT, check=False).returncode


def describe(run: dict) -> str:
    return (f"{run['runId']} {run['status']} {run['pipelineName']} "
            f"app={tag_map(run).get('appsec/application_run_id', 'unallocated')} started {clock(run.get('startTime'))}")


def cmd_review_stop(args: argparse.Namespace) -> int:
    active = active_only(list_runs(args.url))
    if not active:
        say("no non-terminal Dagster run; nothing to stop")
        return OK
    say(f"{len(active)} non-terminal run(s):")
    for run in active:
        say(f"  {describe(run)}")
    if len(active) > 1 and not args.yes:
        raise OpsError(f"{len(active)} runs would be ended; add --yes to confirm (or use review-stop-id for one)", REFUSED)
    return terminate(args, active, args.reason or f"operator review-stop {datetime.now().isoformat(timespec='seconds')}")


def cmd_review_stop_id(args: argparse.Namespace) -> int:
    matches = resolve_runs(args.url, args.id)
    active = active_only(matches)
    if not active:
        raise OpsError(f"{args.id} is already terminal ({', '.join(sorted({run['status'] for run in matches}))}); nothing to stop",
                       REFUSED)
    say(f"{args.id} selects {len(active)} non-terminal run(s):")
    for run in active:
        say(f"  {describe(run)}")
    if len(active) > 1 and not args.yes:
        raise OpsError(f"{len(active)} Dagster runs share application run {args.id}; add --yes to end all of them", REFUSED)
    return terminate(args, active, args.reason or f"operator review-stop-id {args.id}")


# -- command line ---------------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ops.py", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)

    def add(name: str, handler, summary: str, *, dry_run: bool = False, url: bool = True, force: bool = False):
        sub = commands.add_parser(name, help=summary, description=summary, prog=f"scripts/{name}.sh",
                                  epilog=f"PowerShell twin: scripts/{name}.ps1 (same options, -PascalCase; -Wsl runs it in WSL).")
        sub.set_defaults(handler=handler)
        if dry_run:
            sub.add_argument("--dry-run", action="store_true", help="print what would happen; change nothing")
        if url:
            sub.add_argument("--url", default=DEFAULT_URL, help="Dagster GraphQL endpoint (default %(default)s)")
        if force:
            sub.add_argument("--force", action="store_true", help="proceed although a run is active")
        return sub

    start = add("stack-start", cmd_stack_start, "Start (and if needed build) the Dagster stack, then check it.",
                dry_run=True, force=True)
    start.add_argument("--build", action="store_true", help="rebuild the image first")
    start.add_argument("--no-probe", action="store_true", help="skip the one-word model connectivity probe")
    add_deploy_options(start)
    restart = add("stack-restart", cmd_stack_restart, "Stop and start the stack (volumes kept).", dry_run=True, force=True)
    restart.add_argument("--no-probe", action="store_true", help="skip the model connectivity probe")
    restart.add_argument("--code-location-only", action="store_true", help="recreate only the code-location container")
    add_deploy_options(restart)
    rebuild = add("stack-rebuild", cmd_stack_rebuild, "Build the image and recreate the stack with the overlay.",
                  dry_run=True, force=True)
    rebuild.add_argument("--no-probe", action="store_true", help="skip the model connectivity probe")
    add_deploy_options(rebuild)
    stop = add("stack-stop", cmd_stack_stop, "Stop the containers; volumes are kept.", dry_run=True, force=True)
    stop.add_argument("--purge-volumes", action="store_true", help="also remove the containers and the Postgres/Dagster volumes")
    stop.add_argument("--yes", action="store_true", help="confirm --purge-volumes")
    add("stack-status", cmd_stack_status, "One-screen status of the stack, its runs and disk.")
    logs = add("stack-logs", cmd_stack_logs, "Show container logs.", url=False)
    logs.add_argument("service", nargs="?", choices=SERVICES, help="one service (default: all)")
    logs.add_argument("--tail", type=int, default=100, help="lines per service (default %(default)s)")
    logs.add_argument("--follow", action="store_true", help="stream new lines (needs a service)")

    review = add("review-start", cmd_review_start, f"Launch {JOB_NAME} on the target the stack is built for.",
                 dry_run=True, force=True)
    add_deploy_options(review)
    review.add_argument("--run-id", help="resume this existing application run (adds the appsec/application_run_id tag)")
    review.add_argument("--id-wait", type=float, default=60, help="seconds to wait for the application run id (default %(default)s)")
    watch = add("review-watch", cmd_review_watch, "Print one line per newly started job and the final status.")
    watch.add_argument("--run", help="Dagster run id or application run id (default: the active run)")
    watch.add_argument("--once", action="store_true", help="print a snapshot and exit")
    watch.add_argument("--interval", type=float, default=10, help="poll seconds (default %(default)s)")
    status = add("review-status", cmd_review_status, "List recent runs and the active run's current steps.")
    status.add_argument("--limit", type=int, default=10, help="runs to list (default %(default)s)")
    for name, handler, summary in (("review-stop", cmd_review_stop, "End the current review (every non-terminal run)."),
                                   ("review-stop-id", cmd_review_stop_id, "End one review by Dagster or application run id.")):
        sub = add(name, handler, summary, dry_run=True)
        sub.add_argument("--now", action="store_true", help="MARK_AS_CANCELED_IMMEDIATELY instead of SAFE_TERMINATE")
        sub.add_argument("--yes", action="store_true", help="confirm ending more than one run")
        sub.add_argument("--reason", help="recorded in runs/metadata/dagster-recovery evidence")
        if name == "review-stop-id":
            sub.add_argument("id", help="Dagster run id (uuid) or application run id (YYYY-MM-DD-NNNN)")
    import ops_clean
    import ops_tests
    ops_clean.register(commands, add, ROOT)
    ops_tests.register(commands, add, ROOT)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    extra: list[str] = []
    if "--" in argv:
        split = argv.index("--")
        argv, extra = argv[:split], argv[split + 1:]
    args = build_parser().parse_args(argv)
    if extra:
        if args.command != "run-tests":
            print("error: arguments after -- are only accepted by run-tests", file=sys.stderr, flush=True)
            return USAGE
        args.extra = extra
    try:
        try:
            reject_native_environment()
        except RuntimeError as error:
            raise OpsError(str(error), REFUSED) from error
        return args.handler(args)
    except OpsError as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return error.code
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
