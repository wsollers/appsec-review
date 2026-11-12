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

from host import (IMAGE_VARIABLE, actual_platform, dagster_url, deployment_profile, image_tag as host_image_tag, project_name,
                  provider_overlay, read_environment, reject_native_environment)
from image_signing import IMAGE_ID


DEPLOYMENT = Path(__file__).resolve().parents[1]
ROOT = DEPLOYMENT.parents[1]
BIN = Path(__file__).resolve().parent
URL_VARIABLE = "APPSEC_DAGSTER_URL"
SERVICES = ("postgres", "code-location", "daemon", "webserver")
# Reported but never required: reviews run uncached (fail-open) when the result cache is down.
OPTIONAL_SERVICES = ("result-cache",)
ALL_SERVICES = SERVICES + OPTIONAL_SERVICES
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
PROFILES = ("dev", "prod", "copilot-dev", "copilot-prod")
PROFILE_TAG = "appsec/profile"
OVERLAY_TAG = "appsec/overlay"
COMPILER_TARGET_TAG = "appsec/compiler_target"
NO_OVERLAY = "none"
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
    return sorted(containers, key=lambda item: (ALL_SERVICES.index(item.service) if item.service in ALL_SERVICES
                                                else 99))


def by_service(containers: list[Container]) -> dict[str, Container]:
    """One container per service; a running one wins over a stopped leftover of the same service."""
    chosen: dict[str, Container] = {}
    for item in containers:
        current = chosen.get(item.service)
        if current is None or (item.state == "running" and current.state != "running"):
            chosen[item.service] = item
    return chosen


def overlay_name(profile: str = "dev") -> str:
    return provider_overlay(actual_platform(), profile)


def image_tag(profile: str = "dev") -> str:
    return host_image_tag(actual_platform(), profile)


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


def guard_active_runs(url: str, containers: list[Container], force: bool, action: str) -> list[dict]:
    """Refuse to disturb a non-terminal run (multi-session-coordination: do not move what others use).

    Returns the non-terminal runs that ``--force`` let through (empty when none or unverifiable).
    """
    if not stack_running(containers):
        return []
    try:
        active = active_only(list_runs(url))
    except OpsError as error:
        if force:
            say(f"warning: cannot verify active runs ({error}); continuing because of --force")
            return []
        raise OpsError(f"refusing to {action}: cannot verify that no run is active ({error}). "
                       "Use --force only if you know nothing is running.", REFUSED) from error
    if not active:
        return []
    listing = "; ".join(f"{run['runId']} {run['status']} {run['pipelineName']} "
                        f"app={tag_map(run).get('appsec/application_run_id', 'unallocated')}" for run in active)
    if not force:
        raise OpsError(f"refusing to {action}: {len(active)} non-terminal Dagster run(s): {listing}. "
                       "Wait for them (review-watch), end them (review-stop), or use --force.", REFUSED)
    say(f"warning: {action} with --force while {len(active)} run(s) are active: {listing}")
    return active


# -- lifecycle ------------------------------------------------------------------------------------
def lifecycle(action: str, settings: dict[str, str], dry_run: bool) -> int:
    argv = [sys.executable, str(BIN / "lifecycle.py"), action]
    shown = " ".join(f"{key}={shlex.quote(value)}" for key, value in settings.items())
    say(f"+ {(shown + ' ') if shown else ''}{shlex.join(argv)}")
    if dry_run:
        return OK
    returncode = subprocess.run(argv, cwd=ROOT, env={**os.environ, **settings}, check=False).returncode
    if returncode == REFUSED and action in {"start", "reload"}:
        raise OpsError(f"lifecycle {action} refused: the image signature did not verify on this host "
                       "(scripts/stack-rebuild signs a fresh build with the operator key)", REFUSED)
    return returncode


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
    silently reverts a ``--target``/``--overlay``/``--recording`` choice. An explicit empty value is a
    choice too (``--overlay none`` exports ``APPSEC_REVIEW_CONFIG_OVERLAY=``) and is carried as empty:
    dropping it would let a stale ``.env`` value back in on the next restart (HAL5000, 2026-11-10: a
    reload rebound the code location to an old capacity overlay, and the open run refused it).
    Returns (settings, changes_running).
    """
    current = by_service(containers).get("code-location")
    carried = dict(current.settings) if current else {}
    changes = bool(current) and any(running_value(current, key) != value for key, value in requested.items())
    return {**carried, **requested}, changes


def add_deploy_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target", help="review target: a name under targets/ or a container path")
    parser.add_argument("--overlay", help="capacity overlay file under test/acceptance, or 'none'")
    parser.add_argument("--recording", choices=("record", "replay", "off"), help="model recording mode")
    parser.add_argument("--profile", choices=("dev", "prod", "copilot-dev", "copilot-prod"),
                        help="runtime profile (Copilot profiles use a separate login; prod profiles use production limits)")


def add_review_options(parser: argparse.ArgumentParser) -> None:
    fixed = "must equal the running code-location's value (fixed at creation; change it with stack-restart)"
    parser.add_argument("--target", help=f"review target: a name under targets/ or a container path; {fixed}")
    parser.add_argument("--recording", choices=("record", "replay", "off"), help=f"model recording mode; {fixed}")
    parser.add_argument("--profile", choices=PROFILES,
                        help="runtime profile for this run only (default: a resumed run's recorded profile, else the "
                             "container's); must keep the container's provider: dev/prod or copilot-dev/copilot-prod")
    parser.add_argument("--overlay", help="capacity overlay under test/acceptance for this run only, or 'none' "
                                          "(default: a resumed run's recorded overlay, else the container's)")
    parser.add_argument("--compiler-target", choices=("clang", "msvc"),
                        help="debug-symbol compiler family (default: resumed run's recorded choice, else clang)")


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
    for name in OPTIONAL_SERVICES:
        item = services.get(name)
        if item is None:
            say(f"  {name:<14} MISSING (optional: reviews run uncached)")
        elif not item.healthy:
            say(f"  {name:<14} {item.state} ({item.health}) (optional: reviews run uncached)")
        else:
            say(f"  {name:<14} {item.state} ({item.health})")
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


def probe_model(containers: list[Container], timeout: float = 180, profile: str | None = None) -> bool:
    return model_probe_failure(containers, timeout, profile) is None


def model_probe_failure(containers: list[Container], timeout: float = 180, profile: str | None = None) -> str | None:
    """Run the one bounded model probe; ``None`` when the model answered, else the printed failure class.

    ``profile`` is the run's selected profile (default: the container's); it picks the provider's probe.
    The returned text is what the probe line shows: a fixed class, or tool output through ``redact``.
    No credential is read: the probe runs the provider's own client inside the code-location container.
    """
    code = by_service(containers).get("code-location")
    if code is None or code.state != "running":
        say("  model probe    skipped: code-location is not running")
        return "code-location is not running"
    if (profile or running_value(code, PROFILE_VARIABLE)) in {"copilot-dev", "copilot-prod"}:
        result = docker("exec", code.id, "python", "-c",
                        "from appsec_review.inference.copilot_sdk import verify; verify()", timeout=timeout)
        if result.returncode == 0:
            say("  model catalog  ok (dedicated Copilot login; configured models enabled)")
            return None
        reason = redact(result.stderr or result.stdout)
        say(f"  model catalog  FAILED: {reason}")
        return f"Copilot login or model catalog check failed: {reason}"
    try:
        result = docker("exec", code.id, "claude", "-p", "Reply with the single word: ok", timeout=timeout)
    except OpsError as error:
        say(f"  model probe    FAILED: {error}")
        return str(error)
    output = (result.stdout or "") + " " + (result.stderr or "")
    if result.returncode == 0 and (result.stdout or "").strip():
        say(f"  model probe    ok (replied {redact(result.stdout, 40)!r})")
        return None
    if EXPIRED_TOKEN.search(output):
        say("  model probe    FAILED: the Claude OAuth token looks expired or missing")
        say(f"                 fix: {refresh_advice()}")
        return "the Claude OAuth token looks expired or missing"
    reason = redact(output)
    say(f"  model probe    FAILED (exit {result.returncode}): {reason}")
    return f"exit {result.returncode}: {reason}"


def require_model_login(containers: list[Container], profile: str) -> None:
    """Refuse a launch (exit 3) when the selected profile's model login does not answer the probe.

    A review that cannot reach its model fails at its first job, after a run, a submission intent and a
    failed attempt exist; this finds it while nothing has been recorded.
    """
    say("model login:")
    try:
        reason = model_probe_failure(containers, profile=profile)
    except OpsError as error:
        reason = str(error)
        say(f"  model probe    FAILED: {reason}")
    if reason is None:
        return
    remedy = ("sign in the dedicated Copilot account (docs/operations/model-profiles.md, 'Copilot with a separate "
              "GitHub identity')" if provider_family(profile) == "copilot" else refresh_advice())
    raise OpsError(f"refusing to start a review: the model login for profile {profile} did not answer the probe "
                   f"({reason}). No submission intent was recorded and nothing was launched. Fix: {remedy}. "
                   "Then start the review again, or pass --no-probe to launch without this check.", REFUSED)


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
    recorded = read_environment(DEPLOYMENT / ".env")
    pinned = IMAGE_VARIABLE in os.environ or IMAGE_VARIABLE in recorded
    image_missing = (not pinned and not build
                     and docker("image", "inspect", image_tag(profile), "--format", "{{.Id}}").returncode != 0)
    if build or image_missing:
        reason = "--build" if build else f"image {image_tag(profile)} is missing"
        say(f"building, signing and verifying the image ({reason})")
        if lifecycle("build", settings, args.dry_run) != 0:
            raise OpsError("lifecycle build failed")
        if not args.dry_run:
            # The explicit rebuild selects its result, not a stale image exported by the caller.
            built_image = read_environment(DEPLOYMENT / ".env").get(IMAGE_VARIABLE, "")
            if not IMAGE_ID.fullmatch(built_image):
                raise OpsError("lifecycle build did not record a verified image ID; refusing to start")
            settings[IMAGE_VARIABLE] = built_image
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


def provider_family(profile: str) -> str:
    return "copilot" if profile.startswith("copilot-") else "claude"


def recorded_selection(run_id: str) -> tuple[str | None, str | None]:
    """The profile and overlay a resumed application run was bound to (its configuration manifest)."""
    manifest = ROOT / "runs" / run_id / "data" / "configuration" / "manifest.json"
    try:
        selection = json.loads(manifest.read_text(encoding="utf-8")).get("selection") or {}
    except (OSError, ValueError):
        return None, None
    profile = selection.get("profile") if selection.get("profile") in PROFILES else None
    overlay = selection.get("overlay")
    if overlay is None:
        return profile, ""
    return profile, overlay if isinstance(overlay, str) and overlay.startswith(CONTAINER_ACCEPTANCE + "/") else None


def run_selection(args: argparse.Namespace, code: Container) -> tuple[tuple[str, str], tuple[str, str]]:
    """((profile, source), (container overlay path or '', source)) for this run.

    An explicit option wins, then a resumed run's recorded choice, then the container's setting.
    """
    recorded = recorded_selection(args.run_id) if args.run_id else (None, None)
    if args.profile is not None:
        profile = (args.profile, "requested")
    elif recorded[0]:
        profile = (recorded[0], f"recorded by run {args.run_id}")
    else:
        profile = (running_value(code, PROFILE_VARIABLE), "container default")
    if args.overlay is not None:
        overlay = (resolve_overlay(args.overlay), "requested")
    elif recorded[1] is not None:
        overlay = (recorded[1], f"recorded by run {args.run_id}")
    else:
        overlay = (code.settings.get(OVERLAY_VARIABLE, ""), "container default")
    container_profile = running_value(code, PROFILE_VARIABLE)
    if provider_family(profile[0]) != provider_family(container_profile):
        raise OpsError(f"profile {profile[0]} needs the {provider_family(profile[0])} provider, but the running "
                       f"code-location uses {container_profile} ({provider_family(container_profile)}); the provider "
                       f"image and login are fixed at creation: run scripts/stack-restart --profile {profile[0]} first.",
                       REFUSED)
    return profile, overlay


def run_compiler_target(args: argparse.Namespace) -> str:
    requested = getattr(args, "compiler_target", None)
    if requested is None and args.run_id:
        manifest = ROOT / "runs" / args.run_id / "data" / "configuration" / "manifest.json"
        if manifest.is_file():
            try:
                requested = json.loads(manifest.read_text(encoding="utf-8")).get(
                    "selection", {}).get("compiler_target", "clang")
            except (OSError, ValueError, AttributeError) as error:
                raise OpsError("cannot read the resumed run's compiler target", REFUSED) from error
    target = "clang" if requested is None else requested
    if target not in ("clang", "msvc"):
        raise OpsError("compiler_target must be clang or msvc", USAGE)
    if args.run_id and getattr(args, "compiler_target", None) is not None:
        recorded_args = argparse.Namespace(run_id=args.run_id, compiler_target=None)
        if target != run_compiler_target(recorded_args):
            raise OpsError("a resumed run cannot change its compiler target; start a fresh run", REFUSED)
    return target


def host_budget(profile: str, overlay: str):
    """Resolve the run's configuration on the host (container overlay path mapped to test/acceptance)."""
    from appsec_review.config import load_config

    host_overlay = (str(ROOT / "test" / "acceptance" / overlay.removeprefix(CONTAINER_ACCEPTANCE + "/"))
                    if overlay else "")
    try:
        return load_config(ROOT / "appsec-review.toml", profile=profile, overlay=host_overlay)
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise OpsError(f"cannot resolve the resource budget of profile {profile}, overlay {overlay or 'none'} "
                       f"to check it against active work: {error}", REFUSED) from error


def guard_resource_budget(active: list[dict], code: Container, profile: str, overlay: str) -> None:
    """Refuse (even with --force) a run whose resource budget differs from active runs or recorded leases.

    The host lease ledger admits every action against the smallest budget any recorded lease carries, so
    two budgets cannot coexist without one silently clamping the other.
    """
    ledger = ROOT / "runs" / "metadata" / "resource-admission" / "leases.json"
    leases: dict = {}
    if ledger.is_file():
        try:
            leases = json.loads(ledger.read_text(encoding="utf-8")).get("leases") or {}
        except (OSError, ValueError, AttributeError) as error:
            raise OpsError(f"cannot read the resource lease ledger {ledger}: {error}", REFUSED) from error
    default = (running_value(code, PROFILE_VARIABLE), code.settings.get(OVERLAY_VARIABLE, ""))
    others = []
    for run in active:
        tags = tag_map(run)
        theirs = (tags.get(PROFILE_TAG, default[0]),
                  "" if tags.get(OVERLAY_TAG) == NO_OVERLAY else tags.get(OVERLAY_TAG, default[1]))
        if theirs != (profile, overlay):  # the same selection resolves to the same budget
            others.append((run, theirs))
    if not others and not leases:
        return
    from appsec_review.runtime.resources import budget_conflicts

    mine = host_budget(profile, overlay)
    budget = mine.review_policy.resources
    conflicts = budget_conflicts(mine.runtime.metadata_dir, budget)
    for run, theirs in others:
        other = host_budget(*theirs).review_policy.resources
        if other != budget:
            conflicts.append(f"run {run['runId']} (profile {theirs[0]}, overlay {theirs[1] or 'none'}) "
                             f"budget {other.view()} != requested {budget.view()}")
    if conflicts:
        raise OpsError("refusing to start a review whose review_policy.resources budget differs from active work; "
                       "the shared lease ledger (runs/metadata/resource-admission/leases.json) admits against the "
                       "smallest recorded budget, so one review would be silently clamped. --force does not override "
                       "this: wait for that work to finish, or launch with a profile/overlay that has the same "
                       "budget. Conflicts: " + "; ".join(conflicts), REFUSED)


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
        if key in (PROFILE_VARIABLE, OVERLAY_VARIABLE):
            continue  # chosen per run below
        actual = running_value(code, key)
        if actual != wanted:
            flag = {TARGET_VARIABLE: "--target", RECORDING_VARIABLE: "--recording"}[key]
            raise OpsError(f"the running code-location has {key}={actual or '(unset)'}, not {wanted or '(unset)'}. "
                           f"The container fixes it at creation: run scripts/stack-restart {flag} <value> first.", REFUSED)
    if args.run_id:
        if not APP_RUN_ID.fullmatch(args.run_id):
            raise OpsError(f"--run-id {args.run_id!r} is not an application run id like 2026-10-21-0007", USAGE)
        if not (ROOT / "runs" / args.run_id).is_dir():
            raise OpsError(f"no application run runs/{args.run_id} to resume", NOT_FOUND)
    (profile, profile_source), (overlay, overlay_source) = run_selection(args, code)
    compiler_target = run_compiler_target(args)
    active = guard_active_runs(args.url, containers, args.force, "start another review")
    guard_resource_budget(active, code, profile, overlay)
    configuration = ROOT / "appsec-review.toml"
    if configuration.is_file():
        import review_run  # the documented helper: the image pin preflight stepwise.py also runs
        try:
            review_run.verify_build_profile_images(review_run.effective_configuration(configuration))
        except (RuntimeError, ValueError, OSError) as error:
            raise OpsError(str(error), REFUSED) from error
    else:
        say("warning: appsec-review.toml not found; skipping the image pin preflight")
    import review_run

    dagster_run_id = getattr(args, "dagster_run_id", None) or str(uuid4())
    identity = review_run.submission_identity(
        ROOT, target=code.settings.get(TARGET_VARIABLE) or f"{CONTAINER_TARGETS}/appsec-multi-vuln",
        profile=profile, overlay=overlay,
        recording=code.settings.get(RECORDING_VARIABLE, ""), image_id=code.image_id,
        project=project, url=args.url, application_run_id=args.run_id,
        compiler_target=compiler_target)
    safety_policy = None
    if getattr(args, "stop_on_first_error", False):
        if args.run_id:
            raise OpsError("first-error mode requires a fresh review; recovery needs separate approval", REFUSED)
        from appsec_review.runtime import execution_safety
        identity["execution_safety"] = execution_safety.SCHEMA
        safety_policy = execution_safety.policy(dagster_run_id, identity)
    review_run.check_submission(ROOT, identity, dagster_run_id)
    tags = {"appsec/application_run_id": args.run_id} if args.run_id else {}
    tags["appsec/submission_identity"] = review_run.submission_identity_sha256(identity)
    tags[PROFILE_TAG] = profile
    tags[OVERLAY_TAG] = overlay or NO_OVERLAY
    tags[COMPILER_TARGET_TAG] = compiler_target
    if safety_policy is not None:
        tags["appsec/safety_identity"] = execution_safety.identity(safety_policy)
        tags["dagster/max_retries"] = "0"
    command = ["exec", webserver.id, "dagster", "job", "launch", "-w",
               "/opt/dagster/home/workspace.yaml", "-l", "appsec_review", "-j", JOB_NAME, "--run-id", dagster_run_id]
    command += ["--tags", json.dumps(tags, sort_keys=True)]
    if safety_policy is not None:
        command += ["--config-json", json.dumps(
            {"execution": {"config": {"safety": safety_policy}}}, sort_keys=True)]
    say(f"profile:   {profile} ({profile_source})")
    if profile in {"prod", "copilot-prod"}:
        say(PROFILE_NOTICE.format(profile=profile))
    say(f"target:    {code.settings.get(TARGET_VARIABLE) or '(default)'}")
    say(f"overlay:   {overlay or '(none)'} ({overlay_source})")
    say(f"compiler:  {compiler_target}")
    say(f"recording: {code.settings.get(RECORDING_VARIABLE) or 'off'}")
    say("+ docker " + shlex.join(command))
    probe = not getattr(args, "no_probe", False)
    if args.dry_run:
        if probe:
            say("model login: not probed in a dry run (the launch probes it first; --no-probe skips that)")
        say("dry run: nothing launched")
        return OK
    if probe:
        # After every other guard, before any intent or Dagster call: an unanswered probe leaves nothing behind.
        require_model_login(containers, profile)
    else:
        say("model login: not probed (--no-probe)")
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


# -- review recover -------------------------------------------------------------------------------
# One guarded command over the existing recovery steps (docs/operations/recovery-repair.md). It adds no
# authority: every step is the existing check, run in the documented order, and the first refusal ends
# the sequence with that step's own reason. Nothing is retried, skipped or forced past a refusal.
CONTAINER_RUNS = "/opt/app/runs"
REPAIR_PLAN_SCHEMA = "appsec-review/repair-plan/1"
DISPATCH_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
PLAN_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def recorded_dispatches(url: str, run_id: str) -> list[dict]:
    """Every Dagster dispatch recorded for one application run: its tagged runs and its attempt claims."""
    try:
        runs = {run["runId"]: run for run in list_runs(url, 1000)
                if tag_map(run).get("appsec/application_run_id") == run_id}
    except OpsError as error:
        raise OpsError(f"refusing to recover {run_id}: its dispatches cannot be read from Dagster ({error})",
                       REFUSED) from error
    for path in sorted((ROOT / "runs" / run_id / "data" / "jobs").glob("*/attempts/*/claim.json")):
        shown = path.relative_to(ROOT).as_posix()
        try:
            orchestration = json.loads(path.read_text(encoding="utf-8")).get("orchestration") or {}
        except (OSError, ValueError, AttributeError) as error:
            raise OpsError(f"refusing to recover {run_id}: attempt claim {shown} is unreadable ({error})",
                           REFUSED) from error
        dispatch = orchestration.get("run_id")
        if orchestration.get("system") != "dagster" or dispatch in runs:
            continue
        if not isinstance(dispatch, str) or not DISPATCH_ID.fullmatch(dispatch):
            raise OpsError(f"refusing to recover {run_id}: attempt claim {shown} names no usable Dagster dispatch",
                           REFUSED)
        try:
            runs[dispatch] = get_run(url, dispatch)
        except OpsError as error:
            raise OpsError(f"refusing to recover {run_id}: dispatch {dispatch} recorded by {shown} cannot be read "
                           f"from Dagster ({error}); its state is unknown", REFUSED) from error
    return sorted(runs.values(), key=lambda run: (run.get("startTime") or 0, run["runId"]))


def unreconciled_submission(run_id: str, dispatch_ids: list[str]) -> dict | None:
    """This run's ``SUBMITTED`` intent, ``None`` when no intent blocks a launch; any other occupant refuses."""
    import review_run

    try:
        record = review_run.read_submission(ROOT)
    except (OSError, ValueError) as error:
        raise OpsError(f"the submission intent cannot be read ({error}); inspect "
                       f"{review_run.submission_directory(ROOT) / 'active.json'}", REFUSED) from error
    if record is None or record["state"] == "RECONCILED":
        return None
    uuid, state = record["dagster_run_id"], record["state"]
    manual = (f"python deploy/dagster/bin/review_run.py reconcile --run-id {uuid} "
              f"--url {record['identity'].get('url')}")
    if uuid not in dispatch_ids:
        raise OpsError(f"submission {uuid} remains {state} and is not a dispatch of {run_id}; an unreconciled "
                       f"submission blocks every launch. Inspect that exact run and reconcile it yourself once it is "
                       f"confirmed terminal ({manual}); review-recover reconciles only this run's own submission.",
                       REFUSED)
    if state != "SUBMITTED":
        raise OpsError(f"submission {uuid} of {run_id} is {state}: its launch response was lost, so whether Dagster "
                       f"accepted it is not established. Inspect that exact run and reconcile it yourself ({manual}); "
                       "review-recover reconciles only a SUBMITTED intent.", REFUSED)
    return record


def selection_environment(selection: tuple[str | None, str | None]) -> list[str]:
    """``docker exec -e`` options that give the container CLI the profile and overlay the run recorded."""
    profile, overlay = selection
    options = ["-e", f"{PROFILE_VARIABLE}={profile}"] if profile else []
    return options + (["-e", f"{OVERLAY_VARIABLE}={overlay}"] if overlay is not None else [])


def verify_dispatch_stops(code: Container, run_id: str, dispatch_ids: list[str]) -> None:
    """Worker-stop verification of every dispatch, by the probe ``stepwise.py recover`` sends to the container."""
    import stepwise_rewind
    from appsec_review.storage import FileLock, LockUnavailable

    run_root = ROOT / "runs" / run_id
    try:
        # The gates admission and worker registration use: no attempt may change while stops are verified.
        with FileLock(run_root / "data/resume.lock"), FileLock(run_root / "data/recovery/admission.lock"):
            result = docker("exec", code.id, "python", "-c", stepwise_rewind.RUNTIME_PROBE, run_id,
                            json.dumps(dispatch_ids), "verify-stops", timeout=300)
    except LockUnavailable as error:
        raise OpsError(f"stop verification refused: {error} (a worker or another operator command holds it)",
                       REFUSED) from error
    if result.returncode != 0:
        raise OpsError(f"stop verification refused (exit {result.returncode}): "
                       f"{redact(result.stderr or result.stdout, 800)}", REFUSED)
    try:
        runtime = json.loads(result.stdout)
        refusals, verified = list(runtime["refusals"]), set(runtime["verified_dispatches"])
        if runtime["run_id"] != run_id:
            raise ValueError("it belongs to another application run")
    except (ValueError, KeyError, TypeError) as error:
        raise OpsError(f"stop verification returned no usable result ({error}); nothing is verified", REFUSED) from error
    if refusals:
        raise OpsError("recovery requires verified stopped execution: " + "; ".join(str(item) for item in refusals)
                       + ". A failed step is not proof that a worker stopped.", REFUSED)
    unverified = sorted(set(dispatch_ids) - verified)
    if unverified:
        raise OpsError(f"stop verification did not cover dispatch(es) {', '.join(unverified)}", REFUSED)
    say(f"  verified stopped: {', '.join(sorted(verified))}")


def plan_summary(plan: dict) -> None:
    decisions = [item for item in plan.get("decisions") or [] if isinstance(item, dict)]
    reused = [item for item in decisions if item.get("action") == "REUSE"]
    rerun = [item for item in decisions if item.get("action") != "REUSE"]
    say(f"repair plan {plan['plan_sha256']}")
    say(f"  release:  {plan.get('release_sha256') or 'none'}")
    say(f"  reused ({len(reused)}): {', '.join(str(item.get('job_id')) for item in reused) or '-'}")
    say(f"  re-run ({len(rerun)}):" + ("" if rerun else " -"))
    for item in rerun:
        reasons = "; ".join(str(reason) for reason in item.get("reasons") or []) or "no reason recorded"
        say(f"    {item.get('job_id')}  {item.get('action')}  {reasons}")
    refusals = [str(reason) for reason in plan.get("refusals") or []]
    say(f"  refusals ({len(refusals)}):" + ("" if refusals else " none"))
    for reason in refusals:
        say(f"    {reason}")


def confirmed(question: str) -> bool:
    print(f"{question} [y/N] ", end="", flush=True)
    try:
        answer = sys.stdin.readline()
    except (OSError, ValueError):
        answer = ""
    say()
    return answer.strip().lower() in {"y", "yes"}


def fresh_start_command(selection: tuple[str | None, str | None]) -> str:
    profile, overlay = selection
    command = ["scripts/review-start.sh", *(["--profile", profile] if profile else [])]
    if overlay is not None:
        command += ["--overlay", overlay.removeprefix(CONTAINER_ACCEPTANCE + "/") or NO_OVERLAY]
    return shlex.join(command)


def cmd_review_recover(args: argparse.Namespace) -> int:
    run_id = args.run_id
    if not APP_RUN_ID.fullmatch(run_id):
        raise OpsError(f"{run_id!r} is not an application run id like 2026-10-21-0007", USAGE)
    run_root = ROOT / "runs" / run_id
    if not run_root.is_dir():
        raise OpsError(f"no application run runs/{run_id} to recover", NOT_FOUND)
    if (ROOT / "runs" / "metadata" / "stepwise" / run_id / "state.json").is_file():
        raise OpsError(f"{run_id} is a stepwise walk: recover it serially with "
                       f"deploy/dagster/bin/stepwise.py recover --app-run {run_id} "
                       "(a whole-graph resume would bypass its job-by-job acceptance)", REFUSED)
    project = deployment_project()
    containers = stack_containers(project)
    say(f"review-recover: application run {run_id}, project {project}" + (" (dry run)" if args.dry_run else ""))
    _webserver, code = webserver_and_code(containers)
    require_own_stack(containers)
    selection = recorded_selection(run_id)
    target = code.settings.get(TARGET_VARIABLE) or f"{CONTAINER_TARGETS}/appsec-multi-vuln"

    say("step 1/5: recorded Dagster dispatches (a non-terminal one refuses)")
    dispatches = recorded_dispatches(args.url, run_id)
    if not dispatches:
        raise OpsError(f"no Dagster dispatch is recorded for application run {run_id} (no tagged run, no Dagster "
                       "attempt claim); a run the local CLI started is resumed with `appsec-review resume`", NOT_FOUND)
    for run in dispatches:
        say(f"  {describe(run)}")
    running = active_only(dispatches)
    if running:
        raise OpsError(f"refusing to recover {run_id}: {len(running)} of its Dagster dispatch(es) are not terminal: "
                       + "; ".join(f"{run['runId']} {run['status']}" for run in running)
                       + f". Wait for them (review-watch) or end them (review-stop-id {run_id}). "
                       "--force does not override this.", REFUSED)
    guard_active_runs(args.url, containers, args.force, "recover a review")
    dispatch_ids = [run["runId"] for run in dispatches]

    say("step 2/5: submission intent")
    submission = unreconciled_submission(run_id, dispatch_ids)
    reconcile = ([sys.executable, str(BIN / "review_run.py"), "reconcile", "--run-id", submission["dagster_run_id"],
                  "--url", submission["identity"]["url"]] if submission else None)
    if submission is None:
        say("  no unreconciled submission blocks a launch")
    accepted = sorted(path.parent.name for path in (run_root / "data" / "jobs").glob("*/latest.json"))
    probe = ["exec", code.id, "python", "-c", "<stepwise_rewind.RUNTIME_PROBE>", run_id, json.dumps(dispatch_ids),
             "verify-stops"]
    repair = ["exec", *selection_environment(selection), code.id, "python", "-m", "appsec_review"]
    plan_command = [*repair, "plan-repair", "--run-id", run_id, "--target", target]
    plan_directory = ROOT / "runs" / "metadata" / "review-recover" / run_id
    resume = ["review-start", "--url", args.url, "--run-id", run_id, "--id-wait", str(args.id_wait),
              *(["--force"] if args.force else []), *(["--no-probe"] if args.no_probe else [])]
    resume_shown = "scripts/review-start.sh " + shlex.join(resume[1:])

    def nothing_accepted() -> int:
        say(f"no job of {run_id} has an accepted handoff: a repair would reuse nothing, so none is planned.")
        say("start a fresh review instead (not launched here; it runs every launch guard):")
        say(f"  {fresh_start_command(selection)}")
        return OK

    if args.dry_run:
        say("dry run: the steps that would run, in this order, each stopping the sequence when it refuses:")
        say("  2. " + ("+ " + shlex.join(reconcile) if reconcile else "(nothing to reconcile)"))
        if accepted:
            say("  3. + docker " + shlex.join(probe))
            say("  4. + docker " + shlex.join(plan_command) + f"  > {plan_directory.relative_to(ROOT).as_posix()}"
                "/repair-plan-<plan_sha256>.json, then print reused and re-run jobs and refusals")
            say("  5. one confirmation" + (" (pre-confirmed by --yes)" if args.yes else "") + ", then")
            say("     + docker " + shlex.join([*repair, "admit-repair", "--run-id", run_id, "--target", target, "--plan",
                                               f"{CONTAINER_RUNS}/metadata/review-recover/{run_id}/"
                                               "repair-plan-<plan_sha256>.json"]))
            say(f"     + {resume_shown}")
        else:
            nothing_accepted()
        say("dry run: nothing executed")
        return OK

    if submission:
        import review_run

        say("+ " + shlex.join(reconcile))
        try:
            review_run.reconcile_submission(submission["dagster_run_id"], submission["identity"]["url"])
        except (OSError, ValueError, RuntimeError) as error:
            raise OpsError(f"reconcile refused: {error}", REFUSED) from error
    if not accepted:
        return nothing_accepted()

    say("step 3/5: worker stop of every recorded dispatch")
    say("+ docker " + shlex.join(probe))
    verify_dispatch_stops(code, run_id, dispatch_ids)

    say("step 4/5: repair plan")
    say("+ docker " + shlex.join(plan_command))
    planned = docker(*plan_command, timeout=900)
    try:
        plan = json.loads(planned.stdout)
        if (planned.returncode not in {0, 2} or plan["schema"] != REPAIR_PLAN_SCHEMA or plan["run_id"] != run_id
                or not PLAN_SHA256.fullmatch(plan["plan_sha256"])):
            raise ValueError("not a repair plan for this run")
    except (ValueError, KeyError, TypeError) as error:
        raise OpsError(f"plan-repair refused (exit {planned.returncode}): "
                       f"{redact(planned.stderr or planned.stdout, 800) or error}", REFUSED) from error
    plan_file = plan_directory / f"repair-plan-{plan['plan_sha256']}.json"
    plan_directory.mkdir(parents=True, exist_ok=True)
    plan_file.write_text(planned.stdout, encoding="utf-8")  # exactly what plan-repair printed; admission rederives it
    plan_summary(plan)
    say(f"  plan file: {plan_file.relative_to(ROOT).as_posix()}")
    if planned.returncode != 0 or plan.get("admissible") is not True or plan.get("refusals"):
        raise OpsError("the repair plan is not admissible (its refusals are listed above); nothing was admitted or "
                       "resumed", REFUSED)

    say("step 5/5: admit exactly this plan, then resume")
    if args.yes:
        say("  confirmed by --yes")
    elif not confirmed(f"Admit repair plan {plan['plan_sha256'][:12]} and resume {run_id}?"):
        raise OpsError("declined: nothing was admitted and nothing was resumed (the plan file is kept for inspection)",
                       REFUSED)
    admit_command = [*repair, "admit-repair", "--run-id", run_id, "--target", target, "--plan",
                     f"{CONTAINER_RUNS}/{plan_file.relative_to(ROOT / 'runs').as_posix()}"]
    say("+ docker " + shlex.join(admit_command))
    admitted = docker(*admit_command, timeout=900)
    if admitted.returncode != 0:
        raise OpsError(f"admit-repair refused (exit {admitted.returncode}): "
                       f"{redact(admitted.stderr or admitted.stdout, 800)}; nothing was resumed", REFUSED)
    say(f"  admitted repair plan {plan['plan_sha256']}")
    say(f"+ {resume_shown}")
    return cmd_review_start(build_parser().parse_args(resume))


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
            sub.add_argument("--url", help=f"Dagster GraphQL endpoint (default: {URL_VARIABLE}, otherwise "
                             "http://127.0.0.1:<APPSEC_DAGSTER_WEB_PORT, default 3000>/graphql)")
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
    restart.add_argument("--code-location-only", action="store_true",
                         help="reload: verify the image and recreate the code-location, webserver and daemon "
                         "containers, keeping PostgreSQL running")
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
    logs.add_argument("service", nargs="?", choices=ALL_SERVICES, help="one service (default: all)")
    logs.add_argument("--tail", type=int, default=100, help="lines per service (default %(default)s)")
    logs.add_argument("--follow", action="store_true", help="stream new lines (needs a service)")

    review = add("review-start", cmd_review_start, f"Launch {JOB_NAME} on the target the stack is built for.",
                 dry_run=True, force=True)
    review.description = (
        f"Launch {JOB_NAME} on the target the stack is built for. --profile and --overlay choose this run's "
        "configuration (Dagster tags appsec/profile and appsec/overlay); the container's settings are the default. "
        "A run whose review_policy.resources budget differs from an active run or a recorded resource lease is "
        "refused, even with --force, because the shared lease ledger would clamp both to the smaller budget.")
    add_review_options(review)
    review.add_argument("--run-id", help="resume this existing application run (adds the appsec/application_run_id tag)")
    review.add_argument("--stop-on-first-error", action="store_true",
                        help="freeze the run-scoped no-retry safety policy; requires the matching deployed code")
    review.add_argument("--no-probe", action="store_true",
                        help="skip the model login probe that otherwise runs before the submission is recorded")
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
    recover = add("review-recover", cmd_review_recover,
                  "Recover one failed application run through the existing guarded steps, in order.",
                  dry_run=True, force=True)
    recover.description = (
        "Recover one failed application run. Runs the existing steps in their documented order and stops at the "
        "first refusal with that step's reason: (1) the run's recorded Dagster dispatches must all be terminal; "
        "(2) this run's SUBMITTED submission intent is reconciled; (3) worker stop is verified for every dispatch "
        "inside the code location; (4) plan-repair, then the plan summary (reused jobs, re-run jobs, refusals); "
        "(5) one confirmation, admit-repair with exactly that plan, then review-start --run-id. It adds no "
        "authority and overrides no check. --force only lets the launch proceed while another review is active; it "
        "never confirms, and never overrides this run's own non-terminal dispatch or any refusal.")
    recover.add_argument("run_id", metavar="RUN_ID", help="application run id (YYYY-MM-DD-NNNN)")
    recover.add_argument("--yes", action="store_true",
                         help="pre-confirm admission and resume (never implied by --force)")
    recover.add_argument("--no-probe", action="store_true", help="resume without the model login probe (see review-start)")
    recover.add_argument("--id-wait", type=float, default=60,
                         help="seconds the resume waits for the application run id (default %(default)s)")
    import ops_clean
    import ops_readiness
    import ops_tests
    ops_clean.register(commands, add, ROOT)
    ops_readiness.register(commands, add, ROOT)
    ops_tests.register(commands, add, ROOT)
    return parser


def default_url() -> str:
    """``APPSEC_DAGSTER_URL``, otherwise the GraphQL endpoint on the stack's configured web port."""
    return os.environ.get(URL_VARIABLE) or dagster_url("/graphql", DEPLOYMENT / ".env")


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
    if hasattr(args, "url") and not args.url:
        try:
            args.url = default_url()
        except RuntimeError as error:
            print(f"error: {error}", file=sys.stderr, flush=True)
            return USAGE
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
