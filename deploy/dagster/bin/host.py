"""Keep local Dagster deployments bound to one native host workspace."""

from __future__ import annotations
import argparse
from collections.abc import Mapping
import os
from pathlib import Path
import shutil
import subprocess
import sys


PROJECT_PREFIX = "appsec-review-dagster"
PLATFORMS = {"windows", "wsl", "linux"}
GITHUB_TOKEN = "GITHUB_TOKEN"
# Ambient overrides that would make `gh auth token` echo another identity instead of the stored login.
GH_OVERRIDES = ("GH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", GITHUB_TOKEN)


def compose_environment(environ: dict[str, str] | None = None) -> dict[str, str]:
    """Compose's environment, carrying GITHUB_TOKEN from this shell's `gh` login when it is unset.

    Whichever shell or agent creates the code-location, source-history enrichment gets the same
    login. An explicitly set GITHUB_TOKEN (even empty, to opt out) is used as is. The token is
    never printed.
    """
    environment = dict(os.environ if environ is None else environ)
    if GITHUB_TOKEN in environment:
        return environment
    gh = shutil.which("gh")
    token, reason = "", "gh is not installed"
    if gh is not None:
        lookup = {key: value for key, value in environment.items() if key not in GH_OVERRIDES}
        try:
            completed = subprocess.run([gh, "auth", "token", "--hostname", "github.com"], env=lookup,
                                       capture_output=True, text=True, timeout=30, check=False)
            token = completed.stdout.strip() if completed.returncode == 0 else ""
            reason = ("gh has no github.com login" if "unknown" not in completed.stderr
                      else "gh is too old for `gh auth token` (2.17 or later is required)")
        except (OSError, subprocess.TimeoutExpired):
            reason = "gh auth token did not complete"
    if token:
        environment[GITHUB_TOKEN] = token
        print("GITHUB_TOKEN: using this shell's gh login for source-history GitHub enrichment", file=sys.stderr)
    else:
        print(f"GITHUB_TOKEN: unset and {reason}; source-history GitHub enrichment will record "
              "github_credentials_missing", file=sys.stderr)
    return environment


COPILOT_PROFILES = {"copilot-dev", "copilot-prod"}
# Compose launches the application services only by this exact, host-verified image ID.
IMAGE_VARIABLE = "APPSEC_REVIEW_DAGSTER_IMAGE"
# Every Compose service that runs IMAGE_VARIABLE; a unit test keeps this equal to the compose files.
IMAGE_SERVICES = ("code-location", "webserver", "daemon")
# The in-container gate that verifies the running image before the code server starts; the service's
# command starts with it and the service receives IMAGE_VARIABLE (unit tests and smoke.py check both).
SELF_CHECK_SERVICE = "code-location"
SELF_CHECK_COMMAND = ("python", "-m", "appsec_review.signing.container_self_check", "--")
# Fills the variable for Compose actions that never create containers (config, ps, logs, stop).
UNVERIFIED_IMAGE = "sha256:" + "0" * 64
# The webserver's loopback host port; compose.yaml publishes ${APPSEC_DAGSTER_WEB_PORT:-3000}.
WEB_PORT_VARIABLE = "APPSEC_DAGSTER_WEB_PORT"
DEFAULT_WEB_PORT = 3000


def reject_native_environment() -> None:
    if any(name.startswith("APPSEC_NATIVE_") for name in os.environ):
        raise RuntimeError("Compose cannot execute native configuration; ambient engine fallback is prohibited")


def actual_platform() -> str:
    if os.name == "nt":
        return "windows"
    release = Path("/proc/sys/kernel/osrelease")
    if release.is_file() and "microsoft" in release.read_text(encoding="utf-8").lower():
        return "wsl"
    return "linux"


def project_name(platform: str) -> str:
    if platform not in PLATFORMS:
        raise ValueError(f"unknown deployment platform: {platform}")
    return f"{PROJECT_PREFIX}-{platform}"


def validate_workspace(repository: Path, platform: str) -> None:
    resolved = repository.resolve()
    if platform == "wsl" and not resolved.is_relative_to(Path.home().resolve()):
        raise RuntimeError("WSL deployment must use a checkout under the WSL home directory")
    if platform == "windows" and str(resolved).lower().startswith("\\\\wsl"):
        raise RuntimeError("Windows deployment must use a native Windows checkout")


def read_environment(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise RuntimeError("run deploy/dagster/bin/bootstrap.py first")
    return dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines()
                if "=" in line and not line.lstrip().startswith("#"))


def deployment_profile(environment: Path) -> str:
    values = read_environment(environment) if environment.is_file() else {}
    profile = os.environ.get("APPSEC_REVIEW_PROFILE") or values.get("APPSEC_REVIEW_PROFILE") or "dev"
    if profile not in {"dev", "prod", "copilot-dev", "copilot-prod"}:
        raise RuntimeError(f"unknown runtime profile: {profile}")
    return profile


def web_port(environment: Path | None = None, environ: Mapping[str, str] | None = None) -> int:
    """The webserver host port with Compose's precedence: process environment, then ``.env``, then 3000."""
    values = os.environ if environ is None else environ
    raw = values.get(WEB_PORT_VARIABLE)
    if not raw and environment is not None and environment.is_file():
        raw = read_environment(environment).get(WEB_PORT_VARIABLE)
    text = (raw or "").strip()
    if not text:
        return DEFAULT_WEB_PORT
    if not (text.isascii() and text.isdigit()) or not 1 <= int(text) <= 65535:
        raise RuntimeError(f"{WEB_PORT_VARIABLE} must be an integer from 1 to 65535, not {raw!r}")
    return int(text)


def dagster_url(path: str = "", environment: Path | None = None, environ: Mapping[str, str] | None = None) -> str:
    """The local Dagster webserver URL on its configured host port, e.g. ``dagster_url("/graphql")``."""
    return f"http://127.0.0.1:{web_port(environment, environ)}{path}"


def url_or_default(parser: argparse.ArgumentParser, url: str | None, path: str = "") -> str:
    """An explicit ``--url``, otherwise this deployment's webserver URL; an invalid port is a usage error."""
    if url:
        return url
    try:
        return dagster_url(path, Path(__file__).resolve().parents[1] / ".env")
    except RuntimeError as error:
        parser.error(str(error))


def provider_overlay(platform: str, profile: str) -> str:
    if profile in COPILOT_PROFILES:
        return "compose.copilot.yaml"
    return "compose.windows.yaml" if platform == "windows" else "compose.claude.yaml"


def image_target(platform: str, profile: str) -> str:
    """The final, signature-enforcing Dockerfile stage for this host and profile."""
    if profile in COPILOT_PROFILES:
        return "runtime-copilot"
    return "runtime-windows" if platform == "windows" else "runtime"


def image_tag(platform: str, profile: str) -> str:
    """The local build tag; Compose never launches it, only the verified ID it resolves to."""
    suffix = "-copilot" if profile in COPILOT_PROFILES else ""
    return f"appsec-review-dagster:{platform}{suffix}"


def non_launching_environment(environment: Path, environ: dict[str, str] | None = None) -> dict[str, str]:
    """Process environment for a Compose action that never creates containers.

    The recorded verified image (process environment, then ``.env``) is kept; otherwise an unlaunchable
    placeholder satisfies interpolation. Only ``lifecycle.py start``/``reload`` may set a launchable ID.
    """
    values = dict(os.environ if environ is None else environ)
    recorded = read_environment(environment).get(IMAGE_VARIABLE) if environment.is_file() else None
    if not values.get(IMAGE_VARIABLE) and not recorded:
        values[IMAGE_VARIABLE] = UNVERIFIED_IMAGE
    return values


def validate_deployment(repository: Path, environment: Path, platform: str) -> None:
    if platform != actual_platform():
        raise RuntimeError(f"requested {platform}, but this host is {actual_platform()}")
    validate_workspace(repository, platform)
    values = read_environment(environment)
    if values.get("APPSEC_DEPLOYMENT_PLATFORM") != platform or values.get("APPSEC_COMPOSE_PROJECT") != project_name(platform):
        raise RuntimeError("deployment identity does not match this host; run bootstrap.py here")
    web_port(environment)


def reject_other_deployments(platform: str) -> None:
    result = subprocess.run(["docker", "ps", "--format", '{{.Label "com.docker.compose.project"}}'],
                            text=True, capture_output=True, check=True)
    own = project_name(platform)
    active = sorted({line.strip() for line in result.stdout.splitlines()
                     if line.strip() == PROJECT_PREFIX or line.strip().startswith(f"{PROJECT_PREFIX}-")}
                    - {own})
    if active:
        raise RuntimeError(f"stop the other appsec-review deployment first: {', '.join(active)}")
