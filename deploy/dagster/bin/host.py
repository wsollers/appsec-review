"""Keep local Dagster deployments bound to one native host workspace."""

from __future__ import annotations
import os
from pathlib import Path
import subprocess


PROJECT_PREFIX = "appsec-review-dagster"
PLATFORMS = {"windows", "wsl", "linux"}
COPILOT_PROFILES = {"copilot-dev", "copilot-prod"}
# Compose launches the application services only by this exact, host-verified image ID.
IMAGE_VARIABLE = "APPSEC_REVIEW_DAGSTER_IMAGE"
# Fills the variable for Compose actions that never create containers (config, ps, logs, stop).
UNVERIFIED_IMAGE = "sha256:" + "0" * 64


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


def compose_environment(environment: Path, environ: dict[str, str] | None = None) -> dict[str, str]:
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


def reject_other_deployments(platform: str) -> None:
    result = subprocess.run(["docker", "ps", "--format", '{{.Label "com.docker.compose.project"}}'],
                            text=True, capture_output=True, check=True)
    own = project_name(platform)
    active = sorted({line.strip() for line in result.stdout.splitlines()
                     if line.strip() == PROJECT_PREFIX or line.strip().startswith(f"{PROJECT_PREFIX}-")}
                    - {own})
    if active:
        raise RuntimeError(f"stop the other appsec-review deployment first: {', '.join(active)}")
