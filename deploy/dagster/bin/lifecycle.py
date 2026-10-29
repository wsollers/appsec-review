"""Run the bounded lifecycle commands for the local Dagster Compose project.

``build`` signs ``src/appsec_review`` into the module envelope, builds the final image stage, signs the
image ID with the operator key and verifies it. ``start`` and ``reload`` verify the image on the host
first and refuse (exit 3) without touching Compose unless a trusted key signed it; Compose then
launches that exact image ID, which is recorded in ``.env`` for later ``exec`` commands. ``reload``
recreates every service in ``IMAGE_SERVICES`` and leaves PostgreSQL running.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Mapping

from host import (IMAGE_SERVICES, IMAGE_VARIABLE, actual_platform, compose_environment, deployment_profile,
                  image_tag, image_target, provider_overlay, read_environment, reject_native_environment,
                  reject_other_deployments, validate_deployment)
from image_signing import Runner, SigningError, SigningSettings, sign_image, sign_modules, verify_image


deployment = Path(__file__).resolve().parents[1]
repository = deployment.parents[1]
environment_file = deployment / ".env"
OK, FAILED, REFUSED = 0, 1, 3
commands = {
    "config": ["config"],
    "build": [],
    "start": ["up", "-d", "--wait"],
    # Recreates every service that runs the image, so none keeps an older one; PostgreSQL is untouched.
    "reload": ["up", "-d", "--no-deps", "--force-recreate", "--wait", *IMAGE_SERVICES],
    "status": ["ps"],
    "logs": ["logs", "--tail", "100"],
    "stop": ["stop"],
}
LAUNCHING = {"start", "reload"}


def compose_base(platform: str, profile: str) -> list[str]:
    return ["docker", "compose", "--env-file", str(environment_file), "-f", str(deployment / "compose.yaml"),
            "-f", str(deployment / provider_overlay(platform, profile))]


def signing_settings(environ: Mapping[str, str]) -> SigningSettings:
    recorded = read_environment(environment_file) if environment_file.is_file() else {}
    return SigningSettings.load({**recorded, **environ})


def build(platform: str, profile: str, environ: Mapping[str, str], *, runner: Runner = subprocess.run) -> str:
    """Sign modules, build the final stage, sign the image and verify it; return the verified ID."""
    settings = signing_settings(environ)
    envelope = sign_modules(settings, repository, runner=runner)
    print(f"signed and verified the module envelope {envelope}", flush=True)
    tag, target = image_tag(platform, profile), image_target(platform, profile)
    command = ["docker", "build", "--file", str(deployment / "Dockerfile"), "--target", target,
               "--tag", tag, str(repository)]
    if runner(command, cwd=repository, env={**environ, "DOCKER_BUILDKIT": "1"}, check=False).returncode != 0:
        raise SigningError(f"docker build of {target} failed")
    signed = sign_image(settings, repository, tag, runner=runner)
    verified = verify_image(settings, repository, signed, runner=runner)
    print(f"built, signed and verified {tag} as {verified}", flush=True)
    return verified


def verified_image(platform: str, profile: str, environ: Mapping[str, str], *,
                   runner: Runner = subprocess.run) -> str:
    """Verify ``APPSEC_REVIEW_DAGSTER_IMAGE`` from the process environment, else this host's build tag."""
    reference = environ.get(IMAGE_VARIABLE) or image_tag(platform, profile)
    return verify_image(signing_settings(environ), repository, reference, runner=runner)


def record_image(path: Path, image_id: str) -> None:
    """Atomically set the verified image ID in ``.env``, preserving every other line."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    kept = [line for line in lines if line.split("=", 1)[0].strip() != IMAGE_VARIABLE]
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=".env-",
                                     delete=False) as stream:
        temporary = Path(stream.name)
        stream.write("\n".join(kept + [f"{IMAGE_VARIABLE}={image_id}"]) + "\n")
    try:
        temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def run_action(action: str, platform: str, profile: str, environ: Mapping[str, str] | None = None, *,
               runner: Runner = subprocess.run) -> int:
    environ = dict(os.environ if environ is None else environ)
    if action == "build":
        try:
            build(platform, profile, environ, runner=runner)
        except SigningError as error:
            print(f"lifecycle build failed: {error}", file=sys.stderr, flush=True)
            return FAILED
        return OK
    if action in LAUNCHING:
        try:
            settings = signing_settings(environ)
            image_id = verified_image(platform, profile, environ, runner=runner)
        except SigningError as error:
            print(f"refusing to {action}: the image signature did not verify on this host: {error}",
                  file=sys.stderr, flush=True)
            return REFUSED
        record_image(environment_file, image_id)
        print(f"verified {image_id}; Compose launches exactly this image", flush=True)
        # Compose mounts exactly the trust anchors and envelopes the host verification used.
        environment = {**environ, **settings.compose_environment(), IMAGE_VARIABLE: image_id}
    else:
        environment = compose_environment(environment_file, environ)
    return runner(compose_base(platform, profile) + commands[action], cwd=repository, env=environment,
                  check=False).returncode


def main(argv: list[str] | None = None) -> int:
    reject_native_environment()
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=commands)
    args = parser.parse_args(argv)
    platform = actual_platform()
    validate_deployment(repository, environment_file, platform)
    if args.action in {"build", "start", "reload"}:
        reject_other_deployments(platform)
    return run_action(args.action, platform, deployment_profile(environment_file))


if __name__ == "__main__":
    sys.exit(main())
