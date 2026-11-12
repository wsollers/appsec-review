"""Run the bounded lifecycle commands for the local Dagster Compose project.

``build`` builds the tooling-only final image stage, signs and verifies its ID, then records it in
``.env``. ``start`` and ``reload`` verify the selected image on the host and sign the mounted sources
before touching Compose. The shell's explicit image ID takes precedence over the recorded ID; the
build tag is used only before an ID has been selected. Successful launches record the verified ID. ``reload``
recreates every service in ``IMAGE_SERVICES`` and leaves PostgreSQL running. Only ``start`` and ``reload``
create containers, so only they carry ``GITHUB_TOKEN`` from this shell's ``gh`` login
(``host.compose_environment``).
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
                  image_tag, image_target, non_launching_environment, provider_overlay, read_environment,
                  reject_native_environment, reject_other_deployments, validate_deployment)
from image_signing import IMAGE_ID, Runner, SigningError, SigningSettings, sign_image, sign_modules, verify_image


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


# Development hosts may launch with signed-module enforcement off (deploy/dagster/.env or the shell).
# The image is still verified and launched by exact ID; only the mounted sources go unverified.
UNSIGNED_VARIABLE = "APPSEC_UNSIGNED_MODULES"
# The directory Compose mounts read-only at /opt/appsec-review/signing; it holds the module envelope
# signed at launch, and it must exist even for an unsigned development launch.
ENVELOPE_DIRECTORY = deployment / "signing"


def build(platform: str, profile: str, environ: Mapping[str, str], *, runner: Runner = subprocess.run) -> str:
    """Build the tooling-only final stage, sign the image and verify it; return the verified ID.

    The image contains no application sources, so nothing is signed into it here: the module
    envelope over the mounted checkout is produced by ``start``/``reload`` instead.
    """
    settings = signing_settings(environ)
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
    """Verify the explicit or recorded exact ID; use the build tag only for an unpinned first launch."""
    recorded = read_environment(environment_file) if environment_file.is_file() else {}
    if IMAGE_VARIABLE in environ or IMAGE_VARIABLE in recorded:
        reference = environ[IMAGE_VARIABLE] if IMAGE_VARIABLE in environ else recorded[IMAGE_VARIABLE]
        if not IMAGE_ID.fullmatch(reference):
            raise SigningError(f"{IMAGE_VARIABLE} must be an exact sha256 image ID; "
                               "use lifecycle.py build to select a newly signed image")
    else:
        reference = image_tag(platform, profile)
    return verify_image(signing_settings(environ), repository, reference, runner=runner)


def unsigned_modules_requested(environ: Mapping[str, str]) -> bool:
    recorded = read_environment(environment_file) if environment_file.is_file() else {}
    value = {**recorded, **environ}.get(UNSIGNED_VARIABLE, "")
    if value not in {"", "0", "1"}:
        raise SigningError(f"{UNSIGNED_VARIABLE} must be 0 or 1, not {value!r}")
    return value == "1"


def module_environment(settings: SigningSettings, environ: Mapping[str, str], *,
                       runner: Runner = subprocess.run) -> dict[str, str]:
    """Sign the mounted checkout for this launch, or switch enforcement off for a development host.

    Returns the Compose variables that set ``APPSEC_REVIEW_REQUIRE_SIGNED_MODULES`` and
    ``APPSEC_REVIEW_MODULE_SIGNATURE`` inside the services. The envelope directory always exists so
    the read-only mount succeeds either way.
    """
    ENVELOPE_DIRECTORY.mkdir(parents=True, exist_ok=True)
    if unsigned_modules_requested(environ):
        print(f"WARNING: {UNSIGNED_VARIABLE}=1: launching with signed-module enforcement OFF; the mounted "
              "sources are not verified. Development hosts only.", file=sys.stderr, flush=True)
        return {"APPSEC_SIGNED_MODULES": "0", "APPSEC_MODULE_SIGNATURE": ""}
    envelope = sign_modules(settings, repository, runner=runner)
    print(f"signed and verified the module envelope {envelope}", flush=True)
    return {"APPSEC_SIGNED_MODULES": "1",
            "APPSEC_MODULE_SIGNATURE": "/opt/appsec-review/signing/" + envelope.name}


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
            image_id = build(platform, profile, environ, runner=runner)
        except SigningError as error:
            print(f"lifecycle build failed: {error}", file=sys.stderr, flush=True)
            return FAILED
        record_image(environment_file, image_id)
        return OK
    if action in LAUNCHING:
        try:
            settings = signing_settings(environ)
            image_id = verified_image(platform, profile, environ, runner=runner)
        except SigningError as error:
            print(f"refusing to {action}: the image signature did not verify on this host: {error}",
                  file=sys.stderr, flush=True)
            return REFUSED
        print(f"verified {image_id}; Compose launches exactly this image", flush=True)
        try:
            modules = module_environment(settings, environ, runner=runner)
        except SigningError as error:
            print(f"refusing to {action}: the mounted sources could not be signed: {error}",
                  file=sys.stderr, flush=True)
            return REFUSED
        # Compose mounts exactly the trust anchors and envelopes the host verification used; only actions
        # that create containers fix the code-location's GITHUB_TOKEN.
        environment = {**compose_environment(environ), **settings.compose_environment(), **modules,
                       IMAGE_VARIABLE: image_id}
    else:
        environment = non_launching_environment(environment_file, environ)
    from appsec_review.config.host_pins import HOST_PINS_ENV, HOST_PINS_PATH
    pins = Path(environ.get(HOST_PINS_ENV) or repository / HOST_PINS_PATH)
    environment[HOST_PINS_ENV] = str(pins if pins.is_absolute() else repository / pins)
    result = runner(compose_base(platform, profile) + commands[action], cwd=repository, env=environment,
                    check=False).returncode
    if action in LAUNCHING and result == OK:
        record_image(environment_file, image_id)
    return result


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
