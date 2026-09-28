#!/usr/bin/env python3
"""Generate and verify B16 host-local pinned-container image records.

Local Docker image ids differ by host, so these records are generated from the immutable-success
pointer under ``images/.build-state`` at code-location startup and are ignored by Git.  Nothing is
built or pulled here.  A missing image, stale build pointer, Dockerfile change, or local Docker
drift fails closed before any registry file is replaced.

    python3 -B images/registry_records.py generate
    python3 -B images/registry_records.py generate --image-id tool-osv-scanner
    python3 -B images/registry_records.py check
    python3 -B images/registry_records.py list
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
PROCESS = REPO / "appsec-review-process"
DEFAULT_OUTPUT = PROCESS / "registry" / "container-images"
SCHEMA = "appsec-review/container-image/1.0"
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}\Z")
STATE_KEYS = {"attempt_id", "fingerprint", "finished_at", "image_digest", "image_id", "tag"}

TOOL_IMAGE_IDS = (
    "tool-checkov", "tool-gitleaks", "tool-gosec", "tool-grype", "tool-hadolint",
    "tool-microsoft-sbom-tool", "tool-mobsfscan", "tool-phpcs", "tool-phpstan", "tool-psalm", "tool-semgrep",
    "tool-sbomasm", "tool-spotbugs", "tool-syft", "tool-trivy", "tool-osv-scanner",
)
BUILDENV_IMAGE_IDS = (
    "audit-buildenv-cpp", "audit-buildenv-cpp-resolute", "audit-buildenv-dotnet", "audit-buildenv-go", "audit-buildenv-java",
    "audit-buildenv-php", "audit-buildenv-python", "audit-buildenv-rust", "audit-buildenv-typescript",
)
STEP4_IMAGE_IDS = (
    "audit-native", "audit-binary-analysis", "audit-container", "audit-iac",
    "audit-report", "scancode-toolkit", *BUILDENV_IMAGE_IDS, *TOOL_IMAGE_IDS,
)


class RegistryRecordError(RuntimeError):
    """The local build state cannot safely produce the B16 registry."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def repository_from_tag(tag: str) -> str:
    """Canonical repository spelling for a local tag; the tag itself is never returned."""
    repository, separator, _tag = tag.rpartition(":")
    if not separator or not repository:
        raise RegistryRecordError("build state tag is not a named tag")
    if "/" not in repository:
        return "docker.io/library/" + repository
    first = repository.split("/", 1)[0]
    return repository if first == "localhost" or "." in first or ":" in first else "docker.io/" + repository


def docker_image_id(docker: Path, tag: str) -> str:
    completed = subprocess.run(
        [str(docker), "image", "inspect", "--format", "{{.Id}}", tag],
        capture_output=True, text=True, timeout=60, check=False,
    )
    value = completed.stdout.strip()
    if completed.returncode != 0 or not SHA_RE.fullmatch(value):
        raise RegistryRecordError(f"local image is missing or has no immutable image id: {tag}")
    return value


def load_state(state_root: Path, image_id: str) -> dict[str, Any]:
    path = state_root / image_id / "latest.json"
    try:
        raw = path.read_bytes()
        state = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError):
        raise RegistryRecordError(f"{image_id}: missing or unreadable successful build state") from None
    if not isinstance(state, dict) or set(state) != STATE_KEYS:
        raise RegistryRecordError(f"{image_id}: latest.json does not have the closed B16 state shape")
    if state["image_id"] != image_id:
        raise RegistryRecordError(f"{image_id}: latest.json names another image")
    if not SHA_RE.fullmatch(str(state["image_digest"])) or not SHA_RE.fullmatch(str(state["fingerprint"])):
        raise RegistryRecordError(f"{image_id}: latest.json has an invalid digest or fingerprint")
    if not isinstance(state["attempt_id"], str) or not re.fullmatch(r"[A-Za-z0-9:+._-]{1,120}", state["attempt_id"]):
        raise RegistryRecordError(f"{image_id}: latest.json has an invalid attempt id")
    if not isinstance(state["tag"], str) or not 1 <= len(state["tag"]) <= 255 or re.search(r"\s", state["tag"]):
        raise RegistryRecordError(f"{image_id}: latest.json has an invalid tag")
    if not isinstance(state["finished_at"], str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", state["finished_at"]):
        raise RegistryRecordError(f"{image_id}: latest.json has an invalid completion time")
    return state


def dockerfile_path(build: dict[str, Any]) -> Path:
    folder = Path(build["folder"])
    path = (folder / build["context"] / build["dockerfile"]).resolve()
    if not path.is_file():
        raise RegistryRecordError(f"{build['image_id']}: Dockerfile is missing")
    return path


def build_record(image_id: str, build: dict[str, Any], state: dict[str, Any], actual: str) -> dict[str, Any]:
    if state["tag"] != build["tag"]:
        raise RegistryRecordError(f"{image_id}: build state tag differs from image.json")
    if actual != state["image_digest"]:
        raise RegistryRecordError(f"{image_id}: local Docker image id drifted from latest.json")
    dockerfile = dockerfile_path(build)
    return {
        "schema": SCHEMA,
        "image_id": image_id,
        "repository": repository_from_tag(state["tag"]),
        "digest": actual,
        "digest_kind": "image-id",
        "dockerfile_sha256": file_sha256(dockerfile),
        "build_fingerprint_sha256": state["fingerprint"],
        "build_attempt_id": state["attempt_id"],
        "purpose": f"Host-local pinned image for {image_id}; generated for B13 execution.",
        "provenance": f"images/.build-state/{image_id}/latest.json from successful image_build.py attempt.",
    }


def collect_records(*, images_root: Path = HERE, state_root: Path | None = None,
                    image_ids: tuple[str, ...] = STEP4_IMAGE_IDS,
                    inspect: Callable[[str], str] | None = None,
                    fingerprint: Callable[[dict[str, Any]], str] | None = None
                    ) -> dict[str, dict[str, Any]]:
    sys.path.insert(0, str(HERE))
    import image_build  # imported after the root is selected; no Docker call at import time

    builds = image_build.load_builds(images_root)
    state_root = state_root or images_root / ".build-state"
    missing = sorted(set(image_ids) - set(builds))
    if missing:
        raise RegistryRecordError("image.json declarations missing for: " + ", ".join(missing))
    if inspect is None:
        found = os.environ.get("APPSEC_DOCKER_BIN") or shutil.which("docker")
        if not found:
            raise RegistryRecordError("Docker CLI not found (set APPSEC_DOCKER_BIN)")
        docker = Path(found).resolve()
        inspect = lambda tag: docker_image_id(docker, tag)
    fingerprint = fingerprint or (lambda build: image_build.fingerprint(build)[0])
    records = {}
    for image_id in image_ids:
        build = builds[image_id]
        state = load_state(state_root, image_id)
        if fingerprint(build) != state["fingerprint"]:
            raise RegistryRecordError(
                f"{image_id}: current image inputs drifted from the successful build fingerprint")
        records[image_id] = build_record(image_id, build, state, inspect(state["tag"]))
    return records


def validate_records(records: dict[str, dict[str, Any]]) -> None:
    sys.path.insert(0, str(PROCESS))
    from schema_validate import validate_document

    for image_id, record in records.items():
        errors = validate_document(record, "container-image.schema.json")
        if errors:
            raise RegistryRecordError(f"{image_id}: generated record fails schema ({len(errors)} errors)")


def write_records(records: dict[str, dict[str, Any]], output_dir: Path = DEFAULT_OUTPUT) -> None:
    """Replace managed records only after every build, image and record has verified."""
    validate_records(records)
    output_dir.mkdir(parents=True, exist_ok=True)
    temporary: list[tuple[Path, Path]] = []
    try:
        for image_id in sorted(records):
            target = output_dir / f"{image_id}.json"
            temp = output_dir / f".{image_id}.{uuid.uuid4().hex[:12]}.tmp"
            temp.write_bytes(canonical_bytes(records[image_id]))
            temporary.append((temp, target))
        for temp, target in temporary:
            os.replace(temp, target)
    finally:
        for temp, _target in temporary:
            temp.unlink(missing_ok=True)


def check_records(records: dict[str, dict[str, Any]], output_dir: Path = DEFAULT_OUTPUT) -> None:
    validate_records(records)
    errors = []
    for image_id, record in sorted(records.items()):
        path = output_dir / f"{image_id}.json"
        try:
            actual = path.read_bytes()
        except OSError:
            errors.append(f"{image_id}: registry record is missing")
            continue
        if actual != canonical_bytes(record):
            errors.append(f"{image_id}: registry record drifted from build state or local Docker")
    if errors:
        raise RegistryRecordError("; ".join(errors))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "check", "list"))
    parser.add_argument("--images-root", type=Path, default=HERE)
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--image-id", action="append", choices=STEP4_IMAGE_IDS,
                        help="generate/check only this declared image; repeat for a bounded subset")
    args = parser.parse_args(argv)
    if args.command == "list":
        print("\n".join(STEP4_IMAGE_IDS))
        return 0
    try:
        selected = tuple(dict.fromkeys(args.image_id)) if args.image_id else STEP4_IMAGE_IDS
        records = collect_records(images_root=args.images_root, state_root=args.state_root,
                                  image_ids=selected)
        if args.command == "generate":
            write_records(records, args.output_dir)
            print(f"generated {len(records)} host-local container image records in {args.output_dir}")
        else:
            check_records(records, args.output_dir)
            print(f"verified {len(records)} host-local container image records against Docker")
        return 0
    except RegistryRecordError as exc:
        print(f"registry-records: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
