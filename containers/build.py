#!/usr/bin/env python3
"""Deterministic catalog-driven container fetch, build, validation, and smoke runner."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTAINERS = ROOT / "containers"
CATALOG = CONTAINERS / "catalog.toml"
RUN_ROOT = ROOT / "runs" / "container-builds"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
# Per-image ``docker build`` bound; ``build --timeout-seconds`` overrides it within the limits below.
BUILD_TIMEOUT_SECONDS = 1800
BUILD_TIMEOUT_RANGE = (60, 14400)


def load_catalog() -> dict[str, Any]:
    with CATALOG.open("rb") as stream:
        data = tomllib.load(stream)
    images = data.get("images", [])
    data["by_id"] = {item["id"]: item for item in images}
    return data


def safe_path(value: str) -> Path:
    path = (ROOT / value).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"path escapes repository: {value}") from exc
    return path


def dependency_order(ids: list[str], catalog: dict[str, Any]) -> list[str]:
    by_id = catalog["by_id"]
    ordered: list[str] = []
    visiting: set[str] = set()

    def visit(image_id: str) -> None:
        if image_id in ordered:
            return
        if image_id in visiting:
            raise ValueError(f"dependency cycle at {image_id}")
        if image_id not in by_id:
            raise ValueError(f"unknown image: {image_id}")
        visiting.add(image_id)
        for dependency in by_id[image_id].get("dependencies", []):
            visit(dependency)
        visiting.remove(image_id)
        ordered.append(image_id)

    for selected in ids:
        visit(selected)
    return ordered


def validate(catalog: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    policy: dict[str, Any] = {}
    try:
        with safe_path(catalog["runtime_policy"]).open("rb") as stream:
            policy = tomllib.load(stream)
    except (KeyError, OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"runtime policy is unavailable: {exc}")
    images = catalog.get("images", [])
    ids = [item.get("id") for item in images]
    if len(ids) != len(set(ids)):
        errors.append("catalog image ids are not unique")
    audited = [item for item in images if "legacy_class" in item]
    if len(audited) != 42:
        errors.append(f"expected 42 audited legacy entries, found {len(audited)}")
    for item in images:
        image_id = item.get("id", "")
        if not SAFE_ID.fullmatch(image_id):
            errors.append(f"invalid image id: {image_id!r}")
            continue
        state = item.get("state")
        if state not in {"enabled", "deferred", "replaced", "retired"}:
            errors.append(f"{image_id}: invalid state {state!r}")
        if state != "enabled":
            if not item.get("reason"):
                errors.append(f"{image_id}: non-enabled entry needs a reason")
            continue
        for dependency in item.get("dependencies", []):
            if dependency not in catalog["by_id"]:
                errors.append(f"{image_id}: missing dependency {dependency}")
        for field in ("context", "dockerfile", "tag", "version"):
            if not item.get(field):
                errors.append(f"{image_id}: missing {field}")
        if not item.get("context"):
            continue
        if item.get("kind") == "base":
            for field in ("upstream", "upstream_manifest_bytes", "upstream_manifest_sha256",
                          "license", "license_source", "provenance", "signature_verification"):
                if not item.get(field):
                    errors.append(f"{image_id}: base provenance missing {field}")
            digest = str(item.get("upstream", "")).rsplit("@sha256:", 1)[-1]
            if not SHA256.fullmatch(digest) or digest != item.get("upstream_manifest_sha256"):
                errors.append(f"{image_id}: base manifest digest mismatch")
        context = safe_path(item["context"])
        for name, extra in sorted(item.get("build_contexts", {}).items()):
            try:
                if not SAFE_ID.fullmatch(name) or not safe_path(extra).is_dir():
                    errors.append(f"{image_id}: build context {name!r} must be a repository directory")
            except ValueError:
                errors.append(f"{image_id}: build context {name!r} escapes repository")
        dockerfile = context / item["dockerfile"]
        if not dockerfile.is_file():
            errors.append(f"{image_id}: missing {dockerfile.relative_to(ROOT)}")
            continue
        text = dockerfile.read_text(encoding="utf-8")
        if re.search(r"(?i)(curl|wget)[^\n]*(\||bash|sh\s+-c)", text):
            errors.append(f"{image_id}: remote script execution is prohibited")
        if re.search(r"(?m)^FROM\s+\S+:latest(?:\s|$)", text):
            errors.append(f"{image_id}: moving latest base is prohibited")
        if not re.search(r"(?m)^USER\s+10001(?::10001)?\s*$", text):
            errors.append(f"{image_id}: final non-root USER 10001 is required")
        build_network = item.get("build_network", "none")
        if build_network not in {"none", "default"}:
            errors.append(f"{image_id}: build_network must be none or default")
        if item.get("kind") == "buildenv" and (
                not isinstance(item.get("probe_argv"), list) or
                not isinstance(item.get("probe_expect"), list)):
            errors.append(f"{image_id}: buildenv probe contract is required")
        if item.get("kind") == "tool":
            try:
                manifest_path = safe_path(item["tool_manifest"])
                with manifest_path.open("rb") as stream:
                    manifest = tomllib.load(stream)
                for field in ("network", "user", "memory", "cpus", "pids_limit",
                              "timeout_seconds", "output_bytes"):
                    if manifest.get(field) != policy.get(field):
                        errors.append(f"{image_id}: {field} does not match central runtime policy")
            except (KeyError, OSError, ValueError, tomllib.TOMLDecodeError) as exc:
                errors.append(f"{image_id}: tool manifest is unavailable: {exc}")
        lock_name = item.get("assets_lock")
        if lock_name:
            lock_path = safe_path(lock_name)
            if not lock_path.is_file():
                errors.append(f"{image_id}: missing assets lock")
            else:
                lock = json.loads(lock_path.read_text(encoding="utf-8"))
                for index, artifact in enumerate(lock.get("artifacts", [])):
                    prefix = f"{image_id}: artifact {index}"
                    if not str(artifact.get("url", "")).startswith("https://"):
                        errors.append(f"{prefix} needs an HTTPS source")
                    if "/latest/" in str(artifact.get("url", "")):
                        errors.append(f"{prefix} must not use a moving latest URL")
                    if not SHA256.fullmatch(str(artifact.get("sha256", ""))):
                        errors.append(f"{prefix} needs sha256")
                    if not isinstance(artifact.get("bytes"), int) or artifact["bytes"] <= 0:
                        errors.append(f"{prefix} needs byte size")
                    for field in ("version", "license", "license_source", "provenance"):
                        if not artifact.get(field):
                            errors.append(f"{prefix} needs {field}")
                    signature = artifact.get("signature_verification", {})
                    if signature.get("status") not in {"verified", "not-performed", "not-published"}:
                        errors.append(f"{prefix} needs explicit signature verification status")
                    try:
                        target = (context / artifact["path"]).resolve()
                        target.relative_to(context.resolve())
                    except (KeyError, ValueError):
                        errors.append(f"{prefix} path escapes context")
                for field in ("project", "license", "tool_version", "architecture"):
                    if not lock.get(field):
                        errors.append(f"{image_id}: assets lock missing {field}")
    try:
        dependency_order([item["id"] for item in images if item.get("state") == "enabled"], catalog)
    except ValueError as exc:
        errors.append(str(exc))
    return errors


def selected_ids(args: argparse.Namespace, catalog: dict[str, Any]) -> list[str]:
    if getattr(args, "all", False):
        return [item["id"] for item in catalog["images"] if item.get("state") == "enabled"]
    ids = list(getattr(args, "ids", []) or [])
    if not ids:
        raise ValueError("select image ids or pass --all")
    for image_id in ids:
        item = catalog["by_id"].get(image_id)
        if not item:
            raise ValueError(f"unknown image: {image_id}")
        if item.get("state") != "enabled":
            raise ValueError(f"{image_id} is {item.get('state')}, not enabled")
    return ids


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_artifact(artifact: dict[str, Any], context: Path, log, opener=urllib.request.urlopen) -> str:
    """Fetch one locked artifact into the build context, accepting it only at its exact size and SHA-256."""
    target = (context / artifact["path"]).resolve()
    target.relative_to(context.resolve())
    target.parent.mkdir(parents=True, exist_ok=True)
    expected_hash = artifact["sha256"]
    expected_size = artifact["bytes"]
    if target.is_file() and target.stat().st_size == expected_size and file_sha256(target) == expected_hash:
        log.write(f"CURRENT {artifact['path']}\n")
        return "current"
    temporary = target.with_suffix(target.suffix + ".partial")
    temporary.unlink(missing_ok=True)
    request = urllib.request.Request(artifact["url"], headers={"User-Agent": "appsec-review-container-builder/1"})
    digest = hashlib.sha256()
    size = 0
    try:
        with opener(request, timeout=120) as response, temporary.open("wb") as stream:
            while chunk := response.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
                if size > expected_size:
                    break
                stream.write(chunk)
        if size != expected_size or digest.hexdigest() != expected_hash:
            raise RuntimeError(f"asset verification failed: {artifact['url']}")
        temporary.replace(target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    log.write(f"FETCHED {artifact['path']} {size} {expected_hash}\n")
    return "fetched"


def fetch_one(item: dict[str, Any], log) -> None:
    lock_name = item.get("assets_lock")
    if not lock_name:
        return
    context = safe_path(item["context"])
    lock = json.loads(safe_path(lock_name).read_text(encoding="utf-8"))
    for artifact in lock.get("artifacts", []):
        fetch_artifact(artifact, context, log)


def docker_binary() -> str:
    return os.environ.get("APPSEC_DOCKER_BIN", "docker")


def run_logged(argv: list[str], log_path: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write("argv=" + json.dumps(argv) + "\n")
        stream.flush()
        return subprocess.run(argv, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                              text=True, timeout=timeout, check=False)


def build_one(item: dict[str, Any], run_dir: Path, *,
              timeout_seconds: int = BUILD_TIMEOUT_SECONDS) -> dict[str, Any]:
    started = time.monotonic()
    image_id = item["id"]
    fetch_log = run_dir / "logs" / f"{image_id}.fetch.log"
    build_log = run_dir / "logs" / f"{image_id}.build.log"
    context = safe_path(item["context"])
    dockerfile = context / item["dockerfile"]
    lock_path = safe_path(item["assets_lock"]) if item.get("assets_lock") else None
    result: dict[str, Any] = {
        "id": image_id, "tag": item["tag"], "status": "failed", "digest": None,
        "fetch_log": str(fetch_log.relative_to(ROOT)), "build_log": str(build_log.relative_to(ROOT)),
        "dockerfile_sha256": hashlib.sha256(dockerfile.read_bytes()).hexdigest(),
        "assets_lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest() if lock_path else None,
        "base_identity": item.get("upstream"),
    }
    try:
        fetch_log.parent.mkdir(parents=True, exist_ok=True)
        with fetch_log.open("w", encoding="utf-8", newline="\n") as log:
            fetch_one(item, log)
        argv = [docker_binary(), "build", f"--network={item.get('build_network', 'none')}",
                "--pull=false", "--file",
                str(context / item["dockerfile"]), "--tag", item["tag"]]
        for key, value in sorted(item.get("build_args", {}).items()):
            argv += ["--build-arg", f"{key}={value}"]
        for name, extra in sorted(item.get("build_contexts", {}).items()):
            argv += ["--build-context", f"{name}={safe_path(extra)}"]
        argv.append(str(context))
        try:
            completed = run_logged(argv, build_log, timeout_seconds)
        except subprocess.TimeoutExpired:
            result["error"] = f"docker build timed out after {timeout_seconds} seconds"
            return result
        if completed.returncode != 0:
            result["error"] = f"docker build exited {completed.returncode}"
            return result
        inspect = subprocess.run([docker_binary(), "image", "inspect", item["tag"],
                                  "--format", "{{.Id}}"], cwd=ROOT, capture_output=True,
                                 text=True, timeout=30, check=False)
        if inspect.returncode != 0 or not inspect.stdout.strip().startswith("sha256:"):
            result["error"] = "built image digest could not be resolved"
            return result
        result.update(status="passed", digest=inspect.stdout.strip())
        return result
    except Exception as exc:  # explicit per-image failure in machine summary
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    finally:
        result["duration_seconds"] = round(time.monotonic() - started, 3)


def execute_build(args: argparse.Namespace, catalog: dict[str, Any]) -> int:
    requested = selected_ids(args, catalog)
    ordered = dependency_order(requested, catalog)
    timeout_seconds = int(getattr(args, "timeout_seconds", BUILD_TIMEOUT_SECONDS))
    if not BUILD_TIMEOUT_RANGE[0] <= timeout_seconds <= BUILD_TIMEOUT_RANGE[1]:
        raise ValueError(f"build timeout must be within {BUILD_TIMEOUT_RANGE}: {timeout_seconds}")
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
    run_dir = RUN_ROOT / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    jobs = max(1, min(int(args.jobs), 8))
    pending = set(ordered)
    results: dict[str, dict[str, Any]] = {}
    running: dict[concurrent.futures.Future, str] = {}
    failed = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        while pending or running:
            ready = [image_id for image_id in ordered if image_id in pending and
                     all(dep in results for dep in catalog["by_id"][image_id].get("dependencies", []))]
            for image_id in ready:
                dependencies = catalog["by_id"][image_id].get("dependencies", [])
                if any(results[dep]["status"] != "passed" for dep in dependencies):
                    results[image_id] = {"id": image_id, "tag": catalog["by_id"][image_id].get("tag"),
                                         "status": "blocked", "duration_seconds": 0,
                                         "digest": None, "error": "dependency failed",
                                         "fetch_log": None, "build_log": None}
                    pending.remove(image_id)
                    failed = True
                elif not failed or args.continue_on_error:
                    running[pool.submit(build_one, catalog["by_id"][image_id], run_dir,
                                         timeout_seconds=timeout_seconds)] = image_id
                    pending.remove(image_id)
                if len(running) >= jobs:
                    break
            if not running:
                if pending:
                    for image_id in list(pending):
                        results[image_id] = {"id": image_id, "tag": catalog["by_id"][image_id].get("tag"),
                                             "status": "skipped", "duration_seconds": 0,
                                             "digest": None, "error": "stopped after failure",
                                             "fetch_log": None, "build_log": None}
                        pending.remove(image_id)
                break
            done, _ = concurrent.futures.wait(running, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                image_id = running.pop(future)
                results[image_id] = future.result()
                failed = failed or results[image_id]["status"] != "passed"
                print(f"{results[image_id]['status'].upper():7} {image_id}")
    summary = {
        "schema": "appsec-review/container-build-summary/1", "run_id": run_id,
        "catalog": str(CATALOG.relative_to(ROOT)), "jobs": jobs, "timeout_seconds": timeout_seconds,
        "continue_on_error": bool(args.continue_on_error),
        "results": [results[image_id] for image_id in ordered],
    }
    summary_path = run_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    try:
        display_summary = summary_path.relative_to(ROOT)
    except ValueError:
        display_summary = summary_path
    print(f"summary={display_summary}")
    return 1 if any(item["status"] != "passed" for item in summary["results"]) else 0


REGISTRY = Path("rules") / "registry.toml"
PACK_VERIFY_TIMEOUT_SECONDS = 1800


def load_registry() -> dict[str, Any]:
    """The central rule-pack registry (rules/registry.toml)."""
    with safe_path(REGISTRY.as_posix()).open("rb") as stream:
        document = tomllib.load(stream)
    if document.get("schema") != "appsec-review/rule-pack-registry/1":
        raise SystemExit("rule pack registry schema is not appsec-review/rule-pack-registry/1")
    packs = document.get("packs")
    if not isinstance(packs, list) or not packs:
        raise SystemExit("rule pack registry declares no packs")
    seen: set[str] = set()
    for pack in packs:
        if not (isinstance(pack.get("path"), str) or isinstance(pack.get("image_path"), str)):
            raise SystemExit(f"{pack.get('id')}: declare either path or image_path")
        for field in ("id", "engine", "library", "verify", "state"):
            if not isinstance(pack.get(field), str) or not pack[field]:
                raise SystemExit(f"rule pack entry is missing {field}")
        if pack["id"] in seen:
            raise SystemExit(f"rule pack id is declared twice: {pack['id']}")
        seen.add(pack["id"])
        if pack["engine"] not in ("codeql", "semgrep", "pmd", "gitleaks"):
            raise SystemExit(f"{pack['id']}: unknown engine {pack['engine']}")
        if pack["verify"] not in ("check-only", "validate"):
            raise SystemExit(f"{pack['id']}: unknown verify mode {pack['verify']}")
        if isinstance(pack.get("path"), str):
            safe_path(pack["path"])
    return document


def _pack_container_name(pack_id: str) -> str:
    """A named container can be removed when the client dies; an unnamed one cannot be found."""
    return f"appsec-review-packverify-{pack_id}-{os.getpid()}"


def _remove_container(name: str) -> None:
    subprocess.run([docker_binary(), "rm", "--force", name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def _run_pack_container(argv: list[str], log_path: Path, timeout: int,
                        container: str) -> subprocess.CompletedProcess[str] | None:
    """Run a verification container, or return None when it exceeded ``timeout``.

    ``docker run`` killed by a timeout only kills the client: the container keeps running and keeps
    the CPU. Removing it by name is the only way to stop the work.
    """
    try:
        return run_logged(argv, log_path, timeout)
    except subprocess.TimeoutExpired:
        _remove_container(container)
        return None


def _codeql_check_only(pack: dict[str, Any], log_path: Path) -> tuple[bool, str]:
    """Type-check every query in a CodeQL pack inside its pinned image, offline.

    ``codeql query compile --check-only`` resolves imports and types without building a query
    plan. That is the whole bug class we care about (ambiguous or moved library modules, casts
    that no longer typecheck) and it needs no database, so it can gate a run cheaply.
    """
    library, _, version = pack["library"].partition("@")
    in_image = pack.get("image_path")
    mount: list[str] = []
    if in_image:
        stage = f"cp -r {in_image} /tmp/pack\n"
    else:
        root = safe_path(pack["path"])
        mount = ["--volume", f"{root.resolve().as_posix()}:/pack:ro"]
        stage = "cp -r /pack /tmp/pack\n"
    script = (
        "set -eu\n"
        f"test -d /opt/codeql/qlpacks/{library}/{version} || "
        f"{{ echo \"PACK_LIBRARY_ABSENT {library}@{version}\" >&2; exit 3; }}\n"
        + stage +
        "cd /tmp/pack\n"
        # Only the pack's own queries. A self-contained pack vendors its dependency closure
        # under .codeql/libraries/, and those bundled packs carry queries of their own that are
        # not independently resolvable; compiling them reports the dependency as missing.
        "exec /opt/codeql/codeql query compile --check-only --threads=4 -- "
        "$(find . -name '*.ql' -not -path './.codeql/*' -print | sort)\n"
    )
    container = _pack_container_name(pack["id"])
    argv = [docker_binary(), "run", "--rm", "--name", container, "--network", "none", *mount,
            "--entrypoint", "sh", pack["image"], "-c", script]
    timeout = int(pack.get("timeout_seconds", PACK_VERIFY_TIMEOUT_SECONDS))
    result = _run_pack_container(argv, log_path, timeout, container)
    if result is None:
        # A timeout is not a compile failure; reporting it as one sent us chasing the wrong cause.
        return False, f"verification exceeded timeout_seconds={timeout}"
    # run_logged sends both streams to log_path, so the CompletedProcess carries no text. The
    # first line is the argv echo, which quotes the probe script; scanning it would match the
    # marker in the command text rather than in the container's output.
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    text = "\n".join(line for line in lines if not line.startswith("argv="))
    if "PACK_LIBRARY_ABSENT" in text:
        return False, f"pinned library {pack['library']} is not installed in {pack['image']}"
    if result.returncode != 0:
        errors = [line for line in text.splitlines() if line.startswith("ERROR:")]
        failed = sorted({line.split()[-1].rstrip(".") for line in text.splitlines()
                         if line.startswith("Failed [")})
        detail = f"exit {result.returncode}"
        if errors:
            detail = f"{len(errors)} compile error(s) in {len(failed) or 1} query file(s); " \
                     f"first: {errors[0][len('ERROR: '):][:120]}"
        return False, detail
    return True, "check-only compile clean"


COMPILE_CACHE_MOUNT = "/codeql-cache"
WARM_TIMEOUT_SECONDS = 3600
# A cold export-pack compile peaks near 7 GB. Docker containers on the review host share one 10 GB
# cgroup with other sessions: two compiles at once are OOM-killed and 3 GB thrashes the GC, so
# warm compiles run one at a time with this budget unless --ram overrides it.
WARM_RAM_MB = 7000
WARM_THREADS = 8
WARM_CONTAINER_PREFIX = "appsec-review-warm-"
PACK_STAGE_PATH = "/scratch/export/pack"
CACHE_FALLBACK_OWNER = "10001:10001"


def cache_owner() -> str:
    """uid:gid the job runs CodeQL as: the host process owner, else the image's runtime user.

    Mirrors ``appsec_review.container_runtime.identity.application_runtime_user``. The compile cache
    must be written by the same uid the job later reads it as; a cache populated as another uid
    is unreadable to the job's CodeQL (it silently recompiles for the full cold time).
    """
    getuid, getgid = getattr(os, "geteuid", None), getattr(os, "getegid", None)
    if getuid is not None and getgid is not None and getuid() > 0 and getgid() > 0:
        return f"{getuid()}:{getgid()}"
    return CACHE_FALLBACK_OWNER


def compile_cache_volume() -> str:
    """Name of the shared CodeQL compile cache that review runs mount.

    Mirrors ``appsec_review.codeql.runtime.compile_cache_volume``: keyed only by the declared
    CodeQL release and the uid that reads it, so a warm compile here is exactly what runs reuse and
    nothing recompiles until the CodeQL distribution changes (or a pack's own bytes change).
    """
    with (ROOT / "appsec-review.toml").open("rb") as stream:
        release = tomllib.load(stream)["review_policy"]["releases"]["codeql"]
    identity = json.dumps({"codeql": release, "user": cache_owner()}, sort_keys=True,
                          separators=(",", ":"), ensure_ascii=False) + "\n"
    return "appsec-codeql-compile-" + hashlib.sha256(identity.encode()).hexdigest()[:24]


def _warm_script(threads: int, ram_mb: int) -> str:
    return (
        "set -eu\n"
        "mkdir -p /tmp/codeql-home/.codeql\n"
        f"ln -s {COMPILE_CACHE_MOUNT} /tmp/codeql-home/.codeql/compile-cache\n"
        f"cd {PACK_STAGE_PATH}\n"
        f"exec /opt/codeql/codeql query compile --threads={threads} --ram={ram_mb} -- "
        "$(find . -name '*.ql' -not -path './.codeql/*' -print | sort)\n")


def _warm_argv(pack: dict[str, Any], image: str, volume: str, owner: str, threads: int, ram_mb: int) -> list[str]:
    root = safe_path(pack["path"])
    return [docker_binary(), "run", "--rm", "--name", f"{WARM_CONTAINER_PREFIX}{pack['id']}-{os.getpid()}",
            "--network", "none", "--read-only",
            "--user", owner, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=2g", "--env", "HOME=/tmp/codeql-home",
            "--mount", f"type=volume,src={volume},dst={COMPILE_CACHE_MOUNT}",
            "--mount", f"type=bind,src={root.resolve().as_posix()},dst={PACK_STAGE_PATH},readonly",
            "--entrypoint", "sh", image, "-c", _warm_script(threads, ram_mb)]


def _warm_settings(pack: dict[str, Any], threads: int | None, ram_mb: int | None) -> tuple[int, int]:
    return (int(threads or pack.get("warm_threads", WARM_THREADS)),
            int(ram_mb or pack.get("warm_ram_mb", WARM_RAM_MB)))


def running_warm_containers() -> list[str]:
    """Names of compile containers already running (this tool's, or an operator's ad hoc ``warm-*``)."""
    try:
        listed = subprocess.run([docker_binary(), "ps", "--format", "{{.Names}}"],
                                capture_output=True, text=True, check=False)
    except OSError:
        return []
    return sorted(name for name in (listed.stdout or "").split()
                  if name.startswith(WARM_CONTAINER_PREFIX) or name.startswith("warm-"))


def _codeql_warm(pack: dict[str, Any], log_path: Path, *, threads: int | None = None,
                 ram_mb: int | None = None) -> tuple[bool, str]:
    """Really compile every query of a CodeQL pack into the shared compile cache runs mount.

    ``--check-only`` stops before query planning, so it misses errors that only appear when a query
    is planned. This does the full compile once, offline, into the volume named from the pinned
    CodeQL release, at the pack path the job uses. Queries already in the cache are cache hits, so
    a repeat warm costs seconds per query.
    """
    inspected = subprocess.run([docker_binary(), "image", "inspect", pack["image"], "--format", "{{.Id}}"],
                               capture_output=True, text=True, check=False)
    image_id = inspected.stdout.strip()
    if inspected.returncode != 0 or not image_id:
        return False, f"image {pack['image']} is not present"
    volume = compile_cache_volume()
    owner = cache_owner()
    for argv in ([docker_binary(), "volume", "create", "--label", "appsec-review=codeql-compile-cache", volume],
                 [docker_binary(), "run", "--rm", "--network", "none", "--read-only", "--user", "0:0",
                  "--security-opt", "no-new-privileges", "--mount", f"type=volume,src={volume},dst={COMPILE_CACHE_MOUNT}",
                  "--entrypoint", "chown", image_id, "-R", owner, COMPILE_CACHE_MOUNT]):
        prepared = subprocess.run(argv, capture_output=True, text=True, check=False)
        if prepared.returncode != 0:
            return False, f"cache volume {volume} could not be prepared: {prepared.stderr.strip()[:120]}"
    threads, ram_mb = _warm_settings(pack, threads, ram_mb)
    argv = _warm_argv(pack, image_id, volume, owner, threads, ram_mb)
    container = argv[argv.index("--name") + 1]
    timeout = int(pack.get("warm_timeout_seconds", WARM_TIMEOUT_SECONDS))
    started = time.monotonic()
    result = _run_pack_container(argv, log_path, timeout, container)
    if result is None:
        return False, f"warm compile exceeded warm_timeout_seconds={timeout}"
    if result.returncode != 0:
        text = log_path.read_text(encoding="utf-8", errors="replace")
        errors = [line for line in text.splitlines() if line.startswith("ERROR:")]
        return False, f"warm compile exit {result.returncode}" + (f"; first: {errors[0][:120]}" if errors else "")
    return True, f"compiled into {volume} in {time.monotonic() - started:.0f}s"


def _engine_validate(pack: dict[str, Any], log_path: Path) -> tuple[bool, str]:
    """Engine-native validation for non-CodeQL packs."""
    root = safe_path(pack["path"])
    if pack["engine"] == "semgrep":
        # `semgrep --validate` fetches p/semgrep-rule-lints from semgrep.dev, so it cannot run
        # under the no-network packaging boundary. Mirror the real adapter instead: a scan with
        # each config against an empty tree loads and parses every rule offline, and a malformed
        # rule still fails the command.
        inner = ("mkdir -p /tmp/empty && exec semgrep scan --disable-version-check "
                 "--metrics off --config /pack --json --output /dev/null /tmp/empty")
    elif pack["engine"] == "gitleaks":
        # A scan of an empty tree loads and compiles every rule of the config offline; a malformed
        # rule fails the command.
        inner = ("mkdir -p /tmp/empty && exec /opt/tool/bin/gitleaks dir /tmp/empty "
                 "--config /pack/generic-secrets.toml --no-banner --exit-code 0")
    else:
        suite = pack.get("suite")
        if not isinstance(suite, str) or not suite:
            return False, "pmd pack declares no suite to validate"
        inner = f"exec pmd check --rulesets /pack/{suite} --dir /pack --format text --no-progress"
    container = _pack_container_name(pack["id"])
    argv = [docker_binary(), "run", "--rm", "--name", container, "--network", "none",
            "--volume", f"{root.resolve().as_posix()}:/pack:ro",
            "--entrypoint", "sh", pack["image"], "-c", f"set -eu\n{inner}\n"]
    timeout = int(pack.get("timeout_seconds", PACK_VERIFY_TIMEOUT_SECONDS))
    result = _run_pack_container(argv, log_path, timeout, container)
    if result is None:
        return False, f"verification exceeded timeout_seconds={timeout}"
    if result.returncode != 0:
        lines = [line for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines()
                 if line.strip() and not line.startswith("argv=")]
        return False, f"exit {result.returncode}: {lines[-1][:140] if lines else 'no output'}"
    return True, "engine validation clean"


def query_packs(args: argparse.Namespace, _catalog: dict[str, Any]) -> int:
    """Verify every registered rule pack. Any failure fails the command; nothing is a gap.

    With ``--warm`` it instead fully compiles the warm-registered CodeQL packs, one at a time, into
    the shared compile cache. Packs that ship precompiled ``.qlx`` (the image's standard query packs
    and the licensed CERT pack) are never warm-registered: ``database analyze`` loads their ``.qlx``.
    """
    document = load_registry()
    requested = set(args.ids)
    unknown = requested - {pack["id"] for pack in document["packs"]}
    if unknown:
        raise SystemExit("unknown rule pack id(s): " + ", ".join(sorted(unknown)))
    languages = {item.strip() for value in (getattr(args, "language", None) or [])
                 for item in value.split(",") if item.strip()}
    known_languages = {pack.get("language") for pack in document["packs"]}
    if languages - known_languages:
        print("error: unknown language(s): " + ", ".join(sorted(languages - known_languages))
              + "; registered: " + ", ".join(sorted(str(item) for item in known_languages)), file=sys.stderr)
        return 2
    packs = [pack for pack in document["packs"]
             if (not requested or pack["id"] in requested)
             and (not languages or pack.get("language") in languages)]
    dry_run = bool(getattr(args, "dry_run", False))
    threads, ram_mb = getattr(args, "threads", None), getattr(args, "ram", None)
    if args.warm and not getattr(args, "allow_concurrent", False):
        busy = running_warm_containers()
        if busy:
            print("REFUSED another CodeQL compile is running (" + ", ".join(busy) + "); concurrent "
                  "compiles share one memory cgroup and get OOM-killed. Wait for it to finish, or pass "
                  "--allow-concurrent.", file=sys.stderr)
            return 3
    run_dir = RUN_ROOT / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + f"-packs-{os.getpid()}")
    if not dry_run:
        (run_dir / "logs").mkdir(parents=True, exist_ok=True)
    failures = 0
    for pack in packs:
        if pack["state"] != "enabled":
            print(f"SKIPPED {pack['id']:<30} state={pack['state']}")
            continue
        log_path = run_dir / "logs" / f"{pack['id']}.verify.log"
        if args.warm and pack["engine"] != "codeql":
            print(f"SKIPPED {pack['id']:<30} engine={pack['engine']} has nothing to compile")
            continue
        if pack["engine"] == "codeql" and args.warm:
            if not pack.get("warm"):
                reason = pack.get("warm_skip_reason", "not registered for a warm compile")
                print(f"SKIPPED {pack['id']:<30} {reason}")
                continue
            if dry_run:
                pack_threads, pack_ram = _warm_settings(pack, threads, ram_mb)
                argv = _warm_argv(pack, pack["image"], compile_cache_volume(), cache_owner(), pack_threads, pack_ram)
                print(f"WOULD   {pack['id']:<30} compile {pack['path']} into {compile_cache_volume()} "
                      f"(--threads={pack_threads} --ram={pack_ram})")
                print("        " + " ".join(argv[:-1]) + " '<compile script>'")
                continue
            print(f"WARMING {pack['id']:<30} {pack['path']}", flush=True)
            ok, detail = _codeql_warm(pack, run_dir / "logs" / f"{pack['id']}.warm.log",
                                      threads=threads, ram_mb=ram_mb)
            log_path = run_dir / "logs" / f"{pack['id']}.warm.log"
        elif dry_run:
            print(f"WOULD   {pack['id']:<30} verify ({pack['verify']}) in {pack['image']}")
            continue
        elif pack["engine"] == "codeql":
            ok, detail = _codeql_check_only(pack, log_path)
        else:
            ok, detail = _engine_validate(pack, log_path)
        print(f"{'PASSED ' if ok else 'FAILED '}{pack['id']:<30} {detail}", flush=True)
        if not ok:
            failures += 1
            print(f"        log: {log_path.as_posix()}")
    print(f"summary=packs={len(packs)} failed={failures}" + (" dry_run=true" if dry_run else ""))
    return 1 if failures else 0


def runtime_args(policy: dict[str, Any]) -> list[str]:
    argv = [docker_binary(), "run", "--rm", "--network", policy["network"], "--read-only",
            "--user", policy["user"], "--pids-limit", str(policy["pids_limit"]),
            "--memory", policy["memory"], "--cpus", policy["cpus"]]
    for cap in policy["cap_drop"]:
        argv += ["--cap-drop", cap]
    for option in policy["security_opt"]:
        argv += ["--security-opt", option]
    for tmpfs in policy["tmpfs"]:
        argv += ["--tmpfs", tmpfs]
    return argv


def smoke(args: argparse.Namespace, catalog: dict[str, Any]) -> int:
    ids = selected_ids(args, catalog)
    with safe_path(catalog["runtime_policy"]).open("rb") as stream:
        policy = tomllib.load(stream)
    failures = 0
    for image_id in ids:
        item = catalog["by_id"][image_id]
        if item["kind"] == "base":
            command = ["/usr/bin/id", "-u"]
            expected = ["10001"]
        elif item["kind"] == "buildenv":
            command = list(item["probe_argv"])
            expected = list(item["probe_expect"])
        else:
            with safe_path(item["tool_manifest"]).open("rb") as stream:
                tool = tomllib.load(stream)
            command = tool["version_argv"]
            expected = [tool["version_expect"].format(version=tool["version"])]
        completed = subprocess.run(runtime_args(policy) + [item["tag"]] + command, cwd=ROOT,
                                   capture_output=True, text=True, encoding="utf-8", errors="replace",
                                   timeout=policy["timeout_seconds"], check=False)
        output = ((completed.stdout or "") + (completed.stderr or ""))[: policy["output_bytes"]]
        ok = completed.returncode == 0 and all(value in output for value in expected)
        print(f"{'PASSED' if ok else 'FAILED':7} {image_id} startup")
        failures += 0 if ok else 1
    if getattr(args, "functional", False):
        failures += functional_smoke(ids, catalog, policy)
    return 1 if failures else 0


def security_acceptance(args: argparse.Namespace, catalog: dict[str, Any]) -> int:
    ids = selected_ids(args, catalog)
    with safe_path(catalog["runtime_policy"]).open("rb") as stream:
        policy = tomllib.load(stream)
    run_dir = RUN_ROOT / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + f"-security-{os.getpid()}")
    workspace = run_dir / "workspace"
    scratch = run_dir / "scratch"
    workspace.mkdir(parents=True)
    scratch.mkdir()
    scratch.chmod(0o777)
    failures = 0
    results = []
    for image_id in ids:
        item = catalog["by_id"][image_id]
        inspect = subprocess.run([docker_binary(), "image", "inspect", item["tag"]], cwd=ROOT,
                                 capture_output=True, text=True, encoding="utf-8", errors="replace",
                                 timeout=30, check=False)
        reasons: list[str] = []
        if inspect.returncode != 0:
            reasons.append("image inspect failed")
        else:
            config = json.loads(inspect.stdout)[0].get("Config", {})
            if config.get("User") not in {"10001", "10001:10001"}:
                reasons.append(f"image user is {config.get('User')!r}")
            if config.get("Entrypoint"):
                reasons.append("image defines an entrypoint")
            if config.get("ExposedPorts"):
                reasons.append("image exposes ports")
            if config.get("Volumes"):
                reasons.append("image defines implicit volumes")
        marker = f"probe-{image_id}"
        command = ["/bin/sh", "-c",
                   'test "$(id -u)" = 10001 && grep -Eq "^CapEff:[[:space:]]+0+$" /proc/self/status '
                   '&& grep -Eq "^NoNewPrivs:[[:space:]]+1$" /proc/self/status '
                   f'&& ! touch /workspace/{marker} && ! touch /{marker} && touch /scratch/{marker}']
        argv = runtime_args(policy) + [
            "--mount", f"type=bind,src={workspace.resolve()},dst=/workspace,readonly",
            "--mount", f"type=bind,src={scratch.resolve()},dst=/scratch",
            item["tag"], *command,
        ]
        boundary = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace",
                                  timeout=policy["timeout_seconds"], check=False)
        if boundary.returncode != 0:
            reasons.append(f"runtime boundary probe exited {boundary.returncode}")
        if (workspace / marker).exists():
            reasons.append("read-only target was modified")
        if not (scratch / marker).is_file():
            reasons.append("writable scratch was not usable")
        result = {"id": image_id, "tag": item["tag"],
                  "status": "failed" if reasons else "passed", "reasons": reasons}
        results.append(result)
        print(f"{result['status'].upper():7} {image_id} security")
        failures += 1 if reasons else 0
    (run_dir / "summary.json").write_text(json.dumps({
        "schema": "appsec-review/container-security-summary/1",
        "policy": str(safe_path(catalog["runtime_policy"]).relative_to(ROOT)),
        "results": results,
    }, indent=2) + "\n", encoding="utf-8")
    return 1 if failures else 0


def functional_smoke(ids: list[str], catalog: dict[str, Any], policy: dict[str, Any]) -> int:
    """Run the first-wave fixtures with the same locked-down boundary as production."""
    fixtures = CONTAINERS / "fixtures"
    cases = {
        "tool-gitleaks": ("gitleaks", ["/opt/tool/bin/gitleaks", "dir", "/workspace",
                            "--redact", "--no-banner", "--report-format", "json", "--report-path",
                            "/scratch/result.json", "--exit-code", "0"], {0}, "result.json", "leak.txt"),
        "tool-semgrep": ("semgrep", ["/opt/tool/bin/semgrep", "scan", "--metrics=off",
                           "--disable-version-check", "--oss-only", "--config", "/workspace/rules.yml",
                           "--json", "--output", "/scratch/result.json", "/workspace/vulnerable.py"],
                          {0}, "result.json", "appsec-review.fixture.python-eval"),
        "tool-opengrep": ("semgrep", ["/opt/tool/opengrep/opengrep.bin", "scan", "--disable-version-check",
                            "--config", "/workspace/rules.yml", "--json", "--output", "/scratch/result.json",
                            "/workspace/vulnerable.py"], {0}, "result.json", "appsec-review.fixture.python-eval"),
        "tool-infer": ("infer", ["/opt/infer/bin/infer", "run", "--no-progress-bar",
                          "--results-dir", "/scratch/infer-out", "--compilation-database",
                          "/workspace/compile_commands.json"],
                         {0}, "infer-out/report.json", "NULLPTR_DEREFERENCE"),
        "tool-syft": ("syft", ["/opt/tool/bin/syft", "scan", "dir:/workspace", "-o",
                       "cyclonedx-json=/scratch/result.json"], {0}, "result.json", "appsec-review-fixture"),
        "tool-hadolint": ("hadolint", ["/opt/tool/bin/hadolint", "--format", "json",
                           "/workspace/Dockerfile"], {1}, None, "DL3007"),
        "tool-checkov": ("checkov", ["/opt/tool/bin/checkov", "-f", "/workspace/main.tf", "-o",
                          "json", "--quiet"], {1}, None, "CKV_AWS"),
        "tool-trivy": ("trivy", ["/opt/tool/bin/trivy", "config", "--skip-check-update", "--format",
                         "json", "--output", "/scratch/result.json", "/workspace"],
                        {0}, "result.json", "Misconfigurations"),
        "tool-cppcheck": ("cppcheck", ["/opt/cppcheck/bin/cppcheck", "--enable=warning,style,performance,portability",
                              "--xml", "--xml-version=2", "/workspace/vulnerable.cpp"],
                             {0}, None, "arrayIndexOutOfBounds"),
        "tool-clangd-indexer": ("clangd-indexer", ["/opt/clangd/clangd_23.1.0/bin/clangd-indexer",
                                   "--executor=all-TUs", "--format=yaml",
                                   "/workspace/compile_commands.json"],
                                  {0}, None, "Name:            clang_cl_entry"),
        "tool-report-latex": ("report-latex", ["/opt/tool/bin/render-pdf", "/workspace", "/template"],
                              {0}, "report.txt", "appsec-report smoke value"),
        "tool-pmd": ("pmd", ["/opt/pmd/bin/pmd", "check", "--no-cache", "--no-progress",
                       "--format", "json", "--report-file", "/scratch/result.json", "--rulesets",
                       "/rules/java-security.xml", "--dir", "/workspace/Vulnerable.java"],
                      {0, 4}, "result.json", "RuntimeCommandExecution"),
    }
    failures = 0
    run_dir = RUN_ROOT / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + f"-smoke-{os.getpid()}")
    run_dir.mkdir(parents=True, exist_ok=False)
    for image_id in ids:
        if image_id not in cases:
            continue
        fixture_name, command, exit_codes, result_file, expected = cases[image_id]
        output_dir = run_dir / image_id
        output_dir.mkdir()
        output_dir.chmod(0o777)
        source = (fixtures / fixture_name).resolve()
        argv = runtime_args(policy) + [
            "--mount", f"type=bind,src={source},dst=/workspace,readonly",
            "--mount", f"type=bind,src={output_dir.resolve()},dst=/scratch",
        ]
        if image_id == "tool-report-latex":
            argv += ["--mount", f"type=bind,src={(CONTAINERS / 'report' / 'latex' / 'template').resolve()},dst=/template,readonly"]
        if image_id == "tool-pmd":
            argv += ["--mount", f"type=bind,src={(ROOT / 'rules' / 'pmd').resolve()},dst=/rules,readonly"]
        argv += [catalog["by_id"][image_id]["tag"], *command]
        completed = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace",
                                   timeout=policy["timeout_seconds"], check=False)
        observed = ((completed.stdout or "") + (completed.stderr or ""))[: policy["output_bytes"]]
        if result_file and (output_dir / result_file).is_file():
            observed += (output_dir / result_file).read_text(encoding="utf-8", errors="replace")
        (output_dir / "command.log").write_text(observed, encoding="utf-8")
        ok = completed.returncode in exit_codes and expected in observed
        print(f"{'PASSED' if ok else 'FAILED':7} {image_id} functional")
        failures += 0 if ok else 1
    # OSV requires a separately synchronized immutable database snapshot. Bind the resolved snapshot,
    # never a mutable cache. Its verification is recorded as a gap when the feed is unavailable.
    if "tool-osv-scanner" in ids:
        current = ROOT / "data" / "feeds" / "osv" / "current.json"
        ok = False
        if current.is_file():
            pointer = json.loads(current.read_text(encoding="utf-8"))
            snapshot = ROOT / "data" / "feeds" / "osv" / "snapshots" / pointer["snapshot_id"]
            manifest = json.loads((snapshot / "manifest.json").read_text(encoding="utf-8"))
            source_info = manifest["files"]["sources/PyPI.zip"]
            source_zip = snapshot / "sources" / "PyPI.zip"
            source_valid = (source_zip.stat().st_size == source_info["size_bytes"] and
                            hashlib.sha256(source_zip.read_bytes()).hexdigest() == source_info["sha256"])
            fixture = (fixtures / "osv").resolve()
            output_dir = run_dir / "tool-osv-scanner"
            output_dir.mkdir(exist_ok=True)
            output_dir.chmod(0o777)
            database = output_dir / "database" / "osv-scanner" / "PyPI"
            database.mkdir(parents=True)
            shutil.copyfile(source_zip, database / "all.zip")
            argv = runtime_args(policy) + [
                "--env", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/inputs/osv-db",
                "--mount", f"type=bind,src={fixture},dst=/workspace,readonly",
                "--mount", f"type=bind,src={(output_dir / 'database').resolve()},dst=/inputs/osv-db,readonly",
                "--mount", f"type=bind,src={output_dir.resolve()},dst=/scratch",
                catalog["by_id"]["tool-osv-scanner"]["tag"], "/opt/tool/bin/osv-scanner", "scan",
                "--experimental-offline", "--format", "json", "--output",
                "/scratch/result.json", "--sbom", "/workspace/sbom.cdx.json",
            ]
            completed = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                                       encoding="utf-8", errors="replace",
                                       timeout=policy["timeout_seconds"], check=False)
            result = output_dir / "result.json"
            observed = result.read_text(encoding="utf-8", errors="replace") if result.is_file() else ""
            (output_dir / "command.log").write_text(
                ((completed.stdout or "") + (completed.stderr or "") + observed), encoding="utf-8")
            ok = source_valid and completed.returncode in {0, 1} and "django" in observed
        print(f"{'PASSED' if ok else 'FAILED':7} tool-osv-scanner functional-offline-db")
        failures += 0 if ok else 1
    return failures


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError(f"must be a positive integer: {value}")
    return number


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)
    listing = sub.add_parser("list")
    listing.add_argument("ids", nargs="*")
    listing.add_argument("--json", action="store_true")
    sub.add_parser("validate")
    packs = sub.add_parser("query-packs")
    packs.add_argument("ids", nargs="*")
    packs.add_argument("--warm", action="store_true",
                       help="really compile warm-registered CodeQL packs into the persistent compile cache "
                            "(minutes when cold) instead of the type-check-only verification")
    packs.add_argument("--language", action="append", metavar="LANG",
                       help="only packs for these languages (repeatable or comma-separated, e.g. go,java)")
    packs.add_argument("--threads", type=_positive_int, metavar="N",
                       help=f"--warm: codeql query compile threads (default {WARM_THREADS})")
    packs.add_argument("--ram", type=_positive_int, metavar="MB",
                       help=f"--warm: codeql query compile --ram in MB (default {WARM_RAM_MB})")
    packs.add_argument("--dry-run", action="store_true",
                       help="print what would be compiled or verified, with the docker command, and run nothing")
    packs.add_argument("--allow-concurrent", action="store_true",
                       help="--warm: start even when another CodeQL compile container is running")
    for name in ("build", "smoke", "security"):
        command = sub.add_parser(name)
        command.add_argument("ids", nargs="*")
        command.add_argument("--all", action="store_true")
        if name == "build":
            command.add_argument("--continue-on-error", action="store_true")
            command.add_argument("--jobs", type=int, default=2)
            command.add_argument("--timeout-seconds", type=int, default=BUILD_TIMEOUT_SECONDS,
                                 help="per-image docker build timeout")
        elif name == "smoke":
            command.add_argument("--functional", action="store_true")
    return root


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["build", "--all"]
    elif argv[0] == "--list":
        argv[0] = "list"
    elif argv[0] == "--validate-only":
        argv[0] = "validate"
    args = parser().parse_args(argv)
    catalog = load_catalog()
    if args.command == "query-packs":
        return query_packs(args, catalog)
    if args.command == "list":
        items = catalog["images"]
        if args.ids:
            wanted = set(args.ids)
            items = [item for item in items if item["id"] in wanted]
        if args.json:
            print(json.dumps([{"id": item["id"], "state": item["state"],
                               "tag": item.get("tag"), "dependencies": item.get("dependencies", [])}
                              for item in items], sort_keys=True))
        else:
            for item in items:
                print(f"{item['id']:30} {item['state']:9} {item.get('tag', '-')}")
        return 0
    errors = validate(catalog)
    if errors:
        for error in errors:
            print(f"ERROR {error}", file=sys.stderr)
        return 1
    if args.command == "validate":
        enabled = sum(item["state"] == "enabled" for item in catalog["images"])
        print(f"VALID catalog={CATALOG.relative_to(ROOT)} enabled={enabled} audited=42")
        return 0
    if args.command == "build":
        return execute_build(args, catalog)
    if args.command == "security":
        return security_acceptance(args, catalog)
    return smoke(args, catalog)


if __name__ == "__main__":
    raise SystemExit(main())
