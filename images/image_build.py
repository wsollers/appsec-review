#!/usr/bin/env python3
"""Build tool Docker images natively on the host, one independent build at a time.

Every image folder under ``images/<name>/`` may hold an ``image.json`` (schema
``appsec-review/image-build/1``) that declares one or more builds: tag, Dockerfile, build
arguments, images it needs first, fetch steps (a checksummed download or a shallow git clone) and a
timeout. Each build is independent: its own attempt directory, lock, logs and config overrides.
This script has no Dagster or orchestrator dependency and runs anything only inside ``docker build``.

State lives under ``images/.build-state/<image_id>/`` (override: APPSEC_IMAGE_BUILD_STATE):

    lock                          exclusive; a live or crashed build holds it, never stolen silently
    latest.json                   last SUCCESS (fingerprint, tag, image id); never written on failure
    attempts/<attempt_id>/        status.json, plan.json, result.json, command.json, logs/

Outcomes: OK, REUSED (fingerprint unchanged and the image still exists), BLOCKED (a precondition was
not met; nothing was built), FAILED (fetch, build, timeout or verification failed), CANCELED.
A terminal record is always written before the error is reported, with the log tail attached.

    python -B images/image_build.py list
    python -B images/image_build.py build audit-codeql [--no-cache] [--force] [--tag T]
                                       [--build-arg K=V] [--docker-context C] [--timeout-seconds N]
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import urllib.request
import uuid
from typing import Any

ROOT = Path(__file__).resolve().parent
SCHEMA = "appsec-review/image-build/1"
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+\Z")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*\Z")
BUILD_KEYS = {"image_id", "tag", "dockerfile", "context", "build_args", "requires_images",
              "prebuild", "timeout_seconds"}
SKIP_DIRS = {".git", "__pycache__"}


class Blocked(RuntimeError):
    """A precondition was not met; nothing was built."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name("." + uuid.uuid4().hex[:12] + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temp, path)


class BuildFailed(RuntimeError):
    """The build started and did not produce a verified image (terminal record already written)."""

    def __init__(self, code: str, message: str, tail: str = ""):
        super().__init__(f"{code}: {message}")
        self.code, self.tail = code, tail


def images_root() -> Path:
    return Path(os.environ.get("APPSEC_IMAGES_ROOT", ROOT))


def state_root() -> Path:
    return Path(os.environ.get("APPSEC_IMAGE_BUILD_STATE", images_root() / ".build-state"))


def _relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith(("/", "\\")) or ":" in value:
        raise ValueError(f"{label} must be a relative path")
    parts = value.replace("\\", "/").split("/")
    if any(part in ("", "..") for part in parts if part != ".") or value == "..":
        raise ValueError(f"{label} may not contain empty or '..' segments")
    return value


def _validate_build(raw: Any, folder: Path) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != BUILD_KEYS:
        raise ValueError(f"{folder.name}: a build needs exactly the keys {sorted(BUILD_KEYS)}")
    if not isinstance(raw["image_id"], str) or not ID_RE.match(raw["image_id"]):
        raise ValueError(f"{folder.name}: bad image_id")
    if not isinstance(raw["tag"], str) or not TAG_RE.match(raw["tag"]):
        raise ValueError(f"{raw['image_id']}: bad tag")
    _relative(raw["dockerfile"], f"{raw['image_id']} dockerfile")
    _relative(raw["context"], f"{raw['image_id']} context")
    args = raw["build_args"]
    if not isinstance(args, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                          for k, v in args.items()):
        raise ValueError(f"{raw['image_id']}: build_args must map strings to strings")
    if not isinstance(raw["requires_images"], list) or any(
            not isinstance(tag, str) or not TAG_RE.match(tag) for tag in raw["requires_images"]):
        raise ValueError(f"{raw['image_id']}: requires_images must be a list of image tags")
    timeout = raw["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 60 <= timeout <= 86400:
        raise ValueError(f"{raw['image_id']}: timeout_seconds must be 60..86400")
    if not isinstance(raw["prebuild"], list):
        raise ValueError(f"{raw['image_id']}: prebuild must be a list")
    for step in raw["prebuild"]:
        kind = step.get("kind") if isinstance(step, dict) else None
        if kind == "download":
            if set(step) != {"kind", "url", "dest", "sha256", "bytes"} or not str(step["url"]).startswith("https://") \
                    or not re.fullmatch(r"[0-9a-f]{64}", str(step["sha256"])) or not isinstance(step["bytes"], int):
                raise ValueError(f"{raw['image_id']}: malformed download step")
        elif kind == "git_clone":
            if set(step) != {"kind", "url", "dest", "depth"} or not str(step["url"]).startswith("https://") \
                    or not isinstance(step["depth"], int) or step["depth"] < 1:
                raise ValueError(f"{raw['image_id']}: malformed git_clone step")
        else:
            raise ValueError(f"{raw['image_id']}: unknown prebuild kind {kind!r}")
        _relative(step["dest"], f"{raw['image_id']} prebuild dest")
    return dict(raw, folder=str(folder))


def load_builds_from(config: Path) -> dict[str, dict[str, Any]]:
    document = json.loads(config.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema") != SCHEMA \
            or not isinstance(document.get("builds"), list) or set(document) != {"schema", "builds"}:
        raise ValueError(f"not a {SCHEMA} document")
    found: dict[str, dict[str, Any]] = {}
    for raw in document["builds"]:
        build = _validate_build(raw, config.parent)
        if build["image_id"] in found:
            raise ValueError(f"duplicate image_id {build['image_id']}")
        found[build["image_id"]] = build
    return found


def load_builds(root: Path | None = None) -> dict[str, dict[str, Any]]:
    """Every declared build keyed by image_id (strict: any malformed file raises)."""
    root = Path(root) if root else images_root()
    builds: dict[str, dict[str, Any]] = {}
    if not root.is_dir():
        return builds
    for config in sorted(root.glob("*/image.json")):
        for image_id, build in load_builds_from(config).items():
            if image_id in builds:
                raise ValueError(f"duplicate image_id {image_id}")
            builds[image_id] = build
    return builds


def effective(build: dict[str, Any], override: dict[str, Any] | None = None) -> dict[str, Any]:
    """The build merged with per-run config (tag, build_args, no_cache, timeout, docker_context)."""
    override = override or {}
    unknown = set(override) - {"tag", "build_args", "no_cache", "timeout_seconds", "docker_context"}
    if unknown:
        raise Blocked(f"unknown build config keys: {sorted(unknown)}")
    merged = dict(build)
    if override.get("tag"):
        if not TAG_RE.match(override["tag"]):
            raise Blocked("config tag is not a valid image tag")
        merged["tag"] = override["tag"]
    merged["build_args"] = {**build["build_args"], **(override.get("build_args") or {})}
    if override.get("timeout_seconds"):
        merged["timeout_seconds"] = int(override["timeout_seconds"])
    merged["no_cache"] = bool(override.get("no_cache"))
    merged["docker_context"] = override.get("docker_context") or None
    return merged


def _docker() -> Path:
    found = os.environ.get("APPSEC_DOCKER_BIN") or shutil.which("docker")
    if not found:
        raise Blocked("DOCKER_CLI_MISSING: no docker executable on PATH (set APPSEC_DOCKER_BIN)")
    return Path(found).resolve()


def _docker_prefix(build: dict[str, Any]) -> list[str]:
    return ["--context", build["docker_context"]] if build.get("docker_context") else []


def _run(argv: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)


def image_id_of(build: dict[str, Any], tag: str) -> str | None:
    result = _run([str(_docker()), *_docker_prefix(build), "image", "inspect", "--format", "{{.Id}}", tag], 60)
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def _file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fingerprint(build: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Hash everything that decides the built image: the folder's files (except fetched inputs, which
    are identified by their declared checksum or clone commit), the effective config, and the image
    ids of required images."""
    folder = Path(build["folder"])
    fetched = {step["dest"].replace("\\", "/").strip("/") for step in build["prebuild"]}
    files: list[list[str]] = []
    for current, dirs, names in os.walk(folder):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            path = Path(current, name)
            rel = path.relative_to(folder).as_posix()
            if name == "image.json" and current == str(folder):
                continue
            if any(rel == dest or rel.startswith(dest + "/") for dest in fetched):
                continue
            files.append([rel, _file_hash(path)])
    prebuild = []
    for step in build["prebuild"]:
        entry = dict(step)
        clone = folder / step["dest"]
        if step["kind"] == "git_clone" and (clone / ".git").exists():
            head = _run(["git", "-C", str(clone), "rev-parse", "HEAD"], 30)
            entry["head"] = head.stdout.strip() if head.returncode == 0 else "unknown"
        prebuild.append(entry)
    required = {tag: image_id_of(build, tag) for tag in build["requires_images"]}
    plan = {"image_id": build["image_id"], "tag": build["tag"], "dockerfile": build["dockerfile"],
            "context": build["context"], "build_args": build["build_args"], "files": files,
            "prebuild": prebuild, "requires": required}
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest(), plan


def preflight(build: dict[str, Any]) -> Path:
    """Preconditions that need no fetched input: a reachable daemon and the images this one builds on."""
    docker = _docker()
    info = _run([str(docker), *_docker_prefix(build), "info", "--format", "{{.ServerVersion}}"], 60)
    if info.returncode != 0:
        raise Blocked("DOCKER_UNREACHABLE: docker info failed: " + (info.stderr.strip()[-300:] or "no output"))
    missing = [tag for tag in build["requires_images"] if image_id_of(build, tag) is None]
    if missing:
        raise Blocked("REQUIRED_IMAGE_MISSING: build these first: " + ", ".join(missing))
    return docker


def check_dockerfile(build: dict[str, Any]) -> None:
    """Checked after the fetch steps: a cloned image (ScanCode) only has its Dockerfile afterwards."""
    dockerfile = Path(build["folder"]) / build["context"] / build["dockerfile"]
    if not dockerfile.is_file():
        raise Blocked(f"DOCKERFILE_MISSING: {dockerfile}")


def _fetch(step: dict[str, Any], folder: Path, log) -> None:
    dest = folder / step["dest"]
    if step["kind"] == "git_clone":
        if dest.exists():
            log(f"git_clone: {dest} exists, using it as-is")
            return
        log(f"git clone --depth {step['depth']} {step['url']}")
        done = _run(["git", "clone", "--depth", str(step["depth"]), step["url"], str(dest)], 1800)
        if done.returncode != 0:
            shutil.rmtree(dest, ignore_errors=True)
            raise BuildFailed("PREBUILD_CLONE_FAILED", "git clone failed", done.stderr[-2000:])
        return
    if dest.is_file() and _file_hash(dest) == step["sha256"]:
        log(f"download: {dest.name} already present and verified")
        return
    if dest.exists():
        raise BuildFailed("PREBUILD_FILE_CORRUPT", f"{dest} exists but does not match the declared sha256; delete it and rebuild")
    part = dest.with_name(dest.name + ".part")
    log(f"download {step['url']} -> {dest.name} ({step['bytes']} bytes expected)")
    try:
        with urllib.request.urlopen(step["url"], timeout=120) as response, part.open("wb") as stream:
            shutil.copyfileobj(response, stream, 1024 * 1024)
    except Exception as exc:  # network, TLS, disk
        part.unlink(missing_ok=True)
        raise BuildFailed("PREBUILD_DOWNLOAD_FAILED", f"{type(exc).__name__}: {exc}") from exc
    if part.stat().st_size != step["bytes"] or _file_hash(part) != step["sha256"]:
        part.unlink(missing_ok=True)
        raise BuildFailed("PREBUILD_CHECKSUM_MISMATCH", f"{dest.name} does not match the declared size/sha256")
    part.replace(dest)


def _tail(path: Path, lines: int = 40) -> str:
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - 32768))
            return "\n".join(stream.read().decode("utf-8", errors="replace").splitlines()[-lines:])
    except OSError:
        return ""


def _kill(process: subprocess.Popen) -> None:
    """Stop the docker client and its whole process group; escalate if it ignores SIGTERM."""
    def send(sig: int) -> None:
        try:
            os.killpg(process.pid, sig) if hasattr(os, "killpg") else process.send_signal(sig)
        except (ProcessLookupError, PermissionError):
            pass
    send(signal.SIGTERM)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        send(getattr(signal, "SIGKILL", signal.SIGTERM))
        process.wait()


def _execute(argv: list[str], cwd: Path, log_dir: Path, timeout: int, env: dict[str, str]) -> dict[str, Any]:
    """Run one fixed argv (no shell), stdout/stderr straight to files, bounded by the timeout."""
    log_dir.mkdir(parents=True, exist_ok=True)
    meta: dict[str, Any] = {"argv": argv, "cwd": str(cwd), "started_at": now(), "timeout_seconds": timeout,
                            "exit_code": None, "timed_out": False, "error": None}
    with (log_dir / "stdout.log").open("wb") as out, (log_dir / "stderr.log").open("wb") as err:
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=out, stderr=err,
                                       start_new_session=hasattr(os, "killpg"))
        except OSError as exc:
            meta["error"] = f"{type(exc).__name__}: {exc}"
            return meta
        try:
            meta["exit_code"] = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            meta["timed_out"] = True
            _kill(process)
            meta["exit_code"] = process.returncode
        except BaseException:
            _kill(process)
            raise
    meta["finished_at"] = now()
    return meta


def _environment() -> dict[str, str]:
    keep = {"PATH", "HOME", "LANG", "LC_ALL", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "XDG_RUNTIME_DIR"}
    env = {k: v for k, v in os.environ.items() if k in keep}
    env["DOCKER_BUILDKIT"] = "1"
    return env


def run(image_id: str, override: dict[str, Any] | None = None, *, force: bool = False,
        root: Path | None = None) -> dict[str, Any]:
    builds = load_builds(root)
    if image_id not in builds:
        raise Blocked(f"UNKNOWN_IMAGE: {image_id}")
    build = effective(builds[image_id], override)
    base = state_root() / image_id
    base.mkdir(parents=True, exist_ok=True)
    lock = base / "lock"
    attempt_id = now().replace(":", "").replace("+00:00", "Z").replace(".", "") + "-" + uuid.uuid4().hex[:8]
    attempt = base / "attempts" / attempt_id
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        holder = ""
        try:
            holder = lock.read_text(encoding="utf-8")[:300]
        except OSError:
            pass
        raise Blocked(f"BUILD_IN_PROGRESS: {lock} is held ({holder or 'unknown holder'}); remove it only if that build is dead") from None
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({"attempt_id": attempt_id, "pid": os.getpid(), "at": now()}, stream)
    (attempt / "logs").mkdir(parents=True)
    status: dict[str, Any] = {"schema": SCHEMA, "image_id": image_id, "tag": build["tag"], "attempt_id": attempt_id,
                              "started_at": now(), "status": "RUNNING"}
    atomic_json(attempt / "status.json", status)

    def finish(state: str, **extra: Any) -> dict[str, Any]:
        status.update({"status": state, "finished_at": now(), **extra})
        atomic_json(attempt / "status.json", status)
        atomic_json(attempt / "result.json", status)
        return dict(status)

    try:
        docker = preflight(build)
        folder = Path(build["folder"])
        notes = attempt / "logs" / "prebuild.log"

        def log(message: str) -> None:
            with notes.open("a", encoding="utf-8") as stream:
                stream.write(message + "\n")

        for step in build["prebuild"]:
            _fetch(step, folder, log)
        check_dockerfile(build)
        digest, plan = fingerprint(build)
        atomic_json(attempt / "plan.json", plan)
        status["fingerprint"] = digest
        latest = base / "latest.json"
        if not force and not build["no_cache"] and latest.is_file():
            try:
                previous = json.loads(latest.read_text(encoding="utf-8"))
            except ValueError:
                previous = {}
            current = image_id_of(build, build["tag"])
            if previous.get("fingerprint") == digest and current and previous.get("image_digest") == current:
                return finish("REUSED", image_digest=current, reused_attempt=previous.get("attempt_id"))
        context = (folder / build["context"]).resolve()
        dockerfile = (context / build["dockerfile"]).resolve()
        argv = [str(docker), *_docker_prefix(build), "build", "--progress=plain"]
        if build["no_cache"]:
            argv.append("--no-cache")
        for key in sorted(build["build_args"]):
            argv += ["--build-arg", f"{key}={build['build_args'][key]}"]
        argv += ["-f", str(dockerfile), "-t", build["tag"], str(context)]
        result = _execute(argv, context, attempt / "logs", build["timeout_seconds"], _environment())
        atomic_json(attempt / "command.json", result)
        tail = _tail(attempt / "logs" / "stderr.log") or _tail(attempt / "logs" / "stdout.log")
        if result.get("timed_out"):
            raise BuildFailed("BUILD_TIMEOUT", f"docker build exceeded {build['timeout_seconds']}s", tail)
        if result.get("error"):
            raise BuildFailed("BUILD_EXECUTION_ERROR", str(result["error"]), tail)
        if result.get("exit_code") != 0:
            raise BuildFailed("BUILD_FAILED", f"docker build exited {result.get('exit_code')}", tail)
        built = image_id_of(build, build["tag"])
        if not built:
            raise BuildFailed("IMAGE_NOT_FOUND_AFTER_BUILD", f"{build['tag']} was not present after a zero exit", tail)
        atomic_json(base / "latest.json", {"image_id": image_id, "tag": build["tag"], "fingerprint": digest,
                                            "image_digest": built, "attempt_id": attempt_id, "finished_at": now()})
        return finish("OK", image_digest=built)
    except Blocked as exc:
        finish("BLOCKED", error=str(exc))
        raise
    except BuildFailed as exc:
        finish("FAILED", error=str(exc), code=exc.code, log_tail=exc.tail)
        raise
    except (KeyboardInterrupt, SystemExit):
        finish("CANCELED", error="canceled before the build finished")
        raise
    except Exception as exc:  # unexpected: still leave a terminal record
        finish("FAILED", error=f"{type(exc).__name__}: {exc}", code="UNEXPECTED")
        raise BuildFailed("UNEXPECTED", f"{type(exc).__name__}: {exc}") from exc
    finally:
        try:
            lock.unlink()
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    build = sub.add_parser("build")
    build.add_argument("image_id", nargs="+")
    build.add_argument("--no-cache", action="store_true")
    build.add_argument("--force", action="store_true")
    build.add_argument("--tag")
    build.add_argument("--build-arg", action="append", default=[], metavar="K=V")
    build.add_argument("--docker-context")
    build.add_argument("--timeout-seconds", type=int)
    args = parser.parse_args(argv)
    if args.command == "list":
        for image_id, item in sorted(load_builds().items()):
            needs = f"  needs {', '.join(item['requires_images'])}" if item["requires_images"] else ""
            print(f"{image_id:28} {item['tag']}{needs}")
        return 0
    failures = 0
    for image_id in args.image_id:
        override = {"tag": args.tag if len(args.image_id) == 1 else None, "no_cache": args.no_cache,
                    "docker_context": args.docker_context, "timeout_seconds": args.timeout_seconds,
                    "build_args": dict(item.split("=", 1) for item in args.build_arg)}
        try:
            outcome = run(image_id, override, force=args.force)
            print(f"{outcome['status']:8} {image_id} -> {outcome['tag']}")
        except (Blocked, BuildFailed) as exc:
            failures += 1
            print(f"FAILED   {image_id}: {exc}", file=sys.stderr)
            if isinstance(exc, BuildFailed) and exc.tail:
                print(exc.tail, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
