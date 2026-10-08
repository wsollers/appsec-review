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


def fetch_one(item: dict[str, Any], log) -> None:
    lock_name = item.get("assets_lock")
    if not lock_name:
        return
    context = safe_path(item["context"])
    lock = json.loads(safe_path(lock_name).read_text(encoding="utf-8"))
    for artifact in lock.get("artifacts", []):
        target = (context / artifact["path"]).resolve()
        target.relative_to(context.resolve())
        target.parent.mkdir(parents=True, exist_ok=True)
        expected_hash = artifact["sha256"]
        expected_size = artifact["bytes"]
        if target.is_file() and target.stat().st_size == expected_size:
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
            if actual == expected_hash:
                log.write(f"CURRENT {artifact['path']}\n")
                continue
        temporary = target.with_suffix(target.suffix + ".partial")
        temporary.unlink(missing_ok=True)
        request = urllib.request.Request(artifact["url"], headers={"User-Agent": "appsec-review-container-builder/1"})
        digest = hashlib.sha256()
        size = 0
        with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as stream:
            while chunk := response.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
                stream.write(chunk)
        if size != expected_size or digest.hexdigest() != expected_hash:
            temporary.unlink(missing_ok=True)
            raise RuntimeError(f"asset verification failed: {artifact['url']}")
        temporary.replace(target)
        log.write(f"FETCHED {artifact['path']} {size} {expected_hash}\n")


def docker_binary() -> str:
    return os.environ.get("APPSEC_DOCKER_BIN", "docker")


def run_logged(argv: list[str], log_path: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write("argv=" + json.dumps(argv) + "\n")
        stream.flush()
        return subprocess.run(argv, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                              text=True, timeout=timeout, check=False)


def build_one(item: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    started = time.monotonic()
    image_id = item["id"]
    fetch_log = run_dir / "logs" / f"{image_id}.fetch.log"
    build_log = run_dir / "logs" / f"{image_id}.build.log"
    result: dict[str, Any] = {
        "id": image_id, "tag": item["tag"], "status": "failed", "digest": None,
        "fetch_log": str(fetch_log.relative_to(ROOT)), "build_log": str(build_log.relative_to(ROOT)),
    }
    try:
        fetch_log.parent.mkdir(parents=True, exist_ok=True)
        with fetch_log.open("w", encoding="utf-8", newline="\n") as log:
            fetch_one(item, log)
        context = safe_path(item["context"])
        argv = [docker_binary(), "build", "--network=none", "--pull=false", "--file",
                str(context / item["dockerfile"]), "--tag", item["tag"]]
        for key, value in sorted(item.get("build_args", {}).items()):
            argv += ["--build-arg", f"{key}={value}"]
        argv.append(str(context))
        completed = run_logged(argv, build_log, 1800)
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
                    running[pool.submit(build_one, catalog["by_id"][image_id], run_dir)] = image_id
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
        "catalog": str(CATALOG.relative_to(ROOT)), "jobs": jobs,
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
            expected = "10001"
        else:
            with safe_path(item["tool_manifest"]).open("rb") as stream:
                tool = tomllib.load(stream)
            command = tool["version_argv"]
            expected = tool["version_expect"].format(version=tool["version"])
        completed = subprocess.run(runtime_args(policy) + [item["tag"]] + command, cwd=ROOT,
                                   capture_output=True, text=True, encoding="utf-8", errors="replace",
                                   timeout=policy["timeout_seconds"], check=False)
        output = ((completed.stdout or "") + (completed.stderr or ""))[: policy["output_bytes"]]
        ok = completed.returncode == 0 and expected in output
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
        "tool-syft": ("syft", ["/opt/tool/bin/syft", "scan", "dir:/workspace", "-o",
                       "cyclonedx-json=/scratch/result.json"], {0}, "result.json", "appsec-review-fixture"),
        "tool-hadolint": ("hadolint", ["/opt/tool/bin/hadolint", "--format", "json",
                           "/workspace/Dockerfile"], {1}, None, "DL3007"),
        "tool-checkov": ("checkov", ["/opt/tool/bin/checkov", "-f", "/workspace/main.tf", "-o",
                          "json", "--quiet"], {1}, None, "CKV_AWS"),
        "tool-trivy": ("trivy", ["/opt/tool/bin/trivy", "config", "--skip-check-update", "--format",
                         "json", "--output", "/scratch/result.json", "/workspace"],
                        {0}, "result.json", "Misconfigurations"),
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
        source = (fixtures / fixture_name).resolve()
        argv = runtime_args(policy) + [
            "--mount", f"type=bind,src={source},dst=/workspace,readonly",
            "--mount", f"type=bind,src={output_dir.resolve()},dst=/scratch",
            catalog["by_id"][image_id]["tag"], *command,
        ]
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


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)
    listing = sub.add_parser("list")
    listing.add_argument("ids", nargs="*")
    listing.add_argument("--json", action="store_true")
    sub.add_parser("validate")
    for name in ("build", "smoke", "security"):
        command = sub.add_parser(name)
        command.add_argument("ids", nargs="*")
        command.add_argument("--all", action="store_true")
        if name == "build":
            command.add_argument("--continue-on-error", action="store_true")
            command.add_argument("--jobs", type=int, default=2)
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
