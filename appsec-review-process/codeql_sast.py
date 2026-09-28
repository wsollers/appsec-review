"""Deterministic worker for ``02-codeql-sast``: CodeQL security suites, offline, per language.

William (2026-09-28): CodeQL always runs; there is no license gate in the pipeline. The pinned
``audit-codeql`` image carries the CodeQL bundle (CLI plus the ``codeql/<lang>-queries`` packs at
matching versions), so database creation and the ``<lang>-security-extended`` suite need no
network. One B13 container per detected language creates a database with ``--build-mode none``
and analyzes it to SARIF; Python normalizes SARIF results into leads (rule id, pinned rule name,
CWE tags, path, lines, fresh source hash). Raw SARIF messages stay in the immutable attempt, as in
02-source-sast and 02-native-sast: result messages quote target code and are not promoted.

C/C++ uses ``--build-mode none`` (decision recorded in ADR-0017): it needs no accepted native
build (freeciv21 and doom3-bfg had zero built units), runs in the pinned CodeQL image without
the per-target build image, and never executes a target build. The cost is fidelity (no
build-driven macro, include or template resolution), recorded as a coverage gap. Go has no
build-mode none in CodeQL and stays a gap (gosec covers Go in 02-source-sast).

ADR-0013: a language whose container times out, runs out of memory or exits non-zero is a
coverage gap; the job publishes OK_WITH_GAPS. Integrity failures still block.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import threading
from typing import Any
from urllib.parse import unquote

import tunables
import container_execution as ce
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json, run_path
import permission_capabilities as pc
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document

JOB = "02-codeql-sast"
DAGSTER_JOB = "codeql_sast"
CONTRACT = "codeql-sast"
RESULT = "codeql-sast.json"
RECEIPTS = "b13-receipts.json"
SUMMARY = "codeql-sast-summary.md"
PERMISSION = "permission.json"
LINEAGE = "lineage.json"
SCHEMA = "appsec-review/codeql-sast/1"
IMAGE_ID = "audit-codeql"
IMAGE_ROOT = ROOT.parent / "images" / IMAGE_ID
TOOL_METADATA = IMAGE_ROOT / "tool.json"
TEMPLATE = ROOT / "registry" / "job-templates" / f"{JOB}.json"
SARIF = "scratch/codeql.sarif"
CATEGORY = "codeql-security-query"
CODE_FILES = (
    "codeql_sast.py", "container_execution.py", "permission_capabilities.py",
    "publish_job_output.py", "validate_job_output.py",
    "registry/output-contracts/codeql-sast.json", "registry/job-templates/02-codeql-sast.json",
)
# Suffixes per CodeQL extractor. Order is the execution order.
LANGUAGE_SUFFIXES = {
    "cpp": (".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"),
    "csharp": (".cs",),
    "go": (".go",),
    "java": (".java",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"),
    "python": (".py",),
    "ruby": (".rb",),
}
BUILD_MODE_NONE = ("cpp", "csharp", "java", "javascript", "python", "ruby")
OFFLINE_UNSUPPORTED = {
    "go": ("CodeQL go not run: Go extraction has no build-mode none (autobuild needs the Go toolchain "
           "and module downloads, which the offline boundary forbids); gosec covers Go in 02-source-sast."),
}
FIDELITY_GAPS = {
    "cpp": ("CodeQL cpp ran with --build-mode none: no compiler invocation, so macros, include paths and "
            "templates are resolved heuristically; treat missing results as unexamined, not clean."),
    "csharp": "CodeQL csharp ran with --build-mode none: unresolved references lower recall.",
    "java": "CodeQL java ran with --build-mode none: unresolved dependencies lower recall.",
}
GAP_CAUSES = ("TIMEOUT", "OOM_KILLED", "CONTAINER_EXIT_NONZERO")
_CWE = re.compile(r"external/cwe/cwe-0*([1-9][0-9]{0,5})\Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _producer_receipts(inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    template = read_json(TEMPLATE)
    permissions = template.get("permissions")
    if (template.get("job_template_id") != JOB or not isinstance(permissions, list) or
            not permissions or len(permissions) != len(set(permissions)) or
            not all(isinstance(item, str) and item for item in permissions)):
        raise Blocked(f"{JOB}: canonical template permissions are invalid")
    common = {"run_id": inputs["run_id"], "job_id": JOB,
              "source_snapshot_sha256": inputs["source_snapshot_sha256"]}
    return (
        {"schema": "appsec-review/producer-permission-receipt/1.0", **common, "permissions": permissions},
        {"schema": "appsec-review/producer-lineage-receipt/1.0", **common,
         "build_lineage_sha256": "sha256:" + digest(inputs)},
    )


def _source_snapshot(run_id: str) -> str:
    path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not path.is_file():
        raise Blocked(f"{JOB}: staged artifact-manifest.json is required")
    return "sha256:" + file_hash(path)


def _target(run_id: str) -> Path:
    manifest = read_json(run_path(run_id) / "inputs" / "artifact-manifest.json")
    value = manifest.get("target", {}).get("repo_path")
    path = Path(value) if isinstance(value, str) else Path()
    if not value or not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked(f"{JOB}: target.repo_path must be an absolute real checkout directory")
    return path.resolve()


def tool_metadata() -> tuple[dict[str, Any], str]:
    """Authenticated CodeQL metadata: tool.json must name the bundle whose sha256 the image build
    pins (image.json prebuild and the Dockerfile's sha256sum line)."""
    try:
        value = json.loads(TOOL_METADATA.read_text(encoding="utf-8"))
        build = json.loads((IMAGE_ROOT / "image.json").read_text(encoding="utf-8"))
        dockerfile = (IMAGE_ROOT / "Dockerfile").read_text(encoding="utf-8")
    except (OSError, json.JSONDecodeError) as exc:
        raise Blocked(f"{JOB}: authenticated CodeQL tool metadata is unavailable") from exc
    keys = ("image_id", "tool", "version", "executable", "version_argv", "bundle", "query_suites", "lane_script")
    bundle = value.get("bundle") if isinstance(value, dict) else None
    pinned = [step.get("sha256") for row in build.get("builds", []) if row.get("image_id") == IMAGE_ID
              for step in row.get("prebuild", [])]
    suites = value.get("query_suites") if isinstance(value, dict) else None
    if (any(key not in value for key in keys) or value["image_id"] != IMAGE_ID or value["tool"] != "codeql" or
            not isinstance(value["version"], str) or not re.fullmatch(r"[0-9][0-9A-Za-z.+_-]{0,31}", value["version"]) or
            value["version_argv"][:1] != [value["executable"]] or not isinstance(bundle, dict) or
            not isinstance(bundle.get("sha256"), str) or pinned != [bundle["sha256"]] or
            f'echo "{bundle["sha256"]}  bundle.tar.zst" | sha256sum -c -' not in dockerfile or
            not isinstance(suites, dict) or set(suites) != set(BUILD_MODE_NONE) or
            any(suite != f"codeql/{lang}-queries:codeql-suites/{lang}-security-extended.qls"
                for lang, suite in suites.items())):
        raise Blocked(f"{JOB}: CodeQL tool metadata is invalid or differs from the pinned image build")
    lane = value["lane_script"]
    script = IMAGE_ROOT / str(lane.get("source", "")) if isinstance(lane, dict) else None
    if (script is None or set(lane) != {"path", "source"} or not str(lane["source"]).startswith("scripts/") or
            lane["path"] != "/opt/scripts/" + PurePosixPath(lane["source"]).name or
            not script.is_file() or script.is_symlink() or "COPY scripts/ /opt/scripts/" not in dockerfile):
        raise Blocked(f"{JOB}: CodeQL lane script metadata is invalid")
    return {**value, "lane_script_sha256": "sha256:" + file_hash(script)}, "sha256:" + file_hash(TOOL_METADATA)


def detected_languages(paths: list[str]) -> list[str]:
    found = set()
    for path in paths:
        lower = path.lower()
        if lower.startswith(".git/") or "/.git/" in lower:
            continue
        for language, suffixes in LANGUAGE_SUFFIXES.items():
            if lower.endswith(suffixes):
                found.add(language)
    return [language for language in LANGUAGE_SUFFIXES if language in found]


def _limits() -> dict[str, int]:
    return tunables.container_limits(JOB)


def _analysis_tunables() -> dict[str, int]:
    threads, ram = tunables.value(JOB, "codeql_threads"), tunables.value(JOB, "codeql_ram_bytes")
    memory = _limits()["memory_bytes"]
    if (any(isinstance(item, bool) or not isinstance(item, int) or item < 1 for item in (threads, ram)) or
            ram < 1024 * 1024 or ram >= memory):
        raise Blocked(f"{JOB}: codeql_ram_bytes must be at least 1 MiB and below container_memory_bytes")
    return {"threads": threads, "ram_mb": ram // (1024 * 1024)}


def build_plan(languages: list[str], registry: dict[str, dict[str, Any]], metadata: dict[str, Any],
               metadata_sha256: str, analysis: dict[str, int]) -> list[dict[str, Any]]:
    image = registry.get(IMAGE_ID)
    image_digest = image.get("digest") if isinstance(image, dict) else None
    ready = (isinstance(image_digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is not None and
             image.get("image_id") == IMAGE_ID)
    plan = []
    for language in languages:
        row = {"language": language, "tool_id": f"codeql-{language}", "version": metadata["version"],
               "image_id": IMAGE_ID, "image_digest": image_digest if ready else None,
               "tool_metadata_sha256": metadata_sha256, "lane_script_sha256": metadata["lane_script_sha256"],
               "build_mode": None, "query_suite": None,
               "argv": [], "status": "READY", "gap": None}
        if language in OFFLINE_UNSUPPORTED:
            row.update(status="UNSUPPORTED_OFFLINE", gap=OFFLINE_UNSUPPORTED[language])
        elif not ready:
            row.update(status="UNAVAILABLE", gap=f"CodeQL {language} unavailable: authenticated pinned image "
                                                 f"{IMAGE_ID} has no current B16 record.")
        else:
            suite = metadata["query_suites"][language]
            row.update(build_mode="none", query_suite=suite,
                       argv=[metadata["lane_script"]["path"], language, "none", suite,
                             str(analysis["threads"]), str(analysis["ram_mb"])])
        plan.append(row)
    return plan


def _code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    values["schemas/codeql-sast.schema.json"] = file_hash(ROOT.parent / "schemas" / "codeql-sast.schema.json")
    return values


def _permission(run_id: str, source: str, at: str) -> dict[str, Any]:
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": JOB, "capabilities": []}
    context = {"run_id": run_id, "job_id": JOB, "source_snapshot_sha256": source,
               "now": at, "registry_ceiling": []}
    decision = pc.evaluate(requirement, [], context)
    pc.require_granted(decision, requirement=requirement, grants=[], context=context)
    return {"requirement": requirement, "grants": [], "decision": decision}


def current_inputs(run_id: str) -> dict[str, Any]:
    source = _source_snapshot(run_id)
    target = _target(run_id)
    metadata, metadata_sha256 = tool_metadata()
    registry = ce.load_image_registry(ce.IMAGES_DIR)
    paths = [path.relative_to(target).as_posix() for path in target.rglob("*")
             if path.is_file() and not path.is_symlink()]
    analysis = _analysis_tunables()
    return {
        "job": JOB, "run_id": run_id, "source_snapshot_sha256": source, "target_path": str(target),
        "tool_metadata_sha256": metadata_sha256,
        "permission_fingerprint_sha256": pc.input_fingerprint_component(
            _permission(run_id, source, _utc_now())["decision"]),
        "boundary_sha256": ce.boundary_sha256(),
        "limits": _limits(), "analysis": analysis,
        "plan": build_plan(detected_languages(paths), registry, metadata, metadata_sha256, analysis),
        "code": _code_hashes(),
    }


def _runtime(source: str) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise Blocked(f"{JOB}: Docker is unavailable")
    return ce.ContainerRuntime(
        docker_executable=defaults["docker_executable"], docker_host=None, images_dir=ce.IMAGES_DIR,
        host_flavor=defaults["host_flavor"], container_user=defaults["container_user"],
        source_snapshot_sha256=source, registry_ceiling=[], clock=_utc_now, cancel=threading.Event())


def _host(runtime: ce.ContainerRuntime) -> dict[str, Any]:
    return {"host_flavor": runtime.host_flavor, "docker_host": runtime.docker_host,
            "docker_executable": runtime.docker_executable, "container_user": runtime.container_user}


def _request(run_id: str, adapter_id: str, inputs: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    if plan.get("status") != "READY":
        raise Blocked(f"{JOB}: CodeQL {plan.get('language')} is not ready for execution")
    return {"schema": ce.REQUEST_ID, "run_id": run_id, "job_id": JOB, "attempt_id": adapter_id,
            "image": {"image_id": plan["image_id"], "digest": plan["image_digest"]},
            "argv": list(plan["argv"]),
            "environment": [{"name": "LANG", "value": "C.UTF-8"}, {"name": "LC_ALL", "value": "C.UTF-8"},
                            {"name": "NO_COLOR", "value": "1"}, {"name": "XDG_CACHE_HOME", "value": "/tmp/cache"}],
            "target_mounts": [{"host_path": inputs["target_path"], "container_path": "/workspace"}],
            "scratch_path": "scratch", "log_path": "logs/container",
            "network": {"mode": "none", "destinations": []},
            "permission": _permission(run_id, inputs["source_snapshot_sha256"], _utc_now()),
            "limits": dict(inputs["limits"])}


def terminal_gap(language: str, terminal: Any) -> str | None:
    """None when the verified terminal is a completed run; the gap text for a tool-level failure;
    Blocked for anything that is not the tool's own failure (canceled, not started, gate refusals)."""
    status, cause = terminal.get("execution_status"), terminal.get("cause")
    if status == "OK" and terminal.get("exit_code") == 0:
        return None
    if status == "FAILED" and cause in GAP_CAUSES:
        detail = f"{cause} exit {terminal.get('exit_code')}" if cause == "CONTAINER_EXIT_NONZERO" else cause
        return f"CodeQL {language} ended {detail}; no CodeQL leads for {language}."
    raise Blocked(f"{JOB}: CodeQL {language} container ended {status} ({cause}); not a recordable tool gap")


def _clean(text: Any, limit: int = 256) -> str | None:
    if not isinstance(text, str):
        return None
    value = _CONTROL.sub(" ", text).strip()
    return value[:limit] or None


def _source(uri: Any, target: Path) -> tuple[str, Path] | None:
    if not isinstance(uri, str) or not uri:
        return None
    value = unquote(uri)
    for prefix in ("file:///workspace/", "file:/workspace/", "/workspace/"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    if "://" in value or value.startswith("file:"):
        return None
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or any(part in ("", ".", "..") for part in pure.parts):
        return None
    path = (target / Path(*pure.parts)).resolve()
    try:
        path.relative_to(target.resolve())
    except ValueError:
        return None
    if not path.is_file() or path.is_symlink():
        return None
    return pure.as_posix(), path


def _rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    tool = run.get("tool") if isinstance(run.get("tool"), dict) else {}
    components = [tool.get("driver")] + list(tool.get("extensions") or [])
    rules: dict[str, dict[str, Any]] = {}
    for component in components:
        for rule in (component or {}).get("rules") or []:
            if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                rules.setdefault(rule["id"], rule)
    return rules


def _cwe(rule: dict[str, Any]) -> list[str]:
    tags = (rule.get("properties") or {}).get("tags") or []
    found = {int(match.group(1)) for tag in tags if isinstance(tag, str)
             for match in [_CWE.fullmatch(tag.lower())] if match}
    return [f"CWE-{number}" for number in sorted(found)]


def normalize_sarif(language: str, content: bytes, target: Path) -> tuple[list[dict[str, Any]], int]:
    """SARIF -> leads. Results that cite no regular checkout file line are dropped and counted
    (ADR-0013); a document that is not CodeQL SARIF raises."""
    try:
        document = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"{JOB}: CodeQL {language} SARIF is malformed") from exc
    runs = document.get("runs") if isinstance(document, dict) else None
    if not isinstance(runs, list):
        raise RuntimeError(f"{JOB}: CodeQL {language} SARIF has no runs")
    tool_id = f"codeql-{language}"
    leads: dict[str, dict[str, Any]] = {}
    dropped = 0
    hashes: dict[Path, tuple[str, int]] = {}
    for run in runs:
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            raise RuntimeError(f"{JOB}: CodeQL {language} SARIF run is malformed")
        rules = _rules(run)
        for result in run.get("results", []):
            rule_id = result.get("ruleId") if isinstance(result, dict) else None
            if not isinstance(rule_id, str) and isinstance(result, dict) and isinstance(result.get("rule"), dict):
                rule_id = result["rule"].get("id")
            locations = result.get("locations") if isinstance(result, dict) else None
            physical = (locations[0].get("physicalLocation") if isinstance(locations, list) and locations and
                        isinstance(locations[0], dict) else None)
            artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
            region = physical.get("region") if isinstance(physical, dict) else None
            cited = _source(artifact.get("uri") if isinstance(artifact, dict) else None, target)
            start = region.get("startLine") if isinstance(region, dict) else None
            end = region.get("endLine", start) if isinstance(region, dict) else None
            if (not isinstance(rule_id, str) or not rule_id or len(rule_id) > 256 or cited is None or
                    not isinstance(start, int) or isinstance(start, bool) or start < 1 or
                    not isinstance(end, int) or isinstance(end, bool) or end < start):
                dropped += 1
                continue
            path, source = cited
            if source not in hashes:
                data = source.read_bytes()
                hashes[source] = ("sha256:" + hashlib.sha256(data).hexdigest(),
                                  data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0))
            source_sha256, lines = hashes[source]
            if end > lines:
                dropped += 1
                continue
            rule = rules.get(rule_id, {})
            key = {"tool_id": tool_id, "rule_id": rule_id, "path": path, "start_line": start,
                   "end_line": end, "source_sha256": source_sha256}
            lead = {"lead_id": "lead_" + digest(key)[:16], **key, "language": language, "category": CATEGORY}
            name = _clean((rule.get("shortDescription") or {}).get("text")) or _clean(rule.get("name"))
            if name:
                lead["rule_name"] = name
            cwe = _cwe(rule)
            if cwe:
                lead["cwe"] = cwe
            leads.setdefault(lead["lead_id"], lead)  # one query can report one span more than once
    ordered = sorted(leads.values(), key=lambda row: (row["path"], row["start_line"], row["rule_id"], row["lead_id"]))
    return ordered, dropped


def assemble(*, run_id: str, attempt_id: str, inputs: dict[str, Any],
             outcomes: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Pure bookkeeping shared by the worker and the validator. ``outcomes`` maps an executed
    language to {"gap": str|None, "leads": [...], "dropped": int}."""
    tools, leads, gaps = [], [], []
    plan = inputs["plan"]
    if not plan:
        gaps.append("No CodeQL-supported source language was detected in the checkout.")
    for row in plan:
        language = row["language"]
        if row["status"] != "READY":
            gaps.append(row["gap"])
            continue
        outcome = outcomes.get(language)
        if outcome is None:
            raise Blocked(f"{JOB}: CodeQL {language} has no receipt")
        if outcome["gap"] is not None:
            gaps.append(outcome["gap"])
            continue
        leads.extend(outcome["leads"])
        tools.append({"tool_id": row["tool_id"], "tool": "codeql", "version": row["version"],
                      "language": language, "build_mode": row["build_mode"], "query_suite": row["query_suite"],
                      "image_id": row["image_id"], "image_digest": row["image_digest"],
                      "tool_metadata_sha256": row["tool_metadata_sha256"],
                      "lane_script_sha256": row["lane_script_sha256"], "records": len(outcome["leads"]),
                      "dropped_records": outcome["dropped"]})
        if language in FIDELITY_GAPS:
            gaps.append(FIDELITY_GAPS[language])
        if outcome["dropped"]:
            gaps.append(f"codeql-results-outside-checkout:{language}:{outcome['dropped']}")
    leads.sort(key=lambda row: (row["path"], row["start_line"], row["tool_id"], row["rule_id"], row["lead_id"]))
    return {"schema": SCHEMA, "run_id": run_id, "job_id": JOB, "attempt_id": attempt_id,
            "source_snapshot_sha256": inputs["source_snapshot_sha256"],
            "status": "OK_WITH_GAPS" if gaps else "OK", "tools": tools, "leads": leads,
            "coverage_gaps": gaps}


def _outcome(language: str, trial: Path, terminal: Any, target: Path) -> tuple[dict[str, Any], str | None]:
    gap = terminal_gap(language, terminal)
    if gap is not None:
        return {"gap": gap, "leads": [], "dropped": 0}, None
    raw = trial.joinpath(*SARIF.split("/"))
    if not raw.is_file() or raw.is_symlink():
        return {"gap": f"CodeQL {language} completed without SARIF output; no CodeQL leads for {language}.",
                "leads": [], "dropped": 0}, None
    leads, dropped = normalize_sarif(language, raw.read_bytes(), target)
    return {"gap": None, "leads": leads, "dropped": dropped}, "sha256:" + file_hash(raw)


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{JOB}: immutable attempt inputs changed")
    result = read_json(attempt / RESULT)
    if validate_document(result, "codeql-sast.schema.json"):
        raise Blocked(f"{JOB}: result schema validation failed")
    receipt = read_json(attempt / RECEIPTS)
    records = receipt.get("tools") if isinstance(receipt, dict) else None
    ready = {row["language"]: row for row in inputs["plan"] if row["status"] == "READY"}
    if not isinstance(records, list) or sorted(row.get("language") for row in records) != sorted(ready):
        raise Blocked(f"{JOB}: B13 receipt set does not match the READY plan")
    runtime = _runtime(inputs["source_snapshot_sha256"])
    outcomes = {}
    for record in records:
        language = record["language"]
        trial = attempt.joinpath(*record["trial_path"].split("/"))
        request = read_json(trial / "logs/container" / ce.REQUEST_FILE)
        if request.get("argv") != ready[language]["argv"] or request.get("limits") != inputs["limits"]:
            raise Blocked(f"{JOB}: CodeQL {language} request differs from the pinned plan")
        try:
            terminal = ce.load_verified_result(trial, run_id=run_id, job_id=JOB,
                attempt_id=record["adapter_attempt_id"], request=request, images_dir=runtime.images_dir,
                expected_result_sha256=record["expected_result_sha256"], **_host(runtime))
        except ce.ContainerRequestError as exc:
            raise Blocked(f"{JOB}: B13 evidence failed re-verification for codeql-{language}") from exc
        outcome, raw_sha = _outcome(language, trial, terminal, Path(inputs["target_path"]))
        if raw_sha != record["raw_result_sha256"]:
            raise Blocked(f"{JOB}: CodeQL {language} SARIF differs from its receipt")
        outcomes[language] = outcome
    if result != assemble(run_id=run_id, attempt_id=attempt.name, inputs=inputs, outcomes=outcomes):
        raise Blocked(f"{JOB}: normalized result no longer matches immutable CodeQL evidence")
    permission, lineage = _producer_receipts(inputs)
    if read_json(attempt / PERMISSION) != permission or read_json(attempt / LINEAGE) != lineage:
        raise Blocked(f"{JOB}: canonical producer receipts changed")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)
    resume = f"python -B appsec-review-process/launch_job.py --run-id {run_id} --job {DAGSTER_JOB} --wait"

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        if inputs["code"] != _code_hashes():
            raise Blocked(f"{JOB}: implementation changed before execution")
        runtime = _runtime(inputs["source_snapshot_sha256"])
        target = Path(inputs["target_path"])
        receipts, outcomes = [], {}
        for plan in inputs["plan"]:
            if plan["status"] != "READY":
                continue
            adapter_id = plan["tool_id"] + "-" + allocation["attempt_id"][:12]
            trial = attempt / "tools" / plan["tool_id"]
            trial.mkdir(parents=True)
            request = _request(run_id, adapter_id, inputs, plan)
            terminal = ce.run_container(runtime, run_id=run_id, job_id=JOB, attempt_id=adapter_id,
                                        attempt_root=trial, request=request)
            expected = terminal["result_sha256"]
            verified = ce.load_verified_result(trial, run_id=run_id, job_id=JOB, attempt_id=adapter_id,
                request=request, images_dir=runtime.images_dir, expected_result_sha256=expected, **_host(runtime))
            outcome, raw_sha = _outcome(plan["language"], trial, verified, target)
            outcomes[plan["language"]] = outcome
            # A killed or failed lane leaves its database behind; it is not evidence (the verified
            # B13 logs and terminal are), and it can be gigabytes, so it is not published.
            leftover = trial / "scratch" / "db"
            if leftover.is_dir() and not leftover.is_symlink():
                shutil.rmtree(leftover)
            receipts.append({"tool_id": plan["tool_id"], "language": plan["language"],
                             "adapter_attempt_id": adapter_id, "trial_path": trial.relative_to(attempt).as_posix(),
                             "expected_result_sha256": expected, "raw_path": SARIF, "raw_result_sha256": raw_sha})
        result = assemble(run_id=run_id, attempt_id=allocation["attempt_id"], inputs=inputs, outcomes=outcomes)
        atomic_json(attempt / RESULT, result)
        atomic_json(attempt / RECEIPTS, {"tools": receipts})
        (attempt / SUMMARY).write_text(
            "# CodeQL SAST\n\n"
            f"- Languages planned: {len(inputs['plan'])}; executed with results: {len(result['tools'])}.\n"
            f"- Normalized CodeQL leads: {len(result['leads'])}.\n"
            f"- Explicit coverage gaps: {len(result['coverage_gaps'])}.\n", encoding="utf-8")
        status = {"process": JOB, "status": result["status"], "run_id": run_id, "dagster_run_id": dagster_id,
                  "attempt_id": allocation["attempt_id"], "tools_run": len(result["tools"]),
                  "leads": len(result["leads"]), "network": "none",
                  "qualification": "implemented_not_qualified", "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        permission, lineage = _producer_receipts(inputs)
        atomic_json(attempt / PERMISSION, permission)
        atomic_json(attempt / LINEAGE, lineage)
        return record_terminal_current(
            base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
            worker_kind="pinned_container", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=result["status"],
            summary=f"CodeQL produced {len(result['leads'])} normalized lead(s).", status_record=status,
            artifact_paths=[RESULT, RECEIPTS, SUMMARY, "status.json", PERMISSION, LINEAGE],
            gaps=result["coverage_gaps"],
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id, worker_kind="pinned_container",
        output_contract=CONTRACT, resume_command=resume, derive_inputs=lambda: current_inputs(run_id),
        fingerprint_inputs=lambda value: "sha256:" + digest(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()},
        force=force, post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        blocked_summary="CodeQL SAST preflight did not complete.",
        failed_summary="CodeQL SAST did not publish; no older success may be used.")


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    inputs = current_inputs(run_id)
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(inputs),
                                    expected_run_id=run_id, expected_job_id=JOB)
    _validate_attempt(run_id, attempt, inputs)
    return attempt


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id")
    args = parser.parse_args()
    print(validate(args.run_id))


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
