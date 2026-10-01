"""Deterministic worker for the ``02-codeql-<lang>`` nodes: CodeQL security suites, offline, one language per node.

ADR-0023 (brief G) replaced the single ``02-codeql-sast`` job with one graph node per CodeQL
language (cpp, csharp, go, java, javascript, python, ruby, rust); they share this module and the
``codeql-language`` contract and run in parallel in the Docker pool. A node whose language is
absent from the checkout publishes SKIPPED ``not-applicable-language-absent``.

William (2026-09-28): CodeQL always runs; there is no license gate in the pipeline. The pinned
``audit-codeql`` image carries the CodeQL bundle (CLI plus the ``codeql/<lang>-queries`` packs at
matching versions), so database creation and the ``<lang>-security-extended`` suite need no
network. One B13 container per plan row creates a database with ``--build-mode none`` and
analyzes it to SARIF; Python normalizes SARIF results into leads (rule id, pinned rule name, CWE
tags, path, lines, fresh source hash). Raw SARIF messages stay in the immutable attempt, as in
02-source-sast and 02-native-sast: result messages quote target code and are not promoted.

Gating (ADR-0023 decision 2): javascript, python and ruby need only the intake; java and csharp
run ``--build-mode none`` (no build). cpp waits for ``02-native-build``: each replayable native
unit's adapted compile database (the same revalidation and flag screening ``02-native-sast``
uses) is replayed under CodeQL's tracer in the pinned ``audit-codeql-native`` image as tool
``codeql-cpp-traced`` (only compiler invocations run; no target build script does), and the lane
also runs the ``queries/appsec-graph-cpp`` call-graph tables (raw CSV kept in the attempt, hashed
in the receipt). ``--build-mode none`` always runs for cpp as well; without native units the gap
``language not built`` is recorded. Go runs ``autobuild`` (d06d505; module downloads per D-29 when
``CODEQL_NETWORK`` is unrestricted). Rust (no pinned suite) records a gap and no database. A compiled language that cannot be built is never a failure.

Databases (ADR-0023 decision 3): a completed lane keeps its finalized database; the worker moves
it into ``<run>/data/codeql-databases/<job>/<attempt>/<key>/`` (outside the attempt) and publishes
a hash-bound pointer (tree sha256, file count, bytes, bundle version, build mode, source snapshot)
so the reachability engines reuse it and never rebuild.

ADR-0013: a lane that times out, runs out of memory or exits non-zero is a coverage gap; the node
publishes OK_WITH_GAPS. Integrity failures still block.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
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
import registry_paths

# One node per CodeQL language (ADR-0023 decision 1). Order is the graph and catalog order.
LANGUAGES = ("cpp", "csharp", "go", "java", "javascript", "python", "ruby", "rust")
JOBS = {language: f"02-codeql-{language}" for language in LANGUAGES}
DAGSTER_JOB = "codeql_sast"   # standalone Dagster job: every language node, in parallel
CONTRACT = "codeql-language"
RESULT = "codeql-language.json"
RECEIPTS = "b13-receipts.json"
SUMMARY = "codeql-language-summary.md"
PERMISSION = "permission.json"
LINEAGE = "lineage.json"
SCHEMA = "appsec-review/codeql-language/1"
SCHEMA_FILE = "codeql-language.schema.json"
SKIP_REASON = "not-applicable-language-absent"
CONSUMER = "06-reachability-codeql"   # an edge that allows the skip reason (SKIPPED validation)
NATIVE_BUILD_JOB = "02-native-build"
DATABASE_STORE = "codeql-databases"
IMAGE_ID = "audit-codeql"
IMAGE_ROOT = ROOT.parent / "images" / IMAGE_ID
TOOL_METADATA = IMAGE_ROOT / "tool.json"
SARIF = "scratch/codeql.sarif"
DATABASE = "scratch/db"
CATEGORY = "codeql-security-query"
CODE_FILES = (
    "codeql_sast.py", "container_execution.py", "permission_capabilities.py",
    "publish_job_output.py", "validate_job_output.py", "native_sast.py", "native_sast_adapters.py",
    registry_paths.contract_rel(CONTRACT),
)
# Suffixes per CodeQL extractor.
LANGUAGE_SUFFIXES = {
    "cpp": (".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"),
    "csharp": (".cs",),
    "go": (".go",),
    "java": (".java",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"),
    "python": (".py",),
    "ruby": (".rb",),
    "rust": (".rs",),
}
BUILD_MODE_NONE = ("cpp", "csharp", "java", "javascript", "python", "ruby")
# Go has no build-mode none: autobuild runs the image's Go toolchain offline (GOPROXY=off) over each module
# (2026-10-01; before that Go was UNSUPPORTED_OFFLINE).
BUILD_MODE_AUTOBUILD = ("go",)
# D-29 (William, 2026-10-01): the CodeQL lanes run with network (mode unrestricted-build) so
# dependencies resolve: Go modules through the default proxy, and the Java/C# build-mode-none
# extractors' own dependency fetching. "none" restores the offline lanes.
CODEQL_NETWORK = "unrestricted"
COMPILED = ("cpp", "csharp", "go", "java", "rust")
OFFLINE_UNSUPPORTED = {
    "rust": ("CodeQL rust not run: language not supported by the pinned CodeQL metadata (images/audit-codeql/"
             "tool.json pins no rust suite); rust-analyzer and tree-sitter hints cover Rust."),
}
FIDELITY_GAPS = {
    "cpp": ("CodeQL cpp ran with --build-mode none: no compiler invocation, so macros, include paths and "
            "templates are resolved heuristically; treat missing results as unexamined, not clean."),
    "csharp": "CodeQL csharp ran with --build-mode none: unresolved references lower recall.",
    "java": "CodeQL java ran with --build-mode none: unresolved dependencies lower recall.",
    "go": ("CodeQL go ran with --build-mode autobuild: a module whose dependencies could not be fetched "
           "(or, offline, are neither vendored nor in the standard library) does not resolve; treat it as "
           "unexamined, not clean."),
}
GAP_CAUSES = ("TIMEOUT", "OOM_KILLED", "CONTAINER_EXIT_NONZERO")
TRACED_TOOL_ID = "codeql-cpp-traced"
TRACED_IMAGE_ID = "audit-codeql-native"
GRAPH_PACK = ROOT.parent / "queries" / "appsec-graph-cpp"
GRAPH_QUERIES = ("CallEdges.ql", "EntryPoints.ql", "FlowSources.ql")
DB_MOUNT, QUERY_MOUNT = "/inputs/codeql-db", "/inputs/codeql-queries"
REPLAY = "scratch/replay.json"
TRACED_NO_UNITS = ("CodeQL cpp traced replay not run: the accepted 02-native-build has no replayable C/C++ "
                   "translation unit.")
_CWE = re.compile(r"external/cwe/cwe-0*([1-9][0-9]{0,5})\Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


def job_id(language: str) -> str:
    if language not in JOBS:
        raise Blocked(f"02-codeql: unsupported CodeQL language {language!r}")
    return JOBS[language]


def language_of(job: str) -> str:
    for language, name in JOBS.items():
        if name == job:
            return language
    raise Blocked(f"02-codeql: {job!r} is not a CodeQL language node")


def template_path(language: str) -> Path:
    return registry_paths.template(job_id(language))


def root(run_id: str, language: str) -> Path:
    return data_path(run_id, "jobs", job_id(language))


def database_store(run_id: str) -> Path:
    return data_path(run_id, DATABASE_STORE)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _producer_receipts(inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    job = inputs["job"]
    template = read_json(template_path(inputs["language"]))
    permissions = template.get("permissions")
    if (template.get("job_template_id") != job or not isinstance(permissions, list) or
            not permissions or len(permissions) != len(set(permissions)) or
            not all(isinstance(item, str) and item for item in permissions)):
        raise Blocked(f"{job}: canonical template permissions are invalid")
    common = {"run_id": inputs["run_id"], "job_id": job,
              "source_snapshot_sha256": inputs["source_snapshot_sha256"]}
    return (
        {"schema": "appsec-review/producer-permission-receipt/1.0", **common, "permissions": permissions},
        {"schema": "appsec-review/producer-lineage-receipt/1.0", **common,
         "build_lineage_sha256": "sha256:" + digest(inputs)},
    )


def _source_snapshot(run_id: str, job: str) -> str:
    path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not path.is_file():
        raise Blocked(f"{job}: staged artifact-manifest.json is required")
    return "sha256:" + file_hash(path)


def _target(run_id: str, job: str) -> Path:
    manifest = read_json(run_path(run_id) / "inputs" / "artifact-manifest.json")
    value = manifest.get("target", {}).get("repo_path")
    path = Path(value) if isinstance(value, str) else Path()
    if not value or not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked(f"{job}: target.repo_path must be an absolute real checkout directory")
    return path.resolve()


def tool_metadata() -> tuple[dict[str, Any], str]:
    """Authenticated CodeQL metadata: tool.json must name the bundle whose sha256 the image build
    pins (image.json prebuild and the Dockerfile's sha256sum line)."""
    what = "02-codeql"
    try:
        value = json.loads(TOOL_METADATA.read_text(encoding="utf-8"))
        build = json.loads((IMAGE_ROOT / "image.json").read_text(encoding="utf-8"))
        dockerfile = (IMAGE_ROOT / "Dockerfile").read_text(encoding="utf-8")
    except (OSError, json.JSONDecodeError) as exc:
        raise Blocked(f"{what}: authenticated CodeQL tool metadata is unavailable") from exc
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
            not isinstance(suites, dict) or set(suites) != set(BUILD_MODE_NONE) | set(BUILD_MODE_AUTOBUILD) or
            any(suite != f"codeql/{lang}-queries:codeql-suites/{lang}-security-extended.qls"
                for lang, suite in suites.items())):
        raise Blocked(f"{what}: CodeQL tool metadata is invalid or differs from the pinned image build")
    lane = value["lane_script"]
    script = IMAGE_ROOT / str(lane.get("source", "")) if isinstance(lane, dict) else None
    if (script is None or set(lane) != {"path", "source"} or not str(lane["source"]).startswith("scripts/") or
            lane["path"] != "/opt/scripts/" + PurePosixPath(lane["source"]).name or
            not script.is_file() or script.is_symlink() or "COPY scripts/ /opt/scripts/" not in dockerfile):
        raise Blocked(f"{what}: CodeQL lane script metadata is invalid")
    traced = value.get("traced")
    native = IMAGE_ROOT / "Dockerfile.native"
    replay = IMAGE_ROOT / "scripts" / "replay_compile_commands.py"
    try:
        native_text = native.read_text(encoding="utf-8")
    except OSError as exc:
        raise Blocked(f"{what}: traced CodeQL image definition is unavailable") from exc
    native_pins = [step.get("sha256") for row in build.get("builds", []) if row.get("image_id") == TRACED_IMAGE_ID
                   for step in row.get("prebuild", [])]
    if (not isinstance(traced, dict) or traced.get("tool_id") != TRACED_TOOL_ID or
            traced.get("image_id") != TRACED_IMAGE_ID or traced.get("languages") != ["cpp"] or
            traced.get("replay_script") != {"path": "/opt/scripts/replay_compile_commands.py",
                                            "source": "scripts/replay_compile_commands.py"} or
            traced.get("graph_pack") != {"source": "queries/appsec-graph-cpp", "queries": list(GRAPH_QUERIES)} or
            native_pins != [bundle["sha256"]] or
            f'echo "{bundle["sha256"]}  bundle.tar.zst" | sha256sum -c -' not in native_text or
            "COPY scripts/ /opt/scripts/" not in native_text or not replay.is_file() or replay.is_symlink()):
        raise Blocked(f"{what}: traced CodeQL metadata is invalid or differs from the pinned native image build")
    return ({**value, "lane_script_sha256": "sha256:" + file_hash(script),
             "replay_script_sha256": "sha256:" + file_hash(replay)}, "sha256:" + file_hash(TOOL_METADATA))


def graph_pack_sha256() -> str:
    """Digest of the mounted query pack (qlpack.yml, Common.qll and the three queries)."""
    names = ("qlpack.yml", "Common.qll", *GRAPH_QUERIES)
    try:
        hashes = {name: file_hash(GRAPH_PACK / name) for name in names}
    except OSError as exc:
        raise Blocked("02-codeql-cpp: CodeQL graph query pack is incomplete") from exc
    if any((GRAPH_PACK / name).is_symlink() for name in names):
        raise Blocked("02-codeql-cpp: CodeQL graph query pack contains a link")
    return "sha256:" + digest(hashes)


def detected_languages(paths: list[str]) -> list[str]:
    found = set()
    for path in paths:
        lower = path.lower()
        if lower.startswith(".git/") or "/.git/" in lower:
            continue
        for language, suffixes in LANGUAGE_SUFFIXES.items():
            if lower.endswith(suffixes):
                found.add(language)
    return [language for language in LANGUAGES if language in found]


def _limits(language: str) -> dict[str, int]:
    return tunables.container_limits(job_id(language))


def _analysis_tunables(language: str) -> dict[str, int]:
    job = job_id(language)
    threads, ram = tunables.value(job, "codeql_threads"), tunables.value(job, "codeql_ram_bytes")
    memory = _limits(language)["memory_bytes"]
    if (any(isinstance(item, bool) or not isinstance(item, int) or item < 1 for item in (threads, ram)) or
            ram < 1024 * 1024 or ram >= memory):
        raise Blocked(f"{job}: codeql_ram_bytes must be at least 1 MiB and below container_memory_bytes")
    return {"threads": threads, "ram_mb": ram // (1024 * 1024)}


def plan_key(row: dict[str, Any]) -> str:
    """Receipt/outcome key: the language for build-mode none, tool id and unit for traced rows."""
    return row.get("plan_key", row["language"])


def store_key(row: dict[str, Any]) -> str:
    """Directory name of a row's retained database (no ':' in paths)."""
    return plan_key(row).replace(":", "-")


def traced_plan(native_units: list[dict[str, Any]], registry: dict[str, dict[str, Any]], metadata: dict[str, Any],
                metadata_sha256: str, analysis: dict[str, int], graph_sha256: str) -> list[dict[str, Any]]:
    """One ``codeql-cpp-traced`` row per replayable native unit (see load_native_units)."""
    image = registry.get(TRACED_IMAGE_ID)
    image_digest = image.get("digest") if isinstance(image, dict) else None
    ready = (isinstance(image_digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is not None and
             image.get("image_id") == TRACED_IMAGE_ID)
    base = {"language": "cpp", "tool_id": TRACED_TOOL_ID, "version": metadata["version"],
            "image_id": TRACED_IMAGE_ID, "image_digest": image_digest if ready else None,
            "tool_metadata_sha256": metadata_sha256, "lane_script_sha256": metadata["lane_script_sha256"],
            "replay_script_sha256": metadata["replay_script_sha256"], "graph_pack_sha256": graph_sha256,
            "build_mode": None, "query_suite": None, "argv": [], "status": "READY", "gap": None}
    if not native_units:
        return [{**base, "plan_key": TRACED_TOOL_ID, "unit_id": None, "status": "NO_UNITS", "gap": TRACED_NO_UNITS}]
    rows = []
    suite = metadata["query_suites"]["cpp"]
    for unit in native_units:
        key = unit["key"]
        row = {**base, "plan_key": f"{TRACED_TOOL_ID}:{key}", "unit_id": unit["unit_id"],
               "compile_database_sha256": unit["adapted_sha256"], "compile_database_entries": len(unit["adapted"])}
        if not ready:
            row.update(status="UNAVAILABLE", gap=f"CodeQL cpp traced unavailable: authenticated pinned image "
                                                 f"{TRACED_IMAGE_ID} has no current B16 record.")
        else:
            row.update(build_mode="traced", query_suite=suite,
                       argv=[metadata["lane_script"]["path"], "cpp", "traced", suite, str(analysis["threads"]),
                             str(analysis["ram_mb"]), "keep-db", f"{DB_MOUNT}/{key}/compile_commands.json", QUERY_MOUNT])
        rows.append(row)
    return rows


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
            mode = "autobuild" if language in BUILD_MODE_AUTOBUILD else "none"
            argv = [metadata["lane_script"]["path"], language, mode, suite,
                    str(analysis["threads"]), str(analysis["ram_mb"]), "keep-db"]
            if mode == "autobuild":
                argv.append("online" if CODEQL_NETWORK == "unrestricted" else "offline")
            row.update(build_mode=mode, query_suite=suite, argv=argv)
        plan.append(row)
    return plan


def _code_hashes(language: str) -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    template = registry_paths.template_rel(job_id(language))
    values[template] = file_hash(ROOT / template)
    for name in (SCHEMA_FILE, "codeql-database-pointer.schema.json"):
        values["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return values


def _permission(run_id: str, job: str, source: str, at: str) -> dict[str, Any]:
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": job, "capabilities": []}
    context = {"run_id": run_id, "job_id": job, "source_snapshot_sha256": source,
               "now": at, "registry_ceiling": []}
    decision = pc.evaluate(requirement, [], context)
    pc.require_granted(decision, requirement=requirement, grants=[], context=context)
    return {"requirement": requirement, "grants": [], "decision": decision}


def load_native_units(native_build_root: Path, run_id: str, fingerprint: str,
                      target: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Revalidate the accepted 02-native-build exactly as 02-native-sast does (its adapter refuses
    compile databases that could load or wrap compiler code) and return (binding, units)."""
    import native_sast  # deferred: only the traced mode depends on the native-build lineage
    try:
        upstream = native_sast.load_native_build(native_build_root, run_id=run_id, expected_fingerprint=fingerprint)
    except native_sast.Blocked as exc:
        raise Blocked(f"{JOBS['cpp']}: accepted native build failed revalidation ({exc})") from exc
    if upstream["target"] != target:
        raise Blocked(f"{JOBS['cpp']}: accepted native build is for another checkout")
    units = [{"unit_id": unit["unit_id"], "key": digest(unit["unit_id"])[:16],
              "adapted_sha256": unit["compile_database"]["adapted_sha256"], "adapted": unit["adapted"]}
             for unit in upstream["units"]]
    return upstream["binding"], units


def native_build_state(run_id: str) -> tuple[Path | None, str | None, str | None]:
    """(root, fingerprint, None) for an accepted 02-native-build, else (None, None, cause)."""
    base = data_path(run_id, "jobs", NATIVE_BUILD_JOB)
    pointer_path = base / "accepted.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        return None, None, "no accepted 02-native-build publication"
    pointer = read_json(pointer_path)
    if pointer.get("status") == "SKIPPED":
        return None, None, f"02-native-build SKIPPED ({_clean(pointer.get('reason'), 80) or 'no reason'})"
    fingerprint = pointer.get("fingerprint")
    if pointer.get("status") not in ("OK", "OK_WITH_GAPS") or not isinstance(fingerprint, str):
        return None, None, "02-native-build has no current accepted success"
    return base, fingerprint, None


def current_inputs(run_id: str, language: str, *, native_build_root: Path | None = None,
                   native_build_fingerprint: str | None = None) -> dict[str, Any]:
    """``native_build_root``/``native_build_fingerprint`` override the accepted 02-native-build the
    cpp node otherwise discovers itself (tests, offline replays); other languages ignore them."""
    job = job_id(language)
    source = _source_snapshot(run_id, job)
    target = _target(run_id, job)
    metadata, metadata_sha256 = tool_metadata()
    registry = ce.load_image_registry(ce.IMAGES_DIR)
    paths = [path.relative_to(target).as_posix() for path in target.rglob("*")
             if path.is_file() and not path.is_symlink()]
    analysis = _analysis_tunables(language)
    present = language in detected_languages(paths)
    extra: dict[str, Any] = {}
    plan = build_plan([language], registry, metadata, metadata_sha256, analysis) if present else []
    if present and language == "cpp":
        cause = None
        if native_build_root is None:
            native_build_root, native_build_fingerprint, cause = native_build_state(run_id)
        elif not isinstance(native_build_fingerprint, str):
            raise Blocked(f"{job}: a native build root needs its caller-held fingerprint")
        units: list[dict[str, Any]] = []
        if native_build_root is not None:
            binding, units = load_native_units(Path(native_build_root), run_id, native_build_fingerprint, target)
            extra = {"native_build": binding, "native_build_root": str(Path(native_build_root).resolve()),
                     "native_units": units}
            plan += traced_plan(units, registry, metadata, metadata_sha256, analysis, graph_pack_sha256())
            if not units:
                cause = "the accepted 02-native-build has no replayable C/C++ unit"
        if cause is not None:
            extra["not_built"] = f"language not built: {cause}; ran --build-mode none only"
    return {**extra,
        "job": job, "language": language, "present": present,
        "run_id": run_id, "source_snapshot_sha256": source, "target_path": str(target),
        "tool_metadata_sha256": metadata_sha256,
        "permission_fingerprint_sha256": pc.input_fingerprint_component(
            _permission(run_id, job, source, _utc_now())["decision"]),
        "boundary_sha256": ce.boundary_sha256(),
        "limits": _limits(language), "analysis": analysis,
        "plan": plan,
        "code": _code_hashes(language),
    }


def _runtime(source: str) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise Blocked("02-codeql: Docker is unavailable")
    return ce.ContainerRuntime(
        docker_executable=defaults["docker_executable"], docker_host=None, images_dir=ce.IMAGES_DIR,
        host_flavor=defaults["host_flavor"], container_user=defaults["container_user"],
        source_snapshot_sha256=source, registry_ceiling=[], clock=_utc_now, cancel=threading.Event())


def _host(runtime: ce.ContainerRuntime) -> dict[str, Any]:
    return {"host_flavor": runtime.host_flavor, "docker_host": runtime.docker_host,
            "docker_executable": runtime.docker_executable, "container_user": runtime.container_user}


def _request(run_id: str, adapter_id: str, inputs: dict[str, Any], plan: dict[str, Any],
             database_root: Path | None = None) -> dict[str, Any]:
    job = inputs["job"]
    if plan.get("status") != "READY":
        raise Blocked(f"{job}: CodeQL {plan.get('language')} is not ready for execution")
    mounts = [{"host_path": inputs["target_path"], "container_path": "/workspace"}]
    if plan.get("build_mode") == "traced":
        if database_root is None:
            raise Blocked(f"{job}: traced CodeQL needs the adapted compile databases")
        mounts += [{"host_path": str(database_root), "container_path": DB_MOUNT},
                   {"host_path": str(GRAPH_PACK), "container_path": QUERY_MOUNT}]
    return {"schema": ce.REQUEST_ID, "run_id": run_id, "job_id": job, "attempt_id": adapter_id,
            "image": {"image_id": plan["image_id"], "digest": plan["image_digest"]},
            "argv": list(plan["argv"]),
            "environment": [{"name": "LANG", "value": "C.UTF-8"}, {"name": "LC_ALL", "value": "C.UTF-8"},
                            {"name": "NO_COLOR", "value": "1"}, {"name": "XDG_CACHE_HOME", "value": "/tmp/cache"}],
            "target_mounts": mounts,
            "scratch_path": "scratch", "log_path": "logs/container",
            "network": {"mode": "unrestricted-build" if CODEQL_NETWORK == "unrestricted" else "none",
                        "destinations": []},
            "permission": _permission(run_id, job, inputs["source_snapshot_sha256"], _utc_now()),
            "limits": dict(inputs["limits"])}


def terminal_gap(language: str, terminal: Any, job: str = "02-codeql") -> str | None:
    """None when the verified terminal is a completed run; the gap text for a tool-level failure;
    Blocked for anything that is not the tool's own failure (canceled, not started, gate refusals)."""
    status, cause = terminal.get("execution_status"), terminal.get("cause")
    if status == "OK" and terminal.get("exit_code") == 0:
        return None
    if status == "FAILED" and cause in GAP_CAUSES:
        detail = f"{cause} exit {terminal.get('exit_code')}" if cause == "CONTAINER_EXIT_NONZERO" else cause
        return f"CodeQL {language} ended {detail}; no CodeQL leads for {language}."
    raise Blocked(f"{job}: CodeQL {language} container ended {status} ({cause}); not a recordable tool gap")


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


def normalize_sarif(language: str, content: bytes, target: Path,
                    tool_id: str | None = None) -> tuple[list[dict[str, Any]], int]:
    """SARIF -> leads. Results that cite no regular checkout file line are dropped and counted
    (ADR-0013); a document that is not CodeQL SARIF raises."""
    job = JOBS.get(language, "02-codeql")
    try:
        document = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"{job}: CodeQL {language} SARIF is malformed") from exc
    runs = document.get("runs") if isinstance(document, dict) else None
    if not isinstance(runs, list):
        raise RuntimeError(f"{job}: CodeQL {language} SARIF has no runs")
    tool_id = tool_id or f"codeql-{language}"
    leads: dict[str, dict[str, Any]] = {}
    dropped = 0
    hashes: dict[Path, tuple[str, int]] = {}
    for run in runs:
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            raise RuntimeError(f"{job}: CodeQL {language} SARIF run is malformed")
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


# ---- retained databases (ADR-0023 decision 3) ----------------------------------------------------

def database_tree(folder: Path) -> dict[str, Any] | None:
    """{tree_sha256, files, bytes} of a database directory, or None when it is absent, empty or
    contains anything but regular files and directories (links are never followed or kept)."""
    if not folder.is_dir() or folder.is_symlink():
        return None
    rows, total = [], 0
    for directory, dirs, files in os.walk(folder, followlinks=False):
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                return None
        for name in files:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                return None
            rows.append((path.relative_to(folder).as_posix(), file_hash(path)))
            total += path.stat().st_size
    if not rows:
        return None
    rows.sort()
    return {"tree_sha256": "sha256:" + digest(rows), "files": len(rows), "bytes": total}


def pointer(inputs: dict[str, Any], attempt_id: str, row: dict[str, Any], database: dict[str, Any]) -> dict[str, Any]:
    """The published database pointer, derived from the plan row and the receipt's store record."""
    identity = {"job": inputs["job"], "attempt_id": attempt_id, "plan_key": plan_key(row),
                "tree_sha256": database["tree_sha256"]}
    return {"database_id": "codeqldb_" + digest(identity)[:16], "job_id": inputs["job"], "attempt_id": attempt_id,
            "plan_key": plan_key(row), "language": row["language"], "build_mode": row["build_mode"],
            "unit_id": row.get("unit_id"), "bundle_version": row["version"],
            "tool_metadata_sha256": row["tool_metadata_sha256"], "image_digest": row["image_digest"],
            "source_snapshot_sha256": inputs["source_snapshot_sha256"], "store_path": database["store_path"],
            "tree_sha256": database["tree_sha256"], "files": database["files"], "bytes": database["bytes"]}


def retain_database(run_id: str, inputs: dict[str, Any], attempt_id: str, row: dict[str, Any],
                    trial: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Move a completed lane's database into the run's store; (store record, gap)."""
    source = trial.joinpath(*DATABASE.split("/"))
    tree = database_tree(source)
    if tree is None:   # absent, empty or holding a link: not retained (the caller drops the leftover)
        if source.is_symlink() or source.is_file():
            source.unlink()
        return None, f"codeql-database-absent:{plan_key(row)}"
    relative = PurePosixPath(DATABASE_STORE, inputs["job"], attempt_id, store_key(row))
    destination = data_path(run_id, *relative.parts)
    if destination.exists():
        raise Blocked(f"{inputs['job']}: database store {relative} already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(destination))
    moved = database_tree(destination)
    if moved != tree:
        raise Blocked(f"{inputs['job']}: database changed while it was retained")
    return {"store_path": relative.as_posix(), **tree}, None


def verify_database(run_id: str, record: dict[str, Any]) -> Path | None:
    """The store directory when it still hashes to the pointer; None otherwise (a consumer gap)."""
    relative = PurePosixPath(str(record.get("store_path", "")))
    if (relative.is_absolute() or len(relative.parts) != 4 or relative.parts[0] != DATABASE_STORE or
            any(part in ("", ".", "..") for part in relative.parts)):
        return None
    folder = data_path(run_id, *relative.parts)
    tree = database_tree(folder)
    if tree is None or tree != {key: record.get(key) for key in ("tree_sha256", "files", "bytes")}:
        return None
    return folder


def assemble(*, run_id: str, attempt_id: str, inputs: dict[str, Any],
             outcomes: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Pure bookkeeping shared by the worker and the validator. ``outcomes`` maps an executed plan
    key to {"gap": str|None, "leads": [...], "dropped": int, "database": store record|None}."""
    job, language = inputs["job"], inputs["language"]
    tools, leads, gaps, databases = [], [], [], []
    if not inputs["present"]:
        return {"schema": SCHEMA, "run_id": run_id, "job_id": job, "attempt_id": attempt_id, "language": language,
                "source_snapshot_sha256": inputs["source_snapshot_sha256"], "status": "SKIPPED",
                "skip_reason": SKIP_REASON, "build_modes": [], "tools": [], "leads": [], "databases": [],
                "coverage_gaps": []}
    if inputs.get("not_built"):
        gaps.append(inputs["not_built"])
    for row in inputs["plan"]:
        key = plan_key(row)
        if row["status"] != "READY":
            gaps.append(row["gap"])
            continue
        outcome = outcomes.get(key)
        if outcome is None:
            raise Blocked(f"{job}: CodeQL {key} has no receipt")
        if outcome["gap"] is not None:
            gaps.append(outcome["gap"])
            continue
        leads.extend(outcome["leads"])
        database = outcome.get("database")
        published = pointer(inputs, attempt_id, row, database) if database else None
        if published:
            databases.append(published)
        elif outcome.get("database_gap"):
            gaps.append(outcome["database_gap"])
        tool = {"tool_id": row["tool_id"], "tool": "codeql", "version": row["version"],
                "language": language, "build_mode": row["build_mode"], "query_suite": row["query_suite"],
                "image_id": row["image_id"], "image_digest": row["image_digest"],
                "tool_metadata_sha256": row["tool_metadata_sha256"],
                "lane_script_sha256": row["lane_script_sha256"], "records": len(outcome["leads"]),
                "dropped_records": outcome["dropped"],
                "database_id": published["database_id"] if published else None}
        if row["build_mode"] == "traced":
            replay = outcome.get("replay")
            tool.update(unit_id=row["unit_id"], replay=replay)
            if replay is None:
                gaps.append(f"codeql-traced-replay-stats-missing:{key}")
            elif replay["failed"] or replay["refused"]:
                gaps.append(f"codeql-traced-replay-incomplete:{key}:ok={replay['ok']}:failed={replay['failed']}:"
                            f"refused={replay['refused']}:total={replay['total']}")
        elif language in FIDELITY_GAPS:
            gaps.append(FIDELITY_GAPS[language])
        tools.append(tool)
        if outcome["dropped"]:
            gaps.append(f"codeql-results-outside-checkout:{key}:{outcome['dropped']}")
    leads.sort(key=lambda row: (row["path"], row["start_line"], row["tool_id"], row["rule_id"], row["lead_id"]))
    return {"schema": SCHEMA, "run_id": run_id, "job_id": job, "attempt_id": attempt_id, "language": language,
            "source_snapshot_sha256": inputs["source_snapshot_sha256"],
            "status": "OK_WITH_GAPS" if gaps else "OK", "skip_reason": None,
            "build_modes": sorted({tool["build_mode"] for tool in tools}), "tools": tools, "leads": leads,
            "databases": databases, "coverage_gaps": list(dict.fromkeys(gaps))}


def _label(row: dict[str, Any]) -> str:
    return row["language"] if row.get("build_mode") != "traced" else f"cpp traced unit {plan_key(row).split(':')[1]}"


def read_replay(trial: Path) -> dict[str, int] | None:
    """The replay counts the traced lane wrote, or None when absent or malformed."""
    path = trial.joinpath(*REPLAY.split("/"))
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 4096:
        return None
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, UnicodeDecodeError):
        return None
    keys = ("failed", "ok", "refused", "total")
    if (not isinstance(value, dict) or set(value) != set(keys) or
            any(isinstance(value[k], bool) or not isinstance(value[k], int) or value[k] < 0 for k in keys) or
            value["ok"] + value["failed"] + value["refused"] != value["total"]):
        return None
    return {key: value[key] for key in keys}


def graph_outputs(trial: Path) -> dict[str, str | None]:
    """sha256 of each decoded graph table the traced lane produced (None when it did not)."""
    found = {}
    for query in GRAPH_QUERIES:
        path = trial / "scratch" / "graph" / (query[:-3] + ".csv")
        found[query] = "sha256:" + file_hash(path) if path.is_file() and not path.is_symlink() else None
    return found


def _outcome(row: dict[str, Any], trial: Path, terminal: Any, target: Path,
             job: str = "02-codeql") -> tuple[dict[str, Any], str | None]:
    label = _label(row)
    gap = terminal_gap(label, terminal, job)
    if gap is not None:
        return {"gap": gap, "leads": [], "dropped": 0}, None
    raw = trial.joinpath(*SARIF.split("/"))
    if not raw.is_file() or raw.is_symlink():
        return {"gap": f"CodeQL {label} completed without SARIF output; no CodeQL leads for {label}.",
                "leads": [], "dropped": 0}, None
    leads, dropped = normalize_sarif(row["language"], raw.read_bytes(), target, tool_id=row["tool_id"])
    outcome = {"gap": None, "leads": leads, "dropped": dropped}
    if row.get("build_mode") == "traced":
        outcome["replay"] = read_replay(trial)
    return outcome, "sha256:" + file_hash(raw)


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    job = inputs["job"]
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{job}: immutable attempt inputs changed")
    result = read_json(attempt / RESULT)
    if validate_document(result, SCHEMA_FILE):
        raise Blocked(f"{job}: result schema validation failed")
    receipt = read_json(attempt / RECEIPTS)
    records = receipt.get("tools") if isinstance(receipt, dict) else None
    ready = {plan_key(row): row for row in inputs["plan"] if row["status"] == "READY"}
    if (not isinstance(records, list) or
            sorted(row.get("plan_key", row.get("language")) for row in records) != sorted(ready)):
        raise Blocked(f"{job}: B13 receipt set does not match the READY plan")
    runtime = _runtime(inputs["source_snapshot_sha256"]) if records else None
    outcomes = {}
    for record in records:
        key = record.get("plan_key", record["language"])
        row = ready[key]
        trial = attempt.joinpath(*record["trial_path"].split("/"))
        request = read_json(trial / "logs/container" / ce.REQUEST_FILE)
        if request.get("argv") != row["argv"] or request.get("limits") != inputs["limits"]:
            raise Blocked(f"{job}: CodeQL {key} request differs from the pinned plan")
        try:
            terminal = ce.load_verified_result(trial, run_id=run_id, job_id=job,
                attempt_id=record["adapter_attempt_id"], request=request, images_dir=runtime.images_dir,
                expected_result_sha256=record["expected_result_sha256"], **_host(runtime))
        except ce.ContainerRequestError as exc:
            raise Blocked(f"{job}: B13 evidence failed re-verification for {key}") from exc
        outcome, raw_sha = _outcome(row, trial, terminal, Path(inputs["target_path"]), job)
        if raw_sha != record["raw_result_sha256"]:
            raise Blocked(f"{job}: CodeQL {key} SARIF differs from its receipt")
        if row["build_mode"] == "traced" and record.get("graph_outputs") != graph_outputs(trial):
            raise Blocked(f"{job}: CodeQL {key} graph tables differ from their receipt")
        if outcome["gap"] is None:
            outcome.update(database=record.get("database"), database_gap=record.get("database_gap"))
        outcomes[key] = outcome
    if result != assemble(run_id=run_id, attempt_id=attempt.name, inputs=inputs, outcomes=outcomes):
        raise Blocked(f"{job}: normalized result no longer matches immutable CodeQL evidence")
    permission, lineage = _producer_receipts(inputs)
    if read_json(attempt / PERMISSION) != permission or read_json(attempt / LINEAGE) != lineage:
        raise Blocked(f"{job}: canonical producer receipts changed")


def run(run_id: str, dagster_id: str, language: str, force: bool = False, *,
        native_build_root: Path | None = None, native_build_fingerprint: str | None = None) -> dict[str, Any]:
    """One CodeQL language node. ``native_build_root``/``native_build_fingerprint`` override the
    cpp node's own discovery of the accepted 02-native-build."""
    job = job_id(language)
    base = root(run_id, language)
    native = {"native_build_root": native_build_root, "native_build_fingerprint": native_build_fingerprint}
    resume = f"python -B appsec-review-process/launch_job.py --run-id {run_id} --job {DAGSTER_JOB} --wait"

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        if inputs["code"] != _code_hashes(language):
            raise Blocked(f"{job}: implementation changed before execution")
        target = Path(inputs["target_path"])
        receipts, outcomes = [], {}
        runtime = _runtime(inputs["source_snapshot_sha256"]) if any(
            row["status"] == "READY" for row in inputs["plan"]) else None
        database_root = None
        if any(row["status"] == "READY" and row["build_mode"] == "traced" for row in inputs["plan"]):
            database_root = attempt / "adapted-inputs"
            for unit in inputs["native_units"]:
                folder = database_root / unit["key"]
                folder.mkdir(parents=True)
                atomic_json(folder / "compile_commands.json", unit["adapted"])
        for plan in inputs["plan"]:
            if plan["status"] != "READY":
                continue
            key = plan_key(plan)
            name = plan["tool_id"] if plan["build_mode"] != "traced" else f"{TRACED_TOOL_ID}-{key.split(':')[1]}"
            adapter_id = name[:40] + "-" + allocation["attempt_id"][:12]
            trial = attempt / "tools" / name
            trial.mkdir(parents=True)
            request = _request(run_id, adapter_id, inputs, plan, database_root)
            terminal = ce.run_container(runtime, run_id=run_id, job_id=job, attempt_id=adapter_id,
                                        attempt_root=trial, request=request)
            expected = terminal["result_sha256"]
            verified = ce.load_verified_result(trial, run_id=run_id, job_id=job, attempt_id=adapter_id,
                request=request, images_dir=runtime.images_dir, expected_result_sha256=expected, **_host(runtime))
            outcome, raw_sha = _outcome(plan, trial, verified, target, job)
            receipt = {"tool_id": plan["tool_id"], "language": plan["language"],
                       "adapter_attempt_id": adapter_id, "trial_path": trial.relative_to(attempt).as_posix(),
                       "expected_result_sha256": expected, "raw_path": SARIF, "raw_result_sha256": raw_sha}
            if outcome["gap"] is None:
                database, database_gap = retain_database(run_id, inputs, allocation["attempt_id"], plan, trial)
                outcome.update(database=database, database_gap=database_gap)
                receipt.update(database=database, database_gap=database_gap)
            # A killed or failed lane leaves its database behind; it is not evidence (the verified
            # B13 logs and terminal are), and it can be gigabytes, so it is not published.
            leftover = trial / "scratch" / "db"
            if leftover.is_dir() and not leftover.is_symlink():
                shutil.rmtree(leftover)
            outcomes[key] = outcome
            if plan["build_mode"] == "traced":
                receipt.update(plan_key=key, unit_id=plan["unit_id"], graph_outputs=graph_outputs(trial))
            receipts.append(receipt)
        result = assemble(run_id=run_id, attempt_id=allocation["attempt_id"], inputs=inputs, outcomes=outcomes)
        atomic_json(attempt / RESULT, result)
        atomic_json(attempt / RECEIPTS, {"tools": receipts})
        (attempt / SUMMARY).write_text(
            f"# CodeQL {language}\n\n"
            + (f"- SKIPPED: {SKIP_REASON}.\n" if result["status"] == "SKIPPED" else
               f"- Plan rows: {len(inputs['plan'])}; executed with results: {len(result['tools'])}.\n"
               f"- Normalized CodeQL leads: {len(result['leads'])}.\n"
               f"- Retained databases: {len(result['databases'])}.\n"
               f"- Explicit coverage gaps: {len(result['coverage_gaps'])}.\n"), encoding="utf-8")
        status = {"process": job, "status": result["status"], "run_id": run_id, "dagster_run_id": dagster_id,
                  "attempt_id": allocation["attempt_id"], "tools_run": len(result["tools"]),
                  # containers_run counts every lane container started (tools_run only those with results),
                  # and network is what the requests asked for (it was hardcoded "none" before D-29).
                  "containers_run": len(outcomes),
                  "leads": len(result["leads"]), "databases": len(result["databases"]),
                  "network": "unrestricted-build" if CODEQL_NETWORK == "unrestricted" else "none",
                  "qualification": "implemented_not_qualified", "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        permission, lineage = _producer_receipts(inputs)
        atomic_json(attempt / PERMISSION, permission)
        atomic_json(attempt / LINEAGE, lineage)
        skipped = result["status"] == "SKIPPED"
        return record_terminal_current(
            base, attempt, run_id=run_id, job_id=job, dagster_run_id=dagster_id,
            worker_kind="pinned_container", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=result["status"],
            summary=(f"SKIPPED {SKIP_REASON}: no {language} source in the checkout." if skipped else
                     f"CodeQL {language} produced {len(result['leads'])} normalized lead(s)."),
            status_record=status,
            artifact_paths=[RESULT, RECEIPTS, SUMMARY, "status.json", PERMISSION, LINEAGE],
            gaps=result["coverage_gaps"], skip_reason=SKIP_REASON if skipped else None,
            consumer_job_id=CONSUMER if skipped else None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=job, dagster_run_id=dagster_id, worker_kind="pinned_container",
        output_contract=CONTRACT, resume_command=resume,
        derive_inputs=lambda: current_inputs(run_id, language, **native),
        fingerprint_inputs=lambda value: "sha256:" + digest(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": job,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes(language)},
        force=force, post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        consumer_job_id=CONSUMER,
        blocked_summary=f"CodeQL {language} preflight did not complete.",
        failed_summary=f"CodeQL {language} did not publish; no older success may be used.")


def validate(run_id: str, language: str, pointer: dict[str, Any] | None = None, *,
             native_build_root: Path | None = None, native_build_fingerprint: str | None = None) -> Path:
    base = root(run_id, language)
    pointer = pointer or read_json(base / "accepted.json")
    inputs = current_inputs(run_id, language, native_build_root=native_build_root,
                            native_build_fingerprint=native_build_fingerprint)
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(inputs),
                                    expected_run_id=run_id, expected_job_id=job_id(language),
                                    consumer_job_id=CONSUMER)
    _validate_attempt(run_id, attempt, inputs)
    return attempt


def load_accepted(run_id: str, language: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    """(result, binding, None) for a node's accepted publication verified by pointer, envelope and
    attempt tree hashes, else (None, None, gap). Consumers use this; they never re-run CodeQL."""
    from execution_state import tree_hashes
    job = job_id(language)
    base = root(run_id, language)
    pointer_path = base / "accepted.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        return None, None, f"engine-input-absent:{job}"
    try:
        accepted = read_json(pointer_path)
        attempt = base / "attempts" / str(accepted.get("attempt_id"))
        if (accepted.get("run_id") != run_id or accepted.get("job") != job or
                accepted.get("status") not in ("OK", "OK_WITH_GAPS", "SKIPPED") or attempt.is_symlink() or
                not attempt.is_dir() or tree_hashes(attempt) != accepted.get("hashes") or
                file_hash(attempt / accepted.get("envelope_path", "result.json")) != accepted.get("envelope_sha256")):
            return None, None, f"engine-input-not-current:{job}"
        document = read_json(attempt / RESULT)
    except (OSError, ValueError, TypeError):
        return None, None, f"engine-input-not-current:{job}"
    if validate_document(document, SCHEMA_FILE) or document.get("job_id") != job:
        return None, None, f"engine-input-invalid:{job}"
    return document, {"job_id": job, "attempt_id": accepted["attempt_id"],
                      "accepted_pointer_sha256": "sha256:" + file_hash(pointer_path),
                      "result_sha256": "sha256:" + file_hash(attempt / RESULT),
                      "status": accepted["status"]}, None


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id")
    parser.add_argument("language", choices=LANGUAGES)
    args = parser.parse_args()
    print(validate(args.run_id, args.language))


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
