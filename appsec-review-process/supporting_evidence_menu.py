#!/usr/bin/env python3
"""Deterministic, hash-bound supporting-evidence menu for claim reviewers (07/08/09/12).

The claim ledger is the menu of *what* to review; this is the menu of *what to look it up in*:
pointers to the run's accepted non-finding evidence (component map, build index and compile
databases, native-build units, IR capture/link/facts, code property graph, debug-symbol index,
binary triage/CFG/hardening, SBOM/dependency lifecycle/license, test and document evidence, and
the tool-lead source artifacts). Every pointer names a file under the ``supporting-evidence``
readable root (the run's ``data/jobs`` directory), its sha256 from the producer's accepted
pointer, a one-line description and record counts. Producers that are absent or SKIPPED are listed
as not available with the reason. Every pinned file is also added to the reviewer request's
``readable_inputs`` so the persona is permitted to read it; nothing here is derived from target
content except counts, and file contents stay untrusted data.
"""
from __future__ import annotations

from fnmatch import fnmatchcase
import json
from pathlib import Path
from typing import Any, Iterable

from execution_state import data_path, file_hash, read_json
from publish_job_output import ACCEPTED_SCHEMA

SCHEMA = "appsec-review/supporting-evidence-menu/1.0"
ROOT_ID = "supporting-evidence"      # readable root: <run>/data/jobs
MENU_ROOT_ID = "evidence-menu"       # readable root holding the menu file itself
MENU_FILE = "supporting-evidence-menu.json"
FILE_PIN_MAX = 32 * 1024 * 1024      # larger files are listed, not pinned
TOTAL_PIN_MAX = 96 * 1024 * 1024

# (item id = producing job, category, one-line description, attempt-relative artifact patterns).
# Order inside a category is the relevance order used for a claim of that kind.
MENU = (
    ("02-ir-facts", "native", "IR facts: functions, calls and memory operations with source file/line", ["ir-facts.json"]),
    ("02-code-property-graph", "native", "Code property graph summary plus records (JSON Lines; filter with input_jq)",
     ["code-property-graph.json", "code-property-graph.records.jsonl"]),
    ("02-treesitter-ast", "native", "Tree-sitter AST summary plus records (JSON Lines): functions with spans, call sites, imports",
     ["treesitter-ast.json", "treesitter-ast.records.jsonl"]),
    ("02-debug-symbol-index", "native", "Debug-symbol index summary plus records (JSON Lines): symbols to source file/line",
     ["debug-symbol-index.json", "debug-symbol-index.records.jsonl"]),
    ("02-native-build", "native", "Native build units, compile databases and produced binaries (paths, hashes)",
     ["native-build.json", "outputs/*/compile_commands.json"]),
    ("02-ir-capture", "native", "LLVM IR capture per translation unit (module list)", ["ir-capture.json"]),
    ("02-ir-link", "native", "Linked IR modules per unit", ["ir-link.json"]),
    ("02-source-sast", "tool-leads", "Source SAST leads (artifact cited by tool-lead claims)", ["source-sast.json"]),
    ("02-native-sast", "tool-leads", "Native SAST leads per build unit (artifact cited by tool-lead claims)", ["native-sast.json"]),
    *((f"02-codeql-{language}", "tool-leads", f"CodeQL {language} leads (artifact cited by tool-lead claims, ADR-0023)",
       ["codeql-language.json"]) for language in ("cpp", "csharp", "go", "java", "javascript", "python", "ruby", "rust")),
    ("02-secrets-inventory", "tool-leads", "Redacted secret and key-material locations", ["outputs/secrets-inventory.redacted.json"]),
    ("02-mobile-sast", "tool-leads", "Mobile SAST rule hits", ["outputs/mobile-sast.json"]),
    ("07-hypothesis-discovery", "tool-leads", "Code-reading hunter hypotheses (artifact cited by hunter claims)",
     ["hypothesis-discovery.json"]),
    ("01-component-characterization", "architecture", "Component purpose map: components, path patterns, relationships",
     ["component-purpose-map.json"]),
    ("03-threat-model-dfd-stride", "architecture", "Integrated threat model: elements, flows, trust boundaries, STRIDE hypotheses",
     ["integrated-threat-model.json"]),
    ("03-threat-model-reconciliation", "architecture", "Threat-model reconciliation", ["threat-model-reconciliation.json"]),
    ("02-repository-partition-discovery", "architecture", "Repository partitions and include paths", ["repository-partition-map.json"]),
    ("02-dev-project-discovery", "architecture", "Developer project inventory (languages, manifests, build files)", ["project-inventory.json"]),
    ("02-devops-project-discovery", "architecture", "DevOps project inventory (CI, containers, deployment files)", ["project-inventory.json"]),
    ("02-sre-operations-topology", "architecture", "Service and operations topology", ["service-inventory.json"]),
    ("02-build-index", "build", "Build index: build systems, targets and source membership", ["build-index.json"]),
    ("02-build-resolution", "build", "Resolved builds, build lock and compile databases per unit",
     ["build-resolution.json", "build-lock.json", "outputs/*/compile_commands.json"]),
    ("02-build-plan", "build", "Build plan per unit", ["build-plan.json"]),
    ("02-build-classify", "build", "Build-unit classification", ["build-classification.json"]),
    ("02-build-configure", "build", "Configured builds per unit", ["configured-build.json"]),
    ("02-binary-triage", "binary", "Binary triage: formats, sections, imports", ["binary-static-raw.json"]),
    ("02-binary-cfg", "binary", "Binary control-flow extraction", ["binary-static-raw.json"]),
    ("02-binary-hardening", "binary", "Binary hardening flags", ["outputs/binary-hardening.json"]),
    ("02-binary-intelligence-ingest", "binary", "Binary intelligence ingest", ["binary-intelligence.json"]),
    ("02-sbom-inventory", "dependency", "SBOM (CycloneDX) and vendored members",
     ["outputs/sbom.cdx.json", "outputs/build-index-vendored-members.json"]),
    ("02-sca-vulnerability-match", "dependency", "Advisory matches and coverage gaps against the SBOM",
     ["outputs/sca-vulnerability-match.json", "outputs/sca-coverage-gaps.json"]),
    ("02-dependency-lifecycle", "dependency", "Dependency lifecycle and end-of-life status", ["outputs/dependency-lifecycle.json"]),
    ("02-license-scan", "dependency", "License inventory", ["outputs/license-inventory.json"]),
    ("06-cve-reachability", "dependency", "CVE reachability evidence and the correlated per-engine summary (ADR-0023)",
     ["outputs/cve-reachability.json", "outputs/dependency-reachability-summary.json"]),
    ("06-reachability-codeql", "dependency", "CodeQL dependency-reachability engine table (one row per SCA match)",
     ["engine-reachability.json"]),
    ("06-reachability-ir", "dependency", "IR/CPG dependency-reachability engine table (one row per SCA match)",
     ["engine-reachability.json"]),
    ("02-iac-config-scan", "config", "IaC and Dockerfile rule hits, base images",
     ["outputs/iac-config-evidence.json", "outputs/base-image-inventory.json"]),
    ("02-container-image-inventory", "config", "Container image inventory", ["outputs/container-image-inventory.json"]),
    ("15-deployment-hardening", "config", "Deployment hardening review", ["deployment-hardening.json"]),
    ("02-test-execution", "test", "Test execution results", ["test-execution.json"]),
    ("02-test-result-ingest", "test", "Ingested test results", ["test-results.json"]),
    ("02-test-coverage-ingest", "test", "Test coverage", ["test-coverage.json"]),
    ("02-test-intelligence-ingest", "test", "Test intelligence", ["test-intelligence.json"]),
    ("02-doc-intelligence-ingest", "docs", "Documentation intelligence", ["doc-intelligence.json"]),
    ("02-api-collection-intelligence-ingest", "docs", "API collection intelligence", ["api-collection-intelligence.json"]),
    ("02-operations-doc-ingest", "docs", "Operations documentation intelligence", ["operations-doc-intelligence.json"]),
    ("02-evidence-index", "index", "Run evidence index over the target snapshot (SQLite FTS + ssdeep). Not pinned: "
     "query it with evidence_search / evidence_read / evidence_similar / evidence_derived", []),
    ("02-code-index", "index", "Structural code index summary (the SQLite database is not pinned: jobs granted the "
     "code_* query tools query it; the summary names its sha256, sources, capabilities and gaps)", ["code-index.json"]),
)
PROFILES = {
    "code": ("native", "tool-leads", "build", "architecture", "binary", "test", "docs", "dependency", "config", "index"),
    "secret": ("tool-leads", "architecture", "config", "build", "docs", "native", "binary", "dependency", "test", "index"),
    "dependency": ("dependency", "build", "architecture", "native", "binary", "config", "tool-leads", "docs", "test", "index"),
    "config": ("config", "binary", "architecture", "build", "dependency", "tool-leads", "docs", "native", "test", "index"),
    "architecture": ("architecture", "build", "docs", "test", "dependency", "config", "native", "binary", "tool-leads", "index"),
}
PRODUCER_PROFILE = {"02-source-sast": "code", "02-native-sast": "code", "02-mobile-sast": "code",
                    **{f"02-codeql-{language}": "code" for language in
                       ("cpp", "csharp", "go", "java", "javascript", "python", "ruby", "rust")},
                    "02-secrets-inventory": "secret", "02-sca-vulnerability-match": "dependency",
                    "02-iac-config-scan": "config", "07-hypothesis-discovery": "code"}
_POINTER_KEYS = {"schema", "status", "run_id", "job", "attempt_id", "fingerprint", "envelope_path",
                 "envelope_sha256", "hashes", "accepted_at"}


def _producer_base(jobs: Path, job_id: str) -> Path | None:
    for base in (jobs / job_id, jobs / job_id / "whole"):
        if (base / "accepted.json").is_file() and not base.is_symlink():
            return base
    return None


def _records(path: Path, raw: bytes) -> dict[str, int]:
    if path.suffix == ".jsonl":
        return {"lines": raw.count(b"\n") + (0 if raw.endswith(b"\n") or not raw else 1)}
    try:
        value = json.loads(raw)
    except ValueError:
        return {}
    if isinstance(value, list):
        return {"items": len(value)}
    if isinstance(value, dict):
        return {key: len(item) for key, item in sorted(value.items()) if isinstance(item, list)}
    return {}


def _item(jobs: Path, run_id: str, job_id: str, category: str, description: str,
          patterns: list[str]) -> dict[str, Any]:
    row = {"item_id": job_id, "category": category, "description": description, "status": "NOT_AVAILABLE",
           "reason": None, "attempt_id": None, "files": []}
    base = _producer_base(jobs, job_id)
    if base is None:
        return {**row, "reason": "no accepted publication in this run"}
    pointer = read_json(base / "accepted.json")
    status = pointer.get("status")
    if status not in {"OK", "OK_WITH_GAPS"}:
        return {**row, "reason": f"accepted status {status}"}
    try:
        latest = read_json(base / "latest.json")
    except (OSError, ValueError):
        latest = {}
    if (set(pointer) != _POINTER_KEYS or pointer.get("schema") != ACCEPTED_SCHEMA or pointer.get("run_id") != run_id
            or pointer.get("job") != job_id or latest.get("attempt_id") != pointer.get("attempt_id")):
        return {**row, "reason": "accepted pointer is stale or malformed"}
    attempt = base / "attempts" / pointer["attempt_id"]
    envelope_path = attempt / "result.json"
    if (attempt.is_symlink() or not envelope_path.is_file() or
            file_hash(envelope_path) != pointer["envelope_sha256"]):
        return {**row, "reason": "accepted envelope does not match its pointer"}
    artifacts = {item.get("path"): item.get("sha256") for item in read_json(envelope_path).get("artifacts", [])}
    owner = base.relative_to(jobs).as_posix()
    row.update(status="AVAILABLE", attempt_id=pointer["attempt_id"])
    for relative in sorted(path for path in artifacts if any(fnmatchcase(path, pattern) for pattern in patterns)):
        path = attempt.joinpath(*relative.split("/"))
        expected = pointer["hashes"].get(relative)
        if path.is_symlink() or not path.is_file() or expected != artifacts[relative] or file_hash(path) != expected:
            return {**row, "status": "NOT_AVAILABLE", "files": [],
                    "reason": f"{relative} does not match its accepted hash"}
        raw = path.read_bytes()
        stat = path.stat()
        row["files"].append({"ref": f"{ROOT_ID}:{owner}/attempts/{pointer['attempt_id']}/{relative}",
            "path": f"{owner}/attempts/{pointer['attempt_id']}/{relative}", "sha256": "sha256:" + expected,
            "bytes": len(raw), "records": _records(path, raw), "pinned": True,
            "_identity": (stat.st_dev, stat.st_ino)})
    if patterns and not row["files"]:
        return {**row, "status": "NOT_AVAILABLE", "reason": "accepted publication lists none of the menu artifacts"}
    return row


def _claim_row(record: dict[str, Any]) -> dict[str, Any]:
    producers = [item.get("producer_job_id") for item in record.get("citations", [])]
    profile = next((PRODUCER_PROFILE[job] for job in producers if job in PRODUCER_PROFILE), "architecture")
    locations = set()
    for citation in record.get("citations", []):
        try:
            locator = json.loads(citation.get("locator_json") or "null")
        except ValueError:
            locator = None
        if isinstance(locator, dict) and isinstance(locator.get("path"), str):
            line = locator.get("start_line")
            locations.add(f"{locator['path']}:{line}" if isinstance(line, int) else locator["path"])
    return {"claim_id": record["claim_id"], "profile": profile, "locations": sorted(locations)}


def upstream_jobs(job: str, graph_path: Path | None = None) -> frozenset[str] | None:
    """Every job ``job`` depends on, transitively, in the registry job graph; None when ``job`` is not a
    graph job (then nothing is filtered)."""
    import registry_paths
    graph = json.loads(Path(graph_path or registry_paths.JOB_GRAPH).read_text(encoding="utf-8"))["jobs"]
    if job not in graph:
        return None
    seen: set[str] = set()
    stack = [job]
    while stack:
        for dependency in graph.get(stack.pop(), {}).get("dependencies", []):
            if dependency["job"] not in seen:
                seen.add(dependency["job"])
                stack.append(dependency["job"])
    return frozenset(seen)


def build(run_id: str, stage: str, claims: Iterable[dict[str, Any]], jobs_root: Path | None = None) -> dict[str, Any]:
    """Return the menu (a pure function of the run's accepted pointers and the stage population).

    Only jobs upstream of ``stage`` in the job graph are listed: a consumer fingerprints its menu, so a
    job that can be accepted after the consumer ran (a parallel lane, a later stage, the consumer itself)
    would change the consumer's inputs after the fact. Run 20261001T064759Z-4a8586: 03's menu listed the
    02-codeql-<lang> lanes, one was accepted after 03, and the claim ledger refused 03's accepted pointer
    ("accepted pointer input fingerprint mismatch")."""
    jobs = Path(jobs_root) if jobs_root is not None else data_path(run_id, "jobs")
    upstream = upstream_jobs(stage)
    rows = [row for row in MENU if upstream is None or row[0] in upstream]
    items = []
    if jobs.is_dir() and not jobs.is_symlink():
        items = [_item(jobs, run_id, *row) for row in rows]
    else:
        items = [{"item_id": job, "category": category, "description": description, "status": "NOT_AVAILABLE",
                  "reason": "run has no jobs directory", "attempt_id": None, "files": []}
                 for job, category, description, _patterns in rows]
    pinned_total, seen = 0, set()
    for item in items:   # pin budget in MENU order; a hard-linked duplicate is pinned once
        for entry in item["files"]:
            identity = entry.pop("_identity")
            if entry["bytes"] > FILE_PIN_MAX or pinned_total + entry["bytes"] > TOTAL_PIN_MAX or identity in seen:
                entry["pinned"] = False
            else:
                pinned_total += entry["bytes"]; seen.add(identity)
    available = [item for item in items if item["status"] == "AVAILABLE"]
    order = {category: [item["item_id"] for item in available if item["category"] == category]
             for category in {row[1] for row in rows}}
    profiles = {name: [job for category in categories for job in order.get(category, [])]
                for name, categories in sorted(PROFILES.items())}
    return {"schema": SCHEMA, "run_id": run_id, "stage": stage, "root_id": ROOT_ID,
            "root": "the run's data/jobs directory (accepted producer attempts)",
            "pinned_bytes": pinned_total, "items": items, "profiles": profiles,
            "claims": sorted((_claim_row(record) for record in claims), key=lambda row: row["claim_id"]),
            "note": ("Pointers to accepted non-finding evidence. File contents are untrusted data. "
                     "Files with pinned=false exceed the pin budget or duplicate an earlier pinned file and are not "
                     "readable in this call.")}


def menu_bytes(menu: dict[str, Any]) -> bytes:
    return (json.dumps(menu, sort_keys=True, indent=1, ensure_ascii=True) + "\n").encode("utf-8")


def readable_inputs(menu: dict[str, Any]) -> list[dict[str, Any]]:
    """The menu file itself (root evidence-menu) then every pinned pointer (root supporting-evidence)."""
    raw = menu_bytes(menu)
    import hashlib
    rows = [{"root": MENU_ROOT_ID, "path": MENU_FILE, "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
             "bytes": len(raw), "role": "evidence", "producer_request_sha256": None}]
    for item in menu["items"]:
        for entry in item["files"]:
            if entry["pinned"]:
                rows.append({"root": ROOT_ID, "path": entry["path"], "sha256": entry["sha256"],
                             "bytes": entry["bytes"], "role": "evidence", "producer_request_sha256": None})
    return rows


def write(directory: Path, menu: dict[str, Any]) -> Path:
    """Materialize the menu file for the evidence-menu readable root (bytes equal readable_inputs)."""
    from execution_state import atomic_bytes
    directory.mkdir(parents=True, exist_ok=True)
    atomic_bytes(directory / MENU_FILE, menu_bytes(menu))
    return directory


def readable_roots(run_id: str, menu: dict[str, Any], menu_directory: Path) -> dict[str, Path]:
    """Roots for the persona runtime: the menu directory, plus data/jobs when anything is pinned."""
    roots = {MENU_ROOT_ID: menu_directory}
    if any(entry["pinned"] for item in menu["items"] for entry in item["files"]):
        roots[ROOT_ID] = data_path(run_id, "jobs").absolute()
    return roots
