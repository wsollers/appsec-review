#!/usr/bin/env python3
"""Threat workbench for ``03-threat-model-dfd-stride`` (ADR-0008 T05/T07/T08; ADR-0019 slice 1).

The deterministic DFD/STRIDE core (``threat_model_core.build_model``) is the substrate.  This module
adds the persona overlays ADR-0008 describes, as the smallest complete vertical slice:

* **wave runner (T05)** -- each wave is one C01 pool specification (one worker group per selected
  workcell) launched through ``pool_launcher`` and joined by the C02 ``wait_all`` rendezvous.
  Concurrency comes from the job's budget-class tunables, never a local constant.  Wave 1 cells
  read the frozen lane-in bundle; wave 2 cells additionally read ``wave-1-model.json``, the
  deterministic join of wave 1 (the only channel between waves).
* **cells** -- ``pii-user-data-mapper`` (the L13 privacy cell: data classes, personal-data flows,
  LINDDUN privacy threats, candidate regulatory notes), ``deployment-topology-mapper`` (declared
  deployment zones and extra trust boundaries), ``abuse-scenario-analyst``,
  ``attack-tree-builder`` and the trait-selected ``supply-chain-specialist``.  Every cell is a
  registry composition (persona + role + domain + tooling profile + output contract).  Cells
  return judgment only (``threat-workbench-cell-persona.schema.json``).
* **evidence** -- each cell reads the base model, the accepted component map, a supporting-evidence
  menu (``supporting_evidence_menu`` when that module is present, else the same shape built from
  the exact F02 assembly manifest the core already binds) and, by tunable, every target file
  pinned at the bound snapshot, served through the invoker's lookup tools.
* **join (T07)** -- Python derives every id, citation, evidence class, exposure label and
  cross-reference; resolves references to DFD ids; records unresolved references, unresolvable
  evidence refs, failed or omitted cells and open intercom records as gaps; never fails a run on
  model output (ADR-0013).  The join is a pure function of the base model, the retained cell
  replies and the retained readable-input index, so validation replays it byte for byte.
* **validator (T08)** -- :func:`validate_overlays` checks ids, references, attack-tree structure,
  evidence leaves, exposure labels and rescope triggers on the integrated model.
* **intercom (T06 caller)** -- cell notes become typed intercom records appended through
  ``threat_workbench_intercom.IntercomTranscript``; the sweep's open records become assumptions
  and gaps.

Not built in this slice (recorded in coverage, see ADR-0019): the challenge/refutation cell (wave
3) and response round (wave 4), the agent/native/mobile/cloud specialists, and persona versions of
the architecture and STRIDE cells (the deterministic core stands in for them).
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any, Callable, Iterable

import tunables
from execution_state import Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash, read_json, run_path
from schema_validate import SchemaStore, validate_document
import threat_workbench_intercom as intercom

JOB = "03-threat-model-dfd-stride"
RECORD_SCHEMA = "appsec-review/threat-workbench-record/0.1"
CELL_FILE = "cell-output.json"
CELL_SCHEMA = "threat-workbench-cell-persona.schema.json"
CELL_CONTRACT = "threat-workbench-cell-output"
BUNDLE_ROOT = "workbench-bundle"
TARGET_ROOT = "target-repository"          # persona_dispatch.DEFAULT_READABLE_ROOT
ASSEMBLY_ROOT = "evidence-assembly"        # fallback menu root: the exact F02 assembly attempt
BASE_FILE, COMPONENT_FILE, WAVE1_FILE, MENU_FILE = (
    "base-model.json", "component-map.json", "wave-1-model.json", "evidence-menu.json")
WORKDIR = "workbench"
MANIFEST = "workcell-manifest.json"
TRANSCRIPT = "intercom-transcript.jsonl"
TREES_MMD, DFD_MMD, RANKED = "attack-trees.mmd", "dfd.mmd", "ranked-threat-scenarios.json"
DETERMINISTIC_CELLS = frozenset({"deterministic-dfd-core", "deterministic-stride-core"})
ROUTER = "domain-specialist-router"
INTEGRATOR = "integrator"
OK_STATES = ("OK", "OK_WITH_GAPS")
SENSITIVE = frozenset({"pii", "credential", "secret", "payment", "regulated"})
PERSONAL = frozenset({"pii", "credential", "secret", "payment", "regulated", "location", "device_id"})
ADMIN_FILES = frozenset({"permission.json", "lineage.json", "status.json", "result.json", "b13-receipt.json"})
MENU_EXCLUDED = frozenset({"02-standards-source-ingest"})   # a corpus, not target evidence


@dataclass(frozen=True)
class Workcell:
    workcell_id: str
    wave: int
    persona_id: str
    selection: str           # "always" or "trait:<name>"
    families: tuple

    @property
    def template_id(self) -> str:
        return "threat-workbench-" + self.workcell_id


WORKCELLS = (
    Workcell("pii-user-data-mapper", 1, "privacy-and-user-data-modeler", "always",
             ("data_classes", "privacy_threats")),
    Workcell("deployment-topology-mapper", 1, "deployment-and-zone-modeler", "trait:deployment",
             ("deployment_zones", "trust_boundaries")),
    Workcell("abuse-scenario-analyst", 2, "abuse-case-and-attacker-objective-analyst", "always",
             ("abuse_scenarios",)),
    Workcell("attack-tree-builder", 2, "attack-tree-and-chain-builder", "always", ("attack_trees",)),
    Workcell("supply-chain-specialist", 2, "supply-chain-threat-specialist", "trait:third_party",
             ("abuse_scenarios", "attack_trees")),
)
CELLS = {cell.workcell_id: cell for cell in WORKCELLS}
NOTE_TYPES = ("question", "assumption", "coverage_gap", "proposed_threat")
# ADR-0008 workcells this slice does not run: (id, wave, trait that would select it, reason).
NOT_BUILT = (
    ("architecture-dfd-mapper", 1, None, "substituted by deterministic-dfd-core (ADR-0019 slice 1)"),
    ("stride-enumerator", 2, None, "substituted by deterministic-stride-core (ADR-0019 slice 1)"),
    ("agent-tool-boundary-specialist", 2, "agent", "specialist cell not built (ADR-0019 slice 1)"),
    ("native-parser-input-specialist", 2, "native", "specialist cell not built (ADR-0019 slice 1)"),
    ("mobile-client-specialist", 2, "mobile", "specialist cell not built (ADR-0019 slice 1)"),
    ("cloud-control-plane-specialist", 2, "cloud", "specialist cell not built (ADR-0019 slice 1)"),
    ("challenge-refutation-cell", 3, None, "wave 3 challenge cell not built (ADR-0019 slice 1)"),
)
NOTE_TARGETS = frozenset({*CELLS, *(row[0] for row in NOT_BUILT), INTEGRATOR})
SENSITIVITY = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
EVIDENCE_WEIGHT = {"DIRECT_EVIDENCE": 3, "STRONG_INFERENCE": 2, "WEAK_INFERENCE": 1, "FOLLOW_ON_REQUIRED": 0}
EXPOSED_ZONES = frozenset({"public_ingress", "client_device", "third_party"})
LINDDUN_SHORT = {"linking": "l", "identifying": "i", "non_repudiation": "nr", "detecting": "d",
                 "data_disclosure": "dd", "unawareness": "u", "non_compliance": "nc"}

DEPLOY_FILE = re.compile(r"(^|/)(Dockerfile[^/]*|[^/]*\.dockerfile|docker-compose[^/]*\.ya?ml|compose\.ya?ml|"
                         r"[^/]*\.tf|Chart\.yaml|kustomization\.ya?ml|Procfile|[^/]*\.service|nginx[^/]*\.conf|"
                         r"app\.ya?ml|serverless\.ya?ml)$", re.IGNORECASE)
CLOUD_FILE = re.compile(r"(^|/)([^/]*\.tf|Chart\.yaml|kustomization\.ya?ml)$|(^|/)(k8s|kubernetes|helm)/",
                        re.IGNORECASE)
THIRD_PARTY_PRODUCERS = ("02-sbom-inventory", "02-sca-vulnerability-match", "02-dependency-lifecycle")
NATIVE_PRODUCERS = ("02-native-sast", "02-ir-facts", "02-native-build")
AGENT_WORDS = re.compile(r"\b(llm|agent|mcp|model context protocol|openai|anthropic|langchain|tool[- ]use)\b",
                         re.IGNORECASE)
MOBILE_WORDS = re.compile(r"\b(android|ios|mobile app|apk|swiftui|kotlin)\b", re.IGNORECASE)
MENU_DESCRIPTIONS = {
    "02-dev-project-discovery": ("architecture", "Developer project inventory (languages, manifests, build files)"),
    "02-devops-project-discovery": ("architecture", "DevOps project inventory (CI, containers, deployment files)"),
    "02-sre-operations-topology": ("architecture", "Service and operations topology"),
    "02-source-sast": ("tool-leads", "Source SAST leads"),
    "02-native-sast": ("tool-leads", "Native SAST leads per build unit"),
    "02-secrets-inventory": ("tool-leads", "Redacted secret and key-material locations"),
    "02-mobile-sast": ("tool-leads", "Mobile SAST rule hits"),
    "02-sbom-inventory": ("dependency", "SBOM (CycloneDX) and vendored members"),
    "02-sca-vulnerability-match": ("dependency", "Advisory matches and coverage gaps against the SBOM"),
    "02-dependency-lifecycle": ("dependency", "Dependency lifecycle and end-of-life status"),
    "02-license-scan": ("dependency", "License inventory"),
    "02-iac-config-scan": ("config", "IaC and Dockerfile rule hits, base images"),
    "02-container-image-inventory": ("config", "Container image inventory"),
    "02-binary-hardening": ("binary", "Binary hardening flags"),
    "02-doc-intelligence-ingest": ("docs", "Documentation intelligence"),
    "02-api-collection-intelligence-ingest": ("docs", "API collection intelligence"),
    "02-operations-doc-ingest": ("docs", "Operations documentation intelligence"),
    "02-ir-facts": ("native", "IR facts: functions, calls and memory operations with source file/line"),
    "02-code-property-graph": ("native", "Code property graph summary and records"),
}
CODE_FILES = (
    "threat_workbench.py", "threat_workbench_intercom.py",
    *(f"registry/job-templates/{cell.template_id}.json" for cell in WORKCELLS),
    *(f"registry/personas/{cell.persona_id}.json" for cell in WORKCELLS),
    *(f"03-threat-model-dfd-stride/cells/{cell.workcell_id}.md" for cell in WORKCELLS),
    "registry/roles/data-flow-modeler.json", "registry/roles/abuse-modeler.json",
    "registry/roles/attack-modeler.json", "registry/domains/threat-model-graph.json",
    "registry/tooling-profiles/threat-workbench-static-evidence.json",
    "registry/output-contracts/threat-workbench-cell-output.json",
)
SCHEMA_FILES = (CELL_SCHEMA, "threat-model-privacy-threat.schema.json", "threat-model-abuse-scenario.schema.json",
                "threat-model-attack-tree.schema.json", "threat-model-data-class.schema.json",
                "threat-model-deployment-zone.schema.json", "threat-workbench-cell-result.schema.json",
                "threat-workbench-intercom-record.schema.json", "threat-workbench-wave-manifest.schema.json")


def code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    for name in SCHEMA_FILES:
        values[f"schemas/{name}"] = file_hash(ROOT.parent / "schemas" / name)
    return values


def _slug(value: Any, limit: int = 48) -> str:
    text = re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", str(value).lower())).strip("-")
    return text[:limit].strip("-") or "item"


def _tunable(name: str) -> Any:
    return tunables.value(JOB, name)


# ---- lane-in: tunables, menu, traits -------------------------------------------------------------

def settings() -> dict[str, Any]:
    budget_class = _tunable("workbench_budget_class")
    if budget_class not in ("probe", "standard", "deep"):
        raise Blocked(f"{JOB}: workbench_budget_class {budget_class!r} is not probe/standard/deep")
    tier = _tunable("workbench_cell_budget")
    if tier not in ("probe", "standard", "full"):
        raise Blocked(f"{JOB}: workbench_cell_budget {tier!r} is not probe/standard/full")
    return {"enabled": bool(_tunable("workbench_enabled")), "budget_class": budget_class,
            "concurrent_cells": int(_tunable(f"workbench_concurrent_cells_{budget_class}")),
            "cell_budget": tier, "wave_timeout_seconds": int(_tunable("workbench_wave_timeout_seconds")),
            "pin_target_source": bool(_tunable("workbench_pin_target_source")),
            "menu_pin_max_bytes": int(_tunable("workbench_menu_pin_max_bytes")),
            "menu_file_pin_max_bytes": int(_tunable("workbench_menu_file_pin_max_bytes")),
            "record_limit": int(_tunable("workbench_records_per_cell_max"))}


def target_root(run_id: str) -> Path:
    manifest_path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise Blocked(f"{JOB}: staged artifact-manifest.json is required for the threat workbench")
    manifest = read_json(manifest_path)
    target = manifest.get("target") if isinstance(manifest, dict) else None
    value = target.get("repo_path") if isinstance(target, dict) else None
    path = Path(value) if isinstance(value, str) else Path()
    if not value or not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked(f"{JOB}: target.repo_path must be an absolute real checkout directory")
    return path.resolve()


def target_files(root: Path) -> list[str]:
    """Relative paths of regular target files (names only; nothing is read). ``.git`` excluded."""
    paths: list[str] = []
    for folder, directories, files in os.walk(root):
        directories[:] = sorted(d for d in directories if d != ".git")
        base = Path(folder)
        for name in sorted(files):
            path = base / name
            if not path.is_symlink() and path.is_file():
                paths.append(path.relative_to(root).as_posix())
    return sorted(paths)


def _pin(items: list[dict[str, Any]], total_max: int, file_max: int) -> None:
    total = 0
    for item in items:
        for entry in item["files"]:
            if entry["pinned"] and (entry["bytes"] > file_max or total + entry["bytes"] > total_max):
                entry["pinned"] = False
            elif entry["pinned"]:
                total += entry["bytes"]


def build_menu(run_id: str, evidence_attempt: Path, evidence_attempt_id: str, evidence_run_path: str,
               config: dict[str, Any], *, jobs_root: Path | None = None) -> tuple[dict[str, Any], str]:
    """The cells' supporting-evidence menu and the absolute directory its root id names.

    Prefers ``supporting_evidence_menu`` (review-batch branch; ADR-0015) when it is importable,
    restricted to producers upstream of this job (01-/02-, so the menu can never create a cycle
    through 03/06/15).  Otherwise builds the same shape from the exact F02 assembly manifest the
    core already binds.  Every file entry names its producer, attempt and run-relative path, so
    a cell's evidence ref resolves to a hash-bound citation."""
    try:
        import supporting_evidence_menu as sem   # type: ignore[import-not-found]
    except ImportError:
        sem = None
    if sem is not None:
        jobs = Path(jobs_root) if jobs_root is not None else data_path(run_id, "jobs")
        menu = sem.build(run_id, JOB, [], jobs)
        menu["items"] = [item for item in menu["items"] if item["item_id"].startswith(("01-", "02-"))
                         and item["item_id"] not in MENU_EXCLUDED]
        menu["profiles"] = {key: [job for job in value if job.startswith(("01-", "02-"))]
                            for key, value in menu.get("profiles", {}).items()}
        menu["claims"] = []
        for item in menu["items"]:
            for entry in item["files"]:
                entry["producer"], entry["attempt_id"] = item["item_id"], item["attempt_id"]
                entry["run_path"] = "data/jobs/" + entry["path"]
        _pin(menu["items"], config["menu_pin_max_bytes"], config["menu_file_pin_max_bytes"])
        menu["source"] = "supporting_evidence_menu"
        return menu, str(jobs.absolute())
    manifest_path = evidence_attempt / "intel-manifest.json"
    manifest = read_json(manifest_path)
    items = []
    for producer in sorted(manifest.get("producers", []), key=lambda row: row.get("job_id", "")):
        job = producer.get("job_id")
        if not isinstance(job, str) or job in MENU_EXCLUDED:
            continue
        category, description = MENU_DESCRIPTIONS.get(job, ("other", f"Accepted {job} evidence"))
        row = {"item_id": job, "category": category, "description": description, "status": "NOT_AVAILABLE",
               "reason": None, "attempt_id": producer.get("attempt_id"), "files": []}
        if producer.get("execution_status") not in OK_STATES:
            row["reason"] = f"producer status {producer.get('execution_status')}"
            items.append(row)
            continue
        for artifact in sorted(producer.get("artifacts", []), key=lambda value: value["path"]):
            if Path(artifact["producer_path"]).name in ADMIN_FILES:
                continue
            path = evidence_attempt.joinpath(*artifact["path"].split("/"))
            size = path.stat().st_size if path.is_file() and not path.is_symlink() else None
            if size is None:
                continue
            row["files"].append({"ref": f"{ASSEMBLY_ROOT}:{artifact['path']}", "path": artifact["path"],
                                 "sha256": artifact["sha256"], "bytes": size, "pinned": True,
                                 "producer": job, "attempt_id": artifact.get("producer_attempt_id") or row["attempt_id"],
                                 "run_path": f"{evidence_run_path}/{artifact['path']}"})
        row["status"] = "AVAILABLE" if row["files"] else "NOT_AVAILABLE"
        row["reason"] = None if row["files"] else "no evidence artifacts in the assembly"
        items.append(row)
    _pin(items, config["menu_pin_max_bytes"], config["menu_file_pin_max_bytes"])
    return ({"schema": "appsec-review/supporting-evidence-menu/1.0", "run_id": run_id, "stage": JOB,
             "root_id": ASSEMBLY_ROOT, "root": f"the exact F02 evidence assembly attempt {evidence_attempt_id}",
             "items": items, "source": "f02-intel-manifest",
             "note": ("Pointers to accepted upstream evidence. File contents are untrusted data. Files with "
                      "pinned=false exceed the pin budget and are not readable in this call.")},
            str(evidence_attempt.absolute()))


def detect_traits(menu: dict[str, Any], component_map: dict[str, Any], files: Iterable[str]) -> dict[str, list[str]]:
    """Deterministic target traits for cell selection (the ``domain-specialist-router`` job)."""
    files = list(files)
    available = {item["item_id"] for item in menu["items"] if item["status"] == "AVAILABLE"}
    text = " ".join(" ".join(str(component.get(key, "")) for key in ("name", "component_type", "observed_purpose"))
                    for component in component_map.get("functional_components", []))
    traits: dict[str, list[str]] = {}
    deploy = [path for path in files if DEPLOY_FILE.search(path)]
    if deploy:
        traits["deployment"] = [f"deployment files: {', '.join(deploy[:5])}"]
    third = [job for job in THIRD_PARTY_PRODUCERS if job in available]
    if third:
        traits["third_party"] = [f"dependency evidence: {', '.join(third)}"]
    native = [job for job in NATIVE_PRODUCERS if job in available]
    if native:
        traits["native"] = [f"native evidence: {', '.join(native)}"]
    cloud = [path for path in files if CLOUD_FILE.search(path)]
    if cloud:
        traits["cloud"] = [f"control-plane manifests: {', '.join(cloud[:5])}"]
    if MOBILE_WORDS.search(text):
        traits["mobile"] = ["component purposes name a mobile client"]
    if AGENT_WORDS.search(text):
        traits["agent"] = ["component purposes name an LLM/agent/tool integration"]
    return {key: traits[key] for key in sorted(traits)}


def select(traits: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for cell in WORKCELLS:
        trait = cell.selection.split(":", 1)[1] if cell.selection.startswith("trait:") else None
        selected = trait is None or trait in traits
        rows.append({"workcell_id": cell.workcell_id, "wave": cell.wave, "selected": selected,
                     "reason": None if selected else f"trait {trait!r} not present"})
    return rows


def current_inputs(run_id: str, core: dict[str, Any]) -> dict[str, Any]:
    """Workbench part of the job's immutable inputs (fingerprinted with the core's)."""
    config = settings()
    root = target_root(run_id)
    evidence_attempt = data_path(run_id, "jobs", "02-evidence-assembly", "attempts", core["evidence_attempt_id"])
    evidence_run_path = str(Path(core["evidence_path"]).parent.as_posix())
    # evidence_path is <run-relative attempt>/<artifact>; the attempt prefix is the part before the artifact
    marker = f"/attempts/{core['evidence_attempt_id']}"
    if marker in core["evidence_path"]:
        evidence_run_path = core["evidence_path"].split(marker, 1)[0] + marker
    menu, menu_dir = build_menu(run_id, evidence_attempt, core["evidence_attempt_id"], evidence_run_path, config)
    traits = detect_traits(menu, core["component_map"], target_files(root))
    return {"settings": config, "target_root": str(root), "menu": menu, "menu_dir": menu_dir,
            "traits": traits, "selection": select(traits)}


# ---- execution: bundle, pool per wave -------------------------------------------------------------

@dataclass
class CellRuntime:
    """Launch-side facts a wave needs: the invoker and model identity per job template. Tests
    supply a fake invoker; production uses the strict Claude CLI invoker."""
    invoker: Any
    model_for: Callable[[str], dict[str, Any]]
    now: str


def default_runtime(run_id: str) -> CellRuntime:
    import claude_cli_invoker as cli
    import model_version_registry as model_versions
    import persona_prompt_assembly as ppa
    import review_cli
    model_versions.resolve_run_model_versions(run_id)
    store = SchemaStore()

    def model_for(template_id: str) -> dict[str, Any]:
        template = ppa.load_job_template(template_id, store)
        resolved = review_cli.resolve_model(template_id, template["budget_default"])
        return model_versions.model_identity_for(run_id, resolved["model"])

    return CellRuntime(invoker=cli.ClaudeCliInvoker(effort="high"), model_for=model_for,
                       now=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))


def _cell_claims(value: dict[str, Any], inputs: tuple, allowed: tuple, result_filename: str) -> list[dict[str, Any]]:
    """B14 transport claims for a cell reply: one candidate-only claim per non-empty family."""
    first = inputs[0]
    claim_class = "candidate_only" if "candidate_only" in allowed else allowed[0]
    families = [key for key in ("data_classes", "privacy_threats", "deployment_zones", "trust_boundaries",
                                "abuse_scenarios", "attack_trees", "notes", "gaps") if value.get(key)]
    claims = []
    for key in families or ["summary"]:
        count = len(value.get(key) or []) if key != "summary" else 0
        claims.append({"claim_id": f"cell-{key.replace('_', '-')}", "claim_class": claim_class,
                       "statement": (f"Candidate threat-model overlay: {count} {key.replace('_', ' ')}."
                                     if count else "Cell reply with no overlay records."),
                       "file": result_filename,
                       "citations": [{"root": first.root, "path": first.path, "sha256": first.sha256,
                                      "locator": key}]})
    return claims


def register_claim_builder() -> None:
    import claude_cli_invoker as cli
    cli._CLAIM_BUILDERS.setdefault(CELL_SCHEMA, _cell_claims)


def _bytes_entry(root_id: str, path: str, data: bytes) -> dict[str, Any]:
    import hashlib
    return {"root": root_id, "path": path, "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "role": "evidence", "producer_request_sha256": None}


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=1, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def _brief(cell: Workcell, base: dict[str, Any], wave1: dict[str, Any] | None, traits: dict[str, Any],
           menu_root: str, record_limit: int) -> dict[str, Any]:
    brief = {"schema": "appsec-review/threat-workbench-cell-brief/0.1", "workcell_id": cell.workcell_id,
             "wave": cell.wave, "persona_id": cell.persona_id, "families": list(cell.families),
             "record_limit_per_family": record_limit,
             "element_ids": sorted(item["element_id"] for item in base["elements"]),
             "flow_ids": sorted(item["flow_id"] for item in base["flows"]),
             "boundary_ids": sorted(item["boundary_id"] for item in base["trust_boundaries"]),
             "component_ids": sorted(item["component_id"] for item in base["elements"] if item["component_id"]),
             "note_targets": sorted(NOTE_TARGETS), "traits": traits,
             "evidence_ref_formats": {
                 "target_file": f"{TARGET_ROOT}:<repository-relative path>[:<line>[-<line>]]",
                 "menu_file": f"{menu_root}:<path exactly as evidence-menu.json lists it>",
                 "bundle_file": f"{BUNDLE_ROOT}:{COMPONENT_FILE} (weak: the component map itself)"},
             "claim_limits": "candidates only; no findings, severity, runtime state, compliance verdicts, "
                             "intent or remediation status"}
    if wave1 is not None:
        brief["wave_1_ids"] = {"data_class_ids": sorted(item["data_class_id"] for item in wave1["data_classes"]),
                               "zone_ids": sorted(item["zone_id"] for item in wave1["deployment_zones"]),
                               "privacy_threat_ids": sorted(item["privacy_threat_id"] for item in wave1["privacy_threats"]),
                               "boundary_ids": sorted(item["boundary_id"] for item in wave1["trust_boundaries"])}
    return brief


def _readable_index(menu: dict[str, Any], target_entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for item in menu["items"]:
        for entry in item["files"]:
            if entry["pinned"]:
                job = entry["producer"]
                index[f"{menu['root_id']}:{entry['path']}"] = {
                    "sha256": entry["sha256"].removeprefix("sha256:"), "producer": job,
                    "attempt_id": entry["attempt_id"], "run_path": entry["run_path"],
                    "source_class": "accepted_lane" if job.startswith("01-") else "derived"}
    for entry in target_entries:
        index[f"{TARGET_ROOT}:{entry['path']}"] = {"sha256": entry["sha256"].removeprefix("sha256:")}
    return {key: index[key] for key in sorted(index)}


def _menu_inputs(menu: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"root": menu["root_id"], "path": entry["path"], "sha256": entry["sha256"], "bytes": entry["bytes"],
             "role": "evidence", "producer_request_sha256": None}
            for item in menu["items"] for entry in item["files"] if entry["pinned"]]


def _cell_request(run_id: str, cell: Workcell, readable: list[dict[str, Any]], runtime: CellRuntime,
                  tier: str, source: str, prompt_root: Path, store: SchemaStore) -> tuple[dict, dict, str]:
    import persona_dispatch as pd
    import persona_invocation as pi
    import persona_prompt_assembly as ppa
    prompt, template = ppa.assemble_prompt_text(cell.template_id, store)
    data = prompt.encode("utf-8")
    atomic_bytes(prompt_root / f"{cell.workcell_id}.md", data)
    composition = pd._composition_block(cell.template_id, template, store)
    records = pi.load_composition(pi.REGISTRY_DIR, composition, store)
    ceiling = pi.claim_ceiling(records["role"], records["tooling_profile"])
    if "candidate_only" not in ceiling["allowed"]:
        raise Blocked(f"{JOB}: workcell {cell.workcell_id} composition cannot emit candidate-only work")
    model = runtime.model_for(cell.template_id)
    request = {"invocation_role": "produce", "invoker_id": "claude-cli",
               "outer_prompt": {"path": f"{cell.workcell_id}.md", "sha256": pi._bytes_sha(data), "bytes": len(data)},
               "persona": composition, "model": model, "tools": [], "budget": dict(pd.PERSONA_BUDGETS[tier]),
               "readable_inputs": readable, "allowed_claim_classes": ["candidate_only"],
               "prohibited_claim_classes": sorted(set(ceiling["prohibited"]) | (set(ceiling["allowed"]) - {"candidate_only"})),
               "producers": []}
    permission = pd._permission_block(JOB, run_id=run_id, source_snapshot_sha256=source, now=runtime.now)
    return request, permission, pi._bytes_sha(data).removeprefix("sha256:")


def _run_wave(run_id: str, wave: int, cells: list[Workcell], *, work: Path, bundle: Path, menu: dict[str, Any],
              menu_dir: str, target: str, target_entries: list[dict[str, Any]], config: dict[str, Any],
              runtime: CellRuntime, source: str, attempt_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Launch one wave as a C01 pool and wait-all (C02). Returns per-cell rows and the pool record.
    A cell that did not produce a verified reply is a row with a non-OK status, never an exception."""
    import container_execution
    import persona_invocation as pi
    import pool_launcher
    import pool_rendezvous
    import pool_specification
    import resource_pools
    register_claim_builder()
    store = SchemaStore()
    prompt_root = work / "prompts"; prompt_root.mkdir(parents=True, exist_ok=True)
    pool_parent = work / "pools"; pool_parent.mkdir(parents=True, exist_ok=True)
    rendezvous = work / "rendezvous"; rendezvous.mkdir(parents=True, exist_ok=True)
    shared = [_bytes_entry(BUNDLE_ROOT, name, (bundle / name).read_bytes())
              for name in (BASE_FILE, COMPONENT_FILE, MENU_FILE, *( [WAVE1_FILE] if wave == 2 else []))]
    groups, meta, models = [], {}, []
    for cell in cells:
        brief = f"cell-brief-{cell.workcell_id}.json"
        readable = [*shared, _bytes_entry(BUNDLE_ROOT, brief, (bundle / brief).read_bytes()),
                    *_menu_inputs(menu), *target_entries]
        request, permission, prompt_hash = _cell_request(run_id, cell, readable, runtime, config["cell_budget"],
                                                         source, prompt_root, store)
        if request["model"] not in models:
            models.append(request["model"])
        meta[cell.workcell_id] = {"prompt_hash": prompt_hash, "model_identity_hash": digest(request["model"])}
        groups.append({"group_id": cell.workcell_id, "worker_kind": pool_specification.PERSONA, "count": 1,
                       "memory_heavy": False, "permission": permission, "persona_request": request,
                       "tool_request": None})
    groups.sort(key=lambda group: group["group_id"])   # C01: sorted, unique group ids
    budget = groups[0]["persona_request"]["budget"]
    spec = {"schema": pool_specification.SPEC_ID, "pool_id": f"threat-workbench-wave-{wave}", "lane": JOB,
            "run_id": run_id, "job_id": JOB, "attempt_id": f"wb-w{wave}-" + digest(attempt_id)[:24],
            "budget_class": config["budget_class"],
            "pool_budget": {"max_instances": len(groups),
                            "max_persona_input_units": budget["input_unit_limit"] * len(groups),
                            "max_persona_output_units": budget["output_unit_limit"] * len(groups),
                            "max_total_timeout_seconds": budget["timeout_seconds"] * len(groups)},
            "resource_pool_policy": {"allowed_pools": [resource_pools.PERSONA_LLM]},
            "wait_all": True, "rendezvous_timeout_seconds": config["wave_timeout_seconds"],
            "empty_pool_reason": None, "worker_groups": groups}
    roots = {BUNDLE_ROOT: bundle, menu["root_id"]: Path(menu_dir)}
    if target_entries:
        roots[TARGET_ROOT] = Path(target)
    context = pool_specification.PoolContext(pool_parent=pool_parent, registry_dir=pi.REGISTRY_DIR,
        prompt_root=prompt_root, readable_roots=roots, allowed_models=tuple(models), invoker_id="claude-cli",
        images_dir=container_execution.IMAGES_DIR, host_flavor="windows" if os.name == "nt" else "posix",
        docker_host=None, docker_executable=None, container_user=None, mount_roots={},
        source_snapshot_sha256=source, registry_ceiling=None)
    started = runtime.now
    rows = {cell.workcell_id: {"workcell_id": cell.workcell_id, "wave": wave, "selection": "selected",
                               "omission_reason": None, "instance_id": None, "persona_id": cell.persona_id,
                               "prompt_hash": meta[cell.workcell_id]["prompt_hash"],
                               "model_identity_hash": meta[cell.workcell_id]["model_identity_hash"],
                               "terminal_status": "FAILED", "cause": "no verified reply",
                               "output_sha256": None, "started_at": started, "finished_at": started}
            for cell in cells}
    pool = {"wave": wave, "pool_directory": None, "expansion_sha256": None, "terminal_manifest_sha256": None,
            "outcome": "FAILED", "cause": None}
    try:
        live = pool_rendezvous.RendezvousRuntime(rendezvous_parent=rendezvous, invoker=runtime.invoker,
            clock=lambda: runtime.now, stop_grace_seconds=5, cancel=pool_rendezvous.PoolCancel(),
            max_parallel=max(1, min(config["concurrent_cells"], len(groups))),
            wait_limit_seconds=config["wave_timeout_seconds"], drain_seconds=10)
        launched = pool_launcher.launch(spec, context=context, runtime=live)
        pool_root = context.pool_parent / launched.pool_directory
        verified = pool_rendezvous.load_verified_manifest(pool_root, expected_spec=spec, context=context,
                                                          rendezvous_parent=rendezvous)
        pool.update(pool_directory=launched.pool_directory, expansion_sha256=launched.expansion_sha256,
                    terminal_manifest_sha256=launched.terminal_manifest_sha256, outcome=launched.outcome)
        for item in verified.instances:
            group = item.instance.entry.get("group_id")
            row = rows.get(group)
            if row is None:
                continue
            row["instance_id"] = item.instance.instance_id
            state = item.state
            status = {pool_rendezvous.SUCCEEDED: "OK", pool_rendezvous.BLOCKED: "BLOCKED",
                      pool_rendezvous.CANCELED: "CANCELED"}.get(state, "FAILED")
            row["terminal_status"], row["cause"] = status, None if status == "OK" else f"pool state {state}"
            if status != "OK":
                continue
            adapter = item.result
            matches = [entry for entry in adapter["outputs"] if entry["path"] == CELL_FILE]
            path = item.instance.attempt_root_path(pool_root) / adapter["output_root"] / CELL_FILE
            if (len(matches) != 1 or path.is_symlink() or not path.is_file()
                    or "sha256:" + file_hash(path) != matches[0]["sha256"]):
                row["terminal_status"], row["cause"] = "FAILED", "verified reply file is absent or changed"
                continue
            destination = work / "cells" / group / CELL_FILE
            destination.parent.mkdir(parents=True, exist_ok=True)
            atomic_bytes(destination, path.read_bytes())
            row["output_sha256"] = file_hash(destination)
    except Exception as exc:   # ADR-0013: a wave that cannot run is recorded, not fatal
        pool["cause"] = f"{type(exc).__name__}: {str(exc)[:300]}"
        for row in rows.values():
            if row["terminal_status"] == "FAILED" and row["cause"] == "no verified reply":
                row["cause"] = pool["cause"]
    finished = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for row in rows.values():
        row["finished_at"] = max(finished, started)
    return [rows[cell.workcell_id] for cell in cells], pool


EMPTY_RECORD = {"schema": RECORD_SCHEMA, "enabled": False, "budget_class": "standard", "record_limit": 60,
                "traits": {}, "selection": [], "menu_root": ASSEMBLY_ROOT, "cells": [], "pools": [],
                "readable_index": {}, "wave_1_model_sha256": None}


def execute(run_id: str, core: dict[str, Any], attempt: Path, attempt_id: str, base: dict[str, Any],
            runtime: CellRuntime | None = None) -> dict[str, Any] | None:
    """Run the waves and retain what the join needs. Returns the workbench record (also written
    to ``workbench/workcell-manifest.json``)."""
    import persona_dispatch as pd
    if "workbench" not in core:
        return None   # pre-ADR-0019 callers: the deterministic core publishes alone
    wb = core["workbench"]
    config = wb["settings"]
    work = attempt / WORKDIR
    bundle = work / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    atomic_bytes(bundle / BASE_FILE, _json_bytes(base))
    atomic_bytes(bundle / COMPONENT_FILE, _json_bytes(core["component_map"]))
    atomic_bytes(bundle / MENU_FILE, _json_bytes(wb["menu"]))
    target_entries: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    pools: list[dict[str, Any]] = []
    outputs: dict[str, dict[str, Any]] = {}
    selected = {row["workcell_id"] for row in wb["selection"] if row["selected"]}
    wave1_sha = None
    if config["enabled"] and selected:
        runtime = runtime or default_runtime(run_id)
        if config["pin_target_source"]:
            target_entries = pd._walk_target(Path(wb["target_root"]), TARGET_ROOT)
        index = _readable_index(wb["menu"], target_entries)
        for wave in (1, 2):
            cells = [cell for cell in WORKCELLS if cell.wave == wave and cell.workcell_id in selected]
            if not cells:
                continue
            wave1 = None
            if wave == 2:
                wave1 = wave_one_model(base, _record(wb, rows, pools, index, None), outputs)
                data = _json_bytes(wave1)
                atomic_bytes(bundle / WAVE1_FILE, data)
                wave1_sha = file_hash(bundle / WAVE1_FILE)
            for cell in cells:
                atomic_bytes(bundle / f"cell-brief-{cell.workcell_id}.json",
                             _json_bytes(_brief(cell, base, wave1, wb["traits"], wb["menu"]["root_id"],
                                                config["record_limit"])))
            wave_rows, pool = _run_wave(run_id, wave, cells, work=work, bundle=bundle, menu=wb["menu"],
                menu_dir=wb["menu_dir"], target=wb["target_root"], target_entries=target_entries, config=config,
                runtime=runtime, source=core["source_snapshot_sha256"], attempt_id=attempt_id)
            rows.extend(wave_rows)
            pools.append(pool)
            for row in wave_rows:
                if row["output_sha256"] is not None:
                    outputs[row["workcell_id"]] = read_json(work / "cells" / row["workcell_id"] / CELL_FILE)
    else:
        index = {}
    record = _record(wb, rows, pools, index, wave1_sha)
    atomic_json(work / MANIFEST, record)
    return record


def _record(wb: dict[str, Any], rows: list[dict[str, Any]], pools: list[dict[str, Any]],
            index: dict[str, Any], wave1_sha: str | None) -> dict[str, Any]:
    return {"schema": RECORD_SCHEMA, "enabled": wb["settings"]["enabled"],
            "budget_class": wb["settings"]["budget_class"], "record_limit": wb["settings"]["record_limit"],
            "traits": wb["traits"], "selection": wb["selection"], "menu_root": wb["menu"]["root_id"],
            "cells": rows, "pools": pools, "readable_index": index, "wave_1_model_sha256": wave1_sha}


def load_outputs(attempt: Path, record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Retained cell replies, hash-checked against the workbench record."""
    outputs = {}
    for row in record["cells"]:
        if row["output_sha256"] is None:
            continue
        path = attempt / WORKDIR / "cells" / row["workcell_id"] / CELL_FILE
        if path.is_symlink() or not path.is_file() or file_hash(path) != row["output_sha256"]:
            raise Blocked(f"{JOB}: retained reply of {row['workcell_id']} changed")
        outputs[row["workcell_id"]] = read_json(path)
    return outputs


# ---- join (T07): pure, replayable ------------------------------------------------------------------

def prohibited_text() -> tuple:
    """Every downstream text guard the overlays must pass: this job's validator, the claim ledger
    (which scans the whole model) and the synthesis report (which renders gap statements and ledger
    hypotheses). A record that trips any of them is dropped by the join as a gap, so model wording
    can never block a downstream job (ADR-0013)."""
    import claim_ledger
    import synthesis_report
    import threat_model_core as tmc
    return (*tmc.PROHIBITED_TEXT, *claim_ledger.PROHIBITED_TEXT, *synthesis_report.PROHIBITED_TEXT)


class _Join:
    def __init__(self, base: dict[str, Any], record: dict[str, Any], outputs: dict[str, dict[str, Any]]) -> None:
        self.prohibited = prohibited_text()
        self.model = deepcopy(base)
        self.record, self.outputs = record, outputs
        self.limit = record.get("record_limit", 60)
        self.index = record.get("readable_index") or {}
        self.by_path: dict[str, list[str]] = {}
        for key in self.index:
            self.by_path.setdefault(key.split(":", 1)[1], []).append(key)
        self.menu_root = record.get("menu_root", ASSEMBLY_ROOT)
        self.base_citations = base["elements"][0]["citations"] if base["elements"] else (
            base["flows"][0]["citations"] if base["flows"] else [])
        self.elements = {item["element_id"]: item for item in self.model["elements"]}
        self.flows = {item["flow_id"]: item for item in self.model["flows"]}
        self.components = {item["component_id"]: item["element_id"] for item in self.model["elements"]
                           if item["component_id"]}
        self.data_classes: dict[str, dict[str, Any]] = {}
        self.data_keys: dict[str, str] = {}
        self.zones: dict[str, dict[str, Any]] = {}
        self.privacy: list[dict[str, Any]] = []
        self.new_boundaries: list[dict[str, Any]] = []
        self.abuse: list[dict[str, Any]] = []
        self.trees: list[dict[str, Any]] = []
        self.gaps: list[dict[str, Any]] = []
        self.assumptions: list[dict[str, Any]] = []
        self.triggers: list[dict[str, Any]] = []
        self.taken: set[str] = set(self.elements) | set(self.flows) | {
            item["boundary_id"] for item in self.model["trust_boundaries"]} | {
            item["threat_id"] for item in self.model["stride_hypotheses"]}

    # -- helpers
    def _unique(self, base_id: str) -> str:
        candidate, n = base_id, 1
        while candidate in self.taken:
            n += 1
            candidate = f"{base_id}-{n}"
        self.taken.add(candidate)
        return candidate

    def gap(self, cell: str, kind: str, statement: str, affected: Iterable[str] = (), intercom_id: str | None = None) -> None:
        if not self.clean(statement):
            statement = f"A {kind.replace('_', ' ')} note from {cell} was withheld: its text states a prohibited conclusion."
        gap_id = self._unique("gap-wb-" + _slug(cell, 32) + "-" + digest({"s": statement, "a": sorted(affected)})[:10])
        self.gaps.append({"gap_id": gap_id, "kind": kind, "statement": statement,
                          "affected_record_ids": sorted(set(affected)), "originating_workcell_id": cell,
                          "intercom_record_id": intercom_id, "evidence_class": "FOLLOW_ON_REQUIRED",
                          "confidence": "low", "citations": deepcopy(self.base_citations)})

    def clean(self, value: Any) -> bool:
        """False when any text would promote a candidate (the core validator would refuse it)."""
        texts = [value] if isinstance(value, str) else list(intercom._strings(value))
        return not any(pattern.search(text) for text in texts for pattern in self.prohibited)

    def resolve(self, refs: Any) -> tuple[list[dict[str, Any]], list[str]]:
        citations, unresolved = [], []
        for ref in refs if isinstance(refs, list) else []:
            if not isinstance(ref, str) or not ref.strip():
                continue
            cited = self._one(ref.strip().strip("`"))
            if cited is None:
                unresolved.append(ref)
            else:
                citations.extend(cited)
        unique = {digest(item): item for item in citations}
        return [unique[key] for key in sorted(unique, key=lambda k: (unique[k]["path"], unique[k]["line_range"] or "", k))], unresolved

    def _one(self, ref: str) -> list[dict[str, Any]] | None:
        root, path = None, ref
        for known in (TARGET_ROOT, BUNDLE_ROOT, self.menu_root):
            if ref.startswith(known + ":"):
                root, path = known, ref[len(known) + 1:]
                break
        lines = None
        if root == BUNDLE_ROOT:
            name = path.split(":", 1)[0]
            ok = name in (BASE_FILE, COMPONENT_FILE, WAVE1_FILE, MENU_FILE) or name.startswith("cell-brief-")
            return deepcopy(self.base_citations) if ok else None
        key = self._lookup(root, path)
        if key is None:
            match = re.match(r"^(?P<path>.+?):(?P<lines>\d+(?:-\d+)?)$", path)
            if match:
                key, lines = self._lookup(root, match["path"]), match["lines"]
        if key is None:
            return None
        meta, file_path = self.index[key], key.split(":", 1)[1]
        if key.startswith(TARGET_ROOT + ":"):
            return [{"source_class": "raw", "producer": "00-intake", "attempt_id": "source-snapshot",
                     "path": file_path, "sha256": meta["sha256"], "line_range": lines, "index_record_id": None,
                     "note": "target repository file at the bound source snapshot"}]
        return [{"source_class": meta["source_class"], "producer": meta["producer"],
                 "attempt_id": meta["attempt_id"], "path": meta["run_path"], "sha256": meta["sha256"],
                 "line_range": lines, "index_record_id": None,
                 "note": "accepted upstream evidence from the supporting-evidence menu"}]

    def _lookup(self, root: str | None, path: str) -> str | None:
        path = path.removeprefix("./")
        if root is not None:
            key = f"{root}:{path}"
            return key if key in self.index else None
        exact = self.by_path.get(path, [])
        if len(exact) == 1:
            return exact[0]
        suffix = [key for p, keys in self.by_path.items() if p.endswith("/" + path) for key in keys]
        return suffix[0] if len(suffix) == 1 else None

    def grade(self, cell: str, record_id: str, refs: Any, confidence: Any) -> tuple[list, str, str]:
        citations, unresolved = self.resolve(refs)
        if unresolved:
            self.gap(cell, "missing_evidence", f"{len(unresolved)} evidence ref(s) of {record_id} did not resolve "
                     f"to a pinned input or target file: {', '.join(str(r)[:120] for r in unresolved[:5])}",
                     [record_id])
        confidence = confidence if confidence in ("low", "medium", "high") else None
        if citations:
            return citations, "STRONG_INFERENCE", confidence or "medium"
        return deepcopy(self.base_citations), "WEAK_INFERENCE", "medium" if confidence == "high" else (confidence or "low")

    def targets(self, cell: str, record_id: str, values: Any) -> tuple[list[str], list[str], list[str]]:
        elements, flows, classes, unresolved = set(), set(), set(), []
        for raw in values if isinstance(values, list) else []:
            value = str(raw).strip()
            if value in self.elements or "element-" + value in self.elements:
                elements.add(value if value in self.elements else "element-" + value)
            elif value in self.flows or "flow-" + value in self.flows:
                flows.add(value if value in self.flows else "flow-" + value)
            elif value in self.components:
                elements.add(self.components[value])
            elif self.data_class_id(value):
                classes.add(self.data_class_id(value))
            else:
                unresolved.append(value)
        if unresolved:
            self.gap(cell, "missing_evidence", f"{record_id} names ids that are not in the model: "
                     f"{', '.join(unresolved[:8])}", [record_id])
        return sorted(elements), sorted(flows), sorted(classes)

    def data_class_id(self, value: str) -> str | None:
        return self.data_keys.get(value) or self.data_keys.get(_slug(value))

    def limited(self, cell: str, family: str, values: Any) -> list[dict[str, Any]]:
        items = [item for item in (values if isinstance(values, list) else []) if isinstance(item, dict)]
        if len(items) > self.limit:
            self.gap(cell, "missing_evidence", f"{cell} returned {len(items)} {family}; the join kept the first "
                     f"{self.limit} (workbench_records_per_cell_max)")
        return items[:self.limit]

    def keep(self, cell: str, family: str, item: dict[str, Any]) -> bool:
        if self.clean(item):
            return True
        self.gap(cell, "missing_evidence", f"a {family} record from {cell} was dropped: its text states a "
                 "prohibited conclusion (finding, severity, runtime, compliance or remediation)")
        return False

    # -- families
    def add_data_classes(self, cell: str, values: Any) -> None:
        for item in self.limited(cell, "data_classes", values):
            if not self.keep(cell, "data_classes", item):
                continue
            data_id = self._unique("data-" + _slug(item.get("key") or item.get("name")))
            self.data_keys.setdefault(str(item.get("key", "")), data_id)
            self.data_keys.setdefault(_slug(item.get("key") or item.get("name")), data_id)
            self.data_keys[data_id] = data_id
            citations, evidence_class, confidence = self.grade(cell, data_id, item.get("evidence"), item.get("confidence"))
            stores, flows, _ = self.targets(cell, data_id, list(item.get("store_element_ids") or []) +
                                            list(item.get("flow_ids") or []))
            category = item.get("category") if item.get("category") in (
                "pii", "credential", "secret", "user_content", "telemetry", "log", "regulated", "payment",
                "location", "device_id", "other") else "other"
            sensitivity = item.get("sensitivity") if item.get("sensitivity") in SENSITIVITY else (
                "restricted" if category in SENSITIVE else "confidential" if category in PERSONAL else "internal")
            self.data_classes[data_id] = {"data_class_id": data_id, "category": category, "sensitivity": sensitivity,
                "retention_hint": item.get("retention_hint"), "export_hint": item.get("export_hint"),
                "delete_hint": item.get("delete_hint"), "store_element_ids": stores, "flow_ids": flows,
                "evidence_class": evidence_class, "confidence": confidence, "citations": citations,
                "originating_workcell_id": cell}

    def add_privacy(self, cell: str, values: Any) -> None:
        for item in self.limited(cell, "privacy_threats", values):
            if not self.keep(cell, "privacy_threats", item):
                continue
            category = item.get("linddun_category")
            if category not in LINDDUN_SHORT:
                continue
            record_id = self._unique(f"privacy-{LINDDUN_SHORT[category]}-" + digest(
                {"cell": cell, "statement": item.get("statement"), "targets": item.get("target_ids")})[:10])
            citations, evidence_class, confidence = self.grade(cell, record_id, item.get("evidence"), item.get("confidence"))
            elements, flows, classes = self.targets(cell, record_id, list(item.get("target_ids") or []) +
                                                    list(item.get("data_class_keys") or []))
            obligations = [str(text) for text in item.get("proof_obligations") or []] or [
                f"Determine from source whether the {category.replace('_', ' ')} condition holds and which control addresses it."]
            self.privacy.append({"privacy_threat_id": record_id, "linddun_category": category,
                "statement": str(item.get("statement")), "target_element_ids": elements, "target_flow_ids": flows,
                "data_class_ids": classes, "proof_obligations": obligations,
                "regulatory_candidate_notes": [str(text) for text in item.get("regulatory_candidate_notes") or []],
                "evidence_class": evidence_class, "confidence": confidence, "citations": citations,
                "originating_workcell_id": cell})

    def add_zones(self, cell: str, values: Any) -> None:
        for item in self.limited(cell, "deployment_zones", values):
            if not self.keep(cell, "deployment_zones", item):
                continue
            zone_id = self._unique("zone-" + _slug(item.get("key") or item.get("name")))
            citations, evidence_class, confidence = self.grade(cell, zone_id, item.get("evidence"), item.get("confidence"))
            kind = item.get("kind") if item.get("kind") in (
                "public_ingress", "private_service", "admin_control_plane", "build_release", "client_device",
                "third_party") else "private_service"
            elements, _flows, _classes = self.targets(cell, zone_id, item.get("element_ids"))
            self.zones[zone_id] = {"zone_id": zone_id, "kind": kind, "name": str(item.get("name")),
                "exposure_label": "DECLARED_EXPOSURE", "evidence_class": evidence_class, "confidence": confidence,
                "citations": citations, "originating_workcell_id": cell, "_elements": elements}

    def add_boundaries(self, cell: str, values: Any) -> None:
        kinds = ("network", "process", "privilege", "tenant", "organization", "device", "build_release",
                 "third_party", "model_tool")
        for item in self.limited(cell, "trust_boundaries", values):
            if not self.keep(cell, "trust_boundaries", item):
                continue
            boundary_id = self._unique("boundary-wb-" + _slug(item.get("key") or item.get("reason")))
            citations, evidence_class, confidence = self.grade(cell, boundary_id, item.get("evidence"), item.get("confidence"))
            _elements, flows, _classes = self.targets(cell, boundary_id, item.get("flow_ids"))
            self.new_boundaries.append({"boundary_id": boundary_id,
                "kind": item.get("kind") if item.get("kind") in kinds else "process", "reason": str(item.get("reason")),
                "evidence_class": evidence_class, "confidence": confidence, "citations": citations,
                "originating_workcell_id": cell, "_flows": flows})

    def add_abuse(self, cell: str, values: Any) -> None:
        for item in self.limited(cell, "abuse_scenarios", values):
            if not self.keep(cell, "abuse_scenarios", item):
                continue
            record_id = self._unique("abuse-" + _slug(item.get("attacker_objective"), 40) + "-" + digest(
                {"cell": cell, "objective": item.get("attacker_objective"), "targets": item.get("target_ids")})[:8])
            citations, evidence_class, confidence = self.grade(cell, record_id, item.get("evidence"), item.get("confidence"))
            elements, flows, classes = self.targets(cell, record_id, list(item.get("target_ids") or []) +
                                                    list(item.get("data_class_keys") or []))
            for flow in flows:   # the abuse record keys elements; a flow target names both endpoints
                elements = sorted(set(elements) | {self.flows[flow]["source_element_id"],
                                                   self.flows[flow]["destination_element_id"]})
            self.abuse.append({"scenario_id": record_id, "attacker_objective": str(item.get("attacker_objective")),
                "actor": str(item.get("actor")), "capability": str(item.get("capability") or "unspecified"),
                "target_element_ids": elements, "target_data_class_ids": classes, "harm": str(item.get("harm")),
                "preconditions": [str(v) for v in item.get("preconditions") or []],
                "missing_controls": [str(v) for v in item.get("missing_controls") or []],
                "evidence_class": evidence_class, "confidence": confidence, "citations": citations,
                "originating_workcell_id": cell})

    def add_trees(self, cell: str, values: Any) -> None:
        for item in self.limited(cell, "attack_trees", values):
            if not self.keep(cell, "attack_trees", item):
                continue
            tree_id = self._unique("tree-" + _slug(item.get("objective"), 40) + "-" + digest(
                {"cell": cell, "objective": item.get("objective"), "targets": item.get("target_ids")})[:8])
            self._tree(cell, tree_id, item)

    def _tree(self, cell: str, tree_id: str, item: dict[str, Any]) -> None:
        raw = [node for node in item.get("nodes") or [] if isinstance(node, dict) and isinstance(node.get("key"), str)]
        by_key: dict[str, dict[str, Any]] = {}
        for node in raw[: self.limit]:
            if node["key"] in by_key:
                self.gap(cell, "missing_evidence", f"{tree_id}: duplicate node key {node['key']!r} dropped", [tree_id])
                continue
            by_key[node["key"]] = node
        if not by_key:
            self.gap(cell, "missing_evidence", f"attack tree {tree_id} had no usable nodes and was dropped")
            return
        children_of = {key: [c for c in (node.get("children") or []) if isinstance(c, str) and c in by_key and c != key]
                       for key, node in by_key.items()}
        root = item.get("root") if item.get("root") in by_key else next(
            (key for key in by_key if not any(key in kids for kids in children_of.values())), next(iter(by_key)))
        # depth-first from the root: drop back edges (cycles) and nodes the root cannot reach
        order, seen, stack_keys = [], set(), set()

        def walk(key: str) -> None:
            seen.add(key); stack_keys.add(key); order.append(key)
            kept = []
            for child in children_of[key]:
                if child in stack_keys or child in seen:
                    if child in stack_keys:
                        self.gap(cell, "missing_evidence", f"{tree_id}: cycle edge {key} -> {child} dropped", [tree_id])
                        continue
                    kept.append(child)   # shared sub-goal (DAG) is fine
                    continue
                kept.append(child)
                walk(child)
            children_of[key] = kept
            stack_keys.discard(key)

        walk(root)
        dropped = [key for key in by_key if key not in seen]
        if dropped:
            self.gap(cell, "missing_evidence", f"{tree_id}: {len(dropped)} node(s) unreachable from the root dropped",
                     [tree_id])
        ids = {}
        for key in order:
            ids[key] = self._unique(f"{tree_id}-{_slug(key, 32)}")
        nodes, all_citations, evidence_leaves = [], [], 0
        for key in order:
            node = by_key[key]
            kind = node.get("kind") if node.get("kind") in ("AND", "OR", "leaf") else "leaf"
            children = children_of[key]
            if kind == "leaf" and children:
                kind = "OR"   # a leaf with children is an interior choice
            if kind in ("AND", "OR") and not children:
                kind = "leaf"
            citations: list[dict[str, Any]] = []
            support = None
            if kind == "leaf":
                support = node.get("support") if node.get("support") in ("evidence", "assumption", "unresolved") else "unresolved"
                citations, unresolved = self.resolve(node.get("evidence"))
                if unresolved:
                    self.gap(cell, "missing_evidence", f"{ids[key]}: {len(unresolved)} evidence ref(s) did not resolve",
                             [tree_id])
                if support == "evidence" and not citations:
                    support = "unresolved"
                    self.gap(cell, "missing_evidence", f"{ids[key]} was marked evidence without a resolvable ref; "
                             "recorded unresolved", [tree_id])
                evidence_leaves += support == "evidence"
            nodes.append({"node_id": ids[key], "kind": kind, "label": str(node.get("label")),
                          "child_node_ids": [ids[child] for child in children],
                          "prerequisites": [str(v) for v in node.get("prerequisites") or []],
                          "leaf_support": support, "citations": citations, "verification_item_ids": []})
            all_citations.extend(citations)
        unique = {digest(c): c for c in all_citations}
        tree_citations = [unique[k] for k in sorted(unique)] or deepcopy(self.base_citations)
        confidence = item.get("confidence") if item.get("confidence") in ("low", "medium", "high") else "low"
        elements, flows, _classes = self.targets(cell, tree_id, item.get("target_ids"))
        self.trees.append({"tree_id": tree_id, "objective": str(item.get("objective")),
            "citations": tree_citations, "confidence": confidence if evidence_leaves else (
                "medium" if confidence == "high" else confidence),
            "evidence_class": "STRONG_INFERENCE" if evidence_leaves else "WEAK_INFERENCE",
            "root_node_id": ids[root], "nodes": sorted(nodes, key=lambda n: n["node_id"]),
            "originating_workcell_id": cell, "_targets": elements + flows})

    # -- assembly
    def run(self) -> dict[str, Any]:
        rows = {row["workcell_id"]: row for row in self.record.get("cells", [])}
        for wave in (1, 2):
            for cell in WORKCELLS:
                if cell.wave != wave or cell.workcell_id not in rows:
                    continue
                row, reply = rows[cell.workcell_id], self.outputs.get(cell.workcell_id)
                if reply is None or validate_document(reply, CELL_SCHEMA):
                    if reply is not None:
                        row = {**row, "terminal_status": "FAILED", "cause": "reply fails the cell schema"}
                        rows[cell.workcell_id] = row
                    self.gap(cell.workcell_id, "failed_workcell",
                             f"workcell {cell.workcell_id} ended {row['terminal_status']}: {row.get('cause') or 'no reply'}")
                    continue
                cid = cell.workcell_id
                if "data_classes" in cell.families:
                    self.add_data_classes(cid, reply.get("data_classes"))
                if "privacy_threats" in cell.families:
                    self.add_privacy(cid, reply.get("privacy_threats"))
                if "deployment_zones" in cell.families:
                    self.add_zones(cid, reply.get("deployment_zones"))
                if "trust_boundaries" in cell.families:
                    self.add_boundaries(cid, reply.get("trust_boundaries"))
                if "abuse_scenarios" in cell.families:
                    self.add_abuse(cid, reply.get("abuse_scenarios"))
                if "attack_trees" in cell.families:
                    self.add_trees(cid, reply.get("attack_trees"))
                ignored = [key for key in ("data_classes", "privacy_threats", "deployment_zones", "trust_boundaries",
                                           "abuse_scenarios", "attack_trees") if reply.get(key) and key not in cell.families]
                if ignored:
                    self.gap(cid, "missing_evidence", f"{cid} returned families outside its brief, not joined: "
                             f"{', '.join(ignored)}")
                for note in (reply.get("gaps") or [])[: self.limit]:
                    if self.clean(note):
                        self.gap(cid, "missing_evidence", str(note.get("statement"))[:2000])
        self._intercom(rows)
        self._apply_overlays()
        self._coverage(rows)
        return self.model

    def _intercom(self, rows: dict[str, dict[str, Any]]) -> None:
        records = intercom_records(self, rows)
        self.intercom = records
        result = intercom.sweep(records) if records else {"unresolved": [], "quarantined": []}
        by_id = {record["record_id"]: record for record in records}
        for record_id in result["unresolved"]:
            record = by_id[record_id]
            statement = ("Intercom record quarantined: its text reads as an instruction to a reviewer."
                         if record.get("injection_suspected") else str(record["payload"].get("statement"))[:2000])
            if record["record_type"] == "assumption" and not record.get("injection_suspected"):
                self.assumptions.append({"assumption_id": self._unique("assumption-" + record_id),
                    "topic": record["topic"], "statement": statement,
                    "affected_record_ids": list(record["subject_record_ids"]), "status": "unresolved",
                    "confidence": "low", "evidence_class": "FOLLOW_ON_REQUIRED",
                    "originating_workcell_id": record["author_workcell_id"], "intercom_record_id": record_id,
                    "citations": record["citations"] or deepcopy(self.base_citations)})
            else:
                self.gap(record["author_workcell_id"], "unresolved_intercom",
                         f"open {record['record_type'].replace('_', ' ')} to {record['target']}: {statement}",
                         record["subject_record_ids"], record_id)

    def _apply_overlays(self) -> None:
        model = self.model
        zone_of: dict[str, str] = {}
        for zone_id in sorted(self.zones):
            for element in self.zones[zone_id].pop("_elements"):
                zone_of.setdefault(element, zone_id)
        for element in model["elements"]:
            if element["element_id"] in zone_of:
                element["zone_id"] = zone_of[element["element_id"]]
        for boundary in self.new_boundaries:
            for flow in boundary.pop("_flows"):
                if boundary["boundary_id"] not in self.flows[flow]["boundary_ids"]:
                    self.flows[flow]["boundary_ids"] = sorted([*self.flows[flow]["boundary_ids"], boundary["boundary_id"]])
            if not any(boundary["boundary_id"] in f["boundary_ids"] for f in model["flows"]):
                self.gap(boundary["originating_workcell_id"], "missing_evidence",
                         f"{boundary['boundary_id']} names no base flow that crosses it", [boundary["boundary_id"]])
        model["trust_boundaries"] = sorted([*model["trust_boundaries"], *self.new_boundaries],
                                           key=lambda item: item["boundary_id"])
        carried: dict[str, set[str]] = {}
        for data_id, item in self.data_classes.items():
            for flow in item["flow_ids"]:
                carried.setdefault(flow, set()).add(data_id)
            if item["category"] in SENSITIVE and not item["store_element_ids"]:
                self.triggers.append({"trigger_id": self._unique("trigger-wb-no-store-" + _slug(data_id, 40)),
                    "kind": "sensitive_data_without_store",
                    "statement": f"Sensitive data class {data_id} ({item['category']}) has no owning store in the model.",
                    "affected_record_ids": [data_id]})
        for flow in model["flows"]:
            if flow["flow_id"] in carried:
                flow["data_class_ids"] = sorted(set(flow["data_class_ids"]) | carried[flow["flow_id"]])
        for tree in self.trees:
            tree.pop("_targets", None)
        model["data_classes"] = [self.data_classes[key] for key in sorted(self.data_classes)]
        model["deployment_zones"] = [self.zones[key] for key in sorted(self.zones)]
        model["privacy_threats"] = sorted(self.privacy, key=lambda item: item["privacy_threat_id"])
        model["abuse_scenarios"] = sorted(self.abuse, key=lambda item: item["scenario_id"])
        model["attack_trees"] = sorted(self.trees, key=lambda item: item["tree_id"])

    def _coverage(self, rows: dict[str, dict[str, Any]]) -> None:
        model, record = self.model, self.record
        traits = record.get("traits", {})
        workcells = [dict(item) for item in model["coverage"]["workcells"] if item["workcell_id"] in DETERMINISTIC_CELLS]
        if not workcells:
            workcells = list(model["coverage"]["workcells"])
        workcells.append({"workcell_id": ROUTER, "instance_id": None, "wave": 1, "selection": "selected",
                          "omission_reason": None, "terminal_status": "OK", "persona_id": None,
                          "prompt_hash": None, "model_identity_hash": None})
        for selection in record.get("selection", []):
            cid = selection["workcell_id"]
            row = rows.get(cid)
            if row is not None:
                workcells.append({"workcell_id": cid, "instance_id": row["instance_id"], "wave": row["wave"],
                    "selection": "selected", "omission_reason": None, "terminal_status": row["terminal_status"],
                    "persona_id": row["persona_id"], "prompt_hash": row["prompt_hash"],
                    "model_identity_hash": row["model_identity_hash"]})
                continue
            reason = selection["reason"] or ("workbench disabled by tunable workbench_enabled" if not record.get("enabled")
                                             else "not run")
            workcells.append({"workcell_id": cid, "instance_id": None, "wave": selection["wave"],
                              "selection": "omitted", "omission_reason": reason, "terminal_status": None,
                              "persona_id": CELLS[cid].persona_id, "prompt_hash": None, "model_identity_hash": None})
            if selection["selected"]:   # selected but never ran (disabled): that is a gap
                self.gap(cid, "omitted_workcell", f"workcell {cid} was selected but did not run: {reason}")
        for cid, wave, trait, reason in NOT_BUILT:
            workcells.append({"workcell_id": cid, "instance_id": None, "wave": wave, "selection": "omitted",
                              "omission_reason": reason if trait is None or trait in traits else
                              f"trait {trait!r} not present", "terminal_status": None, "persona_id": None,
                              "prompt_hash": None, "model_identity_hash": None})
            if trait is not None and trait in traits:
                self.triggers.append({"trigger_id": self._unique("trigger-wb-trait-" + _slug(trait)),
                    "kind": "trait_without_specialist",
                    "statement": f"Target trait {trait!r} ({'; '.join(traits[trait])}) selects {cid}, which this "
                                 "workbench slice does not run.", "affected_record_ids": []})
                self.gap(cid, "omitted_workcell", f"{cid} is selected by trait {trait!r} but not built", [])
            elif cid == "challenge-refutation-cell":
                self.gap(cid, "omitted_workcell", "No challenge/refutation cell ran; overlay records are "
                         "unchallenged candidates (ADR-0019 slice 1).", [])
        model["coverage"]["workcells"] = workcells
        model["coverage"]["wave_4"] = "omitted_no_challenges"
        model["assumptions"] = sorted([*model["assumptions"], *self.assumptions], key=lambda item: item["assumption_id"])
        model["gaps"] = sorted([*model["gaps"], *self.gaps], key=lambda item: item["gap_id"])
        model["rescope_triggers"] = sorted([*model["rescope_triggers"], *self.triggers],
                                           key=lambda item: item["trigger_id"])


def intercom_records(joiner: _Join, rows: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Cell notes as typed intercom records, hash-chained in wave then workcell order. Pure."""
    records: list[dict[str, Any]] = []
    previous = None
    known = joiner.taken
    for wave in (1, 2):
        for cell in WORKCELLS:
            reply = joiner.outputs.get(cell.workcell_id)
            row = rows.get(cell.workcell_id)
            if cell.wave != wave or reply is None or row is None or row["terminal_status"] not in OK_STATES:
                continue
            for number, note in enumerate((reply.get("notes") or [])[: joiner.limit], 1):
                if note.get("record_type") not in NOTE_TYPES:
                    continue
                target = note.get("target") if note.get("target") in NOTE_TARGETS else INTEGRATOR
                subjects = sorted({str(value) for value in note.get("subject_ids") or []
                                   if str(value) in known and re.fullmatch(r"[a-z0-9][a-z0-9-]*", str(value))})
                citations, _unresolved = joiner.resolve(note.get("evidence"))
                record = {"schema": intercom.INTERCOM_SCHEMA,
                          "record_id": f"ic-{cell.workcell_id}-{number:03d}", "record_type": note["record_type"],
                          "author_workcell_id": cell.workcell_id,
                          "author_instance_id": row["instance_id"] or "not-launched", "wave": wave,
                          "target": target, "topic": str(note.get("topic") or note["record_type"])[:300],
                          "subject_record_ids": subjects, "citations": citations, "status": "open",
                          "resolution": {"text": None, "resolves_record_id": None},
                          "payload": {"statement": str(note.get("statement"))[:4000]},
                          "injection_suspected": False, "previous_hash": previous}
                if intercom.suspect_injection(record) or not joiner.clean(record["payload"]):
                    record["injection_suspected"] = True
                record["content_hash"] = intercom.content_hash(record)
                previous = record["content_hash"]
                records.append(record)
    return records


def wave_one_sha256(base: dict[str, Any], record: dict[str, Any], outputs: dict[str, dict[str, Any]]) -> str | None:
    """sha256 of the wave-1 bundle file wave 2 read, recomputed from the retained replies."""
    import hashlib
    if not any(row["wave"] == 2 and row["instance_id"] is not None or row["wave"] == 2 for row in record["cells"]):
        return None
    return hashlib.sha256(_json_bytes(wave_one_model(base, record, outputs))).hexdigest()


def join(base: dict[str, Any], record: dict[str, Any], outputs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """The integrated model: base + every cell overlay, derived deterministically."""
    return _Join(base, record, outputs).run()


def join_with_intercom(base: dict[str, Any], record: dict[str, Any],
                       outputs: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    joiner = _Join(base, record, outputs)
    model = joiner.run()
    return model, joiner.intercom


def wave_one_model(base: dict[str, Any], record: dict[str, Any], outputs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """What wave 2 reads: the wave-1 overlays, with the ids the full join will also assign."""
    wave1_rows = [row for row in record["cells"] if row["wave"] == 1]
    partial = join(base, {**record, "cells": wave1_rows, "selection": []},
                   {key: value for key, value in outputs.items() if CELLS[key].wave == 1})
    base_boundaries = {item["boundary_id"] for item in base["trust_boundaries"]}
    return {"schema": "appsec-review/threat-workbench-wave-1-model/0.1",
            "data_classes": partial["data_classes"], "privacy_threats": partial.get("privacy_threats", []),
            "deployment_zones": partial["deployment_zones"],
            "trust_boundaries": [item for item in partial["trust_boundaries"] if item["boundary_id"] not in base_boundaries],
            "element_zones": {item["element_id"]: item["zone_id"] for item in partial["elements"] if item["zone_id"]},
            "flow_data_classes": {item["flow_id"]: item["data_class_ids"] for item in partial["flows"] if item["data_class_ids"]}}


# ---- projections -------------------------------------------------------------------------------------

def _mermaid_text(value: Any, limit: int = 80) -> str:
    text = re.sub(r"\s+", " ", str(value)).strip()
    text = text.replace('"', "'").replace("<", "(").replace(">", ")")
    return text[:limit] + ("..." if len(text) > limit else "")


def attack_trees_mmd(model: dict[str, Any]) -> str:
    lines = ["flowchart TD"]
    if not model.get("attack_trees"):
        lines.append('    none["no attack trees in this model"]')
    for tree in model.get("attack_trees", []):
        lines.append(f'    subgraph {tree["tree_id"]}["{_mermaid_text(tree["objective"])}"]')
        for node in tree["nodes"]:
            label = _mermaid_text(node["label"])
            if node["kind"] == "leaf":
                lines.append(f'        {node["node_id"]}("{label} [{node["leaf_support"]}]")')
            else:
                lines.append(f'        {node["node_id"]}["{node["kind"]}: {label}"]')
        for node in tree["nodes"]:
            for child in node["child_node_ids"]:
                lines.append(f"        {node['node_id']} --> {child}")
        lines.append("    end")
    return "\n".join(lines) + "\n"


def dfd_mmd(model: dict[str, Any]) -> str:
    lines = ["flowchart LR"]
    zones: dict[str | None, list[dict[str, Any]]] = {}
    for element in model["elements"]:
        zones.setdefault(element["zone_id"], []).append(element)
    names = {zone["zone_id"]: zone["name"] for zone in model.get("deployment_zones", [])}
    for zone_id in sorted(zones, key=lambda z: z or ""):
        indent = "    "
        if zone_id is not None:
            lines.append(f'    subgraph {zone_id}["{_mermaid_text(names.get(zone_id, zone_id))}"]')
            indent = "        "
        for element in zones[zone_id]:
            lines.append(f'{indent}{element["element_id"]}["{_mermaid_text(element["name"])} ({element["kind"]})"]')
        if zone_id is not None:
            lines.append("    end")
    for flow in model["flows"]:
        lines.append(f'    {flow["source_element_id"]} -->|{flow["flow_id"]}| {flow["destination_element_id"]}')
    return "\n".join(lines) + "\n"


def ranked_scenarios(model: dict[str, Any]) -> dict[str, Any]:
    classes = {item["data_class_id"]: item for item in model.get("data_classes", [])}
    zones = {item["zone_id"]: item for item in model.get("deployment_zones", [])}
    elements = {item["element_id"]: item for item in model["elements"]}
    crossing = {endpoint for flow in model["flows"] if flow["boundary_ids"]
                for endpoint in (flow["source_element_id"], flow["destination_element_id"])}

    def factors(element_ids: list[str], class_ids: list[str], evidence_class: str, leaves: list[dict[str, Any]] | None) -> dict[str, int]:
        exposure = 0
        for element_id in element_ids:
            zone = zones.get((elements.get(element_id) or {}).get("zone_id"))
            if zone is not None:
                exposure = max(exposure, 2 if zone["kind"] in EXPOSED_ZONES else 1)
        evidence_leaves = sum(1 for node in leaves or [] if node["leaf_support"] == "evidence")
        weak_leaves = sum(1 for node in leaves or [] if node["leaf_support"] in ("assumption", "unresolved"))
        return {"data_sensitivity": max([SENSITIVITY[classes[c]["sensitivity"]] for c in class_ids if c in classes] or [0]),
                "personal_or_credential_data": int(any(classes[c]["category"] in PERSONAL for c in class_ids if c in classes)),
                "trust_boundary_crossing": int(any(e in crossing for e in element_ids)),
                "declared_exposure": exposure, "observed_exposure": 0,
                "evidence_confidence": EVIDENCE_WEIGHT[evidence_class],
                "exploit_chain_support": min(3, evidence_leaves),
                "unresolved_assumption_penalty": -min(3, weak_leaves) if leaves is not None else (
                    -1 if evidence_class in ("WEAK_INFERENCE", "FOLLOW_ON_REQUIRED") else 0)}

    rows = []
    for item in model.get("abuse_scenarios", []):
        rows.append(("abuse_scenario", item["scenario_id"], item["attacker_objective"], item["target_element_ids"],
                     item["target_data_class_ids"], factors(item["target_element_ids"], item["target_data_class_ids"],
                                                            item["evidence_class"], None), item["originating_workcell_id"]))
    for item in model.get("privacy_threats", []):
        targets = sorted(set(item["target_element_ids"]) | {e for f in model["flows"] if f["flow_id"] in item["target_flow_ids"]
                                                           for e in (f["source_element_id"], f["destination_element_id"])})
        rows.append(("privacy_threat", item["privacy_threat_id"], item["statement"], targets, item["data_class_ids"],
                     factors(targets, item["data_class_ids"], item["evidence_class"], None), item["originating_workcell_id"]))
    for tree in model.get("attack_trees", []):
        leaves = [node for node in tree["nodes"] if node["kind"] == "leaf"]
        rows.append(("attack_tree", tree["tree_id"], tree["objective"], [], [],
                     factors([], [], tree["evidence_class"], leaves), tree["originating_workcell_id"]))
    scenarios = [{"scenario_ref": ref, "kind": kind, "title": str(title)[:300], "target_element_ids": list(targets),
                  "data_class_ids": list(class_ids), "factors": fac, "prioritization_score": sum(fac.values()),
                  "originating_workcell_id": cell}
                 for kind, ref, title, targets, class_ids, fac, cell in rows]
    scenarios.sort(key=lambda row: (-row["prioritization_score"], row["scenario_ref"]))
    for rank, row in enumerate(scenarios, 1):
        row["rank"] = rank
    return {"schema": "appsec-review/ranked-threat-scenarios/0.1", "run_id": model["run_id"],
            "attempt_id": model["attempt_id"], "purpose": "prioritization_aid_not_severity",
            "note": ("A visible per-factor prioritization aid over candidate scenarios. It is not a severity; "
                     "12-scoring-prioritization owns scoring. observed_exposure is always 0 (static review)."),
            "scenarios": scenarios}


def cell_results(model: dict[str, Any], record: dict[str, Any], run_id: str, attempt_id: str) -> dict[str, dict[str, Any]]:
    """One strict ``threat-workbench-cell-result`` per launched cell: its slice of the join."""
    results = {}
    families = ("elements", "flows", "trust_boundaries", "data_classes", "deployment_zones", "abuse_scenarios",
                "attack_trees", "stride_hypotheses", "assumptions", "gaps", "privacy_threats")
    for row in record["cells"]:
        if row["instance_id"] is None:
            continue
        cid = row["workcell_id"]
        delta = {key: [item for item in model.get(key, []) if item.get("originating_workcell_id") == cid]
                 for key in families}
        delta["stride_coverage"] = []
        template = read_json(ROOT / "registry" / "job-templates" / f"{CELLS[cid].template_id}.json")
        composition = template["composition"]
        status = row["terminal_status"]
        if status == "OK" and any(g["originating_workcell_id"] == cid for g in model["gaps"]):
            status = "OK_WITH_GAPS"
        results[cid] = {"schema": "appsec-review/threat-workbench-cell-result/0.1", "run_id": run_id, "job_id": JOB,
            "attempt_id": attempt_id, "workcell_id": cid, "instance_id": row["instance_id"], "wave": row["wave"],
            "persona_id": composition["persona_id"], "role_id": composition["role_id"],
            "domain_id": composition["domain_id"], "tooling_profile_id": composition["tooling_profile_id"],
            "prompt_hash": row["prompt_hash"], "model_identity_hash": row["model_identity_hash"],
            "budget_class": record["budget_class"], "terminal_status": status, "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "summary": f"{cid}: {sum(len(v) for k, v in delta.items() if k != 'gaps')} overlay record(s), "
                       f"{len(delta['gaps'])} gap(s).",
            "inputs_read": [], "model_delta": delta,
            "intercom_record_ids": [], "gaps": delta["gaps"], "cause": row["cause"]}
    return results


def write_projections(attempt: Path, model: dict[str, Any], record: dict[str, Any],
                      records: list[dict[str, Any]], run_id: str) -> list[str]:
    """Writes the projections and returns their attempt-relative paths (in a stable order)."""
    paths = []
    atomic_bytes(attempt / TREES_MMD, attack_trees_mmd(model).encode("utf-8")); paths.append(TREES_MMD)
    atomic_bytes(attempt / DFD_MMD, dfd_mmd(model).encode("utf-8")); paths.append(DFD_MMD)
    atomic_json(attempt / RANKED, ranked_scenarios(model)); paths.append(RANKED)
    transcript = attempt / TRANSCRIPT
    if transcript.exists():
        transcript.unlink()
    bus = intercom.IntercomTranscript(transcript, write_policy={
        cell.workcell_id: NOTE_TYPES for cell in WORKCELLS})
    for item in records:
        bus.append(item, model_record_authors={})
    if not records:
        atomic_bytes(transcript, b"")
    paths.append(TRANSCRIPT)
    for cid, result in cell_results(model, record, run_id, model["attempt_id"]).items():
        own = [item for item in records if item["author_workcell_id"] == cid]
        result["intercom_record_ids"] = [item["record_id"] for item in own]
        folder = attempt / WORKDIR / "cells" / cid
        folder.mkdir(parents=True, exist_ok=True)
        atomic_json(folder / "cell-result.json", result)
        atomic_bytes(folder / "intercom-records.jsonl",
                     b"".join((json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n").encode() for item in own))
        paths.extend([f"{WORKDIR}/cells/{cid}/cell-result.json", f"{WORKDIR}/cells/{cid}/intercom-records.jsonl"])
        if (folder / CELL_FILE).is_file():
            paths.append(f"{WORKDIR}/cells/{cid}/{CELL_FILE}")
    previous = None
    for wave in (1, 2):
        rows = [row for row in record["cells"] if row["wave"] == wave]
        if not rows:
            continue
        manifest = {"schema": "appsec-review/threat-workbench-wave-manifest/0.1", "run_id": run_id, "job_id": JOB,
            "attempt_id": model["attempt_id"], "wave": wave, "budget_class": record["budget_class"],
            "frozen_at": max(row["finished_at"] for row in rows), "previous_wave_manifest_sha256": previous,
            "expected_instances": [{"workcell_id": row["workcell_id"], "instance_id": row["instance_id"],
                "persona_id": row["persona_id"], "output_root": f"{WORKDIR}/cells/{row['workcell_id']}",
                "selection": "selected", "omission_reason": None} for row in rows],
            "terminal_instances": [{"instance_id": row["instance_id"], "terminal_status": row["terminal_status"],
                "cell_result_path": f"{WORKDIR}/cells/{row['workcell_id']}/cell-result.json",
                "cell_result_sha256": file_hash(attempt / WORKDIR / "cells" / row["workcell_id"] / "cell-result.json"),
                "intercom_records_path": f"{WORKDIR}/cells/{row['workcell_id']}/intercom-records.jsonl",
                "intercom_records_sha256": file_hash(attempt / WORKDIR / "cells" / row["workcell_id"] / "intercom-records.jsonl")}
                for row in rows if row["instance_id"] is not None]}
        name = f"{WORKDIR}/wave-{wave}-manifest.json"
        atomic_json(attempt / name, manifest)
        previous = file_hash(attempt / name)
        paths.append(name)
    if (attempt / WORKDIR / MANIFEST).is_file():
        paths.append(f"{WORKDIR}/{MANIFEST}")
    return paths


def check_projections(attempt: Path, model: dict[str, Any], record: dict[str, Any],
                      records: list[dict[str, Any]], run_id: str) -> list[str]:
    """Validator side of :func:`write_projections`: every projection regenerates identically."""
    errors = []
    if (attempt / TREES_MMD).read_text(encoding="utf-8") != attack_trees_mmd(model):
        errors.append(f"{TREES_MMD} is not the projection of the model")
    if (attempt / DFD_MMD).read_text(encoding="utf-8") != dfd_mmd(model):
        errors.append(f"{DFD_MMD} is not the projection of the model")
    if read_json(attempt / RANKED) != ranked_scenarios(model):
        errors.append(f"{RANKED} is not the projection of the model")
    try:
        stored = intercom.IntercomTranscript(attempt / TRANSCRIPT).records()
    except intercom.IntercomTamperError as exc:
        stored = None
        errors.append(f"intercom transcript tampered: {exc}")
    if stored is not None and stored != records:
        errors.append("intercom transcript differs from the cell notes")
    for cid, result in cell_results(model, record, run_id, model["attempt_id"]).items():
        path = attempt / WORKDIR / "cells" / cid / "cell-result.json"
        result["intercom_record_ids"] = [item["record_id"] for item in records if item["author_workcell_id"] == cid]
        if not path.is_file() or read_json(path) != result:
            errors.append(f"cell result of {cid} is not the projection of the model")
        elif validate_document(result, "threat-workbench-cell-result.schema.json"):
            errors.append(f"cell result of {cid} fails its schema")
    return errors


# ---- validator (T08) ---------------------------------------------------------------------------------

def validate_overlays(model: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    elements = {item["element_id"] for item in model["elements"]}
    flows = {item["flow_id"] for item in model["flows"]}
    classes = {item["data_class_id"] for item in model.get("data_classes", [])}
    zones = {item["zone_id"]: item for item in model.get("deployment_zones", [])}
    ids: list[str] = [*elements, *flows, *(item["boundary_id"] for item in model["trust_boundaries"]),
                      *(item["threat_id"] for item in model["stride_hypotheses"]), *classes, *zones,
                      *(item["scenario_id"] for item in model.get("abuse_scenarios", [])),
                      *(item["privacy_threat_id"] for item in model.get("privacy_threats", [])),
                      *(item["tree_id"] for item in model.get("attack_trees", [])),
                      *(node["node_id"] for tree in model.get("attack_trees", []) for node in tree["nodes"])]
    duplicates = sorted({value for value in ids if ids.count(value) > 1}) if len(ids) != len(set(ids)) else []
    if duplicates:
        errors.append(f"model ids are not unique: {', '.join(duplicates[:5])}")
    for element in model["elements"]:
        if element["zone_id"] is not None and element["zone_id"] not in zones:
            errors.append(f"{element['element_id']}: zone {element['zone_id']} does not resolve")
    for flow in model["flows"]:
        if not set(flow["data_class_ids"]) <= classes:
            errors.append(f"{flow['flow_id']}: data class reference does not resolve")
    for zone in zones.values():
        if zone["exposure_label"] != "DECLARED_EXPOSURE":
            errors.append(f"{zone['zone_id']}: OBSERVED_EXPOSURE is never producible by a static workbench")
    triggers = {affected for item in model["rescope_triggers"] if item["kind"] == "sensitive_data_without_store"
                for affected in item["affected_record_ids"]}
    for item in model.get("data_classes", []):
        if not set(item["store_element_ids"]) <= elements or not set(item["flow_ids"]) <= flows:
            errors.append(f"{item['data_class_id']}: store or flow reference does not resolve")
        if item["category"] in SENSITIVE and not item["store_element_ids"] and item["data_class_id"] not in triggers:
            errors.append(f"{item['data_class_id']}: sensitive data class without a store needs a rescope trigger")
    for item in model.get("abuse_scenarios", []):
        if not set(item["target_element_ids"]) <= elements or not set(item["target_data_class_ids"]) <= classes:
            errors.append(f"{item['scenario_id']}: target reference does not resolve")
    for item in model.get("privacy_threats", []):
        if (not set(item["target_element_ids"]) <= elements or not set(item["target_flow_ids"]) <= flows
                or not set(item["data_class_ids"]) <= classes):
            errors.append(f"{item['privacy_threat_id']}: target reference does not resolve")
    for tree in model.get("attack_trees", []):
        nodes = {node["node_id"]: node for node in tree["nodes"]}
        if tree["root_node_id"] not in nodes:
            errors.append(f"{tree['tree_id']}: root node does not resolve")
            continue
        for node in tree["nodes"]:
            if not set(node["child_node_ids"]) <= set(nodes):
                errors.append(f"{node['node_id']}: child reference leaves the tree")
            if node["kind"] == "leaf":
                if node["leaf_support"] is None or node["child_node_ids"]:
                    errors.append(f"{node['node_id']}: a leaf needs leaf_support and no children")
                if node["leaf_support"] == "evidence" and not node["citations"]:
                    errors.append(f"{node['node_id']}: evidence leaf without a citation")
            elif node["leaf_support"] is not None or not node["child_node_ids"]:
                errors.append(f"{node['node_id']}: an AND/OR node needs children and no leaf_support")
        reached, stack, visiting = set(), [(tree["root_node_id"], ())], None
        while stack:
            node_id, path = stack.pop()
            if node_id in path:
                errors.append(f"{tree['tree_id']}: cycle through {node_id}")
                break
            reached.add(node_id)
            stack.extend((child, (*path, node_id)) for child in nodes.get(node_id, {}).get("child_node_ids", []))
        if reached != set(nodes):
            errors.append(f"{tree['tree_id']}: nodes unreachable from the root")
    for record in [*model.get("data_classes", []), *model.get("deployment_zones", []), *model.get("abuse_scenarios", []),
                   *model.get("privacy_threats", []), *model.get("attack_trees", [])]:
        for citation in record["citations"]:
            if citation["index_record_id"] is not None and not citation["path"]:
                errors.append("an index-only citation names no dereferenced source")
    return errors
