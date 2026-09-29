#!/usr/bin/env python3
"""07-hypothesis-discovery: a code-reading hunter pool that proposes vulnerability hypotheses.

Until this job, nothing in the pipeline read target code to propose vulnerabilities: the claim
ledger received deterministic STRIDE items, OWASP routes and static-tool leads.  This job runs after
evidence assembly, component characterization and source/native SAST, and before
``claim-ledger-routing``, as a persona pool (``pool_specification`` / ``pool_rendezvous``):

* Python shards the target by component (the accepted component map) and packs the shards into
  ``shard_groups`` groups by weight; each group carries its P1/P2 tool-lead cluster as a menu.
* Each instance is one hunter persona (``general-red-team-hunter`` with the general red-team task,
  ``known-list-red-team-hunter`` with the known-issue-catalog task), reads a hash-pinned brief
  (readable input 0), the group's target files, the supporting-evidence menu and the lookup tools
  (input_read / input_grep / input_jq / evidence_*), and is told the leads are a menu, not a limit.
* The persona writes judgment only (``hypothesis-hunt-persona.schema.json``);
  ``hypothesis_hunt_derive`` derives ids, hunter identity and pinned-byte location checks.
* After the pool, :func:`build_result` (pure Python) re-resolves every path and line against the
  checkout bytes, drops what does not resolve as a gap (never invented), deduplicates across
  hunters, records overlap with tool leads, orders, and publishes ``hypothesis-discovery.json``.
  The claim ledger consumes it as its fourth candidate source (``source_kind`` ``hunter``).

Budgets: every instance is one ``claude -p`` call capped at ``budget_max_usd_per_call`` for the
cell template's budget tier (model-config.json; standard = 2.0 USD today), so a run spends at most
``shard_groups * modes_per_group`` times that (default 3 instances, <= 6 USD), repair included.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Callable, Iterable

import bounded_analysis_workers
import claim_ledger
import claude_cli_invoker as cli
import container_execution
import deterministic_pool_merge
import hypothesis_hunt_derive as derive
import model_version_registry as model_versions
import persona_dispatch
import persona_invocation
import persona_prompt_assembly
import pool_launcher
import pool_rendezvous
import pool_specification
import resource_pools
import review_cli
import supporting_evidence_menu as evidence_menu
import tunables
from execution_state import (Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash,
                             read_json, run_path)
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current
from schema_validate import SchemaStore, validate_document

JOB = "07-hypothesis-discovery"
CONTRACT = "hypothesis-discovery"
RESULT = "hypothesis-discovery.json"
SUMMARY = "hypothesis-discovery.md"
MERGE = "hunt-pool-merge.json"
RESULT_SCHEMA = "hypothesis-discovery.schema.json"
PERMISSIONS = ["read-run-data", "write-run-data"]
TEMPLATES = {"general": "hypothesis-hunt-general", "known-list": "hypothesis-hunt-known-list"}
MODE_ORDER = ("general", "known-list")
GUIDES_ROOT_ID = "hunt-guides"
GUIDES_DIR = ROOT / "07-red-team-adversarial"
GUIDE_FILES = {"known-list": ("known-issue-catalog.md", "retrieval-guide.md"), "general": ("retrieval-guide.md",)}
BRIEF_DIR = "hunt-briefs"
TIERS = ("P1", "P2")
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
GAP_REASONS = frozenset({"dropped-by-derive", "not-in-checkout", "line-out-of-range", "file-changed",
                         "malformed-record", "worker-missing", "merge-conflict"})
RULES = (
    "The lead menu lists static-tool leads in your files. It is a menu, not a limit: read the code and "
    "look anywhere in your files (and, through evidence_search / evidence_read, elsewhere) for "
    "vulnerabilities the tools did not flag.",
    "A hypothesis names one construct: repository-relative path plus the line range you read. Never "
    "cite a file or line you did not read; an unresolvable location is dropped as a gap.",
    "Propose candidates only: no severity or rating fields. Adversarial review and independent "
    "verification decide later.",
    "Write only your judgment. Ids, hashes, hunter identity, ordering and citation objects are "
    "derived by the orchestrator.",
)


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def tunable(name: str) -> Any:
    return tunables.value(JOB, name)


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _code_hashes() -> dict[str, str]:
    paths = ["hypothesis_discovery.py", "hypothesis_hunt_derive.py", "contract_derive.py", "claim_ledger.py",
             "claude_cli_invoker.py", "persona_invocation.py", "deterministic_pool_merge.py",
             "pool_launcher.py", "pool_rendezvous.py", "pool_specification.py", "supporting_evidence_menu.py",
             "registry/job-templates/07-hypothesis-discovery.json",
             "registry/output-contracts/hypothesis-discovery.json",
             "registry/output-contracts/hypothesis-hunt-candidates.json",
             "personas/roles/vulnerability-hypothesis-hunter/role.json",
             "personas/roles/hypothesis-hunt-coordinator/role.json",
             "registry/domains/vulnerability-hypothesis-discovery.json",
             "registry/tooling-profiles/hypothesis-hunt-static.json"]
    for mode, template in sorted(TEMPLATES.items()):
        paths += [f"registry/job-templates/{template}.json", f"personas/personas/{derive.MODES[mode]}/persona.json",
                  f"07-red-team-adversarial/task-{template}.md"]
    paths += [f"07-red-team-adversarial/{name}" for name in sorted({n for v in GUIDE_FILES.values() for n in v})]
    values = {path: file_hash(ROOT / path) for path in paths}
    for name in (RESULT_SCHEMA, derive.PERSONA_SCHEMA, derive.CANDIDATES_SCHEMA, derive.RECORD_SCHEMA):
        values["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return values


# --- target inventory and shard planning (pure) -------------------------------------------------------

def walk_target(target_root: Path, *, file_bytes_max: int) -> list[dict[str, Any]]:
    """Every regular non-symlink file under the checkout except ``.git``: path, sha256, bytes, lines,
    and whether it can be pinned for code reading (text, not larger than ``file_bytes_max``)."""
    target_root = Path(target_root)
    rows = []
    for directory, dirs, names in os.walk(target_root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != ".git" and not (Path(directory) / d).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            data = path.read_bytes()
            relative = path.relative_to(target_root).as_posix()
            binary = b"\x00" in data[:8192]
            rows.append({"path": relative, "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                         "bytes": len(data), "lines": derive._line_count(data),
                         "readable": None if not binary and len(data) <= file_bytes_max else
                         ("binary" if binary else f"larger than {file_bytes_max} bytes")})
    return sorted(rows, key=lambda row: row["path"])


def flat_leads(sources: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every located lead with its tier, in a closed shape (the hunter menu and overlap index)."""
    rows = []
    for source in sources:
        for lead in source["leads"]:
            if not lead.get("path") or not lead.get("start_line"):
                continue
            rows.append({"producer_job_id": source["producer_job_id"], "lead_ref": str(lead["lead_ref"]),
                         "tool_id": str(lead["tool_id"]), "rule_id": str(lead["rule_id"]),
                         "category": str(lead["category"]), "path": lead["path"],
                         "start_line": int(lead["start_line"]),
                         "end_line": int(lead.get("end_line") or lead["start_line"]),
                         "tier": claim_ledger.lead_tier(lead)})
    return sorted(rows, key=lambda row: (row["path"], row["start_line"], row["producer_job_id"],
                                         row["tool_id"], row["rule_id"], row["lead_ref"]))


def plan_shards(files: list[dict[str, Any]], components: list[dict[str, Any]], leads: list[dict[str, Any]], *,
                shard_groups: int, modes_per_group: int, pin_bytes_max: int, lead_menu_max: int,
                max_hypotheses: int, max_line_span: int) -> list[dict[str, Any]]:
    """Pack component shards into groups and return one brief per hunter instance (pure)."""
    by_component: dict[str, list[dict[str, Any]]] = {}
    for row in files:
        component = claim_ledger._components_for(row["path"], components)[0]
        by_component.setdefault(component, []).append(row)
    lead_files: dict[str, dict[str, int]] = {}
    for lead in leads:
        lead_files.setdefault(lead["path"], {"P1": 0, "P2": 0, "P3": 0})[lead["tier"]] += 1
    units = []
    for component, rows in by_component.items():
        p1 = sum(lead_files.get(row["path"], {}).get("P1", 0) for row in rows)
        p2 = sum(lead_files.get(row["path"], {}).get("P2", 0) for row in rows)
        weight = sum(row["bytes"] for row in rows if row["readable"] is None)
        units.append({"component_id": component, "files": rows, "p1": p1, "p2": p2, "weight": weight})
    units = [unit for unit in units if any(row["readable"] is None for row in unit["files"])]
    units.sort(key=lambda unit: (-unit["p1"], -unit["p2"], -unit["weight"], unit["component_id"]))
    count = min(max(1, shard_groups), len(units))
    groups: list[dict[str, Any]] = [{"units": [], "weight": 0} for _ in range(count)]
    for unit in units:
        target = min(range(count), key=lambda index: (groups[index]["weight"], index))
        groups[target]["units"].append(unit); groups[target]["weight"] += unit["weight"]
    briefs = []
    for index, group in enumerate(groups):
        rows = [row for unit in group["units"] for row in unit["files"]]
        # Files with leads first (P1 then P2 counts), then the rest by path, until the pin budget.
        rows.sort(key=lambda row: (-lead_files.get(row["path"], {}).get("P1", 0),
                                   -lead_files.get(row["path"], {}).get("P2", 0), row["path"]))
        pinned, unpinned, used = [], [], 0
        for row in rows:
            if row["readable"] is not None:
                unpinned.append({"path": row["path"], "reason": row["readable"]})
            elif used + row["bytes"] > pin_bytes_max:
                unpinned.append({"path": row["path"], "reason": "over the per-instance pin budget; "
                                 "reach it through evidence_search / evidence_read"})
            else:
                pinned.append(row); used += row["bytes"]
        paths = {row["path"] for row in rows}
        menu = [lead for lead in leads if lead["path"] in paths and lead["tier"] in TIERS]
        menu.sort(key=lambda lead: (TIERS.index(lead["tier"]), lead["path"], lead["start_line"], lead["lead_ref"]))
        modes = MODE_ORDER if modes_per_group >= 2 else (MODE_ORDER[index % len(MODE_ORDER)],)
        for mode in modes:
            shard_id = f"g{index + 1:02d}-{mode}"
            briefs.append({"schema": derive.BRIEF_SCHEMA_ID, "shard_id": shard_id, "mode": mode,
                "persona_id": derive.MODES[mode],
                "component_ids": sorted(unit["component_id"] for unit in group["units"]),
                "pinned_files": [{"path": row["path"], "sha256": row["sha256"], "lines": row["lines"]}
                                 for row in sorted(pinned, key=lambda row: row["path"])],
                "unpinned_files": sorted(unpinned, key=lambda row: row["path"])[:200],
                "unpinned_total": len(unpinned),
                "lead_menu": [{key: lead[key] for key in ("path", "start_line", "end_line", "tier", "tool_id",
                               "rule_id", "category", "producer_job_id")} for lead in menu[:lead_menu_max]],
                "lead_menu_total": len(menu),
                "p3_leads_in_files": sum(1 for lead in leads if lead["path"] in paths and lead["tier"] == "P3"),
                "limits": {"max_hypotheses": max_hypotheses, "max_line_span": max_line_span},
                "rules": list(RULES)})
    return briefs


def placeholder_brief() -> dict[str, Any]:
    """The brief of an empty pool's count-0 group (nothing to read, never launched)."""
    return {"schema": derive.BRIEF_SCHEMA_ID, "shard_id": "g00-general", "mode": "general",
            "persona_id": derive.MODES["general"], "component_ids": [], "pinned_files": [], "unpinned_files": [],
            "unpinned_total": 0, "lead_menu": [], "lead_menu_total": 0, "p3_leads_in_files": 0,
            "limits": {"max_hypotheses": 0, "max_line_span": 0}, "rules": list(RULES)}


def brief_bytes(brief: dict[str, Any]) -> bytes:
    return (json.dumps(brief, sort_keys=True, indent=1, ensure_ascii=True) + "\n").encode("utf-8")


def _fit_menu(menu: dict[str, Any], budget_bytes: int) -> dict[str, Any]:
    """Unpin menu files (in menu order) that would push the instance past its input byte budget."""
    menu = copy.deepcopy(menu)
    used = 0
    for item in menu["items"]:
        for entry in item["files"]:
            if entry["pinned"]:
                if used + entry["bytes"] > budget_bytes:
                    entry["pinned"] = False
                else:
                    used += entry["bytes"]
    menu["pinned_bytes"] = used
    return menu


# --- the pool --------------------------------------------------------------------------------------------

def _runtime_instructions(brief: dict[str, Any]) -> str:
    """Trusted block appended to the prompt (the brief itself is pinned input 0 and in the cache key)."""
    return "\n\n## Trusted hunt runtime (not target data)\n\n" + json.dumps({
        "job": JOB, "shard_id": brief["shard_id"], "mode": brief["mode"], "persona_id": brief["persona_id"],
        "component_ids": brief["component_ids"],
        "readable_roots": {derive.BRIEF_ROOT_ID: "your brief (pinned input 0): files, lead menu, limits",
                           derive.TARGET_ROOT_ID: "the target files of your shard (read them)",
                           evidence_menu.MENU_ROOT_ID: "the supporting-evidence menu",
                           evidence_menu.ROOT_ID: "accepted evidence the menu pins",
                           GUIDES_ROOT_ID: "the retrieval guide / known-issue catalog"},
        "reply_shape": ("the candidates envelope value is {\"hypotheses\": [...]} and validates "
                        f"{derive.PERSONA_SCHEMA}; an empty list is a valid answer"),
        "limits": brief["limits"], "rules": brief["rules"],
        "orchestrator_supplies": ("hypothesis ids, file hashes, hunter identity, shard, ordering, citation "
                                  "objects and deduplication against tool leads; do not write them")},
        indent=2, sort_keys=True)


def _derive_fill(package: Any):
    brief_input = package.inputs[0]
    if brief_input.root != derive.BRIEF_ROOT_ID:
        raise cli.InvokerOutputError("hunter brief must be readable input 0")
    brief = derive.read_brief(brief_input.data)

    def fill(envelope: dict[str, Any], result_field: str) -> list[str]:
        value, limitations = derive.derive(brief, envelope.get(result_field), package.inputs,
                                           brief_sha256=brief_input.sha256)
        envelope[result_field] = value
        return limitations

    return fill


cli._CLAIM_BUILDERS.setdefault(derive.CANDIDATES_SCHEMA, derive.hunt_claims)


class HunterInvoker:
    """Lane adapter over the strict Claude CLI invoker: renders the persona-facing reply schema and
    the trusted hunt block, and derives the strict candidates document from the hunter's judgment."""
    invoker_id = "claude-cli"

    def __init__(self, *, effort: str, budget_usd: float | None = None,
                 timeout_seconds: int = cli.DEFAULT_TIMEOUT_SECONDS, dispatch_fn=None) -> None:
        self.effort, self.budget_usd, self.timeout_seconds = effort, budget_usd, timeout_seconds
        self.dispatch_fn = dispatch_fn or review_cli._dispatch_streaming

    def invoke(self, package: Any, *, output_root: Path, cancel: Any) -> None:
        instructions = _runtime_instructions(derive.read_brief(package.inputs[0].data))

        def dispatch(argv: list[str], prompt: str, timeout: int, transcript: Path) -> dict[str, Any]:
            return self.dispatch_fn(argv, prompt + instructions, timeout, transcript)

        cli.ClaudeCliInvoker(effort=self.effort, budget_usd=self.budget_usd,
            timeout_seconds=self.timeout_seconds, dispatch_fn=dispatch,
            fill_result=_derive_fill(package), persona_schema=derive.PERSONA_SCHEMA).invoke(
                package, output_root=output_root, cancel=cancel)


def _cell_request(run_id: str, mode: str, readable: list[dict[str, Any]], store: SchemaStore) -> dict[str, Any]:
    template_id = TEMPLATES[mode]
    template = persona_prompt_assembly.load_job_template(template_id, store)
    composition = persona_dispatch._composition_block(template_id, template, store)
    records = persona_invocation.load_composition(persona_invocation.REGISTRY_DIR, composition, store)
    ceiling = persona_invocation.claim_ceiling(records["role"], records["tooling_profile"])
    if "candidate_only" not in ceiling["allowed"]:
        raise Blocked(f"{JOB}: registry composition forbids candidate_only hunter claims")
    resolved = review_cli.resolve_model(template_id, template["budget_default"])
    return {"invocation_role": "produce", "invoker_id": "claude-cli",
            "outer_prompt": persona_prompt_assembly.assemble_outer_prompt(template_id, store=store),
            "persona": composition, "model": model_versions.model_identity_for(run_id, resolved["model"]),
            "tools": [], "budget": dict(persona_dispatch.PERSONA_BUDGETS[template["budget_default"]]),
            "readable_inputs": readable, "allowed_claim_classes": list(ceiling["allowed"]),
            "prohibited_claim_classes": list(ceiling["prohibited"]), "producers": []}


def _guide_rows(mode: str) -> list[dict[str, Any]]:
    rows = []
    for name in GUIDE_FILES[mode]:
        data = (GUIDES_DIR / name).read_bytes()
        rows.append({"root": GUIDES_ROOT_ID, "path": name, "sha256": persona_invocation._bytes_sha(data),
                     "bytes": len(data), "role": "evidence", "producer_request_sha256": None})
    return rows


def _target(run_id: str) -> tuple[Path, str]:
    manifest_path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise Blocked(f"{JOB}: staged artifact-manifest.json is required")
    value = ((read_json(manifest_path).get("target") or {}).get("repo_path"))
    path = Path(value) if isinstance(value, str) and value else None
    if path is None or not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked(f"{JOB}: target.repo_path must be an absolute real checkout directory")
    import intake
    return path.resolve(), "sha256:" + intake.source_identity(str(path.resolve()))["fingerprint"]


def prepare(run_id: str) -> dict[str, Any]:
    """Derive the stable pool specification from accepted upstreams and the checkout (no model)."""
    pointer = data_path(run_id, "jobs", "01-component-characterization", "accepted.json")
    if not pointer.is_file():
        raise Blocked(f"{JOB}: accepted component map is required")
    component_map, binding = bounded_analysis_workers.load_accepted(pointer, run_id=run_id,
        job_id="01-component-characterization", contract="component-map",
        artifact="component-purpose-map.json", schema="component-purpose-map.schema.json")
    source = component_map["source_snapshot_sha256"]
    target_root, identity = _target(run_id)
    if identity != source:
        raise Blocked(f"{JOB}: the checkout no longer matches the component map's source snapshot")
    lead_sources, lead_coverage = claim_ledger.lead_sources(run_id, source, binding["attempt_id"])
    leads = flat_leads(lead_sources)
    components = claim_ledger.lead_components(component_map)
    files = walk_target(target_root, file_bytes_max=tunable("file_bytes_max"))
    store = SchemaStore()
    budget_bytes = persona_dispatch.PERSONA_BUDGETS[
        persona_prompt_assembly.load_job_template(TEMPLATES["general"], store)["budget_default"]]["input_byte_limit"]
    pin_bytes = min(tunable("target_pin_bytes_max"), budget_bytes // 2)
    briefs = plan_shards(files, components, leads, shard_groups=tunable("shard_groups"),
        modes_per_group=tunable("modes_per_group"), pin_bytes_max=pin_bytes,
        lead_menu_max=tunable("lead_menu_max"), max_hypotheses=tunable("max_hypotheses_per_instance"),
        max_line_span=tunable("max_line_span"))
    for brief in briefs:
        brief["run_id"] = run_id
    accepted_at = read_json(pointer)["accepted_at"]
    evaluated_at = datetime.fromisoformat(accepted_at.replace("Z", "+00:00")).astimezone(
        timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    guides = sum(len((GUIDES_DIR / name).read_bytes()) for name in GUIDE_FILES["known-list"])
    menu = _fit_menu(evidence_menu.build(run_id, JOB, []), max(0, budget_bytes - pin_bytes - guides - 1_000_000))
    # An empty pool still states its one (count 0) group template, so the expansion is well formed.
    pool_briefs = briefs or [{**placeholder_brief(), "run_id": run_id}]
    groups = []
    for brief in pool_briefs:
        data = brief_bytes(brief)
        readable = [{"root": derive.BRIEF_ROOT_ID, "path": brief["shard_id"] + ".json",
                     "sha256": persona_invocation._bytes_sha(data), "bytes": len(data), "role": "evidence",
                     "producer_request_sha256": None}]
        by_path = {row["path"]: row for row in files}
        readable += [{"root": derive.TARGET_ROOT_ID, "path": row["path"], "sha256": row["sha256"],
                      "bytes": by_path[row["path"]]["bytes"], "role": "evidence", "producer_request_sha256": None}
                     for row in brief["pinned_files"]]
        readable += _guide_rows(brief["mode"]) + evidence_menu.readable_inputs(menu)
        groups.append({"group_id": brief["shard_id"], "worker_kind": pool_specification.PERSONA, "count": 1,
            "memory_heavy": False,
            "permission": persona_dispatch._permission_block(JOB, run_id=run_id, source_snapshot_sha256=source,
                                                             now=evaluated_at),
            "persona_request": _cell_request(run_id, brief["mode"], readable, store), "tool_request": None})
    count = len(briefs)
    if not briefs:
        groups[0]["count"] = 0
    budget = groups[0]["persona_request"]["budget"] if groups else persona_dispatch.PERSONA_BUDGETS["standard"]
    spec = {"schema": pool_specification.SPEC_ID, "pool_id": "hypothesis-discovery",
        "lane": "07-red-team-adversarial", "run_id": run_id, "job_id": JOB,
        "attempt_id": "hunt-" + digest({"binding": binding, "briefs": briefs})[:24], "budget_class": "standard",
        "pool_budget": {"max_instances": count, "max_persona_input_units": count * budget["input_unit_limit"],
                        "max_persona_output_units": count * budget["output_unit_limit"],
                        "max_total_timeout_seconds": max(1, count) * budget["timeout_seconds"]},
        "resource_pool_policy": {"allowed_pools": [resource_pools.PERSONA_LLM]},
        "wait_all": True, "rendezvous_timeout_seconds": tunable("rendezvous_timeout_seconds"),
        "empty_pool_reason": None if count else "no_applicable_work",
        "worker_groups": sorted(groups, key=lambda group: group["group_id"])}
    return {"run_id": run_id, "source_generation": source, "component_generation": binding["attempt_id"],
            "component_binding": binding, "target_root": str(target_root), "components": components,
            "leads": leads, "lead_coverage": lead_coverage, "briefs": briefs, "pool_briefs": pool_briefs,
            "evidence_menu": menu,
            "accepted_at": evaluated_at, "spec": spec,
            "applicability": "APPLICABLE" if count else "SKIPPED_NA_NO_READABLE_SOURCE", "code": _code_hashes()}


def _context(inputs: dict[str, Any], attempt: Path) -> pool_specification.PoolContext:
    pool_parent, rendezvous = attempt / "pools", attempt / "rendezvous"
    pool_parent.mkdir(); rendezvous.mkdir()
    briefs = attempt / BRIEF_DIR
    briefs.mkdir()
    for brief in inputs["pool_briefs"]:
        atomic_bytes(briefs / (brief["shard_id"] + ".json"), brief_bytes(brief))
    menu_root = evidence_menu.write(attempt / "evidence-menu", inputs["evidence_menu"])
    roots = {derive.BRIEF_ROOT_ID: briefs, derive.TARGET_ROOT_ID: Path(inputs["target_root"]),
             GUIDES_ROOT_ID: GUIDES_DIR,
             **evidence_menu.readable_roots(inputs["run_id"], inputs["evidence_menu"], menu_root)}
    models = tuple({json.dumps(group["persona_request"]["model"], sort_keys=True): group["persona_request"]["model"]
                    for group in inputs["spec"]["worker_groups"]}.values())
    return pool_specification.PoolContext(pool_parent=pool_parent,
        registry_dir=persona_invocation.REGISTRY_DIR, prompt_root=ROOT, readable_roots=roots,
        allowed_models=models, invoker_id="claude-cli", images_dir=container_execution.IMAGES_DIR,
        host_flavor="windows" if os.name == "nt" else "posix", docker_host=None, docker_executable=None,
        container_user=None, mount_roots={}, source_snapshot_sha256=inputs["source_generation"],
        registry_ceiling=None)


# --- post-pool bookkeeping (pure) -------------------------------------------------------------------

def checkout_reader(target_root: Path) -> Callable[[str], bytes | None]:
    """Bytes of one repository-relative regular file under the checkout, or None (no symlink, no .git)."""
    base = Path(target_root).resolve()

    def read(relative: str) -> bytes | None:
        parts = PurePosixPath(relative).parts
        if (not parts or PurePosixPath(relative).is_absolute() or parts[0] == ".git"
                or any(part in {"", ".", ".."} for part in parts)):
            return None
        cursor = base
        for part in parts:
            cursor = cursor / part
            if cursor.is_symlink():
                return None
        return cursor.read_bytes() if cursor.is_file() else None

    return read


def _gap(kind: str, record: dict[str, Any] | None, reason: str, shard: str | None = None) -> dict[str, Any]:
    assert kind in GAP_REASONS
    record = record or {}
    start = record.get("start_line")
    return {"kind": kind, "path": record.get("path") if isinstance(record.get("path"), str) else None,
            "start_line": start if isinstance(start, int) else None, "reason": reason[:500],
            "shard_id": shard if shard is not None else (record.get("hunter") or {}).get("shard_id")}


def build_result(inputs: dict[str, Any], merge: dict[str, Any], read: Callable[[str], bytes | None]) -> dict[str, Any]:
    """Resolve, deduplicate, overlap and order the merged hunter records against the checkout."""
    store = SchemaStore()
    gaps: list[dict[str, Any]] = []
    cache: dict[str, bytes | None] = {}

    def data_of(path: str) -> bytes | None:
        if path not in cache:
            cache[path] = read(path)
        return cache[path]

    groups: dict[tuple, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for candidate in merge.get("candidates", []):
        try:
            record = json.loads(candidate["assertion"])
        except (ValueError, KeyError, TypeError):
            gaps.append(_gap("malformed-record", None, "hunter candidate assertion is not JSON")); continue
        if validate_document(record, derive.RECORD_SCHEMA, store):
            gaps.append(_gap("malformed-record", None, "hunter record fails hunter-hypothesis.schema.json")); continue
        if record["kind"] == "dropped":
            gaps.append(_gap("dropped-by-derive", record, record["drop_reason"] or "dropped")); continue
        data = data_of(record["path"])
        if data is None:
            gaps.append(_gap("not-in-checkout", record, "path is not a regular file of the reviewed checkout")); continue
        sha = "sha256:" + hashlib.sha256(data).hexdigest()
        if record["file_sha256"] is not None and record["file_sha256"] != sha:
            gaps.append(_gap("file-changed", record, "file bytes differ from what the hunter read")); continue
        lines = derive._line_count(data)
        if record["start_line"] > lines:
            gaps.append(_gap("line-out-of-range", record, f"start_line past the end of the file ({lines} lines)")); continue
        record = {**record, "file_sha256": sha, "end_line": min(record["end_line"], lines)}
        evidence = []
        for item in record["evidence"]:
            if item["kind"] == "target-deferred":
                other = data_of(item["path"])
                ok = other is not None and (item["start_line"] is None or
                                            1 <= item["start_line"] <= derive._line_count(other))
                item = {**item, "kind": "target-range" if ok else "unresolved"}
            evidence.append(item)
        record["evidence"] = evidence
        key = (record["path"], record["start_line"], derive.class_key(record))
        groups.setdefault(key, []).append((record, candidate))
    leads = inputs.get("leads", [])
    components = inputs.get("components", [])
    hypotheses = []
    for (path, start, key), members in groups.items():
        members.sort(key=lambda pair: (-CONFIDENCE_RANK[pair[0]["confidence"]], pair[1]["candidate_id"]))
        primary = members[0][0]
        end = max(record["end_line"] for record, _c in members)
        preconditions = list(dict.fromkeys(text for record, _c in members for text in record["attacker_preconditions"]))
        evidence, seen = [], set()
        for record, _c in members:
            for item in record["evidence"]:
                identity = json.dumps(item, sort_keys=True)
                if identity not in seen:
                    seen.add(identity); evidence.append(item)
        hunters = sorted(({"mode": record["hunter"]["mode"], "persona_id": record["hunter"]["persona_id"],
                           "shard_id": record["hunter"]["shard_id"], "worker_ids": list(candidate.get("worker_ids", [])),
                           "candidate_id": candidate["candidate_id"]} for record, candidate in members),
                         key=lambda row: (row["shard_id"], row["candidate_id"]))
        overlap = [{"producer_job_id": lead["producer_job_id"], "lead_ref": lead["lead_ref"], "tool_id": lead["tool_id"],
                    "rule_id": lead["rule_id"], "start_line": lead["start_line"], "tier": lead["tier"]}
                   for lead in leads if lead["path"] == path and start <= lead["start_line"] <= end]
        confidence = primary["confidence"]
        hypotheses.append({"hypothesis_id": derive.subject_id(path, start, key),
            "tier": "P1" if confidence in {"high", "medium"} else "P2", "path": path, "start_line": start,
            "end_line": end, "file_sha256": primary["file_sha256"],
            "vulnerability_class": primary["vulnerability_class"], "cwe": primary["cwe"],
            "mechanism": primary["mechanism"], "attacker_preconditions": preconditions[:derive.PRECONDITIONS_MAX * 2],
            "confidence": confidence, "component_ids": claim_ledger._components_for(path, components),
            "evidence": evidence, "hunters": hunters, "lead_overlap": overlap})
    hypotheses.sort(key=lambda row: (TIERS.index(row["tier"]), row["path"], row["start_line"], row["hypothesis_id"]))
    for worker in merge.get("missing_worker_ids", []):
        gaps.append(_gap("worker-missing", None, f"hunter instance {worker} returned no result", shard=None))
    for conflict in merge.get("conflicts", []):
        gaps.append(_gap("merge-conflict", None, f"candidate {conflict['candidate_id']} differs between workers"))
    gaps.sort(key=lambda row: (row["kind"], str(row["path"]), row["start_line"] or 0, row["reason"]))
    result = {"schema": "appsec-review/hypothesis-discovery/1.0", "run_id": inputs["run_id"], "job_id": JOB,
        "source_snapshot_sha256": inputs["source_generation"],
        "component_generation": inputs["component_generation"],
        "pool": {"instances": len(inputs["briefs"]), "expected_worker_ids": list(merge.get("expected_worker_ids", [])),
                 "missing_worker_ids": list(merge.get("missing_worker_ids", [])),
                 "conflict_candidate_ids": [row["candidate_id"] for row in merge.get("conflicts", [])],
                 "merge_sha256": merge.get("merge_sha256")},
        "shards": [{"shard_id": brief["shard_id"], "mode": brief["mode"], "persona_id": brief["persona_id"],
                    "component_ids": brief["component_ids"], "pinned_files": len(brief["pinned_files"]),
                    "unpinned_files": brief["unpinned_total"], "lead_menu": brief["lead_menu_total"]}
                   for brief in inputs["briefs"]],
        "hypotheses": hypotheses, "gaps": gaps,
        "claim_limits": {"candidate_only": True, "finding_created": False, "severity_assigned": False,
                         "runtime_claimed": False}}
    errors = validate_document(result, RESULT_SCHEMA, store)
    if errors:
        raise Blocked(f"{JOB}: result fails its closed schema ({errors[0]})")
    return result


def summary(result: dict[str, Any]) -> str:
    lines = ["# Code-reading hypothesis discovery", "",
             f"{len(result['hypotheses'])} candidate hypothesis(es) from {result['pool']['instances']} hunter "
             f"instance(s); {len(result['gaps'])} gap(s).", "",
             "| Tier | Location | Class | Confidence | Hunters | Tool-lead overlap |", "|---|---|---|---|---|---|"]
    for row in result["hypotheses"]:
        where = f"{row['path']}:{row['start_line']}" + (f"-{row['end_line']}" if row["end_line"] != row["start_line"] else "")
        label = (row["cwe"] + " " if row["cwe"] else "") + row["vulnerability_class"]
        lines.append(f"| {row['tier']} | `{where}` | {label.replace('|', '/')} | {row['confidence']} | "
                     f"{', '.join(sorted({h['mode'] for h in row['hunters']}))} | {len(row['lead_overlap'])} |")
    if result["gaps"]:
        lines += ["", "## Gaps", ""] + [f"- {gap['kind']}: {gap['path'] or '-'}"
                                         f"{':' + str(gap['start_line']) if gap['start_line'] else ''} {gap['reason']}"
                                         for gap in result["gaps"]]
    lines += ["", "Hypotheses are candidates for the claim ledger; none is a finding, severity or runtime claim.", ""]
    return "\n".join(lines)


def _receipts(inputs: dict[str, Any], result: dict[str, Any], launched: Any) -> tuple[dict, dict, dict]:
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0", "run_id": inputs["run_id"],
        "job_id": JOB, "source_snapshot_sha256": inputs["source_generation"], "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": inputs["run_id"], "job_id": JOB,
        "source_snapshot_sha256": inputs["source_generation"],
        "build_lineage_sha256": _sha({"component": inputs["component_binding"],
            "spec": pool_specification.spec_sha256(inputs["spec"]), "expansion": launched.expansion_sha256,
            "manifest": launched.terminal_manifest_sha256, "merge": result["pool"]["merge_sha256"]})}
    receipt = {"schema": "appsec-review/hypothesis-hunt-pool-receipt/1.0", "run_id": inputs["run_id"],
        "decision": "APPLICABLE" if inputs["applicability"] == "APPLICABLE" else "SKIPPED_NA",
        "pool_directory": launched.pool_directory, "pool_outcome": launched.outcome,
        "instance_count": launched.instance_count, "expansion_sha256": launched.expansion_sha256,
        "terminal_manifest_sha256": launched.terminal_manifest_sha256, "merge_sha256": result["pool"]["merge_sha256"]}
    return permission, lineage, receipt


def _validate_attempt(attempt: Path, inputs: dict[str, Any], *, reprepare: bool = True) -> None:
    if read_json(attempt / "inputs.json") != inputs or inputs["code"] != _code_hashes():
        raise Blocked(f"{JOB}: immutable inputs or implementation changed")
    if reprepare and prepare(inputs["run_id"]) != inputs:
        raise Blocked(f"{JOB}: accepted upstreams or the checkout changed")
    merge = read_json(attempt / MERGE)
    result = read_json(attempt / RESULT)
    if result != build_result(inputs, merge, checkout_reader(Path(inputs["target_root"]))):
        raise Blocked(f"{JOB}: result differs from the retained merge and the checkout")
    receipt = read_json(attempt / "pool-receipt.json")
    launched = type("RetainedPool", (), {"pool_directory": receipt.get("pool_directory"),
        "outcome": receipt.get("pool_outcome"), "instance_count": receipt.get("instance_count"),
        "expansion_sha256": receipt.get("expansion_sha256"),
        "terminal_manifest_sha256": receipt.get("terminal_manifest_sha256")})()
    permission, lineage, expected = _receipts(inputs, result, launched)
    if (read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage
            or receipt != expected):
        raise Blocked(f"{JOB}: retained receipts changed")


def _budget_usd(mode: str = "general") -> float | None:
    template = persona_prompt_assembly.load_job_template(TEMPLATES[mode], SchemaStore())
    value = (review_cli.load_model_config().get("budget_max_usd_per_call") or {}).get(template["budget_default"])
    return float(value) if isinstance(value, (int, float)) else None


def run(run_id: str, dagster_run_id: str, force: bool = False, *, invoker: Any = None) -> dict[str, Any]:
    """Dispatch the hunter pool and publish the verified, checkout-resolved hypotheses."""
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        context = _context(inputs, attempt)
        rendezvous_parent = attempt / "rendezvous"
        effort = review_cli.resolve_model(TEMPLATES["general"], "standard").get("effort") or "high"
        runtime = pool_rendezvous.RendezvousRuntime(rendezvous_parent=rendezvous_parent,
            invoker=invoker or HunterInvoker(effort=effort, budget_usd=_budget_usd()),
            clock=lambda: inputs["accepted_at"], stop_grace_seconds=5, cancel=pool_rendezvous.PoolCancel(),
            max_parallel=tunable("max_parallel"), wait_limit_seconds=tunable("rendezvous_timeout_seconds"),
            drain_seconds=10)
        launched = pool_launcher.launch(inputs["spec"], context=context, runtime=runtime)
        pool_root = context.pool_parent / launched.pool_directory
        verified = pool_rendezvous.load_verified_manifest(pool_root, expected_spec=inputs["spec"],
            context=context, rendezvous_parent=rendezvous_parent)
        merge = deterministic_pool_merge.merge_verified_manifest(verified, pool_root=pool_root, run_id=run_id)
        result = build_result(inputs, merge, checkout_reader(Path(inputs["target_root"])))
        atomic_json(attempt / MERGE, merge); atomic_json(attempt / RESULT, result)
        atomic_bytes(attempt / SUMMARY, summary(result).encode("utf-8"))
        permission, lineage, receipt = _receipts(inputs, result, launched)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        atomic_json(attempt / "pool-receipt.json", receipt)
        skipped = inputs["applicability"] != "APPLICABLE"
        gaps = ([f"SKIPPED_NA: {inputs['applicability']}; zero hunter instances were launched."] if skipped else [])
        gaps += [f"{gap['kind']}: {gap['path'] or '-'} {gap['reason']}" for gap in result["gaps"]]
        status_value = "OK_WITH_GAPS" if gaps else "OK"
        status = {"process": JOB, "status": status_value, "result": RESULT, "hypotheses": len(result["hypotheses"]),
                  "gaps": len(result["gaps"]), "instances": result["pool"]["instances"],
                  "claim_limit": "candidate-only", "applicability": inputs["applicability"]}
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_run_id,
            worker_kind="pool_coordinator", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=status_value,
            summary=f"Published {len(result['hypotheses'])} code-reading hypothesis(es) for the claim ledger.",
            status_record=status,
            artifact_paths=[RESULT, SUMMARY, MERGE, "permission.json", "lineage.json", "pool-receipt.json",
                            "status.json"], gaps=gaps or None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(path, inputs, reprepare=False))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_run_id,
        worker_kind="pool_coordinator", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/hypothesis_discovery.py --run-id {run_id}",
        derive_inputs=lambda: prepare(run_id), fingerprint_inputs=lambda value: _sha(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()}, force=force,
        post_validate=lambda attempt, _envelope, inputs: _validate_attempt(attempt, inputs),
        blocked_summary="Accepted component map, tool leads or the checkout were not current.",
        failed_summary="Hunter pool did not publish verified hypotheses.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-hypothesis-discovery")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.run_id, args.dagster_run_id, args.force), indent=2))


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
