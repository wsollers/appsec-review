"""Deterministic, offline documentation projections of repository contracts."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from dataclasses import asdict, fields, is_dataclass
from enum import Enum
import hashlib
import inspect
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

from scripts.docs_support import BLOCK, KINDS, frontmatter, slug, with_frontmatter


ROOT = Path(__file__).resolve().parents[1]
LEDGER = "docs/docs-ledger.json"
INVENTORY = "docs/generated/inventory.json"
GUIDANCE = "docs/generated/guidance.md"
GAP_ID = "T-147"
SOURCES = (
    "appsec-review.toml", "containers/catalog.toml", "pipeline/guidance/registry.json",
    "tests/job-test-map.json", "src/appsec_review/runtime/registry.py",
    "src/appsec_review/runtime/contracts.py", "src/appsec_review/runtime/datasets.py",
    "src/appsec_review/guidance/workers.py", "src/appsec_review/mcp/schema.py",
    "src/appsec_review/orchestration/topology.py",
    "src/appsec_review/orchestration/dagster/adapter.py",
)
INDEX_PATHS = {
    "architecture": "docs/architecture/README.md",
    "operations": "docs/operations/README.md",
    "process": "docs/processes/README.md",
    "task": "docs/tasks/README.md",
    "walk": "docs/generated/walk-index.md",
    "review": "docs/reviews/README.md",
    "schema": "docs/schemas/README.md",
    "history": "docs/generated/history-index.md",
    "generated": "docs/generated/README.md",
}


def notice(sources: tuple[str, ...] = SOURCES) -> str:
    return f"generated from: {', '.join(sources)} by scripts/generate-docs.py; do not edit"


def plain(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: plain(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): plain(child) for key, child in sorted(value.items())}
    if isinstance(value, (tuple, list)):
        return [plain(child) for child in value]
    if isinstance(value, (set, frozenset)):
        return sorted(plain(child) for child in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported documentation projection: {type(value).__name__}")


def recipe_config(root: Path):
    """Validate the dev recipe without reading, publishing or provisioning host bindings."""
    from appsec_review.config import load_config
    from appsec_review.config.host_pins import (
        HostPins, configuration_image_settings, serialize_host_pins,
    )
    raw = tomllib.loads((root / "appsec-review.toml").read_text(encoding="utf-8"))
    # The loader requires syntactically valid pins even for a nonexecuting recipe projection.
    # These unbound sentinels are excluded from the documentation projection and never authorize a launch.
    bindings = {
        tag: settings.get(key, "sha256:" + "0" * 64)
        for _, settings, key, tag in configuration_image_settings(raw)
    }
    pins = HostPins(root / "documentation-unbound-pins", serialize_host_pins(bindings, []))
    config = load_config(root / "appsec-review.toml", profile="dev", overlay="", host_pins=pins)
    return config, raw


def task_binding(unit, root: Path) -> dict:
    handler = unit.handler
    source = inspect.getsourcefile(handler)
    if source is None:
        raise ValueError(f"task handler has no source: {unit.unit_id}")
    path = Path(source).resolve().relative_to(root).as_posix()
    _, line = inspect.getsourcelines(handler)
    tools, internal = [], []
    for parameter in inspect.signature(handler).parameters.values():
        selected = parameter.default
        if (unit.unit_id.endswith("_scan") and hasattr(selected, "tool_id")
                and isinstance(selected.tool_id, str)):
            (internal if getattr(selected, "mode", None) in {"static", "discovery"}
             else tools).append(selected.tool_id)
    return {
        "handler": f"{handler.__module__}.{handler.__qualname__}",
        "source": path,
        "line": line,
        "tools": sorted(set(tools)),
        "internal_tools": sorted(set(internal)),
        "tool_binding": "bound_adapter" if tools or internal else "not_declared",
        "tool_gap": None if tools or internal else GAP_ID,
        "guidance_binding": "not_declared",
        "guidance_gap": GAP_ID,
    }


def guidance_assignments(registry: dict) -> dict:
    from appsec_review.guidance.workers import (
        BUILD_FAMILIES, REVIEW_DISPATCHED, SPECIALIZED_WORKERS, WORKBENCH_DISPATCHED,
    )
    assignments = {kind: {name: set() for name in registry[kind]}
                   for kind in ("roles", "personas", "stacks", "runtime_skills")}
    for worker in SPECIALIZED_WORKERS.values():
        roles = ([worker.role.format(family=family) for family in BUILD_FAMILIES]
                 if "{family}" in worker.role else [worker.role])
        for role in roles:
            assignments["roles"][role].add(worker.job)
        if worker.persona:
            assignments["personas"][worker.persona].add(worker.job)
    for role in sorted(REVIEW_DISPATCHED):
        assignments["roles"][role].add("job_inference_security_review")
    for role in sorted(WORKBENCH_DISPATCHED):
        assignments["roles"][role].add("job_owasp_control_assessment")
    for name in registry["personas"]:
        # These are routing candidates, never a claim that every task selects every persona.
        if "path" in registry["personas"][name]:
            assignments["personas"][name].add("job_inference_security_review")
    for name in registry["assignment"]["domain_persona"].values():
        assignments["personas"][name].add("job_owasp_control_assessment")
    for name in registry["stacks"]:
        assignments["stacks"][name].add("job_inference_security_review")
    for name, record in registry["runtime_skills"].items():
        assignments["runtime_skills"][name].update(record["jobs"])
    return plain(assignments)


def source_identifiers(root: Path) -> tuple[set[str], set[str]]:
    result, named_fields = set(), set()
    pattern = re.compile(r"""["']((?:appsec-review/)?[a-z][a-z0-9_/-]*/[1-9]\d*)(?:\+)?["']""")
    tracked = subprocess.run(
        ["git", "ls-files", "-z", "--", "src", "containers", "deploy", "scripts", "tools",
         "docs/schemas", "docs/docs-ledger.json", "docs/docs-sync.json"],
        cwd=root, capture_output=True, text=True, check=True, timeout=5,
    ).stdout.split("\0")
    paths = sorted(set(tracked) | {
        "scripts/documentation.py", "tests/acceptance_review_stages.py",
    })
    for relative in paths:
        path = root / relative
        if not relative or path.suffix not in {".py", ".json", ".ps1", ".sh", ".toml"}:
            continue
        text = path.read_text(encoding="utf-8")
        result.update(pattern.findall(text))
        if path.suffix == ".py":
            named_fields.update(re.findall(r"\bdef (job_[a-z0-9_]+)\(", text))
            named_fields.update(re.findall(r"""["'](job_[a-z0-9_]+)["']\s*:""", text))
            named_fields.update(re.findall(r"\b(job_[a-z0-9_]+)\s*:\s*(?:str|int|Mapping)\b", text))
    result.update(value.removeprefix("appsec-review/") for value in tuple(result))
    return result, named_fields


def source_hashes(root: Path) -> dict[str, str]:
    paths = set(SOURCES)
    paths.update(path.relative_to(root).as_posix()
                 for path in (root / "src/appsec_review").rglob("*.py"))
    paths.add("tests/acceptance_review_stages.py")
    if (root / "docs/intelligence-buckets.json").exists():
        paths.add("docs/intelligence-buckets.json")
    return {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in sorted(paths)}


def build_inventory(root: Path = ROOT) -> dict:
    from appsec_review.guidance import load_registry
    from appsec_review.guidance.workers import SPECIALIZED_WORKERS
    from appsec_review.interchange import GapCode
    from appsec_review.mcp.schema import TOOLS
    from appsec_review.orchestration.dagster.adapter import _pool_for
    from appsec_review.orchestration.topology import wave1_dependencies
    from appsec_review.runtime.registry import builtin_registry
    from appsec_review.runtime.selection import job_is_enabled
    from appsec_review.review.lead_families import FAMILY_RULES
    from appsec_review.jobs.job_threat_model_generation.job import DEPLOYMENT_INPUT, DEPLOYMENT_GAP

    root = root.resolve()
    before = source_hashes(root)
    config, raw = recipe_config(root)
    registry = builtin_registry()
    registry.require_matches(config.jobs, surface="documentation")
    catalog = tomllib.loads((root / "containers/catalog.toml").read_text(encoding="utf-8"))
    guidance = load_registry(root)
    test_map = json.loads((root / "tests/job-test-map.json").read_text(encoding="utf-8"))
    if set(test_map["jobs"]) != set(registry.job_ids()):
        raise ValueError("documentation job/test-map membership differs from the registry")
    all_edges = wave1_dependencies(set(registry.job_ids()))
    if all_edges is None:
        raise ValueError("documentation cannot project the review topology")
    enabled = {job for job in registry.job_ids() if job_is_enabled(config, job)}
    active_edges = wave1_dependencies(enabled)
    tools = {tool["name"]: tool for tool in TOOLS}
    images = {image["id"]: image for image in catalog["images"]}
    jobs = {}
    schemas, named_fields = source_identifiers(root)
    dataset_ids, task_ids = set(), set()
    route_indexes = {name: set() for name in tools}
    for job_id in sorted(config.jobs):
        job = registry.build(job_id)
        configured = config.job(job_id)
        if job.contract is None:
            raise ValueError(f"documentation requires a typed contract: {job_id}")
        units = {unit.unit_id: unit for unit in job.units}
        datasets = []
        for declaration in job.datasets:
            record = plain(declaration)
            route = declaration.query_route or ""
            mcp = [name for name in sorted(tools) if re.search(rf"\b{re.escape(name)}\b", route)]
            record["mcp_tools"] = mcp
            record["route_gap"] = None if mcp else GAP_ID
            datasets.append(record)
            dataset_ids.add(declaration.output_kind)
            schemas.add(declaration.schema)
            for name in mcp:
                route_indexes[name].update(declaration.indexes)
        steps = {}
        for step_id, step in sorted(configured.steps.items()):
            tasks = {}
            for task_id, task in sorted(step.tasks.items()):
                unit_id = f"{step_id}.{task_id}"
                task_ids.add(unit_id)
                if unit_id in units:
                    binding = task_binding(units[unit_id], root)
                    dependencies = list(units[unit_id].dependencies)
                else:
                    binding = {
                        "handler": None, "source": None, "line": None, "tools": [], "internal_tools": [],
                        "tool_binding": "not_declared", "tool_gap": GAP_ID,
                        "guidance_binding": "not_declared", "guidance_gap": GAP_ID,
                    }
                    dependencies = []
                unknown = set(binding["tools"]) - images.keys()
                if unknown:
                    raise ValueError(f"task binds unknown catalog tools: {job_id}/{unit_id}: {unknown}")
                tasks[task_id] = {
                    "id": unit_id, "workers": task.workers, "settings": plain(task.settings),
                    "dependencies": dependencies, "pool": _pool_for(unit_id, job_id), **binding,
                }
            steps[step_id] = {
                "workers": step.workers, "settings": plain(step.settings), "tasks": tasks,
            }
        source_settings = raw["jobs"][job_id].get("settings", {})
        model_configuration = {
            key: value for key, value in source_settings.items()
            if key in {"model", "models", "roles", "budgets", "teams", "retry", "triage"}
        }
        workers = {key: plain(worker) for key, worker in sorted(SPECIALIZED_WORKERS.items())
                   if worker.job == job_id}
        jobs[job_id] = {
            "name": configured.name,
            "description": raw["jobs"][job_id].get("description"),
            "enabled": job_is_enabled(config, job_id),
            "workers": configured.workers,
            "schedule": plain(configured.schedule),
            "settings": source_settings,
            "steps": steps,
            "contract": job.contract.document(),
            "datasets": sorted(datasets, key=lambda row: row["output_kind"]),
            "strict_gaps": job.strict_gaps,
            "model_configuration": model_configuration,
            "specialized_workers": workers,
            "guidance_gap": GAP_ID,
            "tests": test_map["jobs"][job_id],
            "page": f"docs/operations/{job_id}.md",
            "dagster": {
                "dispatch": job.contract.dispatch.value,
                "review_graph_member": job_id in all_edges,
                "enabled_review_graph_member": job_id in (active_edges or {}),
                "declared_after": list(all_edges.get(job_id, ())),
                "enabled_after": list((active_edges or {}).get(job_id, ())),
            },
        }
        schemas.update(item.schema for item in job.contract.inputs)
    schemas.update(FAMILY_RULES.values())
    schemas.update(value.removeprefix("appsec-review/") for value in tuple(schemas))
    unregistered_inputs = {}
    if DEPLOYMENT_INPUT[0] not in jobs:
        unregistered_inputs[DEPLOYMENT_INPUT[0]] = {
            "output_kind": DEPLOYMENT_INPUT[1], "gap": DEPLOYMENT_GAP,
            "source": "src/appsec_review/jobs/job_threat_model_generation/job.py",
            "status": "not_registered",
        }
    result = {
        "schema": "appsec-review/docs-inventory/1",
        "generated_from": notice(),
        "configuration_scope": "Checked-in dev recipe only; no overlay, host pins, targets, run artifacts or tool execution.",
        "binding_limit": f"{GAP_ID}: undeclared task bindings are unknown, not proof that no tool or model runs.",
        "jobs": jobs,
        "job_order": list(test_map["jobs"]),
        "images": dict(sorted(images.items())),
        "mcp_tools": {name: {**tool, "declared_dataset_indexes": sorted(route_indexes[name])}
                      for name, tool in sorted(tools.items())},
        "guidance": guidance,
        "guidance_assignments": guidance_assignments(guidance),
        "lead_family_rules": dict(sorted(FAMILY_RULES.items())),
        "unregistered_inputs": unregistered_inputs,
        "dagster": plain(config.dagster),
        "identifiers": {
            "jobs": sorted(jobs), "tasks": sorted(task_ids), "datasets": sorted(dataset_ids),
            "schemas": sorted(schemas), "gaps": sorted(code.value for code in GapCode),
            "fields_and_functions": sorted(named_fields - jobs.keys()),
        },
        "source_hashes": before,
    }
    bucket_path = root / "docs/intelligence-buckets.json"
    if bucket_path.exists():
        result["intelligence_buckets"] = json.loads(bucket_path.read_text(encoding="utf-8"))
    if source_hashes(root) != before:
        raise RuntimeError("documentation sources changed during generation; retry at a stable boundary")
    return result


def metadata(title: str, kind: str, subsystem: str, commit: str, jobs=()) -> dict:
    return {"title": title, "kind": kind, "subsystem": subsystem, "status": "current",
            "jobs": sorted(jobs), "last reconciled": commit}


def table(headers: tuple[str, ...], rows) -> str:
    def cell(value):
        return str(value).replace("|", r"\|").replace("\n", " ")
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines.extend("| " + " | ".join(cell(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def code(value: str) -> str:
    return f"`{value}`"


def render_job(job_id: str, job: dict) -> str:
    lines = [
        f"<!-- generated:begin job={job_id} -->",
        f"<!-- {notice()} -->",
        "## Declared job contract",
        "",
        job["description"] or job["name"],
        "",
        f"Job: `{job_id}`. Enabled in the dev recipe: **{str(job['enabled']).lower()}**.",
        "Declarations describe possible work, not successful execution or consumed evidence.",
        "",
        "### Steps and tasks",
        "",
        table(("Step", "Task", "Workers", "Pool", "Bound tool or gap", "Handler"), (
            (code(step_id), code(task["id"]), task["workers"], code(task["pool"]),
             ", ".join(map(code, task["tools"])) or
             ("Internal: " + ", ".join(map(code, task["internal_tools"])) if task["internal_tools"]
              else f"Undeclared ([{GAP_ID}](../TODO.md))"),
             f"[source](../../{task['source']}#L{task['line']})" if task["source"] else
             f"Not registered as a unit ([{GAP_ID}](../TODO.md))")
            for step_id, step in job["steps"].items() for task in step["tasks"].values()
        )),
        "",
        "### Accepted input declarations",
        "",
        table(("Producer", "Dataset", "Schema", "Channel", "Availability", "Missing policy"), (
            (code(row["producer"]), code(row["output_kind"]), code(row["schema"]),
             row["channel"], row["availability"], row["missing"])
            for row in job["contract"]["inputs"]
        )),
        "",
        "### Published dataset declarations",
        "",
        table(("Dataset", "Step", "Schema", "Stage", "Indexes", "MCP route"), (
            (code(row["output_kind"]), code(row["step"]), code(row["schema"]), row["disposition"],
             ", ".join(map(code, row["indexes"])) or "Not indexed",
             ", ".join(map(code, row["mcp_tools"])) or f"Undeclared ([{GAP_ID}](../TODO.md))")
            for row in job["datasets"]
        )),
        "",
        "Protected and artifact-only routes expose sanitized metadata, not payload access.",
        "",
        "### Model and guidance declarations",
        "",
    ]
    if job["model_configuration"] or job["specialized_workers"]:
        lines += [
            f"These are job-level declarations; exact per-task selection is not declared ([{GAP_ID}](../TODO.md)).",
            "",
            "```json", json.dumps(job["model_configuration"], indent=2, sort_keys=True), "```", "",
        ]
        for worker in job["specialized_workers"].values():
            role = worker["role"]
            if "{family}" in role:
                lines.append(f"- Role template: `{role}`; family selected by the accepted build.")
            else:
                lines.append(f"- Role: [{role}](../generated/guidance.md#roles-{slug(role)}).")
            if worker["persona"]:
                persona = worker["persona"]
                lines.append(f"- Persona: [{persona}](../generated/guidance.md#personas-{slug(persona)}).")
            lines.append(f"- Task prompt: `{worker['task']}`.")
            if worker["skill"]:
                skill = worker["skill"]
                lines.append(f"- Runtime skill: [{skill}](../generated/guidance.md#runtime_skills-{slug(skill)}).")
    else:
        lines.append(f"No job-level model declaration; absence of a task binding remains [{GAP_ID}](../TODO.md), not a nonexecution claim.")
    lines += [
        "", "### Test selection", "",
        table(("Tier", "Files or selectors"),
              ((tier, "<br>".join(map(code, selectors)) or "None declared")
               for tier, selectors in sorted(job["tests"].items()))),
        "", "### Dagster placement", "",
        f"Dispatch: `{job['dagster']['dispatch']}`. "
        f"Review graph member: **{str(job['dagster']['review_graph_member']).lower()}**. "
        f"Enabled graph member: **{str(job['dagster']['enabled_review_graph_member']).lower()}**.",
        "",
        "Declared predecessors: " + (", ".join(map(code, job["dagster"]["declared_after"])) or "None") + ".",
        "", "### Declared dataflow", "", "```mermaid", "flowchart LR",
        f'  job["{job_id}"]',
    ]
    for index, row in enumerate(job["contract"]["inputs"]):
        lines += [
            f'  producer{index}["{row["producer"]}"]',
            f'  input{index}["{row["output_kind"]}"]',
            f'  input_schema{index}["{row["schema"]}"]',
            f"  producer{index} --> input{index} --> job",
            f"  input{index} -. schema .-> input_schema{index}",
        ]
    for index, row in enumerate(job["datasets"]):
        lines += [
            f'  output{index}["{row["output_kind"]}"]',
            f'  output_schema{index}["{row["schema"]}"]',
            f"  job --> output{index}",
            f"  output{index} -. schema .-> output_schema{index}",
        ]
    lines += ["```", "", "<!-- generated:end -->"]
    return "\n".join(lines)


def authored_documents(root: Path) -> dict[str, str]:
    ledger = json.loads((root / LEDGER).read_text(encoding="utf-8"))
    return {row["path"]: (root / row["path"]).read_text(encoding="utf-8")
            for row in ledger["documents"] if row["path"].endswith(".md")
            and row["disposition"] != "generated"}


def render(root: Path, inventory: dict) -> dict[str, str]:
    import posixpath

    commit = json.loads((root / "docs/docs-sync.json").read_text(encoding="utf-8"))["synced_commit"]
    body = json.dumps({key: value for key, value in inventory.items() if key != "generated_from"},
                      indent=2, sort_keys=True)
    files = {INVENTORY: '{ "generated_from": ' + json.dumps(inventory["generated_from"]) + ",\n"
             + body[2:] + "\n"}
    documents = authored_documents(root)
    assignments = inventory["guidance_assignments"]
    lines = [f"<!-- {notice()} -->", "# Model guidance registry", "",
             "Assignments below are allowed or routed job candidates, not evidence that a task selected them.",
             f"Undeclared per-task selections remain [{GAP_ID}](../TODO.md).", ""]
    for kind in ("roles", "personas", "stacks", "runtime_skills"):
        for name, record in sorted(inventory["guidance"][kind].items()):
            lines += [
                f"## {kind} {name}", "",
                "Jobs: " + (", ".join(map(code, assignments[kind][name])) or "No dispatched job declaration") + ".",
                "", "```json", json.dumps(record, indent=2, sort_keys=True), "```", "",
            ]
    files[GUIDANCE] = with_frontmatter(
        metadata("Model guidance registry", "generated", "review inference and guidance", commit),
        "\n".join(lines),
    )
    for job_id, job in inventory["jobs"].items():
        path = job["page"]
        if (root / path).exists():
            original = (root / path).read_text(encoding="utf-8")
            matches = list(BLOCK.finditer(original))
            if len(matches) != 1 or matches[0][1] != job_id:
                raise ValueError(f"expected exactly one generated block for {job_id}: {path}")
            files[path] = BLOCK.sub(lambda _: render_job(job_id, job), original)
        else:
            files[path] = with_frontmatter(
                metadata(job["name"], "operations", "runtime interchange", commit, [job_id]),
                f"\n# {job['name']}\n\n"
                "This page contains the generated contract; the authored process and acceptance "
                "description are tracked by [T-130](../TODO.md).\n\n"
                + render_job(job_id, job) + "\n",
            )
        documents[path] = files[path]
    documents[GUIDANCE] = files[GUIDANCE]
    for kind, path in INDEX_PATHS.items():
        documents[path] = with_frontmatter(
            metadata(f"{kind.title()} index", "generated", "testing and operations", commit), "")
    documents["docs/README.md"] = with_frontmatter(
        metadata("Documentation", "generated", "overview", commit), "")
    for kind, path in INDEX_PATHS.items():
        rows = []
        for candidate, text in sorted(documents.items()):
            values, _ = frontmatter(text)
            if values["kind"] == kind and candidate != path:
                relative = posixpath.relpath(candidate, posixpath.dirname(path))
                rows.append((f"[{values['title']}]({relative})", values["subsystem"], values["status"]))
        files[path] = with_frontmatter(
            metadata(f"{kind.title()} index", "generated", "testing and operations", commit),
            f"\n<!-- {notice(('document frontmatter',))} -->\n"
            f"# {kind.title()} index\n\n" + table(("Document", "Subsystem", "Status"), rows) + "\n",
        )
    root_lines = [
        f"<!-- {notice(('document frontmatter',))} -->", "# Documentation", "",
        "[How an appsec-review run works](overview.md)", "",
        "## Indexes", "",
        *(f"- [{kind.title()}]({path.removeprefix('docs/')})"
          for kind, path in sorted(INDEX_PATHS.items())),
        "", "## Generated contracts", "",
        "[Machine-readable inventory](generated/inventory.json) and "
        "[model guidance](generated/guidance.md).", "",
        "The inventory describes the checked-in dev recipe, not host bindings or a completed run.",
        f"Undeclared task bindings are named under [{GAP_ID}](TODO.md).", "",
    ]
    files["docs/README.md"] = with_frontmatter(
        metadata("Documentation", "generated", "overview", commit), "\n".join(root_lines),
    )
    return files


def generate(root: Path = ROOT, output_root: Path | None = None, *, check: bool = False) -> list[str]:
    output = output_root or root
    inventory = build_inventory(root)
    rendered = render(root, inventory)
    changed = []
    for path, text in sorted(rendered.items()):
        destination = output / path
        if not destination.exists() or destination.read_bytes() != text.encode("utf-8"):
            changed.append(path)
            if not check:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(text.encode("utf-8"))
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report drift without writing")
    parser.add_argument("--output-root", type=Path, help="write generated views to an isolated directory")
    args = parser.parse_args(argv)
    changed = generate(output_root=args.output_root, check=args.check)
    for path in changed:
        print(("out of date: " if args.check else "generated: ") + path)
    return 1 if args.check and changed else 0


if __name__ == "__main__":
    sys.exit(main())
