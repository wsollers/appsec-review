"""Per-language and per-build-unit producer coverage over accepted shards.

Each cell states what an accepted shard actually provides for one language or build unit and
lane. Compiled, symbol and CodeQL coverage is claimed only where a shard for that scope exists;
a Joern CPG binary is never graph coverage. The ``code_graph`` lane is computed only from accepted
``graph`` shards published by ``job_code_graph_index`` and their per-family coverage rows
(docs/architecture/code-graph-precomputation.md, section 7.4). A missing lane is ``unavailable``
with a reason; missing coverage is never evidence that a target is clean.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from appsec_review.graph.contract import GRAPH_INDEX, Coverage, Family
from appsec_review.indexing.store import ShardSet


LANES = ("source", "syntax", "compiled", "symbols", "cpg_graph", "codeql", "code_graph", "source_sast")
# The code-graph producer (C5). It may be unregistered; the lane then stays unavailable.
GRAPH_JOB = "job_code_graph_index"
GRAPH_UNAVAILABLE = ("no accepted graph shard for this language; code-graph facts come only from "
                     f"{GRAPH_JOB} over an accepted CodeQL export (code-graph-precomputation.md)")
_ALIASES = {
    "c": "c/c++", "c++": "c/c++", "cpp": "c/c++", "c/c++": "c/c++", "objective-c": "c/c++",
    "javascript": "javascript/typescript", "typescript": "javascript/typescript", "tsx": "javascript/typescript",
    "js": "javascript/typescript", "ts": "javascript/typescript", "java": "java/kotlin", "kotlin": "java/kotlin",
    "csharp": "csharp", "c#": "csharp", "python": "python", "go": "go", "rust": "rust", "php": "php",
    "ruby": "ruby", "swift": "swift", "shell": "shell", "bash": "shell",
}
CODEQL_EXTRACTORS = {"c/c++", "csharp", "go", "java/kotlin", "javascript/typescript", "python", "ruby", "swift",
                     "rust"}


def canonical_language(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    return _ALIASES.get(text, text or "unknown")


def _cell(state: str, basis: str, **values: Any) -> dict[str, Any]:
    return {"state": state, "basis": basis, **values}


def graph_shards(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    """Accepted ``graph`` shards of the code-graph job; empty while that job is absent."""
    return shards.select(index=GRAPH_INDEX, job=GRAPH_JOB)


def graph_cell(shards: ShardSet, selected: Sequence[Mapping[str, Any]], unavailable_basis: str) -> dict[str, Any]:
    """One ``code_graph`` cell from accepted graph shards and their coverage rows.

    A family is ``complete`` only when it has an accepted shard and every coverage row of its
    shards is complete, ``unavailable`` when it has no shard or only unavailable rows, and
    ``partial`` otherwise (a shard without a coverage row is partial). The lane is ``complete``
    only when every family is complete and ``unavailable`` when every family is unavailable.
    """
    selected = sorted(selected, key=lambda item: (str(item.get("name")), str(item.get("shard_id"))))
    rows: dict[str, list[str]] = defaultdict(list)
    for row in shards.coverage(selected):
        rows[row["shard_id"]].append(str(row["status"]))
    statuses: dict[str, list[str]] = {family.value: [] for family in Family}
    unknown: list[str] = []
    for shard in selected:
        shard_id = str(shard.get("shard_id", "default"))
        family = str(shard.get("producer", {}).get("family") or "")
        if family not in statuses:
            unknown.append(shard_id)
            continue
        statuses[family].extend(rows.get(shard_id) or [Coverage.PARTIAL.value])
    families: dict[str, str] = {}
    for family, values in statuses.items():
        if not values or all(value == Coverage.UNAVAILABLE.value for value in values):
            families[family] = Coverage.UNAVAILABLE.value
        elif all(value == Coverage.COMPLETE.value for value in values):
            families[family] = Coverage.COMPLETE.value
        else:
            families[family] = Coverage.PARTIAL.value
    states = set(families.values())
    if states == {Coverage.COMPLETE.value} and not unknown:
        state, basis = Coverage.COMPLETE.value, "accepted graph shards with complete coverage for every fact family"
    elif states == {Coverage.UNAVAILABLE.value}:
        state = Coverage.UNAVAILABLE.value
        basis = unavailable_basis if not selected else \
            "accepted graph shards report every fact family unavailable (no database, failed export or no export pack)"
    else:
        state = Coverage.PARTIAL.value
        missing = sorted(name for name, value in families.items() if value != Coverage.COMPLETE.value)
        basis = "accepted graph shards; incomplete families: " + ", ".join(missing) if missing else \
            "accepted graph shards include shards without a recognised fact family"
    return _cell(state, basis, families=families, shards=[str(item.get("shard_id")) for item in selected][:20],
                 unrecognised_shards=unknown[:20])


def language_matrix(shards: ShardSet, lead_languages: Mapping[str, int]) -> list[dict[str, Any]]:
    """One row per catalogued language with a cell per lane."""
    source_counts: dict[str, int] = defaultdict(int)
    for row in shards.entities(shards.select(index="source", job="job_target_catalog"), kinds=("source_file",)):
        source_counts[canonical_language(row["payload"].get("language"))] += 1
    syntax: dict[str, list[str]] = defaultdict(list)
    for shard in shards.select(index="analysis", job="job_tree_sitter_ast"):
        shard_id = str(shard.get("shard_id"))
        if shard_id.startswith("tree-sitter-coverage-"):
            continue
        syntax[canonical_language(shard.get("producer", {}).get("language") or shard_id.split("-")[0])].append(shard_id)
    syntax_states = {}
    for row in shards.coverage(shards.select(index="analysis", job="job_tree_sitter_ast", prefix="tree-sitter-coverage-")):
        syntax_states[str(row["area"])] = row["status"]
    compiled = [str(item.get("shard_id")) for item in shards.select(job="job_cpp_compiled_analysis")]
    symbols = [str(item.get("shard_id")) for item in shards.select(index="analysis", job="job_cpp_symbol_index")]
    cpg = [str(item.get("shard_id")) for item in shards.select(job="job_cpg_analysis")]
    codeql: dict[str, list[str]] = defaultdict(list)
    for shard in shards.select(index="observations", job="job_codeql_analysis"):
        codeql[canonical_language(shard.get("producer", {}).get("language"))].append(str(shard.get("shard_id")))
    graph: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for shard in graph_shards(shards):
        graph[canonical_language(shard.get("producer", {}).get("language"))].append(shard)
    rows = []
    for language in sorted(set(source_counts) | set(syntax) | set(codeql) | set(graph)):
        native = language == "c/c++"
        scope_states = [state for scope, state in syntax_states.items() if canonical_language(scope.split("-")[0]) == language]
        rows.append({
            "cell_type": "language", "language": language, "source_files": source_counts.get(language, 0),
            "lanes": {
                "source": _cell("complete" if source_counts.get(language) else "unavailable",
                                "accepted catalog source_file entities", count=source_counts.get(language, 0)),
                "syntax": _cell(("partial" if any(state != "complete" for state in scope_states) else "complete")
                                if syntax.get(language) else "unavailable",
                                "accepted Tree-sitter shards" if syntax.get(language) else
                                "no accepted Tree-sitter shard for this language (grammar unsupported or scope failed)",
                                shards=sorted(syntax.get(language, ()))[:20]),
                "compiled": _cell("partial" if native and compiled else "unavailable",
                                  "partial Clang AST and LLVM direct-call extraction" if native and compiled else
                                  "no compiled-analysis branch for this language" if not native else
                                  "no accepted C/C++ compiled-analysis shard", shards=sorted(compiled)[:20] if native else []),
                "symbols": _cell("partial" if native and symbols else "unavailable",
                                 "accepted clangd symbol shards" if native and symbols else
                                 "no typed symbol producer for this language" if not native else
                                 "no accepted clangd shard", shards=sorted(symbols)[:20] if native else []),
                "cpg_graph": _cell("unavailable", "Joern CPG is retained as a binary artifact only; Joern is not a "
                                   "graph producer (code-graph-precomputation.md)" if native and cpg else
                                   "no Joern CPG for this language",
                                   artifact_shards=sorted(cpg)[:20] if native else []),
                "codeql": _cell("complete" if codeql.get(language) else "unavailable",
                                "accepted CodeQL observation shards" if codeql.get(language) else
                                "no CodeQL extractor configured for this language" if language not in CODEQL_EXTRACTORS
                                else "no accepted CodeQL shard for this language", shards=sorted(codeql.get(language, ()))[:20]),
                "code_graph": graph_cell(
                    shards, graph.get(language, ()),
                    "no CodeQL extractor configured for this language, so no graph export exists"
                    if language not in CODEQL_EXTRACTORS else GRAPH_UNAVAILABLE),
                "source_sast": _cell("complete" if lead_languages.get(language) else "unavailable",
                                     "accepted source-SAST leads" if lead_languages.get(language) else
                                     "no accepted source-SAST lead names this language (scanner absent, skipped or "
                                     "reported nothing); not evidence of a clean target",
                                     leads=lead_languages.get(language, 0)),
            }})
    return rows


def build_unit_matrix(shards: ShardSet) -> list[dict[str, Any]]:
    """One row per accepted build unit with build, artifact, compiled and CodeQL lanes."""
    units: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for row in shards.entities(shards.select(index="build", job="job_target_catalog"), kinds=("build_action", "project")):
        unit = row["payload"].get("build_unit_id")
        if unit:
            units[str(unit)]["catalog"].append(row["identity"])
    for row in shards.entities(shards.select(index="build", job="job_language_build"), kinds=("build_action",)):
        units[str(row["payload"].get("build_unit_id") or row["native_id"].split(":")[0] or "unassigned")]["build_actions"].append(
            row["identity"])
    for row in shards.entities(shards.select(index="artifacts")):
        unit = row["payload"].get("build_unit_id")
        if unit:
            units[str(unit)]["artifacts"].append(row["identity"])
    for shard in shards.select(job="job_cpp_compiled_analysis"):
        scope = shard.get("producer", {}).get("scope_id") or shard.get("shard_id")
        units[str(scope)]["compiled"].append(str(shard.get("shard_id")))
    for shard in shards.select(index="observations", job="job_codeql_analysis"):
        unit = shard.get("producer", {}).get("build_unit_id") or shard.get("producer", {}).get("scope_id")
        if unit:
            units[str(unit)]["codeql"].append(str(shard.get("shard_id")))
    graph: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for shard in graph_shards(shards):
        producer = shard.get("producer", {})
        unit = producer.get("build_unit_id") or producer.get("scope_id")
        if unit:
            graph[str(unit)].append(shard)
            units[str(unit)]  # a unit known only from graph shards still gets a row
    rows = []
    for unit, lanes in sorted(units.items()):
        cells = {name: _cell("complete" if lanes.get(name) else "unavailable",
                             f"accepted {name} entities or shards" if lanes.get(name) else
                             f"no accepted {name} for this unit", count=len(lanes.get(name, ())))
                 for name in ("catalog", "build_actions", "artifacts", "compiled", "codeql")}
        cells["code_graph"] = graph_cell(shards, graph.get(unit, ()),
                                         "no accepted graph shard for this unit; " + GRAPH_UNAVAILABLE.split("; ", 1)[1])
        rows.append({"cell_type": "build_unit", "build_unit_id": unit, "lanes": cells})
    return rows


def producer_consumer_matrix(jobs: Sequence[Mapping[str, Any]], consumes: Mapping[str, Sequence[str]]) -> list[dict[str, Any]]:
    status = {str(item["job_id"]): item.get("status") for item in jobs}
    return [{"cell_type": "producer_consumer", "consumer": consumer, "producer": producer,
             "consumer_status": status.get(consumer), "producer_status": status.get(producer),
             "state": "complete" if status.get(producer) == "accepted" else "unavailable"}
            for consumer, producers in sorted(consumes.items()) for producer in producers]
