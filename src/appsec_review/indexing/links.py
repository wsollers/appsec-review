"""Typed cross-domain links over accepted shards.

A link is exact only when both sides carry the same resolved identity: an equal content hash with
the same logical path or build unit, an equal byte span in the same hashed file, or an identifier
the producer itself published. Name-only, line-only and hash-only joins are published separately
as explicitly ambiguous relations carrying their mapping method and confidence. Nothing here reads
target files, raw scanner output, IR or a CPG.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from appsec_review.indexing.derive import Derived
from appsec_review.indexing.store import ShardSet
from appsec_review.retrieval.model import EntityKind, EntityRecord, LogicalIdentity, RelationKind


CATALOG = "job_target_catalog"
TREE_SITTER = "job_tree_sitter_ast"
ARTIFACT_KINDS = ("object_file", "library", "executable", "build_artifact", "package", "bytecode_module",
                  "managed_assembly", "wasm_module", "evidence_artifact")
REDACTED = "<redacted>"


@dataclass(frozen=True, slots=True)
class LinkContext:
    snapshot: str
    shards: ShardSet
    max_links: int


@dataclass(frozen=True, slots=True)
class LinkRule:
    family: str
    version: str
    description: str
    select: Callable[[ShardSet], tuple[Mapping[str, Any], ...]]
    build: Callable[[LinkContext, tuple[Mapping[str, Any], ...]], Derived]


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value and value != REDACTED else None


def catalog_sources(context: LinkContext) -> tuple[dict[tuple[str, str], str], dict[str, str]]:
    """Return ((path, sha256) -> identity, path -> sha256) for accepted catalog source files."""
    exact: dict[tuple[str, str], str] = {}
    by_path: dict[str, str] = {}
    for row in context.shards.entities(context.shards.select(index="source", job=CATALOG), kinds=("source_file",)):
        location = row["location"]
        if location is None:
            continue
        exact[(location["path"], location["file_sha256"])] = row["identity"]
        by_path[location["path"]] = location["file_sha256"]
    return exact, by_path


def _bounded(derived: Derived, context: LinkContext) -> bool:
    if len(derived.relations) >= context.max_links:
        derived.gap(f"link bound of {context.max_links} relations reached; remaining candidates were not linked")
        return False
    return True


# --- source, build and artifact representations ------------------------------------------------------

def _select_representation(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return (*shards.select(index="source", job=CATALOG), *shards.select(index="build"),
            *shards.select(index="artifacts", prefix="catalog-"), *shards.select(index="build_security"))


def _case_of(shard_id: str, prefix: str, suffix: str = "") -> str:
    value = shard_id[len(prefix):]
    return value[:-len(suffix)] if suffix and value.endswith(suffix) else value


def _build_representation(context: LinkContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    derived = Derived()
    shards = ShardSet(context.shards.run_root, selected)
    sources, source_paths = catalog_sources(context)
    canonical: dict[tuple[str, str, str], str] = {}
    by_content: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in shards.entities(shards.select(index="artifacts", prefix="catalog-"), kinds=ARTIFACT_KINDS):
        payload = row["payload"]
        unit, path, sha = _text(payload.get("build_unit_id")), _text(payload.get("workspace_path")), \
            _text(payload.get("sha256"))
        if unit and sha:
            by_content[(unit, sha)].append(row["identity"])
            if path:
                canonical[(unit, path, sha)] = row["identity"]
    if not canonical and not by_content:
        derived.gap("artifact catalog shards are unavailable; no artifact representation was linked")
    stale = unmapped_sources = ambiguous_artifacts = unmatched_artifacts = 0
    for row in shards.entities(shards.select(index="build")):
        if not _bounded(derived, context):
            break
        payload, shard_id, kind = row["payload"], row["shard_id"], row["kind"]
        if row["job"] == "job_cpp_compiled_analysis" and kind == "source_file":
            path, sha = row["native_id"], _text(payload.get("sha256"))
            target = sources.get((path, sha or ""))
            if target is not None and target != row["identity"]:
                derived.relate(RelationKind.SAME_AS, row["identity"], target, exact=True, confidence=1.0,
                               method="target-path+sha256")
            elif path in source_paths:
                stale += 1
            else:
                unmapped_sources += 1
            continue
        if kind not in ARTIFACT_KINDS:
            continue
        sha = _text(payload.get("sha256"))
        if row["job"] == "job_language_build":
            unit, path = _text(payload.get("build_unit_id")), _text(payload.get("workspace_path"))
            target = canonical.get((unit or "", path or "", sha or ""))
            if target is not None:
                derived.relate(RelationKind.SAME_AS, row["identity"], target, exact=True, confidence=1.0,
                               method="build-unit+workspace-path+sha256")
            else:
                unmatched_artifacts += 1
        elif row["job"] == "job_cpp_compiled_analysis":
            case = _case_of(shard_id, "cpp-", "-compiled")
            candidates = sorted(set(by_content.get((case, sha or ""), ())))
            if len(candidates) == 1:
                derived.relate(RelationKind.SAME_AS, row["identity"], candidates[0], exact=True, confidence=1.0,
                               method="build-unit+sha256")
            elif candidates:
                ambiguous_artifacts += 1
                for candidate in candidates:
                    derived.relate(RelationKind.SAME_AS, row["identity"], candidate, exact=False, confidence=0.5,
                                   method="sha256-only",
                                   ambiguity=f"{len(candidates)} catalogued artifacts share this content hash")
            else:
                unmatched_artifacts += 1
    for row in shards.entities(shards.select(index="build_security"), kinds=ARTIFACT_KINDS):
        if not _bounded(derived, context):
            break
        case, sha = _case_of(row["shard_id"], "build-security-"), _text(row["payload"].get("sha256"))
        candidates = sorted(set(by_content.get((case, sha or ""), ())))
        if len(candidates) == 1:
            derived.relate(RelationKind.SAME_AS, row["identity"], candidates[0], exact=True, confidence=1.0,
                           method="build-unit+sha256")
        elif candidates:
            ambiguous_artifacts += 1
            for candidate in candidates:
                derived.relate(RelationKind.SAME_AS, row["identity"], candidate, exact=False, confidence=0.5,
                               method="sha256-only",
                               ambiguity=f"{len(candidates)} catalogued artifacts share this content hash")
    if stale:
        derived.gap(f"stale_source_hash: {stale} compiled source file(s) differ from the accepted catalog hash")
    if unmapped_sources:
        derived.gap(f"missing_source_map: {unmapped_sources} compiled source file(s) are outside the accepted catalog")
    if ambiguous_artifacts:
        derived.gap(f"conflicting_artifact_mapping: {ambiguous_artifacts} artifact(s) matched several catalogued "
                    "artifacts by content hash only")
    if unmatched_artifacts:
        derived.gap(f"{unmatched_artifacts} build artifact representation(s) have no catalogued artifact identity")
    derived.gap("source-to-build-action mapping is unavailable outside C/C++ compile databases: captured "
                "file-access inventories are protected and not normalized")
    derived.coverage.append(("representation-links", "partial",
                             "; ".join(derived.gaps[:5])))
    return derived


# --- finding to source ---------------------------------------------------------------------------------

def _select_findings(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return (*shards.select(index="source", job=CATALOG), *shards.select(index="observations"),
            *shards.select(index="evidence"))


def _build_findings(context: LinkContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    derived = Derived()
    shards = ShardSet(context.shards.run_root, selected)
    sources, source_paths = catalog_sources(context)
    observation_shards = (*shards.select(index="observations"), *shards.select(index="evidence"))
    already = {(row["source_id"], row["target_id"])
               for row in shards.relations(observation_shards, kinds=(RelationKind.OBSERVED_AT.value,))}
    ci_observations: dict[str, str] = {}
    findings: list[dict[str, Any]] = []
    stale = unmapped = 0
    for row in shards.entities(observation_shards, kinds=("tool_observation", "finding_package")):
        if row["shard_id"].startswith("ci_"):
            if row["kind"] == "tool_observation":
                ci_observations[row["native_id"]] = row["identity"]
            else:
                findings.append(row)
        location = row["location"]
        if location is None or not _bounded(derived, context):
            continue
        target = sources.get((location["path"], location["file_sha256"]))
        if target is None:
            if location["path"] in source_paths:
                stale += 1
            else:
                unmapped += 1
            continue
        if (row["identity"], target) in already:
            derived.count("already_linked")
            continue
        exact = not bool(location["ambiguous"]) and float(location["confidence"]) >= 1.0
        derived.relate(RelationKind.OBSERVED_AT, row["identity"], target, exact=exact,
                       confidence=float(location["confidence"]), method="location-path+sha256",
                       ambiguity=f"producer location mapped by {location['mapping_method']}",
                       producer_mapping=location["mapping_method"])
    for row in findings:
        for native in row["payload"].get("observation_ids") or ():
            observation = ci_observations.get(str(native))
            if observation is not None and _bounded(derived, context):
                derived.relate(RelationKind.SUPPORTS, observation, row["identity"], exact=True, confidence=1.0,
                               method="producer-observation-id")
    if stale:
        derived.gap(f"stale_source_hash: {stale} observation location(s) name a file whose hash differs from the "
                    "accepted catalog")
    if unmapped:
        derived.gap(f"missing_source_map: {unmapped} observation location(s) are outside the accepted catalog")
    if not observation_shards:
        derived.coverage.append(("finding-source-links", "unavailable", "no accepted observation shards"))
    else:
        derived.coverage.append(("finding-source-links", "partial" if derived.gaps else "complete",
                                 "; ".join(derived.gaps[:5]) or None))
    return derived


# --- package to advisory -------------------------------------------------------------------------------

def package_identity(snapshot: str, name: str, version: str | None, purl: str | None) -> LogicalIdentity:
    return LogicalIdentity.derive(EntityKind.DEPENDENCY_PACKAGE, snapshot,
                                  {"name": name, "version": version, "purl": purl})


def advisory_identity(snapshot: str, advisory: str) -> LogicalIdentity:
    return LogicalIdentity.derive(EntityKind.ADVISORY, snapshot, {"advisory": advisory})


def advisory_pairs(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Extract bounded package/advisory pairs a scanner observation itself reported."""
    payload = row["payload"]
    pairs: list[dict[str, Any]] = []
    package, advisory = _text(payload.get("package")), _text(payload.get("advisory"))
    if package and advisory:
        pairs.append({"package": package, "version": None, "purl": None, "advisory": advisory,
                      "severity": _text(payload.get("severity")), "scanner": _text(payload.get("tool_id"))})
    observation = payload.get("observation")
    matches = observation.get("matches") if isinstance(observation, Mapping) else None
    for match in matches if isinstance(matches, list) else ():
        if not isinstance(match, Mapping):
            continue
        vulnerability, artifact = match.get("vulnerability"), match.get("artifact")
        if not isinstance(vulnerability, Mapping) or not isinstance(artifact, Mapping):
            continue
        name, identifier = _text(artifact.get("name")), _text(vulnerability.get("id"))
        if name and identifier:
            pairs.append({"package": name, "version": _text(artifact.get("version")),
                          "purl": _text(artifact.get("purl")), "advisory": identifier,
                          "severity": _text(vulnerability.get("severity")),
                          "scanner": _text(payload.get("scanner_identity")) or _text(payload.get("capability"))})
    return pairs


def _select_advisories(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return (*shards.select(index="observations", job="job_evidence_collection"),
            *shards.select(index="observations", job="job_artifact_security_analysis"))


def _build_advisories(context: LinkContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    derived = Derived()
    shards = ShardSet(context.shards.run_root, selected)
    for row in shards.entities(selected, kinds=("tool_observation",)):
        for pair in advisory_pairs(row):
            if not _bounded(derived, context):
                break
            versioned = bool(pair["version"] or pair["purl"])
            package = package_identity(context.snapshot, pair["package"], pair["version"], pair["purl"])
            advisory = advisory_identity(context.snapshot, pair["advisory"])
            derived.entities.append(EntityRecord(
                package, pair["purl"] or pair["package"], pair["package"],
                f"dependency package {pair['package']} {pair['version'] or 'version unknown'}",
                {"package_name": pair["package"], "version": pair["version"], "purl": pair["purl"],
                 "identity_basis": "purl-or-version" if versioned else "name-only"}))
            derived.entities.append(EntityRecord(
                advisory, pair["advisory"], pair["advisory"], f"advisory {pair['advisory']}",
                {"advisory_id": pair["advisory"]}))
            derived.relate(RelationKind.AFFECTED_BY, package.value, advisory.value, exact=versioned,
                           confidence=1.0 if versioned else 0.6, method="scanner-reported-match",
                           ambiguity="scanner reported a package name without a version, ecosystem or purl",
                           severity=pair["severity"], scanner=pair["scanner"])
            derived.relate(RelationKind.DERIVED_FROM, package.value, row["identity"], exact=True, confidence=1.0,
                           method="scanner-observation")
            derived.relate(RelationKind.DERIVED_FROM, advisory.value, row["identity"], exact=True, confidence=1.0,
                           method="scanner-observation")
            derived.count("package_advisory_pairs")
            if not versioned:
                derived.count("name_only_pairs")
    if derived.counts.get("name_only_pairs"):
        derived.gap(f"uncertain_package_identity: {derived.counts['name_only_pairs']} match(es) carry a package "
                    "name without a version or purl")
    scanners = [shard for shard in selected if shard.get("shard_id") in {"osv_scanner", "grype", "syft",
                                                                           "artifact-security"}]
    if not scanners:
        derived.coverage.append(("package-advisory-links", "unavailable",
                                 "no accepted dependency scanner observation shards"))
    else:
        incomplete = [f"{row['shard_id']}: {row['gap']}" for row in shards.coverage(scanners)
                      if row["status"] != "complete" and row["gap"]]
        for text in incomplete[:10]:
            derived.gap(f"scanner coverage: {text[:240]}")
        derived.coverage.append(("package-advisory-links", "partial" if derived.gaps else "complete",
                                 "; ".join(derived.gaps[:5]) or None))
    return derived


# --- symbols and history to syntax ---------------------------------------------------------------------

def _syntax_shards(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return tuple(shard for shard in shards.select(index="analysis", job=TREE_SITTER)
                 if not str(shard.get("shard_id")).startswith("tree-sitter-coverage-"))


def syntax_nodes(shards: ShardSet, wanted_lines: set[tuple[str, int]],
                 wanted_spans: set[tuple[str, int, int]]) -> tuple[dict, dict]:
    """One bounded pass over accepted Tree-sitter nodes, keeping only requested lines and spans."""
    by_line: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    by_span: dict[tuple[str, int, int], list[dict[str, Any]]] = defaultdict(list)
    if not wanted_lines and not wanted_spans:
        return by_line, by_span
    for row in shards.entities(_syntax_shards(shards), kinds=("ast_node",)):
        location = row["location"]
        if location is None:
            continue
        node = {"identity": row["identity"], "type": row["name"], "named": bool(row["payload"].get("named")),
                "file_sha256": location["file_sha256"], **{key: location[key] for key in (
                    "start_byte", "end_byte", "start_line", "end_line", "start_column", "end_column")}}
        line_key = (location["path"], int(location["start_line"]))
        if line_key in wanted_lines and node["named"]:
            by_line[line_key].append(node)
        span_key = (location["path"], int(location["start_byte"]), int(location["end_byte"]))
        if span_key in wanted_spans:
            by_span[span_key].append(node)
    return by_line, by_span


def _select_symbols(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return (*shards.select(index="analysis", job=CATALOG),
            *shards.select(index="analysis", job="job_cpp_symbol_index", prefix="clangd-"), *_syntax_shards(shards))


def _build_symbols(context: LinkContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    derived = Derived()
    shards = ShardSet(context.shards.run_root, selected)
    symbol_shards = (*shards.select(index="analysis", job=CATALOG),
                     *shards.select(index="analysis", job="job_cpp_symbol_index", prefix="clangd-"))
    symbols = [row for row in shards.entities(symbol_shards, kinds=("symbol",), limit=context.max_links + 1)
               if row["location"] is not None]
    if len(symbols) > context.max_links:
        symbols = symbols[:context.max_links]
        derived.gap(f"truncated: symbol link bound of {context.max_links} reached")
    by_line, _ = syntax_nodes(shards, {(row["location"]["path"], int(row["location"]["start_line"]))
                                       for row in symbols}, set())
    unresolved: dict[str, int] = defaultdict(int)
    stale = 0
    for row in symbols:
        location = row["location"]
        nodes = by_line.get((location["path"], int(location["start_line"])), [])
        same_file = [node for node in nodes if node["file_sha256"] == location["file_sha256"]]
        if nodes and not same_file:
            stale += 1
            continue
        if not same_file:
            unresolved[str(row["payload"].get("language") or row["payload"].get("lang") or "unknown")] += 1
            continue
        span = tuple(int(location[key]) for key in ("start_line", "start_column", "end_line", "end_column"))
        point_exact = [node for node in same_file if "identifier" in node["type"] and span == tuple(
            int(node[key]) for key in ("start_line", "start_column", "end_line", "end_column"))]
        if row["job"] == "job_cpp_symbol_index" and len(point_exact) == 1:
            derived.relate(RelationKind.DEFINES, point_exact[0]["identity"], row["identity"], exact=True,
                           confidence=1.0, method="point-span-exact", syntax_type=point_exact[0]["type"],
                           start_byte=point_exact[0]["start_byte"], end_byte=point_exact[0]["end_byte"],
                           column_unit="producer columns compared as tree-sitter byte columns")
            continue
        widest = max(node["end_byte"] - node["start_byte"] for node in same_file)
        candidates = sorted((node for node in same_file if node["end_byte"] - node["start_byte"] == widest),
                            key=lambda node: node["identity"])[:4]
        for node in candidates:
            derived.relate(RelationKind.DEFINES, node["identity"], row["identity"], exact=False,
                           confidence=0.6 if len(candidates) == 1 else 0.4, method="start-line-only",
                           ambiguity="line-only join between a declaration location and the outermost syntax "
                                     "node starting on that line",
                           syntax_type=node["type"], candidate_count=len(candidates),
                           start_byte=node["start_byte"], end_byte=node["end_byte"])
    for language, count in sorted(unresolved.items()):
        derived.gap(f"unavailable_language_or_scope: {count} {language} symbol(s) have no accepted syntax node "
                    "on their declaration line")
    if stale:
        derived.gap(f"stale_source_hash: {stale} symbol(s) and their syntax nodes disagree on the file hash")
    if not symbols:
        derived.coverage.append(("symbol-syntax-links", "unavailable", "no accepted symbols with source locations"))
    elif not _syntax_shards(shards):
        derived.gap("no accepted Tree-sitter syntax shards")
        derived.coverage.append(("symbol-syntax-links", "unavailable", "no accepted Tree-sitter syntax shards"))
    else:
        derived.coverage.append(("symbol-syntax-links", "partial" if derived.gaps else "complete",
                                 "; ".join(derived.gaps[:5]) or None))
    return derived


def _select_history(shards: ShardSet) -> tuple[Mapping[str, Any], ...]:
    return (*shards.select(index="source", job=CATALOG), *shards.select(index="history"),
            *shards.select(index="priority"), *_syntax_shards(shards))


_FILE_SCOPED = {"history_signal": "file:", "hotspot": "hotspot:file:", "change_context_signal": "file:",
                "priority_item": "file:"}
_SYMBOL_SCOPED = {"history_signal": "symbol:", "hotspot": "hotspot:symbol:", "change_context_signal": "function:",
                  "priority_item": "function:"}


def _build_history(context: LinkContext, selected: tuple[Mapping[str, Any], ...]) -> Derived:
    derived = Derived()
    shards = ShardSet(context.shards.run_root, selected)
    sources, source_paths = catalog_sources(context)
    signal_shards = (*shards.select(index="history"), *shards.select(index="priority"))
    rows = [row for row in shards.entities(signal_shards, kinds=tuple(_FILE_SCOPED), limit=context.max_links + 1)
            if row["location"] is not None]
    if len(rows) > context.max_links:
        rows = rows[:context.max_links]
        derived.gap(f"truncated: history and priority link bound of {context.max_links} reached")
    spans = {(row["location"]["path"], int(row["location"]["start_byte"]), int(row["location"]["end_byte"]))
             for row in rows if row["native_id"].startswith(_SYMBOL_SCOPED[row["kind"]])}
    _, by_span = syntax_nodes(shards, set(), spans)
    stale = missing_syntax = 0
    for row in rows:
        location = row["location"]
        if row["native_id"].startswith(_FILE_SCOPED[row["kind"]]):
            target = sources.get((location["path"], location["file_sha256"]))
            if target is None:
                stale += 1 if location["path"] in source_paths else 0
                continue
            exact = not bool(location["ambiguous"])
            derived.relate(RelationKind.OBSERVED_AT, row["identity"], target, exact=exact,
                           confidence=float(location["confidence"]), method="path+sha256",
                           ambiguity=f"file bound by {location['mapping_method']} without a matching blob",
                           producer_mapping=location["mapping_method"])
        elif row["native_id"].startswith(_SYMBOL_SCOPED[row["kind"]]):
            nodes = [node for node in by_span.get((location["path"], int(location["start_byte"]),
                                                   int(location["end_byte"])), ())
                     if node["file_sha256"] == location["file_sha256"]]
            if not nodes:
                missing_syntax += 1
                continue
            for node in sorted(nodes, key=lambda item: item["identity"])[:4]:
                derived.relate(RelationKind.OBSERVED_AT, row["identity"], node["identity"], exact=len(nodes) == 1,
                               confidence=1.0 if len(nodes) == 1 else 0.8, method="byte-span-exact",
                               ambiguity=f"{len(nodes)} syntax nodes share the identical byte span",
                               syntax_type=node["type"])
    if stale:
        derived.gap(f"stale_source_hash: {stale} history or priority record(s) name a file whose hash differs "
                    "from the accepted catalog")
    if missing_syntax:
        derived.gap(f"missing_source_map: {missing_syntax} function or symbol span(s) have no accepted syntax node "
                    "with the same byte span")
    if not shards.select(index="history"):
        derived.gap("history shards are unavailable; only priority records were linked")
    if not rows:
        derived.coverage.append(("history-code-links", "unavailable", "no accepted history or priority records"))
    else:
        derived.coverage.append(("history-code-links", "partial" if derived.gaps else "complete",
                                 "; ".join(derived.gaps[:5]) or None))
    return derived


LINK_RULES: tuple[LinkRule, ...] = (
    LinkRule("representation", "representation-links/1",
             "source, build output and artifact representations of the same content",
             _select_representation, _build_representation),
    LinkRule("finding_source", "finding-source-links/1",
             "observations and canonical findings to accepted source files", _select_findings, _build_findings),
    LinkRule("package_advisory", "package-advisory-links/1",
             "scanner-reported dependency packages to advisories", _select_advisories, _build_advisories),
    LinkRule("symbol_syntax", "symbol-syntax-links/1",
             "accepted symbols to Tree-sitter syntax nodes", _select_symbols, _build_symbols),
    LinkRule("history_code", "history-code-links/1",
             "history, change-context and priority records to source files and syntax nodes",
             _select_history, _build_history),
)


def rule_versions(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    return {rule.family: (overrides or {}).get(rule.family, rule.version) for rule in LINK_RULES}


def link_rule(family: str) -> LinkRule:
    return next(rule for rule in LINK_RULES if rule.family == family)
