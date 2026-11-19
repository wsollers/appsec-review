"""Independent C/C++ semantic symbol index built with the pinned clangd-indexer.

The job consumes only the accepted ``job_cpp_compiled_analysis`` handoff. For every accepted
project scope it runs ``tool-clangd-indexer`` over the exact accepted compile commands, then
normalizes declarations, definitions, and call/reference edges between accepted symbols into an
``analysis`` retrieval shard. It does not depend on, or wait for, any other indexing job.
"""

from __future__ import annotations

from appsec_review.storage.shared import PublicationThreadPoolExecutor as ThreadPoolExecutor
from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping
from urllib.parse import unquote, urlparse

from appsec_review.config.first_party import job_dispositions
from appsec_review.review.dispositions import FIRST_PARTY, SourceDispositions
from appsec_review.jobs.cpp_index_scopes import (
    SOURCE_MOUNT, IndexScope, accepted_cpp_scopes, artifact, checkpoint_identity, execute_scope_tool,
    publish_scope_indexes, save_scope_checkpoint, scope_checkpoint, tool_identity,
)
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint,
)
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json

from .clangd_yaml import iter_tagged, parse_documents
from .settings import CppSymbolIndexSettings
from appsec_review.jobs.job_cpp_symbol_index.datasets import CONTRACT, DATASETS


JOB_ID = "job_cpp_symbol_index"
SCHEMA = "appsec-review/cpp-symbol-index/1"
TOOL_ID = "tool-clangd-indexer"
NORMALIZER = "clangd-yaml-normalizer/2"
CALL_BIT = 16  # clangd RefKind::Call
# clangd's all-TUs executor writes these lines from parallel threads, so they interleave by line
# and may carry another thread's fragment as a prefix; none requires a leading line boundary.
_PROCESSED = re.compile(
    r"\[[0-9]+/[0-9]+\] Processing file (/[^\r\n]*?)"
    r"(?=\[[0-9]+/[0-9]+\] Processing file |\r?$)", re.MULTILINE)
_INCLUDED_FROM = re.compile(r"In file included from (/[^\r\n]+?):[0-9]+(?=[:,\r\n]|$)")
_NOT_FOUND = re.compile(r"'([^']+)' file not found")
_NOT_FOUND_AT = re.compile(r"(/[^\r\n]+?):[0-9]+:[0-9]+: fatal error: '([^']+)' file not found")
_ERROR_PROCESSING = re.compile(r"Error while processing (/[^\r\n]+?)\.(?=\r?$)", re.MULTILINE)
_GAP_HEADERS = 16
_GAP_UNITS = 8


def unresolved_system_headers(stderr: str, expected: set[str]) -> tuple[list[str], dict[str, list[str]]]:
    """Headers clangd reported as ``file not found`` and the expected translation units affected.

    Returns ``(headers, units)``: every missing include name, sorted, and for each affected
    translation unit (a path in ``expected``) the sorted headers it could not resolve. A unit is
    affected when it is the diagnosed file or any file on the ``In file included from`` chain that
    precedes the diagnostic. Interleaved chains may credit a header to a neighbouring unit that
    was itself failing on the same header; a diagnostic whose chain names no expected unit still
    contributes its header. The scan is one bounded pass over the lines.
    """
    headers: set[str] = set()
    units: dict[str, set[str]] = {}
    chain: list[str] = []
    for line in stderr.splitlines():
        included = [match.group(1) for match in _INCLUDED_FROM.finditer(line)]
        if included:
            chain.extend(included)
        found = [match.group(1) for match in _NOT_FOUND.finditer(line)]
        if not found:
            continue
        headers.update(found)
        diagnosed = [match.group(1) for match in _NOT_FOUND_AT.finditer(line)]
        for unit in chain + diagnosed:
            if unit in expected:
                units.setdefault(unit, set()).update(found)
        chain = []
    return sorted(headers), {unit: sorted(names) for unit, names in sorted(units.items())}


def _unit_label(path: str) -> str:
    return path[len(SOURCE_MOUNT) + 1:] if path.startswith(SOURCE_MOUNT + "/") else path


def _bounded(names: list[str], limit: int) -> str:
    shown = ", ".join(names[:limit])
    return shown if len(names) <= limit else f"{shown}, +{len(names) - limit} more"


def _settings(unit: UnitContext) -> Mapping[str, int]:
    return CppSymbolIndexSettings.from_mapping(unit.job.config.settings).limits()


def _container_path(uri: Any) -> str | None:
    if not isinstance(uri, str) or not uri.startswith("file://"):
        return None
    return unquote(urlparse(uri).path)


def _position(value: Any) -> tuple[int, int] | None:
    if not isinstance(value, Mapping):
        return None
    coordinates = []
    for name in ("Line", "Column"):
        coordinate = value.get(name)
        if isinstance(coordinate, str) and re.fullmatch(r"[0-9]+", coordinate):
            coordinate = int(coordinate)  # the bounded YAML parser retains scalars as strings
        if type(coordinate) is not int:
            return None
        coordinates.append(coordinate)
    line, column = coordinates
    # SymbolLocation::Position saturates its packed 20-bit line / 12-bit UTF-16 column.
    if not 0 <= line < (1 << 20) - 1 or not 0 <= column < (1 << 12) - 1:
        return None
    return line + 1, column + 1


@dataclass(frozen=True)
class _SourceBytes:
    lines: tuple[bytes, ...]
    starts: tuple[int, ...]

    @classmethod
    def read(cls, path: Path, sha256: str, target_path: str) -> _SourceBytes:
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"clangd symbol source changed after acceptance: {target_path}")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != sha256:
            raise ValueError(f"clangd symbol source changed after acceptance: {target_path}")
        lines = tuple(data.split(b"\n"))
        starts = []
        offset = 0
        for line in lines:
            starts.append(offset)
            offset += len(line) + 1
        return cls(lines, tuple(starts))

    def offset(self, position: tuple[int, int]) -> int | None:
        line, column = position
        if line > len(self.lines):
            return None
        try:
            text = self.lines[line - 1].decode("utf-8")
        except UnicodeDecodeError:
            return None
        units, offset = 1, self.starts[line - 1]
        for char in text:
            if units == column:
                return offset
            units += 2 if ord(char) > 0xFFFF else 1
            offset += len(char.encode("utf-8"))
            if units > column:
                return None
        return offset if units == column else None


def _location_gap(gaps: list[str] | None) -> None:
    message = "clangd source locations could not be resolved against accepted bytes"
    if gaps is not None and message not in gaps:
        gaps.append(message)


def _accepted_location(unit: UnitContext, scope: IndexScope, value: Any,
                       sources: dict[str, _SourceBytes],
                       gaps: list[str] | None = None) -> tuple[SourceLocation, dict] | None:
    if not isinstance(value, Mapping):
        return None
    path = _container_path(value.get("FileURI"))
    accepted = scope.accepted_file(path) if path else None
    start, end = _position(value.get("Start")), _position(value.get("End"))
    if accepted is None:
        return None
    if "End" not in value:
        end = start
    if start is None or end is None:
        _location_gap(gaps)
        return None
    target_path = str(accepted["target_path"])
    if target_path not in sources:  # hash and map the same accepted bytes, once per scope
        target_file = (unit.job.target_root or Path()) / Path(*PurePosixPath(target_path).parts)
        sources[target_path] = _SourceBytes.read(target_file, str(accepted["sha256"]), target_path)
    start_byte, end_byte = sources[target_path].offset(start), sources[target_path].offset(end)
    if start_byte is None or end_byte is None or end_byte < start_byte:
        _location_gap(gaps)
        return None
    location = SourceLocation(
        unit.job.source_fingerprint, target_path, str(accepted["sha256"]), start_byte, end_byte,
        start[0], end[0], start[1], end[1],
        {"uri": str(value.get("FileURI"))[:4096], "line": start[0], "column": start[1]},
        "clangd-uri-utf16-verified-bytes", 1.0, False)
    return location, {"path": target_path, "line": start[0], "column": start[1],
                      "end_line": end[0], "end_column": end[1]}


def _symbol_identity(scope: IndexScope, clangd_id: str) -> LogicalIdentity:
    return LogicalIdentity.derive(EntityKind.SYMBOL, scope.case_snapshot,
                                  {"project_id": scope.project_id, "producer": "clangd",
                                   "clangd_id": clangd_id})


def normalize_scope(unit: UnitContext, scope: IndexScope, execution: Mapping[str, Any],
                    limits: Mapping[str, int], builder: IndexBuilder, shard: str,
                    dispositions: SourceDispositions | None = None) -> dict[str, Any]:
    """Normalize one clangd YAML index into the builder; return counts and gaps.

    Symbols are admitted first-party first (T-5016): when ``max_symbols_per_scope`` is reached, the
    symbols left out are counted per disposition (``excluded_symbols_by_disposition``), and only a
    first-party exclusion is a gap.
    """
    from appsec_review.runtime import execution_safety as safety
    gaps: list[str] = []
    run_root = unit.job.run_root
    diagnostics_truncated = execution.get("stderr_truncated", False)
    safety.failed_result(execution["timed_out"] or execution["oom_killed"]
                         or execution["exit_code"] != 0 or execution["stdout_truncated"]
                         or diagnostics_truncated,
                         "clangd diagnostics were truncated" if diagnostics_truncated
                         else "clangd execution failed or truncated its index", action="cpp.symbols")
    if execution["timed_out"]:
        gaps.append("clangd-indexer timed out")
    elif execution["oom_killed"]:
        gaps.append("clangd-indexer was OOM-killed")
    elif execution["exit_code"] != 0:
        gaps.append(f"clangd-indexer exited with status {execution['exit_code']}")
    if execution["stdout_truncated"]:
        gaps.append("clangd index output exceeded the tool output bound and was truncated")
    if diagnostics_truncated:
        gaps.append("clangd diagnostics exceeded the tool output bound and were truncated")
    stderr = (run_root / execution["stderr_path"]).read_text(encoding="utf-8", errors="replace")
    processed = {match.group(1) for match in _PROCESSED.finditer(stderr)}
    expected = {row["file"] for row in scope.container_compile_database()}
    missing = sorted(expected - processed)
    if missing:
        safety.fail("clangd omitted required translation units", action="cpp.symbols")
    # A unit clangd parsed without its system headers, or reported "Error while processing", is
    # not processed: its index lacks every declaration behind the failing include.
    unresolved_headers, unresolved_units = unresolved_system_headers(stderr, expected)
    errored = {match.group(1) for match in _ERROR_PROCESSING.finditer(stderr)} & expected
    not_processed = sorted(expected if diagnostics_truncated else set(missing) | set(unresolved_units) | errored)
    if unresolved_headers:
        gaps.append(f"system_headers_unresolved: {_bounded(unresolved_headers, _GAP_HEADERS)} not found "
                    f"in {len(unresolved_units)} of {len(expected)} translation units"
                    + (f" ({_bounded([_unit_label(unit) for unit in unresolved_units], _GAP_UNITS)})"
                       if unresolved_units else ""))
    if not_processed:
        gaps.append(f"clangd-indexer processed {len(expected) - len(not_processed)} of {len(expected)} "
                    "translation units")
    text = (run_root / execution["stdout_path"]).read_text(encoding="utf-8", errors="replace")
    try:
        documents, truncated_tail, capped = parse_documents(
            text, document_limit=limits["max_documents_per_scope"])
    except ValueError as exc:
        from appsec_review.runtime import execution_safety as safety
        safety.fail(f"clangd output is malformed: {exc}", action="cpp.symbols")
        documents, truncated_tail, capped = [], False, False
        gaps.append(f"clangd index output is malformed: {exc}")
    if truncated_tail:
        from appsec_review.runtime import execution_safety as safety
        safety.fail("clangd output ended inside a document", action="cpp.symbols")
        gaps.append("clangd index output ended inside a document")
    if capped:
        gaps.append("clangd index document limit reached")

    symbols: dict[str, LogicalIdentity] = {}
    sources: dict[str, _SourceBytes] = {}
    external = 0
    candidates: list[tuple[bool, int, str, Mapping[str, Any], Any, Any, Any, str]] = []
    seen_ids: set[str] = set()
    for value in iter_tagged(documents, "Symbol"):
        clangd_id = str(value.get("ID", ""))
        if not re.fullmatch(r"[0-9A-F]{16}", clangd_id) or clangd_id in seen_ids:
            continue
        seen_ids.add(clangd_id)
        definition = _accepted_location(unit, scope, value.get("Definition"), sources, gaps)
        declaration = _accepted_location(unit, scope, value.get("CanonicalDeclaration"), sources, gaps)
        chosen = definition or declaration
        if chosen is None:
            locations = (value.get("Definition"), value.get("CanonicalDeclaration"))
            if not any(scope.accepted_file(path) for item in locations if isinstance(item, Mapping)
                       if (path := _container_path(item.get("FileURI")))):
                external += 1  # declared only outside accepted sources (system or SDK headers)
            continue
        kind = dispositions.classify(str(chosen[1]["path"])) if dispositions is not None else FIRST_PARTY
        candidates.append((kind != FIRST_PARTY, len(candidates), clangd_id, value, definition, declaration, chosen,
                           kind))
    candidates.sort(key=lambda item: item[:2])
    symbols_by_disposition: dict[str, int] = {}
    excluded_by_disposition: dict[str, int] = {}
    for _, _, clangd_id, value, definition, declaration, chosen, kind in candidates:
        if len(symbols) >= limits["max_symbols_per_scope"]:
            excluded_by_disposition[kind] = excluded_by_disposition.get(kind, 0) + 1
            continue
        symbols_by_disposition[kind] = symbols_by_disposition.get(kind, 0) + 1
        info = value.get("SymInfo") if isinstance(value.get("SymInfo"), Mapping) else {}
        name = str(value.get("Name", ""))[:1024]
        qualified = (str(value.get("Scope", "")) + name)[:4096]
        identity = _symbol_identity(scope, clangd_id)
        symbols[clangd_id] = identity
        builder.add_entity(EntityRecord(identity, clangd_id, qualified,
            f"{info.get('Kind', 'Symbol')} {qualified}{value.get('Signature', '')}"[:16384],
            {"producer": "clangd", "clangd_id": clangd_id, "kind": str(info.get("Kind", ""))[:64],
             "lang": str(info.get("Lang", ""))[:32], "scope": str(value.get("Scope", ""))[:2048],
             "signature": str(value.get("Signature", ""))[:2048],
             "return_type": str(value.get("ReturnType", ""))[:2048],
             "type": str(value.get("Type", ""))[:2048],
             "template_arguments": str(value.get("TemplateSpecializationArgs", ""))[:2048],
             "reference_count": int(value.get("References", 0) or 0)
             if str(value.get("References", "0")).isdigit() else 0,
             "definition": definition[1] if definition else None,
             "declaration": declaration[1] if declaration else None,
             "project_id": scope.project_id, "shard_id": shard},
            chosen[0]))

    if excluded_by_disposition.get(FIRST_PARTY):
        gaps.append("clangd symbol limit reached")
    edges: dict[tuple[RelationKind, str, str], dict[str, Any]] = {}
    unresolved_refs = 0
    for value in iter_tagged(documents, "Refs"):
        target = symbols.get(str(value.get("ID", "")))
        references = value.get("References") if isinstance(value.get("References"), list) else []
        for reference in references:
            container = reference.get("Container", {}) if isinstance(reference, Mapping) else {}
            source = symbols.get(str(container.get("ID", "")) if isinstance(container, Mapping) else "")
            if target is None or source is None:
                unresolved_refs += 1
                continue
            kind_bits = int(reference.get("Kind", 0)) if str(reference.get("Kind", "0")).isdigit() else 0
            kind = RelationKind.CALLS if kind_bits & CALL_BIT else RelationKind.REFERENCES
            if source == target and kind != RelationKind.CALLS:
                continue  # declaration/definition self-references are resolved, but not edges
            key = (kind, source.value, target.value)
            if key not in edges:
                if len(edges) >= limits["max_relations_per_scope"]:
                    if "clangd relation limit reached" not in gaps:
                        gaps.append("clangd relation limit reached")
                    unresolved_refs += 1
                    continue
                edges[key] = {"occurrences": 0, "locations": []}
            edge = edges[key]
            edge["occurrences"] += 1
            location = _accepted_location(unit, scope, reference.get("Location"), sources, gaps)
            if location and len(edge["locations"]) < limits["locations_per_relation"]:
                edge["locations"].append({key: location[1][key] for key in ("path", "line", "column")}
                                         | {"ref_kind": kind_bits})
    for (kind, source, target), edge in sorted(edges.items(), key=lambda item: (item[0][0].value, *item[0][1:])):
        builder.add_relation(RelationRecord(kind, source, target, True, 1.0, None,
                                            {"producer": "clangd", **edge}))
    unique = list(dict.fromkeys(gaps))
    if execution["exit_code"] != 0 and not symbols:
        status = "unavailable"
    else:
        status = "partial" if unique else "complete"
    builder.add_coverage(f"clangd:{scope.project_id}"[:256], status, "; ".join(unique[:10]) or None)
    return {"symbols": len(symbols), "external_symbols": external, "relations": len(edges),
            "unresolved_references": unresolved_refs, "translation_units": len(expected),
            "processed_translation_units": len(expected) - len(not_processed),
            "omitted_translation_units": len(missing),
            "unresolved_system_headers": unresolved_headers,
            "translation_units_with_unresolved_headers": len(unresolved_units),
            "gaps": unique, "coverage": status,
            "symbols_by_disposition": dict(sorted(symbols_by_disposition.items())),
            "excluded_symbols_by_disposition": dict(sorted(excluded_by_disposition.items()))}


def _not_applicable_scope(scope: IndexScope) -> dict[str, Any]:
    """A scope whose compile units are all outside Clang support: SKIPPED_NA, never launched."""
    return {"scope_id": scope.scope_id, "case_id": scope.case_id, "project_id": scope.project_id,
            "terminal_status": "SKIPPED_NA", "gaps": [],
            "not_applicable_inputs": scope.not_applicable_inputs()}


def _index_scope(unit: UnitContext, scope: IndexScope, executor_factory: Any) -> dict[str, Any]:
    limits = _settings(unit)
    dispositions = job_dispositions(unit.job.config.settings)
    root = unit.job.run_root / "data" / "code-index" / "clangd" / scope.scope_id
    identity = checkpoint_identity({
        "schema": SCHEMA, "scope": scope.as_dict(), "normalizer": NORMALIZER,
        "tool": tool_identity(unit.job.repository_root, TOOL_ID) if executor_factory is None
        else {"tool_id": TOOL_ID, "injected_executor": True},
        "limits": {key: value for key, value in limits.items() if key != "workers"},
        "source_dispositions": dispositions.record()})
    reused = scope_checkpoint(root / "checkpoint.json", identity, unit.job.run_root, scope,
                              required=("execution.receipt", "execution.compile_database"))
    if reused is not None:
        return reused
    execution = execute_scope_tool(
        unit, scope, TOOL_ID,
        ("/opt/clangd/clangd_23.1.0/bin/clangd-indexer", "--executor=all-TUs", "--format=yaml",
         "/scratch/compile_commands.json"), root / "run", executor_factory)
    shard = f"clangd-{scope.scope_id}"
    artifacts = [execution["receipt"], execution["compile_database"], dict(scope.compile_database)]
    fingerprint = index_fingerprint(
        name="analysis", target_snapshot=scope.case_snapshot, producer_artifacts=artifacts,
        tool_identity={"tool": TOOL_ID, "image": execution["image_id"],
                       "image_digest": execution["image_digest"]},
        parser_identity="clangd-yaml-parser/1", normalizer_identity=NORMALIZER,
        mapping_identity="cpp-source-mapping/3")
    path = (unit.job.run_root / "data" / "indices" / "analysis" /
            f"{fingerprint}-{hashlib.sha256(shard.encode()).hexdigest()[:16]}.sqlite")
    builder = IndexBuilder(path, name="analysis", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard)
    counts = normalize_scope(unit, scope, execution, limits, builder, shard, dispositions=dispositions)
    sha, _ = builder.build_or_reuse()
    index = IndexIdentity("analysis", "appsec-review/retrieval-index/2", sha, fingerprint,
                          path.relative_to(unit.job.run_root).as_posix(),
                          {"job": JOB_ID, "unit": unit.unit_id, "scope_id": scope.scope_id},
                          tuple(counts["gaps"]), shard)
    result = {"scope_id": scope.scope_id, "case_id": scope.case_id, "project_id": scope.project_id,
              "execution": {key: execution[key] for key in ("receipt", "compile_database", "exit_code",
                                                              "timed_out", "oom_killed", "image_id")},
              "accepted_compile_database": dict(scope.compile_database),
              "index_identity": asdict(index), "counts": counts, "gaps": counts["gaps"],
              "not_applicable_inputs": scope.not_applicable_inputs(),
              "terminal_status": "COMPLETED_WITH_GAPS" if counts["gaps"] else "SUCCEEDED"}
    save_scope_checkpoint(root / "checkpoint.json", identity, result)
    return result


def _validate(context, _result) -> None:
    steps = context.config.steps
    if tuple(steps) != ("load", "index", "acceptance"):
        raise ValueError("C++ symbol-index topology does not match central configuration")
    for step, task in (("load", "accepted_cpp"), ("index", "scopes"), ("acceptance", "publish_handoff")):
        if tuple(context.config.step(step).tasks) != (task,):
            raise ValueError(f"C++ symbol-index task configuration mismatch: {step}")
    CppSymbolIndexSettings.from_mapping(context.config.settings)


def build_job(*, executor_factory=None) -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        accepted, scopes, unavailable = accepted_cpp_scopes(unit.job.run_root)
        if accepted["handoff"].get("source_fingerprint") != unit.job.source_fingerprint:
            raise ValueError("symbol-index target snapshot differs from the accepted C++ build")
        unit.job.events.write("CPP_SYMBOL_INDEX_SCOPES_LOADED", scope_count=len(scopes),
                              unavailable_count=len(unavailable))
        return {"upstream": {"handoff_sha256": accepted["handoff_sha256"], "manifest": accepted["manifest"]},
                "scopes": [scope.as_dict() for scope in scopes], "unavailable": unavailable}

    def index(unit: UnitContext) -> Mapping[str, Any]:
        _accepted, scopes, unavailable = accepted_cpp_scopes(unit.job.run_root)
        planned = {item["scope_id"] for item in unit.output("load.accepted_cpp")["scopes"]}
        if {scope.scope_id for scope in scopes} != planned:
            raise ValueError("accepted C++ scopes changed between load and index")
        runnable = [scope for scope in scopes if scope.container_compile_database()]
        skipped = [_not_applicable_scope(scope) for scope in scopes if not scope.container_compile_database()]
        with ThreadPoolExecutor(max_workers=_settings(unit)["workers"]) as pool:
            results = list(pool.map(lambda scope: _index_scope(unit, scope, executor_factory), runnable))
        gaps = [f"{item['case_id']}: {gap}" for item in results for gap in item["gaps"]]
        gaps.extend(f"{case_id}: {reason}" for case_id, reason in unavailable.items())
        status = ("NOT_APPLICABLE" if not results and not unavailable else
                  "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED")
        return {"scopes": results, "scope_count": len(results), "gaps": gaps,
                "not_applicable_scopes": skipped, "terminal_status": status}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded, indexed = unit.output("load.accepted_cpp"), unit.output("index.scopes")
        manifest = publish_scope_indexes(unit, job_id=JOB_ID, index_name="analysis", prefix="clangd",
                                         results=indexed["scopes"], unavailable=loaded["unavailable"],
                                         gaps=indexed["gaps"])
        counts = {key: sum(int(item["counts"][key]) for item in indexed["scopes"])
                  for key in ("symbols", "external_symbols", "relations", "translation_units",
                              "processed_translation_units")}
        summary_path = unit.unit_root / "cpp-symbol-index-summary.json"
        atomic_json(summary_path, {"schema": SCHEMA, "upstream": loaded["upstream"], "counts": counts,
                                   "scopes": indexed["scopes"], "unavailable": loaded["unavailable"],
                                   "gaps": indexed["gaps"]})
        unit.job.events.write("CPP_SYMBOL_INDEX_COMPLETED", **counts, gap_count=len(indexed["gaps"]))
        return {"schema": SCHEMA, "artifact": artifact(unit.job.run_root, summary_path),
                "index_manifest": manifest,
                "item_count": counts["symbols"], "counts": counts, "gaps": indexed["gaps"],
                "terminal_status": indexed["terminal_status"]}

    units = (
        Unit("load.accepted_cpp", load),
        Unit("index.scopes", index, ("load.accepted_cpp",)),
        Unit("acceptance.publish_handoff", publish, ("load.accepted_cpp", "index.scopes")),
    )
    implementation = None
    return Job(JOB_ID, "cpp_symbol_index", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=SCHEMA, implementation_identity=implementation, units=units,
               datasets=DATASETS, contract=CONTRACT)
