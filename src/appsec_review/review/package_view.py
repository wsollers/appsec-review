"""The model-facing view of a review package (``package-view/1``, review-protocol-v2.md section 4).

The stored package is hash-pinned and keeps every identity and every gap. A review cell is shown a *view* of
it, built at cell time and never stored as an identity: labelled sections (``L`` lead, ``S`` source, ``K`` sink,
``R`` range, ``G`` guard, ``F`` call site, ``P`` path, ``E`` entry point, ``M`` memory context, ``C``
corroborating finding, ``B`` build, ``T`` tag, ``X`` material gap, ``O`` other context) whose labels the
application assigns in a fixed order, so one package always yields the same labels.

* Source text is read through the accepted source index (``RetrievalCore.read_source_lines``: the entity must
  resolve, the file hash must equal the indexed hash). The function span is the lead's function; the type
  declarations are those of the types its signature and body mention, looked up in the accepted index; a type
  that cannot be located is a named gap, never silently absent.
* Coverage gaps that do not bear on the lead stay in the stored package and are written once to a
  hash-referenced ``gaps.jsonl`` (counted under ``files``); only gaps whose scope is the package, its function,
  build unit, file or sink are shown inline as ``X`` labels. Every stored gap is accounted: inline plus file.
* The view has a byte budget. Rows are dropped from the least valuable section first, counted in ``omitted`` and
  named by a ``truncated`` ``X`` label; ``expand`` (or the typed tools) reaches whatever was omitted.

Guard rows repeat what a ``guard_fact`` states (``review.fact_summary``); a view never says a guard is adequate.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
import json
from pathlib import PurePosixPath
import re
from typing import Any

from appsec_review.review.identity import sha256_hex
from appsec_review.review.labels import LabelTable
from appsec_review.review.neighborhood import function_extent, type_names

VIEW_SCHEMA = "appsec-review/review-package-view/1"
VIEW_RULE = "appsec-review/package-view/1"
GAP_VIEW_RULE = "appsec-review/package-gap-view/1"
PROTOCOL = "review-protocol/2"
MAX_INLINE_GAPS = 12
MAX_INLINE_CORROBORATION = 5
MAX_LINE_CHARS = 200
WINDOW_LINES = 12
MAX_TYPE_LINES = 30
SANITIZED_KEYS = frozenset({"package_id", "manifest_sha256", "input_fingerprint", "run_id"})
DECLARATION_KINDS = frozenset({"CXXRecordDecl", "RecordDecl", "EnumDecl", "TypedefDecl", "TypeAliasDecl",
                               "ClassTemplateDecl", "ClassDecl", "StructDecl"})
# Sections trimmed first when the view exceeds its byte budget; the lead, source and sinks are never trimmed.
TRIM_ORDER = ("other", "tags", "memory", "corroboration", "callees", "callers", "flows", "entries", "guards",
              "ranges")
_FILE_ROWS = ("gaps.jsonl", "corroborating_findings.jsonl")


@dataclass(frozen=True, slots=True)
class ViewLimits:
    max_bytes: int = 48 * 1024
    max_source_lines: int = 160
    max_type_declarations: int = 6

    @classmethod
    def from_settings(cls, packages: Any) -> "ViewLimits":
        return cls(int(packages.max_view_bytes), int(packages.max_view_source_lines),
                   int(packages.max_view_type_declarations))


@dataclass(frozen=True, slots=True)
class PackageView:
    document: Mapping[str, Any]
    labels: Mapping[str, str]                            # label -> logical identity
    files: Mapping[str, tuple[Mapping[str, Any], ...]]   # file name -> rows (hash-referenced in ``files``)
    locator_paths: frozenset[str]                        # paths a path+line locator may name
    lead_refs: tuple[str, ...]                           # lead observation ids, in L order
    packaged_refs: frozenset[str]                        # every identity the stored package names
    texts: Mapping[str, str] = field(default_factory=dict)   # X label -> the material gap it names

    def table(self, extra_known: Iterable[str] = ()) -> LabelTable:
        return LabelTable(self.labels, known=(*self.packaged_refs, *extra_known), texts=self.texts)

    def with_extra(self, refs: Iterable[str], *, prefix: str = "A") -> tuple["PackageView", dict[str, str]]:
        """This view with ``prefix`` labels (``A`` by default: a claim\'s affected entities; ``J`` for the rows a
        judge is shown) for identities it has no label for. Returns every given identity\'s label."""
        labels = dict(self.labels)
        by_ref: dict[str, str] = {}
        for label, ref in labels.items():
            by_ref.setdefault(ref, label)
        added: dict[str, str] = {}
        count = sum(1 for label in labels if label.startswith(prefix))
        for ref in refs:
            if ref not in by_ref:
                count += 1
                labels[f"{prefix}{count}"] = ref
                by_ref[ref] = f"{prefix}{count}"
            added[ref] = by_ref[ref]
        return replace(self, labels=labels, packaged_refs=self.packaged_refs | frozenset(added)), added

    def file_page(self, name: str, offset: int, limit: int) -> dict[str, Any] | None:
        rows = self.files.get(name)
        if rows is None:
            return None
        page = rows[offset:offset + limit]
        return {"file": name, "offset": offset, "count": len(rows), "rows": list(page),
                "next_offset": offset + len(page) if offset + len(page) < len(rows) else None}


def file_bytes(rows: Sequence[Mapping[str, Any]]) -> bytes:
    return b"".join(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
                    for row in rows)


def is_material_gap(gap: Mapping[str, Any], *, partition_key: str, unit_key: str | None, terms: Iterable[str]) -> bool:
    """Whether a stored coverage gap bears on this package (``package-gap-view/1``).

    Material: its scope is the package partition (or its unit), or its scope or reason names the package's
    paths, function, build unit, a lead or a sink. Everything else is run-wide or about other code.
    """
    scope = str(gap.get("scope", ""))
    if scope == partition_key or (unit_key and (scope == unit_key or scope.startswith(unit_key + "#"))):
        return True
    text = f"{scope} {gap.get('reason', '')}"
    return any(term in text for term in terms if term)


class _Builder:
    def __init__(self, package: Mapping[str, Any], core: Any, limits: ViewLimits):
        self.package, self.core, self.limits = package, core, limits
        self.neighborhood: Mapping[str, Any] = package.get("neighborhood") or {}
        self._locations: dict[str, Mapping[str, Any] | None] = {}
        self._lines: dict[str, tuple[Mapping[str, Any] | None, str | None]] = {}
        self._names: dict[str, str | None] = {}
        self.extra_gaps: list[str] = []
        self.locator_paths: set[str] = set()

    # -- reads through the accepted index -----------------------------------------------------------------
    def location(self, ref: str) -> Mapping[str, Any] | None:
        if ref not in self._locations:
            try:
                found = self.core.find(identity=ref, limit=1)["results"]
            except (ValueError, LookupError):
                found = []
            location = found[0].get("location") if found else None
            self._locations[ref] = location if isinstance(location, Mapping) else None
        return self._locations[ref]

    def name(self, ref: str) -> str | None:
        if ref not in self._names:
            try:
                found = self.core.find(identity=ref, limit=1)["results"]
            except (ValueError, LookupError):
                found = []
            self._names[ref] = str(found[0].get("name")) if found and found[0].get("name") else None
        return self._names[ref]

    def source(self, ref: str) -> tuple[Mapping[str, Any] | None, str | None]:
        if ref not in self._lines:
            try:
                self._lines[ref] = self.core.read_source_lines(identity=ref)
            except (ValueError, LookupError, OSError) as exc:
                self._lines[ref] = (None, f"source could not be read: {type(exc).__name__}")
        return self._lines[ref]

    # -- sections ------------------------------------------------------------------------------------------
    def leads(self) -> list[dict[str, Any]]:
        rows = []
        function = self.neighborhood.get("function") or {}
        for lead in self.package.get("lead_menu", ()):
            ref = str(lead["observation_id"])
            location = self.location(ref) or {}
            where = {"path": location.get("path"), "line": location.get("start_line"),
                     "function": function.get("name") if len(self.package.get("lead_menu", ())) == 1 else None}
            if location.get("path"):
                self.locator_paths.add(str(location["path"]))
            row = {"ref": ref, "family": lead.get("lead_family"), "scanner": lead.get("scanner"),
                   "rule": lead.get("rule_id"), "severity": lead.get("reported_severity"),
                   "native_severity": lead.get("native_severity"), "message": lead.get("message"),
                   "cwe": list(lead.get("rule_cwe", ())), "where": where,
                   "location_exact": lead.get("location_exact"), "suppression": lead.get("suppression_status"),
                   "duplicate_of": lead.get("duplicate_of"),
                   "weaknesses": [{"cwe": item.get("cwe_id"), "name": item.get("name")}
                                  for item in lead.get("weaknesses", ())]}
            if "admission_reasons" in lead:
                row["admission"] = list(lead["admission_reasons"])
                row["advisory"] = lead.get("advisory_context")
            elif lead.get("advisory_summary") is not None:
                row["advisory"] = lead.get("advisory_summary")
            rows.append(row)
        return rows

    def source_rows(self, leads: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
        """The lead's function span and the declarations of the types it mentions, plus the gaps found."""
        if self.package.get("kind") != "finding_lead" or len(leads) != 1:
            return [], []
        lead = leads[0]
        gaps: list[str] = []
        function = self.neighborhood.get("function")
        located, reason = self.source(lead["ref"])
        if located is None:
            return [], [f"no source text for the lead: {reason}"]
        location, lines = located["location"], located["lines"]
        path, line = str(location["path"]), int(location["start_line"])
        if function and function.get("path") == path and function.get("file_sha256") not in (None, location["file_sha256"]):
            gaps.append("the function's file changed after package assembly; its extent is not shown")
            function = None
        if function and function.get("path") == path:
            first, last, truncated = function_extent(lines, int(function["start_line"]), path,
                                                     max_lines=self.limits.max_source_lines)
            ref = str(function["symbol"])
            if not first <= line <= last:
                gaps.append(f"the lead's line {line} lies outside the {function['name']} extent {first}-{last}; "
                            "a window around the line is shown")
                first, last, truncated, ref = max(1, line - WINDOW_LINES), min(len(lines), line + WINDOW_LINES), False, lead["ref"]
            elif truncated:
                gaps.append(f"the {function['name']} extent was cut at {self.limits.max_source_lines} lines")
        else:
            first, last, truncated, ref = max(1, line - WINDOW_LINES), min(len(lines), line + WINDOW_LINES), False, lead["ref"]
            gaps.append("no graph symbol places the lead in a known function; a window around the lead line is shown")
        rows = [self._span(ref, path, location["file_sha256"], lines, first, last, "function", truncated)]
        self.locator_paths.add(path)
        for name in type_names(lines, first, last, limit=self.limits.max_type_declarations):
            row, gap = self._declaration(name, path, lines, ref)
            if row is not None:
                rows.append(row)
            if gap:
                gaps.append(gap)
        return rows, gaps

    @staticmethod
    def _span(ref: str, path: str, file_sha: str, lines: Sequence[str], first: int, last: int, role: str,
              truncated: bool) -> dict[str, Any]:
        text = [f"{number}| {lines[number - 1].rstrip()[:MAX_LINE_CHARS]}" for number in range(first, last + 1)]
        return {"ref": ref, "role": role, "path": path, "lines": f"{first}-{last}", "file_sha256": file_sha,
                "truncated": truncated, "text": text}

    def _declaration(self, name: str, lead_path: str, lead_lines: Sequence[str], fallback_ref: str
                     ) -> tuple[dict[str, Any] | None, str | None]:
        try:
            found = self.core.find(kind="ast_node", name=name, limit=8)["results"]
        except (ValueError, LookupError):
            found = []
        candidates = sorted((item for item in found if isinstance(item.get("payload"), Mapping)
                             and item["payload"].get("kind") in DECLARATION_KINDS and item.get("location")),
                            key=lambda item: ((item["location"]["path"] != lead_path), item["identity"]))
        entities = set(self.package.get("retrieval", {}).get("entity_ids", ()))
        for item in candidates:
            located, _reason = self.source(item["identity"])
            if located is None:
                continue
            location = located["location"]
            first = int(location["start_line"])
            last = min(int(location["end_line"]), first + MAX_TYPE_LINES - 1)
            self.locator_paths.add(str(location["path"]))
            ref = item["identity"] if item["identity"] in entities else fallback_ref
            return self._span(ref, str(location["path"]), location["file_sha256"], located["lines"], first, last,
                              f"type:{name}", int(location["end_line"]) > last), None
        pattern = re.compile(rf"^\s*(?:typedef\s+)?(?:struct|class|union|enum)\s+{re.escape(name)}\b[^;]*$")
        for index, text in enumerate(lead_lines, start=1):
            if pattern.match(text):
                first, last, truncated = function_extent(lead_lines, index, lead_path, max_lines=MAX_TYPE_LINES)
                span = self._span(fallback_ref, lead_path, self._file_sha(lead_path, fallback_ref), lead_lines, first,
                                  last, f"type:{name}", truncated)
                return span, None
        return None, (f"the declaration of type {name} was not found in the accepted index or the lead's file; "
                      "sizes of its fields are unknown")

    def _file_sha(self, path: str, ref: str) -> str:
        located, _reason = self.source(ref)
        return str(located["location"]["file_sha256"]) if located else ""

    def tags(self, refs: Sequence[str]) -> list[dict[str, Any]]:
        return [{"ref": ref, "tag": self.name(ref)} for ref in refs]


def _gap_text(gap: Mapping[str, Any]) -> str:
    return f"{gap.get('producer')}: {gap.get('state')}: {gap.get('reason')}"[:300]


def build_view(package: Mapping[str, Any], core: Any, limits: ViewLimits) -> PackageView:
    """Build the labelled, budgeted view of ``package`` (routing fields are set by the caller per cell)."""
    builder = _Builder(package, core, limits)
    nb = builder.neighborhood
    leads = builder.leads()
    source, source_gaps = builder.source_rows(leads)
    scope = package.get("scope", {})
    partition_key = str(scope.get("partition_key", ""))
    unit_key = partition_key.split("#", 1)[0] if package.get("kind") == "hunt" else None

    neighborhood_refs = {row["ref"] for name in ("sinks", "ranges", "guards", "callers", "callees", "flows", "entries",
                                                  "corroboration") for row in nb.get(name, ())}
    neighborhood_refs |= {nb["build"]["ref"]} if nb.get("build") else set()
    neighborhood_refs |= {nb["function"]["symbol"]} if nb.get("function") else set()
    lead_refs = {lead["ref"] for lead in leads}
    tag_refs, memory, other = [], [], []
    for entry in package.get("context", ()):
        ref, role = entry["id"], entry["role"]
        if ref in neighborhood_refs or ref in lead_refs:
            continue
        if entry["kind"] == "tag_assignment":
            tag_refs.append(ref)
        elif role in {"points_to", "indirect_call", "memory_object"}:
            memory.append({"ref": ref, "role": role, "kind": entry["kind"]})
        else:
            other.append({"ref": ref, "role": role, "kind": entry["kind"]})

    rows: dict[str, list[dict[str, Any]]] = {
        "sinks": [dict(item) for item in nb.get("sinks", ())], "ranges": [dict(item) for item in nb.get("ranges", ())],
        "guards": [dict(item) for item in nb.get("guards", ())], "callers": [dict(item) for item in nb.get("callers", ())],
        "callees": [dict(item) for item in nb.get("callees", ())], "flows": [dict(item) for item in nb.get("flows", ())],
        "entries": [dict(item) for item in nb.get("entries", ())], "memory": memory,
        "corroboration": [dict(item) for item in nb.get("corroboration", ())],
        "tags": builder.tags(tag_refs), "other": other}

    # Gaps: material ones inline (bounded), everything else in the hash-referenced file.
    terms = {str(item) for item in builder.locator_paths} | {lead["ref"] for lead in leads} | neighborhood_refs
    terms |= {str(scope.get("build_unit_id"))} if scope.get("build_unit_id") else set()
    if nb.get("function") and len(nb["function"]["name"]) >= 4:
        terms.add(nb["function"]["name"])
    material, file_gaps = [], []
    for gap in package.get("coverage_gaps", ()):
        (material if is_material_gap(gap, partition_key=partition_key, unit_key=unit_key, terms=terms)
         else file_gaps).append(gap)
    inline_gaps = [_gap_text(gap) for gap in material[:MAX_INLINE_GAPS]]
    file_gaps.extend(material[MAX_INLINE_GAPS:])
    local_gaps = list(source_gaps)
    if nb.get("build") is None and package.get("kind") == "finding_lead":
        pass                                      # a missing build summary is already a stored build_provenance gap
    omitted: dict[str, int] = {}

    texts: dict[str, str] = {}

    def render() -> tuple[dict[str, Any], dict[str, str], dict[str, tuple[Mapping[str, Any], ...]]]:
        labels: dict[str, str] = {}
        texts.clear()
        by_ref: dict[str, str] = {}
        counters: dict[str, int] = {}

        def label(letter: str, ref: str | None) -> str:
            counters[letter] = counters.get(letter, 0) + 1
            text = f"{letter}{counters[letter]}"
            if ref is not None:
                labels[text] = ref
                by_ref.setdefault(ref, text)
            return text

        def labelled(letter: str, items: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
            out = []
            for item in items:
                if item["ref"] in by_ref:
                    continue
                out.append({"label": label(letter, item["ref"]), **item})
            return out

        view_leads = [{"label": label("L", lead["ref"]), **lead} for lead in leads]
        view_source = [{"label": label("S", item["ref"]), **item} for item in source]
        chain = nb.get("chain") or {}
        chain_view = {"reached": bool(chain.get("reached")), "depth_limit": chain.get("depth_limit"),
                      "hops": labelled("F", chain.get("hops", ())), "entries": labelled("E", chain.get("entries", ()))}
        neighborhood = {
            "rule": nb.get("rule"), "call_depth": nb.get("call_depth"), "chain": chain_view,
            "function": ({"name": nb["function"]["name"], "path": nb["function"]["path"],
                          "line": nb["function"]["start_line"], "basis": nb["function"]["basis"]}
                         if nb.get("function") else None),
            "sinks": labelled("K", rows["sinks"]), "ranges": labelled("R", rows["ranges"]),
            "guards": labelled("G", rows["guards"]),
            "callers": labelled("F", rows["callers"]), "callees": labelled("F", rows["callees"]),
            "flows": labelled("P", rows["flows"]), "entries": labelled("E", rows["entries"]),
            "memory": labelled("M", rows["memory"]),
        }
        corroboration = labelled("C", rows["corroboration"][:MAX_INLINE_CORROBORATION])
        inline_rest = rows["corroboration"][MAX_INLINE_CORROBORATION:]
        tags = labelled("T", rows["tags"])
        other_rows = labelled("O", rows["other"])
        build = None
        if nb.get("build"):
            build = {"label": label("B", nb["build"]["ref"]), **{k: v for k, v in nb["build"].items() if k not in
                                                                  {"rule", "ref"}}}
        gap_texts = [*inline_gaps, *local_gaps]
        dropped = {key: value for key, value in omitted.items() if value}
        if dropped:
            gap_texts.append("view byte budget: omitted " + ", ".join(f"{key}={value}" for key, value in sorted(dropped.items()))
                         + "; the rows remain reachable with expand")
        material_rows = []
        for item in gap_texts:
            marker = label("X", None)
            texts[marker] = item
            material_rows.append({"label": marker, "text": item})
        corroborating_rows = [dict(item) for item in inline_rest]
        files: dict[str, tuple[Mapping[str, Any], ...]] = {}
        file_index: dict[str, Any] = {}
        for name, items in (("gaps.jsonl", file_gaps), ("corroborating_findings.jsonl", corroborating_rows)):
            if items:
                files[name] = tuple(items)
                data = file_bytes(items)
                file_index[name] = {"count": len(items), "bytes": len(data), "sha256": sha256_hex(data.decode("utf-8"))}
        document: dict[str, Any] = {
            "schema": VIEW_SCHEMA, "rule": VIEW_RULE, "protocol": PROTOCOL, "kind": package.get("kind"),
            "lane": package.get("lane"), "lead_family": package.get("lead_family"),
            "persona": None, "stack_profile": None,
            "scope": {"component_id": scope.get("component_id"), "build_unit_id": scope.get("build_unit_id"),
                      "partition_key": partition_key},
            "partition": package.get("partition"), "rank": package.get("rank"),
            "leads": view_leads, "source": view_source, "neighborhood": neighborhood, "build": build,
            "corroboration": corroboration, "tags": tags, "other_context": other_rows,
            "material_gaps": material_rows, "gap_counts": {
                "stored": len(package.get("coverage_gaps", ())), "inline": len(inline_gaps), "file": len(file_gaps)},
            "files": file_index, "omitted": dropped,
            "proof_obligations": list(package.get("proof_obligations", ())),
            "graph_families": list((package.get("retrieval") or {}).get("graph_families", ())),
            "truncation": package.get("truncation"),
        }
        return document, labels, files

    while True:
        document, labels, files = render()
        if len(json.dumps(document, sort_keys=True, ensure_ascii=False).encode("utf-8")) <= limits.max_bytes:
            break
        for section in TRIM_ORDER:
            if rows[section]:
                rows[section].pop()
                omitted[section] = omitted.get(section, 0) + 1
                break
        else:
            document["omitted"] = {**document["omitted"], "view_over_budget": True}
            break
    return PackageView(
        document=document, labels=labels, files=files, locator_paths=frozenset(builder.locator_paths),
        lead_refs=tuple(lead["ref"] for lead in leads), texts=dict(texts),
        packaged_refs=frozenset({*(package.get("retrieval") or {}).get("entity_ids", ()), *lead_refs}))


__all__ = ["GAP_VIEW_RULE", "PROTOCOL", "PackageView", "VIEW_RULE", "VIEW_SCHEMA", "ViewLimits", "build_view",
           "file_bytes", "is_material_gap"]
