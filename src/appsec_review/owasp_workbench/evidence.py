"""Run-pinned evidence bundles and citation re-resolution using the shared retrieval boundary."""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
import re
from typing import Any, Mapping

from appsec_review.config.owasp import OwaspSettings
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.retrieval.model import LogicalIdentity, normalize_relative_path
from appsec_review.retrieval.source_resolution import read_source_bytes
from appsec_review.review.dispositions import FIRST_PARTY
from appsec_review.review.scope import AcceptedScope, accept_manifest
from appsec_review.review.secret_redaction import REDACTION_RULE, placeholder
from .standards import digest
from . import c_subjects
from .subject_selection import (
    LANGUAGE_LABELS, SELECTION_RULE, SourceSubject, parse_gaps, parse_subjects, select_subjects, subject_language,
)


from appsec_review.jobs.job_owasp_control_assessment.datasets import CONTRACT

UPSTREAM_JOBS = CONTRACT.consumes
# The phrase that marks the first-party exclusion gap of component_evidence (run 2026-11-17-0003).
FIRST_PARTY_EXCLUSION = "outside the first-party disposition"
UPSTREAM_INDEXES = ("source", "components", "build", "artifacts", "build_security", "compiled",
                    "analysis", "evidence", "inventory", "observations", "documents", "tags",
                    "priority", "graph")
_SECRET_NAME = r"(?:api[_-]?key|password|passwd|secret|credential|private[_-]?key|(?:access[_-]?)?token|authorization)"
_ASSIGNMENT = re.compile(
    rf"""(?ix)(?<![\w$.-])(?P<head>["']?[\w$.-]*{_SECRET_NAME}[\w$.-]*["']?\s*[:=]\s*(?:Bearer\s+)?)
    (?P<value>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|[^\s,;}}\])]+)""")
_CREDENTIAL = re.compile(r"\b(?:sk_live_|gh[pousr]_|github_pat_|AKIA)[A-Za-z0-9_/-]+")
_BASIC_AUTH = re.compile(r"(?P<head>https?://[^/\s:@]+:)(?P<value>[^@\s/]+)(?=@)")
_ROUTING_INDEXES = frozenset({"tags", "priority", "graph"})
# D1 (run 2026-11-16-0005): tag discovery reads the tags index alone; priority and graph rows are a
# separately capped context list, so a large graph shard can no longer hide the target class.
_CONTEXT_INDEXES = frozenset({"priority", "graph"})
_CLASSIFYING_NAMESPACES = frozenset({"target", "role", "exposure", "trust", "mechanism", "asset", "state"})
_TAG_NAME = re.compile(r"^[a-z][a-z0-9-]*(?::[a-z0-9][a-z0-9.-]*){1,3}$")
_CONCLUSION_KINDS = frozenset({
    "precomputed_fact", "finding_package", "review_unit", "review_signal", "review_flow_step",
    "review_context_file", "coverage_cell",
})
_SOURCE_KINDS = frozenset({"source_file", "source_span", "symbol", "ast_node", "ir_entity"})
_AUTHORITATIVE_INDEX = {
    "source_file": "source", "component": "components", "project": "components",
    "build_action": "build", "tool_observation": "observations", "tag_assignment": "tags",
    "priority_item": "priority",
}
EVIDENCE_RULE = "appsec-review/owasp-evidence-binding/5"


def redact(text: str) -> tuple[str, bool]:
    lines, changed, private = [], False, False
    for line in text.splitlines():
        if "-----BEGIN " in line and "PRIVATE KEY-----" in line:
            private = True
        def assigned(match: re.Match[str]) -> str:
            value = match["value"]
            if value.startswith("<redacted") or value.lstrip("\"'`").startswith("<redacted"):
                return match[0]
            quote = value[0] if value[:1] in {'"', "'", "`"} else ""
            body = value[1:-1] if quote else value
            return match["head"] + quote + placeholder(len(body)) + quote

        value = placeholder(len(line)) if private else _ASSIGNMENT.sub(assigned, line)
        value = _CREDENTIAL.sub(lambda match: placeholder(len(match[0])), value)
        value = _BASIC_AUTH.sub(lambda match: match["head"] + placeholder(len(match["value"])), value)
        lines.append(value)
        changed = changed or value != line
        if "-----END " in line and "PRIVATE KEY-----" in line:
            private = False
    return "\n".join(lines), changed


def _redact_data(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: (placeholder(len(str(child))) if re.search(_SECRET_NAME, str(key), re.I)
                      and key not in {"source_identity", "logical_id", "identity"} else _redact_data(child))
                for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_redact_data(child) for child in value]
    return redact(value)[0] if isinstance(value, str) else value


def _meaningful(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(_meaningful(child) for key, child in value.items()
                   if key not in {"component_id", "build_unit_id", "identity", "logical_id", "sha256", "subject"})
    if isinstance(value, (list, tuple)):
        return any(_meaningful(child) for child in value)
    return value is not None and value != ""


def _evidence_content(record: Mapping[str, Any]) -> dict[str, Any]:
    """Keep content/scope/rules, excluding only the resolver's publication-derived wrapper IDs."""
    return {
        **{key: value for key, value in record.items() if key not in {"evidence_id", "reference"}},
        "reference": {key: value for key, value in record["reference"].items() if key != "publication"},
    }


class EvidenceResolver:
    def __init__(self, core: RetrievalCore, scope: AcceptedScope, max_source_lines: int = 120):
        if type(max_source_lines) is not int or not 1 <= max_source_lines <= 500:
            raise ValueError("OWASP source line cap must be between 1 and 500")
        if (core.run_id != scope.run_id or core.run_root != scope.run_root
                or core.manifest_sha256 != scope.manifest_sha256
                or getattr(core, "view_identity", core.manifest_sha256)
                != getattr(scope, "view_identity", scope.manifest_sha256)
                or core.manifest["target_snapshot"] != scope.target_snapshot):
            raise ValueError("evidence resolver run/target/manifest isolation mismatch")
        self.core, self.scope = core, scope
        self.max_source_lines = max_source_lines
        self._subject_cache: dict[str, tuple[SourceSubject, ...]] = {}
        self._entity_cache: dict[str, tuple[Mapping[str, Any], tuple[Mapping[str, Any], ...]]] = {}
        self.metrics = {"attempts": 0, "denials": 0, "truncations": 0, "missing": 0}
        self.shards = {(item["name"], item["shard_id"]): item for item in scope.shards
                       if item["name"] in UPSTREAM_INDEXES
                       and item.get("producer", {}).get("job") in UPSTREAM_JOBS}

    def query(self, method: str, **parameters: Any) -> Mapping[str, Any]:
        self.metrics["attempts"] += 1
        response = getattr(self.core, method)(**parameters)
        self.metrics["truncations"] += int(bool(response.get("truncated")
                                                    or response.get("pagination", {}).get("next_cursor")))
        self.metrics["missing"] += int(not response["results"])
        return response

    def _entity(self, identity: str) -> Mapping[str, Any]:
        cached = self._entity_cache.get(identity)
        if cached is not None:
            value, shards = cached
            for shard in shards:
                database = self.core._database(shard, self.core.clock() + self.core.limits.timeout_ms / 1000)
                database.close()
            return deepcopy(value)
        kind = LogicalIdentity.parse(identity).kind.value
        original = _AUTHORITATIVE_INDEX.get(kind)
        phases = (((original,), tuple(index for index in UPSTREAM_INDEXES if index != original))
                  if original is not None else (UPSTREAM_INDEXES,))
        values = []
        checked_indexes = set()
        # The existing authoritative-index preference lets us avoid opening unrelated shards.
        # Fall back only when that index supplies no admissible original record.
        for indexes in phases:
            checked_indexes.update(indexes)
            cursor = None
            for _ in range(len(self.scope.shards) + 1):
                result = self.query("find", identity=identity, indexes=indexes,
                                    limit=min(self.core.limits.max_results, max(1, len(self.scope.shards))),
                                    cursor=cursor)
                if result["truncated"]:
                    raise ValueError("citation lookup was truncated")
                for item in result["results"]:
                    shard = self.shards.get((item["index"], item["shard_id"]))
                    if shard is None:
                        continue
                    # Bind the original indexed record, not retrieval's lossy display sanitization.
                    with closing(self.core._database(shard, self.core.clock() + self.core.limits.timeout_ms / 1000)) as database:
                        row = database.execute("SELECT payload_json FROM entities WHERE identity=?", (identity,)).fetchone()
                    item = {**item, "payload": json.loads(row["payload_json"])}
                    if self._original(item):
                        values.append(item)
                cursor = result.get("pagination", {}).get("next_cursor")
                if not cursor:
                    break
            else:
                raise ValueError("citation lookup exceeded accepted shard bound")
            if values:
                break
        authoritative = [item for item in values if item["index"] == original]
        if authoritative:
            values = authoritative
        if original in {"source", "components", "build"}:
            catalog = [item for item in values if self.shards[(item["index"], item["shard_id"])]
                       .get("producer", {}).get("job") == "job_target_catalog"]
            if catalog:
                values = catalog
        if not values:
            raise ValueError("citation is missing, ambiguous or outside accepted upstream publications")
        values.sort(key=lambda item: (item["index"], item["shard_id"]))
        comparable = lambda item: {key: item.get(key) for key in (
            "identity", "kind", "native_id", "name", "payload", "location")}
        if any(comparable(item) != comparable(values[0]) for item in values[1:]):
            raise ValueError("citation has conflicting accepted original records")
        # Retain only byte-pinned record data. Every reuse reopens all searched shards through
        # the live grant, publication-receipt and custody verifier above.
        shards = tuple(shard for name in sorted(checked_indexes)
                       for shard in self.core.indexes.get(name, ()))
        self._entity_cache[identity] = (deepcopy(values[0]), shards)
        return values[0]

    @staticmethod
    def _original(entity: Mapping[str, Any]) -> bool:
        payload = entity.get("payload") or {}
        producer = payload.get("producer")
        return (entity["kind"] not in _CONCLUSION_KINDS
                and producer not in ("bounded_inference", "model", "worker", "inference")
                and not any(key in payload for key in ("model_output", "model_text", "worker_conclusion")))

    @staticmethod
    def _owner(path: str | None, items: Any, label: str) -> Any:
        if path is None:
            return None
        path = normalize_relative_path(path)
        matches = [item for item in items if item.root == "." or path == item.root
                   or path.startswith(item.root + "/")]
        if not matches:
            return None
        length = max(0 if item.root == "." else len(item.root) for item in matches)
        closest = [item for item in matches if (0 if item.root == "." else len(item.root)) == length]
        if len(closest) != 1:
            raise ValueError(f"accepted evidence has ambiguous {label} ownership")
        return closest[0]

    def _build(self, entity: Mapping[str, Any]) -> str | None:
        location, payload = entity.get("location") or {}, entity.get("payload") or {}
        subject = payload.get("subject") or {}
        graph_scope = payload.get("scope") or {}
        shard = self.shards.get((entity.get("index"), entity.get("shard_id")), {})
        declared = [value for value in (payload.get("build_unit_id"),
                    subject.get("build_unit_id") if isinstance(subject, Mapping) else None,
                    graph_scope.get("build_unit_id") if isinstance(graph_scope, Mapping) else None,
                    shard.get("producer", {}).get("build_unit_id")) if value is not None]
        if any(not isinstance(value, str) or not value for value in declared):
            raise ValueError("accepted evidence has an invalid build-unit identity")
        inferred = self._owner(location.get("path"), self.scope.build_units, "build-unit")
        if inferred is not None:
            declared.append(inferred.build_unit_id)
        if len(set(declared)) > 1:
            raise ValueError("accepted evidence build unit disagrees with source scope")
        if declared and declared[0] not in {item.build_unit_id for item in self.scope.build_units}:
            raise ValueError("accepted evidence names an unknown build unit")
        return declared[0] if declared else None

    def _component(self, entity: Mapping[str, Any]) -> str | None:
        location, payload = entity.get("location") or {}, entity.get("payload") or {}
        subject = payload.get("subject")
        graph_scope = payload.get("scope") or {}
        if location.get("ambiguous"):
            raise ValueError("accepted evidence source mapping is ambiguous")
        for owner in (payload, subject):
            if isinstance(owner, Mapping) and owner.get("component_ownership") not in (None, "owned"):
                raise ValueError("accepted evidence has shared, ambiguous or unresolved component ownership")
        path = location.get("path") or (subject.get("path") if isinstance(subject, Mapping) else None)
        path = path or payload.get("path")
        component = self._owner(path, self.scope.components, "component")
        declared = [value for value in (payload.get("component_id"), payload.get("component"),
                    subject.get("component_id") if isinstance(subject, Mapping) else None,
                    graph_scope.get("component_id") if isinstance(graph_scope, Mapping) else None)
                    if value is not None]
        if any(not isinstance(value, str) or not value for value in declared):
            raise ValueError("accepted evidence has an invalid component identity")
        if component:
            declared.append(component.component_id)
        elif path is not None and not path.startswith("@generated/"):
            raise ValueError("accepted evidence source has no component ownership")
        unit = self._build(entity)
        build = next((item for item in self.scope.build_units if item.build_unit_id == unit), None)
        owner = self._owner(build.root, self.scope.components, "component") if build else None
        if owner and component is None:
            declared.append(owner.component_id)
        if len(set(declared)) > 1:
            raise ValueError("accepted evidence component disagrees with source scope")
        if declared and declared[0] not in {item.component_id for item in self.scope.components}:
            raise ValueError("accepted evidence names an unknown component")
        return declared[0] if declared else None

    def _source(self, entity: Mapping[str, Any], *, limit: int = 16_777_216) -> bytes:
        location = entity["location"]
        self.metrics["attempts"] += 1
        data = read_source_bytes(self.core.run_root, self.core.target_root,
            target_snapshot=self.scope.target_snapshot, path=location["path"],
            sha256=location["file_sha256"], native=location.get("producer_location"), limit=limit)
        if (any(type(location[key]) is not int for key in ("start_byte", "end_byte", "start_line", "end_line"))
                or not 0 <= location["start_byte"] < location["end_byte"] <= len(data)
                or not 1 <= location["start_line"] <= location["end_line"] <= len(data.splitlines())):
            raise ValueError("accepted source span is outside verified content")
        return data

    def _subjects(self, data: bytes, sha: str, language: str) -> tuple[SourceSubject, ...]:
        if sha not in self._subject_cache:
            self._subject_cache[sha] = parse_subjects(data.decode("utf-8"), language=language)
        return self._subject_cache[sha]

    def materialize(self, identity: str, *, component_id: str,
                    locator: Mapping[str, Any] | None = None, max_lines: int | None = None) -> dict[str, Any]:
        max_lines = self.max_source_lines if max_lines is None else max_lines
        if type(max_lines) is not int or not 1 <= max_lines <= self.max_source_lines:
            raise ValueError("citation source line bound exceeds configured cap")
        entity = self._entity(identity)
        if self._component(entity) != component_id:
            raise ValueError("citation concerns a different or unresolved component")
        shard = self.shards[(entity["index"], entity["shard_id"])]
        location = entity.get("location")
        payload = entity.get("payload", {})
        gaps, truncated, source_subject = [], False, None
        if shard.get("gaps"):
            gaps.extend(redact(str(item))[0] for item in shard["gaps"])
        if location is not None:
            data = self._source(entity)
            lines = data.decode("utf-8").splitlines()
            first, last = (1, len(lines)) if entity["kind"] == "source_file" else (
                location["start_line"], location["end_line"])
            start, end = first, min(last, first + max_lines - 1)
            expected = {"kind": "source", "path": location["path"], "file_sha256": location["file_sha256"],
                        "lines": [start, end], "source_custody": location.get("producer_location")}
            if locator is not None:
                if (set(locator) != set(expected) or any(locator[key] != expected[key]
                        for key in expected if key != "lines")):
                    raise ValueError("citation source identity or custody differs from accepted evidence")
                span = locator.get("lines")
                if (not isinstance(span, list) or len(span) != 2 or any(type(n) is not int for n in span)
                        or not 1 <= span[0] <= span[1] <= len(lines)
                        or span[1] - span[0] + 1 > max_lines):
                    raise ValueError("citation source span is invalid")
                if entity["kind"] != "source_file" and (
                        span[0] < location["start_line"] or span[1] > location["end_line"]):
                    raise ValueError("citation span escapes its accepted subject")
                expected["lines"] = span
                start, end = span
            raw = "\n".join(lines[start - 1:end])
            language = subject_language(location["path"])
            if language is not None and entity["kind"] in _SOURCE_KINDS:
                try:
                    complete = [item for item in self._subjects(data, location["file_sha256"], language)
                                if (item.first, item.last) == (start, end)]
                except (SyntaxError, ValueError, RecursionError):
                    complete = []
                if complete:
                    subject = min(complete, key=lambda item: (item.kind != "module", item.name))
                    source_subject = {**subject.record(), "complete": True,
                                      "outside_lines": len(lines) - (end - start + 1)}
            private = False
            for line in lines[:start - 1]:
                if "-----BEGIN " in line and "PRIVATE KEY-----" in line:
                    private = True
                if "-----END " in line and "PRIVATE KEY-----" in line:
                    private = False
            excerpt, was_redacted = redact(("-----BEGIN PRIVATE KEY-----\n" if private else "") + raw)
            if private:
                excerpt = excerpt.split("\n", 1)[1]
                was_redacted = excerpt != raw
            category = ("declaration" if entity["index"] in _ROUTING_INDEXES else
                        "source" if entity["kind"] in _SOURCE_KINDS
                        else "scanner_observation" if entity["kind"] == "tool_observation" else "declaration")
            omitted = (start - first) + (last - end)
            if source_subject is not None and source_subject["outside_lines"]:
                gaps.append(f"complete source subject lines {start}-{end}; "
                            f"{source_subject['outside_lines']} file lines outside subject remain unassessed")
            elif omitted:
                gaps.append(f"source excerpt bounded to lines {start}-{end}; {omitted} accepted subject lines omitted")
                truncated = True
        else:
            field = next((key for key in ("result", "checks", "artifact", "headers", "hardening", "tag", "score")
                          if _meaningful(payload.get(key))), None)
            if field is None and entity["kind"] in {"component", "project", "build_action"} and any(
                    payload.get(key) for key in ("root", "build_system", "languages", "frameworks")):
                field = "component_id" if payload.get("component_id") else "build_unit_id" if payload.get("build_unit_id") else None
            if field is None:
                raise ValueError("accepted artifact/fact has no meaningful structured locator")
            expected = {"kind": "artifact" if entity["index"] == "artifacts" else "structured_fact",
                        "pointer": f"/payload/{field}", "artifact_sha256": payload.get("sha256")}
            if locator is not None and dict(locator) != expected:
                raise ValueError("citation artifact/fact locator differs from accepted content")
            raw = json.dumps(payload[field], sort_keys=True)
            excerpt = json.dumps(_redact_data(payload[field]), sort_keys=True)
            excerpt, text_redacted = redact(excerpt)
            was_redacted = text_redacted or excerpt != raw
            category = "declaration" if entity["index"] in {
                "components", "build", "documents", "inventory", *_ROUTING_INDEXES} else "static_fact"
            gaps.append("accepted structured metadata; not proof of implemented or deployed behavior")
        if entity["index"] in _ROUTING_INDEXES:
            gaps.append("tags, priorities and code graph are routing/context only, not control proof")
        build = self._build(entity)
        reference = {
            "schema": "appsec-review/owasp-evidence-reference/1", "run_id": self.scope.run_id,
            "target_snapshot": self.scope.target_snapshot, "component_id": component_id,
            "build_unit_id": build, "environment": "unestablished",
            "source_identity": identity, "entity_kind": entity["kind"],
            "publication": {"manifest_sha256": self.scope.manifest_sha256, "index": entity["index"],
                            "shard_id": entity["shard_id"], "sha256": shard["sha256"]},
            "locator": expected, "content_sha256": digest({
                "identity": identity, "payload": payload, "location": location,
                "locator": expected, "content": raw}),
        }
        if len(excerpt) > 16000:
            gaps.append(f"excerpt character cap reached; {len(excerpt) - 16000} redacted characters omitted")
            truncated = True
        self.metrics["truncations"] += int(truncated)
        return {
            "evidence_id": digest(reference), "reference": reference, "category": category,
            "excerpt": excerpt[:16000], "redaction": {"rule": REDACTION_RULE, "applied": was_redacted},
            "truncated": truncated, "limitations": gaps,
            "expansion": {"tool": "find", "identity": identity},
            **({"source_subject": source_subject} if source_subject is not None else {}),
        }

    def resolve(self, citation: Mapping[str, Any], *, component_id: str) -> dict[str, Any]:
        try:
            if citation.get("run_id") != self.scope.run_id or citation.get("target_snapshot") != self.scope.target_snapshot:
                raise ValueError("citation run/target isolation mismatch")
            value = self.materialize(str(citation.get("source_identity", "")), component_id=component_id,
                                     locator=citation.get("locator"))
            if value["reference"] != dict(citation):
                raise ValueError("citation publication, scope or recorded content identity changed")
            return value
        except (ValueError, OSError, UnicodeError):
            self.metrics["denials"] += 1
            raise


def prerequisite_binding(primary: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, Any]:
    """Bind already re-resolved C/C++ caller/callee context, not a call-graph or predicate proof."""
    first, second = primary["reference"], context["reference"]
    if any(first.get(key) != second.get(key) for key in
           ("run_id", "target_snapshot", "component_id", "build_unit_id", "environment")):
        raise ValueError("prerequisite context differs from the primary source scope")
    functions = []
    for record in (primary, context):
        source = record.get("source_subject", {})
        if (record.get("category") != "source" or source.get("language") != c_subjects.LANGUAGE
                or source.get("kind") != "function" or not source.get("complete")):
            raise ValueError("prerequisite context requires complete C/C++ source functions")
        name = source.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError("qualified source subjects require a semantic prerequisite adapter")
        scan = c_subjects.scan(record["excerpt"])
        if (scan.gaps or len(scan.functions) != 1 or scan.functions[0].kind != "function"
                or scan.functions[0].name != name):
            raise ValueError("prerequisite context has ambiguous or unresolved source definitions")
        functions.append(scan.functions[0])
    for caller_index, callee_index, kind in ((1, 0, "caller"), (0, 1, "callee")):
        records = (primary, context)
        callee = functions[callee_index]
        # Scoped/overloaded methods and indirect dispatch need an accepted semantic adapter.
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", callee.name):
            continue
        callee_text = c_subjects.blank(records[callee_index]["excerpt"])
        head = callee_text[:callee_text.find("{")]
        if (re.search(r"\bstatic\b", head)
                and first["locator"]["path"] != second["locator"]["path"]):
            continue
        caller_text = c_subjects.blank(records[caller_index]["excerpt"])
        body_start = caller_text.find("{") + 1
        body = caller_text[body_start:]
        call = re.search(r"(?<![\w.>:])\b" + re.escape(callee.name) + r"\s*\(", body)
        if call is None:
            continue
        if body[:call.start()].rstrip().endswith((".", "->", "::")):
            continue
        # A local declaration of that name would make even this contextual link ambiguous.
        shadow = re.compile(r"\b" + re.escape(callee.name) + r"\b")
        if shadow.search(caller_text[:body_start]) or shadow.search(body[:call.start()]):
            continue
        prefix = re.split(r"[;{}]", body[:call.start()])[-1].strip()
        words = prefix.replace("*", " ").replace("&", " ").split()
        if prefix != "return" and words and all(re.fullmatch(r"[A-Za-z_]\w*", word) for word in words):
            continue
        return {"kind": kind, "basis": "source_call_context; semantic binding remains analyst_assessed",
                "primary": dict(first), "context": dict(second), "callee_name": callee.name,
                "call_line": records[caller_index]["reference"]["locator"]["lines"][0]
                + caller_text.count("\n", 0, body_start + call.start())}
    raise ValueError("authentic evidence has no source-bound caller/callee prerequisite relationship")


def supported_source(source: Any) -> bool:
    """A recogniser reads Python and C/C++ sources (T-5013); every other language is a named gap."""
    return subject_language(source.path, source.language) is not None


def component_evidence(resolver: EvidenceResolver, component_id: str, files: Any,
                       settings: OwaspSettings) -> tuple[list[dict[str, Any]], list[str]]:
    """Bound discovery reads per component; delivery independently re-verifies selected sources."""
    supported = supported_source
    hints: dict[str, list[Mapping[str, Any]]] = {}
    extras, gaps = [], []
    bound = settings.max_discovery_files * 8
    for number, row in enumerate(resolver.scope.store.entities(
            tuple(resolver.shards.values()), limit=bound + 1)):
        if number == bound:
            gaps.append("accepted subject index scan cap reached; further locations omitted (count unknown)")
            break
        if not resolver._original(row) or row["kind"] in {"source_file", "component", "project"}:
            continue
        try:
            owner = resolver._component(row)
        except ValueError:
            gaps.append("accepted index record has ambiguous or conflicting ownership; 1 record omitted")
            continue
        if owner != component_id:
            continue
        location = row.get("location")
        if location and (row["kind"] in _SOURCE_KINDS or row["index"] == "graph"):
            if (not location.get("ambiguous")
                    and all(type(location.get(key)) is int for key in ("start_line", "end_line"))
                    and 1 <= location["start_line"] <= location["end_line"]):
                hints.setdefault(location["path"], []).append(location)
            else:
                gaps.append("accepted subject location is unresolved; 1 location omitted")
        elif row["index"] not in _ROUTING_INDEXES and row["kind"] not in _SOURCE_KINDS:
            if location is not None:
                gaps.append(f"{location['path']}: 1 located non-subject record omitted; "
                            "source evidence is selected through the bounded source inventory")
            else:
                extras.append(row["identity"])
    # First-party review (T-165 dispositions; run 2026-11-17-0003 D-owasp_control_assessment-1): sources the
    # configured dispositions place outside first_party (vendored, sdk, generated, test) are not subjects.
    # The exclusion is a named gap with its count; scanners and indexes still cover those trees.
    distinct = list({(source.path, source.identity): source for source in files}.values())
    excluded: dict[str, int] = {}
    for source in distinct:
        disposition = getattr(source, "disposition", FIRST_PARTY)
        if disposition != FIRST_PARTY:
            excluded[disposition] = excluded.get(disposition, 0) + 1
    if excluded:
        detail = ", ".join(f"{name} {count}" for name, count in sorted(excluded.items()))
        gaps.append(f"{sum(excluded.values())} accepted source files {FIRST_PARTY_EXCLUSION} excluded "
                    f"from subject selection ({detail}); their subjects are unassessed")
    ordered = sorted((source for source in distinct if getattr(source, "disposition", FIRST_PARTY) == FIRST_PARTY),
                     key=lambda source: (not supported(source), source.path not in hints, source.path, source.identity))
    omitted_files = max(0, len(ordered) - settings.max_discovery_files)
    if omitted_files:
        gaps.append(f"max_discovery_files reached; {omitted_files} accepted files omitted (subject count unknown)")
    remaining = settings.max_discovery_bytes
    evidence, omitted_subjects = [], 0
    for source in ordered[:settings.max_discovery_files]:
        entity = resolver._entity(source.identity)
        location = entity.get("location")
        if location is None or location["path"] != source.path:
            raise ValueError("accepted source inventory disagrees with original source location")
        try:
            owner = resolver._component(entity)
        except ValueError:
            gaps.append(f"{source.path}: ambiguous source ownership; 1 file omitted (subject count unknown)")
            continue
        if owner != component_id:
            gaps.append(f"{source.path}: unresolved source ownership; 1 file omitted (subject count unknown)")
            continue
        if not supported(source):
            gaps.append(f"{source.path}: unsupported source language; 1 file omitted (subject count unknown); "
                        f"source sha256 {location['file_sha256']}")
            continue
        try:
            data = resolver._source(entity, limit=remaining)
        except ValueError as exc:
            if str(exc) != "source exceeds excerpt verification bound":
                raise
            gaps.append(f"{source.path}: max_discovery_bytes reached; 1 file omitted (subject count unknown)")
            continue
        remaining -= len(data)
        language = subject_language(source.path, source.language)
        try:
            text = data.decode("utf-8")
            parsed = resolver._subjects(data, location["file_sha256"], language)
        except (UnicodeError, SyntaxError, ValueError, RecursionError):
            gaps.append(f"{source.path}: accepted {LANGUAGE_LABELS[language]} source parse failure; "
                        "1 file omitted (subject count unknown)")
            continue
        gaps.extend(f"{source.path}: {gap}" for gap in parse_gaps(text, language=language))
        verified_hints = [hint for hint in hints.get(source.path, ())
                          if hint["file_sha256"] == location["file_sha256"]
                          and hint["end_line"] <= len(text.splitlines())]
        if len(verified_hints) != len(hints.get(source.path, ())):
            raise ValueError("accepted subject index location disagrees with original source")
        selected, omitted = select_subjects(parsed, text, max_lines=settings.max_source_lines,
                                           hints=verified_hints, language=language)
        gaps.extend(f"{source.path}: {gap}" for gap in omitted)
        for subject in selected:
            if len(evidence) >= settings.max_evidence_per_component:
                omitted_subjects += 1
                continue
            locator = {"kind": "source", "path": source.path, "file_sha256": location["file_sha256"],
                       "lines": [subject.first, subject.last],
                       "source_custody": location.get("producer_location")}
            value = resolver.materialize(source.identity, component_id=component_id, locator=locator)
            evidence.append({"component_id": component_id, **value})
    if omitted_subjects:
        gaps.append(f"evidence cap reached; {omitted_subjects} complete recognized subjects omitted")
    extra_ids = sorted(set(extras))
    available = max(0, settings.max_evidence_per_component - len(evidence))
    if len(extra_ids) > available:
        gaps.append(f"evidence cap reached; {len(extra_ids) - available} accepted non-subject records omitted")
    for identity in extra_ids[:available]:
        try:
            value = resolver.materialize(identity, component_id=component_id)
        except (ValueError, OSError, UnicodeError) as exc:
            gaps.append(f"{identity}: {type(exc).__name__}: {exc}")
        else:
            evidence.append({"component_id": component_id, **value})
    return evidence, [f"{component_id}: {gap}" for gap in gaps]


def _routing_record(row: Mapping[str, Any]) -> dict[str, Any]:
    payload = row["payload"]
    name = row.get("name")
    return {
        "identity": row["identity"], "kind": row["kind"], "index": row["index"],
        # The entity name is the tag itself (closed vocabulary); the payload copy may be redacted.
        "name": name if isinstance(name, str) and _TAG_NAME.match(name) else None,
        "content_sha256": digest({"payload": payload, "location": row.get("location")}),
        "usage": "routing_only", "tag": _redact_data(payload.get("tag")),
        "basis": _redact_data(payload.get("basis")), "subject": _redact_data(payload.get("subject")),
        # tag-assignment/1 keeps the assignment id beside the subject; citations name it when present.
        "assignment_id": payload.get("assignment_id") if isinstance(payload.get("assignment_id"), str) else None,
        "evidence": _redact_data(payload.get("evidence", [])),
        "context": _redact_data({key: payload[key] for key in (
            "rank", "score", "scope", "family", "classification", "result", "source", "target",
            "guard", "sink", "entry_point", "frameworks", "language") if key in payload}),
    }


def _classifying(row: Mapping[str, Any]) -> bool:
    """A component-subject ``target:*`` or facet assignment: the records classification reads (T-5008)."""
    subject = row["payload"].get("subject")
    name = row.get("name")
    return (isinstance(subject, Mapping) and subject.get("kind") == "component"
            and isinstance(name, str) and bool(_TAG_NAME.match(name))
            and name.split(":", 1)[0] in _CLASSIFYING_NAMESPACES)


def accepted_inputs(core: RetrievalCore, settings: OwaspSettings, *, manifest_path: Path) -> dict[str, Any]:
    scope = accept_manifest(core.run_root, manifest_path=manifest_path,
                            manifest_sha256=core.manifest_sha256, dispositions=settings.source_dispositions,
                            selection=getattr(core, "selection", None))
    resolver = EvidenceResolver(core, scope, max_source_lines=settings.max_source_lines)
    components, evidence, limitations = [], [], []
    for (index, shard_id), shard in sorted(resolver.shards.items()):
        limitations.extend(f"{index}/{shard_id}: {redact(str(gap))[0]}" for gap in shard.get("gaps", ()))
    gaps: list[str] = []
    routes: dict[str, list[dict[str, Any]]] = {item.component_id: [] for item in scope.components}
    context: dict[str, list[dict[str, Any]]] = {item.component_id: [] for item in scope.components}
    # D1: classification reads tag_assignment rows of the tags index under their own cap. A dropped
    # component-level target/facet record is a gap (the class cannot be read), never a limitation.
    tag_shards = tuple(item for key, item in resolver.shards.items() if key[0] == "tags")
    tag_limit = settings.max_tag_records
    tag_scan_complete = True
    for number, row in enumerate(scope.store.entities(tag_shards, kinds=("tag_assignment",), limit=tag_limit + 1)):
        if number == tag_limit:
            tag_scan_complete = False
            gaps.append("tag index scan cap reached; target class and facet records may be unread (count unknown)")
            break
        if not resolver._original(row):
            continue
        try:
            owner = resolver._component(row)
        except ValueError:
            limitations.append("accepted routing record has ambiguous or conflicting ownership")
            continue
        if owner in routes:
            routes[owner].append({**_routing_record(row), "classifies_component": _classifying(row)})
    # Priority and graph rows are context for packages; their cap is a limitation, not a gap.
    context_shards = tuple(item for key, item in resolver.shards.items() if key[0] in _CONTEXT_INDEXES)
    scan_limit = settings.max_evidence_per_component * max(1, len(scope.components)) * 4
    for number, row in enumerate(scope.store.entities(context_shards, limit=scan_limit + 1)):
        if number == scan_limit:
            limitations.append("routing index scan cap reached; further priority/graph context records "
                               "may be omitted (count unknown)")
            break
        if not resolver._original(row):
            continue
        try:
            owner = resolver._component(row)
        except ValueError:
            limitations.append("accepted routing record has ambiguous or conflicting ownership")
            continue
        if owner not in context or len(context[owner]) > settings.max_evidence_per_component:
            continue
        context[owner].append(_routing_record(row))
    # Inventory walks are over accepted indices, never the target tree, and stop at named bounds.
    for component in sorted(scope.components, key=lambda item: item.component_id):
        raw = resolver._entity(component.identity)
        payload = raw["payload"]
        refs = []
        try:
            refs.append(resolver.materialize(component.identity, component_id=component.component_id)["reference"])
        except ValueError as exc:
            limitations.append(f"{component.component_id}: {exc}")
        files = []
        for source in scope.source_files:
            try:
                owner = resolver._owner(source.path, scope.components, "component")
            except ValueError:
                limitations.append(f"{component.component_id}: ambiguous source ownership excluded")
                continue
            if owner == component:
                files.append(source)
        cid = component.component_id
        cap = settings.max_evidence_per_component
        classifying = [item for item in routes[cid] if item["classifies_component"]]
        routing = (classifying + [item for item in routes[cid] if not item["classifies_component"]])[:cap]
        dropped_classifying = max(0, len(classifying) - cap)
        if dropped_classifying:
            gaps.append(f"{cid}: tag record cap omitted {dropped_classifying} target class or facet records; "
                        "the component classification is unread")
        elif len(routes[cid]) > len(routing):
            limitations.append(f"{cid}: tag record cap reached; {len(routes[cid]) - len(routing)} "
                               "file-level tag records omitted")
        if not tag_scan_complete:
            gaps.append(f"{cid}: tag index scan incomplete; target class and facet records may be unread")
        graph_context = context[cid][:cap]
        if len(context[cid]) > len(graph_context):
            limitations.append(f"{cid}: routing cap reached; at least 1 priority/graph context record omitted")
        selected, component_gaps = component_evidence(resolver, cid, files, settings)
        evidence.extend(selected)
        # Sources outside the first-party disposition are excluded coverage (a gap), not a method limitation.
        gaps.extend(item for item in component_gaps if FIRST_PARTY_EXCLUSION in item)
        limitations.extend(item for item in component_gaps if FIRST_PARTY_EXCLUSION not in item)
        # D2: a component whose accepted sources no recogniser reads has no subjects to assess; the
        # applicability rows name that cause instead of an unresolved class (T-5011/T-5013).
        supported_files = sum(1 for source in files if supported_source(source))
        languages = sorted({subject_language(source.path, source.language) for source in files} - {None})
        source_support = {"supported_files": supported_files, "unsupported_files": len(files) - supported_files,
                          "evidence_count": len(selected), "languages": languages,
                          "recognisers": "python, c-cpp (T-5013)"}
        tag_subjects: dict[str, set[str]] = {}
        for item in routing:
            if isinstance(item["tag"], str):
                subject = item["subject"] if isinstance(item["subject"], Mapping) else {}
                tag_subjects.setdefault(item["tag"], set()).add(subject.get("logical_id") or item["identity"])
        tag_cloud = {
            "usage": "routing_only", "counts": {tag: len(subjects) for tag, subjects in sorted(tag_subjects.items())},
            "count_metric": "distinct_subjects", "counts_are_lower_bounds": True,
            "reading_rule": "Absent tags are unknown, never proof of absence.",
        }
        components.append({
            "target_id": scope.target_snapshot, "project_id": str(payload.get("project_id") or component.identity),
            "component_id": component.component_id, "paths": sorted(source.path for source in files),
            "languages": sorted({source.language for source in files if source.language}),
            "frameworks": _redact_data(list(payload.get("frameworks") or ())),
            "tags": _redact_data(list(payload.get("tags") or ())),
            "evidence": refs, "run_id": scope.run_id, "root": component.root,
            "routing_context": routing,
            "graph_context": graph_context,
            "tag_cloud": tag_cloud,
            "source_support": source_support,
            "tag_records_omitted": dropped_classifying,
            "tag_scan_complete": tag_scan_complete,
            "gaps": [item for item in gaps if item.startswith(cid + ":")],
            "evidence_fingerprint": digest({
                "evidence": [_evidence_content(item) for item in evidence
                             if item["component_id"] == component.component_id],
                "routing_context": routing, "graph_context": graph_context, "tag_cloud": tag_cloud,
                "source_support": source_support,
                "discovery_inventory": sorted((source.path, source.identity) for source in files),
                "coverage": [item for item in limitations if item.startswith(component.component_id + ":")],
                "rules": {"binding": EVIDENCE_RULE, "selection": SELECTION_RULE, "redaction": REDACTION_RULE,
                          "max_source_lines": settings.max_source_lines,
                          "max_discovery_files": settings.max_discovery_files,
                          "max_discovery_bytes": settings.max_discovery_bytes,
                          "max_evidence_per_component": settings.max_evidence_per_component},
            }),
            "limitations": [item for item in limitations if item.startswith(component.component_id + ":")],
        })
    scope.verify()
    return {
        "components": components, "evidence": evidence, "input_mode": "accepted_indexes",
        "retrieval_manifest": {"path": scope.manifest_path.relative_to(core.run_root).as_posix(),
                               "sha256": scope.manifest_sha256, "target_snapshot": scope.target_snapshot,
                               **({"view_identity": scope.view_identity,
                                   "selection_sha256": scope.selection.sha256,
                                   "excluded_shards": [{"name": item["name"], "shard_id": item["shard_id"],
                                       "producer": item["producer"]["job"], "disposition": "not_selected"}
                                       for item in scope.excluded_shards]}
                                  if getattr(scope, "selection", None) is not None else {})},
        "limitations": limitations, "gaps": gaps, "retrieval_metrics": dict(resolver.metrics),
    }
