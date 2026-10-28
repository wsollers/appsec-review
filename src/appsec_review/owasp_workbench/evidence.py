"""Run-pinned evidence bundles and citation re-resolution using the shared retrieval boundary."""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Mapping

from appsec_review.config.owasp import OwaspSettings
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.retrieval.model import LogicalIdentity, normalize_relative_path
from appsec_review.retrieval.source_resolution import read_source_bytes
from appsec_review.review.scope import AcceptedScope, accept_manifest
from appsec_review.review.secret_redaction import REDACTION_RULE, placeholder
from .standards import digest


UPSTREAM_JOBS = (
    "job_target_analysis_plan", "job_target_catalog", "job_target_documents", "job_language_build",
    "job_project_build", "job_artifact_indexing", "job_artifact_security_analysis",
    "job_evidence_collection", "job_cpp_compiled_analysis", "job_clang_static_analysis",
    "job_cpp_symbol_index", "job_cpg_analysis", "job_svf_alias_analysis",
    "job_post_build_security_assessment", "job_tree_sitter_ast", "job_codeql_analysis",
    "job_security_tagging", "job_review_prioritization", "job_code_graph_index",
)
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
EVIDENCE_RULE = "appsec-review/owasp-evidence-binding/1"


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
                or core.manifest["target_snapshot"] != scope.target_snapshot):
            raise ValueError("evidence resolver run/target/manifest isolation mismatch")
        self.core, self.scope = core, scope
        self.max_source_lines = max_source_lines
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
        kind = LogicalIdentity.parse(identity).kind.value
        values, cursor = [], None
        # A logical identity occurs at most once in each physical shard. Pagination is not ambiguity.
        for _ in range(len(self.scope.shards) + 1):
            result = self.query("find", identity=identity, indexes=UPSTREAM_INDEXES,
                                limit=min(self.core.limits.max_results, max(1, len(self.scope.shards))),
                                cursor=cursor)
            if result["truncated"]:
                raise ValueError("citation lookup was truncated")
            for item in result["results"]:
                shard = self.shards.get((item["index"], item["shard_id"]))
                if shard is None:
                    continue
                # Bind the original indexed record, not retrieval's lossy display sanitization.
                with self.core._database(shard, self.core.clock() + self.core.limits.timeout_ms / 1000) as database:
                    row = database.execute("SELECT payload_json FROM entities WHERE identity=?", (identity,)).fetchone()
                item = {**item, "payload": json.loads(row["payload_json"])}
                if self._original(item):
                    values.append(item)
            cursor = result.get("pagination", {}).get("next_cursor")
            if not cursor:
                break
        else:
            raise ValueError("citation lookup exceeded accepted shard bound")
        original = _AUTHORITATIVE_INDEX.get(kind)
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
        gaps, truncated = [], False
        if shard.get("gaps"):
            gaps.extend(redact(str(item))[0] for item in shard["gaps"])
        if location is not None:
            self.metrics["attempts"] += 1
            data = read_source_bytes(self.core.run_root, self.core.target_root,
                target_snapshot=self.scope.target_snapshot, path=location["path"],
                sha256=location["file_sha256"], native=location.get("producer_location"))
            lines = data.decode("utf-8").splitlines()
            if (any(type(location[key]) is not int for key in ("start_byte", "end_byte", "start_line", "end_line"))
                    or not 0 <= location["start_byte"] < location["end_byte"] <= len(data)
                    or not 1 <= location["start_line"] <= location["end_line"] <= len(lines)):
                raise ValueError("accepted source span is outside verified content")
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
            if omitted:
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


def accepted_inputs(core: RetrievalCore, settings: OwaspSettings, *, manifest_path: Path) -> dict[str, Any]:
    scope = accept_manifest(core.run_root, manifest_path=manifest_path,
                            manifest_sha256=core.manifest_sha256)
    resolver = EvidenceResolver(core, scope, max_source_lines=settings.max_source_lines)
    components, evidence, limitations = [], [], []
    for (index, shard_id), shard in sorted(resolver.shards.items()):
        limitations.extend(f"{index}/{shard_id}: {redact(str(gap))[0]}" for gap in shard.get("gaps", ()))
    routes: dict[str, list[dict[str, Any]]] = {item.component_id: [] for item in scope.components}
    routing_shards = tuple(item for key, item in resolver.shards.items() if key[0] in _ROUTING_INDEXES)
    scan_limit = settings.max_evidence_per_component * max(1, len(scope.components)) * 4
    for number, row in enumerate(scope.store.entities(routing_shards, limit=scan_limit + 1)):
        if number == scan_limit:
            limitations.append("routing index scan cap reached; further routing records may be omitted (count unknown)")
            break
        if not resolver._original(row):
            continue
        try:
            owner = resolver._component(row)
        except ValueError:
            limitations.append("accepted routing record has ambiguous or conflicting ownership")
            continue
        if owner not in routes:
            continue
        if len(routes[owner]) > settings.max_evidence_per_component:
            continue
        payload = row["payload"]
        routes[owner].append({
            "identity": row["identity"], "kind": row["kind"], "index": row["index"],
            "content_sha256": digest({"payload": payload, "location": row.get("location")}),
            "usage": "routing_only", "tag": _redact_data(payload.get("tag")),
            "basis": _redact_data(payload.get("basis")), "subject": _redact_data(payload.get("subject")),
            "evidence": _redact_data(payload.get("evidence", [])),
            "context": _redact_data({key: payload[key] for key in (
                "rank", "score", "scope", "family", "classification", "result", "source", "target",
                "guard", "sink", "entry_point", "frameworks", "language") if key in payload}),
        })
    # Inventory walks are over accepted indices, never the target tree, and stop at named bounds.
    for component in scope.components:
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
        routing = routes[component.component_id][:settings.max_evidence_per_component]
        if len(routes[component.component_id]) > len(routing):
            limitations.append(f"{component.component_id}: routing cap reached; at least 1 routing record omitted")
        candidates = dict.fromkeys(source.identity for source in files)
        inspected = 0
        stopped = False
        if len(candidates) <= settings.max_evidence_per_component:
            for shard in scope.shards:
                if (shard["name"], shard["shard_id"]) not in resolver.shards or shard["name"] in {"source", "components"}:
                    continue
                for row in scope.store.entities((shard,), limit=scan_limit - inspected + 1):
                    if inspected == scan_limit:
                        stopped = True
                        break
                    inspected += 1
                    if not resolver._original(row):
                        continue
                    try:
                        owner = resolver._component(row)
                    except ValueError:
                        continue
                    if owner == component.component_id:
                        candidates[row["identity"]] = None
                        if len(candidates) > settings.max_evidence_per_component:
                            break
                if stopped or len(candidates) > settings.max_evidence_per_component:
                    break
        unique = list(candidates)
        omitted = max(0, len(unique) - settings.max_evidence_per_component)
        for identity in unique[:settings.max_evidence_per_component]:
            try:
                value = resolver.materialize(identity, component_id=component.component_id,
                                             max_lines=settings.max_source_lines)
                evidence.append({"component_id": component.component_id, **value})
            except (ValueError, OSError, UnicodeError) as exc:
                limitations.append(f"{component.component_id}/{identity}: {type(exc).__name__}: {exc}")
        if omitted:
            limitations.append(f"{component.component_id}: evidence cap reached; at least {omitted} further accepted records omitted")
        if stopped:
            limitations.append(f"{component.component_id}: accepted index scan cap reached; further evidence may be omitted (count unknown)")
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
            "component_id": component.component_id, "paths": [source.path for source in files],
            "languages": sorted({source.language for source in files if source.language}),
            "frameworks": _redact_data(list(payload.get("frameworks") or ())),
            "tags": _redact_data(list(payload.get("tags") or ())),
            "evidence": refs, "run_id": scope.run_id, "root": component.root,
            "routing_context": routing,
            "tag_cloud": tag_cloud,
            "evidence_fingerprint": digest({
                "evidence": [_evidence_content(item) for item in evidence
                             if item["component_id"] == component.component_id],
                "routing_context": routing, "tag_cloud": tag_cloud,
                "rules": {"binding": EVIDENCE_RULE, "redaction": REDACTION_RULE,
                          "max_source_lines": settings.max_source_lines,
                          "max_evidence_per_component": settings.max_evidence_per_component},
            }),
            "limitations": [item for item in limitations if item.startswith(component.component_id + ":")],
        })
    scope.verify()
    return {
        "components": components, "evidence": evidence, "input_mode": "accepted_indexes",
        "retrieval_manifest": {"path": scope.manifest_path.relative_to(core.run_root).as_posix(),
                               "sha256": scope.manifest_sha256, "target_snapshot": scope.target_snapshot},
        "limitations": limitations, "retrieval_metrics": dict(resolver.metrics),
    }
