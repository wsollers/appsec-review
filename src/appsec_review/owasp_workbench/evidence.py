"""Run-pinned evidence bundles and citation re-resolution using the shared retrieval boundary."""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Mapping

from appsec_review.config.owasp import OwaspSettings
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.retrieval.model import LogicalIdentity
from appsec_review.retrieval.source_resolution import read_source_bytes
from appsec_review.review.scope import AcceptedScope, accept_manifest
from appsec_review.review.secret_redaction import REDACTION_RULE, redact_source_line
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
_SECRET = re.compile(r"(?i)(?:api[_-]?key|password|passwd|secret|credential|private[_-]?key|"
                     r"access[_-]?token)\s*[:=]|(?:sk_live_|gh[pousr]_|AKIA)[A-Za-z0-9]")


def redact(text: str) -> tuple[str, bool]:
    lines, changed, private = [], False, False
    for line in text.splitlines():
        if "-----BEGIN " in line and "PRIVATE KEY-----" in line:
            private = True
        value = redact_source_line(line, whole_line=private) if private or _SECRET.search(line) else line
        lines.append(value)
        changed = changed or value != line
        if "-----END " in line and "PRIVATE KEY-----" in line:
            private = False
    return "\n".join(lines), changed


class EvidenceResolver:
    def __init__(self, core: RetrievalCore, scope: AcceptedScope):
        self.core, self.scope = core, scope
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
        LogicalIdentity.parse(identity)
        result = self.query("find", identity=identity, indexes=UPSTREAM_INDEXES, limit=2)
        values = [item for item in result["results"]
                  if (item["index"], item["shard_id"]) in self.shards]
        if len(values) != 1 or result["truncated"]:
            raise ValueError("citation is missing, ambiguous or outside accepted upstream publications")
        return values[0]

    def _component(self, entity: Mapping[str, Any]) -> str | None:
        location, payload = entity.get("location") or {}, entity.get("payload") or {}
        component = self.scope.component_for(location.get("path"))
        declared = payload.get("component_id", payload.get("component"))
        subject = payload.get("subject")
        if declared is None and isinstance(subject, Mapping):
            declared = subject.get("component_id")
        if declared is not None:
            if component is not None and declared != component.component_id:
                raise ValueError("accepted evidence component disagrees with source scope")
            return str(declared)
        if component:
            return component.component_id
        unit = payload.get("build_unit_id")
        build = next((item for item in self.scope.build_units if item.build_unit_id == unit), None)
        component = self.scope.component_for(build.root) if build else None
        return component.component_id if component else None

    def materialize(self, identity: str, *, component_id: str,
                    locator: Mapping[str, Any] | None = None, max_lines: int = 120) -> dict[str, Any]:
        entity = self._entity(identity)
        if self._component(entity) != component_id:
            raise ValueError("citation concerns a different or unresolved component")
        shard = self.shards[(entity["index"], entity["shard_id"])]
        location = entity.get("location")
        payload = entity.get("payload", {})
        gaps = []
        if shard.get("gaps"):
            gaps.extend(str(item) for item in shard["gaps"])
        if location is not None:
            self.metrics["attempts"] += 1
            data = read_source_bytes(self.core.run_root, self.core.target_root,
                target_snapshot=self.scope.target_snapshot, path=location["path"],
                sha256=location["file_sha256"], native=location.get("producer_location"))
            lines = data.decode("utf-8").splitlines()
            if (not 0 <= location["start_byte"] <= location["end_byte"] <= len(data)
                    or not 1 <= location["start_line"] <= location["end_line"] <= len(lines)):
                raise ValueError("accepted source span is outside verified content")
            start = int(location["start_line"])
            end = min(len(lines), start + max_lines - 1) if entity["kind"] == "source_file" else min(
                int(location["end_line"]), start + max_lines - 1)
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
            excerpt, was_redacted = redact(raw)
            category = ("source" if entity["kind"] in {"source_file", "source_span", "symbol", "ast_node", "ir_entity"}
                        else "scanner_observation" if entity["kind"] == "tool_observation" else "declaration")
            if location.get("ambiguous"):
                gaps.append("ambiguous source mapping")
            if entity["kind"] == "source_file" and end < len(lines):
                gaps.append(f"source excerpt bounded to lines {start}-{end}; {len(lines) - end} trailing lines omitted")
                self.metrics["truncations"] += 1
        else:
            # Structured accepted facts and artifact metadata retain a meaningful record locator.
            field = next((key for key in ("result", "checks", "artifact", "sha256", "component_id", "build_unit_id",
                                         "subject", "language")
                          if key in payload), None)
            if field is None:
                raise ValueError("accepted artifact/fact has no meaningful structured locator")
            expected = {"kind": "artifact" if entity["index"] == "artifacts" else "structured_fact",
                        "pointer": f"/payload/{field}", "artifact_sha256": payload.get("sha256")}
            if locator is not None and dict(locator) != expected:
                raise ValueError("citation artifact/fact locator differs from accepted content")
            raw = json.dumps(payload[field], sort_keys=True)
            excerpt, was_redacted = redact(raw)
            category = "declaration" if entity["index"] in {
                "components", "documents", "inventory", "tags", "priority"} else "static_fact"
            gaps.append("accepted structured metadata; not proof of implemented or deployed behavior")
        unit = self.scope.build_unit_for(location["path"]) if location else None
        build = unit.build_unit_id if unit else payload.get("build_unit_id")
        reference = {
            "schema": "appsec-review/owasp-evidence-reference/1", "run_id": self.scope.run_id,
            "target_snapshot": self.scope.target_snapshot, "component_id": component_id,
            "build_unit_id": build, "environment": "unestablished",
            "source_identity": identity, "entity_kind": entity["kind"],
            "publication": {"manifest_sha256": self.scope.manifest_sha256, "index": entity["index"],
                            "shard_id": entity["shard_id"], "sha256": shard["sha256"]},
            "locator": expected, "content_sha256": digest({
                "identity": identity, "payload": payload, "locator": expected, "content": raw}),
        }
        return {
            "evidence_id": digest(reference), "reference": reference, "category": category,
            "excerpt": excerpt[:16000], "redaction": {"rule": REDACTION_RULE, "applied": was_redacted},
            "truncated": len(excerpt) > 16000, "limitations": gaps,
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
    resolver = EvidenceResolver(core, scope)
    components, evidence, limitations = [], [], []
    tag_records = list(scope.store.entities(scope.store.select(index="tags"), kinds=("tag_assignment",)))
    # Metadata walks are over the compact accepted inventory, never over the target tree.
    for component in scope.components:
        raw = resolver._entity(component.identity)
        payload = raw["payload"]
        refs = []
        try:
            refs.append(resolver.materialize(component.identity, component_id=component.component_id)["reference"])
        except ValueError as exc:
            limitations.append(f"{component.component_id}: {exc}")
        files = [source for source in scope.source_files if scope.component_for(source.path) == component]
        tags = [row for row in tag_records if resolver._component(row) == component.component_id]
        routing = [{"identity": row["identity"], "tag": row["payload"].get("tag"),
                    "basis": row["payload"].get("basis"), "subject": row["payload"].get("subject"),
                    "evidence": row["payload"].get("evidence", [])} for row in tags]
        candidates = [source.identity for source in files]
        remaining = settings.max_evidence_per_component - len(candidates)
        if remaining > 0:
            for shard in scope.shards:
                if (shard["name"], shard["shard_id"]) not in resolver.shards or shard["name"] in {"source", "components"}:
                    continue
                for row in scope.store.entities((shard,)):
                    if resolver._component(row) == component.component_id:
                        candidates.append(row["identity"])
                        if len(candidates) > settings.max_evidence_per_component:
                            break
                if len(candidates) > settings.max_evidence_per_component:
                    break
        unique = list(dict.fromkeys(candidates))
        omitted = max(0, len(unique) - settings.max_evidence_per_component)
        for identity in unique[:settings.max_evidence_per_component]:
            try:
                value = resolver.materialize(identity, component_id=component.component_id,
                                             max_lines=settings.max_source_lines)
                evidence.append({"component_id": component.component_id, **value})
            except (ValueError, OSError, UnicodeError) as exc:
                limitations.append(f"{component.component_id}/{identity}: {type(exc).__name__}: {exc}")
        if omitted:
            limitations.append(f"{component.component_id}: evidence cap reached; further accepted records omitted")
        components.append({
            "target_id": scope.target_snapshot, "project_id": str(payload.get("project_id") or component.identity),
            "component_id": component.component_id, "paths": [source.path for source in files],
            "languages": sorted({source.language for source in files if source.language}),
            "frameworks": list(payload.get("frameworks") or ()), "tags": list(payload.get("tags") or ()),
            "evidence": refs, "run_id": scope.run_id, "root": component.root,
            "routing_context": routing,
            "evidence_fingerprint": digest([item for item in evidence if item["component_id"] == component.component_id]),
            "limitations": [item for item in limitations if item.startswith(component.component_id + ":")],
        })
    return {
        "components": components, "evidence": evidence, "input_mode": "accepted_indexes",
        "retrieval_manifest": {"path": scope.manifest_path.relative_to(core.run_root).as_posix(),
                               "sha256": scope.manifest_sha256, "target_snapshot": scope.target_snapshot},
        "limitations": limitations, "retrieval_metrics": dict(resolver.metrics),
    }
