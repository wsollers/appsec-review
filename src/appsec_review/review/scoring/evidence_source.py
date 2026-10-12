"""Accepted-manifest evidence for scoring factors.

:class:`AcceptedEvidenceSource` is the scoring stage's :class:`~.factors.EvidenceSource`. It
re-resolves each counted relation's cited entity through the bounded retrieval core, exactly as
``review/evidence.py`` resolved it at validation time, and accepts the payload only when the
re-resolved content hash equals the relation's ``content_sha256``. A changed or vanished entity is
reported as unresolved, so its payload-derived factor becomes missing rather than silently
re-read. Accepted security-tag assignments come from the accepted ``security_tagging`` shards,
indexed once by subject and component; no target tree is scanned.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping

from appsec_review.retrieval.core import RetrievalCore
from appsec_review.review.evidence import _content_record
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import EvidenceRelation
from appsec_review.review.scope import AcceptedScope
from appsec_review.review.scoring.factors import ResolvedEntity, TagAssignment

TAGS_PRODUCER_UNAVAILABLE = "the security_tagging producer has no accepted shard in this run"


class AcceptedEvidenceSource:
    def __init__(self, core: RetrievalCore, scope: AcceptedScope) -> None:
        self._core = core
        self._scope = scope
        self._component_ids = {item.identity: item.component_id for item in scope.components}
        self.tags_unavailable_reason = TAGS_PRODUCER_UNAVAILABLE
        shards = scope.producer("security_tagging").shards
        self._by_subject: dict[str, list[TagAssignment]] | None = None
        self._by_component: dict[str, list[TagAssignment]] = defaultdict(list)
        if shards:
            self._by_subject = defaultdict(list)
            for row in scope.store.entities(shards, kinds=("tag_assignment",)):
                payload = row["payload"]
                subject = payload.get("subject") if isinstance(payload.get("subject"), Mapping) else {}
                tag, basis = payload.get("tag"), payload.get("basis")
                if not isinstance(tag, str) or not isinstance(basis, str):
                    continue
                identity = str(row["identity"])
                if isinstance(subject.get("logical_id"), str):
                    self._by_subject[subject["logical_id"]].append(TagAssignment(identity, tag, basis, "entity"))
                if isinstance(subject.get("component_id"), str):
                    self._by_component[subject["component_id"]].append(
                        TagAssignment(identity, tag, basis, "component"))

    def _component(self, path: str | None, payload: Mapping[str, Any]) -> str | None:
        scope = payload.get("scope") if isinstance(payload.get("scope"), Mapping) else {}
        if isinstance(scope.get("component_id"), str) and scope["component_id"]:
            return scope["component_id"]
        component = self._scope.component_for(path)
        return component.component_id if component is not None else None

    def resolve(self, relation: EvidenceRelation) -> ResolvedEntity | None:
        found = self._core.find(identity=relation.entity_id, limit=1)
        if not found["results"]:
            return None
        entity = found["results"][0]
        if entity.get("identity") != relation.entity_id or entity.get("kind") != relation.entity_kind:
            return None
        excerpt: str | None = None
        if entity.get("location") is not None:
            response = self._core.read_excerpt(identity=relation.entity_id, context_lines=0)
            if not response["results"]:
                return None
            excerpt = str(response["results"][0]["excerpt"])
        if sha256_hex(_content_record(entity, excerpt)) != relation.content_sha256:
            return None
        payload = entity.get("payload") if isinstance(entity.get("payload"), Mapping) else {}
        location = entity.get("location") if isinstance(entity.get("location"), Mapping) else {}
        path = str(location["path"]) if location.get("path") else None
        return ResolvedEntity(relation.entity_id, str(entity["kind"]), payload, path, self._component(path, payload))

    def tags(self, anchors: set[str], paths: set[str], components: set[str]) -> tuple[TagAssignment, ...] | None:
        if self._by_subject is None:
            return None
        owners = set(components)
        owners |= {self._component_ids[item] for item in anchors if item in self._component_ids}
        owners |= {component.component_id for path in paths if (component := self._scope.component_for(path))}
        found: dict[str, TagAssignment] = {}
        for anchor in sorted(anchors):
            for item in self._by_subject.get(anchor, ()):
                found.setdefault(item.assignment_id, item)
        for owner in sorted(owners):
            for item in self._by_component.get(owner, ()):
                found.setdefault(item.assignment_id, item)
        return tuple(found[key] for key in sorted(found))


__all__ = ["AcceptedEvidenceSource", "TAGS_PRODUCER_UNAVAILABLE"]
