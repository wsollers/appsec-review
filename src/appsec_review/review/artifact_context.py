"""Artifact-local scan and build provenance from accepted indexes, never family-wide coverage."""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from appsec_review.retrieval.observations import RECORD_KIND_SUMMARY, scanner_of
from appsec_review.review.lead_families import ARTIFACT_KINDS, Lead
from appsec_review.review.models import IntegrityError
from appsec_review.review.scope import AcceptedScope, PRODUCERS, ScopeGap, sorted_gaps
from appsec_review.review.units import ContextEntry, context_entry


class ArtifactContext:
    def __init__(self, scope: AcceptedScope):
        self.entities: dict[str, Mapping[str, Any]] = {}
        self.relations: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        self.scans: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        self.commands: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        shards = scope.select(lambda shard: shard["name"] in {"artifacts", "build"}
                              or PRODUCERS["artifact_scanner"](shard))
        summaries = {}
        for row in scope.store.entities(shards):
            if row["kind"] in ARTIFACT_KINDS or row["kind"] == "build_action":
                previous = self.entities.get(row["identity"])
                if previous is None:
                    self.entities[row["identity"]] = row
                else:
                    payload = dict(previous["payload"])
                    for key in ("path", "workspace_path", "sha256", "build_unit_id"):
                        value = row["payload"].get(key)
                        if value is not None:
                            if payload.get(key) not in (None, value):
                                raise IntegrityError(f"accepted artifact identity has conflicting {key}: "
                                                     f"{row['identity']}")
                            payload[key] = value
                    self.entities[row["identity"]] = {**previous, "payload": payload}
            payload = row["payload"]
            if payload.get("record_kind") == RECORD_KIND_SUMMARY:
                summaries[row["identity"]] = row
        for relation in scope.store.relations(shards, kinds=("OBSERVED_AT", "GENERATED_FROM", "LINKS_INTO")):
            if relation["kind"] == "OBSERVED_AT":
                summary = summaries.get(relation["source_id"])
                if summary is not None and relation["exact"]:
                    self.scans[relation["target_id"]].append(summary)
            elif relation["kind"] == "GENERATED_FROM":
                self.relations[relation["source_id"]].append(relation)
            else:
                for subject in {relation["source_id"], relation["target_id"]}:
                    self.relations[subject].append(relation)
        facts = scope.select(lambda shard: shard["name"] == "precomputed"
                             and (shard.get("producer") or {}).get("query_set") == "build_provenance")
        for row in scope.store.entities(facts, kinds=("precomputed_fact",)):
            payload = row["payload"]
            result = payload.get("result") or {}
            if payload.get("fact_type") == "build_action" and isinstance(result.get("build_action_id"), str):
                self.commands[result["build_action_id"]].append(row)

    def for_lead(self, lead: Lead, *, limit: int
                 ) -> tuple[list[dict[str, Any]], list[ContextEntry], tuple[ScopeGap, ...]]:
        records, entries, gaps = [], [], []
        for identity, role in lead.related:
            if role != "artifact" or identity not in self.entities:
                continue
            row = self.entities[identity]
            if row["kind"] == "evidence_artifact":
                continue
            payload = row["payload"]
            record = {
                "identity": identity, "name": row["name"],
                "path": payload.get("path"), "workspace_path": payload.get("workspace_path"),
                "sha256": payload.get("sha256"), "build_unit_id": payload.get("build_unit_id"),
                "provenance": [], "provenance_omitted": 0,
            }
            entries.append(context_entry(identity, "artifact"))
            # A scan's own gaps qualify only this artifact and this scanner, not its siblings.
            for scan in self.scans.get(identity, ()):
                scan_payload = scan["payload"]
                for gap in scan_payload.get("gaps", ()):
                    if isinstance(gap, str) and gap:
                        gaps.append(ScopeGap(scanner_of(scan_payload), identity, "partial", gap))
            relations = {(r["kind"], r["source_id"], r["target_id"], r["exact"], r["confidence"],
                          r["ambiguity"] or ""): r for r in self.relations.get(identity, ())}
            record["provenance_omitted"] = max(0, len(relations) - limit)
            if record["provenance_omitted"]:
                gaps.append(ScopeGap("artifact_provenance", identity, "truncated",
                                     f"{record['provenance_omitted']} related build/link records omitted"))
            for key in sorted(relations)[:limit]:
                relation = relations[key]
                other_id = (relation["target_id"] if relation["source_id"] == identity
                            else relation["source_id"])
                other = self.entities.get(other_id)
                if other is None:
                    gaps.append(ScopeGap("artifact_provenance", identity, "unavailable",
                                         f"accepted {relation['kind']} endpoint {other_id} is unavailable"))
                    continue
                entries.append(context_entry(other_id, "build" if other["kind"] == "build_action" else "artifact"))
                other_payload = other["payload"]
                facts = sorted(self.commands.get(other_id, ()), key=lambda fact: fact["identity"])
                commands = []
                for fact in facts:
                    entries.append(context_entry(fact["identity"], "build"))
                    result = fact["payload"]["result"]
                    for reason in (*fact["payload"].get("gaps", ()), *result.get("gaps", ())):
                        if isinstance(reason, str) and reason:
                            gaps.append(ScopeGap("artifact_provenance", identity, "partial", reason))
                    # Only indexed safe command tokens, never raw argv or environment values.
                    for command in result.get("command_facts", ()):
                        tokens = command.get("ordered_tokens", ())
                        text = " ".join(str(token.get("safe_value", "<redacted>")) for token in tokens)
                        commands.append({"ref": fact["identity"], "text": text[:1024],
                                         "truncated": len(text) > 1024})
                if len(commands) > limit or any(command["truncated"] for command in commands):
                    gaps.append(ScopeGap("artifact_provenance", identity, "truncated",
                                         f"build command context bounded to {limit} commands of 1024 characters; "
                                         f"{max(0, len(commands) - limit)} commands omitted"))
                record["provenance"].append({
                    "relation": relation["kind"], "source_id": relation["source_id"],
                    "target_id": relation["target_id"], "exact": bool(relation["exact"]),
                    "confidence": relation["confidence"], "ambiguity": relation["ambiguity"],
                    "name": other["name"], "workspace_path": other_payload.get("workspace_path"),
                    "tool": other_payload.get("tool"), "working_directory": other_payload.get("working_directory"),
                    "argv_sha256": other_payload.get("argv_sha256"), "commands": commands[:limit],
                })
                if not relation["exact"]:
                    gaps.append(ScopeGap("artifact_provenance", identity, "ambiguous",
                                         relation["ambiguity"] or f"{relation['kind']} mapping is not exact"))
                if other["kind"] == "build_action" and not commands:
                    gaps.append(ScopeGap("artifact_provenance", identity, "unavailable",
                                         f"safe command tokens unavailable for accepted build action {other_id}"))
            if not any(r["kind"] == "GENERATED_FROM" for r in relations.values()):
                gaps.append(ScopeGap("artifact_provenance", identity, "unavailable",
                                     "no accepted producing-action relation; build command is unknown"))
            if not any(r["kind"] == "LINKS_INTO" and r["source_id"] == identity for r in relations.values()):
                gaps.append(ScopeGap("artifact_provenance", identity, "unavailable",
                                     "no accepted outgoing link-use relation; absence does not prove unused"))
            records.append(record)
        return records, entries, sorted_gaps(gaps)
