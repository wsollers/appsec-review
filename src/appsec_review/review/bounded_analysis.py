"""Join conditional CBMC context to its exact accepted scanner seeds, never create new leads."""

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from appsec_review.indexing.store import open_shard
from appsec_review.review.models import IntegrityError
from appsec_review.review.scope import ScopeGap
from appsec_review.review.units import context_entry

ROLE = "bounded_analysis"
PRODUCER = "job_cbmc_analysis"
NATIVE_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh")
JUDGMENTS = frozenset({"counterexample_candidate", "bounded_pass", "inconclusive", "not_attempted"})


def summary(payload: Mapping[str, Any]) -> dict[str, Any]:
    if payload.get("schema") != "appsec-review/cbmc-result/1" or payload.get("judgment") not in JUDGMENTS:
        raise IntegrityError("invalid accepted CBMC result")
    return {
        **{key: payload[key] for key in ("judgment", "function", "reason", "property_count", "candidate_count",
                                        "unwind_limits_attempted", "assumptions", "gaps")},
        "counterexamples": [
            {key: prop[key] for key in ("property_id", "description", "source", "trace", "trace_omitted")}
            for prop in payload["properties"] if prop["status"] == "FAILURE" and prop["kind"] == "safety"
            and prop["trace_steps"] > 0 and prop["source"] is not None],
        "omitted_properties": payload["omitted_properties"],
    }


class BoundedAnalysisContext:
    def __init__(self, scope: Any):
        self.by_seed: dict[str, list[Any]] = defaultdict(list)
        self.gaps: dict[str, list[ScopeGap]] = defaultdict(list)
        self.shards = scope.select(lambda row: row["name"] == "observations"
                                   and row.get("producer", {}).get("job") == PRODUCER)
        shard_hashes = {(shard["name"], shard.get("shard_id", "default")): scope.shard_sha256(shard)
                        for shard in self.shards}
        rows = list(scope.store.entities(self.shards, kinds=("review_signal",)))
        wanted = sorted({identity for row in rows for identity in row["payload"]["seed_observation_ids"]})
        if not wanted:
            return
        locations = {}
        originals = scope.select(lambda row: row["name"] == "observations"
                                 and row.get("producer", {}).get("job") != PRODUCER)
        for shard in originals:
            with open_shard(scope.run_root, shard) as database:
                for start in range(0, len(wanted), 256):
                    ids = wanted[start:start + 256]
                    sql = "SELECT entity_id, path, file_sha256, start_line, end_line FROM locations WHERE entity_id IN (" + ",".join("?" for _ in ids) + ")"
                    for location in database.execute(sql, ids):
                        value = dict(location)
                        previous = locations.setdefault(value["entity_id"], value)
                        if previous != value:
                            raise IntegrityError("CBMC originating seed has conflicting source identities")
        for row in rows:
            payload = row["payload"]
            summary(payload)
            for seed in payload["seed_locations"]:
                for identity in seed["observation_ids"]:
                    original = locations.get(identity)
                    if original is None:
                        self.gaps[identity].append(ScopeGap(
                            ROLE, identity, "unavailable", "CBMC seed does not resolve in the accepted scanner inputs"))
                        continue
                    if any(original[key] != seed[key] for key in ("path", "file_sha256", "start_line", "end_line")):
                        raise IntegrityError("CBMC result names different bytes or lines for its originating seed")
                    self.by_seed[identity].append(context_entry(
                        row["identity"], ROLE, shard_hashes[(row["index"], row["shard_id"])]))
                    for reason in payload["gaps"]:
                        self.gaps[identity].append(ScopeGap(ROLE, identity, "partial", str(reason)))

    def for_leads(self, leads: Sequence[Any]) -> tuple[list[Any], list[ScopeGap]]:
        entries = {}
        gaps = []
        for lead in leads:
            if not lead.path or not lead.path.lower().endswith(NATIVE_SUFFIXES):
                continue
            attached = self.by_seed.get(lead.observation_id, ())
            for item in attached:
                entries[item.id] = item
            gaps.extend(self.gaps.get(lead.observation_id, ()))
            if not attached:
                gaps.append(ScopeGap(ROLE, lead.observation_id, "missing" if not self.shards else "unavailable",
                                     "No accepted CBMC result for this exact seed; it was not shown safe."))
        return [entries[key] for key in sorted(entries)], gaps
