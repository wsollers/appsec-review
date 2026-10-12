"""Dataset publication declarations shared by every producer job.

A *dataset* is one logical output of one job step, even when it spans many files or shards. Each
job declares its output kinds on :class:`~appsec_review.runtime.job.Job` before execution; the
publication audit in ``appsec_review.indexing`` compares these declarations with the handoffs,
artifacts, run-owned files and index shards the run actually emitted. A declaration is a contract,
not evidence: nothing here claims a dataset was produced.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


DISPOSITIONS = ("indexed", "artifact_only", "protected", "unavailable")
SENSITIVITIES = ("public", "internal", "sensitive", "secret")
FAMILIES = (
    "configuration", "catalog", "analysis_plan", "build", "source", "syntax", "compiled", "symbols",
    "cpg", "artifacts", "sbom", "scanner_findings", "codeql", "ci", "history", "change_context",
    "priority", "tags", "owasp", "reference_feeds", "inventory", "links", "precomputed",
    "execution_receipts", "documents", "inference_review", "graph",
)
STORES = ("retrieval", "owasp")
_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


@dataclass(frozen=True, slots=True)
class DatasetDeclaration:
    """One output kind a job step may emit and how retrieval must account for it.

    ``indexes`` with optional ``shard_prefixes``/``shard_suffixes`` claim accepted index shards
    produced by the declaring job; ``artifacts`` are run-relative glob patterns (``*`` within one
    path segment, ``**`` across segments, a trailing ``/**`` claims a whole tree) claiming
    run-owned files. ``disposition`` is the publication the producer intends when the output
    exists; an expected output that was not emitted is always reported as ``unavailable`` with a
    reason, never as an empty success.
    """

    output_kind: str
    step: str
    family: str
    schema: str
    sensitivity: str
    disposition: str
    description: str
    indexes: tuple[str, ...] = ()
    shard_prefixes: tuple[str, ...] = ()
    shard_suffixes: tuple[str, ...] = ()
    artifacts: tuple[str, ...] = ()
    query_route: str | None = None
    reason: str | None = None
    required: bool = False
    store: str = "retrieval"

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.output_kind) or not _NAME.fullmatch(self.step):
            raise ValueError(f"invalid dataset output kind or step: {self.output_kind}/{self.step}")
        if self.family not in FAMILIES:
            raise ValueError(f"unknown dataset family: {self.family}")
        if self.sensitivity not in SENSITIVITIES:
            raise ValueError(f"unknown dataset sensitivity: {self.sensitivity}")
        if self.store not in STORES:
            raise ValueError(f"unknown dataset store: {self.output_kind}")
        if self.disposition not in DISPOSITIONS[:3]:
            raise ValueError(f"declared disposition must be indexed, artifact_only or protected: {self.output_kind}")
        if not self.schema.strip() or not self.description.strip():
            raise ValueError(f"dataset schema and description are required: {self.output_kind}")
        if self.disposition == "indexed":
            if not self.indexes:
                raise ValueError(f"indexed dataset must claim an index: {self.output_kind}")
            if not (self.query_route or "").strip():
                raise ValueError(f"indexed dataset requires a query route: {self.output_kind}")
        else:
            if self.indexes or self.shard_prefixes or self.shard_suffixes:
                raise ValueError(f"only an indexed dataset may claim index shards: {self.output_kind}")
            if not self.artifacts:
                raise ValueError(f"non-indexed dataset must claim artifacts: {self.output_kind}")
            if not (self.reason or "").strip():
                raise ValueError(f"{self.disposition} dataset requires a named exception reason: {self.output_kind}")
            if not (self.query_route or "").strip():
                raise ValueError(f"{self.disposition} dataset requires a sanitized-metadata query route: "
                                 f"{self.output_kind}")
        if self.disposition == "protected" and self.sensitivity not in {"sensitive", "secret"}:
            raise ValueError(f"protected dataset must be sensitive or secret: {self.output_kind}")
        if (self.shard_prefixes or self.shard_suffixes) and not self.indexes:
            raise ValueError(f"shard claims require an index: {self.output_kind}")
        for pattern in self.artifacts:
            if not pattern or pattern.startswith("/") or ".." in pattern.split("/") or "\\" in pattern:
                raise ValueError(f"artifact pattern must be run-relative: {self.output_kind}")

    def claims_shard(self, index: str, shard_id: str) -> int:
        """Return a specificity score (0 = no claim) for one shard of the declaring job."""
        if index not in self.indexes:
            return 0
        prefix = max((len(item) for item in self.shard_prefixes if shard_id.startswith(item)), default=None)
        suffix = max((len(item) for item in self.shard_suffixes if shard_id.endswith(item)), default=None)
        if (self.shard_prefixes and prefix is None) or (self.shard_suffixes and suffix is None):
            return 0
        return 1 + (prefix or 0) + (suffix or 0)


METADATA_ROUTE = "query_dataset_inventory (sanitized identity, hash, status and coverage only)"


def indexed(output_kind: str, step: str, family: str, schema: str, description: str, *,
            indexes: tuple[str, ...], route: str, prefixes: tuple[str, ...] = (),
            suffixes: tuple[str, ...] = (), artifacts: tuple[str, ...] = (), sensitivity: str = "internal",
            required: bool = False, store: str = "retrieval") -> DatasetDeclaration:
    return DatasetDeclaration(output_kind, step, family, schema, sensitivity, "indexed", description,
                              indexes=indexes, shard_prefixes=prefixes, shard_suffixes=suffixes,
                              artifacts=artifacts, query_route=route, required=required, store=store)


def artifact_only(output_kind: str, step: str, family: str, schema: str, description: str, *,
                  artifacts: tuple[str, ...], reason: str, sensitivity: str = "internal",
                  route: str = METADATA_ROUTE) -> DatasetDeclaration:
    return DatasetDeclaration(output_kind, step, family, schema, sensitivity, "artifact_only", description,
                              artifacts=artifacts, query_route=route, reason=reason)


def protected(output_kind: str, step: str, family: str, schema: str, description: str, *,
              artifacts: tuple[str, ...], reason: str, sensitivity: str = "sensitive",
              route: str = METADATA_ROUTE) -> DatasetDeclaration:
    return DatasetDeclaration(output_kind, step, family, schema, sensitivity, "protected", description,
                              artifacts=artifacts, query_route=route, reason=reason)


def validate_declarations(job_id: str, declarations: tuple[DatasetDeclaration, ...]) -> None:
    """Reject ambiguous declarations so one emitted shard can never match two datasets equally."""
    kinds = [item.output_kind for item in declarations]
    if len(kinds) != len(set(kinds)):
        raise ValueError(f"duplicate dataset output kinds: {job_id}")
    claims: dict[tuple[str, str], set[tuple[tuple[str, ...], tuple[str, ...]]]] = {}
    for item in declarations:
        for index in item.indexes:
            key = (item.store, index)
            claim = (tuple(sorted(item.shard_prefixes)), tuple(sorted(item.shard_suffixes)))
            if claim in claims.setdefault(key, set()):
                raise ValueError(f"duplicate shard claim for index {index}: {job_id}")
            claims[key].add(claim)
