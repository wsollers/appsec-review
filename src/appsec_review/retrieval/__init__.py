"""Run-scoped indexing and bounded retrieval contracts."""

from .interfaces import RunIndexBackend, SearchBackend, SearchHit, SearchPage, SearchRequest
from .core import RetrievalCore, RetrievalGap, RetrievalLimits
from .index import INDEX_SCHEMA, MANIFEST_SCHEMA, IndexBuilder, IndexIdentity, index_fingerprint, write_manifest
from .model import (
    EntityKind, EntityRecord, LogicalIdentity, RelationKind, RelationRecord, SourceLocation,
    sanitize_producer_data,
)

__all__ = [
    "EntityKind", "EntityRecord", "INDEX_SCHEMA", "IndexBuilder", "IndexIdentity", "LogicalIdentity",
    "MANIFEST_SCHEMA", "RelationKind", "RelationRecord", "RetrievalCore", "RetrievalGap",
    "RetrievalLimits", "RunIndexBackend", "SearchBackend", "SearchHit", "SearchPage", "SearchRequest",
    "SourceLocation", "index_fingerprint", "sanitize_producer_data", "write_manifest",
]
