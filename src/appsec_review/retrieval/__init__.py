"""Run-scoped indexing and bounded retrieval contracts."""

from .interfaces import SearchBackend, SearchHit, SearchPage, SearchRequest

__all__ = ["SearchBackend", "SearchHit", "SearchPage", "SearchRequest"]
