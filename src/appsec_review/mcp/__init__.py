"""Thin MCP adapters over trusted application services.

This package must not contain indexing, ranking, filesystem-discovery, or evidence-validation
logic. It translates bounded tool requests to the corresponding core service.
"""

from .adapter import RetrievalMcpAdapter
from .schema import TOOLS

__all__ = ["RetrievalMcpAdapter", "TOOLS"]
