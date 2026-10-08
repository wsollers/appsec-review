"""Thin MCP adapters over trusted application services.

This package must not contain indexing, ranking, filesystem-discovery, or evidence-validation
logic. It translates bounded tool requests to the corresponding core service.
"""

from .adapter import RetrievalMcpAdapter
from .schema import TOOLS

from .owasp import QUERY_TOOL_SCHEMA as OWASP_QUERY_TOOL_SCHEMA, query_owasp_workbench

__all__ = ["RetrievalMcpAdapter", "TOOLS", "OWASP_QUERY_TOOL_SCHEMA", "query_owasp_workbench"]
