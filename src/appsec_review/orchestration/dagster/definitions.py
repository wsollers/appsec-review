"""Module entry point loaded by the Dagster code location."""

from .adapter import build_definitions

defs = build_definitions()
