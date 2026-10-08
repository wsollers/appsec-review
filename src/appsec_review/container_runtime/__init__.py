"""Typed, policy-enforcing execution of cataloged scanner containers."""

from .catalog import ContainerCatalog, ToolImage, load_catalog
from .executor import (
    ContainerExecutor,
    ExecutionRequest,
    ExecutionResult,
    Mount,
)

__all__ = [
    "ContainerCatalog",
    "ContainerExecutor",
    "ExecutionRequest",
    "ExecutionResult",
    "Mount",
    "ToolImage",
    "load_catalog",
]
