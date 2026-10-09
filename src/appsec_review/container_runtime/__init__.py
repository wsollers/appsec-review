"""Typed, policy-enforcing execution of cataloged scanner containers."""

from .catalog import ContainerCatalog, ToolImage, load_catalog
from .build_executor import BuildCommandResult, BuildContainerExecutor, BuildProfile, profiles_from_settings
from .build_capture import BuildExecutionRecorder, CaptureScope
from .project_images import (
    ProjectImage,
    ProjectImageBuildError,
    ProjectImageResolver,
    project_dependency_environment,
    project_recipe_identity,
)
from .executor import (
    ContainerExecutor,
    ExecutionRequest,
    ExecutionResult,
    Mount,
)

__all__ = [
    "BuildCommandResult",
    "BuildExecutionRecorder",
    "BuildContainerExecutor",
    "BuildProfile",
    "CaptureScope",
    "ProjectImage",
    "ProjectImageBuildError",
    "ProjectImageResolver",
    "project_dependency_environment",
    "ContainerCatalog",
    "ContainerExecutor",
    "ExecutionRequest",
    "ExecutionResult",
    "Mount",
    "ToolImage",
    "load_catalog",
    "profiles_from_settings",
    "project_recipe_identity",
]
