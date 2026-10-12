"""Shared review-worker guidance: fragments, generated coverage, routing, and bundle assembly."""

from .compose import (
    BUNDLE_SCHEMA, PERSONA_VIEWS, bundle_sha256, compose_bundle, governing_rules, load_fragment,
    load_persona_covers, load_registry, load_task, pin_bundle, render_prompt, validate_registry,
    verify_bundle,
)
from .coverage import expand_coverage
from .fragments import (
    PERSONA_SECTIONS, STACK_SECTIONS, Fragment, GuidanceError, TaskPrompt, load_tool_names,
    parse_fragment, parse_task,
)
from .routing import hunt_panel, partition_check, route_persona, route_stack


__all__ = [
    "BUNDLE_SCHEMA", "PERSONA_SECTIONS", "PERSONA_VIEWS", "STACK_SECTIONS", "Fragment", "GuidanceError",
    "TaskPrompt", "bundle_sha256", "compose_bundle", "expand_coverage", "governing_rules", "hunt_panel",
    "load_fragment", "load_persona_covers", "load_registry", "load_task", "load_tool_names", "parse_fragment",
    "parse_task", "partition_check", "pin_bundle", "render_prompt", "route_persona", "route_stack",
    "validate_registry", "verify_bundle",
]
