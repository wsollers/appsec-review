"""Static-only CI configuration analysis."""

from .job import PROVIDER_TOOLS, TOPOLOGY, build_job, discover_ci_definitions

__all__ = ["PROVIDER_TOOLS", "TOPOLOGY", "build_job", "discover_ci_definitions"]
from .static_rules import classify_ci_lead_promotion
