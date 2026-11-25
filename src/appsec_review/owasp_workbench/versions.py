"""The rule and validator versions the workbench implements.

D6 (run 2026-11-16-0005): ``[jobs.job_owasp_control_assessment.settings.parser_versions]`` must declare
exactly these values, so a rule change cannot ship under an old declared version; the job's input
validator asserts equality before any unit runs.
"""
from __future__ import annotations

from .assessment import RESULT_RULE
from .batching import REQUEST_RULE
from .engine import APPLICABILITY_RULE, CLASSIFICATION_SCHEMA
from .evidence import EVIDENCE_RULE
from .subject_selection import SELECTION_RULE


def _version(identifier: str) -> str:
    return identifier.rsplit("/", 1)[1]


def implemented_parser_versions() -> dict[str, str]:
    """The ``parser_versions`` mapping derived from the code constants, key for key."""
    return {
        "component_rules": _version(CLASSIFICATION_SCHEMA),
        "applicability_rules": _version(APPLICABILITY_RULE),
        "batching_rules": _version(REQUEST_RULE),
        "evidence_binding": _version(EVIDENCE_RULE),
        "subject_selection": _version(SELECTION_RULE),
        "result_validator": _version(RESULT_RULE),
    }
