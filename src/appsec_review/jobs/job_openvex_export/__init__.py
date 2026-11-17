"""Protected local OpenVEX export; ``job.build_job`` supplies its model-free runtime."""
from __future__ import annotations

from .cve_reachability import (
    CVE_OPENVEX_SUMMARY_SCHEMA,
    NOT_IN_EXECUTE_PATH,
    CveOpenVexBundle,
    CveReachabilityDecision,
    classify_cve_reachability,
    construct_purl,
    extract_vulnerability_identity,
    project_dependency_advisories_to_openvex,
    validate_cve_openvex_document,
)

__all__ = [
    "CVE_OPENVEX_SUMMARY_SCHEMA",
    "NOT_IN_EXECUTE_PATH",
    "CveOpenVexBundle",
    "CveReachabilityDecision",
    "classify_cve_reachability",
    "construct_purl",
    "extract_vulnerability_identity",
    "project_dependency_advisories_to_openvex",
    "validate_cve_openvex_document",
]
