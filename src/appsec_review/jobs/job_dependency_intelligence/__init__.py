"""Dependency intelligence job and independently testable producer components."""

from .inference import PROPOSAL_SCHEMA
from .discovery import discover_native_dependencies
from .job import JOB_ID, TOPOLOGY, build_job, load_accepted_dependency_intelligence
from .native import parse_native_candidates
from .resolution import (apply_model_resolution, deduplicate_repositories, infer_maximal_exposure,
                         normalize_dependencies, repository_identity)
from .scorecard import HttpResponse, ScorecardCache, ScorecardCacheError, ScorecardClient, ScorecardError
from .sbom import build_spdx, schema_sha256, validate_spdx

__all__ = ["HttpResponse", "JOB_ID", "PROPOSAL_SCHEMA", "ScorecardCache", "ScorecardCacheError",
           "ScorecardClient", "ScorecardError", "TOPOLOGY", "apply_model_resolution", "build_job",
           "build_spdx", "deduplicate_repositories", "discover_native_dependencies",
           "load_accepted_dependency_intelligence", "infer_maximal_exposure",
           "normalize_dependencies", "parse_native_candidates", "repository_identity",
           "schema_sha256", "validate_spdx"]
