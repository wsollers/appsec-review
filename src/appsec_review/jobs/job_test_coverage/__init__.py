"""Bounded ingestion of test-coverage artifacts from accepted build receipts."""

from .job import (
    CoverageBounds,
    bind_coverage_paths,
    build_job,
    ingest_coverage_artifacts,
    load_accepted_test_coverage,
)
from .parsers import CoverageDocument, CoverageFile, CoverageTotals, parse_coverage

__all__ = [
    "CoverageBounds",
    "CoverageDocument",
    "CoverageFile",
    "CoverageTotals",
    "bind_coverage_paths",
    "build_job",
    "ingest_coverage_artifacts",
    "load_accepted_test_coverage",
    "parse_coverage",
]
