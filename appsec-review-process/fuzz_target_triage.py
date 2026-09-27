"""Standalone 13-fuzz-target-triage worker; ranks harness feasibility without fuzzing."""
from bounded_analysis_workers import fuzz_triage as analyze, publish_attempt

JOB = "13-fuzz-target-triage"
RESULT = "fuzz-target-triage.json"

__all__ = ["JOB", "RESULT", "analyze", "publish_attempt"]
