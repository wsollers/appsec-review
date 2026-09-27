"""Standalone 13-fuzz-target-triage worker; ranks harness feasibility without fuzzing."""
from bounded_analysis_workers import load_accepted as load_upstream, fuzz_triage as analyze, publish_attempt

JOB = "13-fuzz-target-triage"
RESULT = "fuzz-target-triage.json"

__all__ = ["JOB", "RESULT", "load_upstream", "analyze", "publish_attempt"]

def run(run_id, dagster_run_id, force=False):
    from analysis_feature_lifecycle import run as lifecycle_run
    return lifecycle_run(run_id, dagster_run_id, JOB, force)

def validate(run_id):
    from analysis_feature_lifecycle import validate as lifecycle_validate
    return lifecycle_validate(run_id, JOB)
