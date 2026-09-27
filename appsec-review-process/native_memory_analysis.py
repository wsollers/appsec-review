"""Standalone 05-native-memory worker; consumes accepted evidence and emits candidates only."""
from bounded_analysis_workers import load_accepted as load_upstream, native_memory as analyze, publish_attempt

JOB = "05-native-memory"
RESULT = "native-memory-analysis.json"

__all__ = ["JOB", "RESULT", "load_upstream", "analyze", "publish_attempt"]

def run(run_id, dagster_run_id, force=False):
    from analysis_feature_lifecycle import run as lifecycle_run
    return lifecycle_run(run_id, dagster_run_id, JOB, force)

def validate(run_id):
    from analysis_feature_lifecycle import validate as lifecycle_validate
    return lifecycle_validate(run_id, JOB)
