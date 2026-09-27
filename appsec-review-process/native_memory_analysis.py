"""Standalone 05-native-memory worker; consumes accepted evidence and emits candidates only."""
from bounded_analysis_workers import load_accepted as load_upstream, native_memory as analyze, publish_attempt

JOB = "05-native-memory"
RESULT = "native-memory-analysis.json"

__all__ = ["JOB", "RESULT", "load_upstream", "analyze", "publish_attempt"]
