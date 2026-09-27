"""Standalone STIG/SRG worklist worker; preserves applicability and tailoring gaps."""
from bounded_analysis_workers import publish_attempt, standards_worklist

JOB = "15-stig-srg-validation-worklist"
RESULT = "stig-srg-validation-worklist.json"

def build(**kwargs):
    return standards_worklist(family="stig_srg", **kwargs)

__all__ = ["JOB", "RESULT", "build", "publish_attempt"]
