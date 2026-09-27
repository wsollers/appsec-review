"""Standalone OWASP worklist worker; it cannot assess or satisfy a control."""
from bounded_analysis_workers import load_accepted as load_upstream, publish_attempt, standards_worklist

JOB = "04-owasp-validation-worklist"
RESULT = "owasp-validation-worklist.json"

def build(**kwargs):
    return standards_worklist(family="owasp", **kwargs)

__all__ = ["JOB", "RESULT", "load_upstream", "build", "publish_attempt"]
