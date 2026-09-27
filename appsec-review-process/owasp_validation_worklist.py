"""Standalone OWASP worklist worker; it cannot assess or satisfy a control."""
from bounded_analysis_workers import publish_attempt, standards_worklist

JOB = "04-owasp-validation-worklist"
RESULT = "owasp-validation-worklist.json"

def build(**kwargs):
    return standards_worklist(family="owasp", **kwargs)

__all__ = ["JOB", "RESULT", "build", "publish_attempt"]
