"""Standalone deployment hardening worker; static state never becomes runtime proof."""
from bounded_analysis_workers import deployment_hardening as analyze, publish_attempt

JOB = "15-deployment-hardening"
RESULT = "deployment-hardening.json"

__all__ = ["JOB", "RESULT", "analyze", "publish_attempt"]
