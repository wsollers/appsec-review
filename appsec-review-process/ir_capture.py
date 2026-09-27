"""Public E04 nominal IR capture worker core."""
from ir_evidence import capture, run_job, validate as validate_job
JOB = "02-ir-capture"
RESULT = "ir-capture.json"
CONTRACT = "ir-capture"
def run(run_id, dagster_id, force=False): return run_job(run_id, dagster_id, JOB, force)
def validate(run_id, pointer=None): return validate_job(run_id, JOB, pointer)
__all__ = ["JOB", "RESULT", "CONTRACT", "capture", "run", "validate"]
