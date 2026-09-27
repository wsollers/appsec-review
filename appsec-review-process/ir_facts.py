"""Public E05 nominal pointer/memory fact worker core."""
from ir_evidence import facts, run_job, validate as validate_job
JOB = "02-ir-facts"
RESULT = "ir-facts.json"
CONTRACT = "ir-facts"
def run(run_id, dagster_id, force=False): return run_job(run_id, dagster_id, JOB, force)
def validate(run_id, pointer=None): return validate_job(run_id, JOB, pointer)
__all__ = ["JOB", "RESULT", "CONTRACT", "facts", "run", "validate"]
