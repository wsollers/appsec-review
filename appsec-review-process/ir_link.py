"""Public E05 nominal deterministic IR link worker core."""
from ir_evidence import link, run_job, validate as validate_job
JOB = "02-ir-link"
RESULT = "ir-link.json"
CONTRACT = "ir-link"
def run(run_id, dagster_id, force=False): return run_job(run_id, dagster_id, JOB, force)
def validate(run_id, pointer=None): return validate_job(run_id, JOB, pointer)
__all__ = ["JOB", "RESULT", "CONTRACT", "link", "run", "validate"]
