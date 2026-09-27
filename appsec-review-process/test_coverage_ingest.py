from test_evidence import lcov, run_job, validate_job
JOB="02-test-coverage-ingest"; RESULT="test-coverage.json"; CONTRACT="test-coverage-intelligence"
def run(run_id,dagster_id,force=False): return run_job(run_id,dagster_id,JOB,force)
def validate(run_id,pointer=None): return validate_job(run_id,JOB,pointer)
